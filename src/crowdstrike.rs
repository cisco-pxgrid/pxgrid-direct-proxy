use crate::{Config, CrowdStrikeConfig};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bytes::Bytes;
use futures_util::stream;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    time::Duration,
};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};
use tokio::time::sleep;
use url::Url;

pub async fn handle_crowdstrike(
    request: Request<Body>,
    config: Arc<Config>,
    http: Client,
) -> Response {
    let Some(settings) = config
        .crowdstrike
        .as_ref()
        .filter(|settings| settings.enabled)
    else {
        return text(StatusCode::NOT_FOUND, "CrowdStrike endpoint is disabled");
    };
    if request.method() != http::Method::GET {
        return text(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }
    let (client_id, client_secret) =
        match credentials(request.headers().get(http::header::AUTHORIZATION)) {
            Ok(value) => value,
            Err(message) => return unauthorized(&message),
        };
    if let Err(message) = validate(settings) {
        return text(StatusCode::INTERNAL_SERVER_ERROR, &message);
    }
    let mut client = FalconClient::new(http, settings.clone(), client_id, client_secret);
    match collect(&mut client).await {
        Ok(data) => response(data),
        Err(error) => error_response(error),
    }
}

fn credentials(header: Option<&http::HeaderValue>) -> Result<(String, String), String> {
    let value = header
        .ok_or_else(|| "HTTP Basic Authentication is required".to_string())?
        .to_str()
        .map_err(|_| "HTTP Basic Authentication is required".to_string())?;
    let (scheme, encoded) = value
        .split_once(" ")
        .ok_or_else(|| "HTTP Basic Authentication is required".to_string())?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err("HTTP Basic Authentication is required".into());
    }
    let raw = String::from_utf8(
        BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| "HTTP Basic Authentication is required".to_string())?,
    )
    .map_err(|_| "HTTP Basic Authentication is required".to_string())?;
    let (id, secret) = raw
        .split_once(":")
        .ok_or_else(|| "HTTP Basic Authentication is required".to_string())?;
    if id.is_empty() || secret.is_empty() {
        return Err("HTTP Basic Authentication is required".into());
    }
    Ok((id.into(), secret.into()))
}
fn validate(settings: &CrowdStrikeConfig) -> Result<(), String> {
    let url = Url::parse(&settings.base_url).map_err(|error| error.to_string())?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return Err("crowdstrike.base_url must be an HTTPS URL".into());
    }
    if settings.page_size == 0 || settings.page_size > 1000 {
        return Err("crowdstrike.page_size must be 1 to 1000".into());
    }
    if settings.lookback_days < 0 {
        return Err("crowdstrike.lookback_days must not be negative".into());
    }
    Ok(())
}

#[derive(Debug)]
enum Error {
    Auth(StatusCode),
    Status(StatusCode),
    Transport,
    Decode,
}
struct FalconClient {
    http: Client,
    settings: CrowdStrikeConfig,
    client_id: String,
    client_secret: String,
    token: Option<String>,
}
impl FalconClient {
    fn new(
        http: Client,
        settings: CrowdStrikeConfig,
        client_id: String,
        client_secret: String,
    ) -> Self {
        Self {
            http,
            settings,
            client_id,
            client_secret,
            token: None,
        }
    }
    fn url(&self, path: &str) -> Result<Url, Error> {
        self.settings
            .base_url
            .trim_end_matches("/")
            .parse::<Url>()
            .map_err(|_| Error::Transport)?
            .join(path)
            .map_err(|_| Error::Transport)
    }
    async fn token(&mut self) -> Result<String, Error> {
        if let Some(token) = &self.token {
            return Ok(token.clone());
        }
        let response = self
            .http
            .post(self.url("/oauth2/token")?)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .timeout(Duration::from_secs(self.settings.timeout_seconds))
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        let status = response.status();
        let body = response.text().await.map_err(|_| Error::Transport)?;
        if !status.is_success() {
            return if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                Err(Error::Auth(status))
            } else {
                Err(Error::Status(status))
            };
        }
        let token = serde_json::from_str::<Value>(&body)
            .map_err(|_| Error::Decode)?
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or(Error::Decode)?
            .to_string();
        self.token = Some(token.clone());
        Ok(token)
    }
    async fn request(
        &mut self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<Value>,
    ) -> Result<Value, Error> {
        let token = self.token().await?;
        for attempt in 0..=self.settings.rate_limit_retries {
            let mut request = self
                .http
                .request(method.clone(), self.url(path)?)
                .bearer_auth(&token)
                .query(query)
                .timeout(Duration::from_secs(self.settings.timeout_seconds));
            if let Some(body) = &body {
                request = request.json(body);
            }
            let response = request.send().await.map_err(|_| Error::Transport)?;
            let status = response.status();
            let wait = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(1);
            let body = response.text().await.map_err(|_| Error::Transport)?;
            if status == StatusCode::TOO_MANY_REQUESTS && attempt < self.settings.rate_limit_retries
            {
                sleep(Duration::from_secs(wait.min(60))).await;
                continue;
            }
            if !status.is_success() {
                return Err(Error::Status(status));
            }
            return serde_json::from_str(&body).map_err(|_| Error::Decode);
        }
        Err(Error::Transport)
    }
    async fn probe(
        &mut self,
        name: &str,
        path: &str,
        available: &mut BTreeMap<String, bool>,
    ) -> Result<bool, Error> {
        match self
            .request(Method::GET, path, &[("limit".into(), "1".into())], None)
            .await
        {
            Ok(_) => {
                available.insert(name.into(), true);
                Ok(true)
            }
            Err(Error::Status(status))
                if matches!(
                    status,
                    StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
                ) =>
            {
                available.insert(name.into(), false);
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }
}

fn resources(value: &Value) -> Vec<Value> {
    value
        .get("resources")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
fn string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}
fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
fn cutoff(days: i64) -> String {
    (OffsetDateTime::now_utc() - TimeDuration::days(days))
        .format(&Rfc3339)
        .unwrap_or_default()
}

struct Data {
    devices: Vec<Value>,
    unmanaged: Vec<Value>,
    zta: HashMap<String, Value>,
    alerts: HashMap<String, Vec<Value>>,
    detections: HashMap<String, Vec<Value>>,
    incidents: HashMap<String, Vec<Value>>,
    vulns: HashMap<String, Value>,
    prevention: HashMap<String, Value>,
    sensor: HashMap<String, Value>,
    groups: HashMap<String, Value>,
    available: BTreeMap<String, bool>,
    refreshed: String,
}

async fn paged_ids(
    client: &mut FalconClient,
    path: &str,
    mut query: Vec<(String, String)>,
) -> Result<Vec<String>, Error> {
    let mut output = Vec::new();
    let mut offset = 0;
    loop {
        query.retain(|(key, _)| key != "limit" && key != "offset");
        query.push(("limit".into(), client.settings.page_size.to_string()));
        query.push(("offset".into(), offset.to_string()));
        let response = client.request(Method::GET, path, &query, None).await?;
        let page = resources(&response)
            .into_iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        let total = response
            .pointer("/meta/pagination/total")
            .and_then(Value::as_u64)
            .unwrap_or((offset + page.len() as u64) as u64);
        let empty = page.is_empty();
        output.extend(page);
        offset += client.settings.page_size;
        if empty || offset >= total {
            break;
        }
    }
    Ok(output)
}
async fn details(
    client: &mut FalconClient,
    path: &str,
    key: &str,
    ids: &[String],
) -> Result<Vec<Value>, Error> {
    let mut output = Vec::new();
    for batch in ids.chunks(100) {
        output.extend(resources(
            &client
                .request(Method::POST, path, &[], Some(json!({key: batch})))
                .await?,
        ));
    }
    Ok(output)
}
async fn by_device(
    client: &mut FalconClient,
    name: &str,
    query_path: &str,
    entity_path: &str,
    body_key: &str,
    available: &mut BTreeMap<String, bool>,
) -> Result<HashMap<String, Vec<Value>>, Error> {
    if !client.probe(name, query_path, available).await? {
        return Ok(HashMap::new());
    }
    let filter = format!(
        "created_timestamp:>\"{}\"",
        cutoff(client.settings.lookback_days)
    );
    let ids = paged_ids(client, query_path, vec![("filter".into(), filter)]).await?;
    let mut output = HashMap::new();
    for value in details(client, entity_path, body_key, &ids).await? {
        if let Some(id) = value.pointer("/device/device_id").and_then(Value::as_str) {
            output.entry(id.into()).or_insert_with(Vec::new).push(value);
        }
    }
    Ok(output)
}
async fn zta(
    client: &mut FalconClient,
    ids: &[String],
    available: &mut BTreeMap<String, bool>,
) -> Result<HashMap<String, Value>, Error> {
    let path = "/zero-trust-assessment/entities/assessments/v1";
    if !client.probe("zta", path, available).await? {
        return Ok(HashMap::new());
    }
    let mut output = HashMap::new();
    for batch in ids.chunks(100) {
        let query = batch
            .iter()
            .map(|id| ("ids".into(), id.clone()))
            .collect::<Vec<_>>();
        for value in resources(&client.request(Method::GET, path, &query, None).await?) {
            if let Some(id) = string(&value, "aid") {
                output.insert(id, value);
            }
        }
    }
    Ok(output)
}
async fn incidents(
    client: &mut FalconClient,
    available: &mut BTreeMap<String, bool>,
) -> Result<HashMap<String, Vec<Value>>, Error> {
    let path = "/incidents/queries/incidents/v1";
    if !client.probe("incidents", path, available).await? {
        return Ok(HashMap::new());
    }
    let ids = paged_ids(
        client,
        path,
        vec![(
            "filter".into(),
            format!("start:>\"{}\"", cutoff(client.settings.lookback_days)),
        )],
    )
    .await?;
    let mut output = HashMap::new();
    for incident in details(client, "/incidents/entities/incidents/GET/v1", "ids", &ids).await? {
        for host in incident
            .get("hosts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            if let Some(id) = string(&host, "device_id") {
                output
                    .entry(id)
                    .or_insert_with(Vec::new)
                    .push(incident.clone());
            }
        }
    }
    Ok(output)
}
async fn policies(
    client: &mut FalconClient,
    available: &mut BTreeMap<String, bool>,
) -> Result<(HashMap<String, Value>, HashMap<String, Value>), Error> {
    let mut prevention = HashMap::new();
    let mut sensor = HashMap::new();
    if client
        .probe(
            "prevention_policy",
            "/policy/queries/prevention/v1",
            available,
        )
        .await?
    {
        for value in resources(
            &client
                .request(
                    Method::GET,
                    "/policy/combined/prevention/v1",
                    &[("limit".into(), "500".into())],
                    None,
                )
                .await?,
        ) {
            if let Some(id) = string(&value, "id") {
                prevention.insert(id, value);
            }
        }
    }
    if client
        .probe(
            "sensor_policy",
            "/policy/queries/sensor-update/v1",
            available,
        )
        .await?
    {
        for value in resources(
            &client
                .request(
                    Method::GET,
                    "/policy/combined/sensor-update/v2",
                    &[("limit".into(), "500".into())],
                    None,
                )
                .await?,
        ) {
            if let Some(id) = string(&value, "id") {
                sensor.insert(id, value);
            }
        }
    }
    Ok((prevention, sensor))
}
async fn groups(
    client: &mut FalconClient,
    available: &mut BTreeMap<String, bool>,
) -> Result<HashMap<String, Value>, Error> {
    if !client
        .probe("host_groups", "/devices/queries/host-groups/v1", available)
        .await?
    {
        return Ok(HashMap::new());
    }
    let mut output = HashMap::new();
    for value in resources(
        &client
            .request(
                Method::GET,
                "/devices/combined/host-groups/v1",
                &[("limit".into(), "500".into())],
                None,
            )
            .await?,
    ) {
        if let Some(id) = string(&value, "id") {
            output.insert(id, value);
        }
    }
    Ok(output)
}
async fn unmanaged(
    client: &mut FalconClient,
    available: &mut BTreeMap<String, bool>,
) -> Result<Vec<Value>, Error> {
    let path = "/discover/queries/hosts/v1";
    if !client.probe("discover", path, available).await? {
        return Ok(Vec::new());
    }
    let ids = paged_ids(
        client,
        path,
        vec![("filter".into(), "entity_type: \"unmanaged\"".into())],
    )
    .await?;
    let mut output = Vec::new();
    for batch in ids.chunks(100) {
        let query = batch
            .iter()
            .map(|id| ("ids".into(), id.clone()))
            .collect::<Vec<_>>();
        output.extend(resources(
            &client
                .request(Method::GET, "/discover/entities/hosts/v1", &query, None)
                .await?,
        ));
    }
    Ok(output)
}

async fn vulnerabilities(
    client: &mut FalconClient,
    ids: &[String],
    available: &mut BTreeMap<String, bool>,
) -> Result<HashMap<String, Value>, Error> {
    let path = "/spotlight/queries/vulnerabilities/v1";
    if !client.probe("spotlight", path, available).await? {
        return Ok(HashMap::new());
    }
    let mut output = HashMap::new();
    for aids in ids.chunks(50) {
        let filter = format!(
            "aid:[{}]+status: \"open\"",
            aids.iter()
                .map(|id| format!("\"{}\"", id))
                .collect::<Vec<_>>()
                .join(",")
        );
        let vuln_ids = paged_ids(client, path, vec![("filter".into(), filter)]).await?;
        for batch in vuln_ids.chunks(400) {
            let query = batch
                .iter()
                .map(|id| ("ids".into(), id.clone()))
                .collect::<Vec<_>>();
            for vuln in resources(
                &client
                    .request(
                        Method::GET,
                        "/spotlight/entities/vulnerabilities/v2",
                        &query,
                        None,
                    )
                    .await?,
            ) {
                let Some(aid) = string(&vuln, "aid") else {
                    continue;
                };
                let entry=output.entry(aid).or_insert_with(||json!({"critical":0,"high":0,"medium":0,"low":0,"total":0,"max_cvss":0.0,"cves":[]}));
                let score = vuln
                    .pointer("/cve/base_score")
                    .and_then(Value::as_f64)
                    .unwrap_or(0.0);
                let severity = if score >= 9.0 {
                    "critical"
                } else if score >= 7.0 {
                    "high"
                } else if score >= 4.0 {
                    "medium"
                } else {
                    "low"
                };
                entry["total"] = json!(entry["total"].as_u64().unwrap_or(0) + 1);
                entry[severity] = json!(entry[severity].as_u64().unwrap_or(0) + 1);
                entry["max_cvss"] = json!(entry["max_cvss"].as_f64().unwrap_or(0.0).max(score));
                if severity == "critical" && entry["cves"].as_array().map_or(0, Vec::len) < 5 {
                    entry["cves"].as_array_mut().unwrap().push(json!(vuln
                        .pointer("/cve/id")
                        .and_then(Value::as_str)
                        .unwrap_or("")));
                }
            }
        }
    }
    Ok(output)
}
async fn collect(client: &mut FalconClient) -> Result<Data, Error> {
    let mut available = BTreeMap::new();
    available.insert("hosts".into(), true);
    let ids = paged_ids(client, "/devices/queries/devices/v1", vec![]).await?;
    let devices = details(client, "/devices/entities/devices/v2", "ids", &ids).await?;
    let device_ids = devices
        .iter()
        .filter_map(|device| string(device, "device_id"))
        .collect::<Vec<_>>();
    let features = client.settings.features.clone();
    let (prevention, sensor) = if features.policies {
        policies(client, &mut available).await?
    } else {
        (HashMap::new(), HashMap::new())
    };
    let zta_data = if features.zta {
        zta(client, &device_ids, &mut available).await?
    } else {
        HashMap::new()
    };
    let alerts = if features.alerts {
        by_device(
            client,
            "alerts",
            "/alerts/queries/alerts/v2",
            "/alerts/entities/alerts/v2",
            "composite_ids",
            &mut available,
        )
        .await?
    } else {
        HashMap::new()
    };
    let detections = if features.detections {
        by_device(
            client,
            "detections",
            "/detects/queries/detects/v1",
            "/detects/entities/summaries/GET/v1",
            "ids",
            &mut available,
        )
        .await?
    } else {
        HashMap::new()
    };
    let incident_data = if features.incidents {
        incidents(client, &mut available).await?
    } else {
        HashMap::new()
    };
    let vulns = if features.vulnerability_summary {
        vulnerabilities(client, &device_ids, &mut available).await?
    } else {
        HashMap::new()
    };
    let group_data = if features.host_groups {
        groups(client, &mut available).await?
    } else {
        HashMap::new()
    };
    let unmanaged_data = if features.unmanaged_assets {
        unmanaged(client, &mut available).await?
    } else {
        Vec::new()
    };
    Ok(Data {
        devices,
        unmanaged: unmanaged_data,
        zta: zta_data,
        alerts,
        detections,
        incidents: incident_data,
        vulns,
        prevention,
        sensor,
        groups: group_data,
        available,
        refreshed: now(),
    })
}
fn mac(value: Option<&str>) -> Option<String> {
    let raw = value?
        .replace("-", "")
        .replace(":", "")
        .replace(".", "")
        .to_uppercase();
    if raw.len() != 12 {
        return None;
    }
    Some(
        (0..12)
            .step_by(2)
            .map(|i| &raw[i..i + 2])
            .collect::<Vec<_>>()
            .join(":"),
    )
}
fn severity(values: &[Value], needle: &str) -> u64 {
    values
        .iter()
        .filter(|value| value.to_string().to_ascii_lowercase().contains(needle))
        .count() as u64
}
fn managed(device: &Value, data: &Data) -> Value {
    let id = string(device, "device_id").unwrap_or_default();
    let zta = data.zta.get(&id).cloned().unwrap_or(Value::Null);
    let alerts = data.alerts.get(&id).cloned().unwrap_or_default();
    let detections = data.detections.get(&id).cloned().unwrap_or_default();
    let incidents = data.incidents.get(&id).cloned().unwrap_or_default();
    let vuln = data.vulns.get(&id).cloned().unwrap_or_else(|| json!({}));
    let policies = device
        .get("device_policies")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let prev = policies
        .pointer("/prevention/policy_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let sensor = policies
        .pointer("/sensor_update/policy_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let groups = device
        .get("groups")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let group_ids = groups.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    let group_names = group_ids
        .iter()
        .filter_map(|id| {
            data.groups
                .get(*id)
                .and_then(|v| v.get("name"))
                .and_then(Value::as_str)
        })
        .collect::<Vec<_>>();
    let ac = severity(&alerts, "critical");
    let ah = severity(&alerts, "high");
    let dc = severity(&detections, "critical");
    let dh = severity(&detections, "high");
    let risk = ((((100.0
        - zta
            .pointer("/assessment/overall")
            .and_then(Value::as_f64)
            .unwrap_or(100.0))
        * 0.3) as u64)
        + ac * 12
        + ah * 8
        + dc * 12
        + dh * 8
        + incidents.len() as u64 * 10
        + vuln.get("critical").and_then(Value::as_u64).unwrap_or(0) * 5
        + vuln.get("high").and_then(Value::as_u64).unwrap_or(0) * 2
        + vuln
            .get("max_cvss")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            .min(10.0) as u64)
        .min(100);
    let compliance = if risk >= 70 {
        "Critical"
    } else if risk >= 50 {
        "NonCompliant"
    } else if risk >= 30 {
        "Warning"
    } else {
        "Compliant"
    };
    json!({"assetId":id,"assetMacAddress":mac(string(device,"mac_address").as_deref()),"assetIpAddress":device.get("local_ip"),"assetExternalIp":device.get("external_ip"),"assetHostname":device.get("hostname"),"osVersion":device.get("os_version"),"platformName":device.get("platform_name"),"platformId":device.get("platform_id"),"systemManufacturer":device.get("system_manufacturer"),"systemProductName":device.get("system_product_name"),"serialNumber":device.get("serial_number"),"machineDomain":device.get("machine_domain"),"agentVersion":device.get("agent_version"),"lastSeen":device.get("last_seen"),"firstSeen":device.get("first_seen"),"deviceStatus":device.get("status"),"ztaOverallScore":zta.pointer("/assessment/overall"),"preventionPolicyId":prev,"preventionPolicyName":data.prevention.get(prev).and_then(|v|v.get("name")),"sensorPolicyId":sensor,"sensorPolicyName":data.sensor.get(sensor).and_then(|v|v.get("name")),"hostGroupIds":if group_ids.is_empty(){None}else{Some(group_ids.join(","))},"hostGroupNames":if group_names.is_empty(){None}else{Some(group_names.join(","))},"alertCriticalCount":ac,"alertHighCount":ah,"alertTotalCount":alerts.len(),"detectionCriticalCount":dc,"detectionHighCount":dh,"detectionTotalCount":detections.len(),"incidentCount":incidents.len(),"vulnCriticalCount":vuln.get("critical").and_then(Value::as_u64).unwrap_or(0),"vulnHighCount":vuln.get("high").and_then(Value::as_u64).unwrap_or(0),"vulnTotalCount":vuln.get("total").and_then(Value::as_u64).unwrap_or(0),"vulnMaxCvss":vuln.get("max_cvss").and_then(Value::as_f64).unwrap_or(0.0),"riskScore":risk,"complianceState":compliance,"isHighRisk":risk>=50,"isCriticalRisk":risk>=70,"dataSource":"CrowdStrike Falcon","lastUpdated":data.refreshed})
}
fn unmanaged_record(asset: &Value, refreshed: &str) -> Value {
    json!({"assetId":asset.get("id"),"assetMacAddress":mac(string(asset,"mac_address").as_deref()),"assetIpAddress":asset.get("local_ip_addresses").and_then(Value::as_array).and_then(|v|v.first()),"assetHostname":asset.get("hostname"),"osVersion":asset.get("os_version"),"platformName":asset.get("platform_name"),"systemManufacturer":asset.get("system_manufacturer"),"discoveryMethod":asset.get("discoverer_product_type_desc"),"lastSeen":asset.get("last_seen_timestamp"),"firstSeen":asset.get("first_seen_timestamp"),"isManaged":false,"riskScore":50,"complianceState":"Unknown","dataSource":"CrowdStrike Discover","lastUpdated":refreshed})
}

fn response(mut data: Data) -> Response {
    data.devices
        .retain(|device| mac(string(device, "mac_address").as_deref()).is_some());
    data.unmanaged
        .retain(|asset| mac(string(asset, "mac_address").as_deref()).is_some());
    let managed_total = data.devices.len();
    let unmanaged_total = data.unmanaged.len();
    let stats = json!({"total_devices":data.devices.len(),"with_mac":managed_total,"without_mac":data.devices.len().saturating_sub(managed_total),"unmanaged":unmanaged_total,"with_zta":data.zta.len(),"with_alerts":data.alerts.len(),"with_detections":data.detections.len(),"with_incidents":data.incidents.len(),"with_vulns":data.vulns.len()});
    let tail = json!({"total":managed_total,"totalUnmanaged":unmanaged_total,"lastRefresh":data.refreshed,"apiStatus":data.available,"stats":stats});
    let body = Body::from_stream(stream::unfold(
        (0usize, 0usize, 0usize, data, tail),
        |(phase, managed_index, unmanaged_index, data, tail)| async move {
            let next = match phase {
                0 => (
                    Bytes::from_static(b"{\"endpoints\":["),
                    (1, managed_index, unmanaged_index, data, tail),
                ),
                1 => {
                    let mut index = managed_index;
                    while index < data.devices.len()
                        && mac(string(&data.devices[index], "mac_address").as_deref()).is_none()
                    {
                        index += 1;
                    }
                    if index < data.devices.len() {
                        let prefix = if managed_index == 0 { "" } else { "," };
                        let item = managed(&data.devices[index], &data);
                        (
                            Bytes::from(format!(
                                "{}{}",
                                prefix,
                                serde_json::to_string(&item).unwrap_or_else(|_| "null".into())
                            )),
                            (1, index + 1, unmanaged_index, data, tail),
                        )
                    } else {
                        (
                            Bytes::from_static(b"],\"unmanaged\":["),
                            (2, index, unmanaged_index, data, tail),
                        )
                    }
                }
                2 => {
                    let mut index = unmanaged_index;
                    while index < data.unmanaged.len()
                        && mac(string(&data.unmanaged[index], "mac_address").as_deref()).is_none()
                    {
                        index += 1;
                    }
                    if index < data.unmanaged.len() {
                        let prefix = if unmanaged_index == 0 { "" } else { "," };
                        let item = unmanaged_record(&data.unmanaged[index], &data.refreshed);
                        (
                            Bytes::from(format!(
                                "{}{}",
                                prefix,
                                serde_json::to_string(&item).unwrap_or_else(|_| "null".into())
                            )),
                            (2, managed_index, index + 1, data, tail),
                        )
                    } else {
                        let value = serde_json::to_string(&tail).unwrap_or_else(|_| "{}".into());
                        (
                            Bytes::from(format!("],{}", &value[1..])),
                            (3, managed_index, index, data, tail),
                        )
                    }
                }
                _ => return None,
            };
            Some((Ok::<Bytes, std::convert::Infallible>(next.0), next.1))
        },
    ));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}
fn unauthorized(message: &str) -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "text/plain")
        .header("www-authenticate", r#"Basic realm="api-pagination-proxy""#)
        .body(Body::from(message.to_string()))
        .unwrap()
}
fn text(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from(message.to_string()))
        .unwrap()
}
fn error_response(error: Error) -> Response {
    match error {
        Error::Auth(status) => text(status, "CrowdStrike rejected client credentials"),
        Error::Status(status) => text(
            if status.is_client_error() {
                status
            } else {
                StatusCode::BAD_GATEWAY
            },
            "CrowdStrike request failed",
        ),
        Error::Transport | Error::Decode => {
            text(StatusCode::BAD_GATEWAY, "CrowdStrike request failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_oauth_client_credentials_from_basic_auth() {
        let header = "Basic Y2xpZW50OnNlY3JldA==".parse().unwrap();
        assert_eq!(
            credentials(Some(&header)).unwrap(),
            ("client".into(), "secret".into())
        );
    }
    #[test]
    fn normalizes_mac_addresses() {
        assert_eq!(
            mac(Some("001a.2b3c-4d5e")).as_deref(),
            Some("00:1A:2B:3C:4D:5E")
        );
        assert!(mac(Some("not-a-mac")).is_none());
    }
}
