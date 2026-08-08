use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    response::Response,
};
use bytes::Bytes;
use futures_util::{stream, StreamExt};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::{
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use url::Url;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub target: TargetConfig,
    pub pagination: PaginationConfig,
    pub response: ResponseConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetConfig {
    pub base_url: String,
    pub username_env: String,
    pub password_env: String,
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PaginationConfig {
    Offset {
        offset_parameter: String,
        page_size_parameter: String,
        start_offset: u64,
        page_size: u64,
    },
    Page {
        page_parameter: String,
        page_size_parameter: String,
        start_page: u64,
        page_size: u64,
    },
    NextLink {
        next_link_path: String,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseConfig {
    pub array_path: String,
    #[serde(default)]
    pub error_policy: ErrorPolicy,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ErrorPolicy {
    #[default]
    Terminate,
    Complete,
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("upstream request failed: {0}")]
    Upstream(String),
    #[error("upstream returned HTTP {status}: {body}")]
    UpstreamStatus { status: StatusCode, body: String },
    #[error("upstream authentication failed with HTTP {status}")]
    Authentication { status: StatusCode },
    #[error("response JSON was invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("JSON pointer {0:?} was not an array")]
    MissingArray(String),
    #[error("JSON pointer {0:?} was not a string")]
    MissingNext(String),
}

pub async fn handle(request: Request<Body>, config: Arc<Config>, client: Client) -> Response {
    let request_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let client_request = format_client_request(&request);
    let query_parameter_count = request
        .uri()
        .query()
        .map(|query| query.matches('&').count() + 1)
        .unwrap_or(0);
    info!(request_id, %method, %path, query_parameter_count, "inbound request accepted");
    if request.method() != http::Method::GET {
        warn!(request_id, %method, "rejecting unsupported HTTP method");
        return plain_error(StatusCode::METHOD_NOT_ALLOWED, "GET only");
    }
    let query = request.uri().query().unwrap_or("").to_string();
    let incoming_header_count = request.headers().len();
    let headers = forward_headers(request.headers());
    info!(
        request_id,
        incoming_header_count,
        forwarded_header_count = headers.len(),
        "prepared inbound headers for upstream"
    );
    let (tx, mut rx) = mpsc::channel::<Result<Bytes, ProxyError>>(16);
    let task_config = config.clone();
    tokio::spawn(async move {
        if let Err(error) = stream_request(
            request_id,
            &client,
            &task_config,
            &path,
            &query,
            headers,
            &client_request,
            tx.clone(),
        )
        .await
        {
            error!(
                request_id,
                error = %error_summary(&error),
                client_request = %client_request,
                "request failed"
            );
            let _ = tx.send(Err(error)).await;
        } else {
            info!(request_id, "request completed successfully");
        }
    });
    let first_chunk = match rx.recv().await {
        Some(Ok(chunk)) => chunk,
        Some(Err(error)) => return error_response(&error),
        None => return plain_error(StatusCode::BAD_GATEWAY, "upstream returned no response"),
    };
    let body = Body::from_stream(
        stream::once(async move { Ok::<Bytes, ProxyError>(first_chunk) })
            .chain(stream::unfold(rx, |mut rx| async {
                rx.recv().await.map(|item| (item, rx))
            })),
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(body)
        .unwrap()
}

pub fn load_config(path: &str) -> Result<Config, ProxyError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ProxyError::Config(e.to_string()))?;
    serde_yaml::from_str(&raw).map_err(|e| ProxyError::Config(e.to_string()))
}

async fn stream_request(
    request_id: u64,
    client: &Client,
    config: &Config,
    path: &str,
    query: &str,
    headers: HeaderMap,
    client_request: &str,
    tx: mpsc::Sender<Result<Bytes, ProxyError>>,
) -> Result<(), ProxyError> {
    info!(request_id, mode = pagination_mode(&config.pagination), array_path = %config.response.array_path, error_policy = error_policy_name(&config.response.error_policy), "starting paginated upstream request");
    let username = match env::var(&config.target.username_env) {
        Ok(value) => value,
        Err(_) => {
            error!(request_id, username_env = %config.target.username_env, "username environment variable is missing or invalid");
            return Err(ProxyError::Config(format!(
                "missing or invalid {}",
                config.target.username_env
            )));
        }
    };
    let password = match env::var(&config.target.password_env) {
        Ok(value) => value,
        Err(_) => {
            error!(request_id, password_env = %config.target.password_env, "password environment variable is missing or invalid");
            return Err(ProxyError::Config(format!(
                "missing or invalid {}",
                config.target.password_env
            )));
        }
    };
    info!(
        request_id,
        username_env = %config.target.username_env,
        password_env = %config.target.password_env,
        username = %masked_credential(&username),
        password = %masked_credential(&password),
        "loaded outbound credential variables"
    );
    let mut query_pairs: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    match &config.pagination {
        PaginationConfig::Offset {
            offset_parameter,
            page_size_parameter,
            start_offset,
            page_size,
        } => {
            set_query(
                &mut query_pairs,
                offset_parameter,
                &start_offset.to_string(),
            );
            set_query(
                &mut query_pairs,
                page_size_parameter,
                &page_size.to_string(),
            );
        }
        PaginationConfig::Page {
            page_parameter,
            page_size_parameter,
            start_page,
            page_size,
        } => {
            set_query(&mut query_pairs, page_parameter, &start_page.to_string());
            set_query(
                &mut query_pairs,
                page_size_parameter,
                &page_size.to_string(),
            );
        }
        PaginationConfig::NextLink { .. } => {}
    }
    let mut next_url: Option<String> = None;
    let mut first = true;
    let mut started = false;
    let mut emitted = false;
    let mut suffix = Bytes::new();
    let mut page_number = 0u64;
    loop {
        page_number += 1;
        let url = if let Some(next) = next_url.take() {
            next
        } else {
            build_url(&config.target.base_url, path, &query_pairs)?
        };
        info!(request_id, page_number, target_path = %path, query_parameter_count = query_pairs.len(), "dispatching upstream page request");
        let mut request = client.get(&url).basic_auth(&username, Some(&password));
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        let status = response.status();
        let upstream_headers = response.headers().clone();
        debug!(request_id, page_number, status = %status, "received upstream HTTP response");
        let body = response
            .text()
            .await
            .map_err(|e| ProxyError::Upstream(e.to_string()))?;
        if !status.is_success() {
            log_upstream_response_diagnostics(
                request_id,
                client_request,
                &upstream_headers,
                &body,
                "upstream returned an unsuccessful HTTP status",
            );
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                error!(request_id, page_number, status = %status, username_env = %config.target.username_env, "upstream rejected configured credentials");
                return handle_error(
                    config,
                    tx,
                    ProxyError::Authentication { status },
                    started,
                    suffix.clone(),
                )
                .await;
            }
            warn!(request_id, page_number, status = %status, "upstream returned an error response");
            return handle_error(
                config,
                tx,
                ProxyError::UpstreamStatus { status, body },
                started,
                suffix.clone(),
            )
            .await;
        }
        let document: Value = match serde_json::from_str(&body) {
            Ok(document) => document,
            Err(error) => {
                log_upstream_response_diagnostics(
                    request_id,
                    client_request,
                    &upstream_headers,
                    &body,
                    "upstream payload could not be parsed as JSON",
                );
                return Err(ProxyError::Json(error));
            }
        };
        let items = document
            .pointer(&config.response.array_path)
            .and_then(Value::as_array)
            .ok_or_else(|| {
                log_upstream_response_diagnostics(
                    request_id,
                    client_request,
                    &upstream_headers,
                    &body,
                    "configured response array was missing or not an array",
                );
                ProxyError::MissingArray(config.response.array_path.clone())
            })?;
        info!(
            request_id,
            page_number,
            item_count = items.len(),
            body_bytes = body.len(),
            "parsed upstream page"
        );
        if first {
            let (prefix, response_suffix) = split_document(&document, &config.response.array_path)?;
            suffix = response_suffix;
            send(&tx, prefix).await?;
            started = true;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    send(&tx, Bytes::from(",")).await?;
                }
                send(&tx, serde_json::to_vec(item)?.into()).await?;
                emitted = true;
            }
            first = false;
        } else {
            // The first page already emitted the containing array's brackets. Append only items.
            for item in items {
                if emitted {
                    send(&tx, Bytes::from(",")).await?;
                }
                send(&tx, serde_json::to_vec(item)?.into()).await?;
                emitted = true;
            }
        }
        match &config.pagination {
            PaginationConfig::Offset {
                offset_parameter,
                page_size_parameter,
                start_offset,
                page_size,
            } => {
                let current = query_pairs
                    .iter()
                    .find(|(k, _)| k == offset_parameter)
                    .and_then(|(_, v)| v.parse::<u64>().ok())
                    .unwrap_or(*start_offset);
                if items.len() < *page_size as usize {
                    info!(
                        request_id,
                        page_number,
                        item_count = items.len(),
                        page_size,
                        "offset pagination complete: short page"
                    );
                    break;
                }
                set_query(
                    &mut query_pairs,
                    offset_parameter,
                    &(current + *page_size).to_string(),
                );
                set_query(
                    &mut query_pairs,
                    page_size_parameter,
                    &page_size.to_string(),
                );
            }
            PaginationConfig::Page {
                page_parameter,
                page_size_parameter,
                start_page,
                page_size,
            } => {
                let current = query_pairs
                    .iter()
                    .find(|(k, _)| k == page_parameter)
                    .and_then(|(_, v)| v.parse::<u64>().ok())
                    .unwrap_or(*start_page);
                if items.len() < *page_size as usize {
                    info!(
                        request_id,
                        page_number,
                        item_count = items.len(),
                        page_size,
                        "page pagination complete: short page"
                    );
                    break;
                }
                set_query(&mut query_pairs, page_parameter, &(current + 1).to_string());
                set_query(
                    &mut query_pairs,
                    page_size_parameter,
                    &page_size.to_string(),
                );
            }
            PaginationConfig::NextLink { next_link_path } => {
                next_url = match document.pointer(next_link_path) {
                    None | Some(Value::Null) => None,
                    Some(Value::String(value)) => Some(value.clone()),
                    _ => {
                        log_upstream_response_diagnostics(
                            request_id,
                            client_request,
                            &upstream_headers,
                            &body,
                            "configured next-page link was not a string",
                        );
                        return Err(ProxyError::MissingNext(next_link_path.clone()));
                    }
                };
                if next_url.is_none() {
                    info!(
                        request_id,
                        page_number, "next-link pagination complete: no next link"
                    );
                    break;
                }
                debug!(
                    request_id,
                    page_number, "next-link pagination found another page"
                );
            }
        }
    }
    if !first {
        send(&tx, suffix).await?;
    }
    info!(
        request_id,
        pages = page_number,
        items_emitted = emitted,
        "streamed consolidated JSON response"
    );
    Ok(())
}

async fn handle_error(
    config: &Config,
    tx: mpsc::Sender<Result<Bytes, ProxyError>>,
    error: ProxyError,
    emitted: bool,
    suffix: Bytes,
) -> Result<(), ProxyError> {
    if matches!(&error, ProxyError::Authentication { .. }) {
        error!(error = %error_summary(&error), "propagating authentication failure to client");
        return Err(error);
    }
    match config.response.error_policy {
        ErrorPolicy::Complete if emitted => {
            warn!(error = %error_summary(&error), "completing partial response after upstream error");
            send(&tx, suffix).await?;
            Ok(())
        }
        _ => {
            error!(error = %error_summary(&error), "terminating response after upstream error");
            Err(error)
        }
    }
}

async fn send(
    tx: &mpsc::Sender<Result<Bytes, ProxyError>>,
    bytes: Bytes,
) -> Result<(), ProxyError> {
    tx.send(Ok(bytes))
        .await
        .map_err(|_| ProxyError::Upstream("caller disconnected".into()))
}

fn build_url(base: &str, path: &str, pairs: &[(String, String)]) -> Result<String, ProxyError> {
    let mut url = Url::parse(base).map_err(|e| ProxyError::Config(e.to_string()))?;
    url.set_path(path);
    url.set_query(Some(
        &url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish(),
    ));
    Ok(url.to_string())
}

fn set_query(pairs: &mut Vec<(String, String)>, key: &str, value: &str) {
    pairs.retain(|(name, _)| name != key);
    pairs.push((key.into(), value.into()));
}

fn forward_headers(input: &HeaderMap) -> HeaderMap {
    input
        .iter()
        .filter(|(name, _)| {
            let lower = name.as_str().to_ascii_lowercase();
            lower != "host"
                && lower != "authorization"
                && lower != "proxy-authorization"
                && lower != "accept-encoding"
                && !lower.contains("auth")
                && !lower.contains("token")
                && !lower.contains("credential")
        })
        .fold(HeaderMap::new(), |mut output, (name, value)| {
            output.append(name, value.clone());
            output
        })
}

fn plain_error(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .body(Body::from(message.to_string()))
        .unwrap()
}

fn format_client_request(request: &Request<Body>) -> String {
    format!(
        "{} {}\n{}\nbody: <none; GET requests only>",
        request.method(),
        request.uri(),
        format_headers(request.headers()),
    )
}

fn format_headers(headers: &HeaderMap) -> String {
    if headers.is_empty() {
        return "headers: <none>".into();
    }
    let mut output = String::from("headers:");
    for (name, value) in headers {
        output.push_str("\n");
        output.push_str(name.as_str());
        output.push_str(": ");
        output.push_str(value.to_str().unwrap_or("<non-UTF-8 header value>"));
    }
    output
}

fn format_payload(payload: &str) -> String {
    if payload.is_empty() {
        return "<empty>".into();
    }
    let mut output = String::with_capacity(payload.len() + payload.len() / 60);
    let mut line_width = 0;
    for character in payload.chars() {
        if character == '\n' {
            output.push(character);
            line_width = 0;
            continue;
        }
        if line_width == 60 {
            output.push('\n');
            line_width = 0;
        }
        output.push(character);
        line_width += 1;
    }
    output
}

fn log_upstream_response_diagnostics(
    request_id: u64,
    client_request: &str,
    upstream_headers: &HeaderMap,
    upstream_payload: &str,
    reason: &str,
) {
    error!(
        request_id,
        reason,
        client_request = %client_request,
        upstream_response_headers = %format_headers(upstream_headers),
        upstream_payload = %format_payload(upstream_payload),
        "upstream response diagnostics"
    );
}

fn error_response(error: &ProxyError) -> Response {
    let status = match error {
        ProxyError::Authentication { status } => *status,
        ProxyError::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_GATEWAY,
    };
    plain_error(status, &error_summary(error))
}

fn pagination_mode(pagination: &PaginationConfig) -> &'static str {
    match pagination {
        PaginationConfig::Offset { .. } => "offset",
        PaginationConfig::Page { .. } => "page",
        PaginationConfig::NextLink { .. } => "next_link",
    }
}

fn error_policy_name(policy: &ErrorPolicy) -> &'static str {
    match policy {
        ErrorPolicy::Terminate => "terminate",
        ErrorPolicy::Complete => "complete",
    }
}

fn error_summary(error: &ProxyError) -> String {
    match error {
        ProxyError::UpstreamStatus { status, .. } => format!("upstream HTTP status {status}"),
        ProxyError::Authentication { status } => {
            format!("upstream authentication failed with HTTP status {status}")
        }
        ProxyError::Config(message) => format!("configuration error: {message}"),
        ProxyError::Upstream(_) => "upstream transport error".into(),
        ProxyError::Json(_) => "invalid upstream JSON".into(),
        ProxyError::MissingArray(path) => format!("missing array at JSON pointer {path:?}"),
        ProxyError::MissingNext(path) => format!("invalid next link at JSON pointer {path:?}"),
    }
}

fn masked_credential(value: &str) -> String {
    format!("{}******", value.chars().take(3).collect::<String>())
}

fn split_document(document: &Value, pointer: &str) -> Result<(Bytes, Bytes), ProxyError> {
    let array = document
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| ProxyError::MissingArray(pointer.into()))?;
    let mut prefix_doc = document.clone();
    let mut suffix_doc = document.clone();
    replace_pointer(
        &mut prefix_doc,
        pointer,
        Value::String("__STREAM_ARRAY__".into()),
    )?;
    replace_pointer(
        &mut suffix_doc,
        pointer,
        Value::String("__STREAM_ARRAY_END__".into()),
    )?;
    let serialized_prefix = String::from_utf8(serde_json::to_vec(&prefix_doc)?).unwrap();
    let marker = "\"__STREAM_ARRAY__\"";
    let marker_start = serialized_prefix
        .find(marker)
        .ok_or_else(|| ProxyError::MissingArray(pointer.into()))?;
    let prefix = format!("{}[", &serialized_prefix[..marker_start]);
    let serialized_suffix = String::from_utf8(serde_json::to_vec(&suffix_doc)?).unwrap();
    let end_marker = "\"__STREAM_ARRAY_END__\"";
    let end_start = serialized_suffix
        .find(end_marker)
        .ok_or_else(|| ProxyError::MissingArray(pointer.into()))?;
    let suffix = format!("]{}", &serialized_suffix[end_start + end_marker.len()..]);
    let _ = array;
    Ok((prefix.into(), suffix.into()))
}

fn replace_pointer(root: &mut Value, pointer: &str, replacement: Value) -> Result<(), ProxyError> {
    if pointer.is_empty() {
        *root = replacement;
        return Ok(());
    }
    let (parent, key) = pointer
        .rsplit_once('/')
        .ok_or_else(|| ProxyError::MissingArray(pointer.into()))?;
    let key = key.replace("~1", "/").replace("~0", "~");
    match root.pointer_mut(parent) {
        Some(Value::Object(map)) => {
            map.insert(key, replacement);
            Ok(())
        }
        _ => Err(ProxyError::MissingArray(pointer.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::convert::Infallible;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    #[test]
    fn preserves_document_shape_around_array() {
        let document: Value = serde_json::json!({"result": [{"id": 1}], "meta": {"ok": true}});
        let (prefix, suffix) = split_document(&document, "/result").unwrap();
        let output = format!(
            "{}{}{}",
            String::from_utf8(prefix.to_vec()).unwrap(),
            serde_json::json!({"id": 1}),
            String::from_utf8(suffix.to_vec()).unwrap()
        );
        assert_eq!(serde_json::from_str::<Value>(&output).unwrap(), document);
    }

    #[test]
    fn replaces_pagination_query_keys() {
        let mut pairs = vec![
            ("sysparm_limit".into(), "100".into()),
            ("x".into(), "y".into()),
        ];
        set_query(&mut pairs, "sysparm_limit", "10");
        assert_eq!(
            pairs,
            vec![
                ("x".into(), "y".into()),
                ("sysparm_limit".into(), "10".into())
            ]
        );
    }

    #[test]
    fn filters_authentication_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("host", "local.example".parse().unwrap());
        headers.insert("authorization", "Bearer secret".parse().unwrap());
        headers.insert("accept-encoding", "gzip".parse().unwrap());
        headers.insert("x-request-id", "abc".parse().unwrap());
        let forwarded = forward_headers(&headers);
        assert!(!forwarded.contains_key("host"));
        assert!(!forwarded.contains_key("authorization"));
        assert!(!forwarded.contains_key("accept-encoding"));
        assert_eq!(forwarded.get("x-request-id").unwrap(), "abc");
    }

    #[test]
    fn masks_credentials_with_three_characters_and_six_asterisks() {
        assert_eq!(masked_credential("username"), "use******");
        assert_eq!(masked_credential("åßçdef"), "åßç******");
        assert_eq!(masked_credential("ab"), "ab******");
    }

    #[test]
    fn wraps_upstream_payload_at_sixty_characters() {
        let payload = "a".repeat(61);
        assert_eq!(format_payload(&payload), format!("{}\na", "a".repeat(60)));
    }

    #[tokio::test]
    async fn streaming_response_uses_valid_http_1_1_chunked_framing() {
        let app = Router::new().route(
            "/",
            get(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "text/plain")
                    .body(Body::from_stream(stream::iter([Ok::<Bytes, Infallible>(
                        Bytes::from_static(b"hello"),
                    )])))
                    .unwrap()
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut raw = Vec::new();
        client.read_to_end(&mut raw).await.unwrap();
        server.abort();

        let response = String::from_utf8(raw).unwrap();
        assert!(
            response
                .to_ascii_lowercase()
                .contains("transfer-encoding: chunked\r\n"),
            "raw HTTP response: {response:?}"
        );
        assert!(response.ends_with("\r\n5\r\nhello\r\n0\r\n\r\n"));
    }
}
