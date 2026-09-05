#!/usr/bin/env python3
"""
CrowdStrike to Cisco ISE On-Premises Service
Collects endpoint data from CrowdStrike Falcon APIs for ISE pxGrid Direct.

Designed for wide deployment across different CrowdStrike tenants.
APIs are auto-detected - missing scopes are handled gracefully.

REQUIRED Environment Variables:
  CS_CLIENT_ID     = Your CrowdStrike API Client ID
  CS_CLIENT_SECRET = Your CrowdStrike API Client Secret

OPTIONAL Environment Variables:
  CS_BASE_URL      = API base URL (default: https://api.crowdstrike.com)
                     US-1: https://api.crowdstrike.com
                     US-2: https://api.us-2.crowdstrike.com
                     EU-1: https://api.eu-1.crowdstrike.com
                     GOV:  https://api.laggar.gcw.crowdstrike.com
  CS_OUTPUT_DIR    = Output directory (default: ./output)
  CS_LOOKBACK_DAYS = Days of history for alerts/incidents (default: 7)

REQUIRED API Scopes:
  - Hosts: READ (required)

OPTIONAL API Scopes (auto-detected):
  - Zero Trust Assessment: READ
  - Alerts: READ
  - Detections: READ
  - Incidents: READ
  - Prevention Policies: READ
  - Sensor Update Policies: READ
  - Host Groups: READ
  - Spotlight Vulnerabilities: READ
  - Discover (Asset Discovery): READ
"""

import os
import sys
import time
import json
import logging
import platform
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

# Credentials (from environment)
CS_CLIENT_ID = os.getenv("CS_CLIENT_ID", "")
CS_CLIENT_SECRET = os.getenv("CS_CLIENT_SECRET", "")
CS_BASE_URL = os.getenv("CS_BASE_URL", "https://api.crowdstrike.com")

# Directories
BASE_DIR = Path(__file__).parent.absolute()
OUTPUT_DIR = Path(os.getenv("CS_OUTPUT_DIR", str(BASE_DIR / "output")))
OUTPUT_FILE = OUTPUT_DIR / "endpoints.json"
LOGS_DIR = BASE_DIR / "logs"
LOG_FILE = LOGS_DIR / "onpremservice.log"

# API Settings
API_PAGE_SIZE = 100
API_TIMEOUT = 120
LOOKBACK_DAYS = int(os.getenv("CS_LOOKBACK_DAYS", "7"))

# Feature Flags
# Set to False to skip even if API scope is available
# Set to True to attempt (will auto-skip if scope missing)
ENABLE_ZTA = True                  # Zero Trust Assessment scores
ENABLE_ALERTS = True               # Security alerts
ENABLE_DETECTIONS = True           # EDR detections
ENABLE_INCIDENTS = True            # Security incidents
ENABLE_VULN_SUMMARY = True         # Vulnerability counts per host (NOT full CVE list)
ENABLE_POLICIES = True             # Prevention and sensor policies
ENABLE_HOST_GROUPS = True          # Host group memberships
ENABLE_DISCOVER = True             # Unmanaged/discovered assets

# =============================================================================
# SETUP
# =============================================================================

LOGS_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("OnPremService")


# =============================================================================
# UTILITIES
# =============================================================================

def normalize_mac(mac):
    """Convert MAC address to ISE format (00:1A:2B:3C:4D:5E)."""
    if not mac:
        return None
    mac_clean = mac.replace("-", "").replace(":", "").replace(".", "").upper()
    if len(mac_clean) != 12:
        return None
    return ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))


def write_json(data, filepath):
    """
    Atomic JSON write with temp file.
    Works on Windows, macOS, and Linux.
    """
    filepath = Path(filepath)
    try:
        # Create temp file in same directory (ensures same filesystem for atomic move)
        fd, temp_path = tempfile.mkstemp(
            suffix=".tmp",
            prefix="endpoints_",
            dir=filepath.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # On Windows, we need to remove destination first
            # shutil.move handles this more gracefully than os.rename
            if filepath.exists():
                filepath.unlink()
            shutil.move(temp_path, filepath)
            return True
        except Exception:
            # Clean up temp file on error
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
    except Exception as e:
        logger.error("Write failed: %s", e)
        return False


# =============================================================================
# CROWDSTRIKE API CLIENT
# =============================================================================

class CrowdStrikeAPI:
    def __init__(self, base_url, client_id, client_secret):
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = None
        self.token_expiry = None
        self.session = requests.Session()
        self.available_apis = {}

    def get_token(self):
        """Get OAuth2 token with auto-refresh."""
        if self.token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.token

        logger.info("Acquiring OAuth2 token...")
        resp = self.session.post(
            self.base_url + "/oauth2/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            timeout=API_TIMEOUT
        )
        resp.raise_for_status()
        data = resp.json()

        self.token = data["access_token"]
        expires = data.get("expires_in", 1799) - 60
        self.token_expiry = datetime.now() + timedelta(seconds=expires)
        logger.info("Token acquired (expires in %d seconds)", expires)
        return self.token

    def request(self, method, endpoint, params=None, json_body=None, silent_errors=None):
        """
        Make API request with error handling.
        silent_errors: list of status codes to handle silently (for API detection)
        """
        headers = {
            "Authorization": "Bearer " + self.get_token(),
            "Content-Type": "application/json"
        }

        url = self.base_url + endpoint
        silent_errors = silent_errors or []

        try:
            resp = self.session.request(
                method, url, headers=headers,
                params=params, json=json_body,
                timeout=API_TIMEOUT
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code
            if status in silent_errors:
                return None
            if status == 400:
                logger.warning("400 Bad Request on %s", endpoint)
            elif status == 403:
                logger.warning("403 Forbidden on %s - scope not available", endpoint)
            elif status == 404:
                logger.warning("404 Not Found on %s - API not available", endpoint)
            elif status == 429:
                logger.warning("Rate limited - waiting 60s")
                time.sleep(60)
                return self.request(method, endpoint, params, json_body, silent_errors)
            else:
                logger.error("HTTP %d on %s", status, endpoint)
            return None
        except requests.exceptions.Timeout:
            logger.warning("Timeout on %s", endpoint)
            return None
        except Exception as e:
            logger.error("Request error on %s: %s", endpoint, e)
            return None

    def check_api(self, name, endpoint, params=None):
        """Check if an API endpoint is available (has required scope)."""
        resp = self.request("GET", endpoint, params=params or {"limit": 1}, silent_errors=[400, 403, 404])
        available = resp is not None and "resources" in resp
        self.available_apis[name] = available
        return available

    def get_devices(self):
        """Fetch all devices using two-step approach."""
        logger.info("Fetching devices...")

        # Step 1: Get all device IDs
        all_ids = []
        offset = 0
        total = None

        while True:
            resp = self.request("GET", "/devices/queries/devices/v1",
                               params={"limit": API_PAGE_SIZE, "offset": offset})

            if not resp:
                logger.error("Failed to query devices - check Hosts:READ scope")
                return []

            ids = resp.get("resources", [])
            all_ids.extend(ids)

            if total is None:
                total = resp.get("meta", {}).get("pagination", {}).get("total", len(ids))

            offset += API_PAGE_SIZE
            if offset >= total or not ids:
                break

            if len(all_ids) % 500 == 0:
                logger.info("  ... fetched %d/%d device IDs", len(all_ids), total)

        if not all_ids:
            logger.warning("No devices found")
            return []

        logger.info("  Found %d device IDs, fetching details...", len(all_ids))

        # Step 2: Get device details in batches
        devices = []
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            resp = self.request("POST", "/devices/entities/devices/v2",
                               json_body={"ids": batch})
            if resp:
                devices.extend(resp.get("resources", []))

            if len(devices) % 500 == 0 and len(devices) > 0:
                logger.info("  ... fetched details for %d/%d devices", len(devices), len(all_ids))

        logger.info("  Retrieved %d devices", len(devices))
        return devices

    def get_zta(self, device_ids):
        """Fetch Zero Trust Assessment scores."""
        if not ENABLE_ZTA or not device_ids:
            return {}

        if not self.check_api("zta", "/zero-trust-assessment/entities/assessments/v1", {"ids": device_ids[:1]}):
            logger.info("  ZTA API not available - skipping")
            return {}

        logger.info("Fetching ZTA scores for %d devices...", len(device_ids))
        result = {}

        for i in range(0, len(device_ids), 100):
            batch = device_ids[i:i+100]
            resp = self.request("GET", "/zero-trust-assessment/entities/assessments/v1",
                               params={"ids": batch})
            if resp:
                for item in resp.get("resources", []):
                    aid = item.get("aid")
                    if aid:
                        result[aid] = item

        logger.info("  Found %d ZTA scores", len(result))
        return result

    def get_alerts(self):
        """Fetch recent security alerts."""
        if not ENABLE_ALERTS:
            return {}

        if not self.check_api("alerts", "/alerts/queries/alerts/v2"):
            logger.info("  Alerts API not available - skipping")
            return {}

        logger.info("Fetching alerts (last %d days)...", LOOKBACK_DAYS)
        cutoff = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = "created_timestamp:>'" + cutoff + "'"

        # Get alert IDs
        all_ids = []
        offset = 0
        total = None

        while True:
            resp = self.request("GET", "/alerts/queries/alerts/v2",
                               params={"filter": filter_str, "limit": API_PAGE_SIZE, "offset": offset})
            if not resp:
                break

            ids = resp.get("resources", [])
            all_ids.extend(ids)

            if total is None:
                total = resp.get("meta", {}).get("pagination", {}).get("total", len(ids))

            offset += API_PAGE_SIZE
            if offset >= total or not ids:
                break

        if not all_ids:
            logger.info("  No alerts found")
            return {}

        # Get alert details
        result = {}
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            resp = self.request("POST", "/alerts/entities/alerts/v2",
                               json_body={"composite_ids": batch})
            if resp:
                for alert in resp.get("resources", []):
                    dev_id = alert.get("device", {}).get("device_id")
                    if dev_id:
                        if dev_id not in result:
                            result[dev_id] = []
                        result[dev_id].append(alert)

        logger.info("  Found alerts for %d devices", len(result))
        return result

    def get_detections(self):
        """Fetch recent EDR detections."""
        if not ENABLE_DETECTIONS:
            return {}

        if not self.check_api("detections", "/detects/queries/detects/v1"):
            logger.info("  Detections API not available - skipping")
            return {}

        logger.info("Fetching detections (last %d days)...", LOOKBACK_DAYS)
        cutoff = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = "created_timestamp:>'" + cutoff + "'"

        # Get detection IDs
        all_ids = []
        offset = 0
        total = None

        while True:
            resp = self.request("GET", "/detects/queries/detects/v1",
                               params={"filter": filter_str, "limit": API_PAGE_SIZE, "offset": offset})
            if not resp:
                break

            ids = resp.get("resources", [])
            all_ids.extend(ids)

            if total is None:
                total = resp.get("meta", {}).get("pagination", {}).get("total", len(ids))

            offset += API_PAGE_SIZE
            if offset >= total or not ids:
                break

        if not all_ids:
            logger.info("  No detections found")
            return {}

        # Get detection details
        result = {}
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            resp = self.request("POST", "/detects/entities/summaries/GET/v1",
                               json_body={"ids": batch})
            if resp:
                for det in resp.get("resources", []):
                    dev_id = det.get("device", {}).get("device_id")
                    if dev_id:
                        if dev_id not in result:
                            result[dev_id] = []
                        result[dev_id].append(det)

        logger.info("  Found detections for %d devices", len(result))
        return result

    def get_incidents(self):
        """Fetch recent security incidents."""
        if not ENABLE_INCIDENTS:
            return {}

        if not self.check_api("incidents", "/incidents/queries/incidents/v1"):
            logger.info("  Incidents API not available - skipping")
            return {}

        logger.info("Fetching incidents (last %d days)...", LOOKBACK_DAYS)
        cutoff = (datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = "start:>'" + cutoff + "'"

        # Get incident IDs
        all_ids = []
        offset = 0
        total = None

        while True:
            resp = self.request("GET", "/incidents/queries/incidents/v1",
                               params={"filter": filter_str, "limit": API_PAGE_SIZE, "offset": offset})
            if not resp:
                break

            ids = resp.get("resources", [])
            all_ids.extend(ids)

            if total is None:
                total = resp.get("meta", {}).get("pagination", {}).get("total", len(ids))

            offset += API_PAGE_SIZE
            if offset >= total or not ids:
                break

        if not all_ids:
            logger.info("  No incidents found")
            return {}

        # Get incident details
        result = {}
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            resp = self.request("POST", "/incidents/entities/incidents/GET/v1",
                               json_body={"ids": batch})
            if resp:
                for inc in resp.get("resources", []):
                    for host in inc.get("hosts", []):
                        dev_id = host.get("device_id")
                        if dev_id:
                            if dev_id not in result:
                                result[dev_id] = []
                            result[dev_id].append(inc)

        logger.info("  Found incidents for %d devices", len(result))
        return result

    def get_vulnerability_summary(self, device_ids):
        """
        Fetch vulnerability SUMMARY per host (counts by severity, max CVSS).
        Uses Spotlight host-info API - much faster than fetching individual CVEs.
        """
        if not ENABLE_VULN_SUMMARY or not device_ids:
            return {}

        if not self.check_api("spotlight", "/spotlight/queries/vulnerabilities/v1"):
            logger.info("  Spotlight API not available - skipping vulnerability summary")
            return {}

        logger.info("Fetching vulnerability summary for %d devices...", len(device_ids))

        # Query vulnerabilities grouped by host with severity counts
        # We'll aggregate CVSS scores per device
        result = {}

        # Process in batches of device IDs
        for i in range(0, len(device_ids), 50):
            batch = device_ids[i:i+50]
            # Create FQL filter for these device IDs
            aids_filter = ",".join(["'" + aid + "'" for aid in batch])
            filter_str = "aid:[" + aids_filter + "]+status:'open'"

            # Get vulnerability IDs for these hosts (limited to critical/high for speed)
            resp = self.request("GET", "/spotlight/queries/vulnerabilities/v1",
                               params={"filter": filter_str, "limit": 5000})

            if not resp or not resp.get("resources"):
                continue

            vuln_ids = resp.get("resources", [])

            # Get vulnerability details
            for j in range(0, len(vuln_ids), 400):
                vuln_batch = vuln_ids[j:j+400]
                details = self.request("GET", "/spotlight/entities/vulnerabilities/v2",
                                       params={"ids": vuln_batch})

                if not details:
                    continue

                for vuln in details.get("resources", []):
                    aid = vuln.get("aid")
                    if not aid:
                        continue

                    if aid not in result:
                        result[aid] = {
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "total": 0,
                            "max_cvss": 0.0,
                            "cves": []
                        }

                    # Get CVSS score
                    cve = vuln.get("cve", {})
                    cvss = cve.get("base_score", 0) or 0

                    result[aid]["total"] += 1
                    result[aid]["max_cvss"] = max(result[aid]["max_cvss"], cvss)

                    # Categorize by severity
                    if cvss >= 9.0:
                        result[aid]["critical"] += 1
                        if len(result[aid]["cves"]) < 5:
                            result[aid]["cves"].append(cve.get("id", ""))
                    elif cvss >= 7.0:
                        result[aid]["high"] += 1
                    elif cvss >= 4.0:
                        result[aid]["medium"] += 1
                    else:
                        result[aid]["low"] += 1

            if (i + 50) % 200 == 0:
                logger.info("  ... processed %d/%d devices", min(i+50, len(device_ids)), len(device_ids))

        logger.info("  Found vulnerabilities for %d devices", len(result))
        return result

    def get_policies(self):
        """Fetch prevention and sensor update policies."""
        if not ENABLE_POLICIES:
            return {}, {}

        logger.info("Fetching policies...")
        prevention = {}
        sensor = {}

        # Prevention policies
        if self.check_api("prevention_policy", "/policy/queries/prevention/v1"):
            resp = self.request("GET", "/policy/combined/prevention/v1", params={"limit": 500})
            if resp:
                for p in resp.get("resources", []):
                    if p.get("id"):
                        prevention[p["id"]] = {"name": p.get("name"), "enabled": p.get("enabled", True)}

        # Sensor update policies
        if self.check_api("sensor_policy", "/policy/queries/sensor-update/v1"):
            resp = self.request("GET", "/policy/combined/sensor-update/v2", params={"limit": 500})
            if resp:
                for p in resp.get("resources", []):
                    if p.get("id"):
                        sensor[p["id"]] = {"name": p.get("name"), "enabled": p.get("enabled", True)}

        logger.info("  Found %d prevention, %d sensor policies", len(prevention), len(sensor))
        return prevention, sensor

    def get_host_groups(self):
        """Fetch host groups."""
        if not ENABLE_HOST_GROUPS:
            return {}

        if not self.check_api("host_groups", "/devices/queries/host-groups/v1"):
            logger.info("  Host Groups API not available - skipping")
            return {}

        logger.info("Fetching host groups...")
        result = {}

        resp = self.request("GET", "/devices/combined/host-groups/v1", params={"limit": 500})
        if resp:
            for g in resp.get("resources", []):
                if g.get("id"):
                    result[g["id"]] = {"name": g.get("name"), "description": g.get("description")}

        logger.info("  Found %d host groups", len(result))
        return result

    def get_unmanaged_assets(self):
        """Fetch discovered/unmanaged assets from Falcon Discover."""
        if not ENABLE_DISCOVER:
            return []

        if not self.check_api("discover", "/discover/queries/hosts/v1"):
            logger.info("  Discover API not available - skipping")
            return []

        logger.info("Fetching unmanaged assets...")

        # Get unmanaged asset IDs
        all_ids = []
        offset = 0

        while True:
            resp = self.request("GET", "/discover/queries/hosts/v1",
                               params={"filter": "entity_type:'unmanaged'", "limit": API_PAGE_SIZE, "offset": offset})
            if not resp:
                break

            ids = resp.get("resources", [])
            all_ids.extend(ids)

            total = resp.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += API_PAGE_SIZE
            if offset >= total or not ids:
                break

        if not all_ids:
            logger.info("  No unmanaged assets found")
            return []

        # Get asset details
        assets = []
        for i in range(0, len(all_ids), 100):
            batch = all_ids[i:i+100]
            resp = self.request("GET", "/discover/entities/hosts/v1",
                               params={"ids": batch})
            if resp:
                assets.extend(resp.get("resources", []))

        logger.info("  Found %d unmanaged assets", len(assets))
        return assets


# =============================================================================
# TRANSFORMATION
# =============================================================================

def calc_risk(zta, alerts, detections, incidents, vulns):
    """
    Calculate risk score (0-100) based on multiple factors.
    Higher score = higher risk.
    """
    score = 0

    # ZTA score (inverted - lower ZTA = higher risk) - 30% weight
    if zta:
        zta_score = zta.get("assessment", {}).get("overall", 100)
        score += (100 - zta_score) * 0.3

    # Alerts by severity - up to 25 points
    for a in alerts:
        sev = str(a.get("severity", "")).lower()
        if sev == "critical":
            score += 12
        elif sev == "high":
            score += 8
        elif sev == "medium":
            score += 3

    # Detections by severity - up to 25 points
    for d in detections:
        sev = str(d.get("max_severity_displayname", "")).lower()
        if "critical" in sev:
            score += 12
        elif "high" in sev:
            score += 8
        elif "medium" in sev:
            score += 3

    # Incidents - 10 points each
    score += len(incidents) * 10

    # Vulnerabilities - based on CVSS
    if vulns:
        score += vulns.get("critical", 0) * 5
        score += vulns.get("high", 0) * 2
        score += min(vulns.get("max_cvss", 0), 10)

    return min(int(score), 100)


def transform_device(device, data):
    """Transform CrowdStrike device data to ISE-compatible format."""
    dev_id = device.get("device_id")

    # Get related data
    zta = data["zta"].get(dev_id, {})
    alerts = data["alerts"].get(dev_id, [])
    detections = data["detections"].get(dev_id, [])
    incidents = data["incidents"].get(dev_id, [])
    vulns = data["vulns"].get(dev_id, {})

    # Policy details
    policies = device.get("device_policies", {})
    prev = policies.get("prevention", {})
    sens = policies.get("sensor_update", {})

    prev_info = data["prev_policies"].get(prev.get("policy_id"), {})
    sens_info = data["sens_policies"].get(sens.get("policy_id"), {})

    # Host groups
    group_ids = device.get("groups", [])
    group_names = [data["groups"].get(gid, {}).get("name", "") for gid in group_ids if data["groups"].get(gid)]

    # Counts
    alert_crit = sum(1 for a in alerts if str(a.get("severity", "")).lower() == "critical")
    alert_high = sum(1 for a in alerts if str(a.get("severity", "")).lower() == "high")
    det_crit = sum(1 for d in detections if "critical" in str(d.get("max_severity_displayname", "")).lower())
    det_high = sum(1 for d in detections if "high" in str(d.get("max_severity_displayname", "")).lower())

    # Risk score
    risk = calc_risk(zta, alerts, detections, incidents, vulns)

    # Compliance state based on risk
    if risk >= 70:
        compliance = "Critical"
    elif risk >= 50:
        compliance = "NonCompliant"
    elif risk >= 30:
        compliance = "Warning"
    else:
        compliance = "Compliant"

    return {
        # ===== IDENTIFIERS (for ISE correlation) =====
        "assetId": dev_id,
        "assetMacAddress": normalize_mac(device.get("mac_address")),
        "assetIpAddress": device.get("local_ip"),
        "assetExternalIp": device.get("external_ip"),
        "assetHostname": device.get("hostname"),

        # ===== DEVICE INFO =====
        "osVersion": device.get("os_version"),
        "platformName": device.get("platform_name"),
        "platformId": device.get("platform_id"),
        "systemManufacturer": device.get("system_manufacturer"),
        "systemProductName": device.get("system_product_name"),
        "serialNumber": device.get("serial_number"),
        "biosVersion": device.get("bios_version"),
        "machineDomain": device.get("machine_domain"),
        "ou": device.get("ou"),
        "siteName": device.get("site_name"),

        # ===== AGENT INFO =====
        "agentVersion": device.get("agent_version"),
        "agentLocalTime": device.get("agent_local_time"),
        "lastSeen": device.get("last_seen"),
        "firstSeen": device.get("first_seen"),
        "deviceStatus": device.get("status"),
        "containmentStatus": device.get("containment_status", "normal"),
        "reducedFunctionalityMode": device.get("reduced_functionality_mode"),

        # ===== ZERO TRUST ASSESSMENT =====
        "ztaOverallScore": zta.get("assessment", {}).get("overall"),
        "ztaSensorStatus": zta.get("assessment", {}).get("sensor_file_status"),
        "ztaOsStatus": zta.get("assessment", {}).get("os_signals_status"),

        # ===== POLICIES =====
        "preventionPolicyId": prev.get("policy_id"),
        "preventionPolicyName": prev_info.get("name"),
        "preventionPolicyApplied": prev.get("applied", False),
        "sensorPolicyId": sens.get("policy_id"),
        "sensorPolicyName": sens_info.get("name"),
        "sensorPolicyApplied": sens.get("applied", False),

        # ===== HOST GROUPS =====
        "hostGroupIds": ",".join(group_ids) if group_ids else None,
        "hostGroupNames": ",".join(group_names) if group_names else None,

        # ===== ALERTS =====
        "alertCriticalCount": alert_crit,
        "alertHighCount": alert_high,
        "alertTotalCount": len(alerts),
        "hasCriticalAlert": alert_crit > 0,
        "hasHighAlert": alert_high > 0,

        # ===== DETECTIONS =====
        "detectionCriticalCount": det_crit,
        "detectionHighCount": det_high,
        "detectionTotalCount": len(detections),
        "hasCriticalDetection": det_crit > 0,
        "hasHighDetection": det_high > 0,

        # ===== INCIDENTS =====
        "incidentCount": len(incidents),
        "hasActiveIncident": len(incidents) > 0,

        # ===== VULNERABILITIES (summary) =====
        "vulnCriticalCount": vulns.get("critical", 0),
        "vulnHighCount": vulns.get("high", 0),
        "vulnMediumCount": vulns.get("medium", 0),
        "vulnLowCount": vulns.get("low", 0),
        "vulnTotalCount": vulns.get("total", 0),
        "vulnMaxCvss": vulns.get("max_cvss", 0.0),
        "vulnTopCves": ",".join(vulns.get("cves", []))[:200] if vulns.get("cves") else None,
        "hasCriticalVuln": vulns.get("critical", 0) > 0,
        "hasHighVuln": vulns.get("high", 0) > 0,

        # ===== RISK (for ISE policy decisions) =====
        "riskScore": risk,
        "complianceState": compliance,
        "isHighRisk": risk >= 50,
        "isCriticalRisk": risk >= 70,

        # ===== METADATA =====
        "dataSource": "CrowdStrike Falcon",
        "lastUpdated": datetime.utcnow().isoformat() + "Z"
    }


def transform_unmanaged(asset):
    """Transform discovered/unmanaged asset to ISE format."""
    return {
        "assetId": asset.get("id"),
        "assetMacAddress": normalize_mac(asset.get("mac_address")),
        "assetIpAddress": asset.get("local_ip_addresses", [None])[0] if asset.get("local_ip_addresses") else None,
        "assetHostname": asset.get("hostname"),
        "osVersion": asset.get("os_version"),
        "platformName": asset.get("platform_name"),
        "systemManufacturer": asset.get("system_manufacturer"),
        "discoveryMethod": asset.get("discoverer_product_type_desc"),
        "lastSeen": asset.get("last_seen_timestamp"),
        "firstSeen": asset.get("first_seen_timestamp"),
        "isManaged": False,
        "riskScore": 50,
        "complianceState": "Unknown",
        "dataSource": "CrowdStrike Discover",
        "lastUpdated": datetime.utcnow().isoformat() + "Z"
    }


# =============================================================================
# MAIN
# =============================================================================

def main():
    print()
    print("=" * 60)
    print("  CrowdStrike to Cisco ISE On-Premises Service")
    print("=" * 60)
    print()

    logger.info("STARTING DATA COLLECTION")
    logger.info("-" * 50)
    logger.info("Platform: %s %s", platform.system(), platform.release())
    logger.info("Python:   %s", platform.python_version())

    if not CS_CLIENT_ID or not CS_CLIENT_SECRET:
        logger.error("ERROR: CS_CLIENT_ID and CS_CLIENT_SECRET required!")
        logger.error("")
        logger.error("Set environment variables:")
        if platform.system() == "Windows":
            logger.error("  Command Prompt:")
            logger.error("    set CS_CLIENT_ID=your_id")
            logger.error("    set CS_CLIENT_SECRET=your_secret")
            logger.error("  PowerShell:")
            logger.error("    $env:CS_CLIENT_ID = 'your_id'")
            logger.error("    $env:CS_CLIENT_SECRET = 'your_secret'")
        else:
            logger.error("  export CS_CLIENT_ID='your_id'")
            logger.error("  export CS_CLIENT_SECRET='your_secret'")
        sys.exit(1)

    logger.info("Base URL:     %s", CS_BASE_URL)
    logger.info("Output:       %s", str(OUTPUT_FILE).replace("\\", "/"))
    logger.info("Lookback:     %d days", LOOKBACK_DAYS)
    logger.info("")

    start = time.time()

    try:
        api = CrowdStrikeAPI(CS_BASE_URL, CS_CLIENT_ID, CS_CLIENT_SECRET)

        # Fetch devices (required)
        devices = api.get_devices()

        if not devices:
            logger.error("No devices found! Check API credentials and Hosts:READ scope")
            sys.exit(1)

        dev_ids = [d.get("device_id") for d in devices if d.get("device_id")]
        logger.info("")

        # Fetch supporting data (auto-detects availability)
        prev_pol, sens_pol = api.get_policies()

        data = {
            "zta": api.get_zta(dev_ids),
            "alerts": api.get_alerts(),
            "detections": api.get_detections(),
            "incidents": api.get_incidents(),
            "vulns": api.get_vulnerability_summary(dev_ids),
            "prev_policies": prev_pol,
            "sens_policies": sens_pol,
            "groups": api.get_host_groups()
        }

        # Fetch unmanaged assets (optional)
        unmanaged = api.get_unmanaged_assets()

        logger.info("")
        logger.info("Transforming %d devices...", len(devices))

        endpoints = []
        no_mac = 0
        no_mac_list = []

        for device in devices:
            try:
                ep = transform_device(device, data)
                if ep.get("assetMacAddress"):
                    endpoints.append(ep)
                else:
                    no_mac += 1
                    no_mac_list.append(device.get("hostname", "unknown"))
            except Exception as e:
                logger.warning("Transform error for %s: %s", device.get("hostname"), e)

        # Transform unmanaged assets
        unmanaged_eps = []
        for asset in unmanaged:
            try:
                ep = transform_unmanaged(asset)
                if ep.get("assetMacAddress"):
                    unmanaged_eps.append(ep)
            except Exception as e:
                logger.warning("Transform error for unmanaged asset: %s", e)

        # Build output
        output = {
            "endpoints": endpoints,
            "unmanaged": unmanaged_eps,
            "total": len(endpoints),
            "totalUnmanaged": len(unmanaged_eps),
            "lastRefresh": datetime.utcnow().isoformat() + "Z",
            "apiStatus": {
                "hosts": True,
                "zta": api.available_apis.get("zta", False),
                "alerts": api.available_apis.get("alerts", False),
                "detections": api.available_apis.get("detections", False),
                "incidents": api.available_apis.get("incidents", False),
                "spotlight": api.available_apis.get("spotlight", False),
                "policies": api.available_apis.get("prevention_policy", False),
                "hostGroups": api.available_apis.get("host_groups", False),
                "discover": api.available_apis.get("discover", False)
            },
            "stats": {
                "total_devices": len(devices),
                "with_mac": len(endpoints),
                "without_mac": no_mac,
                "unmanaged": len(unmanaged_eps),
                "with_zta": len(data["zta"]),
                "with_alerts": len(data["alerts"]),
                "with_detections": len(data["detections"]),
                "with_incidents": len(data["incidents"]),
                "with_vulns": len(data["vulns"])
            }
        }

        if no_mac_list:
            logger.info("  Devices without MAC: %s", ", ".join(no_mac_list[:10]))
            if len(no_mac_list) > 10:
                logger.info("    ... and %d more", len(no_mac_list) - 10)

        logger.info("")
        logger.info("Writing JSON to %s", str(OUTPUT_FILE).replace("\\", "/"))

        if write_json(output, OUTPUT_FILE):
            elapsed = time.time() - start

            logger.info("")
            logger.info("=" * 50)
            logger.info("COLLECTION COMPLETE")
            logger.info("=" * 50)
            logger.info("  Total devices:      %d", len(devices))
            logger.info("  Endpoints with MAC: %d", len(endpoints))
            logger.info("  Without MAC:        %d", no_mac)
            logger.info("  Unmanaged assets:   %d", len(unmanaged_eps))
            logger.info("")
            logger.info("  APIs available:")
            for api_name, available in sorted(api.available_apis.items()):
                status = "OK" if available else "not available"
                logger.info("    %-20s %s", api_name + ":", status)
            logger.info("")
            logger.info("  Output: %s", str(OUTPUT_FILE).replace("\\", "/"))
            logger.info("  Time:   %.1f seconds", elapsed)
            logger.info("=" * 50)
        else:
            logger.error("Failed to write output!")
            sys.exit(1)

    except Exception as e:
        logger.error("FAILED: %s", e)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
