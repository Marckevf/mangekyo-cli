"""
0_collect_internetdb.py
=======================
Project Mangekyo — Real-World Data Collector (InternetDB / no API key)

Samples IPs from cloud-provider ranges, queries the free Shodan InternetDB
API, scores each qualifying host through the Mangekyo GTE, and appends real
samples to the training datasets.

Usage:
    python 0_collect_internetdb.py --test    # 100-IP probe, print stats only
    python 0_collect_internetdb.py           # full run, up to 50 000 IPs
"""

from __future__ import annotations

import ipaddress
import json
import random
import sys
import time
from pathlib import Path

import pandas as pd
import requests

# ─────────────────────────────────────────────────────────────────────────────
# 0. CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

TEST_MODE = "--test" in sys.argv

MAX_IPS_FULL   = 50_000
MAX_IPS_TEST   = 100
INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"
RATE_LIMIT_SLEEP    = 1.0
MAX_BACKOFF_RETRIES = 5

TRAINING_CSV = "training_data_v2.csv"
FEATURE_CSV  = "final_feature_matrix.csv"
LOG_INTERVAL = 50   # print progress every N IPs checked

# Provider IP-range URLs — plain text, one CIDR per line
_RANGE_SOURCES = {
    "DigitalOcean": "https://cloud-ip-ranges.com/download/digitalocean.txt",
    "Vultr":        "https://cloud-ip-ranges.com/download/vultr.txt",
    "Linode":       "https://raw.githubusercontent.com/lord-alfred/ipranges/main/linode/ipv4.txt",
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. IMPORT EXISTING PIPELINE MODULES
# ─────────────────────────────────────────────────────────────────────────────

try:
    from mangekyo import scoring_engine as _gte
    from mangekyo import feature_extractor as _fe
    from mangekyo.mangekyo_db import init_db
except ImportError as exc:
    sys.exit(f"[!] Cannot import mangekyo package (run 'pip install -e .' from "
             f"the project root): {exc}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. IP RANGE DOWNLOAD + EXPANSION  (Stage 1)
# ─────────────────────────────────────────────────────────────────────────────

def _download_ranges(name: str, url: str) -> list[str]:
    """Download a plain-text CIDR list from a URL."""
    print(f"  [{name}] Fetching {url} …")
    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": "Mangekyo-Collector/1.0"})
        resp.raise_for_status()
        lines = [ln.strip() for ln in resp.text.splitlines()]
        cidrs = [ln for ln in lines if ln and not ln.startswith("#")]
        print(f"  [{name}] {len(cidrs)} CIDR blocks downloaded")
        return cidrs
    except Exception as exc:
        print(f"  [{name}] Download failed: {exc}")
        return []


def _expand_cidrs(cidrs: list[str]) -> list[str]:
    """
    Expand CIDR blocks to individual IP strings.
    Skips IPv6, private, and reserved ranges.
    """
    ips: list[str] = []
    for cidr in cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        for host in net.hosts():
            if host.is_global:
                ips.append(str(host))
    return ips


def build_ip_list(max_ips: int) -> list[str]:
    """
    Download all provider ranges, expand, shuffle, and cap at max_ips.
    """
    print("[+] Stage 1 — Downloading IP ranges")
    all_cidrs: list[str] = []
    for name, url in _RANGE_SOURCES.items():
        all_cidrs.extend(_download_ranges(name, url))

    print(f"\n[*] Total CIDR blocks: {len(all_cidrs)} — expanding to individual IPs …")
    all_ips = _expand_cidrs(all_cidrs)
    print(f"[*] Total routable IPs: {len(all_ips):,}")

    random.shuffle(all_ips)
    capped = all_ips[:max_ips]
    print(f"[*] Working set capped at: {len(capped):,} IPs\n")
    return capped

# ─────────────────────────────────────────────────────────────────────────────
# 3. INTERNETDB QUERY  (Stage 2)
# ─────────────────────────────────────────────────────────────────────────────

def _get_with_backoff(ip: str) -> requests.Response | None:
    """GET InternetDB with exponential back-off on 429."""
    url = INTERNETDB_URL.format(ip=ip)
    for attempt in range(MAX_BACKOFF_RETRIES):
        try:
            resp = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": "Mangekyo-Collector/1.0"},
            )
        except requests.exceptions.RequestException:
            return None   # network error — skip silently

        if resp.status_code == 429:
            wait = 2 ** (attempt + 1)
            print(f"  [!] Rate limited (429) — backing off {wait}s")
            time.sleep(wait)
            continue

        return resp
    return None   # exhausted retries


def query_internetdb(ip: str) -> dict | None:
    """
    Query InternetDB for a single IP.
    Returns the parsed JSON dict, or None if no usable data.

    Filtering rules:
      - 404 → no data, skip silently
      - empty ports list → skip silently
      - kept only when: ≥1 open port AND (≥1 CPE OR ≥1 CVE)
    """
    resp = _get_with_backoff(ip)
    if resp is None or resp.status_code == 404:
        return None
    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except Exception:
        return None

    ports = data.get("ports", [])
    cpes  = data.get("cpes",  [])
    vulns = data.get("vulns", [])

    if not ports:
        return None
    if not cpes and not vulns:
        return None

    return data

# ─────────────────────────────────────────────────────────────────────────────
# 4. HOST DICT BUILDER  (Stage 3)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cpe(cpe_str: str) -> tuple[str, str, str]:
    """
    Parse a CPE string (v1 or v2.3) into (vendor, product, version).

    v1:  cpe:/a:vendor:product:version
    v2.3: cpe:2.3:a:vendor:product:version:...
    """
    if cpe_str.startswith("cpe:/"):
        # "cpe:/a:vendor:product:version" splits on ":"
        # → ["cpe", "/a", "vendor", "product", "version"]
        parts = cpe_str.split(":")
        vendor  = parts[2].lower().strip() if len(parts) > 2 else ""
        product = parts[3].lower().strip() if len(parts) > 3 else ""
        version = parts[4].strip()         if len(parts) > 4 else ""
    elif cpe_str.startswith("cpe:2.3:"):
        parts   = cpe_str.split(":")
        vendor  = parts[3].lower().strip() if len(parts) > 3 else ""
        product = parts[4].lower().strip() if len(parts) > 4 else ""
        version = parts[5].strip()         if len(parts) > 5 else ""
    else:
        return "", "", ""

    # Treat "*" or "-" as unknown version
    if version in ("*", "-"):
        version = ""
    return vendor, product, version


# Map product keywords to likely port numbers (used to assign CPEs to ports)
_PRODUCT_PORT_HINTS: dict[str, list[int]] = {
    "openssh":           [22],
    "ssh":               [22],
    "vsftpd":            [21],
    "proftpd":           [21],
    "ftp":               [21],
    "pure-ftpd":         [21],
    "http_server":       [80, 443, 8080, 8443],
    "httpd":             [80, 443, 8080],
    "apache":            [80, 443, 8080, 8443],
    "nginx":             [80, 443, 8080, 8443],
    "lighttpd":          [80, 443],
    "iis":               [80, 443],
    "internet_information_services": [80, 443],
    "tomcat":            [8080, 8443, 80, 443],
    "jetty":             [8080, 8443],
    "samba":             [139, 445],
    "smbd":              [139, 445],
    "mysql":             [3306],
    "mariadb":           [3306],
    "postgresql":        [5432],
    "mongodb":           [27017],
    "redis":             [6379],
    "memcached":         [11211],
    "sql_server":        [1433],
    "mssql":             [1433],
    "dovecot":           [143, 993, 110, 995],
    "postfix":           [25, 587],
    "exim":              [25, 587],
    "sendmail":          [25, 587],
    "named":             [53],
    "bind":              [53],
    "telnet":            [23],
    "rdp":               [3389],
    "terminal_services": [3389],
    "vnc":               [5900, 5901, 5902],
    "unrealircd":        [6667, 6697, 6660],
    "ircd":              [6667],
    "elasticsearch":     [9200, 9300],
    "jenkins":           [8080, 443],
    "webmin":            [10000],
    "wordpress":         [80, 443],
    "joomla":            [80, 443],
}

# Simple port → service name lookup for service_names list
_PORT_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",     22: "ssh",      23: "telnet",    25: "smtp",
    53: "dns",     80: "http",     110: "pop3",     143: "imap",
    443: "https",  445: "smb",     993: "imaps",    995: "pop3s",
    1433: "mssql", 3306: "mysql",  3389: "rdp",     5432: "postgres",
    5900: "vnc",   6379: "redis",  8080: "http-alt",8443: "https-alt",
    9200: "elasticsearch", 10000: "webmin", 11211: "memcached",
    27017: "mongodb",
}


def _build_banner(vendor: str, product: str, version: str) -> str:
    """
    Construct a banner string designed to match ANCIENT_VERSION_PATTERNS.

    Apache uses "apache/X.Y" in its patterns, but other services use
    "product X.Y" (space-separated) format.
    """
    v = version.lower().strip() if version else ""

    # Apache HTTP Server uses "apache/version" in patterns
    if vendor == "apache" and any(k in product for k in ("http", "httpd")):
        return f"apache/{v}" if v else "apache"

    # Tomcat uses "tomcat/version" in patterns
    if "tomcat" in product:
        return f"tomcat/{v}" if v else "tomcat"

    # General case: "product version"
    name = product.lower()
    return f"{name} {v}".strip() if v else name


def _match_cpes_to_ports(
    cpes: list[str],
    open_ports: list[int],
) -> dict[int, dict]:
    """
    Match each CPE to the most likely open port using product keywords.

    Returns: {port_number: {vendor, product, version, cpe_str}}

    Each port is assigned at most one CPE (first match wins).
    Unmatched CPEs (library CPEs like openssl) are ignored for port
    assignment but still used for host-level EPSS/KEV checks.
    """
    port_set = set(open_ports)
    assigned: dict[int, dict] = {}

    for cpe_str in cpes:
        vendor, product, version = _parse_cpe(cpe_str)
        if not product:
            continue

        # Find candidate ports from hints table
        candidate_ports: list[int] = []
        for keyword, hint_ports in _PRODUCT_PORT_HINTS.items():
            if keyword in product or product in keyword:
                candidate_ports.extend(hint_ports)

        # Assign to first open, unassigned candidate port
        for port in candidate_ports:
            if port in port_set and port not in assigned:
                assigned[port] = {
                    "vendor":  vendor,
                    "product": product,
                    "version": version,
                    "cpe_str": cpe_str,
                }
                break

    return assigned


def build_host_dict(raw: dict) -> dict:
    """
    Convert an InternetDB response to the intermediate host dict format
    that mirrors what the Nmap XML parser produces.

    Output schema:
        {
          "ip":        str,
          "ports":     [{"port": int, "protocol": "tcp", "state": "open",
                         "service": str, "product": str, "version": str}],
          "hostnames": list[str],
          "os":        "",
          "cves":      list[str],
          "cpes":      list[str],
          "tags":      list[str]
        }
    """
    ip    = raw.get("ip", "")
    ports = sorted(set(int(p) for p in raw.get("ports", []) if p))
    cpes  = [str(c) for c in raw.get("cpes",      []) if c]
    cves  = [str(v) for v in raw.get("vulns",     []) if v]
    hosts = [str(h) for h in raw.get("hostnames", []) if h]
    tags  = [str(t) for t in raw.get("tags",      []) if t]

    # Match CPEs to ports to get product/version per port
    port_cpe_map = _match_cpes_to_ports(cpes, ports)

    port_list = []
    for p in ports:
        cpe_info = port_cpe_map.get(p, {})
        vendor   = cpe_info.get("vendor",  "")
        product  = cpe_info.get("product", "")
        version  = cpe_info.get("version", "")

        port_list.append({
            "port":     p,
            "protocol": "tcp",
            "state":    "open",
            "service":  product or _PORT_SERVICE_NAMES.get(p, "unknown"),
            "product":  product,
            "version":  version,
        })

    return {
        "ip":        ip,
        "ports":     port_list,
        "hostnames": hosts,
        "os":        "",
        "cves":      cves,
        "cpes":      cpes,
        "tags":      tags,
    }

# ─────────────────────────────────────────────────────────────────────────────
# 5. SCORER  (Stage 4-a)
# ─────────────────────────────────────────────────────────────────────────────

def score_internetdb_host(host_dict: dict) -> tuple[float, dict]:
    """
    Four-signal GTE scoring without XML.

    Key difference from the Censys scorer: InternetDB provides CVE IDs
    directly in the `cves` field.  These are used for EPSS + KEV lookups
    without waiting for NVD to return CVE IDs per CPE.

    NVD CVSS is still queried per CPE (same as Censys path) and cached
    in mangekyo_db, so repeated CPEs (openssh, apache…) are instant.
    """
    port_list = host_dict.get("ports", [])
    cpes      = host_dict.get("cpes",  [])
    cve_ids   = host_dict.get("cves",  [])

    if not port_list:
        return 0.0, _gte._zero_intel()

    # Host-level EPSS + KEV pre-computed from InternetDB's CVE list
    # (avoids per-CPE EPSS round-trips; uses the same _gte helpers)
    host_epss      = _gte.get_epss_score(cve_ids) if cve_ids else 0.0
    host_in_kev    = _gte.check_kev(cve_ids)       if cve_ids else False
    host_kev_bonus = 15.0 if host_in_kev else 0.0

    if host_in_kev:
        matched = [c for c in cve_ids if c in _gte._KEV_SET]
        print(f"    [!!!] KEV HIT: {matched} -> +15 bonus")
    if host_epss > 0:
        print(f"    [*] EPSS: {host_epss:.1f}/100")

    open_ports   = [p["port"] for p in port_list]
    port_cpe_map = _match_cpes_to_ports(cpes, open_ports)

    all_port_risks:  list[float] = []
    all_epss_scores: list[float] = []
    all_nvd_risks:   list[int]   = []
    kev_port_count = 0
    nvd_zero_count = 0
    seen_cpes: dict[str, tuple[int, list[str]]] = {}

    for port_dict in port_list:
        port_id  = port_dict["port"]
        cpe_info = port_cpe_map.get(port_id, {})
        cpe_str  = cpe_info.get("cpe_str", "")

        # Build a cleaned CPE 2.3 search term
        search_term: str | None = None
        if cpe_str:
            formatted = _gte.format_cpe_23(cpe_str)
            if formatted:
                search_term = _gte.clean_cpe_string(formatted)
        else:
            product = cpe_info.get("product", "")
            version = cpe_info.get("version", "")
            if product:
                fallback = _gte.generate_fallback_cpe(product, version)
                if fallback:
                    search_term = _gte.clean_cpe_string(fallback)

        # NVD query with per-host CPE deduplication (GTE FIX-2)
        if search_term:
            print(f"    [*] Querying NVD for: {search_term}")
            if search_term in seen_cpes:
                print("    [~] Duplicate CPE — reusing cached score.")
                nvd_risk, _ = seen_cpes[search_term]
            else:
                nvd_risk, _ = _gte.get_nvd_cvss(search_term)

                # Version-unknown confidence discount (GTE FIX-3)
                ver_field = _gte._cpe_version_field(search_term)
                if ver_field in ("*", "", "-") and nvd_risk > 0:
                    discounted = int(nvd_risk * _gte._VERSION_UNKNOWN_DISCOUNT)
                    print(f"    [~] Version unknown — discount: {nvd_risk} -> {discounted}")
                    nvd_risk = discounted

                seen_cpes[search_term] = (nvd_risk, [])
        else:
            nvd_risk = 0

        # Use host-level EPSS + KEV for every port (shared intel)
        epss_score = host_epss
        in_kev     = host_in_kev
        kev_bonus  = host_kev_bonus

        # Four-signal hybrid formula (GTE INTEL-3)
        base_risk   = _gte.EXPOSURE_RULES.get(port_id, _gte.DEFAULT_EXPOSURE)
        ver_field   = _gte._cpe_version_field(search_term) if search_term else "*"
        ver_unknown = ver_field in ("*", "", "-")

        if nvd_risk > 0 or epss_score > 0 or in_kev:
            port_risk = (
                (nvd_risk   * 0.60)
                + (base_risk  * 0.15)
                + (epss_score * 0.20)
                + kev_bonus
            )
        elif ver_unknown:
            port_risk = float(base_risk) * 0.75
        else:
            port_risk = float(base_risk)

        all_port_risks.append(port_risk)
        all_epss_scores.append(epss_score)
        all_nvd_risks.append(nvd_risk)
        if in_kev:
            kev_port_count += 1
        if nvd_risk == 0:
            nvd_zero_count += 1

    score = _gte.calculate_final_score(all_port_risks)
    intel = {
        "max_epss_score": max(all_epss_scores) if all_epss_scores else 0.0,
        "has_high_epss":  1 if any(e > 50 for e in all_epss_scores) else 0,
        "has_kev_cve":    1 if kev_port_count > 0 else 0,
        "kev_port_count": kev_port_count,
        "max_nvd_score":  max(all_nvd_risks) if all_nvd_risks else 0,
        "mean_nvd_score": (
            round(sum(all_nvd_risks) / len(all_nvd_risks), 2)
            if all_nvd_risks else 0.0
        ),
        "nvd_zero_count": nvd_zero_count,
    }
    return score, intel

# ─────────────────────────────────────────────────────────────────────────────
# 6. FEATURE EXTRACTION  (Stage 4-b)
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(host_dict: dict, risk_score: float, intel: dict) -> dict:
    """
    Extract the full 37-feature vector using _fe._build_features(),
    exactly as the Nmap XML pipeline does.
    """
    port_list    = host_dict["ports"]
    cpes         = host_dict.get("cpes", [])
    open_ports   = [p["port"] for p in port_list]
    port_cpe_map = _match_cpes_to_ports(cpes, open_ports)

    service_names: list[str]  = []
    has_version:   list[bool] = []
    all_banners:   list[str]  = []

    for p in port_list:
        port     = p["port"]
        cpe_info = port_cpe_map.get(port, {})
        vendor   = cpe_info.get("vendor",  "")
        product  = cpe_info.get("product", p.get("product", ""))
        version  = cpe_info.get("version", p.get("version", ""))

        svc_name = product or _PORT_SERVICE_NAMES.get(port, "")
        service_names.append(svc_name)

        ver_known = bool(version) and "*" not in version
        has_version.append(ver_known)

        banner = _build_banner(vendor, product, version)
        all_banners.append(banner)

    # OS detection — InternetDB doesn't expose OS; check tags for Windows hints
    os_is_win = 0
    for tag in host_dict.get("tags", []):
        if "windows" in str(tag).lower():
            os_is_win = 1
            break

    features = _fe._build_features(
        open_ports, service_names, has_version, all_banners, os_is_win
    )

    for col in _fe._INTEL_COLS:
        features[col] = intel.get(col, 0)

    if risk_score >= 90:
        tier = "critical"
    elif risk_score >= 70:
        tier = "high"
    elif risk_score >= 40:
        tier = "medium"
    else:
        tier = "low"

    features["tier"]       = tier
    features["risk_score"] = risk_score
    return features

# ─────────────────────────────────────────────────────────────────────────────
# 7. CSV HELPERS  (Stage 4-c)
# ─────────────────────────────────────────────────────────────────────────────

import re as _re
_IP_RE = _re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _load_seen_ips(csv_path: str) -> set[str]:
    if not Path(csv_path).exists():
        return set()
    try:
        df = pd.read_csv(csv_path, usecols=["target_name"])
        return {str(v) for v in df["target_name"] if _IP_RE.match(str(v))}
    except Exception:
        return set()


def _append_training_row(csv_path: str, row: dict) -> None:
    df_new = pd.DataFrame([row])
    if Path(csv_path).exists():
        existing = pd.read_csv(csv_path)
        combined = pd.concat([existing, df_new], ignore_index=True)
    else:
        combined = df_new
    combined.to_csv(csv_path, index=False)


def _append_feature_row(csv_path: str, features: dict) -> None:
    if Path(csv_path).exists():
        existing = pd.read_csv(csv_path)
        cols = list(existing.columns)
        # Guarantee the identity/label columns survive even if the existing
        # matrix predates them (union, not intersection).
        for extra in ("filename", "is_synthetic"):
            if extra not in cols:
                cols.append(extra)
        ordered  = {col: features.get(col, 0) for col in cols}
        df_new   = pd.DataFrame([ordered])
        combined = pd.concat([existing, df_new], ignore_index=True)
    else:
        combined = pd.DataFrame([features])
    combined.to_csv(csv_path, index=False)

# ─────────────────────────────────────────────────────────────────────────────
# 8. TEST MODE  (Stage 6)
# ─────────────────────────────────────────────────────────────────────────────

def run_test() -> None:
    print("[+] InternetDB Collector — TEST MODE (100 IPs, no pipeline scoring)\n")

    ip_list = build_ip_list(MAX_IPS_TEST)

    checked = kept = had_ports = had_intel = 0
    example: dict | None = None

    for ip in ip_list:
        checked += 1
        raw = query_internetdb(ip)

        if raw is None:
            time.sleep(RATE_LIMIT_SLEEP)
            continue

        ports = raw.get("ports", [])
        cpes  = raw.get("cpes",  [])
        vulns = raw.get("vulns", [])

        if ports:
            had_ports += 1
        if cpes or vulns:
            had_intel += 1
        if ports and (cpes or vulns):
            kept += 1
            if example is None:
                example = build_host_dict(raw)

        if checked % LOG_INTERVAL == 0:
            print(f"  Checked: {checked} | With ports: {had_ports} | "
                  f"With CPE/CVE: {had_intel} | Kept: {kept}")

        time.sleep(RATE_LIMIT_SLEEP)

    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"  IPs checked         : {checked}")
    print(f"  Had open ports      : {had_ports}  "
          f"({had_ports / max(checked,1) * 100:.1f}%)")
    print(f"  Had CPE or CVE      : {had_intel}  "
          f"({had_intel / max(checked,1) * 100:.1f}%)")
    print(f"  Kept (ports+intel)  : {kept}  "
          f"({kept / max(checked,1) * 100:.1f}% yield)")
    print()
    if example:
        print("EXAMPLE HOST DICT:")
        print(json.dumps(example, indent=2))
    else:
        print("  (no qualifying host found in sample — try a larger --test run)")
    print("=" * 60)
    print("\nIf the mapping looks correct, run without --test for full collection.")

# ─────────────────────────────────────────────────────────────────────────────
# 9. FULL COLLECTION RUN  (Stages 1-5)
# ─────────────────────────────────────────────────────────────────────────────

def run_full() -> None:
    print("[+] InternetDB Collector — FULL RUN")
    print(f"    IP cap          : {MAX_IPS_FULL:,}")
    print(f"    Training CSV    : {TRAINING_CSV}")
    print(f"    Feature CSV     : {FEATURE_CSV}\n")
    print(
        "    NOTE: NVD API calls include a 6.5s sleep each. Results are\n"
        "    cached in mangekyo_db — repeated CPEs are instant.\n"
    )

    # Initialise DB and KEV catalog
    print("[*] Initializing databases and threat intel feeds...")
    init_db()
    _gte.load_kev_catalog()
    print()

    seen_ips = _load_seen_ips(TRAINING_CSV)
    print(f"[*] {len(seen_ips)} real-host IPs already in dataset — will skip duplicates\n")

    ip_list = build_ip_list(MAX_IPS_FULL)

    checked = kept = skipped = total_added = 0

    for ip in ip_list:
        checked += 1

        # Progress log every N IPs
        if checked % LOG_INTERVAL == 0:
            print(
                f"  Checked: {checked:,} | Kept: {kept} | "
                f"Skipped: {skipped} | New real samples total: {total_added}"
            )

        if ip in seen_ips:
            skipped += 1
            time.sleep(0)   # no sleep for skipped IPs
            continue

        raw = query_internetdb(ip)
        if raw is None:
            skipped += 1
            time.sleep(RATE_LIMIT_SLEEP)
            continue

        host_dict = build_host_dict(raw)

        svc_summary = ", ".join(
            f"{p['port']}/{p['service'] or '?'}"
            for p in host_dict["ports"]
        )
        print(f"\n  [{checked:,}] {ip}  |  ports: [{svc_summary}]"
              f"  cpes: {len(host_dict['cpes'])}  cves: {len(host_dict['cves'])}")

        # Score
        try:
            risk_score, intel = score_internetdb_host(host_dict)
        except Exception as exc:
            print(f"    [!] Scoring error: {exc} — skipping")
            skipped += 1
            continue
        print(f"    => Risk score: {risk_score:.1f}")

        # Features
        try:
            features = extract_features(host_dict, risk_score, intel)
        except Exception as exc:
            print(f"    [!] Feature error: {exc} — skipping")
            skipped += 1
            continue
        tier = features["tier"]

        # Training CSV row
        training_row = {
            "filename":     f"internetdb/{ip}",
            "target_name":  ip,
            "tier":         tier,
            "risk_score":   risk_score,
            "is_synthetic": 0,
        }
        for col in _gte._INTEL_COLS:
            training_row[col] = intel.get(col, 0)

        # Carry the stable id + explicit real label into the feature matrix too,
        # so the synthetic/real split is never re-inferred from values downstream.
        features["filename"]     = f"internetdb/{ip}"
        features["is_synthetic"] = 0

        _append_training_row(TRAINING_CSV, training_row)
        _append_feature_row(FEATURE_CSV, features)

        seen_ips.add(ip)
        kept += 1
        total_added += 1

        print(f"    => Saved. Real hosts in dataset: {len(seen_ips)}")

        time.sleep(RATE_LIMIT_SLEEP)

    print()
    print("=" * 60)
    print("[V] Collection complete.")
    print(f"    IPs checked            : {checked:,}")
    print(f"    Hosts kept & scored    : {kept}")
    print(f"    Hosts skipped          : {skipped}")
    print(f"    New real samples added : {total_added}")
    print(f"    Training CSV           : {TRAINING_CSV}")
    print(f"    Feature CSV            : {FEATURE_CSV}")
    print("=" * 60)

# ─────────────────────────────────────────────────────────────────────────────
# 10. ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if TEST_MODE:
        run_test()
    else:
        run_full()
