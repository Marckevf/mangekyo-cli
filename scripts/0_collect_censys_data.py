"""
0_collect_censys_data.py
========================
Project Mangekyo — Real-World Data Collector

Queries the Censys Platform API v3 for hosts running historically
vulnerable software, scores each host through the Mangekyo GTE,
extracts all 37 features, and appends real samples to both
training_data_v2.csv and final_feature_matrix.csv.

Usage:
    python 0_collect_censys_data.py           # test run: ProFTPD only
    python 0_collect_censys_data.py --all     # full 30-query run

Requires:
    .env file containing:  CENSYS_API_TOKEN=<your_bearer_token>
    Packages: requests, pandas, python-dotenv
              (all present in the ml-exercise conda env)
"""

from __future__ import annotations

import math
import os
import re
import sys
import time
from pathlib import Path

import pandas as pd
import requests

# ─────────────────────────────────────────────────────────────────────────────
# 0. CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# CLI flag: pass --all to run every query; default is ProFTPD test run only
TEST_RUN = "--all" not in sys.argv

# All target software strings — ProFTPD must stay first (test run uses [0])
QUERIES: list[str] = [
    # ── Original 11 ──────────────────────────────────────────────────────────
    "ProFTPD",
    "vsftpd",
    "Samba",
    "Apache httpd 2.2",
    "OpenSSH 4",
    "OpenSSH 5",
    "Dovecot",
    "UnrealIRCd",
    "MySQL 5",
    "PostgreSQL 8",
    "PostgreSQL 9",
    # ── Extended 19 ──────────────────────────────────────────────────────────
    "Microsoft IIS 6",
    "Microsoft IIS 7",
    "OpenSSL 1.0",
    "PHP 5",
    "WordPress",
    "Joomla",
    "Jenkins",
    "Elasticsearch",
    "MongoDB",
    "Redis",
    "Telnet",
    "VNC",
    "Webmin",
    "Tomcat 6",
    "Tomcat 7",
    "MSSQL",
    "Oracle",
    "RDP",
    "memcached",
]

# Censys Query Language (CQL) for each software string.
# Banner search is the most universally supported form.
# Adjust these if a query returns 0 results (Censys indexes vary by plan tier).
_CENSYS_QUERY_MAP: dict[str, str] = {
    # FTP servers
    "ProFTPD":          'services.banner: "ProFTPD"',
    "vsftpd":           'services.banner: "vsFTPd"',
    # File sharing
    "Samba":            'services.banner: "Samba"',
    # Web servers
    "Apache httpd 2.2": 'services.banner: "Apache/2.2"',
    "Microsoft IIS 6":  'services.banner: "Microsoft-IIS/6."',
    "Microsoft IIS 7":  'services.banner: "Microsoft-IIS/7."',
    # SSH
    "OpenSSH 4":        'services.banner: "OpenSSH_4."',
    "OpenSSH 5":        'services.banner: "OpenSSH_5."',
    # Mail
    "Dovecot":          'services.banner: "Dovecot"',
    # IRC
    "UnrealIRCd":       'services.banner: "UnrealIRCd"',
    # Databases
    "MySQL 5":          'services.banner: "5." and services.service_name: "MYSQL"',
    "PostgreSQL 8":     'services.banner: "8." and services.service_name: "POSTGRESQL"',
    "PostgreSQL 9":     'services.banner: "9." and services.service_name: "POSTGRESQL"',
    "Elasticsearch":    'services.banner: "Elasticsearch"',
    "MongoDB":          'services.banner: "MongoDB"',
    "Redis":            'services.banner: "Redis server"',
    "MSSQL":            'services.banner: "Microsoft SQL Server"',
    "Oracle":           'services.banner: "Oracle"',
    "memcached":        'services.banner: "memcached"',
    # Crypto / app layers
    "OpenSSL 1.0":      'services.banner: "OpenSSL/1.0"',
    "PHP 5":            'services.banner: "PHP/5."',
    # CMS / apps
    "WordPress":        'services.banner: "WordPress"',
    "Joomla":           'services.banner: "Joomla"',
    "Jenkins":          'services.banner: "Jenkins"',
    "Webmin":           'services.banner: "Webmin"',
    # App servers
    "Tomcat 6":         'services.banner: "Apache Tomcat/6."',
    "Tomcat 7":         'services.banner: "Apache Tomcat/7."',
    # Remote access — port-based since no unique banner string
    "Telnet":           "services.port=23",
    "VNC":              'services.banner: "RFB"',
    "RDP":              "services.port=3389",
}

MAX_HOSTS_PER_QUERY = 50 if TEST_RUN else 100
RATE_LIMIT_SLEEP    = 1.0   # seconds between paginated API calls
MAX_BACKOFF_RETRIES = 5     # max retries on HTTP 429

TRAINING_CSV = "training_data_v2.csv"
FEATURE_CSV  = "final_feature_matrix.csv"

# ─────────────────────────────────────────────────────────────────────────────
# 1. ENVIRONMENT — load .env, validate token
# ─────────────────────────────────────────────────────────────────────────────

_env_path = Path(__file__).parent / ".env"

# Create a template .env if none exists, then exit so the user can fill it in
if not _env_path.exists():
    _env_path.write_text(
        "# Censys Platform API v3 bearer token\n"
        "# Get yours at: https://app.censys.io/account/api\n"
        "CENSYS_API_TOKEN=your_token_here\n"
    )
    print(
        f"[!] .env not found — created a template at {_env_path}\n"
        "    Add your Censys bearer token and re-run."
    )
    sys.exit(0)

# Load .env (python-dotenv preferred; plain fallback if not installed)
try:
    from dotenv import load_dotenv
    load_dotenv(_env_path)
except ImportError:
    # Manual parse for environments without python-dotenv
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

CENSYS_TOKEN = os.getenv("CENSYS_API_TOKEN", "").strip()
if not CENSYS_TOKEN or CENSYS_TOKEN == "your_token_here":
    sys.exit(
        "[!] CENSYS_API_TOKEN not set.\n"
        f"    Edit {_env_path} and set: CENSYS_API_TOKEN=<your_token>"
    )

CENSYS_BASE = "https://api.platform.censys.io/v3"
# Platform API v3 uses Censys-Api-Key header, not Authorization: Bearer
_HEADERS = {
    "Censys-Api-Key": CENSYS_TOKEN,
    "Accept":         "application/json",
    "User-Agent":     "Mangekyo-Collector/1.0",
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. IMPORT EXISTING PIPELINE MODULES
# ─────────────────────────────────────────────────────────────────────────────

try:
    from mangekyo import scoring_engine as _gte
    from mangekyo import feature_extractor as _fe
    from mangekyo.mangekyo_db import init_db
except ImportError as exc:
    sys.exit(f"[!] Cannot import mangekyo package (run 'pip install -e .' from "
             f"the project root): {exc}")

# ─────────────────────────────────────────────────────────────────────────────
# 3. INITIALISE DB AND THREAT INTEL FEEDS
# ─────────────────────────────────────────────────────────────────────────────

print("[*] Initializing databases and threat intel feeds...")
init_db()
_gte.load_kev_catalog()
print()

# ─────────────────────────────────────────────────────────────────────────────
# 4. CENSYS API — SEARCH + PAGINATION
# ─────────────────────────────────────────────────────────────────────────────

def _get_with_backoff(url: str, params: dict) -> requests.Response:
    """GET request with exponential back-off on HTTP 429."""
    for attempt in range(MAX_BACKOFF_RETRIES):
        try:
            resp = requests.get(url, headers=_HEADERS, params=params, timeout=30)
        except requests.exceptions.RequestException as exc:
            if attempt == MAX_BACKOFF_RETRIES - 1:
                raise
            wait = 2 ** attempt
            print(f"  [!] Network error ({exc}) — retrying in {wait}s")
            time.sleep(wait)
            continue

        if resp.status_code != 429:
            return resp

        wait = 2 ** attempt
        print(
            f"  [!] Rate limited (HTTP 429) — backing off {wait}s "
            f"(attempt {attempt + 1}/{MAX_BACKOFF_RETRIES})"
        )
        time.sleep(wait)

    raise RuntimeError(f"Max back-off retries exceeded for {url}")


def search_censys(query: str, max_hosts: int) -> list[dict]:
    """
    Page through Censys Platform API v3 host search results.
    Returns raw host dicts (up to max_hosts).
    """
    url    = f"{CENSYS_BASE}/hosts/search"
    params: dict = {"q": query, "per_page": min(max_hosts, 100)}
    hits:  list[dict] = []

    while len(hits) < max_hosts:
        resp = _get_with_backoff(url, params)

        if resp.status_code == 401:
            print("  [!] HTTP 401 Unauthorized — token rejected.")
            print("       The Platform v3 Search API requires a Search API key,")
            print("       not an ASM key. Get it at: app.censys.io -> Team Settings -> API Keys")
            print(f"       Raw response: {resp.text[:200]}")
            break
        if resp.status_code == 403:
            print("  [!] HTTP 403 Forbidden — token lacks 'search' scope")
            print(f"       Raw response: {resp.text[:200]}")
            break
        if resp.status_code == 422:
            print(f"  [!] HTTP 422 Unprocessable — CQL query rejected: {resp.text[:300]}")
            break
        if resp.status_code != 200:
            print(f"  [!] HTTP {resp.status_code}: {resp.text[:300]}")
            break

        data   = resp.json()
        # Platform v3 wraps results in {"result": {...}}; handle both layouts
        result = data.get("result", data)
        page   = result.get("hits", [])
        if not page:
            break
        hits.extend(page)

        next_cursor = result.get("links", {}).get("next", "")
        if not next_cursor or len(hits) >= max_hosts:
            break

        params = {
            "q":        query,
            "per_page": min(max_hosts - len(hits), 100),
            "cursor":   next_cursor,
        }
        time.sleep(RATE_LIMIT_SLEEP)

    return hits[:max_hosts]


# ─────────────────────────────────────────────────────────────────────────────
# 5. HOST PARSER — Censys JSON → normalised service list
# ─────────────────────────────────────────────────────────────────────────────

# Fallback: parse "Product/1.2.3" or "Product 1.2.3" from a raw banner
_BANNER_PRODUCT_RE = re.compile(
    r"(?:^|[\s/(])([A-Za-z][\w\-\.]+)[/\s_]([\d][\d.a-z\-]*)",
    re.IGNORECASE,
)


def _banner_product_version(banner: str) -> tuple[str, str]:
    """Extract a product name and version from a raw banner string."""
    m = _BANNER_PRODUCT_RE.search(banner)
    if m:
        return m.group(1).strip(), m.group(2).strip()
    return "", ""


def parse_censys_host(raw: dict) -> dict | None:
    """
    Convert a Censys Platform API v3 host object into a normalised host dict
    that mirrors the structure produced by parse_xml() in the Nmap pipeline.

    Output:
        {
          "ip":           "1.2.3.4",
          "os_is_windows": 0 | 1,
          "services": [
              {"port": int, "service_name": str,
               "product": str, "version": str, "banner": str},
              ...
          ]
        }
    """
    ip = raw.get("ip")
    if not ip:
        return None

    # OS detection from structured field
    os_obj   = raw.get("operating_system") or raw.get("os") or {}
    os_fam   = (
        os_obj.get("family") or os_obj.get("product") or os_obj.get("vendor") or ""
    ).lower()
    os_is_win = 1 if "windows" in os_fam else 0

    # OS hint from labels/tags
    for lbl in raw.get("labels", []):
        if "windows" in str(lbl).lower():
            os_is_win = 1
            break

    services: list[dict] = []
    for svc in raw.get("services", []):
        port = int(svc.get("port") or 0)
        if not port:
            continue

        # Service name — Censys typically returns uppercase ("HTTP", "SSH", etc.)
        svc_name = (
            svc.get("service_name")
            or svc.get("extended_service_name")
            or ""
        ).lower()

        # Raw banner text
        raw_banner = svc.get("banner") or ""
        if isinstance(raw_banner, bytes):
            raw_banner = raw_banner.decode("utf-8", errors="replace")
        banner = raw_banner.strip()

        # Windows hint from banner (SMB, RDP, IIS)
        if not os_is_win and "windows" in banner.lower():
            os_is_win = 1

        # Product + version — prefer the structured software list
        product, version = "", ""
        sw_list = (
            svc.get("software")
            or svc.get("softwares")
            or svc.get("applications")
            or []
        )
        if sw_list:
            sw = sw_list[0] if isinstance(sw_list[0], dict) else {}
            product = (
                sw.get("product") or sw.get("name") or sw.get("uniform_resource_identifier") or ""
            ).strip()
            version = (sw.get("version") or "").strip()

        # Fallback: parse product/version from banner text
        if not product and banner:
            product, version = _banner_product_version(banner)

        # Windows hint from IIS product name
        if not os_is_win and "iis" in product.lower():
            os_is_win = 1

        services.append({
            "port":         port,
            "service_name": svc_name,
            "product":      product,
            "version":      version,
            "banner":       banner,
        })

    return {"ip": ip, "os_is_windows": os_is_win, "services": services}


# ─────────────────────────────────────────────────────────────────────────────
# 6. SCORER — four-signal GTE formula without XML
# ─────────────────────────────────────────────────────────────────────────────

def score_host(host: dict) -> tuple[float, dict]:
    """
    Run the Mangekyo four-signal scoring formula on a parsed Censys host.

    Replicates calculate_machine_risk() from the GTE (v3 — EPSS + KEV)
    without requiring an Nmap XML file.

    Returns:
        risk_score  — float 0.0-100.0
        intel_dict  — keys: max_epss_score, has_high_epss, has_kev_cve,
                            kev_port_count, max_nvd_score, mean_nvd_score,
                            nvd_zero_count
    """
    services = host.get("services", [])
    if not services:
        return 0.0, _gte._zero_intel()

    all_port_risks:  list[float] = []
    all_epss_scores: list[float] = []
    all_nvd_risks:   list[int]   = []
    kev_port_count = 0
    nvd_zero_count = 0
    # Per-host CPE deduplication (GTE FIX-2 equivalent)
    seen_cpes: dict[str, tuple[int, list[str]]] = {}

    for svc in services:
        port_id = svc["port"]
        product = svc.get("product", "")
        version = svc.get("version", "")

        # Build CPE search term from product/version
        search_term: str | None = None
        if product:
            raw_fallback = _gte.generate_fallback_cpe(product, version)
            if raw_fallback:
                search_term = _gte.clean_cpe_string(raw_fallback)

        # NVD query with per-host CPE deduplication
        if search_term:
            print(f"    [*] Querying NVD for: {search_term}")
            if search_term in seen_cpes:
                print("    [~] Duplicate CPE on this host — reusing cached score.")
                nvd_risk, cve_ids = seen_cpes[search_term]
            else:
                nvd_risk, cve_ids = _gte.get_nvd_cvss(search_term)

                # Version-unknown confidence discount (GTE FIX-3)
                ver_field = _gte._cpe_version_field(search_term)
                if ver_field in ("*", "", "-") and nvd_risk > 0:
                    discounted = int(nvd_risk * _gte._VERSION_UNKNOWN_DISCOUNT)
                    print(
                        f"    [~] Version unknown — confidence discount: "
                        f"{nvd_risk} → {discounted}"
                    )
                    nvd_risk = discounted

                seen_cpes[search_term] = (nvd_risk, cve_ids)
        else:
            nvd_risk, cve_ids = 0, []

        # CISA KEV check — confirmed wild exploitation bonus (INTEL-1)
        in_kev    = _gte.check_kev(cve_ids) if cve_ids else False
        kev_bonus = 15.0 if in_kev else 0.0
        if in_kev:
            matched = [c for c in cve_ids if c in _gte._KEV_SET]
            print(f"    [!!!] KEV HIT — {matched} → +15 bonus")

        # EPSS — exploitation probability (INTEL-2)
        epss_score = _gte.get_epss_score(cve_ids) if cve_ids else 0.0
        if epss_score > 0:
            print(f"    [*] EPSS: {epss_score:.1f}/100")

        # Four-signal hybrid formula (INTEL-3)
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
            print(
                f"    [~] No CVE data + unknown version — "
                f"base_risk discounted: {base_risk} → {port_risk:.1f}"
            )
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
# 7. FEATURE EXTRACTION — exact parity with Nmap XML pipeline
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(host: dict, risk_score: float, intel: dict) -> dict:
    """
    Extract the full 37-feature vector by calling _fe._build_features(),
    the same function used when processing Nmap XML files.

    The only difference: inputs come from parsed Censys JSON rather than XML.
    """
    services    = host["services"]
    os_is_win   = host["os_is_windows"]

    open_ports    = [s["port"]          for s in services]
    service_names = [s["service_name"]  for s in services]
    has_version   = [
        bool(s["version"]) and "*" not in s["version"]
        for s in services
    ]
    # Banner strings for ancient-version detection (same format as Nmap parser)
    all_banners   = [
        f"{s['product']} {s['version']}".lower().strip()
        for s in services
    ]

    features = _fe._build_features(
        open_ports, service_names, has_version, all_banners, os_is_win
    )

    # Intel columns — pass through from scorer (same path as Nmap pipeline)
    for col in _fe._INTEL_COLS:
        features[col] = intel.get(col, 0)

    # Tier derived from risk score (consistent with synthetic data labelling)
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
# 8. CSV HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _load_seen_ips(csv_path: str) -> set[str]:
    """
    Return the set of IPs already collected (stored as target_name for
    Censys rows). Existing synthetic/real rows use hostnames, not IPs,
    so there is no collision risk.
    """
    if not Path(csv_path).exists():
        return set()
    try:
        df = pd.read_csv(csv_path, usecols=["target_name"])
        return {str(v) for v in df["target_name"] if _IP_RE.match(str(v))}
    except Exception:
        return set()


def _append_to_training_csv(csv_path: str, row: dict) -> None:
    """Append one row to training_data_v2.csv (read-modify-write)."""
    df_new = pd.DataFrame([row])
    if Path(csv_path).exists():
        existing = pd.read_csv(csv_path)
        combined = pd.concat([existing, df_new], ignore_index=True)
    else:
        combined = df_new
    combined.to_csv(csv_path, index=False)


def _append_to_feature_csv(csv_path: str, features: dict) -> None:
    """
    Append one row to final_feature_matrix.csv, aligned to the existing
    column order so that the model training script needs no changes.
    """
    if Path(csv_path).exists():
        existing = pd.read_csv(csv_path)
        # Keep existing schema, but guarantee the identity/label columns
        # survive even if the matrix predates them (union, not intersection).
        cols = list(existing.columns)
        for extra in ("filename", "is_synthetic"):
            if extra not in cols:
                cols.append(extra)
        ordered  = {col: features.get(col, 0) for col in cols}
        df_new   = pd.DataFrame([ordered])
        combined = pd.concat([existing, df_new], ignore_index=True)
    else:
        # No feature CSV yet — write with whatever we have
        combined = pd.DataFrame([features])
    combined.to_csv(csv_path, index=False)


# ─────────────────────────────────────────────────────────────────────────────
# 9. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    mode = (
        "TEST RUN — ProFTPD only (pass --all for full run)"
        if TEST_RUN
        else f"FULL RUN — {len(QUERIES)} queries"
    )
    print(f"[+] Mangekyo Censys Collector — {mode}")
    print(f"    Max hosts per query : {MAX_HOSTS_PER_QUERY}")
    print(f"    Training CSV        : {TRAINING_CSV}")
    print(f"    Feature CSV         : {FEATURE_CSV}")
    print()
    print(
        "    NOTE: NVD API calls include a 6.5s sleep each. Results are\n"
        "    cached in mangekyo_db — subsequent runs on the same software\n"
        "    are significantly faster.\n"
    )

    seen_ips = _load_seen_ips(TRAINING_CSV)
    print(f"[*] {len(seen_ips)} real-host IPs already in dataset — will skip duplicates\n")

    active_queries = QUERIES[:1] if TEST_RUN else QUERIES
    total_added    = 0

    for q_idx, q in enumerate(active_queries, 1):
        cql = _CENSYS_QUERY_MAP.get(q, f'services.banner: "{q}"')

        print("=" * 65)
        print(f"[{q_idx}/{len(active_queries)}] Query  : {q}")
        print(f"           CQL    : {cql}")
        print("=" * 65)

        try:
            raw_hits = search_censys(cql, MAX_HOSTS_PER_QUERY)
        except Exception as exc:
            print(f"  [!] Censys search error: {exc}\n")
            continue

        if not raw_hits:
            print(f"  [~] 0 results returned — query may need CQL adjustment\n")
            continue

        print(f"  [+] {len(raw_hits)} hosts returned by Censys\n")

        query_added = 0

        for hit_idx, raw in enumerate(raw_hits, 1):
            host = parse_censys_host(raw)
            if not host:
                continue

            ip = host["ip"]

            if ip in seen_ips:
                print(f"  [{hit_idx}/{len(raw_hits)}] {ip} — already in dataset, skipping")
                continue

            svc_summary = ", ".join(
                f"{s['port']}/{s['service_name'] or '?'}" for s in host["services"]
            )
            print(
                f"\n  [{hit_idx}/{len(raw_hits)}] {ip}"
                f"  |  services: [{svc_summary}]"
            )

            # ── Score ────────────────────────────────────────────────────────
            try:
                risk_score, intel = score_host(host)
            except Exception as exc:
                print(f"    [!] Scoring error: {exc} — skipping host")
                continue
            print(f"    => Risk score: {risk_score:.1f}")

            # ── Features ─────────────────────────────────────────────────────
            try:
                features = extract_features(host, risk_score, intel)
            except Exception as exc:
                print(f"    [!] Feature extraction error: {exc} — skipping host")
                continue
            tier = features["tier"]

            # ── Build training_data_v2.csv row ────────────────────────────────
            training_row: dict = {
                "filename":     f"censys/{ip}",
                "target_name":  ip,
                "tier":         tier,
                "risk_score":   risk_score,
                "is_synthetic": 0,
            }
            # Include intel columns inline
            for col in _gte._INTEL_COLS:
                training_row[col] = intel.get(col, 0)

            # Carry the stable id + explicit real label into the feature matrix
            # too, so the synthetic/real split is never re-inferred downstream.
            features["filename"]     = f"censys/{ip}"
            features["is_synthetic"] = 0

            # ── Write both CSVs ───────────────────────────────────────────────
            _append_to_training_csv(TRAINING_CSV, training_row)
            _append_to_feature_csv(FEATURE_CSV, features)

            seen_ips.add(ip)
            query_added += 1
            total_added += 1

            print(
                f"    => Saved. Total real hosts in dataset: "
                f"{len(seen_ips)}"
            )

            # Brief pause between hosts so Censys and NVD APIs stay happy
            time.sleep(RATE_LIMIT_SLEEP)

        print(
            f"\n  [+] '{q}' done — {query_added} new hosts added\n"
        )

    print("=" * 65)
    print(f"[V] Collection complete.")
    print(f"    New real hosts added this run : {total_added}")
    print(f"    Training CSV                  : {TRAINING_CSV}")
    print(f"    Feature CSV                   : {FEATURE_CSV}")
    print("=" * 65)


if __name__ == "__main__":
    main()
