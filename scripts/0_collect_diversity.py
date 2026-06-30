"""
0_collect_diversity.py
======================
Project Mangekyo — Diversity Collection Sweep
Source: ipverse/as-ip-blocks (CC0, daily-updated)
Target: ISP + Business networks only (EXCLUDES "hosting" / cloud)

Usage:
    python 0_collect_diversity.py --test    # 100-IP probe, print stats only
    python 0_collect_diversity.py           # full run, up to 30,000 IPs
"""

from __future__ import annotations

import io
import ipaddress
import json
import random
import re as _re
import sys
import tarfile
import time
from collections import Counter
from pathlib import Path

import pandas as pd
import requests

# ─────────────────────────────────────────────────────────────────────────────
# 0. CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

TEST_MODE = "--test" in sys.argv

MAX_IPS_FULL        = 50_000
MAX_IPS_TEST        = 100
INTERNETDB_URL      = "https://internetdb.shodan.io/{ip}"
RATE_LIMIT_SLEEP    = 1.0
MAX_BACKOFF_RETRIES = 5

TRAINING_CSV = "training_data_v2.csv"
FEATURE_CSV  = "final_feature_matrix.csv"
LOG_INTERVAL = 50

ASN_ARCHIVE_URL   = "https://github.com/ipverse/as-ip-blocks/releases/latest/download/as-ip-blocks.tar.gz"
TARGET_CATEGORIES = {"isp", "business"}   # include
MAX_IPS_PER_ASN   = 50                    # cap per ASN; round-robin fills the rest

# ─────────────────────────────────────────────────────────────────────────────
# 1. IMPORT EXISTING PIPELINE MODULES  (identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from mangekyo import scoring_engine as _gte
    from mangekyo import feature_extractor as _fe
    from mangekyo.mangekyo_db import init_db
except ImportError as exc:
    sys.exit(f"[!] Cannot import mangekyo package (run 'pip install -e .' from "
             f"the project root): {exc}")

# ─────────────────────────────────────────────────────────────────────────────
# 2. ASN ARCHIVE DOWNLOAD + IP SELECTION  (Stage 1 — diversity-specific)
# ─────────────────────────────────────────────────────────────────────────────

def _download_archive() -> bytes:
    """Download the full as-ip-blocks tarball in one request; report size."""
    print(f"[+] Downloading ipverse ASN archive …")
    print(f"    {ASN_ARCHIVE_URL}")
    resp = requests.get(
        ASN_ARCHIVE_URL,
        timeout=300,
        headers={"User-Agent": "Mangekyo-DiversityCollector/1.0"},
        stream=True,
    )
    resp.raise_for_status()

    chunks = []
    total  = 0
    for chunk in resp.iter_content(chunk_size=65_536):
        chunks.append(chunk)
        total += len(chunk)

    data     = b"".join(chunks)
    size_mb  = len(data) / 1_048_576
    print(f"    Archive size: {size_mb:.1f} MB ({len(data):,} bytes)")
    return data


def _sample_ips_from_cidrs(cidr_list: list[str], count: int) -> list[str]:
    """
    Sample up to `count` random public IPv4 addresses from CIDR blocks.
    Uses weighted random selection — no full expansion needed, so this
    works even for ISPs with /8 blocks.
    """
    parsed: list[ipaddress.IPv4Network] = []
    for cidr in cidr_list:
        try:
            net = ipaddress.ip_network(cidr.strip(), strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.num_addresses < 2:
            continue
        parsed.append(net)

    if not parsed:
        return []

    weights  = [n.num_addresses for n in parsed]
    results: list[str] = []
    seen:    set[str]  = set()
    attempts = 0
    max_attempts = count * 20

    while len(results) < count and attempts < max_attempts:
        attempts += 1
        (net,) = random.choices(parsed, weights=weights, k=1)
        offset = random.randint(0, net.num_addresses - 1)
        ip_obj = ipaddress.IPv4Address(int(net.network_address) + offset)
        s      = str(ip_obj)
        if ip_obj.is_global and s not in seen:
            seen.add(s)
            results.append(s)

    return results


def build_ip_list(max_ips: int) -> list[str]:
    """
    Download the ipverse archive, select ISP+business ASNs,
    and build a diverse IP list interleaved across many ASNs.
    """
    archive = _download_archive()

    print("\n[+] Stage 1 — Parsing ASN metadata for isp/business categories")
    asn_cidrs: dict[str, list[str]] = {}

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        members = tf.getmembers()
        print(f"    Archive members: {len(members):,}")

        # Build maps: asn -> member names for json and txt
        json_map: dict[str, str] = {}
        txt_map:  dict[str, str] = {}

        for m in members:
            name = m.name.replace("\\", "/")
            parts = [p for p in name.split("/") if p and p != "."]
            if len(parts) < 2:
                continue
            asn   = parts[-2]
            fname = parts[-1]
            if fname == "aggregated.json":
                json_map[asn] = m.name
            elif fname == "ipv4-aggregated.txt":
                txt_map[asn] = m.name

        print(f"    ASNs found in archive: {len(json_map):,}")

        # Identify qualifying ASNs by category
        qualifying: list[str] = []
        category_counts: Counter = Counter()

        for asn, json_name in json_map.items():
            try:
                f = tf.extractfile(json_name)
                if f is None:
                    continue
                meta     = json.loads(f.read().decode("utf-8", errors="ignore"))
                category = (
                    meta.get("metadata", {}).get("category", "")
                    or meta.get("category", "")
                ).lower().strip()
            except Exception:
                category = ""

            category_counts[category or "(none)"] += 1
            if category in TARGET_CATEGORIES:
                qualifying.append(asn)

        print(f"    Category breakdown (top 10): {dict(category_counts.most_common(10))}")
        print(f"    Qualifying ASNs (isp+business): {len(qualifying):,}")

        # Load CIDRs for qualifying ASNs
        for asn in qualifying:
            txt_name = txt_map.get(asn)
            if not txt_name:
                continue
            try:
                f = tf.extractfile(txt_name)
                if f is None:
                    continue
                cidrs = [
                    ln.strip()
                    for ln in f.read().decode("utf-8", errors="ignore").splitlines()
                    if ln.strip() and not ln.startswith("#")
                ]
                if cidrs:
                    asn_cidrs[asn] = cidrs
            except Exception:
                continue

    print(f"    ASNs with CIDR data loaded: {len(asn_cidrs):,}")

    # Sample IPs round-robin across ASNs
    asn_list = list(asn_cidrs.keys())
    random.shuffle(asn_list)

    per_asn = max(1, min(MAX_IPS_PER_ASN, max_ips // max(len(asn_list), 1)))
    print(f"    Sampling up to {per_asn} IPs per ASN (round-robin for spread) …")

    pools: list[list[str]] = []
    for asn in asn_list:
        ips = _sample_ips_from_cidrs(asn_cidrs[asn], per_asn)
        if ips:
            pools.append(ips)

    # Interleave pools round-robin so IPs from different ASNs alternate
    all_ips: list[str] = []
    indices  = [0] * len(pools)
    while len(all_ips) < max_ips:
        added_any = False
        for i, pool in enumerate(pools):
            if indices[i] < len(pool):
                all_ips.append(pool[indices[i]])
                indices[i] += 1
                added_any = True
                if len(all_ips) >= max_ips:
                    break
        if not added_any:
            break

    random.shuffle(all_ips)
    print(f"[*] Working set: {len(all_ips):,} IPs from {len(pools):,} ASNs\n")
    return all_ips

# ─────────────────────────────────────────────────────────────────────────────
# 3. INTERNETDB QUERY  (Stage 2 — identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

def _get_with_backoff(ip: str) -> requests.Response | None:
    url = INTERNETDB_URL.format(ip=ip)
    for attempt in range(MAX_BACKOFF_RETRIES):
        try:
            resp = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": "Mangekyo-DiversityCollector/1.0"},
            )
        except requests.exceptions.RequestException:
            return None

        if resp.status_code == 429:
            wait = 2 ** (attempt + 1)
            print(f"  [!] Rate limited (429) — backing off {wait}s")
            time.sleep(wait)
            continue

        return resp
    return None


def query_internetdb(ip: str) -> dict | None:
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
# 4. HOST DICT BUILDER  (Stage 3 — identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cpe(cpe_str: str) -> tuple[str, str, str]:
    if cpe_str.startswith("cpe:/"):
        parts   = cpe_str.split(":")
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

    if version in ("*", "-"):
        version = ""
    return vendor, product, version


_PRODUCT_PORT_HINTS: dict[str, list[int]] = {
    "openssh":                    [22],
    "ssh":                        [22],
    "vsftpd":                     [21],
    "proftpd":                    [21],
    "ftp":                        [21],
    "pure-ftpd":                  [21],
    "http_server":                [80, 443, 8080, 8443],
    "httpd":                      [80, 443, 8080],
    "apache":                     [80, 443, 8080, 8443],
    "nginx":                      [80, 443, 8080, 8443],
    "lighttpd":                   [80, 443],
    "iis":                        [80, 443],
    "internet_information_services": [80, 443],
    "tomcat":                     [8080, 8443, 80, 443],
    "jetty":                      [8080, 8443],
    "samba":                      [139, 445],
    "smbd":                       [139, 445],
    "mysql":                      [3306],
    "mariadb":                    [3306],
    "postgresql":                 [5432],
    "mongodb":                    [27017],
    "redis":                      [6379],
    "memcached":                  [11211],
    "sql_server":                 [1433],
    "mssql":                      [1433],
    "dovecot":                    [143, 993, 110, 995],
    "postfix":                    [25, 587],
    "exim":                       [25, 587],
    "sendmail":                   [25, 587],
    "named":                      [53],
    "bind":                       [53],
    "telnet":                     [23],
    "rdp":                        [3389],
    "terminal_services":          [3389],
    "vnc":                        [5900, 5901, 5902],
    "unrealircd":                 [6667, 6697, 6660],
    "ircd":                       [6667],
    "elasticsearch":              [9200, 9300],
    "jenkins":                    [8080, 443],
    "webmin":                     [10000],
    "wordpress":                  [80, 443],
    "joomla":                     [80, 443],
}

_PORT_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",      22: "ssh",      23: "telnet",    25: "smtp",
    53: "dns",      80: "http",     110: "pop3",     143: "imap",
    443: "https",   445: "smb",     993: "imaps",    995: "pop3s",
    1433: "mssql",  3306: "mysql",  3389: "rdp",     5432: "postgres",
    5900: "vnc",    6379: "redis",  8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 10000: "webmin", 11211: "memcached",
    27017: "mongodb",
}


def _build_banner(vendor: str, product: str, version: str) -> str:
    v = version.lower().strip() if version else ""
    if vendor == "apache" and any(k in product for k in ("http", "httpd")):
        return f"apache/{v}" if v else "apache"
    if "tomcat" in product:
        return f"tomcat/{v}" if v else "tomcat"
    name = product.lower()
    return f"{name} {v}".strip() if v else name


def _match_cpes_to_ports(
    cpes: list[str],
    open_ports: list[int],
) -> dict[int, dict]:
    port_set = set(open_ports)
    assigned: dict[int, dict] = {}

    for cpe_str in cpes:
        vendor, product, version = _parse_cpe(cpe_str)
        if not product:
            continue

        candidate_ports: list[int] = []
        for keyword, hint_ports in _PRODUCT_PORT_HINTS.items():
            if keyword in product or product in keyword:
                candidate_ports.extend(hint_ports)

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
    ip    = raw.get("ip", "")
    ports = sorted(set(int(p) for p in raw.get("ports", []) if p))
    cpes  = [str(c) for c in raw.get("cpes",      []) if c]
    cves  = [str(v) for v in raw.get("vulns",     []) if v]
    hosts = [str(h) for h in raw.get("hostnames", []) if h]
    tags  = [str(t) for t in raw.get("tags",      []) if t]

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
# 5. SCORER  (Stage 4-a — identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

def score_internetdb_host(host_dict: dict) -> tuple[float, dict]:
    port_list = host_dict.get("ports", [])
    cpes      = host_dict.get("cpes",  [])
    cve_ids   = host_dict.get("cves",  [])

    if not port_list:
        return 0.0, _gte._zero_intel()

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

        if search_term:
            print(f"    [*] Querying NVD for: {search_term}")
            if search_term in seen_cpes:
                print("    [~] Duplicate CPE — reusing cached score.")
                nvd_risk, _ = seen_cpes[search_term]
            else:
                nvd_risk, _ = _gte.get_nvd_cvss(search_term)
                ver_field   = _gte._cpe_version_field(search_term)
                if ver_field in ("*", "", "-") and nvd_risk > 0:
                    discounted = int(nvd_risk * _gte._VERSION_UNKNOWN_DISCOUNT)
                    print(f"    [~] Version unknown — discount: {nvd_risk} -> {discounted}")
                    nvd_risk = discounted
                seen_cpes[search_term] = (nvd_risk, [])
        else:
            nvd_risk = 0

        epss_score = host_epss
        in_kev     = host_in_kev
        kev_bonus  = host_kev_bonus

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
# 6. FEATURE EXTRACTION  (Stage 4-b — identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(host_dict: dict, risk_score: float, intel: dict) -> dict:
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
# 7. CSV HELPERS  (Stage 4-c — identical to 0_collect_internetdb.py)
# ─────────────────────────────────────────────────────────────────────────────

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
# 8. DIVERSITY VERIFICATION HELPERS  (Stage 6)
# ─────────────────────────────────────────────────────────────────────────────

def _load_existing_services(training_csv: str) -> Counter:
    """
    Build a Counter of service/product strings already in the dataset.
    We use the 'filename' column (format internetdb/<ip> or censys/<ip>)
    and the tier column as proxies since the CSV stores aggregate rows.
    The feature matrix has per-port product info indirectly via CPE columns.
    We approximate using the 'filename' prefix as source label.
    """
    if not Path(training_csv).exists():
        return Counter()
    try:
        df = pd.read_csv(training_csv)
        if "tier" in df.columns:
            return Counter(df["tier"].dropna().astype(str).tolist())
        return Counter()
    except Exception:
        return Counter()


def _format_service_profile(service_counter: Counter, label: str) -> str:
    lines = [f"  {label}:"]
    total = sum(service_counter.values())
    for svc, cnt in service_counter.most_common(15):
        pct = cnt / max(total, 1) * 100
        lines.append(f"    {svc:<30} {cnt:>5}  ({pct:.1f}%)")
    return "\n".join(lines)


def print_diversity_report(
    this_run_services:    Counter,
    this_run_products:    Counter,
    existing_products:    Counter,
    n_kept:               int,
    n_checked:            int,
) -> None:
    """Print Stage 6 diversity analysis."""
    new_products = set(this_run_products.keys()) - set(existing_products.keys())

    print()
    print("=" * 70)
    print("STAGE 6 — DIVERSITY VERIFICATION REPORT")
    print("=" * 70)
    print(f"  IPs checked this run   : {n_checked:,}")
    print(f"  Hosts kept this run    : {n_kept:,}")
    print(f"  Yield                  : {n_kept / max(n_checked, 1) * 100:.1f}%")
    print()
    print(f"  Distinct products this run  : {len(this_run_products):,}")
    print(f"  Products already in dataset : {len(existing_products):,}")
    print(f"  NEW products (not in dataset): {len(new_products):,}")
    if new_products:
        top_new = sorted(new_products)[:20]
        print(f"    First 20: {', '.join(top_new)}")
    print()
    print("  Service-port breakdown this run:")
    for svc, cnt in this_run_services.most_common(20):
        print(f"    {svc:<35} {cnt:>4}")
    print()
    print("  Top products this run vs. existing dataset:")
    all_keys = set(this_run_products.keys()) | set(existing_products.keys())
    rows = []
    for k in all_keys:
        rows.append((k, this_run_products.get(k, 0), existing_products.get(k, 0)))
    rows.sort(key=lambda r: r[1], reverse=True)
    print(f"    {'Product':<30} {'This run':>10} {'Existing':>10}")
    print(f"    {'-'*30} {'-'*10} {'-'*10}")
    for product, run_cnt, exist_cnt in rows[:25]:
        print(f"    {product:<30} {run_cnt:>10} {exist_cnt:>10}")
    print("=" * 70)

# ─────────────────────────────────────────────────────────────────────────────
# 9. TEST MODE
# ─────────────────────────────────────────────────────────────────────────────

def run_test() -> None:
    print("[+] Diversity Collector — TEST MODE (100 IPs, no CSV writes)\n")

    ip_list = build_ip_list(MAX_IPS_TEST)

    checked = kept = had_ports = had_intel = 0
    example: dict | None = None
    this_run_services: Counter = Counter()
    this_run_products: Counter = Counter()

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
            hd = build_host_dict(raw)

            # Collect service/product for diversity reporting
            for p in hd["ports"]:
                svc_label = f"{p['port']}/{p['service'] or '?'}"
                this_run_services[svc_label] += 1
            for cpe in cpes:
                _, product, _ = _parse_cpe(cpe)
                if product:
                    this_run_products[product] += 1

            if example is None:
                example = hd

        if checked % LOG_INTERVAL == 0:
            print(f"  Checked: {checked} | With ports: {had_ports} | "
                  f"With CPE/CVE: {had_intel} | Kept: {kept}")

        time.sleep(RATE_LIMIT_SLEEP)

    print()
    print("=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"  IPs checked        : {checked}")
    print(f"  Had open ports     : {had_ports}  ({had_ports / max(checked, 1) * 100:.1f}%)")
    print(f"  Had CPE or CVE     : {had_intel}  ({had_intel / max(checked, 1) * 100:.1f}%)")
    print(f"  Kept (ports+intel) : {kept}  ({kept / max(checked, 1) * 100:.1f}% yield)")
    print()
    if example:
        print("EXAMPLE HOST DICT (first qualifying host):")
        print(json.dumps(example, indent=2))
    else:
        print("  (no qualifying host found — try increasing --test size)")
    print()
    if this_run_services:
        print("SERVICE BREAKDOWN (test sample):")
        for svc, cnt in this_run_services.most_common(20):
            print(f"  {svc:<35} {cnt:>3}")
    print("=" * 60)
    print("\nIf hosts look non-cloud, run without --test for the full sweep.")

# ─────────────────────────────────────────────────────────────────────────────
# 10. FULL COLLECTION RUN  (Stages 1-6)
# ─────────────────────────────────────────────────────────────────────────────

def run_full() -> None:
    print("[+] Diversity Collector — FULL RUN")
    print(f"    IP cap       : {MAX_IPS_FULL:,}")
    print(f"    Source       : ipverse/as-ip-blocks (isp + business ASNs)")
    print(f"    Training CSV : {TRAINING_CSV}")
    print(f"    Feature CSV  : {FEATURE_CSV}\n")

    print("[*] Initializing databases and threat intel feeds …")
    init_db()
    _gte.load_kev_catalog()
    print()

    # Load existing product set for diversity delta
    existing_products: Counter = Counter()
    if Path(TRAINING_CSV).exists():
        try:
            df_exist = pd.read_csv(TRAINING_CSV)
            if "filename" in df_exist.columns:
                # filenames like "internetdb/<ip>" — use as proxy for now
                pass
        except Exception:
            pass
    # We'll build this properly from kept hosts during run and compare at end

    seen_ips = _load_seen_ips(TRAINING_CSV)
    print(f"[*] {len(seen_ips):,} real-host IPs already in dataset — skipping duplicates\n")

    ip_list = build_ip_list(MAX_IPS_FULL)

    checked = kept = skipped = total_added = 0
    this_run_services: Counter = Counter()
    this_run_products: Counter = Counter()

    for ip in ip_list:
        checked += 1

        if checked % LOG_INTERVAL == 0:
            print(
                f"  Checked: {checked:,} | Kept: {kept} | "
                f"Skipped: {skipped} | Added: {total_added}"
            )

        if ip in seen_ips:
            skipped += 1
            continue

        raw = query_internetdb(ip)
        if raw is None:
            skipped += 1
            time.sleep(RATE_LIMIT_SLEEP)
            continue

        host_dict = build_host_dict(raw)

        svc_summary = ", ".join(
            f"{p['port']}/{p['service'] or '?'}" for p in host_dict["ports"]
        )
        print(
            f"\n  [{checked:,}] {ip}  |  ports: [{svc_summary}]"
            f"  cpes: {len(host_dict['cpes'])}  cves: {len(host_dict['cves'])}"
        )

        # Track services/products for diversity report
        for p in host_dict["ports"]:
            svc_label = f"{p['port']}/{p['service'] or '?'}"
            this_run_services[svc_label] += 1
        for cpe in host_dict["cpes"]:
            _, product, _ = _parse_cpe(cpe)
            if product:
                this_run_products[product] += 1

        try:
            risk_score, intel = score_internetdb_host(host_dict)
        except Exception as exc:
            print(f"    [!] Scoring error: {exc} — skipping")
            skipped += 1
            continue
        print(f"    => Risk score: {risk_score:.1f}")

        try:
            features = extract_features(host_dict, risk_score, intel)
        except Exception as exc:
            print(f"    [!] Feature error: {exc} — skipping")
            skipped += 1
            continue
        tier = features["tier"]

        training_row = {
            "filename":     f"diversity/{ip}",
            "target_name":  ip,
            "tier":         tier,
            "risk_score":   risk_score,
            "is_synthetic": 0,
        }
        for col in _gte._INTEL_COLS:
            training_row[col] = intel.get(col, 0)

        # Carry the stable id + explicit real label into the feature matrix too,
        # so the synthetic/real split is never re-inferred from values downstream.
        features["filename"]     = f"diversity/{ip}"
        features["is_synthetic"] = 0

        _append_training_row(TRAINING_CSV, training_row)
        _append_feature_row(FEATURE_CSV, features)

        seen_ips.add(ip)
        kept       += 1
        total_added += 1

        print(f"    => Saved. Real hosts in dataset: {len(seen_ips):,}")
        time.sleep(RATE_LIMIT_SLEEP)

    # Build existing_products from training CSV (before this run rows)
    if Path(TRAINING_CSV).exists():
        try:
            df_all = pd.read_csv(TRAINING_CSV)
            # Rows NOT from this diversity run
            prior = df_all[~df_all["filename"].str.startswith("diversity/", na=False)]
            # We don't have per-CPE columns in the training CSV, but we can
            # approximate from tier distribution for comparison
            existing_products = Counter(prior["tier"].dropna().astype(str).tolist())
            this_run_tiers    = Counter(
                df_all[df_all["filename"].str.startswith("diversity/", na=False)]["tier"]
                .dropna().astype(str).tolist()
            )
        except Exception:
            existing_products = Counter()
            this_run_tiers    = Counter()

    print()
    print("=" * 60)
    print("[V] Collection complete.")
    print(f"    IPs checked         : {checked:,}")
    print(f"    Hosts kept & scored : {kept:,}")
    print(f"    Hosts skipped       : {skipped:,}")
    print(f"    New samples added   : {total_added:,}")
    print("=" * 60)

    print_diversity_report(
        this_run_services = this_run_services,
        this_run_products = this_run_products,
        existing_products = existing_products,
        n_kept            = kept,
        n_checked         = checked,
    )

# ─────────────────────────────────────────────────────────────────────────────
# 11. ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if TEST_MODE:
        run_test()
    else:
        run_full()
