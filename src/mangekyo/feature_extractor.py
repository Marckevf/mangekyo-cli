"""
2_prepare_training_data.py
==========================
Project Mangekyo — Phase 2: Feature Engineering

Converts raw Nmap XML files into a numerical feature matrix
that the ML model can train on.

Input:
    training_data_v2.csv   — labeled dataset (filename + risk_score)
    xml_logs/              — Nmap XML files

Output:
    final_feature_matrix.csv — one row per host, all numerical

Features extracted:
    Service presence flags   — is_ssh, is_http, is_smb etc.
    Numerical features       — port_count, unique_service_count etc.
    Risk flags               — has_critical_port, has_cleartext etc.
    Target                   — risk_score

Author : Project Mangekyo
Python : 3.10+
Deps   : pandas, xml.etree.ElementTree (stdlib)
"""

from __future__ import annotations

import math
import statistics
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd


# ─────────────────────────────────────────────────────────────────────────────
# PORT DEFINITIONS
# ─────────────────────────────────────────────────────────────────────────────

# Top 15 services to one-hot encode
# Each becomes an is_<service> binary column
SERVICE_PORTS = {
    "is_ftp":        {21, 2121},
    "is_ssh":        {22},
    "is_telnet":     {23},
    "is_smtp":       {25, 587},
    "is_dns":        {53},
    "is_http":       {80, 8080, 8888},
    "is_https":      {443, 8443},
    "is_smb":        {139, 445},
    "is_rdp":        {3389},
    "is_mysql":      {3306},
    "is_postgres":   {5432},
    "is_vnc":        {5900},
    "is_redis":      {6379},
    "is_mongodb":    {27017},
    "is_mssql":      {1433},
}

# Ports that represent critical exposure regardless of CVEs
CRITICAL_PORTS     = {445, 23, 3389}

# Cleartext protocols — data transmitted unencrypted
CLEARTEXT_PORTS    = {21, 23, 25, 80, 110, 143, 2121}

# Database ports exposed — direct DB access risk
DATABASE_PORTS     = {3306, 5432, 1433, 27017, 6379}

# Columns written by the scorer that pass through directly to the feature matrix
_INTEL_COLS = [
    "max_epss_score", "has_high_epss", "has_kev_cve",
    "kev_port_count", "max_nvd_score", "mean_nvd_score", "nvd_zero_count",
]

# Base exposure scores — single source of truth (M3 consolidation).
# Dropped the local 2121:65 entry; 2121 now falls through to DEFAULT_EXPOSURE=5,
# matching the scorer/label. Imported as a package-relative module so it
# resolves regardless of cwd.
from .exposure_rules import EXPOSURE_RULES, DEFAULT_EXPOSURE


# ─────────────────────────────────────────────────────────────────────────────
# VERSION AGE DETECTION
# Services whose versions are known to be 5+ years old as of 2025.
# Any host running one of these gets has_ancient_version = 1.
# This is one of the strongest real-world risk signals — unpatched,
# end-of-life software is disproportionately targeted by attackers.
# ─────────────────────────────────────────────────────────────────────────────

ANCIENT_VERSION_PATTERNS = [
    # OpenSSH older than 8.0 (released 2019)
    "openssh 4.", "openssh 5.", "openssh 6.", "openssh 7.",
    # Apache older than 2.4.50 (pre-path-traversal fix 2021)
    "apache/1.", "apache/2.0", "apache/2.2",
    # nginx older than 1.18 (2020)
    "nginx/0.", "nginx/1.0", "nginx/1.2", "nginx/1.4",
    "nginx/1.6", "nginx/1.8", "nginx/1.10", "nginx/1.12",
    "nginx/1.14", "nginx/1.16",
    # MySQL older than 5.7 (5.7 EOL Oct 2023, 5.5/5.6 long dead)
    "mysql 5.0", "mysql 5.1", "mysql 5.5", "mysql 5.6",
    # PostgreSQL older than 12 (12+ still supported)
    "postgresql 8.", "postgresql 9.", "postgresql 10.", "postgresql 11.",
    # Samba older than 4.14 (2021)
    "samba 3.", "samba 4.0", "samba 4.1", "samba 4.2",
    "samba 4.3", "samba 4.4", "samba 4.5", "samba 4.6",
    "samba 4.7", "samba 4.8", "samba 4.9", "samba 4.10",
    "samba 4.11", "samba 4.12", "samba 4.13",
    # ProFTPD — all versions are old/unmaintained
    "proftpd",
    # vsftpd 2.x (3.x is current)
    "vsftpd 2.",
    # ISC BIND older than 9.16 (9.16 is oldest supported)
    "bind 9.4", "bind 9.5", "bind 9.6", "bind 9.7",
    "bind 9.8", "bind 9.9", "bind 9.10", "bind 9.11",
    # PHP older than 8.0 (7.x EOL Nov 2022)
    "php/5.", "php/7.",
    # Tomcat older than 9.0 (8.x EOL)
    "tomcat/5.", "tomcat/6.", "tomcat/7.", "tomcat/8.",
    # OpenSSL older than 1.1.1 (EOL Sept 2023)
    "openssl/0.", "openssl/1.0",
    # Linux kernel older than 4.x (very old)
    "linux 2.6", "linux 3.",
]

def parse_xml(xml_path: str) -> dict:
    """
    Parse one Nmap XML file and return a flat feature dict.
    Returns None if the file is malformed or host is down.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        # Host reachability check
        hosts_stat = root.find(".//hosts")
        if hosts_stat is not None and hosts_stat.get("up") == "0":
            return _dead_host_features()

        # Collect open ports
        open_ports    = []
        service_names = []
        has_version   = []
        all_banners   = []   # product + version strings for ancient version check

        for port_elem in root.findall(".//port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue

            port_id      = int(port_elem.get("portid", 0))
            service_elem = port_elem.find("service")

            svc_name = ""
            version  = ""
            product  = ""

            if service_elem is not None:
                svc_name = service_elem.get("name", "")
                version  = service_elem.get("version", "")
                product  = service_elem.get("product", "")

            open_ports.append(port_id)
            service_names.append(svc_name)

            # Build banner string for ancient version detection
            banner = f"{product} {version}".lower().strip()
            all_banners.append(banner)

            # Track whether version was identifiable
            version_known = bool(version) and "*" not in version
            has_version.append(version_known)

        # OS detection
        os_is_windows = _detect_windows(root)

        return _build_features(open_ports, service_names, has_version,
                               all_banners, os_is_windows)

    except Exception as e:
        print(f"    [!] Parse error {xml_path}: {e}")
        return None


def _detect_windows(root: ET.Element) -> int:
    """
    Return 1 if the host OS is Windows, 0 otherwise.
    Checks OS detection results and service fingerprints.
    """
    for osclass in root.findall(".//osclass"):
        if "windows" in osclass.get("osfamily", "").lower():
            return 1
    for osmatch in root.findall(".//osmatch"):
        if "windows" in osmatch.get("name", "").lower():
            return 1
    for service in root.findall(".//service"):
        if "windows" in service.get("ostype", "").lower():
            return 1
        if "ms-wbt" in service.get("name", "").lower():
            return 1
    return 0


def _has_ancient_version(banners: list[str]) -> int:
    """
    Return 1 if any service banner matches a known ancient version pattern.
    Ancient = software more than ~5 years old or known EOL.
    """
    for banner in banners:
        if not banner.strip():
            continue
        for pattern in ANCIENT_VERSION_PATTERNS:
            if pattern in banner:
                return 1
    return 0


def _dead_host_features() -> dict:
    """Return a zeroed feature dict for a host that was down."""
    features = {col: 0 for col in SERVICE_PORTS}
    features.update({
        "port_count":                0,
        "unique_service_count":      0,
        "max_base_exposure":         0,
        "mean_base_exposure":        0.0,
        "nvd_hit_count":             0,
        "versionless_service_count": 0,
        "log_port_count":            0.0,
        "versionless_ratio":         0.0,
        "base_exposure_std":         0.0,
        "max_epss_score":            0.0,
        "has_high_epss":             0,
        "has_kev_cve":               0,
        "kev_port_count":            0,
        "max_nvd_score":             0,
        "mean_nvd_score":            0.0,
        "nvd_zero_count":            0,
        "has_critical_port":         0,
        "has_cleartext_protocol":    0,
        "has_database_exposed":      0,
        "os_is_windows":             0,
        "has_ancient_version":       0,
        "host_is_down":              1,
    })
    return features


def _build_features(
    open_ports:    list[int],
    service_names: list[str],
    has_version:   list[bool],
    all_banners:   list[str],
    os_is_windows: int,
) -> dict:
    """Build the full feature dict from parsed port data."""

    features = {}

    # ── Service presence flags (one-hot) ─────────────────────────────────────
    port_set = set(open_ports)
    for col, port_group in SERVICE_PORTS.items():
        features[col] = 1 if port_set & port_group else 0

    # ── Numerical features ───────────────────────────────────────────────────
    features["port_count"]           = len(open_ports)
    features["unique_service_count"] = len(set(service_names) - {""})

    # Base exposure scores
    exposures = [EXPOSURE_RULES.get(p, DEFAULT_EXPOSURE) for p in open_ports]
    features["max_base_exposure"]  = max(exposures)  if exposures else 0
    features["mean_base_exposure"] = (
        round(sum(exposures) / len(exposures), 2) if exposures else 0.0
    )

    # Version tracking
    features["versionless_service_count"] = sum(
        1 for v in has_version if not v
    )

    port_count = len(open_ports)
    features["log_port_count"] = math.log(port_count) if port_count > 1 else 0.0
    features["versionless_ratio"] = (
        round(features["versionless_service_count"] / port_count, 4)
        if port_count > 0 else 0.0
    )
    features["base_exposure_std"] = (
        round(statistics.pstdev(exposures), 4) if len(exposures) > 1 else 0.0
    )

    # NVD hit count proxy
    features["nvd_hit_count"] = sum(
        1 for p in open_ports if p in EXPOSURE_RULES
    )

    # ── Risk flags ───────────────────────────────────────────────────────────
    features["has_critical_port"]      = 1 if port_set & CRITICAL_PORTS  else 0
    features["has_cleartext_protocol"] = 1 if port_set & CLEARTEXT_PORTS else 0
    features["has_database_exposed"]   = 1 if port_set & DATABASE_PORTS  else 0

    # NEW: OS and version age signals
    features["os_is_windows"]      = os_is_windows
    features["has_ancient_version"] = _has_ancient_version(all_banners)

    features["host_is_down"] = 0

    return features


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

def build_feature_matrix(
    labels_csv:  str = "training_data_v2.csv",
    output_csv:  str = "final_feature_matrix.csv",
) -> None:

    print("[+] Mangekyo Phase 2 — Feature Engineering")
    print(f"    Labels : {labels_csv}")
    print(f"    Output : {output_csv}\n")

    # Load labeled dataset.
    # NOTE: the label log (training_data_v2.csv) is a SUPERSET of this matrix —
    # internet-collected rows (internetdb/, diversity/) have no Nmap XML on disk
    # and so cannot be featurized here. The two files are joinable on `filename`;
    # treat the label log as the full record and this matrix as the modeling set.
    df = pd.read_csv(labels_csv)
    print(f"    Loaded {len(df)} labeled rows\n")

    rows = []
    skipped = 0

    for _, row in df.iterrows():
        xml_path   = str(row["filename"])
        risk_score = row["risk_score"]
        tier       = row.get("tier", "unknown")

        if not Path(xml_path).exists():
            print(f"    [!] Missing: {xml_path}")
            skipped += 1
            continue

        features = parse_xml(xml_path)

        if features is None:
            skipped += 1
            continue

        # Intel features from scorer — pass through from labels CSV
        for col in _INTEL_COLS:
            val = row.get(col, 0)
            features[col] = 0 if pd.isna(val) else val

        # Add metadata + carry the source-of-truth identifiers straight
        # through so synthetic/real never has to be re-inferred downstream.
        features["filename"]     = xml_path
        is_syn                   = row.get("is_synthetic", 0)
        features["is_synthetic"] = 0 if pd.isna(is_syn) else int(is_syn)
        features["tier"]         = tier
        features["risk_score"]   = risk_score
        rows.append(features)

    print(f"    Processed : {len(rows)} hosts")
    print(f"    Skipped   : {skipped} hosts\n")

    # Build dataframe
    feature_df = pd.DataFrame(rows)

    # Ensure consistent column order.
    # filename + is_synthetic lead the matrix as the stable join key and the
    # explicit synthetic/real label (never inferred downstream again).
    meta_cols    = ["filename", "is_synthetic", "tier"]
    flag_cols    = list(SERVICE_PORTS.keys())
    numeric_cols = [
        "port_count", "unique_service_count",
        "max_base_exposure", "mean_base_exposure",
        "nvd_hit_count", "versionless_service_count",
        "log_port_count", "versionless_ratio", "base_exposure_std",
        "max_epss_score", "mean_nvd_score", "max_nvd_score",
        "kev_port_count", "nvd_zero_count",
    ]
    risk_cols    = [
        "has_critical_port", "has_cleartext_protocol",
        "has_database_exposed", "os_is_windows",
        "has_ancient_version", "host_is_down",
        "has_high_epss", "has_kev_cve",
    ]
    target_col   = ["risk_score"]

    ordered_cols = meta_cols + flag_cols + numeric_cols + risk_cols + target_col
    feature_df   = feature_df[ordered_cols]

    # Save
    feature_df.to_csv(output_csv, index=False)

    # ── Summary report ────────────────────────────────────────────────────────
    print("=" * 55)
    print("  FEATURE MATRIX SUMMARY")
    print("=" * 55)
    print(f"  Rows     : {len(feature_df)}")
    print(f"  Columns  : {len(feature_df.columns)}")
    print(f"  Features : {len(ordered_cols) - 4} "
          f"(excl. filename + is_synthetic + tier + risk_score)")
    print()
    print("  Risk score distribution:")
    print(f"    Min    : {feature_df['risk_score'].min()}")
    print(f"    Max    : {feature_df['risk_score'].max()}")
    print(f"    Mean   : {feature_df['risk_score'].mean():.1f}")
    print(f"    Median : {feature_df['risk_score'].median():.1f}")
    print()
    print("  Service flag prevalence (% of hosts):")
    for col in flag_cols:
        pct = feature_df[col].mean() * 100
        bar = "#" * int(pct / 5)
        print(f"    {col:<25} {pct:5.1f}%  {bar}")
    print()
    print("  Risk flag prevalence:")
    for col in risk_cols:
        pct = feature_df[col].mean() * 100
        print(f"    {col:<30} {pct:5.1f}%")
    print("=" * 55)
    print(f"\n[V] Saved to {output_csv}")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    build_feature_matrix()