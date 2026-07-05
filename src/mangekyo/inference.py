"""
inference.py
=============
Project Mangekyo — shared scoring pipeline for the CLI.

Bridges Nmap XML (one or more <host> elements) into the same
feature -> model -> confidence -> SHAP -> ATT&CK pipeline used by
test_score.py, but:

  * is multi-host aware (iterates every <host> in the XML, scoped
    element lookups so hosts never bleed into each other), and
  * uses the per-port <service><cpe> values Nmap already provides
    directly, instead of the InternetDB CPE-to-port heuristic.

Does not change the model, the scoring formula, or any training
data -- this module only assembles inputs for the frozen pipeline
(feature_extractor._build_features, confidence_layer.compute_confidence,
mitre_mapper.map_cves) and shapes the results for CLI output.
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from . import feature_extractor as _fe
from . import mitre_mapper as _mapper
from . import scoring_engine as _gte
from .confidence_layer import compute_confidence
from .paths import MODEL_PATH

# ─────────────────────────────────────────────────────────────────────────────
# MODEL LOADING
# ─────────────────────────────────────────────────────────────────────────────

def load_model():
    """Load the frozen model + build its SHAP explainer."""
    import joblib
    import shap
    if not Path(MODEL_PATH).exists():
        raise FileNotFoundError(
            "model.pkl not found. Download it from the GitHub release and "
            "place it in your data directory."
        )
    model = joblib.load(MODEL_PATH)
    explainer = shap.TreeExplainer(model)
    return model, explainer


# ─────────────────────────────────────────────────────────────────────────────
# NMAP XML PARSING (multi-host aware)
# ─────────────────────────────────────────────────────────────────────────────

def parse_nmap_hosts(xml_path: str) -> list[dict]:
    """
    Parse an Nmap XML file into a list of host dicts, one per <host>.

    Each host dict:
        ip, hostnames, ports (list of dicts with port/protocol/state/
        service/product/version/cpe), cpes (flat list of per-port CPEs),
        cves (empty -- filled in by get_intel), tags, host_is_down
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    return [_parse_host(host_elem) for host_elem in root.findall("host")]


def parse_nmap_hosts_from_string(xml_text: str) -> list[dict]:
    """Same as parse_nmap_hosts, but for Nmap XML already in memory
    (e.g. captured from `nmap -oX -` via subprocess)."""
    root = ET.fromstring(xml_text)
    return [_parse_host(host_elem) for host_elem in root.findall("host")]


def _parse_host(host_elem: ET.Element) -> dict:
    status = host_elem.find("status")
    is_up = status is None or status.get("state") == "up"

    ip = ""
    for addr in host_elem.findall("address"):
        if addr.get("addrtype") in ("ipv4", "ipv6"):
            ip = addr.get("addr", "")
            break

    hostnames = [
        h.get("name", "") for h in host_elem.findall("hostnames/hostname")
        if h.get("name")
    ]

    if not is_up:
        return {
            "ip": ip, "hostnames": hostnames, "ports": [], "cpes": [],
            "cves": [], "tags": [], "host_is_down": True,
        }

    ports: list[dict] = []
    cpes: list[str] = []

    for port_elem in host_elem.findall("ports/port"):
        state = port_elem.find("state")
        if state is None or state.get("state") != "open":
            continue

        port_id  = int(port_elem.get("portid", 0))
        protocol = port_elem.get("protocol", "tcp")

        service = product = version = cpe_str = ""
        service_elem = port_elem.find("service")
        if service_elem is not None:
            service = service_elem.get("name", "")
            product = service_elem.get("product", "")
            version = service_elem.get("version", "")
            cpe_elem = service_elem.find("cpe")
            if cpe_elem is not None and cpe_elem.text:
                cpe_str = cpe_elem.text.strip()

        ports.append({
            "port": port_id, "protocol": protocol, "state": "open",
            "service": service, "product": product, "version": version,
            "cpe": cpe_str,
        })
        if cpe_str:
            cpes.append(cpe_str)

    os_is_windows = _fe._detect_windows(host_elem)
    tags = ["windows"] if os_is_windows else []

    return {
        "ip": ip, "hostnames": hostnames, "ports": ports, "cpes": cpes,
        "cves": [], "tags": tags, "host_is_down": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CPE / BANNER HELPERS (mirrors test_score.py's self-contained helpers)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cpe(cpe_str: str) -> tuple[str, str, str]:
    if cpe_str.startswith("cpe:/"):
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
    if version in ("*", "-"):
        version = ""
    return vendor, product, version


def _build_banner(vendor: str, product: str, version: str) -> str:
    v = version.lower().strip() if version else ""
    p = product.lower()
    if vendor == "apache" and any(k in p for k in ("http", "httpd")):
        return f"apache/{v}" if v else "apache"
    if "tomcat" in p:
        return f"tomcat/{v}" if v else "tomcat"
    return (f"{p} {v}".strip() if v else p)


# ─────────────────────────────────────────────────────────────────────────────
# INTEL GATHERING (NVD / EPSS / KEV)
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_search_term(port_dict: dict) -> str | None:
    """Return the cleaned CPE search term for one port dict, or None."""
    cpe_str = port_dict.get("cpe", "")
    product = port_dict.get("product", "")
    version = port_dict.get("version", "")
    if cpe_str:
        fmt = _gte.format_cpe_23(cpe_str)
        if fmt:
            return _gte.clean_cpe_string(fmt)
    if product:
        fb = _gte.generate_fallback_cpe(product, version)
        if fb:
            return _gte.clean_cpe_string(fb)
    return None


def _fetch_nvd_one(st: str) -> tuple[str, int, list[str]]:
    """Fetch NVD data for one search term and return (term, nvd_risk, cve_ids).
    Cache hits return immediately; misses go through get_nvd_cvss() which
    holds the rate-limit lock for the duration of the API call."""
    ver = _gte._cpe_version_field(st)
    is_generic = ver in ("*", "", "-")
    nvd_risk, raw_cve_ids = _gte.get_nvd_cvss(st)
    if is_generic and nvd_risk > 0:
        nvd_risk = int(nvd_risk * _gte._VERSION_UNKNOWN_DISCOUNT)
    cve_ids = [] if is_generic else raw_cve_ids
    return st, nvd_risk, cve_ids


def get_intel(host_dict: dict) -> dict:
    """
    Query NVD/EPSS/KEV for this host's ports and return the 7 intel
    feature values.

    If host_dict["cves"] already carries CVE IDs (e.g. InternetDB's
    confirmed "vulns" list), that list is treated as authoritative and
    used as-is for EPSS/KEV/ATT&CK. Otherwise (e.g. an Nmap-derived host
    with no such list), host_dict["cves"] is populated from the CVE IDs
    NVD returns for the host's specific (versioned) CPE matches.

    Unique CPE lookups are dispatched in parallel (max 5 workers). Cache
    hits in get_nvd_cvss() return without touching the rate-limit lock, so
    they complete immediately.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    port_list = host_dict.get("ports", [])
    if not port_list:
        return {col: 0 for col in _fe._INTEL_COLS}

    # First pass: resolve search terms for every port.
    port_terms: list[str | None] = [_resolve_search_term(p) for p in port_list]

    # Pre-fetch all unique terms in parallel (cache hits skip the lock).
    seen_cpes: dict[str, tuple[int, list[str]]] = {}
    unique_terms = list({t for t in port_terms if t})
    if unique_terms:
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(_fetch_nvd_one, st): st for st in unique_terms}
            for future in as_completed(futures):
                try:
                    st, nvd_risk, cve_ids = future.result()
                    seen_cpes[st] = (nvd_risk, cve_ids)
                except Exception as exc:
                    failed_term = futures[future]
                    print(f"    [!] NVD lookup failed for '{failed_term}': "
                          f"{type(exc).__name__}: {exc}", file=sys.stderr)
                    seen_cpes[failed_term] = (0, [])

    # Second pass: aggregate per-port results using pre-fetched data.
    all_nvd: list[int] = []
    nvd_zero_count = 0
    cve_set: set[str] = set(host_dict.get("cves", []))
    augment_cves = not cve_set
    cve_by_port: dict[str, list[str]] = {}

    for port_dict, search_term in zip(port_list, port_terms):
        if search_term and search_term in seen_cpes:
            nvd_risk, cve_ids = seen_cpes[search_term]
        else:
            nvd_risk, cve_ids = 0, []

        if augment_cves:
            cve_set.update(cve_ids)
        if cve_ids:
            protocol = port_dict.get("protocol", "tcp")
            port_key = f"{port_dict['port']}/{protocol}"
            cve_by_port[port_key] = list(dict.fromkeys(cve_ids))

        all_nvd.append(nvd_risk)
        if nvd_risk == 0:
            nvd_zero_count += 1

    host_dict["cves"] = sorted(cve_set)
    cve_ids = host_dict["cves"]

    host_epss   = _gte.get_epss_score(cve_ids) if cve_ids else 0.0
    host_in_kev = _gte.check_kev(cve_ids)       if cve_ids else False
    kev_port_count = len(port_list) if host_in_kev else 0

    return {
        "max_epss_score": host_epss,
        "has_high_epss":  1 if host_epss > 50 else 0,
        "has_kev_cve":    1 if host_in_kev else 0,
        "kev_port_count": kev_port_count,
        "max_nvd_score":  max(all_nvd) if all_nvd else 0,
        "mean_nvd_score": round(sum(all_nvd) / len(all_nvd), 2) if all_nvd else 0.0,
        "nvd_zero_count": nvd_zero_count,
        "cve_by_port":    cve_by_port,
    }


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(host_dict: dict, intel: dict) -> dict:
    port_list = host_dict["ports"]
    open_ports = [p["port"] for p in port_list]

    service_names: list[str]  = []
    has_version:   list[bool] = []
    all_banners:   list[str]  = []

    for p in port_list:
        product = p.get("product", "")
        version = p.get("version", "")
        vendor  = ""
        if p.get("cpe"):
            vendor, _, _ = _parse_cpe(p["cpe"])

        service_names.append(product or p.get("service", ""))
        has_version.append(bool(version) and "*" not in version)
        all_banners.append(_build_banner(vendor, product, version))

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
    return features


# ─────────────────────────────────────────────────────────────────────────────
# TIERING
# ─────────────────────────────────────────────────────────────────────────────

def tier_for_score(score: float) -> str:
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    else:
        return "LOW"


# ─────────────────────────────────────────────────────────────────────────────
# TOP SIGNAL — short, data-driven summary of what drove the score
# ─────────────────────────────────────────────────────────────────────────────

def _build_top_signals(features: dict, intel: dict) -> list[str]:
    """
    Build a single short, data-driven signal string, e.g.:
        "KEV ✓ + EPSS 94.4"
        "NVD 9.1 CVSS"
        "3 unidentified services"

    Priority: KEV (confirmed exploited) > EPSS > 50 > NVD CVSS > 70.
    Falls back to unidentified-service count when none of those signals
    are present (low confidence driving the score).
    """
    has_kev  = bool(intel.get("has_kev_cve", 0))
    max_epss = float(intel.get("max_epss_score", 0.0))
    max_nvd  = float(intel.get("max_nvd_score", 0))

    parts: list[str] = []
    if has_kev:
        parts.append("KEV")
    if max_epss > 50:
        parts.append(f"EPSS {max_epss:.1f}")
    if max_nvd > 70:
        parts.append(f"NVD {max_nvd / 10:.1f}")

    if not parts:
        versionless = int(features.get("versionless_service_count", 0))
        if versionless > 0:
            noun = "service" if versionless == 1 else "services"
            parts.append(f"{versionless} unidentified {noun}")
        elif max_nvd > 0:
            parts.append(f"NVD {max_nvd / 10:.1f} CVSS")
        elif max_epss > 0:
            parts.append(f"EPSS {max_epss:.1f}")
        else:
            parts.append("No notable signals")
    elif len(parts) == 1 and parts[0].startswith("NVD"):
        parts[0] += " CVSS"

    return [" + ".join(parts)]


# ─────────────────────────────────────────────────────────────────────────────
# SCORE A SINGLE HOST -> STRUCTURED RESULT
# ─────────────────────────────────────────────────────────────────────────────

def score_host(host_dict: dict, model, explainer, max_tier3: int = 5) -> dict:
    """
    Run the full pipeline for one host dict and return a structured
    result. Does not print anything.
    """
    import numpy as np
    import pandas as pd

    ip = host_dict.get("ip", "unknown")
    port_list = host_dict.get("ports", [])

    if not port_list or host_dict.get("host_is_down"):
        intel    = {col: 0 for col in _fe._INTEL_COLS}
        features = _fe._dead_host_features()
    else:
        intel    = get_intel(host_dict)
        features = extract_features(host_dict, intel)

    feat_cols = list(model.feature_names_in_)
    X = pd.DataFrame([{col: features.get(col, 0) for col in feat_cols}])

    predicted_score = float(np.clip(model.predict(X)[0], 0.0, 100.0))
    tier = tier_for_score(predicted_score)

    conf_score, conf_label, conf_msg, conf_reasons, conf_sub = compute_confidence(
        host_dict, intel, features
    )

    shap_vals = explainer.shap_values(X)
    shap_series = (
        pd.Series(shap_vals[0], index=feat_cols)
        .sort_values(key=abs, ascending=False)
    )

    shap_top = []
    for feat, val in shap_series.head(5).items():
        shap_top.append({
            "feature":   feat,
            "shap":      round(float(val), 4),
            "value":     float(X[feat].iloc[0]),
            "direction": "up" if val > 0 else "down",
        })

    cves = host_dict.get("cves", [])
    attack_techniques = []
    if cves:
        mappings = _mapper.map_cves(cves, max_tier3=max_tier3)
        for m in mappings:
            if m["technique_id"] is None:
                continue
            attack_techniques.append({
                "cve_id":         m["cve_id"],
                "technique_id":   m["technique_id"],
                "technique_name": m["technique_name"],
                "tactic":         m["tactic"],
                "source":         m.get("_source", ""),
                "mitigations":    m.get("mitigations", []),
            })

    top_signals = _build_top_signals(features, intel)

    return {
        "host":                   ip,
        "hostnames":              host_dict.get("hostnames", []),
        "risk_score":             round(predicted_score, 1),
        "tier":                   tier,
        "confidence":             conf_label,
        "confidence_score":       conf_score,
        "confidence_sub_scores":  conf_sub,
        "confidence_message":     conf_msg,
        "confidence_reasons":     conf_reasons,
        "open_ports":             [p["port"] for p in port_list],
        "top_signals":            top_signals,
        "cves":                   cves,
        "cve_count":              len(cves),
        "cve_by_port":            intel.get("cve_by_port", {}),
        "shap_top":               shap_top,
        "attack_techniques":      attack_techniques,
        "policy_override":        None,
        "intel":                  intel,
        "features":               features,
    }


# ─────────────────────────────────────────────────────────────────────────────
# THREAT-INTEL INIT (KEV catalog + local DB cache)
# ─────────────────────────────────────────────────────────────────────────────

def init_threat_intel() -> None:
    """Initialise the local DB and load the CISA KEV catalog (read-only)."""
    _gte.init_db()
    _gte.load_kev_catalog()
