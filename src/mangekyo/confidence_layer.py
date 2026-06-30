"""
confidence_layer.py
===================
Project Mangekyo — Confidence scoring layer.

Confidence is a SEPARATE axis from risk.  It measures how much
real evidence was available to support the risk score, not how
dangerous the host is.

LOW confidence does NOT mean low risk.
It means: unresolved finding — the human's job is to investigate.

Scoring components (100 pts total):
  CPE presence       — 30 pts  (software identifiable at all / with version)
  Intel availability — 50 pts  (NVD CVSS + EPSS + CVE/KEV data found)
  Version coverage   — 20 pts  (proportion of ports with version info)

Thresholds:
  HIGH   >= 60   "Score is well-supported by available data."
  MEDIUM >= 30   "Score is partially supported by available data."
  LOW    <  30   (unresolved — see MSG_LOW)
"""

from __future__ import annotations

# ─── Thresholds ───────────────────────────────────────────────────────────────

_HIGH_THRESHOLD   = 60
_MEDIUM_THRESHOLD = 30

# ─── Labels and messages ──────────────────────────────────────────────────────

LABEL_HIGH   = "HIGH"
LABEL_MEDIUM = "MEDIUM"
LABEL_LOW    = "LOW"

MSG_HIGH = "Score is well-supported by available data."
MSG_MEDIUM = "Score is partially supported by available data."
MSG_LOW = (
    "Limited data. This score reflects what could NOT be verified, not confirmed "
    "safety. An exposed host we cannot fingerprint is an unresolved finding -- "
    "investigate to determine what is running before trusting this score in either "
    "direction. This applies equally to offense (worth probing further) and defense "
    "(an asset on your perimeter that you cannot account for is a gap, not a clearance)."
)


# ─── Public API ───────────────────────────────────────────────────────────────

def compute_confidence(
    host_dict: dict,
    intel:     dict,
    features:  dict,
) -> tuple[int, str, str, list[str], dict]:
    """
    Compute a confidence score for a scored host.

    Parameters
    ----------
    host_dict : output of build_host_dict()
    intel     : output of get_intel() — the 7 NVD/EPSS/KEV signals
    features  : output of extract_features() — the full feature dict

    Returns
    -------
    (score, label, message, reasons, sub_scores)

    score      — 0–100 int
    label      — "HIGH" / "MEDIUM" / "LOW"
    message    — the canonical label message
    reasons    — list of plain-English strings naming what drove low confidence;
                 empty when confidence is HIGH (nothing to flag)
    sub_scores — dict with keys "cpe" (0-30), "intel" (0-50), "version" (0-20)
    """
    reasons  = []     # things that hurt confidence
    evidence = []     # things that helped (used internally, not returned)
    cpe_pts  = 0
    intel_pts = 0

    port_list  = host_dict.get("ports", [])
    cpes       = host_dict.get("cpes",  [])
    cves       = host_dict.get("cves",  [])
    port_count = len(port_list)

    # ── Component 1: CPE presence  (0–30 pts) ────────────────────────────────
    # +15 host has at least one CPE (software identified at all)
    # +15 at least one CPE carries a real version string
    has_any_cpe      = len(cpes) > 0
    has_versioned_cpe = any(_cpe_has_version(c) for c in cpes)

    if has_any_cpe:
        cpe_pts += 15
        evidence.append(f"{len(cpes)} CPE(s) identified")
    else:
        reasons.append(
            f"{port_count} open port(s) but no identifiable software -- "
            "could not check for known CVEs."
        )

    if has_versioned_cpe:
        cpe_pts += 15
        evidence.append("version information present in CPEs")
    elif has_any_cpe:
        reasons.append(
            "CPE(s) found but no version information -- "
            "software identified but exact version unknown."
        )

    # ── Component 2: Intel availability  (0–50 pts) ───────────────────────────
    # +20 NVD CVSS data was available for at least one service
    # +20 EPSS exploitation probability retrieved
    # +10 CVEs or KEV confirmed
    max_nvd   = intel.get("max_nvd_score",  0)
    max_epss  = intel.get("max_epss_score", 0.0)
    has_kev   = intel.get("has_kev_cve",    0)

    if max_nvd > 0:
        intel_pts += 20
        evidence.append(f"NVD CVSS data available (max score {max_nvd})")
    else:
        reasons.append(
            "No NVD CVSS data -- software not in NVD, version unrecognised, "
            "or all services were unidentified."
        )

    if max_epss > 0.0:
        intel_pts += 20
        evidence.append(f"EPSS exploitation probability available ({max_epss:.1f}/100)")
    else:
        reasons.append(
            "No EPSS data -- no CVE IDs to look up exploitation probability."
        )

    if cves or has_kev:
        intel_pts += 10
        kev_tag = " (KEV match confirmed)" if has_kev else ""
        evidence.append(f"{len(cves)} CVE(s) found{kev_tag}")
    else:
        reasons.append(
            "No CVEs found -- either genuinely unaffected, or software "
            "could not be fingerprinted well enough to look up CVEs."
        )

    # ── Component 3: Version coverage  (0–20 pts) ────────────────────────────
    # Fraction of ports whose software version was identifiable.
    versionless_ratio = float(features.get("versionless_ratio", 1.0))
    versionless_ratio = max(0.0, min(1.0, versionless_ratio))  # clamp to valid range
    version_pts       = round((1.0 - versionless_ratio) * 20)

    if port_count > 0:
        versioned_n = round((1.0 - versionless_ratio) * port_count)
        missing_n   = port_count - versioned_n
        if missing_n == port_count:
            reasons.append(
                f"All {port_count} service(s) lacked version information."
            )
        elif missing_n > 0:
            reasons.append(
                f"{missing_n}/{port_count} service(s) had no version data -- "
                "partial coverage."
            )

    # ── Label + message ───────────────────────────────────────────────────────
    score = min(cpe_pts + intel_pts + version_pts, 100)

    if score >= _HIGH_THRESHOLD:
        label, message = LABEL_HIGH,   MSG_HIGH
    elif score >= _MEDIUM_THRESHOLD:
        label, message = LABEL_MEDIUM, MSG_MEDIUM
    else:
        label, message = LABEL_LOW,    MSG_LOW

    sub_scores = {"cpe": cpe_pts, "intel": intel_pts, "version": version_pts}
    return score, label, message, reasons, sub_scores


# ─── Internal helper ──────────────────────────────────────────────────────────

def _cpe_has_version(cpe_str: str) -> bool:
    """Return True if the CPE contains a real version field (not wildcard)."""
    try:
        if cpe_str.startswith("cpe:/"):
            parts = cpe_str.split(":")
            ver   = parts[4] if len(parts) > 4 else ""
        elif cpe_str.startswith("cpe:2.3:"):
            parts = cpe_str.split(":")
            ver   = parts[5] if len(parts) > 5 else ""
        else:
            return False
        return bool(ver) and ver not in ("*", "-", "")
    except Exception:
        return False
