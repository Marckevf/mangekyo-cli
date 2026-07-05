"""
1_generate_ground_truth.py
==========================
Project Mangekyo — Ground Truth Engine (Expert Teacher / SSoT Grader)

Changes from v1:
  FIX-1  Logarithmic stacking penalty — replaces flat +2/port linear model.
          Prevents score compression at 100.0 for any host with 6+ services.
  FIX-2  Per-host CPE deduplication — identical CPE strings on the same host
          (e.g. dovecot_imapd appearing on port 143 AND 993) are scored once
          and their risk re-used, not double-counted in the aggregation list.
  FIX-3  Version-less CPE confidence discount — wildcard version CPEs receive
          a 35% penalty, separating "confirmed vulnerable version" from
          "unknown version, possibly vulnerable." Breaks Windows-only clusters.
  FIX-4  HTTP 429 / non-200 surfaced explicitly — silent return 0 replaced
          with a logged warning so rate-limit failures are visible.
  FIX-5  DISTRO_SUFFIX compiled at module level — not re-compiled per call.
  FIX-6  is_generic detection tightened — checks version field == "*" instead
          of substring match on the whole CPE string.

Changes from v2 (patch round):
  PATCH-A  CPE semicolon cleaner — strips build tags from version field before
            any other rule runs. e.g. "15.00.2000.00;_rtm" → "15.00.2000.00".
            Fixes MSSQL CPEs that caused NVD to return 0 results, which
            previously forced hard_target to fall back to raw base_risk only.
  PATCH-B  Base-risk uncertainty discount — when NVD returns 0 CVEs AND the
            CPE version is a wildcard, base_risk is multiplied by 0.75 instead
            of used at face value. Breaks the Windows-RDP-only cluster at 70.0
            (all six hosts were identical; now ~52.5).
  PATCH-C  Log penalty coefficient reduced 8.0 → 5.5 — prevents borderline
            hosts (medium-severity CVEs, 3–5 services) from being dragged to
            100.0 by the aggregation penalty alone. Hosts that are genuinely
            critical still reach 100; borderline hosts now land in the 75–90
            range, giving the ML model meaningful gradient to learn from.

Changes from v3 (EPSS + KEV integration):
  INTEL-1  CISA KEV integration — downloads the CISA Known Exploited
            Vulnerabilities catalog at startup (free, no API key).
            Any CVE confirmed actively exploited in the wild receives a
            flat +15 point bonus. This is the strongest real-world signal:
            not "this could be exploited" but "attackers are using this now."
            Catalog cached in memory, refreshed each run (~1100 CVEs).

  INTEL-2  EPSS integration — queries the FIRST Exploit Prediction Scoring
            System API per CVE ID (free, no API key, no rate limit noted).
            EPSS estimates the probability of exploitation within 30 days
            using ML trained on real-world threat intelligence. Score 0–1,
            contributes 20% weight in the new hybrid formula. Cached in
            local DB to avoid redundant API calls.

  INTEL-3  Updated hybrid scoring formula — four-signal blend:
            Old: (nvd_risk × 0.80) + (base_risk × 0.20)
            New: (nvd_risk × 0.60)      ← CVSS severity
               + (base_risk × 0.15)     ← architectural exposure
               + (epss_score × 0.20)    ← exploitation likelihood
               + (kev_bonus × 15.0)     ← confirmed wild exploitation
            CVSS tells you how bad. EPSS tells you how likely. KEV tells
            you it's already happening. Base risk tells you the architecture
            is exposed. All four signals together = Senior SA judgment.
"""

import json
import math
import os
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
import requests

from . import mitre_mapper as _mitre_mod
from . import paths
from .mangekyo_db import get_local_score, init_db, save_local_score


# ─────────────────────────────────────────────────────────────────────────────
# NVD API KEY — loaded from .env at import time
# Authenticated: 0.6 s between calls  (50 req/30 s)
# Unauthenticated: 6.5 s between calls (5 req/30 s)
# ─────────────────────────────────────────────────────────────────────────────

from .config import NVD_API_KEY as _NVD_API_KEY, NVD_RATE_DELAY as _NVD_SLEEP

# Serialises actual NVD API calls across threads so rate limiting is respected
# even when get_nvd_cvss() is called from a ThreadPoolExecutor.  Cache hits
# return before acquiring this lock, so they are never blocked.
#
# Rate limiting uses a timestamp-based spacing lock: the gap check + remaining
# sleep is serialised under the lock so concurrent threads dispatch requests at
# least _NVD_SLEEP apart, but the network request itself runs OUTSIDE the lock
# so multiple calls can be in flight at once. This preserves ThreadPoolExecutor
# parallelism while enforcing real inter-request spacing (matching the pattern
# in mitre_mapper._fetch_cwe_for_cve).
_nvd_api_lock = threading.Lock()
_last_nvd_req = 0.0   # monotonic timestamp of the most recent NVD request dispatch

# Set once NVD rejects the configured key (HTTP 404 "Invalid apiKey"); the key
# is then dropped for the rest of the session and requests fall back to the
# unauthenticated rate limit instead of 404ing on every call.
_nvd_key_rejected = False
_NVD_SLEEP_UNAUTH = 6.5

# ─────────────────────────────────────────────────────────────────────────────
# ZONE 0A: THREAT INTELLIGENCE FEEDS
# CISA KEV + EPSS — free, no API key required
# ─────────────────────────────────────────────────────────────────────────────

# CISA Known Exploited Vulnerabilities catalog
_KEV_URL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_CACHE_FILE = paths.KEV_CACHE_PATH
_KEV_SET: set[str] = set()   # loaded at startup, CVE IDs in the wild

# EPSS API — Exploit Prediction Scoring System by FIRST
_EPSS_URL = "https://api.first.org/data/v1/epss"
_EPSS_CACHE: dict[str, float] = {}   # in-process cache: CVE ID → EPSS score


_KEV_TTL_SECONDS = 86_400  # 24 hours


def load_kev_catalog() -> None:
    """
    Download and cache the CISA Known Exploited Vulnerabilities catalog.
    Populates _KEV_SET with confirmed actively-exploited CVE IDs.
    Uses local cache if < 24 h old; only fetches from CISA when stale.
    """
    global _KEV_SET
    if _KEV_CACHE_FILE.exists():
        age = time.time() - _KEV_CACHE_FILE.stat().st_mtime
        if age < _KEV_TTL_SECONDS:
            print(f"[*] KEV catalog: local cache is {age/3600:.1f}h old — skipping download")
            _load_kev_from_file()
            return
    try:
        print("[*] Fetching CISA KEV catalog...")
        resp = requests.get(_KEV_URL, timeout=15,
                            headers={"User-Agent": "Mangekyo-GTE/3.0"})
        if resp.status_code == 200:
            data = resp.json()
            cves = {v["cveID"] for v in data.get("vulnerabilities", [])}
            _KEV_SET = cves
            _KEV_CACHE_FILE.write_text(json.dumps(list(cves)), encoding="utf-8")
            print(f"    [+] KEV loaded: {len(_KEV_SET)} confirmed exploited CVEs")
        else:
            _load_kev_from_file()
    except Exception as exc:
        print(f"    [!] KEV fetch failed ({exc}) — trying local cache", file=sys.stderr)
        _load_kev_from_file()


def _load_kev_from_file() -> None:
    """Fallback: load KEV from the local cache file if it exists."""
    global _KEV_SET
    if _KEV_CACHE_FILE.exists():
        try:
            _KEV_SET = set(json.loads(_KEV_CACHE_FILE.read_text(encoding="utf-8")))
            print(f"    [~] KEV loaded from local cache: {len(_KEV_SET)} CVEs")
        except Exception:
            print("    [!] KEV local cache unreadable — KEV scoring disabled", file=sys.stderr)
            _KEV_SET = set()
    else:
        print("    [!] No KEV cache available — KEV scoring disabled this run", file=sys.stderr)
        _KEV_SET = set()


def get_epss_score(cve_ids: list[str]) -> float:
    """
    Query FIRST EPSS API for a list of CVE IDs.
    Returns the MAXIMUM EPSS score across all CVEs (worst-case exploitation
    probability), normalized to 0–100 to match the nvd_risk scale.

    EPSS score of 1.0 = 100% probability of exploitation in next 30 days.
    Cached in-process to avoid redundant API calls per run.
    """
    if not cve_ids:
        return 0.0

    scores = []
    uncached = []

    # Check in-process cache first
    for cve_id in cve_ids:
        if cve_id in _EPSS_CACHE:
            scores.append(_EPSS_CACHE[cve_id])
        else:
            uncached.append(cve_id)

    # Batch query for uncached CVEs (EPSS supports comma-separated). Chunked
    # to stay under the API's URL-length limit -- a single request with 100+
    # CVE IDs gets rejected outright, silently zeroing the whole result.
    _EPSS_CHUNK_SIZE = 75
    for i in range(0, len(uncached), _EPSS_CHUNK_SIZE):
        chunk = uncached[i:i + _EPSS_CHUNK_SIZE]
        params = {"cve": ",".join(chunk)}
        for attempt in range(3):
            try:
                resp = requests.get(_EPSS_URL, params=params, timeout=10,
                                    headers={"User-Agent": "Mangekyo-GTE/3.0"})
                if resp.status_code == 429:
                    time.sleep(2 ** (attempt + 1))
                    continue
                if resp.status_code == 200:
                    for entry in resp.json().get("data", []):
                        cve_id   = entry.get("cve", "")
                        epss_val = float(entry.get("epss", 0.0))
                        _EPSS_CACHE[cve_id] = epss_val
                        scores.append(epss_val)
                else:
                    print(f"    [!] EPSS API returned {resp.status_code}", file=sys.stderr)
                break
            except Exception as exc:
                print(f"    [!] EPSS fetch failed: {exc}", file=sys.stderr)
                break

    if not scores:
        return 0.0

    # Max score × 100 to normalize to the same 0–100 scale as nvd_risk
    return round(max(scores) * 100, 1)


def check_kev(cve_ids: list[str]) -> bool:
    """Return True if any of the given CVE IDs are in the CISA KEV catalog."""
    return bool(_KEV_SET & set(cve_ids))


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 0: CPE CLEANING ENGINE
# Compiled once at module level (FIX-5)
# ─────────────────────────────────────────────────────────────────────────────

_DISTRO_SUFFIX = re.compile(
    r"_("
    r"ubuntu|debian|deb\d|centos|fedora|rhel|suse|arch|alpine|gentoo|mint|"
    r"raspbian|kali|manjaro|slackware|freebsd|openbsd|netbsd|"
    r"squeeze|lenny|wheezy|jessie|stretch|buster|bullseye|bookworm|"
    r"trusty|xenial|bionic|focal|jammy|noble|etch|sarge|woody"
    r")[^:]*",
    re.IGNORECASE,
)
_RANGE_PATTERN = re.compile(r"^([\d.]+)[xX\w]*_-_")


def clean_cpe_string(cpe_str: str) -> str:
    """
    Cleans a dirty CPE 2.3 string from Nmap output.

    Rules applied (in order):
      1. Strip OS-specific distro suffixes from the version component
         e.g. "7.6p1_ubuntu_4ubuntu0.3" → "7.6p1"
      2. Collapse version ranges like "3.x_-_4.x" to the first major version
         e.g. "3.x_-_4.x" → "3.0",  "2.4_-_2.9" → "2.4"
      3. Replace remaining underscores between digits with dots
         e.g. "1_2_3" → "1.2.3"
    """
    if not cpe_str or not cpe_str.startswith("cpe:"):
        return cpe_str

    parts = cpe_str.split(":")
    if len(parts) < 6:
        return cpe_str

    version = parts[5]

    # Rule 0 — strip build tags after semicolon (PATCH-A)
    # e.g. "15.00.2000.00;_rtm" → "15.00.2000.00"
    # NVD rejects CPEs with semicolons and returns 0 results silently.
    version = version.split(";")[0].strip()

    # Rule 1 — strip OS distro suffixes
    version = _DISTRO_SUFFIX.sub("", version)
    version = re.sub(r"_\d+[a-z]+[\w.]*$", "", version, flags=re.IGNORECASE)

    # Rule 2 — collapse version ranges
    m = _RANGE_PATTERN.search(version)
    if m:
        extracted = m.group(1).rstrip(".")
        version = extracted if "." in extracted else f"{extracted}.0"

    # Rule 3 — underscore → dot between digits
    version = re.sub(r"(?<=\d)_(?=\d)", ".", version)

    rebuilt = parts[:5] + [version]
    trailing = (parts[6:] + ["*"] * 7)[:7]
    return ":".join(rebuilt + trailing)


def parse_nmap_cpe(raw: str) -> dict:
    """Parse a cleaned CPE 2.3 string into a dict for easy downstream use."""
    cleaned = clean_cpe_string(raw)
    parts = cleaned.split(":")
    return {
        "raw_input": raw,
        "cleaned":   cleaned,
        "type":      parts[2] if len(parts) > 2 else "*",
        "vendor":    parts[3] if len(parts) > 3 else "*",
        "product":   parts[4] if len(parts) > 4 else "*",
        "version":   parts[5] if len(parts) > 5 else "*",
    }


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 1: THE BRAIN'S VOCABULARY
# ─────────────────────────────────────────────────────────────────────────────

INTEL_KEYWORDS = [
    "proftpd", "apache", "nginx", "openssh", "samba",
    "bind", "vsftpd", "microsoft-ds", "rpcbind",
]

# ─────────────────────────────────────────────────────────────────────────────
# ZONE 2: THE RULEBOOK (Port exposure baseline scores)
# Consolidated (M3): single source of truth lives in exposure_rules.py.
# Imported as a package-relative module so it resolves regardless of cwd.
# ─────────────────────────────────────────────────────────────────────────────

from .exposure_rules import EXPOSURE_RULES, DEFAULT_EXPOSURE

# ─────────────────────────────────────────────────────────────────────────────
# ZONE 3: THE PRECISION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def format_cpe_23(nmap_cpe: str) -> str | None:
    """Standardises CPE strings for NVD and DB lookups."""
    if not nmap_cpe:
        return None
    if nmap_cpe.startswith("cpe:2.3:"):
        return nmap_cpe
    if nmap_cpe.startswith("cpe:/"):
        core_cpe = nmap_cpe.replace("cpe:/", "")
        parts = core_cpe.split(":")
        # CPE 2.3 needs exactly 11 components after "cpe:2.3:"
        padded = parts + ["*"] * (11 - len(parts))
        return "cpe:2.3:" + ":".join(padded[:11])
    return None


def generate_fallback_cpe(product: str, version: str) -> str | None:
    """Builds a best-effort CPE from a raw Nmap product/version string."""
    if not product:
        return None
    vendor = product.split()[0].lower()
    prod   = product.replace(" ", "_").lower()
    ver    = version.replace(" ", "_").lower() if version else "*"
    return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"


def _cpe_version_field(cpe: str) -> str:
    """Extract the version component (index 5) from a CPE 2.3 string."""
    parts = cpe.split(":")
    return parts[5] if len(parts) > 5 else "*"


def get_nvd_cvss(search_term: str) -> tuple[int, list[str]]:
    """
    Query NVD for the CVSS risk of a CPE string.

    Returns a tuple: (nvd_risk_0_to_100, list_of_cve_ids)
    nvd_risk is CVSS base score × 10.
    cve_ids are used downstream for EPSS + KEV lookups.

    FIX-4: Non-200 HTTP responses now print an explicit warning instead of
            silently returning 0, so rate-limit hits are visible in the log.
    FIX-6: is_generic now checks the actual version field instead of doing a
            substring match on the whole CPE, which previously mis-classified
            versioned CPEs with wildcard trailing fields as generic.
    """
    if not search_term:
        return 0, []

    # Normalise input to CPE 2.3
    if search_term.startswith("cpe:/") or search_term.startswith("cpe:2.3:"):
        cpe_23 = format_cpe_23(search_term)
    else:
        cpe_23 = generate_fallback_cpe(search_term, "*")

    if not cpe_23:
        return 0, []

    # 1. CHECK THE LOCAL DB CACHE
    cached = get_local_score(cpe_23)
    if cached is not None:
        # Cache hit — full result (score + CVE IDs). Returning the cached CVE
        # list (instead of []) keeps EPSS/KEV/MITRE deterministic regardless of
        # cache state (M1 fix).
        cached_score, cached_cves = cached
        return int(cached_score * 10), cached_cves

    # 2. DETERMINE SEARCH MODE (FIX-6: version field check, not substring)
    version_field = _cpe_version_field(cpe_23)
    is_generic    = version_field in ("*", "", "-")

    if is_generic:
        product_name = cpe_23.split(":")[4]
        print(f"    [*] Keyword Search for: {product_name.upper()}")
        search_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?keywordSearch={product_name}"
        )
    else:
        print(f"    [!] LEARNING: Calling NVD API for '{cpe_23}'...")
        search_url = (
            f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            f"?cpeName={cpe_23}"
        )

    # 3. FETCH FROM NVD API (one call at a time to respect rate limiting)
    try:
        global _last_nvd_req, _NVD_SLEEP, _nvd_key_rejected

        response = None
        while True:
            _hdrs = {"User-Agent": "Mangekyo-GTE/3.0"}
            sent_key = bool(_NVD_API_KEY) and not _nvd_key_rejected
            if sent_key:
                _hdrs["apiKey"] = _NVD_API_KEY

            # Enforce a minimum gap of _NVD_SLEEP between request dispatches
            # across all threads. Only the gap check + remaining sleep is held
            # under the lock (often near-zero when requests are naturally
            # spaced by network latency); the network request runs outside it
            # so calls can overlap.
            with _nvd_api_lock:
                elapsed = time.monotonic() - _last_nvd_req
                if elapsed < _NVD_SLEEP:
                    time.sleep(_NVD_SLEEP - elapsed)
                _last_nvd_req = time.monotonic()

            for attempt in range(2):
                try:
                    response = requests.get(search_url, headers=_hdrs, timeout=25)
                    break
                except requests.exceptions.Timeout:
                    if attempt == 0:
                        print(f"    [!] NVD timeout — retrying in 2s...", file=sys.stderr)
                        time.sleep(2)
                    else:
                        print(f"    [!] NVD timeout (retry) for '{cpe_23}' — defaulting to 0.", file=sys.stderr)
                        return 0, []

            if response is None:
                return 0, []

            # NVD reports a rejected/deactivated API key as HTTP 404 with a
            # "message: Invalid apiKey" response header. Warn loudly once,
            # drop the key for the rest of the session, and retry this (and
            # all later) requests unauthenticated at the public rate limit
            # instead of silently 404ing everything.
            if (sent_key and response.status_code == 404
                    and "invalid apikey" in response.headers.get("message", "").lower()):
                with _nvd_api_lock:
                    if not _nvd_key_rejected:
                        _nvd_key_rejected = True
                        _NVD_SLEEP = _NVD_SLEEP_UNAUTH
                        print(
                            "[!!] NVD rejected the configured API key (HTTP 404 'Invalid apiKey').\n"
                            "     Falling back to UNAUTHENTICATED mode for the rest of this run "
                            f"({_NVD_SLEEP_UNAUTH}s between requests).\n"
                            f"     Rotate NVD_API_KEY in {paths.ENV_PATH} — NVD deactivates unused or expired keys.",
                            file=sys.stderr,
                        )
                continue
            break

        # FIX-4: Explicit non-200 handling
        if response.status_code == 429:
            print(f"    [!] RATE LIMITED by NVD — score defaulting to 0. Consider adding an API key.", file=sys.stderr)
            return 0, []
        if response.status_code != 200:
            print(f"    [!] NVD returned HTTP {response.status_code} for '{cpe_23}' — defaulting to 0.", file=sys.stderr)
            return 0, []

        data     = response.json()
        scores   = []
        cve_ids  = []

        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id   = cve_data.get("id", "")
            if cve_id:
                cve_ids.append(cve_id)

            m    = cve_data.get("metrics", {})
            cvss = m.get("cvssMetricV31", []) or m.get("cvssMetricV30", [])
            if cvss:
                scores.append(cvss[0].get("cvssData", {}).get("baseScore", 0.0))

        if scores:
            # Generic keyword search → average (breadth across all versions)
            # Specific version CPE   → max    (worst-case for that exact version)
            final_nvd_score = (
                sum(scores) / len(scores) if is_generic else max(scores)
            )
            print(f"    [+] NVD Score: {round(final_nvd_score, 2)} "
                  f"({'avg' if is_generic else 'max'} of {len(scores)} CVEs)")
        else:
            print(f"    [!] No NVD entries found for '{cpe_23}'.", file=sys.stderr)
            final_nvd_score = 0.0

        save_local_score(cpe_23, final_nvd_score, cve_ids)
        return int(final_nvd_score * 10), cve_ids

    except Exception as exc:
        print(f"    [!] API Error for '{cpe_23}': {exc}", file=sys.stderr)
        return 0, []


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 4: AGGREGATION ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def calculate_final_score(port_scores: list[float]) -> float:
    """
    Attack Surface Aggregation with logarithmic stacking penalty.

    FIX-1 — replaces the flat +2/port linear model that caused score
    compression (every 6+ service host hitting 100.0 regardless of severity).

    Formula:
        final = max_service_score
              + log_stacking_penalty   (diminishing returns per extra port)
              + secondary_contribution (weighted avg of non-max services × 0.15)

    Log penalty curve (base 5.5):  ← PATCH-C: reduced from 8.0 to prevent
                                       borderline hosts saturating at 100.0
        1 service  →  +0.0
        2 services →  +3.8
        3 services →  +6.0
        5 services →  +8.9
        7 services →  +10.7
        10 services → +12.7
        15 services → +15.0

    This means a host with many low-severity ports cannot hit 100 unless its
    top service is already in the high-80s, which is architecturally correct.
    """
    if not port_scores:
        return 0.0

    sorted_scores = sorted(port_scores, reverse=True)
    base_max      = sorted_scores[0]
    n             = len(sorted_scores)

    # Logarithmic stacking penalty (PATCH-C: coefficient 5.5, down from 8.0)
    log_penalty = 5.5 * math.log(n) if n > 1 else 0.0

    # Secondary services contribute a dampened average (not just port count)
    secondary = sorted_scores[1:]
    secondary_contribution = (
        (sum(secondary) / len(secondary)) * 0.15 if secondary else 0.0
    )

    final = base_max + log_penalty + secondary_contribution
    return round(min(final, 100.0), 1)


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 5: MAIN GRADING PIPELINE
# ─────────────────────────────────────────────────────────────────────────────

# Confidence discount applied when version is unknown (wildcard CPE)
_VERSION_UNKNOWN_DISCOUNT = 0.65   # FIX-3

_INTEL_COLS = [
    "max_epss_score", "has_high_epss", "has_kev_cve",
    "kev_port_count", "max_nvd_score", "mean_nvd_score", "nvd_zero_count",
]


def _zero_intel() -> dict:
    d = {col: 0 for col in _INTEL_COLS}
    d["mitre_mappings"] = []
    return d


def calculate_machine_risk(xml_file: str) -> tuple[float, dict]:
    """
    SSoT Ground Truth Grader.

    Four-signal hybrid scoring formula per service (INTEL-3):
        port_risk = (nvd_risk  × 0.60)   ← CVSS severity
                  + (base_risk × 0.15)   ← architectural exposure
                  + (epss     × 0.20)    ← exploitation likelihood
                  + (kev      × 15.0)    ← confirmed wild exploitation

    Then aggregated across all open services via calculate_final_score().

    FIX-2:   Per-host CPE deduplication
    FIX-3:   Wildcard-version confidence discount
    INTEL-1: KEV bonus — flat +15 if any CVE confirmed exploited in wild
    INTEL-2: EPSS — exploitation probability contributes 20% of score
    """
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        # HOST REACHABILITY CHECK
        hosts_stat = root.find(".//hosts")
        if hosts_stat is not None and hosts_stat.get("up") == "0":
            print(f"    [!] SKIPPING: Host in {xml_file} was DOWN during scan.")
            return 0.0, _zero_intel()

        all_port_risks:  list[float] = []
        all_epss_scores: list[float] = []
        all_nvd_risks:   list[int]   = []
        all_cve_ids:     list[str]   = []   # accumulated for host-level MITRE mapping
        kev_port_count:  int         = 0
        nvd_zero_count:  int         = 0
        cve_by_port:     dict[str, list[str]] = {}
        # FIX-2: CPE → (nvd_risk, cve_ids) already computed this host
        seen_cpes: dict[str, tuple[int, list[str]]] = {}

        for port_elem in root.findall(".//port"):
            if port_elem.find("state").get("state") != "open":
                continue

            port_id      = int(port_elem.get("portid"))
            service_elem = port_elem.find("service")

            # DATA EXTRACTION
            product = (service_elem.get("product", "")  if service_elem is not None else "")
            version = (service_elem.get("version", "")  if service_elem is not None else "")
            script_data = "".join(
                str(s.get("output", "")).lower()
                for s in port_elem.findall("script")
            )

            # DEEP SCAN FALLBACK for missing product names
            if not product:
                for word in INTEL_KEYWORDS:
                    if (word in script_data
                            or word in str(service_elem.get("servicefp", "")).lower()):
                        product = word
                        print(f"    [!] DEEP SCAN FOUND: {product.upper()} on port {port_id}")
                        break

            # CPE SANITIZATION
            raw_cpe      = service_elem.get("cpe") if service_elem is not None else None
            search_term  = None

            if raw_cpe:
                formatted = format_cpe_23(raw_cpe)
                if formatted:
                    search_term = clean_cpe_string(formatted)
                else:
                    print(f"    [~] Could not format CPE '{raw_cpe}' — falling back to product name.")

            if not search_term and product:
                search_term = clean_cpe_string(generate_fallback_cpe(product, version))

            # NVD QUERY — with deduplication (FIX-2)
            if search_term:
                print(f"    [*] Querying NVD for: {search_term}")

                if search_term in seen_cpes:
                    print(f"    [~] Duplicate CPE on this host — reusing cached risk score.")
                    nvd_risk, cve_ids = seen_cpes[search_term]
                else:
                    nvd_risk, cve_ids = get_nvd_cvss(search_term)

                    # FIX-3: confidence discount for unknown version
                    version_field = _cpe_version_field(search_term)
                    if version_field in ("*", "", "-") and nvd_risk > 0:
                        discounted = int(nvd_risk * _VERSION_UNKNOWN_DISCOUNT)
                        print(f"    [~] Version unknown — confidence discount: "
                              f"{nvd_risk} -> {discounted}")
                        nvd_risk = discounted

                    seen_cpes[search_term] = (nvd_risk, cve_ids)
            else:
                nvd_risk, cve_ids = 0, []

            all_cve_ids.extend(cve_ids)

            if cve_ids:
                protocol = port_elem.get("protocol", "tcp")
                port_key = f"{port_id}/{protocol}"
                cve_by_port[port_key] = list(dict.fromkeys(cve_ids))

            # INTEL-1: KEV check — confirmed wild exploitation bonus
            in_kev    = check_kev(cve_ids) if cve_ids else False
            kev_bonus = 15.0 if in_kev else 0.0
            if in_kev:
                matched = [c for c in cve_ids if c in _KEV_SET]
                print(f"    [!!!] KEV HIT — {matched} confirmed exploited in the wild! +15 bonus")

            # INTEL-2: EPSS — exploitation probability
            epss_score = get_epss_score(cve_ids) if cve_ids else 0.0
            if epss_score > 0:
                print(f"    [*] EPSS Score: {epss_score:.1f}/100 exploitation probability")

            # FOUR-SIGNAL HYBRID SCORING FORMULA (INTEL-3)
            base_risk     = EXPOSURE_RULES.get(port_id, DEFAULT_EXPOSURE)
            version_field = _cpe_version_field(search_term) if search_term else "*"
            version_unknown = version_field in ("*", "", "-")

            if nvd_risk > 0 or epss_score > 0 or in_kev:
                # We have real intelligence — use full four-signal formula
                port_risk = (
                    (nvd_risk  * 0.60) +
                    (base_risk * 0.15) +
                    (epss_score * 0.20) +
                    kev_bonus
                )
            elif version_unknown:
                # No intelligence AND no version — uncertainty discount on base
                port_risk = float(base_risk) * 0.75
                print(f"    [~] No CVE data + unknown version — base_risk discounted: "
                      f"{base_risk} -> {port_risk:.1f}")
            else:
                # No CVE data but version known — full base_risk
                port_risk = float(base_risk)

            all_port_risks.append(port_risk)
            all_epss_scores.append(epss_score)
            all_nvd_risks.append(nvd_risk)
            if in_kev:
                kev_port_count += 1
            if nvd_risk == 0:
                nvd_zero_count += 1

        # MITRE ATT&CK mapping — deduplicated CVEs seen across all ports
        unique_cves     = list(dict.fromkeys(all_cve_ids))
        mitre_mappings: list[dict] = []
        if _mitre_mod is not None and unique_cves:
            try:
                mitre_mappings = _mitre_mod.map_cves(unique_cves)
            except Exception as _me:
                print(f"    [!] MITRE mapping error: {_me}")

        score = calculate_final_score(all_port_risks)
        intel = {
            "max_epss_score": max(all_epss_scores) if all_epss_scores else 0.0,
            "has_high_epss":  1 if any(e > 50 for e in all_epss_scores) else 0,
            "has_kev_cve":    1 if kev_port_count > 0 else 0,
            "kev_port_count": kev_port_count,
            "max_nvd_score":  max(all_nvd_risks) if all_nvd_risks else 0,
            "mean_nvd_score": round(sum(all_nvd_risks) / len(all_nvd_risks), 2) if all_nvd_risks else 0.0,
            "nvd_zero_count": nvd_zero_count,
            "mitre_mappings": mitre_mappings,
            "cve_by_port":    cve_by_port,
        }
        return score, intel

    except Exception as exc:
        print(f"    [!] Error processing {xml_file}: {exc}")
        return 0.0, _zero_intel()


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 6: SELF-TEST (CPE Cleaner)
# ─────────────────────────────────────────────────────────────────────────────

def _run_cpe_tests() -> bool:
    test_cases = [
        ("cpe:2.3:a:openbsd:openssh:7.6p1_ubuntu_4ubuntu0.3:*:*:*:*:*:*:*", "7.6p1"),
        ("cpe:2.3:a:openbsd:openssh:8.2p1_4ubuntu0.5:*:*:*:*:*:*:*",        "8.2p1"),
        ("cpe:2.3:a:apache:httpd:3.x_-_4.x:*:*:*:*:*:*:*",                  "3.0"),
        ("cpe:2.3:a:apache:httpd:2.4_-_2.9:*:*:*:*:*:*:*",                  "2.4"),
        ("cpe:2.3:a:php:php:7_4_3:*:*:*:*:*:*:*",                            "7.4.3"),
        ("cpe:2.3:a:nginx:nginx:1_18_0:*:*:*:*:*:*:*",                       "1.18.0"),
        ("cpe:2.3:a:openssl:openssl:1.1.1f_debian_1:*:*:*:*:*:*:*",         "1.1.1f"),
        ("cpe:2.3:a:curl:curl:7.68.0:*:*:*:*:*:*:*",                         "7.68.0"),
        # PATCH-A: semicolon build-tag stripping
        ("cpe:2.3:a:microsoft:sql_server:15.00.2000.00;_rtm:*:*:*:*:*:*:*", "15.00.2000.00"),
    ]
    all_pass = True
    for cpe_in, expected_ver in test_cases:
        result  = clean_cpe_string(cpe_in)
        got_ver = result.split(":")[5]
        status  = "PASS" if got_ver == expected_ver else "FAIL"
        if got_ver != expected_ver:
            all_pass = False
        print(f"{status}  {got_ver:<15} (expected {expected_ver:<15})"
              f"  <-  {cpe_in.split(':')[4]}:{cpe_in.split(':')[5]}")
    print(f"\n{'All tests passed!' if all_pass else 'Some tests FAILED — check above.'}\n")
    return all_pass


# ─────────────────────────────────────────────────────────────────────────────
# ZONE 7: MAIN EXECUTION
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _run_cpe_tests()

    init_db()
    load_kev_catalog()
    print("[+] Mangekyo Ground Truth Engine v3 Initialized.\n")

    df         = pd.read_csv("metadata.csv")
    scores     = []
    intel_rows = []

    for xml_path in df["filename"]:
        xml_path = str(xml_path)
        if os.path.exists(xml_path):
            print(f"[*] Grading {xml_path}...")
            score, intel = calculate_machine_risk(xml_path)
            print(f"    => Final Score: {score}\n")
            scores.append(score)
            intel_rows.append(intel)
        else:
            print(f"[!] File not found: {xml_path} — scoring as 0.0\n")
            scores.append(0.0)
            intel_rows.append(_zero_intel())

    df["risk_score"] = scores
    intel_df = pd.DataFrame(intel_rows)
    for col in intel_df.columns:
        df[col] = intel_df[col].values
    df.to_csv("training_data_v2.csv", index=False)
    print("[V] SUCCESS: Ground Truth & Database updated.")
    print(f"    Score range: {min(scores):.1f} – {max(scores):.1f}")
    print(f"    Mean: {sum(scores)/len(scores):.1f}  |  Unique values: {len(set(scores))}")
