"""
4_mitre_mapper.py
=================
Project Mangekyo -- MITRE ATT&CK Mapping Engine

Maps CVE IDs to ATT&CK techniques, tactics, mitigations, and
plain-English descriptions.

Mapping tiers (in priority order):
  Tier 1 -- ATT&CK STIX bundle    (CVEs mentioned in technique descriptions)
  Tier 2 -- Supplement            (two sub-sources, checked in order):
              a) Hand-curated     (high-confidence analyst mappings)
              b) KEV-derived      (CISA KEV catalog + NVD CWE + CWE->ATT&CK)
                 Built once, cached locally as kev_supplement_cache.json,
                 refreshed every 30 days.  NVD API key in .env speeds build.
  Tier 3 -- CWE fallback          (live NVD CWE lookup -> ATT&CK, per CVE)

Data sources:
  MITRE CTI enterprise-attack STIX bundle (CC0):
    https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
  CISA Known Exploited Vulnerabilities catalog (CC0):
    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  NVD CVE API 2.0 (optional key in .env speeds rate limit 5->50 req/30 s):
    https://services.nvd.nist.gov/rest/json/cves/2.0

The STIX bundle is cached locally as mitre_attack_cache.json.

Public API:
    from mitre_mapper import map_cves, ensure_loaded
    results = map_cves(["CVE-2021-40438", "CVE-2021-41773"])

CLI:
    python 4_mitre_mapper.py                        # run built-in test suite
    python 4_mitre_mapper.py CVE-2021-40438         # score specific CVE(s)
    python 4_mitre_mapper.py --refresh              # force re-download
    python 4_mitre_mapper.py --refresh CVE-2021-40438
"""

from __future__ import annotations

import atexit
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

from . import paths

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

STIX_URL        = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CACHE_PATH      = paths.MITRE_CACHE_PATH
CACHE_MAX_DAYS  = 30

KEV_URL                  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_SUPPLEMENT_PATH      = paths.KEV_SUPPLEMENT_PATH
KEV_SUPPLEMENT_MAX_DAYS  = 30

_UA = "Mangekyo-MITREMapper/1.0"

# ─────────────────────────────────────────────────────────────────────────────
# NVD API KEY  (loaded from .env — reduces rate delay 6.5 s → 0.6 s)
# _NVD_RATE_DELAY default must be set here so _load_nvd_key() can override it
# before the NVD globals section below reuses the same name.
# ─────────────────────────────────────────────────────────────────────────────

from .config import NVD_API_KEY as _NVD_API_KEY, NVD_RATE_DELAY as _NVD_RATE_DELAY

# ─────────────────────────────────────────────────────────────────────────────
# KEV SUPPLEMENT SERVICE FILTER
# Only KEV entries whose vendorProject/product overlaps these keywords are
# fetched from NVD for CWE derivation. Keeps the build scoped to services
# that appear in our dataset.
# ─────────────────────────────────────────────────────────────────────────────

_KEV_RELEVANT = frozenset({
    "apache", "nginx", "openssh", "openssl", "openssl project",
    "openbsd",   # KEV tags OpenSSH vulns under vendorProject="OpenBSD"
    "samba", "microsoft", "cisco", "bind", "vsftpd", "proftpd",
    "dovecot", "postfix", "exim", "sendmail", "mysql", "mariadb",
    "postgresql", "mongodb", "redis", "memcached", "elasticsearch",
    "jenkins", "tomcat", "jboss", "wildfly", "weblogic",
    "iis", "rdp", "smb", "ntp", "wordpress", "drupal", "joomla",
    "atlassian", "confluence", "jira", "gitlab", "bitbucket",
    "f5", "citrix", "pulse secure", "fortinet", "palo alto",
    "sonicwall", "vmware", "exchange", "sharepoint", "spring",
    "log4j", "log4shell", "roundcube", "zimbra", "openfire",
    "fortra", "papercut", "progress", "moveit",
})

# ─────────────────────────────────────────────────────────────────────────────
# SUPPLEMENTARY CVE → ATT&CK TECHNIQUE MAPPING
#
# The ATT&CK STIX bundle is technique-centric: only ~6 CVEs appear anywhere
# in the current bundle (all in description text).  This curated supplement
# covers high-impact CVEs (KEV entries, widely-exploited software) and maps
# each to the most authoritative ATT&CK technique.
#
# Source authority:
#   CISA KEV advisory notes + ATT&CK technique definitions.
#   T-codes resolve to full technique data from the STIX bundle at runtime.
# ─────────────────────────────────────────────────────────────────────────────

_CVE_SUPPLEMENT: dict[str, str] = {
    # ── Web / App Server ─────────────────────────────────────────────────────
    "CVE-2021-40438": "T1190",   # Apache mod_proxy SSRF
    "CVE-2021-41773": "T1190",   # Apache 2.4.49 path traversal / RCE
    "CVE-2021-42013": "T1190",   # Apache 2.4.50 path traversal (bypass of above)
    "CVE-2021-26084": "T1190",   # Atlassian Confluence OGNL injection
    "CVE-2022-22965": "T1190",   # Spring4Shell (Spring Framework RCE)
    "CVE-2021-44228": "T1190",   # Log4Shell
    "CVE-2021-45046": "T1190",   # Log4Shell bypass (CVE-2021-44228 incomplete fix)
    "CVE-2022-47966": "T1190",   # ManageEngine RCE
    "CVE-2023-44487": "T1499",   # HTTP/2 Rapid Reset (DoS / DDoS amplification)
    "CVE-2023-22515": "T1190",   # Atlassian Confluence broken access control
    "CVE-2023-22518": "T1190",   # Atlassian Confluence improper auth
    "CVE-2021-22986": "T1190",   # F5 BIG-IP iControl REST RCE (unauth)
    "CVE-2020-5902" : "T1190",   # F5 BIG-IP TMUI RCE
    "CVE-2019-11510": "T1190",   # Pulse Secure VPN arbitrary file read
    "CVE-2019-19781": "T1190",   # Citrix ADC / Gateway path traversal
    "CVE-2020-12812": "T1190",   # FortiOS SSL VPN 2FA bypass
    "CVE-2022-40684": "T1190",   # FortiOS/FortiProxy auth bypass
    "CVE-2023-27997": "T1190",   # FortiGate SSL-VPN heap overflow
    "CVE-2023-4966" : "T1190",   # Citrix Bleed (NetScaler session token leak)
    "CVE-2024-3400" : "T1190",   # PAN-OS GlobalProtect command injection
    # ── Remote Services / Lateral Movement ──────────────────────────────────
    "CVE-2017-0144": "T1210",    # EternalBlue (MS17-010 SMBv1 RCE)
    "CVE-2017-0145": "T1210",    # EternalChampion (SMBv1)
    "CVE-2019-0708": "T1210",    # BlueKeep (RDP pre-auth RCE)
    "CVE-2021-26855": "T1210",   # ProxyLogon (Exchange SSRF → SYSTEM)
    "CVE-2021-27065": "T1210",   # ProxyLogon component (Exchange RCE)
    "CVE-2021-34473": "T1210",   # ProxyShell (Exchange pre-auth RCE)
    "CVE-2021-34523": "T1210",   # ProxyShell component
    "CVE-2021-31207": "T1210",   # ProxyShell component
    "CVE-2023-46604": "T1210",   # Apache ActiveMQ ClassInfo deserialization RCE
    # ── Privilege Escalation ─────────────────────────────────────────────────
    "CVE-2021-34527": "T1068",   # PrintNightmare (Windows Print Spooler LPE/RCE)
    "CVE-2021-1675" : "T1068",   # Windows Print Spooler RCE (PrintNightmare precursor)
    "CVE-2021-3156" : "T1068",   # Sudo heap overflow (Linux privesc)
    "CVE-2021-4034" : "T1068",   # PwnKit (pkexec LPE)
    "CVE-2022-0847" : "T1068",   # Dirty Pipe (Linux kernel LPE)
    "CVE-2016-5195" : "T1068",   # Dirty COW (Linux kernel LPE)
    "CVE-2020-1472" : "T1068",   # ZeroLogon (Netlogon privesc → DC takeover)
    # ── Credential Access ────────────────────────────────────────────────────
    "CVE-2018-15473": "T1589",   # OpenSSH username enumeration
    "CVE-2014-0160" : "T1555",   # Heartbleed (OpenSSL memory disclosure)
    "CVE-2021-36934": "T1003",   # HiveNightmare / SeriousSAM (SAM database read)
    "CVE-2022-26925": "T1557",   # Windows LSA spoofing (NTLM relay / PetitPotam)
    # ── Defense Evasion / Initial Access via Office/Client ──────────────────
    "CVE-2017-11882": "T1203",   # Microsoft Office memory corruption (Equation Editor)
    "CVE-2017-0199" : "T1203",   # Microsoft Office HTA handler RCE
    "CVE-2021-40444": "T1203",   # Microsoft MSHTML RCE (weaponized Office docs)
    "CVE-2022-30190": "T1203",   # Follina (MSDT RCE via Office)
    "CVE-2023-23397": "T1557",   # Outlook NTLM hash theft via calendar invite
    # ── Denial of Service ────────────────────────────────────────────────────
    "CVE-2020-3566" : "T1498",   # Cisco IOS XR UDP multicast DoS
    "CVE-2020-3569" : "T1498",   # Cisco IOS XR UDP multicast DoS (variant)
    # ── Supply Chain / Code Execution ────────────────────────────────────────
    "CVE-2020-10148": "T1195",   # SolarWinds Orion supply chain
    "CVE-2021-44515": "T1195",   # Zoho ManageEngine Desktop Central RCE
}

# ─────────────────────────────────────────────────────────────────────────────
# CWE → ATT&CK TECHNIQUE MAPPING  (Tier 3 fallback)
#
# When a CVE has no mapping in Tier 1 or Tier 2, we query the NVD CVE API
# for the CVE's CWE classification and resolve that to the closest ATT&CK
# technique using this table.
#
# Mapping authority: MITRE CWE-to-ATT&CK cross-reference + analyst judgment.
# ─────────────────────────────────────────────────────────────────────────────

_CWE_TO_ATTACK: dict[str, str] = {
    # ── Injection ──────────────────────────────────────────────────────────
    "CWE-77":  "T1059",   # Command Injection
    "CWE-78":  "T1059",   # OS Command Injection
    "CWE-88":  "T1059",   # Argument Injection
    "CWE-89":  "T1190",   # SQL Injection
    "CWE-90":  "T1190",   # LDAP Injection
    "CWE-91":  "T1059",   # XML Injection
    "CWE-94":  "T1059",   # Code Injection
    "CWE-95":  "T1059",   # Eval Injection
    "CWE-502": "T1059",   # Deserialization of Untrusted Data
    "CWE-611": "T1190",   # XML External Entity (XXE)
    "CWE-917": "T1059",   # Expression Language Injection
    # ── Path / File Access ─────────────────────────────────────────────────
    "CWE-22":  "T1083",   # Path Traversal
    "CWE-23":  "T1083",   # Relative Path Traversal
    "CWE-36":  "T1083",   # Absolute Path Traversal
    "CWE-73":  "T1083",   # External Control of File Name or Path
    # ── Memory Corruption ──────────────────────────────────────────────────
    "CWE-119": "T1203",   # Buffer Errors (parent)
    "CWE-120": "T1203",   # Classic Buffer Overflow
    "CWE-121": "T1203",   # Stack-based Buffer Overflow
    "CWE-122": "T1203",   # Heap-based Buffer Overflow
    "CWE-125": "T1203",   # Out-of-bounds Read
    "CWE-190": "T1068",   # Integer Overflow → Privilege Escalation
    "CWE-191": "T1068",   # Integer Underflow
    "CWE-362": "T1068",   # Race Condition (commonly exploited for LPE)
    "CWE-416": "T1068",   # Use After Free
    "CWE-787": "T1068",   # Out-of-bounds Write
    # ── Authentication / Access Control ────────────────────────────────────
    "CWE-287": "T1078",   # Improper Authentication → Valid Accounts
    "CWE-288": "T1078",   # Auth Bypass Using Alternate Path
    "CWE-306": "T1078",   # Missing Authentication for Critical Function
    "CWE-307": "T1110",   # Improper Restriction of Excessive Auth Attempts → Brute Force
    "CWE-521": "T1110",   # Weak Password Requirements
    "CWE-522": "T1552",   # Insufficiently Protected Credentials
    "CWE-640": "T1078",   # Weak Password Recovery
    "CWE-798": "T1552",   # Use of Hard-coded Credentials
    "CWE-862": "T1078",   # Missing Authorization
    "CWE-863": "T1078",   # Incorrect Authorization
    # ── Session / Web ──────────────────────────────────────────────────────
    "CWE-79":  "T1185",   # XSS → Browser Session Hijacking
    "CWE-80":  "T1185",   # Basic XSS
    "CWE-352": "T1185",   # CSRF → Browser Session Hijacking
    "CWE-384": "T1563",   # Session Fixation → Remote Service Session Hijacking
    "CWE-601": "T1566",   # Open Redirect → Phishing
    "CWE-918": "T1090",   # SSRF → Proxy
    # ── Information Disclosure ─────────────────────────────────────────────
    "CWE-200": "T1005",   # Information Exposure → Data from Local System
    "CWE-209": "T1005",   # Error Message Info Leak
    "CWE-312": "T1552",   # Cleartext Storage of Sensitive Information
    "CWE-313": "T1552",   # Cleartext Storage in File
    "CWE-319": "T1040",   # Cleartext Transmission → Network Sniffing
    # ── Cryptographic Weakness ─────────────────────────────────────────────
    "CWE-295": "T1557",   # Improper Certificate Validation → Adversary-in-the-Middle
    "CWE-297": "T1557",   # Improper Validation of Cert with Host Mismatch
    "CWE-310": "T1600",   # Cryptographic Issues (parent)
    "CWE-326": "T1600",   # Inadequate Encryption Strength → Weaken Encryption
    "CWE-327": "T1600",   # Use of Broken Cryptographic Algorithm
    "CWE-330": "T1600",   # Use of Insufficiently Random Values
    # ── Privilege / Permission ─────────────────────────────────────────────
    "CWE-264": "T1068",   # Permissions, Privileges, Access Controls (parent)
    "CWE-269": "T1068",   # Improper Privilege Management
    "CWE-732": "T1222",   # Incorrect Permission Assignment → File/Dir Permissions Mod
    # ── Denial of Service ──────────────────────────────────────────────────
    "CWE-400": "T1499",   # Uncontrolled Resource Consumption → Endpoint DoS
    "CWE-401": "T1499",   # Memory Leak → Endpoint DoS
    "CWE-476": "T1499",   # NULL Pointer Dereference → Endpoint DoS
    # ── File Upload / Transfer ─────────────────────────────────────────────
    "CWE-434": "T1105",   # Unrestricted Upload of File with Dangerous Type
    # ── General Input Validation (broad fallback) ──────────────────────────
    "CWE-20":  "T1190",   # Improper Input Validation
}

# NVD CVE API 2.0  (_NVD_RATE_DELAY initialised in CONFIGURATION above)
NVD_CVE_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_last_nvd_req = 0.0   # monotonic timestamp of the most recent NVD call
_nvd_cwe_cache: dict[str, list[str]] = {}   # cve_id -> [CWE-NNN, ...]
_cwe_cache_loaded_count: int = 0            # entries present after startup restore
_atexit_registered: bool     = False        # guard against double-registration

# ─────────────────────────────────────────────────────────────────────────────
# IN-MEMORY INDEXES (populated once by _build_indexes / _load_kev_supplement)
# ─────────────────────────────────────────────────────────────────────────────

# CVE-XXXX-XXXXX  ->  [technique STIX ID, ...]
_cve_index:           dict[str, list[str]] = {}
# technique STIX ID  ->  technique data dict
_technique_index:     dict[str, dict]      = {}
# ATT&CK T-code (e.g. "T1190")  ->  technique STIX ID  (for supplement lookup)
_attack_id_to_stix:   dict[str, str]       = {}
# mitigation STIX ID  ->  mitigation data dict
_mitigation_index:    dict[str, dict]      = {}
# technique STIX ID  ->  [mitigation STIX ID, ...]
_tech_mitig_index:    dict[str, list[str]] = {}

_indexes_built = False

# KEV-derived supplement: CVE-ID -> {t_code, cwe, source, vendor}
_kev_supplement:  dict[str, dict] = {}
# Merged supplement: hardcoded + KEV-derived (hardcoded takes priority)
_supplement_index: dict[str, dict] = {}

# ─────────────────────────────────────────────────────────────────────────────
# BUNDLE DOWNLOAD + CACHE
# ─────────────────────────────────────────────────────────────────────────────

def _cache_age_days() -> float | None:
    """
    Return the age of the cache in days based on the timestamp stored
    inside the cache file itself.  Returns None if cache is absent or
    has no timestamp (old format without wrapper).
    """
    if not CACHE_PATH.exists():
        return None
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            wrapper = json.load(fh)
        ts = wrapper.get("downloaded_at")
        if not ts:
            return None
        then = datetime.fromisoformat(ts)
        now  = datetime.now(timezone.utc)
        return (now - then).total_seconds() / 86_400
    except Exception:
        return None


def _load_cached_bundle() -> dict | None:
    """
    Load and return the STIX bundle from the cache file.
    Handles both the new wrapped format ({downloaded_at, bundle})
    and old unwrapped format (raw STIX bundle dict).
    Returns None on any read/parse error.
    """
    try:
        with open(CACHE_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
        # New format: wrapper dict with 'bundle' key
        if "bundle" in data and "downloaded_at" in data:
            return data["bundle"]
        # Old format: raw STIX bundle (type == "bundle")
        if data.get("type") == "bundle":
            return data
        return None
    except Exception:
        return None


def _fetch_and_cache() -> dict:
    """Download the STIX bundle from STIX_URL and write the wrapped cache.

    Returns an empty dict on network failure so callers degrade gracefully
    (Tier 1 STIX mappings unavailable) rather than crashing.
    """
    print(f"[*] Downloading ATT&CK STIX bundle ...")
    print(f"    {STIX_URL}")
    try:
        resp = requests.get(
            STIX_URL,
            timeout=180,
            headers={"User-Agent": _UA},
            stream=True,
        )
        resp.raise_for_status()

        chunks: list[bytes] = []
        for chunk in resp.iter_content(chunk_size=65_536):
            chunks.append(chunk)

        raw     = b"".join(chunks)
        size_mb = len(raw) / 1_048_576
        print(f"    Downloaded: {size_mb:.1f} MB ({len(raw):,} bytes)")

        bundle = json.loads(raw.decode("utf-8"))
        now_ts = datetime.now(timezone.utc).isoformat()

        wrapper = {"downloaded_at": now_ts, "bundle": bundle}
        with open(CACHE_PATH, "w", encoding="utf-8") as fh:
            json.dump(wrapper, fh)
        print(f"    Cached with timestamp {now_ts} -> {CACHE_PATH}")

        return bundle

    except Exception as exc:
        print(f"    [!] ATT&CK STIX download failed: {exc}")
        print(f"    [!] Tier 1 STIX mappings unavailable this run.")
        return {}


def _download_bundle(force: bool = False) -> dict:
    """
    Return the parsed ATT&CK STIX bundle dict.

    Logic:
      - force=True          -> always re-download (--refresh flag)
      - cache absent        -> download
      - cache >= 30 days    -> auto-refresh, log age
      - cache < 30 days     -> load silently from cache
    """
    if not force and CACHE_PATH.exists():
        age = _cache_age_days()

        if age is None:
            # Cache exists but no embedded timestamp — treat as stale
            print("[*] ATT&CK cache has no timestamp; refreshing ...")
            return _fetch_and_cache()

        if age >= CACHE_MAX_DAYS:
            print(
                f"[*] ATT&CK cache refreshed -- was {age:.0f} days old "
                f"(threshold: {CACHE_MAX_DAYS} days)"
            )
            return _fetch_and_cache()

        # Fresh cache — load silently
        bundle = _load_cached_bundle()
        if bundle is not None:
            return bundle
        # Corrupted cache — fall through to re-download
        print("[!] ATT&CK cache unreadable; re-downloading ...")

    return _fetch_and_cache()

# ─────────────────────────────────────────────────────────────────────────────
# STIX PARSING HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _tactic_display(phase_name: str) -> str:
    """'initial-access'  ->  'Initial Access'"""
    return " ".join(w.capitalize() for w in phase_name.split("-"))


def _first_sentence(text: str) -> str:
    """
    Return the first meaningful sentence of an ATT&CK description.
    Strips markdown citations like (Citation: Source) and cleans
    extra whitespace before extracting.
    """
    if not text:
        return ""

    # Remove inline citations that clutter the first sentence
    cleaned = re.sub(r'\(Citation:[^)]+\)', '', text)
    cleaned = re.sub(r'\[Citation:[^\]]+\]', '', cleaned)
    # Collapse runs of whitespace
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()

    # Find the first sentence boundary
    m = re.match(r'([^.!?]+[.!?])', cleaned)
    if m:
        return m.group(1).strip()

    # Fallback: first 250 chars
    return (cleaned[:250].rstrip() + "...") if len(cleaned) > 250 else cleaned


def _attack_id_from_refs(ext_refs: list[dict], prefix: str = "") -> str:
    """Extract the ATT&CK external_id (T-code, M-code) from external_references."""
    for ref in ext_refs:
        if ref.get("source_name") == "mitre-attack":
            eid = ref.get("external_id", "")
            if not prefix or eid.startswith(prefix):
                return eid
    return ""

# ─────────────────────────────────────────────────────────────────────────────
# INDEX BUILDING
# ─────────────────────────────────────────────────────────────────────────────

def _build_indexes(bundle: dict) -> None:
    """
    Parse the STIX bundle once and populate all in-memory indexes.

    Pass 1: attack-pattern objects  -> technique index + CVE index
    Pass 1: course-of-action objects -> mitigation index
    Pass 2: relationship objects (mitigates) -> tech-mitigation index
    """
    global _cve_index, _technique_index, _mitigation_index
    global _tech_mitig_index, _indexes_built

    objects = bundle.get("objects", [])
    print(f"[*] Indexing {len(objects):,} STIX objects ...")

    n_techniques  = 0
    n_mitigations = 0
    n_cve_extref  = 0   # from external_references (source_name="cve")
    n_cve_desc    = 0   # from description text scanning

    # CVE pattern: CVE-YYYY-NNNN(N+) as a standalone token
    _CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)

    # ── Pass 1 ────────────────────────────────────────────────────────────────
    for obj in objects:
        obj_type = obj.get("type", "")

        # Skip revoked / deprecated objects
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        if obj_type == "attack-pattern":
            stix_id  = obj["id"]
            name     = obj.get("name", "")
            desc     = obj.get("description", "")
            ext_refs = obj.get("external_references", [])
            phases   = obj.get("kill_chain_phases", [])

            attack_id = _attack_id_from_refs(ext_refs, prefix="T")

            # Use the first mitre-attack tactic (most relevant one)
            tactic = next(
                (
                    _tactic_display(p["phase_name"])
                    for p in phases
                    if p.get("kill_chain_name") == "mitre-attack"
                ),
                "",
            )

            # ── Source A: structured external_references[source_name="cve"] ─
            # (used in older ATT&CK versions; zero hits in current bundle but
            #  kept for forward-compatibility)
            extref_cves: list[str] = []
            for ref in ext_refs:
                if ref.get("source_name") == "cve":
                    cve_id = ref.get("external_id", "").upper().strip()
                    if cve_id.startswith("CVE-"):
                        extref_cves.append(cve_id)
                        n_cve_extref += 1

            # ── Source B: CVE IDs mentioned inline in the description text ──
            # Current ATT&CK bundles embed CVEs this way instead of structured
            # external_references.  Example: "...BIG-IP F5 (CVE-2020-5902)."
            desc_cves: list[str] = [
                m.upper() for m in _CVE_RE.findall(desc)
            ]

            # Merge: extref first (higher confidence), then description hits
            seen: set[str] = set()
            technique_cves: list[str] = []
            for cve in extref_cves + desc_cves:
                if cve not in seen:
                    seen.add(cve)
                    technique_cves.append(cve)
                    if cve not in extref_cves:
                        n_cve_desc += 1

            _technique_index[stix_id] = {
                "stix_id":       stix_id,
                "attack_id":     attack_id,
                "name":          name,
                "tactic":        tactic,
                "plain_english": _first_sentence(desc),
            }

            # Reverse lookup: T-code -> STIX ID (for supplement resolution)
            if attack_id:
                _attack_id_to_stix[attack_id] = stix_id

            for cve in technique_cves:
                _cve_index.setdefault(cve, []).append(stix_id)

            n_techniques += 1

        elif obj_type == "course-of-action":
            stix_id  = obj["id"]
            name     = obj.get("name", "")
            ext_refs = obj.get("external_references", [])
            m_code   = _attack_id_from_refs(ext_refs, prefix="M")

            # Only store entries with proper M-codes (skip non-mitigation CoA)
            if m_code:
                _mitigation_index[stix_id] = {
                    "stix_id": stix_id,
                    "id":      m_code,
                    "name":    name,
                }
                n_mitigations += 1

    # ── Pass 2: relationships ─────────────────────────────────────────────────
    n_relations = 0
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
            and not obj.get("revoked")
        ):
            src = obj.get("source_ref", "")   # course-of-action (mitigation)
            tgt = obj.get("target_ref", "")   # attack-pattern   (technique)
            if src in _mitigation_index and tgt in _technique_index:
                _tech_mitig_index.setdefault(tgt, []).append(src)
                n_relations += 1

    _indexes_built = True

    print(f"    Techniques indexed      : {n_techniques:,}")
    print(f"    Mitigations indexed     : {n_mitigations:,}")
    print(f"    CVE refs (ext_refs)     : {n_cve_extref:,}")
    print(f"    CVE refs (desc text)    : {n_cve_desc:,}  ({len(_cve_index):,} distinct CVEs)")
    print(f"    Mitigation relations    : {n_relations:,}")


def ensure_loaded(force_refresh: bool = False) -> None:
    """Public entry point — build all indexes if not already done."""
    global _indexes_built, _atexit_registered
    if _indexes_built and _supplement_index and not force_refresh:
        return
    if force_refresh:
        _cve_index.clear()
        _technique_index.clear()
        _attack_id_to_stix.clear()
        _mitigation_index.clear()
        _tech_mitig_index.clear()
        _kev_supplement.clear()
        _supplement_index.clear()
        _indexes_built = False
    bundle = _download_bundle(force=force_refresh)
    _build_indexes(bundle)
    _load_kev_supplement(force=force_refresh)
    if not _atexit_registered:
        atexit.register(_flush_cwe_cache)
        _atexit_registered = True

# ─────────────────────────────────────────────────────────────────────────────
# KEV SUPPLEMENT  (Tier 2b — CISA KEV + NVD CWE + CWE->ATT&CK)
# ─────────────────────────────────────────────────────────────────────────────

def _is_relevant_kev_entry(entry: dict) -> bool:
    """Return True if the KEV entry's vendor/product matches our service set."""
    text = (entry.get("vendorProject", "") + " " + entry.get("product", "")).lower()
    return any(kw in text for kw in _KEV_RELEVANT)


def _fetch_kev_catalog() -> list[dict]:
    """Download the CISA KEV catalog. Returns the vulnerabilities list."""
    try:
        resp = requests.get(KEV_URL, timeout=30, headers={"User-Agent": _UA})
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except Exception as exc:
        print(f"    [!] KEV download failed: {exc}")
        return []


def _kev_supplement_age_days() -> float | None:
    if not KEV_SUPPLEMENT_PATH.exists():
        return None
    try:
        data = json.loads(KEV_SUPPLEMENT_PATH.read_text(encoding="utf-8"))
        ts   = data.get("built_at")
        if not ts:
            return None
        then = datetime.fromisoformat(ts)
        return (datetime.now(timezone.utc) - then).total_seconds() / 86_400
    except Exception:
        return None


def _build_and_cache_kev_supplement() -> dict[str, dict]:
    """
    Build the Tier 2b supplement from CISA KEV + NVD CWE lookups.

    For each KEV entry matching our service keywords:
      1. Skip if already in the hand-curated _CVE_SUPPLEMENT (it wins).
      2. Check the persisted cwe_lookup_cache inside kev_supplement_cache.json;
         pre-populate _nvd_cwe_cache so _fetch_cwe_for_cve skips those CVEs.
      3. Fetch CWE from NVD only for CVEs not already cached.
      4. Map CWE -> ATT&CK via _CWE_TO_ATTACK.
      5. Store with source tag "KEV-confirmed + CWE-derived (CWE-NNN)".

    Writes kev_supplement_cache.json with built_at timestamp,
    per-entry mappings, AND the full cwe_lookup_cache so future
    refreshes only fetch newly-added KEV CVEs.
    Returns the supplement dict.
    """
    print("[*] Building KEV supplement (CISA KEV + NVD CWE) ...")
    if _NVD_API_KEY:
        print(f"    NVD API key present -- delay: {_NVD_RATE_DELAY}s/call")
    else:
        print(f"    No NVD API key -- delay: {_NVD_RATE_DELAY}s/call  (add NVD_API_KEY to .env to speed up)")

    # ── Pre-load persisted CWE lookup cache to skip already-fetched CVEs ──────
    if KEV_SUPPLEMENT_PATH.exists():
        try:
            prior = json.loads(KEV_SUPPLEMENT_PATH.read_text(encoding="utf-8"))
            prior_cwe_cache = prior.get("cwe_lookup_cache", {})
            if prior_cwe_cache:
                _nvd_cwe_cache.update(prior_cwe_cache)
                print(f"    Loaded {len(prior_cwe_cache):,} prior CWE lookups from cache")
        except Exception:
            pass

    kev_entries = _fetch_kev_catalog()
    if not kev_entries:
        print("    [!] KEV catalog empty -- supplement will be empty.")
        return {}

    total_kev = len(kev_entries)
    relevant  = [e for e in kev_entries if _is_relevant_kev_entry(e)]
    to_lookup = [e for e in relevant if e["cveID"] not in _CVE_SUPPLEMENT]

    n_cached  = sum(1 for e in to_lookup if e["cveID"] in _nvd_cwe_cache)
    n_new     = len(to_lookup) - n_cached

    print(f"    KEV total           : {total_kev:,}")
    print(f"    Relevant to dataset : {len(relevant):,}")
    print(f"    New (not in curated): {len(to_lookup):,}  "
          f"({n_cached} cached / {n_new} new NVD fetch{'es' if n_new != 1 else ''})")
    if not _NVD_API_KEY and n_new:
        est_min = n_new * _NVD_RATE_DELAY / 60
        print(f"    Estimated fetch time: ~{est_min:.0f} min (unauthenticated)")

    supplement:    dict[str, dict] = {}
    vendor_mapped: dict[str, int]  = {}
    mapped  = 0
    missed  = 0

    for i, entry in enumerate(to_lookup, 1):
        cve_id = entry["cveID"]
        vendor = entry.get("vendorProject", "unknown")
        cwe_ids = _fetch_cwe_for_cve(cve_id)

        resolved = False
        for cwe_id in cwe_ids:
            t_code = _CWE_TO_ATTACK.get(cwe_id)
            if t_code and _attack_id_to_stix.get(t_code):
                supplement[cve_id] = {
                    "t_code":  t_code,
                    "cwe":     cwe_id,
                    "source":  f"KEV-confirmed + CWE-derived ({cwe_id})",
                    "vendor":  vendor,
                }
                vendor_mapped[vendor] = vendor_mapped.get(vendor, 0) + 1
                mapped   += 1
                resolved  = True
                break
        if not resolved:
            missed += 1

        if i % 25 == 0 or i == len(to_lookup):
            print(f"    Progress {i:>4}/{len(to_lookup)}  mapped={mapped}  missed={missed}")

    print(f"    Build complete: {mapped} mapped, {missed} with no CWE->ATT&CK path")

    # Per-vendor report
    apache_n  = sum(v for k, v in vendor_mapped.items() if "apache"  in k.lower())
    openssh_n = sum(v for k, v in vendor_mapped.items() if "openssh" in k.lower() or "openbsd" in k.lower())
    cisco_n   = sum(v for k, v in vendor_mapped.items() if "cisco"   in k.lower())
    ms_n      = sum(v for k, v in vendor_mapped.items() if "microsoft" in k.lower())
    print(f"    By vendor  Apache={apache_n}  OpenSSH={openssh_n}  "
          f"Cisco={cisco_n}  Microsoft={ms_n}  "
          f"other={mapped - apache_n - openssh_n - cisco_n - ms_n}")

    cache = {
        "built_at":        datetime.now(timezone.utc).isoformat(),
        "kev_total":       total_kev,
        "relevant":        len(relevant),
        "mapped":          mapped,
        "vendor_stats":    vendor_mapped,
        "cwe_lookup_cache": dict(_nvd_cwe_cache),
        "entries":         supplement,
    }
    KEV_SUPPLEMENT_PATH.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    print(f"    Cached -> {KEV_SUPPLEMENT_PATH}  "
          f"({len(_nvd_cwe_cache):,} CWE lookups persisted)")
    return supplement


def _load_kev_supplement(force: bool = False) -> None:
    """Load the KEV supplement from cache or build it if stale/absent."""
    global _kev_supplement, _supplement_index, _cwe_cache_loaded_count

    age = _kev_supplement_age_days()

    if not force and age is not None and age < KEV_SUPPLEMENT_MAX_DAYS:
        try:
            data = json.loads(KEV_SUPPLEMENT_PATH.read_text(encoding="utf-8"))
            _kev_supplement = data.get("entries", {})
            # Restore persisted CWE lookups so Tier-3 _fetch_cwe_for_cve calls
            # are cache hits on subsequent runs instead of live NVD API calls.
            cwe_cache = data.get("cwe_lookup_cache", {})
            if cwe_cache:
                _nvd_cwe_cache.update(cwe_cache)
            vs = data.get("vendor_stats", {})
            apache_n  = sum(v for k, v in vs.items() if "apache"  in k.lower())
            openssh_n = sum(v for k, v in vs.items() if "openssh" in k.lower() or "openbsd" in k.lower())
            print(f"[*] KEV supplement loaded: {len(_kev_supplement):,} entries "
                  f"(age {age:.0f}d) -- Apache={apache_n} OpenSSH={openssh_n} "
                  f"[{len(cwe_cache)} CWE lookups restored]")
        except Exception as exc:
            print(f"[!] KEV supplement cache unreadable ({exc}) -- rebuilding")
            _kev_supplement = _build_and_cache_kev_supplement()
    else:
        reason = "forced refresh" if force else ("stale" if age is not None else "first run")
        print(f"[*] KEV supplement: {reason} -- building now ...")
        _kev_supplement = _build_and_cache_kev_supplement()

    _cwe_cache_loaded_count = len(_nvd_cwe_cache)
    _build_supplement_index()


def _flush_cwe_cache() -> None:
    """Persist any new Tier-3 CWE lookups acquired this run back to disk.

    Called via atexit so subsequent runs get immediate cache hits instead of
    live NVD API calls for the same CVEs.
    """
    if len(_nvd_cwe_cache) <= _cwe_cache_loaded_count:
        return
    if not KEV_SUPPLEMENT_PATH.exists():
        return
    try:
        data = json.loads(KEV_SUPPLEMENT_PATH.read_text(encoding="utf-8"))
        data["cwe_lookup_cache"] = dict(_nvd_cwe_cache)
        KEV_SUPPLEMENT_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass  # best-effort — a failed flush just means a slower next run


def _build_supplement_index() -> None:
    """Merge hand-curated + KEV-derived supplements. Curated entries win."""
    global _supplement_index
    _supplement_index = {}
    for cve_id, t_code in _CVE_SUPPLEMENT.items():
        _supplement_index[cve_id] = {"t_code": t_code, "source": "curated supplement"}
    for cve_id, entry in _kev_supplement.items():
        if cve_id not in _supplement_index:
            _supplement_index[cve_id] = {"t_code": entry["t_code"], "source": entry["source"]}

# ─────────────────────────────────────────────────────────────────────────────
# NVD CWE LOOKUP  (shared by Tier 2b builder + Tier 3 fallback)
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_cwe_for_cve(cve_id: str) -> list[str]:
    """
    Query the NVD CVE API 2.0 for *cve_id* and return its CWE IDs in
    declaration order (Primary weakness first).

    Respects NVD's 5-req/30-s rate limit via a module-level timestamp.
    Results are cached in _nvd_cwe_cache for the process lifetime so a
    given CVE is never fetched twice.

    Returns an empty list on network error, HTTP error, or no CWE data.
    """
    global _last_nvd_req

    if cve_id in _nvd_cwe_cache:
        return _nvd_cwe_cache[cve_id]

    elapsed = time.monotonic() - _last_nvd_req
    if elapsed < _NVD_RATE_DELAY:
        time.sleep(_NVD_RATE_DELAY - elapsed)

    hdrs = {"User-Agent": _UA}
    if _NVD_API_KEY:
        hdrs["apiKey"] = _NVD_API_KEY

    for attempt in range(3):
        try:
            resp = requests.get(
                NVD_CVE_URL,
                params={"cveId": cve_id},
                timeout=15,
                headers=hdrs,
            )
            _last_nvd_req = time.monotonic()

            if resp.status_code == 429:
                time.sleep(2 ** (attempt + 2))
                continue

            if resp.status_code != 200:
                _nvd_cwe_cache[cve_id] = []
                return []

            vulns = resp.json().get("vulnerabilities", [])
            if not vulns:
                _nvd_cwe_cache[cve_id] = []
                return []

            cwe_ids: list[str] = []
            for weakness in vulns[0]["cve"].get("weaknesses", []):
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    # Skip NVD placeholder values
                    if val.startswith("CWE-") and val not in ("NVD-CWE-Other", "NVD-CWE-noinfo"):
                        if val not in cwe_ids:
                            cwe_ids.append(val)

            _nvd_cwe_cache[cve_id] = cwe_ids
            return cwe_ids

        except Exception:
            _nvd_cwe_cache[cve_id] = []
            return []

    _nvd_cwe_cache[cve_id] = []
    return []

# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def map_cves(cve_list: list[str], max_tier3: int = 50) -> list[dict]:
    """
    Map a list of CVE IDs to MITRE ATT&CK techniques, tactics,
    mitigations, and a plain-English description.

    Returns one result dict per input CVE, in the same order.
    CVEs with no ATT&CK mapping return a null-mapping dict.

    Automatically loads/caches the ATT&CK bundle on first call.

    max_tier3: maximum number of NVD API calls allowed for Tier 3 CWE
               fallback in this call.  Set to 0 to skip Tier 3 entirely.
               Defaults to 50 (uncapped for pipeline use).
    """
    ensure_loaded()

    results:    list[dict] = []
    tier3_used: int        = 0

    for raw_cve in cve_list:
        cve_id = raw_cve.upper().strip()

        # ── Tier 1: STIX description-scan index (ATT&CK explicitly mentions CVE)
        matched_stix_ids = _cve_index.get(cve_id, [])
        source_label = "ATT&CK STIX"

        # ── Tier 2: supplement (curated + KEV-derived)
        if not matched_stix_ids:
            entry = _supplement_index.get(cve_id)
            if entry:
                stix_id = _attack_id_to_stix.get(entry["t_code"])
                if stix_id:
                    matched_stix_ids = [stix_id]
                    source_label = entry["source"]

        # ── Tier 3: CWE fallback via NVD API ─────────────────────────────────
        if not matched_stix_ids and tier3_used < max_tier3:
            cwe_ids = _fetch_cwe_for_cve(cve_id)
            tier3_used += 1
            for cwe_id in cwe_ids:
                t_code  = _CWE_TO_ATTACK.get(cwe_id)
                stix_id = _attack_id_to_stix.get(t_code, "") if t_code else ""
                if stix_id:
                    matched_stix_ids = [stix_id]
                    source_label = f"CWE fallback ({cwe_id})"
                    break

        if not matched_stix_ids:
            results.append({
                "cve_id":         cve_id,
                "technique_id":   None,
                "technique_name": "No ATT&CK mapping available",
                "tactic":         None,
                "mitigations":    [],
                "plain_english":  "No MITRE ATT&CK mapping found for this CVE.",
                "_source":        "none",
            })
            continue

        # If multiple techniques match (rare), use the first reference
        tech_stix_id = matched_stix_ids[0]
        tech         = _technique_index[tech_stix_id]

        # Gather mitigations sorted by M-code for deterministic output
        mitig_stix_ids = _tech_mitig_index.get(tech_stix_id, [])
        mitigations = sorted(
            (
                {"id": _mitigation_index[msid]["id"], "name": _mitigation_index[msid]["name"]}
                for msid in mitig_stix_ids
                if msid in _mitigation_index
            ),
            key=lambda m: m["id"],
        )

        results.append({
            "cve_id":         cve_id,
            "technique_id":   tech["attack_id"],
            "technique_name": tech["name"],
            "tactic":         tech["tactic"],
            "mitigations":    mitigations,
            "plain_english":  tech["plain_english"],
            "_source":        source_label,
        })

    return results

# ─────────────────────────────────────────────────────────────────────────────
# CLI / TEST
# ─────────────────────────────────────────────────────────────────────────────

_TEST_CVES = [
    # ── Tier 1 (STIX) ────────────────────────────────────────────────────────
    # (no reliable STIX hits in the current bundle — see n_cve_desc count)
    # ── Tier 2a (curated supplement) ─────────────────────────────────────────
    "CVE-2021-40438",   # Apache mod_proxy SSRF         -- curated
    "CVE-2023-44487",   # HTTP/2 Rapid Reset            -- curated
    "CVE-2018-15473",   # OpenSSH username enum         -- curated
    # ── Tier 2b (KEV-derived supplement) ─────────────────────────────────────
    "CVE-2021-41618",   # Apache Airflow auth bypass    -- expected KEV-derived
    "CVE-2017-7679",    # Apache mod_mime buffer overread -- expected KEV-derived
    # ── Tier 3 (live CWE fallback) ───────────────────────────────────────────
    "CVE-2024-6387",    # OpenSSH regreSSHion           -- CWE-362 -> T1068
    "CVE-2023-38545",   # cURL SOCKS5 heap overflow     -- CWE-787 -> T1068
    # ── No mapping ───────────────────────────────────────────────────────────
    "CVE-FAKE-00000",   # not a real CVE                -- none
]

_SEP  = "=" * 65
_SEP2 = "-" * 65


def _print_result(r: dict) -> None:
    """Pretty-print one map_cves() result dict."""
    print()
    print(_SEP)
    print(f"  CVE     : {r['cve_id']}")
    print(_SEP)

    if r["technique_id"] is None:
        print(f"  RESULT  : {r['technique_name']}")
        print(f"  PLAIN   : {r['plain_english']}")
        print(_SEP2)
        return

    print(f"  T-CODE  : {r['technique_id']}  (source: {r.get('_source','')})")
    print(f"  NAME    : {r['technique_name']}")
    print(f"  TACTIC  : {r['tactic']}")
    print()
    print(f"  PLAIN-ENGLISH DESCRIPTION:")
    # Word-wrap at 60 chars
    words  = r["plain_english"].split()
    line   = "    "
    for w in words:
        if len(line) + len(w) + 1 > 64:
            print(line)
            line = "    " + w
        else:
            line += (" " if line.strip() else "") + w
    if line.strip():
        print(line)
    print()

    if r["mitigations"]:
        print(f"  MITIGATIONS ({len(r['mitigations'])}):")
        for m in r["mitigations"]:
            print(f"    {m['id']:<8}  {m['name']}")
    else:
        print("  MITIGATIONS : (none mapped for this technique)")

    print(_SEP2)


def main() -> None:
    args = sys.argv[1:]
    force_refresh = "--refresh" in args
    cli_cves      = [a for a in args if a.upper().startswith("CVE-") or a == "--refresh"]
    user_cves     = [a for a in cli_cves if a != "--refresh"]

    ensure_loaded(force_refresh=force_refresh)

    target_cves = user_cves if user_cves else _TEST_CVES

    n_curated = len(_CVE_SUPPLEMENT)
    n_kev_new = len(_supplement_index) - n_curated
    print()
    print(_SEP)
    if user_cves:
        print(f"  MITRE ATT&CK MAPPER  --  {len(target_cves)} CVE(s) from CLI")
    else:
        print(f"  MITRE ATT&CK MAPPER  --  built-in test suite ({len(target_cves)} CVEs)")
    print(f"  Supplement: {n_curated} curated + {n_kev_new} KEV-derived = {len(_supplement_index)} total")
    print(_SEP)

    results = map_cves(target_cves)

    for r in results:
        _print_result(r)

    # Summary table
    mapped   = [r for r in results if r["technique_id"] is not None]
    unmapped = [r for r in results if r["technique_id"] is None]

    print()
    print(_SEP)
    print("  SUMMARY")
    print(_SEP)
    print(f"  CVEs tested   : {len(results)}")
    print(f"  Mapped        : {len(mapped)}")
    print(f"  Not in ATT&CK : {len(unmapped)}")
    if mapped:
        print()
        print(f"  {'CVE':<22}  {'T-Code':<10}  {'Tactic':<25}  Mitigations")
        print(f"  {'-'*22}  {'-'*10}  {'-'*25}  -----------")
        for r in results:
            tid    = r["technique_id"]  or "N/A"
            tactic = (r["tactic"]       or "N/A")[:25]
            nm     = len(r["mitigations"])
            print(f"  {r['cve_id']:<22}  {tid:<10}  {tactic:<25}  {nm}")
    print(_SEP)


if __name__ == "__main__":
    main()
