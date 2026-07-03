"""
mangekyo.cli.main
==================
Project Mangekyo — command-line interface.

Commands:
    mangekyo scan <target>    run nmap, score every host, print a table
    mangekyo explain <ip>     full breakdown (SHAP + CVEs + ATT&CK) for one host
    mangekyo score <file>     score an existing Nmap XML file

Reports confirmed threat data, not breach prediction.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import socket
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from mangekyo import __version__

TAGLINE = "Reports confirmed threat data, not breach prediction."

TIER_COLORS = {
    "CRITICAL": "\033[1;91m",  # bold red
    "HIGH":     "\033[91m",    # red
    "MEDIUM":   "\033[93m",    # yellow
    "LOW":      "\033[92m",    # green
}
_RESET = "\033[0m"

# JSON fields emitted per host, in this order.
_JSON_HOST_FIELDS = [
    "host", "risk_score", "tier", "confidence", "confidence_score",
    "open_ports", "top_signals", "cve_count", "cve_by_port", "shap_top",
    "attack_techniques", "policy_override",
]


# ─────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mangekyo",
        description=f"{TAGLINE}\n\nProject Mangekyo -- attack surface reconnaissance "
                     f"and ML risk scoring.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"mangekyo {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--output", choices=["table", "json"], default="table",
                        help="output format (default: table)")
        sp.add_argument("--top", type=int, default=None, metavar="N",
                        help="show only the top N highest-risk hosts")
        sp.add_argument("--no-color", action="store_true",
                        help="disable colored table output")

    p_scan = subparsers.add_parser(
        "scan", help="run nmap against a target and score every host",
        description=f"{TAGLINE}\n\nRun nmap against a target and score every host.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_scan.add_argument("target", help="IP address, CIDR range, or domain to scan")
    p_scan.add_argument("--version-intensity", type=int, choices=range(0, 10),
                        default=5, metavar="{0-9}",
                        help="Nmap version detection intensity (0-9, default: 5)")
    add_common(p_scan)

    p_explain = subparsers.add_parser(
        "explain",
        help="full risk breakdown for a live host "
             "(runs an Nmap scan + live threat intel in real time)",
        description=(
            f"{TAGLINE}\n\n"
            "explain <ip|host>   Full risk breakdown for a live host\n"
            "                    (runs an Nmap scan + live threat "
            "intel in real time)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_explain.add_argument("ip", metavar="ip|host",
                            help="IP address or hostname of the target")
    p_explain.add_argument("--from-xml", metavar="FILE", default=None,
                            help="load host data from an Nmap XML file instead of running a live scan")
    p_explain.add_argument("--all-cves", action="store_true",
                            help="show every CVE found instead of just the top 10")
    p_explain.add_argument("--version-intensity", type=int, choices=range(0, 10),
                            default=5, metavar="{0-9}",
                            help="Nmap version detection intensity (0-9, default: 5)")
    add_common(p_explain)

    p_score = subparsers.add_parser(
        "score", help="score an existing Nmap XML file",
        description=f"{TAGLINE}\n\nScore one or more hosts from an existing Nmap XML file.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_score.add_argument("file", help="path to an Nmap XML file (-oX output)")
    add_common(p_score)

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# OUTPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _progress(message: str, args: argparse.Namespace):
    """
    Transient progress indicator for one pipeline phase.

    Rich spinner on an interactive, colored terminal; plain "[*] ..."
    text for --no-color or non-tty output; suppressed entirely for
    --output json so piped output stays clean.
    """
    if args.output == "json":
        yield
        return

    if (not args.no_color) and sys.stderr.isatty():
        from rich.console import Console
        console = Console(stderr=True)
        with console.status(message):
            yield
    else:
        print(f"[*] {message}", file=sys.stderr)
        yield


def _tier_color(tier: str, use_color: bool) -> str:
    if not use_color:
        return tier
    color = TIER_COLORS.get(tier, "")
    return f"{color}{tier}{_RESET}" if color else tier


def _format_ports(ports: list[int], limit: int = 8) -> str:
    if not ports:
        return "(none)"
    shown = ports[:limit]
    text = ",".join(str(p) for p in shown)
    if len(ports) > limit:
        text += f" (+{len(ports) - limit} more)"
    return text


def _format_policy_note(r: dict) -> str:
    """
    "  (policy: "exposed RDP port" -> CRITICAL, model scored HIGH)"

    Always shows the original model tier alongside the override so the
    model's finding is never hidden.
    """
    override = r["policy_override"]
    name = override["rule"].rsplit(" → ", 1)[0]
    return (f'  (policy: "{name}" → {r["tier"]}, '
            f'model scored {override["original_tier"]})')


_MIN_COL_WIDTHS = (14, 5, 8, 12, 12, 20)
# HOST, RISK, TIER, CONFIDENCE, OPEN PORTS, TOP SIGNALS

def _format_elapsed(elapsed: float) -> str:
    """Wall-clock seconds rendered for the summary line, e.g. '23s'."""
    return f"{round(elapsed)}s"


def _print_table(results: list[dict], use_color: bool,
                 elapsed: float | None = None, intensity: int = 5) -> None:
    if not results:
        print("[!] No hosts found.")
        return

    headers = ("HOST", "RISK", "TIER", "CONFIDENCE", "OPEN PORTS", "TOP SIGNALS")
    rows = []
    plain_tiers = []
    for r in results:
        host  = r["host"] or "(unknown)"
        risk  = f"{r['risk_score']:.1f}"
        marker = " ⚙" if r.get("policy_override") else ""
        plain_tier = r["tier"] + marker
        tier  = _tier_color(r["tier"], use_color) + marker
        conf  = f"{r['confidence']} ({r['confidence_score']})"
        ports = _format_ports(r["open_ports"])
        signals = "; ".join(r["top_signals"][:2]) if r["top_signals"] else "(none)"
        rows.append((host, risk, tier, conf, ports, signals))
        plain_tiers.append(plain_tier)

    # Column widths: max of header, per-column minimum, and actual content length.
    widths = [max(len(h), _MIN_COL_WIDTHS[i]) for i, h in enumerate(headers)]
    for plain_tier, row in zip(plain_tiers, rows):
        plain = (row[0], row[1], plain_tier, row[3], row[4], row[5])
        for i, cell in enumerate(plain):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(cells, tier_plain_len=None):
        parts = []
        for i, cell in enumerate(cells):
            if i == 2 and tier_plain_len is not None:
                pad = " " * max(0, widths[i] - tier_plain_len)
                parts.append(cell + pad)
            else:
                parts.append(f"{cell:<{widths[i]}}")
        return "  ".join(parts)

    print(fmt_row(headers))
    print("  ".join("-" * w for w in widths))
    for r, row, plain_tier in zip(results, rows, plain_tiers):
        print(fmt_row(row, tier_plain_len=len(plain_tier)))
        if r.get("policy_override"):
            print(_format_policy_note(r))

    print()
    _print_summary(results, elapsed)
    for r in results:
        hint = _version_intensity_hint(r.get("confidence_sub_scores") or {}, intensity)
        if hint:
            print(hint)
            break


def _print_summary(results: list[dict], elapsed: float | None = None) -> None:
    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1

    parts = ", ".join(f"{tier}: {count}" for tier, count in tier_counts.items())
    line = f"Scanned {len(results)} host(s)  |  {parts}"
    if elapsed is not None:
        line += f"  |  {_format_elapsed(elapsed)}"
    print(line)


def _to_json_record(r: dict) -> dict:
    record = {k: r[k] for k in _JSON_HOST_FIELDS}
    record["attack_techniques"] = [
        {k: t[k] for k in ("cve_id", "technique_id", "technique_name", "tactic")}
        for t in record["attack_techniques"]
    ]
    return record


def _build_summary(results: list[dict]) -> dict:
    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        tier_counts[r["tier"]] = tier_counts.get(r["tier"], 0) + 1

    highest = max(results, key=lambda r: r["risk_score"]) if results else None
    return {
        "total_hosts": len(results),
        "tier_counts": tier_counts,
        "highest_risk": (
            {"host": highest["host"], "risk_score": highest["risk_score"],
             "tier": highest["tier"]}
            if highest else None
        ),
    }


def _print_json(results: list[dict]) -> None:
    payload = {
        "hosts": [_to_json_record(r) for r in results],
        "summary": _build_summary(results),
    }
    print(json.dumps(payload, indent=2))


def _emit(results: list[dict], output: str, use_color: bool,
          elapsed: float | None = None, intensity: int = 5) -> None:
    if output == "json":
        _print_json(results)
    else:
        _print_table(results, use_color, elapsed, intensity)


# ─────────────────────────────────────────────────────────────────────────────
# SCORE COMMAND
# ─────────────────────────────────────────────────────────────────────────────

def _run_score(args: argparse.Namespace) -> int:
    from .. import inference
    from .. import policy

    start = time.monotonic()

    if args.top is not None and args.top < 1:
        print(f"[!] --top must be >= 1 (got {args.top})", file=sys.stderr)
        return 1

    xml_path = Path(args.file)
    if not xml_path.exists():
        print(f"[!] File not found: {xml_path}", file=sys.stderr)
        return 1

    with _progress("Parsing XML...", args):
        try:
            host_dicts = inference.parse_nmap_hosts(str(xml_path))
        except ET.ParseError as exc:
            print(f"[!] Could not parse {xml_path}: {exc}", file=sys.stderr)
            return 1

    if not host_dicts:
        print(f"[!] No <host> entries found in {xml_path}", file=sys.stderr)
        return 1

    try:
        model, explainer = inference.load_model()
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    # Threat-intel lookups print progress/diagnostics to stdout; keep the
    # report clean by discarding that chatter.
    with _progress("Enriching against NVD / EPSS / KEV...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            inference.init_threat_intel()

    _perf = policy.load_performance()
    with _progress("Scoring and explaining...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            results = [inference.score_host(h, model, explainer, max_tier3=_perf["max_tier3_mappings"]) for h in host_dicts]

    rules = policy.load_rules()
    results = [
        applied for h, r in zip(host_dicts, results)
        if (applied := policy.apply_policy(h, r, rules)) is not None
    ]

    results.sort(key=lambda r: (r["risk_score"], r["confidence_score"]), reverse=True)
    if args.top is not None:
        results = results[:args.top]

    use_color = (not args.no_color) and sys.stdout.isatty() and args.output == "table"
    # score reads a static XML and has no --version-intensity flag, so the
    # hint treats it as Nmap's default intensity of 5 (suggest going higher).
    _emit(results, args.output, use_color, time.monotonic() - start, intensity=5)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# SCAN COMMAND
# ─────────────────────────────────────────────────────────────────────────────

def _run_scan(args: argparse.Namespace) -> int:
    import shutil
    import subprocess

    from .. import inference
    from .. import policy

    start = time.monotonic()

    if args.top is not None and args.top < 1:
        print(f"[!] --top must be >= 1 (got {args.top})", file=sys.stderr)
        return 1

    nmap_path = shutil.which("nmap")
    if not nmap_path:
        print("[!] nmap not found on PATH. Install nmap and try again.", file=sys.stderr)
        return 1

    # -sT (TCP connect) is used instead of the default SYN scan (-sS) because
    # -sS requires raw-socket/admin privileges; without them Npcap reports
    # every probed port as open/tcpwrapped. -T4 keeps -sT's per-port handshake
    # overhead from making a full 1000-port scan impractically slow.
    cmd = [nmap_path, "-Pn", "-sT", "-sV", "--version-intensity",
           str(args.version_intensity), "-T4", "-oX", "-", args.target]
    with _progress(f"Running Nmap scan on {args.target}...", args):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        except subprocess.TimeoutExpired:
            print("[!] nmap scan timed out.", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"[!] Failed to run nmap: {exc}", file=sys.stderr)
            return 1

    if not proc.stdout.strip():
        print(f"[!] nmap produced no output: {proc.stderr.strip()}", file=sys.stderr)
        return 1

    try:
        host_dicts = inference.parse_nmap_hosts_from_string(proc.stdout)
    except ET.ParseError as exc:
        print(f"[!] Could not parse nmap output: {exc}", file=sys.stderr)
        return 1

    if not host_dicts:
        print(f"[!] No hosts found for {args.target}", file=sys.stderr)
        return 1

    try:
        model, explainer = inference.load_model()
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    # Threat-intel lookups print progress/diagnostics to stdout; keep the
    # report clean by discarding that chatter.
    with _progress(f"Enriching {len(host_dicts)} host(s) against NVD / EPSS / KEV...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            inference.init_threat_intel()

    _perf = policy.load_performance()
    with _progress("Scoring and explaining...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            results = [inference.score_host(h, model, explainer, max_tier3=_perf["max_tier3_mappings"]) for h in host_dicts]

    rules = policy.load_rules()
    results = [
        applied for h, r in zip(host_dicts, results)
        if (applied := policy.apply_policy(h, r, rules)) is not None
    ]

    results.sort(key=lambda r: (r["risk_score"], r["confidence_score"]), reverse=True)
    if args.top is not None:
        results = results[:args.top]

    use_color = (not args.no_color) and sys.stdout.isatty() and args.output == "table"
    _emit(results, args.output, use_color, time.monotonic() - start,
          intensity=args.version_intensity)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# EXPLAIN HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_CWE_NAMES: dict[str, str] = {
    "CWE-20":  "Improper Input Validation",
    "CWE-22":  "Path Traversal",
    "CWE-23":  "Relative Path Traversal",
    "CWE-36":  "Absolute Path Traversal",
    "CWE-73":  "External Control of File Name",
    "CWE-77":  "Command Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting",
    "CWE-80":  "Basic XSS",
    "CWE-88":  "Argument Injection",
    "CWE-89":  "SQL Injection",
    "CWE-90":  "LDAP Injection",
    "CWE-91":  "XML Injection",
    "CWE-94":  "Code Injection",
    "CWE-95":  "Eval Injection",
    "CWE-119": "Buffer Errors",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-121": "Stack Buffer Overflow",
    "CWE-122": "Heap Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-191": "Integer Underflow",
    "CWE-200": "Information Exposure",
    "CWE-209": "Error Message Info Leak",
    "CWE-264": "Privileges / Permissions",
    "CWE-269": "Improper Privilege Management",
    "CWE-287": "Improper Authentication",
    "CWE-288": "Auth Bypass via Alternate Path",
    "CWE-295": "Certificate Validation Failure",
    "CWE-297": "Cert / Host Mismatch",
    "CWE-306": "Missing Authentication",
    "CWE-307": "Excessive Auth Attempts",
    "CWE-310": "Cryptographic Issues",
    "CWE-312": "Cleartext Storage",
    "CWE-313": "Cleartext Storage in File",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken Cryptographic Algorithm",
    "CWE-330": "Insufficient Random Values",
    "CWE-352": "CSRF",
    "CWE-362": "Race Condition",
    "CWE-384": "Session Fixation",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-401": "Memory Leak",
    "CWE-416": "Use After Free",
    "CWE-434": "Dangerous File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-640": "Weak Password Recovery",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hardcoded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-917": "Expression Language Injection",
    "CWE-918": "SSRF",
}


def _attack_tier_label(source: str) -> str:
    """Map a mitre_mapper '_source' string to a Tier 1/2/3 label."""
    if source == "ATT&CK STIX":
        return "Tier 1"
    if source.startswith("CWE fallback"):
        m = re.search(r"(CWE-\d+)", source)
        if m:
            cwe_id = m.group(1)
            cwe_name = _CWE_NAMES.get(cwe_id, "")
            label = f"{cwe_id} {cwe_name}" if cwe_name else cwe_id
            return f"Tier 3 ({label})"
        return "Tier 3"
    return "Tier 2"


def _order_cves_by_severity(cves: list[str], gte) -> list[str]:
    """
    Order CVEs for display: CISA KEV (confirmed exploited) first, then by
    EPSS exploitation probability (already cached by get_intel during
    scoring), then alphabetically as a stable tiebreaker.
    """
    def key(cve: str):
        in_kev = cve in gte._KEV_SET
        epss = gte._EPSS_CACHE.get(cve, 0.0)
        return (0 if in_kev else 1, -epss, cve)

    return sorted(cves, key=key)


def _epss_pct(gte, cve: str) -> float:
    """EPSS probability for one CVE, normalized to 0-100 (matches max_epss_score)."""
    return round(gte._EPSS_CACHE.get(cve, 0.0) * 100, 1)


def _group_attack_techniques(
    techniques: list[dict],
) -> dict[str, dict[tuple[str, str], list[dict]]]:
    """
    Group ATT&CK mappings by tactic, then by technique, preserving the
    incoming order (KEV-first, EPSS-descending) so the highest-impact
    tactic/technique/CVE appears first within each group.
    """
    grouped: dict[str, dict[tuple[str, str], list[dict]]] = {}
    for t in techniques:
        tech_key = (t["technique_id"], t["technique_name"])
        grouped.setdefault(t["tactic"], {}).setdefault(tech_key, []).append(t)
    return grouped


def _sort_techniques_by_severity(techniques: list[dict], gte) -> list[dict]:
    """Order ATT&CK mappings the same way as the CVE list: KEV first, then
    by EPSS descending, so the highest-impact mapped CVEs appear first."""
    def key(t: dict):
        cve = t["cve_id"]
        in_kev = cve in gte._KEV_SET
        epss = gte._EPSS_CACHE.get(cve, 0.0)
        return (0 if in_kev else 1, -epss, cve)

    return sorted(techniques, key=key)


def _cvss_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


# Plain-English descriptions for the SHAP "risk drivers" line, keyed by
# feature name. A value of None means the feature is skipped entirely
# (redundant with another feature already shown).
_FEATURE_DESCRIPTIONS: dict[str, object] = {
    "max_epss_score":       lambda v: f"Exploitation probability {v:.1f} — actively exploited in the wild",
    "max_nvd_score":        lambda v: f"Max CVSS {v / 10:.1f} — {_cvss_severity(v / 10)} severity",
    "kev_port_count":       lambda v: f"{int(v)} ports have CISA KEV-confirmed CVEs",
    "mean_nvd_score":       lambda v: f"Average CVSS {v / 10:.1f} across all services",
    "max_base_exposure":    lambda v: f"Exposure score {v:.0f} on open ports",
    "unique_service_count": lambda v: f"{int(v)} distinct services detected",
    "port_count":           lambda v: f"{int(v)} open ports",
    "log_port_count":       None,
    "nvd_zero_count":       lambda v: f"{int(v)} services with no CVE data",
    "has_kev_cve":          lambda v: "KEV-confirmed CVE present",
    "has_high_epss":        lambda v: "High exploitation probability CVE present",
    "versionless_ratio":    lambda v: f"{v:.0%} of services unversioned",
    "has_ancient_version":  lambda v: "End-of-life software detected",
    "is_rdp":               lambda v: "RDP exposed",
    "is_telnet":            lambda v: "Telnet exposed",
    "is_ftp":               lambda v: "FTP exposed",
    "os_is_windows":        lambda v: "Windows host detected",
}


def _describe_feature(feature: str, value: float) -> str | None:
    """Plain-English description of a SHAP feature/value pair, or None to
    skip this feature in the RISK DRIVERS display."""
    describe = _FEATURE_DESCRIPTIONS.get(feature)
    if describe is None:
        return None
    return describe(value)


def _format_risk_drivers(shap_top: list[dict]) -> list[str]:
    """
    Build the RISK DRIVERS lines: "  [+X.X]  feature_name   plain description",
    with the contribution brackets and feature-name column aligned.
    """
    entries = []
    for s in shap_top:
        desc = _describe_feature(s["feature"], s["value"])
        if desc is None:
            continue
        sign = "+" if s["direction"] == "up" else "-"
        val_str = f"{sign}{abs(s['shap']):.1f}"
        entries.append((val_str, s["feature"], desc))

    if not entries:
        return []

    val_width = max(len(v) for v, _, _ in entries)
    name_width = max(len(n) for _, n, _ in entries) + 2

    return [
        f"  [{val:<{val_width}}]  {name:<{name_width}}{desc}"
        for val, name, desc in entries
    ]


_CONF_SUB_LABELS = [
    ("CPE Match",    "cpe",     30),
    ("Threat Intel", "intel",   50),
    ("Version Data", "version", 20),
]

_CONF_SUB_WARNINGS: dict[str, dict[tuple[int, int], str]] = {
    "CPE Match": {
        (0,  0):  "No services identified — score is based on port exposure only.",
        (1, 49):  "Poor service identification — significant portions of attack surface unscored.",
        (50, 69): "Partial service identification — unrecognized ports excluded from scoring.",
        (70, 89): "Minor gaps in service identification — some ports unrecognized.",
    },
    "Threat Intel": {
        (0,  0):  "No threat intel retrieved — score reflects exposure only, not known vulnerabilities.",
        (1, 49):  "Poor intel coverage — most services lack vulnerability data, score may underestimate risk.",
        (50, 69): "Partial intel coverage — some services have no vulnerability data.",
        (70, 89): "Minor intel gaps — a few services returned no NVD data.",
    },
    "Version Data": {
        (0,  0):  "No version data available — CVE matches are unverified broad estimates.",
        (1, 49):  "Poor version coverage — CVE counts may be significantly inflated.",
        (50, 69): "Partial version coverage — CVE matches broader than ideal.",
        (70, 89): "Minor gaps in version data — CVE matches may include some false positives.",
    },
}


def _conf_pct(score: int, max_score: int) -> int:
    """A confidence sub-score as a 0-100 percentage of its maximum."""
    return round((score / max_score) * 100) if max_score > 0 else 0


def _conf_sub_warn(label: str, score: int, max_score: int) -> str:
    """Return ' — <warning>' for a sub-score, or '' if 90-100% (silent)."""
    pct = _conf_pct(score, max_score)
    if pct >= 90:
        return ""
    for (lo, hi), msg in _CONF_SUB_WARNINGS.get(label, {}).items():
        if lo <= pct <= hi:
            return f" — {msg}"
    return ""


_MAX_VERSION_INTENSITY = 9

_HINT_TRY_HIGHER = (
    "[!] Some services could not be identified. Try a higher --version-intensity "
    "(e.g. 7, 8, or 9) for fuller CVE coverage. Higher values are slower."
)
_HINT_AT_MAX = (
    "[!] Some services could not be identified even at maximum scan intensity. "
    "This network may be filtering Nmap probes — try scanning from a different "
    "network for fuller CVE coverage."
)


def _coverage_is_thin(sub: dict) -> bool:
    """True when CPE Match or Version Data is below 70% of its maximum.

    Reuses the same sub-score percentage logic as the confidence warnings,
    so a well-identified host (>= 70%) stays silent.
    """
    for _, key, max_score in _CONF_SUB_LABELS:
        if key in ("cpe", "version") and _conf_pct(sub.get(key, 0), max_score) < 70:
            return True
    return False


def _version_intensity_hint(sub: dict, intensity: int) -> str | None:
    """
    Return the version-intensity hint when identification coverage is thin
    (CPE Match or Version Data below 70% of its maximum), otherwise None.

    The wording depends on the intensity the current run actually used:
    below the maximum, suggest raising --version-intensity; already at the
    maximum, suggest scanning from a different network instead. A run with
    no --version-intensity flag uses Nmap's default of 5.
    """
    if not _coverage_is_thin(sub):
        return None
    if intensity >= _MAX_VERSION_INTENSITY:
        return _HINT_AT_MAX
    return _HINT_TRY_HIGHER


def _print_explain_table(r: dict, gte, use_color: bool, show_all_cves: bool,
                         intensity: int = 5) -> None:
    host = r["host"] or "(unknown)"
    hostnames = ", ".join(r.get("hostnames", []))
    title = f"{host} ({hostnames})" if hostnames else host

    print(f"HOST: {title}")
    print()
    marker = " ⚙" if r.get("policy_override") else ""
    print(f"RISK SCORE  : {r['risk_score']:.1f}  {_tier_color(r['tier'], use_color)}{marker}")
    if r.get("policy_override"):
        print(f"             {_format_policy_note(r)}")
    conf_label = r["confidence"]
    conf_score = r["confidence_score"]
    if conf_label == "LOW":
        print(f"CONFIDENCE  : ⚠  LOW — Unresolved Finding ({conf_score}/100)")
    else:
        print(f"CONFIDENCE  : {conf_label} ({conf_score}/100)")
    sub = r.get("confidence_sub_scores") or {}
    if sub:
        label_w = max(len(lbl) for lbl, _, _ in _CONF_SUB_LABELS)
        for lbl, key, max_score in _CONF_SUB_LABELS:
            val = sub.get(key, 0)
            score_str = f"{val}/{max_score}"
            warn = _conf_sub_warn(lbl, val, max_score)
            print(f"              {lbl:<{label_w}}  {score_str}{warn}")
        hint = _version_intensity_hint(sub, intensity)
        if hint:
            print(f"              {hint}")
    print()
    print(f"OPEN PORTS  : {_format_ports(r['open_ports'], limit=20)}")
    print(f"TOP SIGNALS : {'; '.join(r['top_signals'])}")
    print()

    print("RISK DRIVERS")
    drivers = _format_risk_drivers(r["shap_top"])
    if drivers:
        for line in drivers:
            print(line)
    else:
        print("  (none)")
    print()

    cves = r.get("cves", [])
    cve_count = len(cves)
    ordered = _order_cves_by_severity(cves, gte)
    shown = ordered if show_all_cves else ordered[:10]

    # Build reverse index: cve_id -> [port/proto keys]
    cve_by_port = r.get("cve_by_port", {})
    cve_port_map: dict[str, list[str]] = {}
    for port_key, port_cves in cve_by_port.items():
        for cve_id in port_cves:
            cve_port_map.setdefault(cve_id, []).append(port_key)

    if show_all_cves:
        print(f"CVES FOUND: {cve_count} total  (showing all {len(shown)})")
    else:
        print(f"CVES FOUND: {cve_count} total  (showing top {len(shown)} by exploitation probability)")
    print("-" * 52)
    if shown:
        for cve in shown:
            tags = []
            if cve in gte._KEV_SET:
                tags.append("KEV ✓")
            epss = _epss_pct(gte, cve)
            if epss > 0:
                tags.append(f"EPSS {epss:.1f}")
            suffix = f"  [{'  '.join(tags)}]" if tags else ""
            port_attr = ""
            if cve_port_map.get(cve):
                port_attr = f"  → {', '.join(cve_port_map[cve])}"
            print(f"{cve}{suffix}{port_attr}")
    else:
        print("(none)")
    remaining = len(ordered) - len(shown)
    if remaining > 0:
        print()
        print(f"+ {remaining} lower-priority CVEs not shown")
        print("  (use --all-cves flag to see complete list)")
    print()

    techniques = _sort_techniques_by_severity(r.get("attack_techniques", []), gte)
    print(f"ATT&CK MAPPINGS  ({len(techniques)} of {cve_count} CVEs mapped)")
    print("-" * 52)
    if techniques:
        grouped = _group_attack_techniques(techniques)
        for tactic, techs in grouped.items():
            print(tactic)
            for (tech_id, tech_name), mappings in techs.items():
                tier_label = _attack_tier_label(mappings[0].get("source", ""))
                tier_note = f"  [{tier_label}]" if tier_label != "Tier 1" else ""
                print(f"  {tech_id}  {tech_name}{tier_note}")
                for m in mappings:
                    tags = []
                    if m["cve_id"] in gte._KEV_SET:
                        tags.append("KEV ✓")
                    epss = _epss_pct(gte, m["cve_id"])
                    if epss > 0:
                        tags.append(f"EPSS {epss:.1f}")
                    suffix = f"  [{'  '.join(tags)}]" if tags else ""
                    print(f"         {m['cve_id']}{suffix}")
                mit_ids: list[str] = []
                for m in mappings:
                    for mit in m.get("mitigations", []):
                        if mit["id"] not in mit_ids:
                            mit_ids.append(mit["id"])
                if mit_ids:
                    print(f"         Mitigations: {', '.join(mit_ids[:5])}")
            print()
    else:
        print("(none)")
    if len(techniques) < cve_count:
        print("Mappings shown for KEV-confirmed and highest-EPSS CVEs only.")
    unmapped = cve_count - len(techniques)
    print(f"{len(techniques)} CVEs mapped · {unmapped} have no ATT&CK mapping available")


def _print_explain_json(r: dict, gte, show_all_cves: bool) -> None:
    cves = r.get("cves", [])
    ordered = _order_cves_by_severity(cves, gte)
    shown = ordered if show_all_cves else ordered[:10]
    cve_records = [
        {
            "cve_id":     cve,
            "in_kev":     cve in gte._KEV_SET,
            "epss_score": _epss_pct(gte, cve),
        }
        for cve in shown
    ]

    attack_techniques = [
        {
            "cve_id":         t["cve_id"],
            "technique_id":   t["technique_id"],
            "technique_name": t["technique_name"],
            "tactic":         t["tactic"],
            "tier":           _attack_tier_label(t.get("source", "")),
            "mitigations":    t.get("mitigations", []),
        }
        for t in _sort_techniques_by_severity(r.get("attack_techniques", []), gte)
    ]

    payload = {
        "host":               r["host"],
        "hostnames":          r.get("hostnames", []),
        "risk_score":         r["risk_score"],
        "tier":               r["tier"],
        "confidence":         r["confidence"],
        "confidence_score":   r["confidence_score"],
        "confidence_message": r["confidence_message"],
        "confidence_reasons": r["confidence_reasons"],
        "open_ports":         r["open_ports"],
        "top_signals":        r["top_signals"],
        "shap_top":           r["shap_top"],
        "cve_count":          r["cve_count"],
        "cve_by_port":        r.get("cve_by_port", {}),
        "cves":               cve_records,
        "attack_techniques":  attack_techniques,
        "policy_override":    r["policy_override"],
    }
    print(json.dumps(payload, indent=2))


# ─────────────────────────────────────────────────────────────────────────────
# EXPLAIN COMMAND
# ─────────────────────────────────────────────────────────────────────────────

def _run_explain(args: argparse.Namespace) -> int:
    from .. import inference
    from .. import policy
    from .. import scoring_engine as _gte

    start = time.monotonic()

    target = args.ip
    if "/" in target or "\\" in target or target.lower().endswith(".xml"):
        print("[!] Pass a target IP/hostname, not a file path.", file=sys.stderr)
        print("    To score an XML file use: mangekyo score <file>", file=sys.stderr)
        print("    To explain a host from XML use: mangekyo explain <ip> --from-xml <file>", file=sys.stderr)
        return 1

    try:
        ip = socket.gethostbyname(target)
    except OSError:
        print(f"[!] Could not resolve {target}", file=sys.stderr)
        return 1

    from_xml = getattr(args, "from_xml", None)
    if from_xml:
        xml_path = Path(from_xml)
        if not xml_path.exists():
            print(f"[!] File not found: {xml_path}", file=sys.stderr)
            return 1
        try:
            host_dicts = inference.parse_nmap_hosts(str(xml_path))
        except ET.ParseError as exc:
            print(f"[!] Could not parse {xml_path}: {exc}", file=sys.stderr)
            return 1
        host_dict = next((h for h in host_dicts if h.get("ip") == ip), None)
        if host_dict is None:
            print(f"[!] Host {ip} not found in {xml_path}", file=sys.stderr)
            available = [h.get("ip", "?") for h in host_dicts]
            print(f"    Hosts in file: {', '.join(available)}", file=sys.stderr)
            return 1
    else:
        import shutil
        import subprocess

        nmap_path = shutil.which("nmap")
        if not nmap_path:
            print("[!] nmap not found on PATH. Install nmap and try again.", file=sys.stderr)
            return 1

        # Same scan profile as `mangekyo scan` (-sT connect scan needs no
        # raw-socket privileges; -sV for service/version detection).
        cmd = [nmap_path, "-Pn", "-sT", "-sV", "--version-intensity",
               str(args.version_intensity), "-T4", "-oX", "-", target]
        with _progress(f"Running Nmap scan on {target}...", args):
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            except subprocess.TimeoutExpired:
                print("[!] nmap scan timed out.", file=sys.stderr)
                return 1
            except Exception as exc:
                print(f"[!] Failed to run nmap: {exc}", file=sys.stderr)
                return 1

        if not proc.stdout.strip():
            print(f"[!] nmap produced no output: {proc.stderr.strip()}", file=sys.stderr)
            return 1

        try:
            host_dicts = inference.parse_nmap_hosts_from_string(proc.stdout)
        except ET.ParseError as exc:
            print(f"[!] Could not parse nmap output: {exc}", file=sys.stderr)
            return 1

        if not host_dicts:
            print(f"[!] No hosts found for {target}", file=sys.stderr)
            return 1

        # explain is single-host: prefer the host matching the resolved IP,
        # otherwise fall back to the only host returned for this target.
        host_dict = next((h for h in host_dicts if h.get("ip") == ip), host_dicts[0])
        if not host_dict.get("ip"):
            host_dict["ip"] = ip

    if target != ip and target not in host_dict.get("hostnames", []):
        host_dict.setdefault("hostnames", []).append(target)

    try:
        model, explainer = inference.load_model()
    except FileNotFoundError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    # Threat-intel lookups print progress/diagnostics to stdout; keep the
    # report clean by discarding that chatter.
    with _progress("Enriching against NVD / EPSS / KEV...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            inference.init_threat_intel()

    _perf = policy.load_performance()
    with _progress("Scoring and explaining...", args):
        with contextlib.redirect_stdout(io.StringIO()):
            result = inference.score_host(host_dict, model, explainer, max_tier3=_perf["max_tier3_mappings"])

    rules = policy.load_rules()
    result = policy.apply_policy(host_dict, result, rules)
    if result is None:
        print(f"[!] {ip} is suppressed by a policy rule in mangekyo.yaml.", file=sys.stderr)
        return 0

    use_color = (not args.no_color) and sys.stdout.isatty() and args.output == "table"

    if args.output == "json":
        _print_explain_json(result, _gte, args.all_cves)
    else:
        _print_explain_table(result, _gte, use_color, args.all_cves,
                             args.version_intensity)
        print()
        print(f"Completed in {_format_elapsed(time.monotonic() - start)}")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# FIRST-RUN DEDICATION
# ─────────────────────────────────────────────────────────────────────────────

_DEDICATION = "For my cousin, Tony Chery. With love."


def _print_first_run_dedication() -> None:
    """
    On the first run on a given machine, print a small framed dedication
    to stderr and write a marker file so it never shows again.
    """
    marker = Path.home() / ".mangekyo" / ".initialized"
    if marker.exists():
        return

    width = len(_DEDICATION) + 2
    print("┌" + "─" * width + "┐", file=sys.stderr)
    print("│ " + _DEDICATION + " │", file=sys.stderr)
    print("└" + "─" * width + "┘", file=sys.stderr)
    print(file=sys.stderr)

    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def app() -> None:
    # explain's CVE/ATT&CK sections use a few Unicode glyphs (checkmarks,
    # box-drawing separators). Reconfigure stdout so they render on
    # UTF-8-capable terminals instead of raising UnicodeEncodeError on
    # legacy Windows code pages.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass

    _print_first_run_dedication()

    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    handlers = {
        "scan":    _run_scan,
        "explain": _run_explain,
        "score":   _run_score,
    }
    try:
        sys.exit(handlers[args.command](args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}", file=sys.stderr)
        print("    Set MANGEKYO_DEBUG=1 to see the full traceback.", file=sys.stderr)
        if __import__("os").environ.get("MANGEKYO_DEBUG"):
            import traceback
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    app()
