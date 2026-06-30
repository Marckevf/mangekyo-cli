"""
policy.py
=========
Project Mangekyo — policy rule overlay.

Loads optional user-defined rules from mangekyo.yaml at the project
root and applies them AFTER model scoring. Rules can only:

  - raise a host's tier (the model's tier is a floor, never a ceiling)
  - suppress (hide) a host entirely

They never change risk_score, the model, the scoring formula, or
training data. If mangekyo.yaml is absent or empty, apply_policy is a
no-op and every result passes through unchanged.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from .paths import DATA_DIR

RULES_PATH = DATA_DIR / "mangekyo.yaml"

TIER_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Default for performance.max_tier3_mappings when not set in mangekyo.yaml.
_DEFAULT_MAX_TIER3 = 5

# Common service-name aliases -> substrings to look for in a port's
# service/product/cpe fields (case-insensitive). Lets rule authors write
# "rdp" without needing to know nmap reports it as "ms-wbt-server".
_SERVICE_ALIASES: dict[str, list[str]] = {
    "rdp":      ["rdp", "ms-wbt-server", "terminal services", "terminal_services"],
    "ssh":      ["ssh"],
    "ftp":      ["ftp"],
    "telnet":   ["telnet"],
    "vnc":      ["vnc"],
    "smb":      ["smb", "microsoft-ds", "netbios"],
    "mysql":    ["mysql", "mariadb"],
    "postgres": ["postgres", "postgresql"],
    "mssql":    ["mssql", "ms-sql", "sql server"],
    "http":     ["http"],
    "https":    ["https", "ssl/http"],
}


def load_performance(path: Path | None = None) -> dict:
    """
    Read the ``performance`` section of mangekyo.yaml.

    Returns a dict of performance settings with defaults applied for any
    missing keys. Safe to call even when the file is absent or malformed.
    """
    defaults: dict = {"max_tier3_mappings": _DEFAULT_MAX_TIER3}
    rules_path = path or RULES_PATH
    if not rules_path.exists():
        return defaults
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError:
        return defaults
    if not data:
        return defaults
    perf = data.get("performance") or {}
    return {**defaults, **{k: v for k, v in perf.items() if k in defaults}}


def load_rules(path: Path | None = None) -> list[dict]:
    """
    Load policy rules from mangekyo.yaml. Returns an empty list if the
    file does not exist or defines no rules -- callers can always pass
    the result to apply_policy unconditionally.
    """
    rules_path = path or RULES_PATH
    if not rules_path.exists():
        return []
    try:
        with open(rules_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as exc:
        print(f"[!] mangekyo.yaml is malformed — policy rules disabled: {exc}")
        return []
    if not data:
        return []
    return data.get("rules", []) or []


def _port_matches(when_port, open_ports: list[int]) -> bool:
    wanted = when_port if isinstance(when_port, list) else [when_port]
    return any(int(p) in open_ports for p in wanted)


def _service_matches(when_service: str, ports: list[dict]) -> bool:
    needle = str(when_service).strip().lower()
    candidates = _SERVICE_ALIASES.get(needle, [needle])
    for port in ports:
        haystack = " ".join(
            str(port.get(f, "")) for f in ("service", "product", "cpe")
        ).lower()
        if any(c in haystack for c in candidates):
            return True
    return False


def _host_matches(when_host, ip: str) -> bool:
    if not ip:
        return False
    wanted = when_host if isinstance(when_host, list) else [when_host]
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for w in wanted:
        try:
            if addr in ipaddress.ip_network(str(w), strict=False):
                return True
        except ValueError:
            continue
    return False


def _matches(when: dict, host_dict: dict, result: dict) -> bool:
    """All conditions in `when` must match (AND)."""
    if "port" in when and not _port_matches(when["port"], result["open_ports"]):
        return False
    if "service" in when and not _service_matches(when["service"], host_dict.get("ports", [])):
        return False
    if "confidence" in when and str(when["confidence"]).strip().upper() != result["confidence"]:
        return False
    if "host" in when and not _host_matches(when["host"], host_dict.get("ip", "")):
        return False
    return True


def apply_policy(host_dict: dict, result: dict, rules: list[dict]) -> dict | None:
    """
    Apply policy rules to one scored host.

    Returns the (possibly modified) result dict, or None if the host
    should be suppressed entirely. Mutates and returns `result` in
    place for convenience.
    """
    if not rules:
        return result

    for rule in rules:
        if rule.get("suppress") and _matches(rule.get("when", {}), host_dict, result):
            return None

    original_tier = result["tier"]
    best_tier = original_tier
    best_rule_name: str | None = None

    for rule in rules:
        if rule.get("suppress"):
            continue
        target = rule.get("force_tier") or rule.get("min_tier")
        if not target:
            continue
        target = str(target).strip().upper()
        if target not in TIER_ORDER:
            continue
        if not _matches(rule.get("when", {}), host_dict, result):
            continue
        if TIER_ORDER[target] > TIER_ORDER[best_tier]:
            best_tier = target
            best_rule_name = rule.get("name", "policy rule")

    if best_rule_name is not None:
        result["tier"] = best_tier
        result["policy_override"] = {
            "rule": f"{best_rule_name} → {best_tier}",
            "original_tier": original_tier,
        }

    return result
