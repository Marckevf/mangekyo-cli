"""
internetdb.py
=============
Project Mangekyo — Shodan InternetDB lookups for `mangekyo explain`.

Builds host dicts compatible with inference.score_host() from
InternetDB's flat port/CPE/CVE lists, matching CPEs to ports with
the same heuristic test_score.py uses for its InternetDB path.
"""

from __future__ import annotations

import time

import requests

from .inference import _parse_cpe

INTERNETDB_URL = "https://internetdb.shodan.io/{ip}"

_PRODUCT_PORT_HINTS: dict[str, list[int]] = {
    "openssh": [22], "ssh": [22],
    "vsftpd": [21], "proftpd": [21], "ftp": [21], "pure-ftpd": [21],
    "http_server": [80, 443, 8080, 8443], "httpd": [80, 443, 8080],
    "apache": [80, 443, 8080, 8443], "nginx": [80, 443, 8080, 8443],
    "lighttpd": [80, 443], "iis": [80, 443],
    "tomcat": [8080, 8443, 80, 443], "jetty": [8080, 8443],
    "samba": [139, 445], "smbd": [139, 445],
    "mysql": [3306], "mariadb": [3306],
    "postgresql": [5432], "mongodb": [27017],
    "redis": [6379], "memcached": [11211],
    "sql_server": [1433], "mssql": [1433],
    "dovecot": [143, 993, 110, 995],
    "postfix": [25, 587], "exim": [25, 587], "sendmail": [25, 587],
    "named": [53], "bind": [53],
    "telnet": [23], "rdp": [3389], "terminal_services": [3389],
    "vnc": [5900, 5901, 5902],
    "elasticsearch": [9200, 9300], "jenkins": [8080, 443],
    "webmin": [10000], "wordpress": [80, 443], "joomla": [80, 443],
}

_PORT_SERVICE_NAMES: dict[int, str] = {
    21: "ftp",     22: "ssh",      23: "telnet",  25: "smtp",
    53: "dns",     80: "http",    110: "pop3",   143: "imap",
    443: "https",  445: "smb",    993: "imaps",  995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp",   5432: "postgres",
    5900: "vnc",   6379: "redis", 8080: "http-alt", 8443: "https-alt",
    9200: "elasticsearch", 10000: "webmin", 11211: "memcached", 27017: "mongodb",
}


def query_internetdb(ip: str) -> dict | None:
    url = INTERNETDB_URL.format(ip=ip)
    for attempt in range(5):
        try:
            resp = requests.get(url, timeout=10,
                                headers={"User-Agent": "Mangekyo-CLI/1.0"})
        except requests.exceptions.RequestException:
            return None
        if resp.status_code == 429:
            time.sleep(2 ** (attempt + 1))
            continue
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        try:
            return resp.json()
        except Exception:
            return None
    return None


def _match_cpes_to_ports(cpes: list[str], open_ports: list[int]) -> dict[int, dict]:
    port_set = set(open_ports)
    assigned: dict[int, dict] = {}
    for cpe_str in cpes:
        vendor, product, version = _parse_cpe(cpe_str)
        if not product:
            continue
        candidates: list[int] = []
        for keyword, hint_ports in _PRODUCT_PORT_HINTS.items():
            if keyword in product or product in keyword:
                candidates.extend(hint_ports)
        for port in candidates:
            if port in port_set and port not in assigned:
                assigned[port] = {
                    "vendor": vendor, "product": product,
                    "version": version, "cpe_str": cpe_str,
                }
                break
    return assigned


def build_host_dict(raw: dict) -> dict:
    """
    Convert a raw InternetDB JSON response into the same host-dict
    schema produced by inference.parse_nmap_hosts(), so it can be
    passed straight into inference.score_host().
    """
    ip    = raw.get("ip", "")
    _raw_ports: list[int] = []
    for _p in raw.get("ports", []):
        try:
            _raw_ports.append(int(_p))
        except (ValueError, TypeError):
            pass
    ports = sorted(set(_raw_ports))
    cpes  = [str(c) for c in raw.get("cpes",      []) if c]
    cves  = [str(v) for v in raw.get("vulns",     []) if v]
    hosts = [str(h) for h in raw.get("hostnames", []) if h]
    tags  = [str(t) for t in raw.get("tags",      []) if t]

    port_cpe_map = _match_cpes_to_ports(cpes, ports)
    port_list = []
    for p in ports:
        info    = port_cpe_map.get(p, {})
        product = info.get("product", "")
        version = info.get("version", "")
        cpe_str = info.get("cpe_str", "")
        port_list.append({
            "port": p, "protocol": "tcp", "state": "open",
            "service": product or _PORT_SERVICE_NAMES.get(p, "unknown"),
            "product": product, "version": version, "cpe": cpe_str,
        })

    return {
        "ip": ip, "hostnames": hosts, "ports": port_list,
        "cpes": cpes, "cves": cves, "tags": tags, "host_is_down": False,
    }
