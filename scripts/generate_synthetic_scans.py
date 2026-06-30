"""
generate_synthetic_scans.py
===========================
Project Mangekyo — Synthetic Training Data Generator

Produces N syntactically valid Nmap XML files that feed directly into
1_generate_ground_truth(with new api calls).py without any modification.

Design goals:
  1. Seed library built from CPEs already validated against NVD in real scans
  2. Broad fingerprint library for score variance across the full 0–100 range
  3. Noise injection layer — mimics real Nmap output messiness
  4. Controlled complexity tiers — ensures balanced score distribution
  5. Auto-appends to metadata.csv so the scorer pipeline needs zero changes

Usage:
    python generate_synthetic_scans.py            # generates 300 XMLs
    python generate_synthetic_scans.py --count 500
    python generate_synthetic_scans.py --count 100 --out_dir xml_logs/synthetic

Author : Project Mangekyo
Python : 3.10+
"""

from __future__ import annotations

import argparse
import csv
import os
import random
import string
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.dom import minidom


# ─────────────────────────────────────────────────────────────────────────────
# SEED FINGERPRINT LIBRARY
# Every entry here has been validated against NVD in real Mangekyo scans
# or is a well-known service with documented CVE history.
# Format: (port, protocol, service_name, product, version, cpe, banner)
# cpe=None  → scorer falls back to generate_fallback_cpe (noise path)
# version="" → scorer gets no version (wildcard CPE path)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ServiceFingerprint:
    port:     int
    proto:    str
    name:     str
    product:  str
    version:  str
    cpe:      str | None   # None = no CPE tag in XML (noise)
    banner:   str = ""


# ── CONFIRMED HIGH-CVSS fingerprints (real NVD hits from your scans) ─────────
CRITICAL_SERVICES = [
    ServiceFingerprint(21,   "tcp", "ftp",    "ProFTPD",          "1.3.5e",
        "cpe:/a:proftpd:proftpd:1.3.5e"),
    ServiceFingerprint(21,   "tcp", "ftp",    "ProFTPD",          "1.3.3c",
        "cpe:/a:proftpd:proftpd:1.3.3c"),
    ServiceFingerprint(21,   "tcp", "ftp",    "vsftpd",           "2.3.4",
        "cpe:/a:vsftpd:vsftpd:2.3.4"),
    ServiceFingerprint(21,   "tcp", "ftp",    "vsftpd",           "3.0.3",
        "cpe:/a:vsftpd:vsftpd:3.0.3"),
    ServiceFingerprint(139,  "tcp", "netbios-ssn", "Samba smbd",  "3.0",
        "cpe:/a:samba:samba:3.0"),
    ServiceFingerprint(445,  "tcp", "microsoft-ds","Samba smbd",  "4.6.2",
        "cpe:/a:samba:samba:4.6.2"),
    ServiceFingerprint(445,  "tcp", "microsoft-ds","Samba smbd",  "3.0.20",
        "cpe:/a:samba:samba:3.0.20"),
    ServiceFingerprint(445,  "tcp", "microsoft-ds","Samba smbd",  "4.2.14",
        "cpe:/a:samba:samba:4.2.14"),
    ServiceFingerprint(23,   "tcp", "telnet",  "Linux telnetd",   "",
        None),
    ServiceFingerprint(5900, "tcp", "vnc",     "VNC",             "3.8",
        "cpe:/a:realvnc:realvnc:3.8"),
]

# ── HIGH-RISK fingerprints (known versions, real CVE history) ─────────────────
HIGH_SERVICES = [
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "7.6p1",
        "cpe:/a:openbsd:openssh:7.6p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "8.2p1",
        "cpe:/a:openbsd:openssh:8.2p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "7.4",
        "cpe:/a:openbsd:openssh:7.4"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "6.6.1p1",
        "cpe:/a:openbsd:openssh:6.6.1p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "5.9p1",
        "cpe:/a:openbsd:openssh:5.9p1"),
    ServiceFingerprint(80,   "tcp", "http",   "Apache httpd",     "2.4.29",
        "cpe:/a:apache:http_server:2.4.29"),
    ServiceFingerprint(80,   "tcp", "http",   "Apache httpd",     "2.4.49",
        "cpe:/a:apache:http_server:2.4.49"),
    ServiceFingerprint(80,   "tcp", "http",   "Apache httpd",     "2.2.34",
        "cpe:/a:apache:http_server:2.2.34"),
    ServiceFingerprint(443,  "tcp", "https",  "Apache httpd",     "2.4.53",
        "cpe:/a:apache:http_server:2.4.53"),
    ServiceFingerprint(80,   "tcp", "http",   "nginx",            "1.14.0",
        "cpe:/a:nginx:nginx:1.14.0"),
    ServiceFingerprint(80,   "tcp", "http",   "nginx",            "1.18.0",
        "cpe:/a:nginx:nginx:1.18.0"),
    ServiceFingerprint(80,   "tcp", "http",   "nginx",            "1.10.3",
        "cpe:/a:nginx:nginx:1.10.3"),
    ServiceFingerprint(3306, "tcp", "mysql",  "MySQL",            "5.5.62",
        "cpe:/a:mysql:mysql:5.5.62"),
    ServiceFingerprint(3306, "tcp", "mysql",  "MySQL",            "5.7.33",
        "cpe:/a:mysql:mysql:5.7.33"),
    ServiceFingerprint(3389, "tcp", "ms-wbt-server","Microsoft Terminal Services","",
        None),
    ServiceFingerprint(1433, "tcp", "ms-sql-s","Microsoft SQL Server","2019",
        "cpe:/a:microsoft:sql_server:2019"),
    ServiceFingerprint(53,   "tcp", "domain", "ISC BIND",         "9.16.1",
        "cpe:/a:isc:bind:9.16.1"),
    ServiceFingerprint(53,   "tcp", "domain", "ISC BIND",         "9.11.3",
        "cpe:/a:isc:bind:9.11.3"),
    ServiceFingerprint(53,   "udp", "domain", "ISC BIND",         "9.9.5",
        "cpe:/a:isc:bind:9.9.5"),
]

# ── MEDIUM-RISK fingerprints ──────────────────────────────────────────────────
MEDIUM_SERVICES = [
    ServiceFingerprint(25,   "tcp", "smtp",   "Postfix smtpd",    "2.11.0",
        "cpe:/a:postfix:postfix:2.11.0"),
    ServiceFingerprint(25,   "tcp", "smtp",   "Exim smtpd",       "4.92",
        "cpe:/a:exim:exim:4.92"),
    ServiceFingerprint(110,  "tcp", "pop3",   "Dovecot pop3d",    "",
        None),
    ServiceFingerprint(143,  "tcp", "imap",   "Dovecot imapd",    "",
        None),
    ServiceFingerprint(993,  "tcp", "imaps",  "Dovecot imapd",    "",
        None),
    ServiceFingerprint(995,  "tcp", "pop3s",  "Dovecot pop3d",    "",
        None),
    ServiceFingerprint(8080, "tcp", "http-proxy","Apache Tomcat", "9.0.30",
        "cpe:/a:apache:tomcat:9.0.30"),
    ServiceFingerprint(8080, "tcp", "http-proxy","Apache Tomcat", "7.0.76",
        "cpe:/a:apache:tomcat:7.0.76"),
    ServiceFingerprint(8443, "tcp", "https-alt","Apache Tomcat",  "8.5.32",
        "cpe:/a:apache:tomcat:8.5.32"),
    ServiceFingerprint(5432, "tcp", "postgresql","PostgreSQL",     "12.3",
        "cpe:/a:postgresql:postgresql:12.3"),
    ServiceFingerprint(5432, "tcp", "postgresql","PostgreSQL",     "9.6.17",
        "cpe:/a:postgresql:postgresql:9.6.17"),
    ServiceFingerprint(6379, "tcp", "redis",  "Redis",            "6.0.9",
        "cpe:/a:redislabs:redis:6.0.9"),
    ServiceFingerprint(6379, "tcp", "redis",  "Redis",            "5.0.7",
        "cpe:/a:redislabs:redis:5.0.7"),
    ServiceFingerprint(27017,"tcp", "mongod", "MongoDB",          "4.2.8",
        "cpe:/a:mongodb:mongodb:4.2.8"),
    ServiceFingerprint(111,  "tcp", "rpcbind","rpcbind",          "2-4",
        None),
    ServiceFingerprint(2049, "tcp", "nfs",    "NFS",              "3",
        None),
]

# ── LOW-RISK fingerprints (modern, patched, real-world clean servers) ─────────
LOW_SERVICES = [
    # Modern patched web servers
    ServiceFingerprint(443,  "tcp", "https",  "Apache httpd",     "2.4.57",
        "cpe:/a:apache:http_server:2.4.57"),
    ServiceFingerprint(443,  "tcp", "https",  "nginx",            "1.24.0",
        "cpe:/a:nginx:nginx:1.24.0"),
    ServiceFingerprint(443,  "tcp", "https",  "nginx",            "1.22.1",
        "cpe:/a:nginx:nginx:1.22.1"),
    ServiceFingerprint(80,   "tcp", "http",   "nginx",            "1.23.0",
        "cpe:/a:nginx:nginx:1.23.0"),
    ServiceFingerprint(443,  "tcp", "https",  "lighttpd",         "1.4.67",
        "cpe:/a:lighttpd:lighttpd:1.4.67"),
    ServiceFingerprint(443,  "tcp", "https",  "Apache httpd",     "2.4.54",
        "cpe:/a:apache:http_server:2.4.54"),
    ServiceFingerprint(443,  "tcp", "https",  "nginx",            "1.22.0",
        "cpe:/a:nginx:nginx:1.22.0"),
    # Modern SSH
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "9.3p1",
        "cpe:/a:openbsd:openssh:9.3p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "9.1p1",
        "cpe:/a:openbsd:openssh:9.1p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "8.9p1",
        "cpe:/a:openbsd:openssh:8.9p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "9.0p1",
        "cpe:/a:openbsd:openssh:9.0p1"),
    # Modern databases — patched
    ServiceFingerprint(5432, "tcp", "postgresql", "PostgreSQL",   "15.2",
        "cpe:/a:postgresql:postgresql:15.2"),
    ServiceFingerprint(3306, "tcp", "mysql",  "MySQL",            "8.0.32",
        "cpe:/a:mysql:mysql:8.0.32"),
    # Monitoring and modern infra
    ServiceFingerprint(9090, "tcp", "http",   "Prometheus",       "2.42.0",
        None),
    ServiceFingerprint(3000, "tcp", "http",   "Grafana",          "9.4.3",
        None),
    ServiceFingerprint(9200, "tcp", "http",   "Elasticsearch",    "8.6.2",
        "cpe:/a:elastic:elasticsearch:8.6.2"),
    # Encrypted mail
    ServiceFingerprint(993,  "tcp", "imaps",  "Dovecot imapd",    "2.3.20",
        None),
    ServiceFingerprint(587,  "tcp", "smtp",   "Postfix smtpd",    "3.7.4",
        "cpe:/a:postfix:postfix:3.7.4"),
    # Modern DNS
    ServiceFingerprint(53,   "tcp", "domain", "ISC BIND",         "9.18.12",
        "cpe:/a:isc:bind:9.18.12"),
    ServiceFingerprint(8888, "tcp", "http",   "Jupyter Notebook", "",
        None),
]

# ── CLEAN fingerprints (minimal tier only — genuinely low-risk hosts) ─────────
# These are well-maintained, single-purpose servers with no known critical CVEs.
# Designed to produce scores in the 5–25 range to pull the dataset mean down.
CLEAN_SERVICES = [
    ServiceFingerprint(443,  "tcp", "https",  "nginx",            "1.24.0",
        "cpe:/a:nginx:nginx:1.24.0"),
    ServiceFingerprint(443,  "tcp", "https",  "Apache httpd",     "2.4.57",
        "cpe:/a:apache:http_server:2.4.57"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "9.3p1",
        "cpe:/a:openbsd:openssh:9.3p1"),
    ServiceFingerprint(22,   "tcp", "ssh",    "OpenSSH",          "9.1p1",
        "cpe:/a:openbsd:openssh:9.1p1"),
    ServiceFingerprint(587,  "tcp", "smtp",   "Postfix smtpd",    "3.7.4",
        "cpe:/a:postfix:postfix:3.7.4"),
    ServiceFingerprint(53,   "tcp", "domain", "ISC BIND",         "9.18.12",
        "cpe:/a:isc:bind:9.18.12"),
    ServiceFingerprint(443,  "tcp", "https",  "lighttpd",         "1.4.67",
        "cpe:/a:lighttpd:lighttpd:1.4.67"),
    ServiceFingerprint(9090, "tcp", "http",   "Prometheus",       "2.42.0",
        None),
]

# ── OS fingerprint pool ───────────────────────────────────────────────────────
OS_POOL = [
    ("Linux 4.15 - 5.6",   "Linux",   "general purpose"),
    ("Linux 5.4",          "Linux",   "general purpose"),
    ("Linux 3.10 - 4.11",  "Linux",   "general purpose"),
    ("Ubuntu 18.04",       "Linux",   "general purpose"),
    ("Ubuntu 20.04",       "Linux",   "general purpose"),
    ("Debian 10",          "Linux",   "general purpose"),
    ("CentOS 7",           "Linux",   "general purpose"),
    ("Windows Server 2019","Windows", "general purpose"),
    ("Windows Server 2016","Windows", "general purpose"),
    ("Windows 10",         "Windows", "general purpose"),
    ("FreeBSD 12.1",       "BSD",     "general purpose"),
    ("",                   "",        ""),   # unknown OS — noise
]


# ─────────────────────────────────────────────────────────────────────────────
# COMPLEXITY TIERS
# Controls which service pools are sampled and how many ports are open.
# Weights control how often each tier appears in the final dataset.
# ─────────────────────────────────────────────────────────────────────────────

TIERS = {
    "dead":     {"weight": 0.15, "port_range": (0, 0),   "pools": []},
    "minimal":  {"weight": 0.35, "port_range": (1, 2),   "pools": [CLEAN_SERVICES]},
    "low":      {"weight": 0.30, "port_range": (1, 3),   "pools": [LOW_SERVICES]},
    "medium":   {"weight": 0.12, "port_range": (3, 5),   "pools": [MEDIUM_SERVICES, LOW_SERVICES]},
    "high":     {"weight": 0.15, "port_range": (5, 8),   "pools": [HIGH_SERVICES, MEDIUM_SERVICES]},
    "critical": {"weight": 0.03, "port_range": (4, 10),  "pools": [CRITICAL_SERVICES, HIGH_SERVICES, MEDIUM_SERVICES]},
}


# ─────────────────────────────────────────────────────────────────────────────
# NOISE INJECTION LAYER
# Mimics real Nmap output messiness. Applied per-service after selection.
# ─────────────────────────────────────────────────────────────────────────────

def apply_noise(svc: ServiceFingerprint) -> ServiceFingerprint:
    """
    Returns a (possibly mutated) copy of the fingerprint with real-world noise.

    Noise probabilities:
      30% → CPE stripped entirely (product name only path in scorer)
      20% → version string stripped (wildcard CPE path)
      15% → distro suffix appended to version (CPE cleaner path)
       5% → semicolon build tag appended (PATCH-A path)
      10% → product name only, no CPE, no version (deep scan fallback path)
    """
    import copy
    s = copy.copy(svc)

    roll = random.random()

    if roll < 0.10:
        # Total banner noise — no product, no version, no CPE
        # Forces scorer into the "no search_term" path → nvd_risk = 0
        s.product = ""
        s.version = ""
        s.cpe     = None

    elif roll < 0.20:
        # Product only, no version, no CPE
        s.version = ""
        s.cpe     = None

    elif roll < 0.35:
        # CPE present but version stripped → wildcard CPE path
        s.version = ""
        if s.cpe:
            # Replace version in CPE with wildcard
            parts = s.cpe.split(":")
            if len(parts) >= 5:
                parts[4] = "*" if s.cpe.startswith("cpe:/") else parts[4]
            s.cpe = ":".join(parts)

    elif roll < 0.50:
        # CPE stripped — scorer falls back to generate_fallback_cpe
        s.cpe = None

    elif roll < 0.60 and s.version:
        # Distro suffix appended — CPE cleaner Rule 1 path
        distro = random.choice([
            "_ubuntu_4ubuntu0.3", "_debian_1", "_deb9u2",
            "_focal_1", "_bionic_2", "_1ubuntu0.1",
        ])
        s.version = s.version + distro

    elif roll < 0.65 and s.version:
        # Semicolon build tag — PATCH-A path
        s.version = s.version + ";_rtm"

    # else: clean fingerprint, no noise (35% of services are clean)

    return s


# ─────────────────────────────────────────────────────────────────────────────
# IP GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def _random_ip() -> str:
    """Generate a plausible private or HTB-range IP."""
    ranges = [
        (10, 129, None, None),    # HTB range
        (10, 10,  None, None),    # HTB range 2
        (192, 168, None, None),   # Private class C
        (172, random.randint(16, 31), None, None),  # Private class B
    ]
    r = random.choice(ranges)
    a, b = r[0], r[1]
    c = random.randint(0, 254)
    d = random.randint(1, 254)
    return f"{a}.{b}.{c}.{d}"


# ─────────────────────────────────────────────────────────────────────────────
# XML BUILDER
# Produces Nmap XML that is structurally identical to real Nmap output.
# The scorer's ET.parse() will consume this without modification.
# ─────────────────────────────────────────────────────────────────────────────

def _pick_tier() -> str:
    tiers  = list(TIERS.keys())
    weights = [TIERS[t]["weight"] for t in tiers]
    return random.choices(tiers, weights=weights, k=1)[0]


def _pick_services(tier: str) -> list[ServiceFingerprint]:
    cfg = TIERS[tier]
    if tier == "dead":
        return []

    lo, hi   = cfg["port_range"]
    n        = random.randint(lo, hi)
    pools    = cfg["pools"]
    combined = []
    for pool in pools:
        combined.extend(pool)

    # Sample without replacement where possible
    n        = min(n, len(combined))
    selected = random.sample(combined, n)

    # Apply noise to each service
    return [apply_noise(s) for s in selected]


def build_nmap_xml(ip: str, tier: str, services: list[ServiceFingerprint]) -> ET.Element:
    """Construct a valid Nmap XML ElementTree rooted at <nmaprun>."""

    now_ts  = str(int(datetime.now(timezone.utc).timestamp()))
    os_info = random.choice(OS_POOL)

    # ── <nmaprun> root ────────────────────────────────────────────────────────
    root = ET.Element("nmaprun", attrib={
        "scanner":     "nmap",
        "args":        f"nmap -sV -sC -O {ip}",
        "start":       now_ts,
        "startstr":    datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        "version":     "7.94",
        "xmloutputversion": "1.05",
    })

    # ── <scaninfo> ────────────────────────────────────────────────────────────
    ET.SubElement(root, "scaninfo", attrib={
        "type": "syn", "protocol": "tcp", "numservices": "1000",
        "services": "1-1000",
    })

    # ── <host> ────────────────────────────────────────────────────────────────
    host_status = "down" if tier == "dead" else "up"
    host = ET.SubElement(root, "host", attrib={
        "starttime": now_ts, "endtime": now_ts,
    })

    ET.SubElement(host, "status", attrib={
        "state": host_status, "reason": "echo-reply", "reason_ttl": "64",
    })
    ET.SubElement(host, "address", attrib={
        "addr": ip, "addrtype": "ipv4",
    })

    # Hostnames
    hostnames_elem = ET.SubElement(host, "hostnames")
    if random.random() > 0.6:
        ET.SubElement(hostnames_elem, "hostname", attrib={
            "name": f"host-{ip.replace('.', '-')}.local",
            "type": "PTR",
        })

    # ── <ports> ───────────────────────────────────────────────────────────────
    if tier != "dead" and services:
        ports_elem = ET.SubElement(host, "ports")

        # Add a handful of closed/filtered ports for realism
        used_ports = {s.port for s in services}
        for _ in range(random.randint(0, 3)):
            fake_port = random.randint(1024, 9999)
            if fake_port not in used_ports:
                p = ET.SubElement(ports_elem, "port", attrib={
                    "protocol": "tcp", "portid": str(fake_port),
                })
                ET.SubElement(p, "state", attrib={
                    "state":  random.choice(["closed", "filtered"]),
                    "reason": "reset",
                    "reason_ttl": "64",
                })

        # Open ports
        for svc in services:
            port_elem = ET.SubElement(ports_elem, "port", attrib={
                "protocol": svc.proto,
                "portid":   str(svc.port),
            })
            ET.SubElement(port_elem, "state", attrib={
                "state": "open", "reason": "syn-ack", "reason_ttl": "64",
            })

            # <service> element
            svc_attribs: dict[str, str] = {
                "name":   svc.name,
                "method": "probed",
                "conf":   str(random.randint(7, 10)),
            }
            if svc.product:
                svc_attribs["product"] = svc.product
            if svc.version:
                svc_attribs["version"] = svc.version
            if svc.cpe:
                svc_attribs["cpe"] = svc.cpe

            ET.SubElement(port_elem, "service", attrib=svc_attribs)

            # Occasional <script> block for deep scan fallback testing
            if not svc.product and random.random() > 0.5:
                script_kw = random.choice(["proftpd", "apache", "openssh", "samba"])
                ET.SubElement(port_elem, "script", attrib={
                    "id":     "banner",
                    "output": f"220 {script_kw} FTP server ready",
                })

    # ── <os> ──────────────────────────────────────────────────────────────────
    if tier != "dead" and os_info[0]:
        os_elem = ET.SubElement(host, "os")
        osmatch = ET.SubElement(os_elem, "osmatch", attrib={
            "name":     os_info[0],
            "accuracy": str(random.randint(85, 100)),
            "line":     str(random.randint(1, 9999)),
        })
        ET.SubElement(osmatch, "osclass", attrib={
            "type":     os_info[2],
            "vendor":   os_info[1],
            "osfamily": os_info[1],
            "accuracy": str(random.randint(85, 100)),
        })

    # ── <runstats> ────────────────────────────────────────────────────────────
    runstats = ET.SubElement(root, "runstats")
    ET.SubElement(runstats, "finished", attrib={
        "time":    now_ts,
        "timestr": datetime.now().strftime("%a %b %d %H:%M:%S %Y"),
        "elapsed": str(round(random.uniform(5.0, 45.0), 2)),
        "summary": f"Nmap done at {datetime.now().strftime('%a %b %d %H:%M:%S %Y')}",
        "exit":    "success",
    })
    hosts_up   = "0" if tier == "dead" else "1"
    hosts_down = "1" if tier == "dead" else "0"
    ET.SubElement(runstats, "hosts", attrib={
        "up": hosts_up, "down": hosts_down, "total": "1",
    })

    return root


def _pretty_xml(root: ET.Element) -> str:
    """Return indented XML string."""
    raw = ET.tostring(root, encoding="unicode")
    dom = minidom.parseString(raw)
    return dom.toprettyxml(indent="  ", encoding=None)


# ─────────────────────────────────────────────────────────────────────────────
# METADATA WRITER
# ─────────────────────────────────────────────────────────────────────────────

def _append_metadata(csv_path: Path, rows: list[dict]) -> None:
    """Append new rows to metadata.csv, creating it with headers if needed."""
    file_exists = csv_path.exists()
    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["filename", "target_name", "tier", "is_synthetic"]
        )
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate(count: int, out_dir: Path, csv_path: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata_rows = []
    tier_counts   = {t: 0 for t in TIERS}

    print(f"[+] Mangekyo Synthetic Generator")
    print(f"    Output dir : {out_dir}")
    print(f"    Count      : {count}")
    print(f"    Metadata   : {csv_path}\n")

    for i in range(count):
        ip        = _random_ip()
        tier      = _pick_tier()
        services  = _pick_services(tier)
        xml_root  = build_nmap_xml(ip, tier, services)
        xml_str   = _pretty_xml(xml_root)

        # Filename: synthetic_<tier>_<ip>_<short_uuid>.xml
        short_id  = uuid.uuid4().hex[:6]
        filename  = f"synthetic_{tier}_{ip.replace('.', '_')}_{short_id}.xml"
        filepath  = out_dir / filename

        filepath.write_text(xml_str, encoding="utf-8")

        metadata_rows.append({
            "filename":     str(filepath),
            "target_name":  f"synthetic_{tier}_{ip}",
            "tier":         tier,
            "is_synthetic": 1,          # explicit label at creation time
        })
        tier_counts[tier] += 1

        if (i + 1) % 50 == 0 or (i + 1) == count:
            print(f"    [{i+1:>3}/{count}] generated...")

    _append_metadata(csv_path, metadata_rows)

    print(f"\n[V] Done. {count} XML files written to {out_dir}")
    print(f"\n    Tier distribution:")
    for tier, n in tier_counts.items():
        bar = "█" * n + "░" * (count // 10 - n // 10)
        pct = (n / count) * 100
        print(f"      {tier:<10} {n:>4}  ({pct:4.1f}%)")
    print(f"\n    Next step: run '1_generate_ground_truth(with new api calls).py' to score all files.")
    print(f"    Make sure metadata.csv includes the new rows (it does — already appended).")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate synthetic Nmap XML training data for Project Mangekyo"
    )
    parser.add_argument(
        "--count", type=int, default=300,
        help="Number of synthetic XML files to generate (default: 300)",
    )
    parser.add_argument(
        "--out_dir", type=str, default="xml_logs/synthetic",
        help="Output directory for XML files (default: xml_logs/synthetic)",
    )
    parser.add_argument(
        "--csv", type=str, default="metadata.csv",
        help="Path to metadata.csv to append to (default: metadata.csv)",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducibility (default: None = random)",
    )
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)
        print(f"[*] Random seed set to {args.seed}")

    generate(
        count    = args.count,
        out_dir  = Path(args.out_dir),
        csv_path = Path(args.csv),
    )