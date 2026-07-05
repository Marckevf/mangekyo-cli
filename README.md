# mangekyo-cli

Attack surface reconnaissance and ML risk scoring.

Mangekyo takes an Nmap scan, enriches every open port against NVD, EPSS, CISA KEV, and MITRE ATT&CK, runs the results through a trained Random Forest, and hands you a prioritized, explainable risk score for every host — in seconds, for free, with no black boxes.

> **Mangekyo reports confirmed threat data, not breach predictions.** Every score is built from authoritative sources: NVD CVSSv3, EPSS exploitation probability, CISA KEV confirmed-in-the-wild status, and MITRE ATT&CK technique mappings. The ML layer aggregates and explains those signals. It does not predict whether a host will be breached.

---

## What it does

- Scans a target with Nmap or ingests an existing Nmap XML file
- Queries NVD for CVSSv3 scores on every detected service version
- Enriches each CVE with EPSS (exploitation probability from [FIRST.org](https://www.first.org/epss/)) and CISA KEV (confirmed exploitation in the wild from [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog))
- Maps CVEs to MITRE ATT&CK techniques via a three-tier mapper: direct STIX bundle lookup → curated KEV supplement → CWE fallback via live NVD
- Scores each host 0–100 using a Random Forest surrogate model (R² 0.9963 on real-on-real 5-fold CV)
- Explains each score with SHAP — which signals drove the risk and by how much
- Applies optional YAML-defined policy rules on top of the model score (never replacing it)
- Outputs a terminal table or clean JSON for downstream pipelines

---

## Prerequisites

- Python 3.11+
- [Nmap](https://nmap.org/download.html) installed and on your PATH
- An [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (free, takes ~30 seconds to request)

---

## Installation

### Docker (recommended for Windows/Linux)

> **Mac users:** native install (below) is recommended over Docker for live scanning (`scan` and `explain`). Docker on Mac runs Linux containers inside a VM, which adds an extra layer of network overhead on top of whatever your network already imposes.

```bash
docker pull ghcr.io/marckevf/mangekyo-cli:latest
docker run --rm -it \
  -e NVD_API_KEY=your_key_here \
  -v ~/.mangekyo:/root/.mangekyo \
  ghcr.io/marckevf/mangekyo-cli:latest \
  mangekyo explain 45.33.32.156
```

The volume mount persists your NVD cache and config between runs. `model.pkl` is baked into the image — no separate download needed.

Multi-platform image (linux/amd64, linux/arm64) — tested and confirmed working on Windows and on Apple Silicon (M-series) Mac via both Docker and native install.

### From source

```bash
git clone https://github.com/Marckevf/mangekyo-cli
cd mangekyo-cli

# Mac/Linux
python -m venv venv && source venv/bin/activate

# Windows
python -m venv venv && venv\Scripts\activate

pip install -e .
```

Copy `.env.example` to `.env` and add your NVD API key:

```
NVD_API_KEY=your_key_here
```

Download `model.pkl` from the [latest GitHub Release](https://github.com/Marckevf/mangekyo-cli/releases/latest) and place it in the project root.

---

## Usage

### `mangekyo scan`

Run a live Nmap scan and score every host immediately.

```bash
mangekyo scan 192.168.1.0/24
mangekyo scan example.com --top 5
mangekyo scan 10.0.0.1 --output json
```

### `mangekyo score`

Score an existing Nmap XML file. Use this when you already have scan output or need to run Nmap separately with custom flags or elevated privileges.

```bash
mangekyo score scan.xml
mangekyo score scan.xml --top 10 --all-cves
mangekyo score scan.xml --output json > results.json
```

### `mangekyo explain`

Run a live Nmap scan against a single host and produce a full risk breakdown — CVEs with port attribution, SHAP drivers, ATT&CK techniques, and confidence breakdown.

```bash
mangekyo explain 45.33.32.156
mangekyo explain scanme.nmap.org --all-cves

# Explain from an existing XML file instead of scanning live
mangekyo explain --from-xml scan.xml 45.33.32.156
```

---

## Flags

| Flag | Commands | Description |
|------|----------|-------------|
| `--output json` | scan, score | Machine-readable JSON output |
| `--top N` | scan, score | Show only the N highest-risk hosts |
| `--no-color` | all | Plain text output, no ANSI codes |
| `--all-cves` | score, explain | Show all CVEs instead of top 10 by EPSS |
| `--version-intensity {0-9}` | scan, explain | Nmap service detection intensity (default: 5). Higher values are slower but more likely to succeed when scan conditions are unfavorable. |
| `--from-xml FILE` | explain | Load host from existing Nmap XML instead of scanning live |
| `--version` | — | Print version and exit |

---

## Output

### Terminal (default)

```
HOST              RISK    TIER      CONFIDENCE    OPEN PORTS
45.33.32.156      100.0   CRITICAL  HIGH (90)     22,80,9929,31337
192.168.1.105     74.0    HIGH      MEDIUM (61)   22,80,443
192.168.1.1       31.0    LOW       HIGH (88)     22,80

Scanned 3 host(s)  |  CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 1  |  12s
```

### Risk tiers

| Tier | Score range |
|------|-------------|
| CRITICAL | 90–100 |
| HIGH | 70–89 |
| MEDIUM | 40–69 |
| LOW | 0–39 |

### Confidence scoring

Every host receives a confidence score (0–100) broken into three sub-scores that degrade dynamically based on data quality:

| Sub-score | Max | What it measures |
|---|---|---|
| CPE Match | 30 | Whether all services were identified with a valid CPE string |
| Threat Intel | 50 | Whether NVD and EPSS returned data for all CPEs |
| Version Data | 20 | Whether Nmap detected version strings for all services |

Warnings appear inline when coverage is poor, so you always know how much to trust the score.

### `mangekyo explain` detail

```
HOST: 45.33.32.156 (scanme.nmap.org)

RISK SCORE  : 100.0  CRITICAL
CONFIDENCE  : HIGH (90/100)
              CPE Match    30/30
              Threat Intel 50/50
              Version Data 10/20  — Partial version coverage — CVE matches broader than ideal.

OPEN PORTS  : 22,80,123,31337
TOP SIGNALS : KEV + EPSS 100.0 + NVD 9.8

RISK DRIVERS
  [+17.7]  max_epss_score        Exploitation probability 100.0 — actively exploited in the wild
  [+16.4]  max_nvd_score         Max CVSS 9.8 — critical severity
  [+2.1 ]  kev_port_count        4 ports have CISA KEV-confirmed CVEs
  [+1.3 ]  mean_nvd_score        Average CVSS 4.9 across all services
  [+0.6 ]  unique_service_count  3 distinct services detected

CVES FOUND: 120 total  (showing top 10 by exploitation probability)
----------------------------------------------------
CVE-2021-40438  [KEV ✓  EPSS 100.0]  → 80/tcp
CVE-2024-38475  [KEV ✓  EPSS 100.0]  → 80/tcp
CVE-2021-44790  [EPSS 97.1]  → 80/tcp
...
+ 110 lower-priority CVEs not shown  (use --all-cves to see complete list)

ATT&CK MAPPINGS  (8 of 120 CVEs mapped)
----------------------------------------------------
Initial Access
  T1190  Exploit Public-Facing Application  [Tier 2]
         CVE-2021-40438  [KEV ✓  EPSS 100.0]
         Mitigations: M1016, M1026, M1030, M1035, M1037

Privilege Escalation
  T1068  Exploitation for Privilege Escalation  [Tier 3 (CWE-787 Out-of-bounds Write)]
         CVE-2006-20001  [EPSS 3.5]
         Mitigations: M1019, M1038, M1048, M1050, M1051
```

### JSON output

```json
{
  "hosts": [
    {
      "host": "45.33.32.156",
      "risk_score": 100.0,
      "tier": "CRITICAL",
      "confidence": "HIGH",
      "confidence_score": 90,
      "open_ports": [22, 80, 9929, 31337],
      "cve_count": 120,
      "cve_by_port": {
        "80/tcp": ["CVE-2021-40438", "CVE-2024-38475", "..."],
        "22/tcp": ["CVE-2023-38408", "..."]
      },
      "top_signals": ["KEV + EPSS 100.0 + NVD 9.8"],
      "shap_top": [
        {"feature": "max_epss_score", "shap": 17.7, "value": 100.0, "direction": "up"},
        {"feature": "max_nvd_score",  "shap": 16.4, "value": 9.8,   "direction": "up"}
      ],
      "attack_techniques": [
        {"cve_id": "CVE-2021-40438", "technique_id": "T1190",
         "technique_name": "Exploit Public-Facing Application", "tactic": "Initial Access"}
      ],
      "policy_override": null
    }
  ],
  "summary": {
    "total_hosts": 1,
    "tier_counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "highest_risk": {"host": "45.33.32.156", "risk_score": 100.0, "tier": "CRITICAL"}
  }
}
```

When confidence is low and coverage is thin (see Networking notes above), JSON output includes an additional `scan_quality_note` field explaining the likely cause and suggesting next steps. This field is omitted entirely when coverage is sufficient.

```json
{
  "confidence_score": 0,
  "scan_quality_note": "Low confidence may reflect scan conditions (network variability or target-side rate limiting) rather than a genuinely low-risk host. Consider re-running the scan or trying --version-intensity 7-9."
}
```

---

## Policy rules (`mangekyo.yaml`)

Create a `mangekyo.yaml` in the project root to define custom risk rules. Rules apply **after** the model scores — they never modify the underlying risk score, only the displayed tier.

```yaml
rules:
  - name: "RDP always critical"
    type: force_tier
    port: 3389
    tier: CRITICAL

  - name: "Any database exposed"
    type: min_tier
    service: mysql
    tier: HIGH

  - name: "Suppress internal monitoring"
    type: suppress
    cidr: 10.0.0.0/8

performance:
  max_tier3_mappings: 5   # Max live NVD CWE lookups per run (default: 5)
```

When a rule fires, the output records what changed and why: `policy_override: {rule: 'RDP always critical', original_tier: 'HIGH', forced_tier: 'CRITICAL'}`.

---

## Performance

| Scenario | Time |
|----------|------|
| First run, cold cache | 22–85 seconds (NVD-dependent) |
| Warm cache | ~10 seconds |

Cold-cache time is driven by NVD API latency on uncached CPEs — NVD server-side query time for some CPEs exceeds 10 seconds regardless of client configuration. Subsequent runs on the same CPEs hit the local SQLite cache (7-day TTL) and are near-instant.

**Without an NVD API key**, requests are rate-limited to 5 per 30 seconds (vs 50 with a key). Runs on CVE-heavy targets will be significantly slower. Get a free key at [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key).

---

## Networking notes

Live scanning (`scan` and `explain`) depends on Nmap getting timely responses from the target for each service-detection probe it sends. Against any live target — especially shared public test hosts like `scanme.nmap.org` — this can vary run to run due to network conditions, target-side rate limiting, or aggressive scan timing (`-T4`).

In testing, identical commands against the same target produced different results across repeated runs: sometimes full service versions and CVE data, sometimes zero identified services. This is expected behavior for active network scanning against a shared, publicly-scanned target — not a bug in Mangekyo. When it happens, Mangekyo's confidence layer reports it honestly (low confidence, thin coverage warnings) rather than presenting an uncertain result as a confirmed finding.

If you see `CPE Match 0/30` or a low Version Data score along with a `[!] Some services could not be identified` warning:

```bash
mangekyo explain <target> --version-intensity 7
```

Start at 7 rather than jumping to 9 — higher intensity sends more probes, which helps when conditions are unfavorable, but is also significantly slower. If results are still inconsistent, try re-running the scan, or use `--from-xml` with a scan file generated separately.

This is a general characteristic of active network scanning, not specific to Mangekyo — it affects any tool built on Nmap.

---

## Threat intelligence sources

| Source | What it provides | How it's used |
|--------|-----------------|---------------|
| [NVD](https://nvd.nist.gov/) | CVSSv3 severity scores | 60% of formula weight; cached locally (7-day TTL) |
| [FIRST.org EPSS](https://www.first.org/epss/) | Exploitation probability (0–1) | 20% of formula weight |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed-in-the-wild exploitation | +15.0 bonus per KEV CVE on host |
| [MITRE ATT&CK](https://attack.mitre.org/) | Adversary technique mapping | Three-tier mapper: STIX → KEV supplement → CWE fallback |

---

## How the model works

Mangekyo uses a **Random Forest surrogate model** — a model trained to reproduce a deterministic four-signal scoring formula:

```
risk = (nvd_risk × 0.60) + (base_risk × 0.15) + (epss × 0.20) + (kev_bonus × 15.0)
```

The model learns this formula from 17,113 labeled training rows. R² 0.9963 means it reproduces the formula with near-perfect fidelity. On a held-out test set the model scores R² 0.9975. It does not mean 99.63% of hosts scored CRITICAL will be breached.

The ML layer exists so SHAP can explain which signals drove each score. Without it, the tool would be a weighted sum with no explainability. With it, you see exactly which feature moved the needle and by how much.

All signals come from authoritative sources. Nothing is invented.

---

## Environment variables

| Variable | Description |
|---|---|
| `NVD_API_KEY` | NVD API key — increases rate limit from 5 to 50 req/30s. If the key is invalid or deactivated, Mangekyo prints a clear warning and automatically falls back to unauthenticated NVD access rather than silently returning incomplete results. |
| `MANGEKYO_HOME` | Override the data directory (model, caches, config) |
| `MANGEKYO_DEBUG` | Set to `1` for full tracebacks on errors |

---

## License

MIT — see [LICENSE](LICENSE).

---

*For my cousin, Tony Chery. With love.*
