# CyberCommandCenter

> One file. No cloud. Full SOC.

A self-contained security operations platform that runs entirely from a single Python script — no mandatory pip installs, no SaaS accounts, no configuration required to start. Pop it on any machine and you have a working SOC in 10 seconds.

---

## The Problem It Solves

Most security tools require: a SIEM subscription, cloud connectivity, a running agent, or root access. CyberCommandCenter needs none of those. It's designed for the analyst who lands on an unfamiliar system and needs visibility *now*.

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.8 or higher |
| OS | Linux, macOS, Windows |
| Dependencies | None (stdlib only). Optional packages unlock extra features. |

Check your Python version:
```bash
python3 --version
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/SRINIVASAN55/CyberCommandCenter.git
cd CyberCommandCenter

# (Optional) Install packages for full features
pip install -r requirements.txt
```

Optional packages and what they unlock:

| Package | Feature unlocked |
|---------|-----------------|
| `rich` | Beautiful live terminal dashboard |
| `scikit-learn` | ML Isolation Forest anomaly detection |
| `numpy` | Numerical feature processing for ML |
| `requests` | Live AbuseIPDB threat intelligence |

---

## Running It

### Try it instantly — no setup needed
```bash
python3 cyber_command_center.py --demo
```
Runs a full walkthrough: threat intel, anomaly detection, APT simulation, IOC scan. Everything in one shot. No API keys, no config.

### Live SOC Dashboard
```bash
python3 cyber_command_center.py --dashboard
```
Opens a live terminal UI showing real-time alerts, threat feed, and analyst stats. Updates every few seconds. Press `Ctrl+C` to exit.

### Simulate an APT Attack
```bash
# Simulate a specific APT group
python3 cyber_command_center.py --simulate-apt --apt-group apt29

# Simulate against a named target org
python3 cyber_command_center.py --simulate-apt --apt-group apt28 --target "ACME Corp"
```

Available APT groups: `apt28`, `apt29`, `apt41`, `lazarus`, `apt34`, `sandworm`

Generates an HTML report + JSON timeline in the current directory.

### Start a Honeypot
```bash
python3 cyber_command_center.py --honeypot
```
Listens on ports 22 (SSH), 80 (HTTP), 21 (FTP). Logs every connection with attacker IP, banner grab, and session data to `honeypot_sessions.jsonl`.

### Analyze a Log File for Anomalies
```bash
python3 cyber_command_center.py --analyze /var/log/auth.log
python3 cyber_command_center.py --analyze /var/log/syslog
python3 cyber_command_center.py --analyze myapp.log
```
Trains a baseline from the first portion of the file, then flags anomalous lines with an explanation of *why* they look suspicious.

---

## Configuration (Optional)

```bash
cp config.sample.json config.json
```

Edit `config.json`:
```json
{
  "abuseipdb_key":  "get free key at abuseipdb.com/api",
  "virustotal_key": "get free key at virustotal.com",
  "honeypot_ports": [22, 80, 21, 443, 8080],
  "alert_threshold": 75,
  "analyst_name": "Your Name"
}
```
All fields are optional — the tool works without any API keys.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'rich'`**
→ Run `pip install rich` or use `--demo` which works without it.

**Honeypot says "Permission denied" on port 22**
→ Ports below 1024 need root on Linux: `sudo python3 cyber_command_center.py --honeypot`

**Dashboard looks broken / garbled**
→ Your terminal doesn't support Rich. Try a modern terminal (iTerm2, Windows Terminal, GNOME Terminal).

---

## What's Inside

**Threat Intel Engine** — checks IPs against AbuseIPDB and a local IOC database (known-bad IPs, domains, file hashes, user-agents). Works offline with the built-in dataset; plugs into live feeds when you have an API key.

**ML Anomaly Detector** — trains a baseline from your logs, then flags deviations using Isolation Forest. Falls back to Z-score statistics if sklearn isn't available. Explains *why* something looks anomalous.

**APT Simulator** — replays kill chains for APT28, APT29, APT41, Lazarus, APT34, and Sandworm across all 11 MITRE ATT&CK tactics. Outputs HTML and JSON reports.

**Honeypot** — listens on configurable ports, pretends to be SSH/HTTP/FTP, logs every connection with attacker fingerprint data.

**SOC Dashboard** — live terminal UI showing alerts, stats, and threat feed in real time.

---

## APT Groups & MITRE Coverage

| Group | Nation | Specialty |
|-------|--------|-----------|
| APT28 (Fancy Bear) | Russia | Credential theft, spearphishing |
| APT29 (Cozy Bear) | Russia | Supply chain, C2, exfiltration |
| APT41 (Double Dragon) | China | Espionage + financial crime |
| Lazarus (Hidden Cobra) | North Korea | Ransomware, bank heists |
| APT34 (OilRig) | Iran | DNS tunneling, long-term access |
| Sandworm (Voodoo Bear) | Russia | ICS/SCADA destruction |

All 11 ATT&CK tactics: `Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration`

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
