<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██████╗ ██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║     ██║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║     ██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚██████╗╚██████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝ ╚═════╝
```

# 🛡️ CyberCommandCenter

**AI-Powered Security Operations Platform**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red?style=for-the-badge)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/SRINIVASAN55/CyberCommandCenter?style=for-the-badge&color=yellow)](https://github.com/SRINIVASAN55/CyberCommandCenter)

*A single-file, zero-dependency SOC platform for threat hunting, anomaly detection, and APT simulation*

</div>

---

## 🚀 What is CyberCommandCenter?

CyberCommandCenter is a **production-grade Security Operations Center (SOC) platform** built entirely in Python. It combines real-time threat intelligence, ML-powered anomaly detection, MITRE ATT&CK simulation, and an interactive honeypot — all in a single file with no mandatory dependencies.

Built for: **Security Analysts · Penetration Testers · SOC Teams · Blue Team Defenders**

---

## ✨ Features

| Module | Description |
|--------|-------------|
| 🔍 **Threat Intel Engine** | Real-time IP reputation via AbuseIPDB, local IOC database (IPs, domains, hashes, user-agents), bulk lookup with caching |
| 🤖 **ML Anomaly Detector** | Isolation Forest (sklearn) with Z-score fallback, 8-feature log vector, auto-baseline training, explainable alerts |
| 🎯 **APT Simulator** | 6 APT groups, 11 MITRE ATT&CK v14 tactics, full kill-chain simulation, HTML + JSON reports |
| 🍯 **TCP Honeypot** | Multi-service simulation (SSH/HTTP/FTP), attacker fingerprinting, JSONL session logging |
| 📊 **SOC Dashboard** | Rich terminal Live layout, real-time alerts, color-coded severity, analyst workflow |
| 🔎 **IOC Scanner** | Bulk IOC scanning across IPs, domains, file hashes, user-agents |

---

## ⚡ Quick Start

```bash
# Clone the repo
git clone https://github.com/SRINIVASAN55/CyberCommandCenter.git
cd CyberCommandCenter

# Run with no dependencies (stdlib only)
python cyber_command_center.py --demo

# Install optional packages for full features
pip install -r requirements.txt

# Launch live SOC dashboard
python cyber_command_center.py --dashboard

# Simulate APT attack (e.g. APT29 Cozy Bear)
python cyber_command_center.py --simulate-apt --apt-group apt29

# Start honeypot on ports 22, 80, 21
python cyber_command_center.py --honeypot

# Analyze a log file for anomalies
python cyber_command_center.py --analyze /var/log/auth.log
```

---

## 🎯 APT Groups Supported

| Group | Alias | Nation | Tactics |
|-------|-------|--------|---------|
| APT28 | Fancy Bear | Russia 🇷🇺 | Spearphishing → Credential Dump → Lateral Movement |
| APT29 | Cozy Bear | Russia 🇷🇺 | Supply Chain → C2 → Data Exfiltration |
| APT41 | Double Dragon | China 🇨🇳 | Watering Hole → Persistence → Espionage |
| Lazarus | Hidden Cobra | North Korea 🇰🇵 | Ransomware → Financial Theft |
| APT34 | OilRig | Iran 🇮🇷 | DNS Tunneling → Long-term Access |
| Sandworm | Voodoo Bear | Russia 🇷🇺 | ICS/SCADA → Infrastructure Attacks |

---

## 🧠 MITRE ATT&CK Coverage

```
Initial Access → Execution → Persistence → Privilege Escalation →
Defense Evasion → Credential Access → Discovery → Lateral Movement →
Collection → Command & Control → Exfiltration
```

All 11 tactics mapped. Each simulated attack generates technique IDs (e.g. `T1566.001`, `T1059.003`) with real-world APT attribution.

---

## 📁 Project Structure

```
CyberCommandCenter/
├── cyber_command_center.py   # Main platform (single file, ~800 lines)
├── requirements.txt          # Optional dependencies
├── config.sample.json        # API key configuration template
└── README.md                 # This file
```

---

## 🔧 Configuration

```bash
cp config.sample.json config.json
# Edit config.json and add your API keys:
# - abuseipdb_key: Get free key at https://www.abuseipdb.com/api
# - virustotal_key: Get free key at https://www.virustotal.com/gui/join-us
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│              CyberCommandCenter              │
├──────────┬──────────┬───────────┬───────────┤
│  Threat  │ Anomaly  │    APT    │ Honeypot  │
│  Intel   │ Detector │ Simulator │           │
│  Engine  │ (ML/IsoF)│ (MITRE)  │ (TCP/Multi│
│          │          │           │  service) │
├──────────┴──────────┴───────────┴───────────┤
│         SOC Dashboard (Rich Terminal UI)     │
├─────────────────────────────────────────────┤
│   IOC Scanner │ Report Generator │ CLI Args  │
└─────────────────────────────────────────────┘
```

---

## 📊 Sample Output

```
╔══════════════════════════════════════════════╗
║  🛡️  CYBER COMMAND CENTER  |  SOC DASHBOARD  ║
╠══════════════════════════════════════════════╣
║  Threats Detected: 7   Anomalies: 3          ║
║  Intel Lookups: 142    IOCs Blocked: 29      ║
╠══════════════════════════════════════════════╣
║  [CRITICAL] 185.220.101.45 — TOR exit node  ║
║  [HIGH]     Brute force: 847 attempts/min    ║
║  [MEDIUM]   Lateral movement: SMB detected   ║
╚══════════════════════════════════════════════╝
```

---

## 🤝 Contributing

PRs welcome! Open an issue first for major changes.

---

## 👤 Author

**S. Srinivasan** — Security Researcher & Developer
- GitHub: [@SRINIVASAN55](https://github.com/SRINIVASAN55)
- LinkedIn: [srinivasan132](https://linkedin.com/in/srinivasan132)

---

<div align="center">

⭐ **Star this repo if you find it useful!** ⭐

*Built with ❤️ for the blue team community*

</div>