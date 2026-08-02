<div align="center">

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗
╚██████╗   ██║   ██████╔╝███████╗██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝
 ██████╗ ██████╗ ███╗   ███╗███╗   ███╗ █████╗ ███╗   ██╗██████╗
██╔════╝██╔═══██╗████╗ ████║████╗ ████║██╔══██╗████╗  ██║██╔══██╗
██║     ██║   ██║██╔████╔██║██╔████╔██║███████║██╔██╗ ██║██║  ██║
██║     ██║   ██║██║╚██╔╝██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║  ██║
╚██████╗╚██████╔╝██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║██████╔╝
 ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝
 ██████╗███████╗███╗   ██╗████████╗███████╗██████╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║     █████╗  ██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║     ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
╚██████╗███████╗██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

### **AI-Powered SOC Platform — Real Threat Intel · ML Detection · APT Simulation · Honeypot**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_v14-red?style=for-the-badge)](https://attack.mitre.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![SOC](https://img.shields.io/badge/Blue_Team-SOC_Ready-cyan?style=for-the-badge)]()

*Built by **S. Srinivasan** — SOC & NOC Analyst, Chennai*

</div>

---

## ⚡ What Is This?

**CyberCommandCenter** is a single-file, fully self-contained SOC platform that runs in your terminal. No servers. No cloud. No vendor lock-in. Just Python and raw security engineering.

It combines six production-grade modules that would normally cost thousands in commercial SIEM/SOAR licenses:

| Module | What It Does |
|--------|-------------|
| 🖥 **Live SOC Dashboard** | Real-time alert feed with Rich terminal UI — severity, MITRE tactics, source IPs, block status |
| 🎯 **APT Simulator** | Generates realistic multi-stage attack chains for 6 real APT groups mapped to MITRE ATT&CK v14 |
| 🤖 **ML Anomaly Detector** | Isolation Forest (sklearn) or Z-score statistical detection on raw log streams |
| 🌐 **Threat Intel Engine** | IP reputation lookup via AbuseIPDB API + built-in IOC database fallback |
| 🍯 **Honeypot** | Multi-port TCP honeypot simulating SSH/HTTP/FTP with full attacker session logging |
| 📋 **IOC Bulk Scanner** | Scan IPs, domains, and file hashes against threat intelligence in bulk |

---

## 🚀 Quick Start

```bash
# Clone
git clone https://github.com/SRINIVASAN55/CyberCommandCenter
cd CyberCommandCenter

# Install optional deps for full features
pip install rich scikit-learn numpy

# Run full demo (no API keys needed)
python cyber_command_center.py --demo

# Launch live dashboard
python cyber_command_center.py --dashboard

# Simulate APT29 attack
python cyber_command_center.py --simulate-apt --apt-group "APT29 (Cozy Bear)" --target MyOrg

# Analyze a log file for anomalies
python cyber_command_center.py --analyze /var/log/auth.log

# Start honeypot
sudo python cyber_command_center.py --honeypot

# Interactive menu
python cyber_command_center.py
```

> **Zero dependencies for core features** — stdlib only. `rich` and `scikit-learn` are optional enhancements.

---

## 🎯 APT Simulation — MITRE ATT&CK Chains

Simulates full kill-chain attacks for real threat actor groups:

```
[SIM] APT29 (Cozy Bear) → DemoCorpInc

  [10:00:01] [CRITICAL]  Initial Access        | Phishing (T1566)
  [10:23:45] [HIGH    ]  Execution             | Command & Scripting Interpreter (T1059)
  [11:02:11] [HIGH    ]  Persistence           | Boot/Logon Autostart (T1547)
  [11:45:00] [CRITICAL]  Defense Evasion       | Indicator Removal (T1070)
  [12:10:33] [HIGH    ]  Credential Access     | OS Credential Dumping (T1003)
  [13:22:00] [CRITICAL]  Collection            | Data from Local System (T1005)
  [14:05:17] [CRITICAL]  Exfiltration          | Exfiltration Over C2 Channel (T1041)

[REPORT] HTML report saved → incidents/INC-1234567890_report.html
[REPORT] JSON report saved → incidents/INC-1234567890_report.json
```

**Supported APT Groups:**
- APT29 (Cozy Bear) — Russian SVR
- APT28 (Fancy Bear) — Russian GRU  
- Lazarus Group — North Korean RGB
- FIN7 — Financially motivated
- Sandworm — Russian GRU destructive ops
- Carbanak — Banking sector attacks

---

## 🤖 ML Anomaly Detection

```
[ML] Isolation Forest trained on 52 baseline samples

🔴 ANOMALY | score:0.847 | High authentication failure rate | Failed password for root from 185.220.101.1
🔴 ANOMALY | score:0.791 | Unusually high port diversity    | Connection refused REJECT SRC=198.20.69.74
🔴 ANOMALY | score:0.823 | Abnormal request frequency       | GET /etc/passwd 404 — 45.33.32.156
🟢 NORMAL  | score:0.112 |                                  | GET /index.html 200 192.168.1.10
```

**Feature vector (8 dimensions):**
- Requests/min, unique endpoints, error rate, avg payload size
- Failed auth rate, port diversity, bytes out, time-of-day score

Falls back to Z-score statistical detection if sklearn is not installed.

---

## 🍯 Honeypot

Simulates SSH (port 2222), HTTP (port 8080), and FTP (port 2121):

```
[HONEYPOT] 🍯 185.220.101.4:41223 → port 2222 (SSH) | 3 payloads
[HONEYPOT] 🍯 45.33.32.156:55102  → port 8080 (HTTP) | 1 payloads
[HONEYPOT] 🍯 198.20.69.74:39201  → port 2222 (SSH)  | 7 payloads
```

All sessions logged to `honeypot.jsonl` with full fingerprinting: IP, port, service, session ID, payloads, timestamp.

---

## 📊 Incident Reports

Every APT simulation auto-generates:

- **HTML Report** — Professional dark-theme incident report with MITRE chain visualization, alert table, timeline, and affected IPs
- **JSON Report** — Machine-readable full incident data for SIEM ingestion

---

## 🗂 Project Structure

```
CyberCommandCenter/
├── cyber_command_center.py   # All 6 modules — single file, ~800 lines
├── requirements.txt          # Optional dependencies
├── config.sample.json        # API key configuration template
├── incidents/                # Auto-created: HTML + JSON incident reports
└── honeypot.jsonl            # Auto-created: honeypot session log
```

---

## 🔧 Configuration

Copy `config.sample.json` to `config.json` and add your API keys for live threat intel:

```json
{
  "abuseipdb_key":  "your_key_from_abuseipdb.com",
  "virustotal_key": "your_key_from_virustotal.com",
  "honeypot_ports": [2222, 8080, 2121],
  "alert_threshold": 75,
  "analyst_name": "Your Name"
}
```

**Without API keys** — falls back to realistic simulated intel using the built-in IOC database. Everything works.

---

## 🛡 IOC Database (Built-in)

Pre-loaded with known malicious indicators:
- **IPs** — Shodan crawlers, known C2 infrastructure, Tor exit nodes
- **Domains** — C2 domains, phishing kits, ransomware payment pages  
- **Hashes** — Known malware file hashes
- **User-Agents** — Masscan, ZGrab, Go scrapers, malicious crawlers

---

## 📦 Dependencies

| Package | Purpose | Required? |
|---------|---------|-----------|
| `rich` | Beautiful terminal dashboard UI | Optional (falls back to plain text) |
| `scikit-learn` | Isolation Forest ML model | Optional (falls back to Z-score) |
| `numpy` | Array operations for ML | Optional (with sklearn) |
| *stdlib only* | Everything else | ✅ Always works |

---

## 👤 Author

**S. Srinivasan** — SOC & NOC Analyst · Chennai, India  
[LinkedIn](https://linkedin.com/in/srinivasan132) · [GitHub](https://github.com/SRINIVASAN55)

> *"The best SIEM is the one you built yourself."*

---

<div align="center">
<sub>MITRE ATT&CK® is a registered trademark of The MITRE Corporation. This project is for educational and defensive security research purposes.</sub>
</div>
