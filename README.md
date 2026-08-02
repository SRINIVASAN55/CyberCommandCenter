# CyberCommandCenter

> One file. No cloud. Full SOC.

A self-contained security operations platform that runs entirely from a single Python script — no mandatory pip installs, no SaaS accounts, no configuration required to start. Pop it on any machine and you have a working SOC in 10 seconds.

---

## The Problem It Solves

Most security tools require: a SIEM subscription, cloud connectivity, a running agent, or root access. CyberCommandCenter needs none of those. It's designed for the analyst who lands on an unfamiliar system and needs visibility *now*.

---

## What's Inside

**Threat Intel Engine** — checks IPs against AbuseIPDB and a local IOC database (known-bad IPs, domains, file hashes, user-agents). Works offline with the built-in dataset; plugs into live feeds when you have an API key.

**ML Anomaly Detector** — trains a baseline from your logs, then flags deviations using Isolation Forest. If sklearn isn't available it falls back to Z-score statistics. Either way it tells you *why* something looks anomalous.

**APT Simulator** — replays kill chains for APT28, APT29, APT41, Lazarus, APT34, and Sandworm across all 11 MITRE ATT&CK tactics. Outputs HTML and JSON reports you can hand to a client or drop in a ticket.

**Honeypot** — listens on configurable ports, pretends to be SSH/HTTP/FTP, logs every connection with attacker fingerprint data.

**SOC Dashboard** — live terminal UI showing alerts, stats, and threat feed in real time.

---

## Quickstart

```bash
git clone https://github.com/SRINIVASAN55/CyberCommandCenter
cd CyberCommandCenter
python cyber_command_center.py --demo          # works with zero deps
python cyber_command_center.py --dashboard     # live SOC view
python cyber_command_center.py --simulate-apt --apt-group apt29
python cyber_command_center.py --honeypot
python cyber_command_center.py --analyze /var/log/auth.log
```

Optional: `pip install rich scikit-learn numpy requests` for the full experience.

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

All 11 ATT&CK tactics covered: `Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration`

---

## Config

```bash
cp config.sample.json config.json
# Add your AbuseIPDB / VirusTotal keys — both optional
```

---

## Requirements

None to start. `requirements.txt` lists optional packages that unlock ML detection and live threat feeds.

---

**Author:** S. Srinivasan · [GitHub](https://github.com/SRINIVASAN55) · [LinkedIn](https://linkedin.com/in/srinivasan132)
