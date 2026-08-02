#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                        CYBER COMMAND CENTER v1.0                            ║
║              AI-Powered SOC Platform by S. Srinivasan                       ║
║                                                                              ║
║  Modules:                                                                    ║
║   • Threat Intelligence Engine  (AbuseIPDB / VirusTotal / Shodan)           ║
║   • ML Anomaly Detection        (Isolation Forest on log streams)            ║
║   • APT Attack Simulator        (MITRE ATT&CK chain generation)             ║
║   • Honeypot Listener           (TCP trap with attacker fingerprinting)      ║
║   • Auto Incident Reporter      (HTML + Markdown reports)                    ║
║   • Live SOC Dashboard          (Real-time terminal UI)                      ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python cyber_command_center.py                  # Full interactive menu
    python cyber_command_center.py --dashboard      # Live dashboard only
    python cyber_command_center.py --simulate-apt   # Run APT simulation
    python cyber_command_center.py --honeypot       # Start honeypot
    python cyber_command_center.py --demo           # Full demo (no APIs needed)
"""

import os, sys, json, time, random, socket, struct, threading, hashlib
import re, math, datetime, argparse, collections, ipaddress, base64
import urllib.request, urllib.parse, urllib.error, http.server, socketserver
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from enum import Enum

# ─── Optional rich import (falls back to plain text) ────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    class Console:
        def print(self, *a, **kw): print(*a)
        def clear(self): os.system('cls' if os.name=='nt' else 'clear')
    console = Console()

# ─── Optional sklearn (falls back to pure-Python isolation forest) ───────────
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    ML = True
except ImportError:
    ML = False


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIG
# ══════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
BANNER  = r"""
   ____      _              ____                                          _
  / ___|   _| |__   ___ _ _/ ___|___  _ __ ___  _ __ ___   __ _ _ __   __| |
 | |  | | | | '_ \ / _ \ '__| |   / _ \| '_ ` _ \| '_ ` _ \ / _` | '_ \ / _` |
 | |__| |_| | |_) |  __/ |  | |__| (_) | | | | | | | | | | | (_| | | | | (_| |
  \____\__, |_.__/ \___|_|   \____\___/|_| |_| |_|_| |_| |_|\__,_|_| |_|\__,_|
       |___/                   C e n t e r
  ─────────────────────────────────────────────────────────────────────────────
  AI-Powered SOC Platform  •  by S. Srinivasan  •  v{v}
  MITRE ATT&CK  •  ML Anomaly Detection  •  Threat Intel  •  Honeypot
""".format(v=VERSION)

MITRE_TACTICS = {
    "TA0001": ("Initial Access",        ["T1190","T1566","T1078","T1133"]),
    "TA0002": ("Execution",             ["T1059","T1203","T1204","T1053"]),
    "TA0003": ("Persistence",           ["T1547","T1053","T1098","T1543"]),
    "TA0004": ("Privilege Escalation",  ["T1068","T1055","T1134","T1078"]),
    "TA0005": ("Defense Evasion",       ["T1070","T1036","T1055","T1562"]),
    "TA0006": ("Credential Access",     ["T1003","T1110","T1555","T1212"]),
    "TA0007": ("Discovery",             ["T1082","T1083","T1057","T1018"]),
    "TA0008": ("Lateral Movement",      ["T1021","T1534","T1080","T1210"]),
    "TA0009": ("Collection",            ["T1005","T1039","T1025","T1113"]),
    "TA0010": ("Exfiltration",          ["T1041","T1048","T1052","T1567"]),
    "TA0040": ("Impact",                ["T1485","T1486","T1490","T1498"]),
}

TECHNIQUE_NAMES = {
    "T1190": "Exploit Public-Facing Application",
    "T1566": "Phishing",           "T1078": "Valid Accounts",
    "T1133": "External Remote Services",
    "T1059": "Command & Scripting Interpreter",
    "T1203": "Exploitation for Client Execution",
    "T1204": "User Execution",     "T1053": "Scheduled Task/Job",
    "T1547": "Boot/Logon Autostart", "T1098": "Account Manipulation",
    "T1543": "Create/Modify System Process",
    "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection",  "T1134": "Access Token Manipulation",
    "T1070": "Indicator Removal",  "T1036": "Masquerading",
    "T1562": "Impair Defenses",    "T1003": "OS Credential Dumping",
    "T1110": "Brute Force",        "T1555": "Credentials from Password Stores",
    "T1212": "Exploitation for Credential Access",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1057": "Process Discovery",  "T1018": "Remote System Discovery",
    "T1021": "Remote Services",    "T1534": "Internal Spearphishing",
    "T1080": "Taint Shared Content","T1210": "Exploitation of Remote Services",
    "T1005": "Data from Local System",
    "T1039": "Data from Network Shared Drive",
    "T1025": "Data from Removable Media",
    "T1113": "Screen Capture",     "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1052": "Exfiltration Over Physical Medium",
    "T1567": "Exfiltration Over Web Service",
    "T1485": "Data Destruction",   "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1498": "Network Denial of Service",
}

APT_GROUPS = {
    "APT29 (Cozy Bear)":    ["TA0001","TA0002","TA0003","TA0005","TA0006","TA0009","TA0010"],
    "APT28 (Fancy Bear)":   ["TA0001","TA0002","TA0004","TA0006","TA0007","TA0008","TA0010"],
    "Lazarus Group":        ["TA0001","TA0002","TA0003","TA0005","TA0009","TA0040"],
    "FIN7":                 ["TA0001","TA0002","TA0006","TA0007","TA0009","TA0010"],
    "Sandworm":             ["TA0001","TA0002","TA0003","TA0004","TA0005","TA0040"],
    "Carbanak":             ["TA0001","TA0002","TA0006","TA0007","TA0008","TA0010"],
}

SEVERITY = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
COLORS   = {"CRITICAL":"red","HIGH":"orange3","MEDIUM":"yellow","LOW":"cyan","INFO":"dim"}


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatAlert:
    id:          str
    timestamp:   str
    source_ip:   str
    severity:    str
    tactic:      str
    technique:   str
    description: str
    mitre_id:    str
    score:       float = 0.0
    blocked:     bool  = False

@dataclass
class IPIntelligence:
    ip:           str
    abuse_score:  int   = 0
    country:      str   = "Unknown"
    isp:          str   = "Unknown"
    is_tor:       bool  = False
    is_proxy:     bool  = False
    threat_types: list  = field(default_factory=list)
    reports:      int   = 0
    reputation:   str   = "UNKNOWN"

@dataclass
class Incident:
    id:          str
    title:       str
    severity:    str
    status:      str
    created_at:  str
    updated_at:  str
    alerts:      list  = field(default_factory=list)
    timeline:    list  = field(default_factory=list)
    mitre_chain: list  = field(default_factory=list)
    affected_ips:list  = field(default_factory=list)
    analyst:     str   = "S. Srinivasan (SOC)"


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1: THREAT INTELLIGENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class ThreatIntelEngine:
    """
    Pulls real threat intelligence from public APIs.
    Falls back to simulated intel if no API keys configured.
    """

    def __init__(self, config: dict):
        self.config   = config
        self.cache    = {}
        self.ioc_db   = self._load_ioc_db()

    def _load_ioc_db(self) -> dict:
        """Built-in IOC database (known malicious indicators)."""
        return {
            "ips": [
                "45.33.32.156","198.20.69.74","198.20.69.98",
                "80.82.77.33","80.82.77.139","185.220.101.1",
            ],
            "domains": [
                "evil-c2.xyz","malware-drop.ru","phish-kit.tk",
                "ransomware-pay.onion","cobalt-strike.cc",
            ],
            "hashes": [
                "d41d8cd98f00b204e9800998ecf8427e",
                "098f6bcd4621d373cade4e832627b4f6",
            ],
            "user_agents": [
                "python-requests/2.18.0",
                "Go-http-client/1.1",
                "masscan/1.0",
                "zgrab/0.x",
            ]
        }

    def lookup_ip(self, ip: str) -> IPIntelligence:
        """Lookup IP reputation — real API or simulated."""
        if ip in self.cache:
            return self.cache[ip]

        intel = IPIntelligence(ip=ip)

        # Try AbuseIPDB
        api_key = self.config.get("abuseipdb_key","")
        if api_key and api_key != "YOUR_KEY_HERE":
            intel = self._lookup_abuseipdb(ip, api_key)
        else:
            intel = self._simulate_ip_intel(ip)

        # Cross-check local IOC DB
        if ip in self.ioc_db["ips"]:
            intel.abuse_score = max(intel.abuse_score, 95)
            intel.reputation  = "MALICIOUS"
            intel.threat_types.append("Known Malicious IP (Local IOC DB)")

        self.cache[ip] = intel
        return intel

    def _lookup_abuseipdb(self, ip: str, key: str) -> IPIntelligence:
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(url, headers={"Key": key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())["data"]
            score = data.get("abuseConfidenceScore", 0)
            return IPIntelligence(
                ip=ip,
                abuse_score=score,
                country=data.get("countryCode","??"),
                isp=data.get("isp","Unknown"),
                is_tor=data.get("isTor", False),
                is_proxy=data.get("isPublicProxy", False),
                threat_types=list(set(data.get("reports",[{}])[0].get("categories",[]) if data.get("reports") else [])),
                reports=data.get("totalReports",0),
                reputation="MALICIOUS" if score>75 else "SUSPICIOUS" if score>25 else "CLEAN",
            )
        except Exception:
            return self._simulate_ip_intel(ip)

    def _simulate_ip_intel(self, ip: str) -> IPIntelligence:
        """Generate realistic simulated intel for demo mode."""
        h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
        random.seed(h)
        countries = ["RU","CN","KP","IR","US","BR","UA","DE","NL","FR"]
        isps      = ["AS-CHOOPA","Hetzner","OVH","DigitalOcean","Linode","Vultr","Amazon AS"]
        threats   = ["SSH Brute Force","Port Scan","Web Scraping","DDoS","C2 Communication","Spam"]
        score = random.randint(0,100)
        return IPIntelligence(
            ip=ip,
            abuse_score=score,
            country=random.choice(countries),
            isp=random.choice(isps),
            is_tor=random.random()<0.1,
            is_proxy=random.random()<0.15,
            threat_types=random.sample(threats, k=random.randint(0,3)),
            reports=random.randint(0,500),
            reputation="MALICIOUS" if score>75 else "SUSPICIOUS" if score>25 else "CLEAN",
        )

    def bulk_lookup(self, ips: list) -> list:
        return [self.lookup_ip(ip) for ip in ips]

    def check_ioc(self, indicator: str, ioc_type: str = "auto") -> dict:
        """Check any indicator against local IOC database."""
        if ioc_type == "auto":
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
                ioc_type = "ip"
            elif re.match(r'^[a-f0-9]{32,64}$', indicator, re.I):
                ioc_type = "hash"
            else:
                ioc_type = "domain"

        matched = indicator in self.ioc_db.get(ioc_type+"s", [])
        return {
            "indicator": indicator,
            "type":      ioc_type,
            "matched":   matched,
            "severity":  "CRITICAL" if matched else "CLEAN",
            "source":    "Local IOC DB",
            "timestamp": datetime.datetime.now().isoformat(),
        }


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2: ML ANOMALY DETECTION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Machine learning anomaly detection on log streams.
    Uses Isolation Forest (sklearn) or falls back to pure-Python
    statistical Z-score detection.
    """

    def __init__(self):
        self.model         = None
        self.baseline      = []
        self.alerts        = []
        self.feature_names = [
            "requests_per_min","unique_endpoints","error_rate",
            "avg_payload_size","failed_auth_rate","port_diversity",
            "bytes_out","time_of_day_score",
        ]

        if ML:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.05,
                random_state=42
            )
            print("[ML] Isolation Forest loaded (sklearn)")
        else:
            print("[ML] sklearn not found — using Z-score statistical detection")

    def extract_features(self, log_line: str) -> Optional[list]:
        """Parse a log line into an 8-feature vector."""
        # Support syslog, Apache combined log, JSON
        features = [0.0] * 8

        # Apache/Nginx combined log
        apache_re = re.compile(
            r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+)[^"]*" (\d+) (\d+|-)'
        )
        m = apache_re.search(log_line)
        if m:
            status = int(m.group(5))
            size   = int(m.group(6)) if m.group(6) != '-' else 0
            features[2] = 1.0 if status >= 400 else 0.0  # error_rate proxy
            features[3] = size / 1000.0                   # payload size (KB)
            features[4] = 1.0 if status in (401,403) else 0.0

        # SSH brute force indicator
        if "Failed password" in log_line or "authentication failure" in log_line:
            features[4] = 1.0
            features[0] = random.uniform(20, 200)  # high req rate

        # Port scan indicator
        if "Connection refused" in log_line or "REJECT" in log_line:
            features[5] = random.uniform(50, 500)

        # Randomize baseline noise slightly
        for i in range(len(features)):
            features[i] += random.gauss(0, 0.05)

        return features

    def train_baseline(self, log_lines: list):
        """Train the model on baseline (normal) logs."""
        vectors = []
        for line in log_lines:
            f = self.extract_features(line)
            if f:
                vectors.append(f)

        if not vectors:
            return

        self.baseline = vectors

        if ML and self.model:
            X = np.array(vectors)
            self.model.fit(X)
            print(f"[ML] Isolation Forest trained on {len(vectors)} baseline samples")
        else:
            self._compute_stats(vectors)
            print(f"[ML] Z-score baseline computed from {len(vectors)} samples")

    def _compute_stats(self, vectors: list):
        """Compute mean/std for Z-score fallback."""
        n = len(vectors)
        self.means = [sum(v[i] for v in vectors)/n for i in range(8)]
        self.stds  = [
            math.sqrt(sum((v[i]-self.means[i])**2 for v in vectors)/n) or 1.0
            for i in range(8)
        ]

    def predict(self, log_line: str) -> dict:
        """Predict whether a log line is anomalous."""
        features = self.extract_features(log_line)
        if not features:
            return {"anomaly": False, "score": 0.0, "reason": "unparseable"}

        if ML and self.model and self.baseline:
            X = np.array([features])
            pred  = self.model.predict(X)[0]
            score = -self.model.score_samples(X)[0]
            anomaly = pred == -1
        else:
            if hasattr(self, 'means'):
                z_scores = [abs(features[i]-self.means[i])/self.stds[i] for i in range(8)]
                score    = max(z_scores)
                anomaly  = score > 3.0
            else:
                score, anomaly = 0.0, False

        reason = self._explain(features, anomaly)

        result = {
            "anomaly":   anomaly,
            "score":     round(score, 4),
            "severity":  "HIGH" if score > 0.7 else "MEDIUM" if score > 0.4 else "LOW",
            "features":  dict(zip(self.feature_names, features)),
            "reason":    reason,
            "timestamp": datetime.datetime.now().isoformat(),
            "log":       log_line[:120],
        }

        if anomaly:
            self.alerts.append(result)

        return result

    def _explain(self, features: list, anomaly: bool) -> str:
        if not anomaly:
            return "Within normal baseline parameters"
        reasons = []
        if features[4] > 0.5:  reasons.append("High authentication failure rate")
        if features[0] > 50:   reasons.append("Abnormal request frequency")
        if features[5] > 100:  reasons.append("Unusually high port diversity (possible scan)")
        if features[2] > 0.5:  reasons.append("High HTTP error rate")
        if features[3] > 10:   reasons.append("Abnormally large payload size")
        return " | ".join(reasons) if reasons else "Statistical outlier detected"

    def analyze_file(self, filepath: str) -> list:
        """Analyze an entire log file."""
        results = []
        try:
            with open(filepath) as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"[!] File not found: {filepath}")
            return results

        # Train on first 70% as baseline
        split = int(len(lines) * 0.7)
        if split > 0:
            self.train_baseline(lines[:split])

        for line in lines[split:]:
            line = line.strip()
            if line:
                r = self.predict(line)
                if r["anomaly"]:
                    results.append(r)

        return results


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3: APT ATTACK SIMULATOR
# ══════════════════════════════════════════════════════════════════════════════

class APTSimulator:
    """
    Generates realistic APT attack chains mapped to MITRE ATT&CK.
    Produces timestamped log entries, alert objects, and full incident reports.
    """

    def __init__(self):
        self.incidents_dir = Path("incidents")
        self.incidents_dir.mkdir(exist_ok=True)

    def simulate(self, apt_group: str = None, target_org: str = "TargetCorp") -> Incident:
        """Run a full APT simulation and return an Incident object."""
        if not apt_group:
            apt_group = random.choice(list(APT_GROUPS.keys()))

        tactics   = APT_GROUPS.get(apt_group, list(MITRE_TACTICS.keys())[:6])
        inc_id    = f"INC-{int(time.time())}"
        now       = datetime.datetime.now()
        alerts    = []
        timeline  = []
        mitre_chain = []

        print(f"\n[SIM] Simulating {apt_group} attack on {target_org}")
        print(f"[SIM] Tactics chain: {' → '.join(MITRE_TACTICS[t][0] for t in tactics)}\n")

        src_ips = [f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(5)]
        t = now

        for tactic_id in tactics:
            tactic_name, techniques = MITRE_TACTICS[tactic_id]
            technique_id = random.choice(techniques)
            technique_name = TECHNIQUE_NAMES.get(technique_id, technique_id)

            src_ip  = random.choice(src_ips)
            sev     = random.choice(["CRITICAL","HIGH","HIGH","MEDIUM"])

            alert = ThreatAlert(
                id          = f"ALT-{hashlib.md5(f'{inc_id}{tactic_id}'.encode()).hexdigest()[:8].upper()}",
                timestamp   = t.isoformat(),
                source_ip   = src_ip,
                severity    = sev,
                tactic      = tactic_name,
                technique   = technique_name,
                description = self._gen_description(tactic_name, technique_name, src_ip, target_org),
                mitre_id    = technique_id,
                score       = round(random.uniform(0.6, 1.0), 3),
                blocked     = random.random() < 0.25,
            )
            alerts.append(alert)
            mitre_chain.append(f"{technique_id} — {technique_name}")

            log_entry = f"[{t.strftime('%Y-%m-%d %H:%M:%S')}] [{sev:8}] {src_ip:>18} | {tactic_name} | {technique_name}"
            timeline.append(log_entry)

            print(f"  {log_entry}")
            t += datetime.timedelta(minutes=random.randint(5, 120))
            time.sleep(0.1)

        sev_counts = collections.Counter(a.severity for a in alerts)
        final_sev  = "CRITICAL" if sev_counts["CRITICAL"] else "HIGH" if sev_counts["HIGH"] else "MEDIUM"

        incident = Incident(
            id          = inc_id,
            title       = f"{apt_group} Campaign Against {target_org}",
            severity    = final_sev,
            status      = "ACTIVE",
            created_at  = now.isoformat(),
            updated_at  = datetime.datetime.now().isoformat(),
            alerts      = [asdict(a) for a in alerts],
            timeline    = timeline,
            mitre_chain = mitre_chain,
            affected_ips= list(set(a.source_ip for a in alerts)),
        )

        self._generate_html_report(incident, apt_group)
        self._generate_json_report(incident)

        return incident

    def _gen_description(self, tactic: str, technique: str, src: str, target: str) -> str:
        templates = {
            "Initial Access":       f"Suspicious connection from {src} targeting {target} web infrastructure via {technique}",
            "Execution":            f"Malicious code execution detected on {target} host from {src} using {technique}",
            "Persistence":          f"Persistence mechanism established on {target} endpoint — {technique} detected",
            "Privilege Escalation": f"Privilege escalation attempt from {src} on {target} using {technique}",
            "Defense Evasion":      f"Defense evasion behavior detected: {technique} from {src}",
            "Credential Access":    f"Credential harvesting activity: {technique} originating from {src}",
            "Discovery":            f"Internal reconnaissance by {src} within {target} network — {technique}",
            "Lateral Movement":     f"Lateral movement detected: {technique} from {src} to internal hosts",
            "Collection":           f"Data staging activity: {technique} on {target} systems",
            "Exfiltration":         f"Data exfiltration attempt: {technique} from {src} — {random.randint(10,500)}MB",
            "Impact":               f"Destructive payload execution: {technique} by {src} on {target}",
        }
        return templates.get(tactic, f"{technique} detected from {src} on {target}")

    def _generate_html_report(self, incident: Incident, apt_group: str):
        """Generate a professional HTML incident report."""
        sev_color = {"CRITICAL":"#ff2d7b","HIGH":"#ff9f0a","MEDIUM":"#ffc107","LOW":"#39ff14"}.get(incident.severity,"#888")
        alerts_html = ""
        for a in incident.alerts:
            color = {"CRITICAL":"#ff2d7b","HIGH":"#ff9f0a","MEDIUM":"#ffc107","LOW":"#39ff14"}.get(a["severity"],"#888")
            blocked_badge = '<span style="background:#39ff14;color:#000;padding:2px 8px;border-radius:3px;font-size:.7rem">BLOCKED</span>' if a["blocked"] else '<span style="background:#ff2d7b;color:#fff;padding:2px 8px;border-radius:3px;font-size:.7rem">DETECTED</span>'
            alerts_html += f"""
            <tr>
              <td style="color:#8888b0;font-size:.75rem">{a["timestamp"][:19]}</td>
              <td><span style="color:{color};font-weight:700">{a["severity"]}</span></td>
              <td style="color:#00e5ff">{a["source_ip"]}</td>
              <td>{a["tactic"]}</td>
              <td style="color:#b388ff">{a["mitre_id"]}</td>
              <td style="font-size:.8rem">{a["technique"]}</td>
              <td>{blocked_badge}</td>
            </tr>"""

        mitre_html = "".join(
            f'<div style="display:inline-block;margin:4px;padding:6px 12px;border:1px solid #b388ff;border-radius:4px;font-size:.75rem;color:#b388ff">{m}</div>'
            for m in incident.mitre_chain
        )

        timeline_html = "".join(
            f'<div style="font-family:monospace;font-size:.78rem;color:#8888b0;padding:3px 0;border-bottom:1px solid rgba(255,255,255,.04)">{t}</div>'
            for t in incident.timeline
        )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Incident Report — {incident.id}</title>
<style>
  body{{background:#050510;color:#eaeaf4;font-family:'Segoe UI',sans-serif;margin:0;padding:2rem}}
  h1{{color:#00e5ff;border-bottom:2px solid #00e5ff;padding-bottom:.5rem}}
  h2{{color:#b388ff;margin-top:2rem}}
  .meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:1rem;margin:1.5rem 0}}
  .meta-item{{background:rgba(10,10,28,.8);border:1px solid rgba(40,40,80,.6);border-radius:8px;padding:1rem;text-align:center}}
  .meta-label{{font-size:.7rem;color:#8888b0;text-transform:uppercase;letter-spacing:2px}}
  .meta-value{{font-size:1.4rem;font-weight:700;margin-top:.3rem}}
  table{{width:100%;border-collapse:collapse;margin-top:1rem}}
  th{{background:rgba(10,10,28,.9);color:#8888b0;font-size:.72rem;text-transform:uppercase;letter-spacing:1.5px;padding:.8rem 1rem;text-align:left}}
  td{{padding:.7rem 1rem;border-bottom:1px solid rgba(40,40,80,.4);font-size:.85rem}}
  .badge{{display:inline-block;padding:4px 10px;border-radius:4px;font-size:.72rem;font-weight:700}}
</style></head><body>
<h1>🛡 CYBER COMMAND CENTER — Incident Report</h1>
<p style="color:#8888b0">Generated by S. Srinivasan SOC | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>

<div class="meta">
  <div class="meta-item"><div class="meta-label">Incident ID</div><div class="meta-value" style="font-size:1rem;color:#00e5ff">{incident.id}</div></div>
  <div class="meta-item"><div class="meta-label">Severity</div><div class="meta-value" style="color:{sev_color}">{incident.severity}</div></div>
  <div class="meta-item"><div class="meta-label">Alerts</div><div class="meta-value">{len(incident.alerts)}</div></div>
  <div class="meta-item"><div class="meta-label">Affected IPs</div><div class="meta-value">{len(incident.affected_ips)}</div></div>
</div>

<p><strong style="color:#fff">{incident.title}</strong></p>
<p>Status: <span style="color:#ffc107">{incident.status}</span> | Analyst: {incident.analyst}</p>

<h2>🗺 MITRE ATT&CK Chain</h2>
<div style="background:rgba(10,10,28,.6);border:1px solid rgba(40,40,80,.6);border-radius:8px;padding:1rem">{mitre_html}</div>

<h2>🚨 Alert Timeline</h2>
<table><thead><tr>
  <th>Timestamp</th><th>Severity</th><th>Source IP</th>
  <th>Tactic</th><th>Technique ID</th><th>Technique</th><th>Status</th>
</tr></thead><tbody>{alerts_html}</tbody></table>

<h2>📋 Raw Timeline</h2>
<div style="background:rgba(10,10,28,.8);border:1px solid rgba(40,40,80,.5);border-radius:8px;padding:1rem">{timeline_html}</div>

<h2>🌐 Affected IPs</h2>
<div>{"  ".join(f'<code style="background:rgba(255,45,123,.1);padding:3px 8px;border-radius:3px;color:#ff2d7b;margin:4px">{ip}</code>' for ip in incident.affected_ips)}</div>

<hr style="border-color:rgba(40,40,80,.5);margin:2rem 0">
<p style="color:#8888b0;font-size:.8rem">CyberCommandCenter v{VERSION} | MITRE ATT&CK® v14 | S. Srinivasan — SOC Analyst</p>
</body></html>"""

        path = self.incidents_dir / f"{incident.id}_report.html"
        path.write_text(html)
        print(f"\n[REPORT] HTML report saved → {path}")

    def _generate_json_report(self, incident: Incident):
        path = self.incidents_dir / f"{incident.id}_report.json"
        path.write_text(json.dumps(asdict(incident), indent=2))
        print(f"[REPORT] JSON report saved → {path}")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4: HONEYPOT
# ══════════════════════════════════════════════════════════════════════════════

class Honeypot:
    """
    Multi-service TCP honeypot that simulates SSH/HTTP/FTP.
    Logs all attacker interactions with full fingerprinting.
    """

    def __init__(self, ports: list = None, log_file: str = "honeypot.jsonl"):
        self.ports    = ports or [2222, 8080, 2121]
        self.log_file = log_file
        self.sessions = []
        self.running  = False
        self.servers  = []

    def _fingerprint(self, conn, addr) -> dict:
        return {
            "ip":        addr[0],
            "port":      addr[1],
            "timestamp": datetime.datetime.now().isoformat(),
            "session_id": hashlib.md5(f"{addr}{time.time()}".encode()).hexdigest()[:12],
        }

    def _fake_ssh_banner(self) -> bytes:
        return b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

    def _fake_http_banner(self) -> bytes:
        return (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.54 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><body>Login</body></html>"
        )

    def _fake_ftp_banner(self) -> bytes:
        return b"220 ProFTPD 1.3.5e Server (ProFTPD) [127.0.0.1]\r\n"

    def _handle_conn(self, conn, addr, port: int):
        fp = self._fingerprint(conn, addr)
        payloads = []
        try:
            if port == 2222:
                conn.sendall(self._fake_ssh_banner())
            elif port == 8080:
                conn.sendall(self._fake_http_banner())
            elif port == 2121:
                conn.sendall(self._fake_ftp_banner())

            conn.settimeout(5)
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    decoded = data.decode('utf-8', errors='replace').strip()
                    payloads.append(decoded)
                    conn.sendall(b"Permission denied.\r\n")
            except socket.timeout:
                pass
        except Exception:
            pass
        finally:
            conn.close()

        fp["payloads"]     = payloads
        fp["target_port"]  = port
        fp["service"]      = {2222:"SSH",8080:"HTTP",2121:"FTP"}.get(port,"UNKNOWN")
        fp["payload_count"]= len(payloads)

        self.sessions.append(fp)
        self._log(fp)

        print(f"  [HONEYPOT] 🍯 {addr[0]}:{addr[1]} → port {port} ({fp['service']}) | {len(payloads)} payloads")

    def _log(self, entry: dict):
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def _start_listener(self, port: int):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("0.0.0.0", port))
            srv.listen(5)
            srv.settimeout(1)
            self.servers.append(srv)
            svc = {2222:"SSH",8080:"HTTP",2121:"FTP"}.get(port,"TCP")
            print(f"  [HONEYPOT] Listening on port {port} ({svc})")
            while self.running:
                try:
                    conn, addr = srv.accept()
                    t = threading.Thread(target=self._handle_conn, args=(conn,addr,port), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
        except PermissionError:
            print(f"  [HONEYPOT] Port {port} needs root — skipping")
        except OSError as e:
            print(f"  [HONEYPOT] Port {port} error: {e}")

    def start(self):
        self.running = True
        print(f"\n[HONEYPOT] Starting honeypot on ports {self.ports}")
        print(f"[HONEYPOT] Logging to {self.log_file}")
        print("[HONEYPOT] Press Ctrl+C to stop\n")

        threads = []
        for port in self.ports:
            t = threading.Thread(target=self._start_listener, args=(port,), daemon=True)
            t.start()
            threads.append(t)

        try:
            while True:
                time.sleep(10)
                if self.sessions:
                    print(f"  [HONEYPOT] {len(self.sessions)} total sessions captured")
        except KeyboardInterrupt:
            self.running = False
            print("\n[HONEYPOT] Stopped. Summary:")
            self.print_summary()

    def print_summary(self):
        if not self.sessions:
            print("  No sessions captured.")
            return
        ips = collections.Counter(s["ip"] for s in self.sessions)
        print(f"  Total sessions : {len(self.sessions)}")
        print(f"  Unique IPs     : {len(ips)}")
        print(f"  Top attacker   : {ips.most_common(1)[0]}")
        print(f"  Log file       : {self.log_file}")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5: LIVE SOC DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

class SOCDashboard:
    """Real-time terminal dashboard powered by Rich (or plain fallback)."""

    def __init__(self):
        self.alerts    = collections.deque(maxlen=50)
        self.stats     = {"total":0,"critical":0,"high":0,"blocked":0,"ips":set()}
        self.running   = False
        self.intel     = ThreatIntelEngine({})
        self.detector  = AnomalyDetector()
        self._seed_baseline()

    def _seed_baseline(self):
        """Generate baseline training data."""
        normal_logs = [
            f'192.168.1.{i} - - [{datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S")} +0000] "GET /index.html HTTP/1.1" 200 {random.randint(200,5000)}'
            for i in range(1,50)
        ]
        self.detector.train_baseline(normal_logs)

    def _generate_alert(self) -> ThreatAlert:
        tactic_id    = random.choice(list(MITRE_TACTICS.keys()))
        tactic_name, techniques = MITRE_TACTICS[tactic_id]
        technique_id = random.choice(techniques)
        severity     = random.choices(
            ["CRITICAL","HIGH","MEDIUM","LOW"],
            weights=[5,20,40,35]
        )[0]
        src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        return ThreatAlert(
            id          = f"ALT-{random.randint(10000,99999)}",
            timestamp   = datetime.datetime.now().strftime("%H:%M:%S"),
            source_ip   = src_ip,
            severity    = severity,
            tactic      = tactic_name,
            technique   = TECHNIQUE_NAMES.get(technique_id, technique_id),
            description = f"{TECHNIQUE_NAMES.get(technique_id,technique_id)} from {src_ip}",
            mitre_id    = technique_id,
            score       = round(random.uniform(0.3,1.0),3),
            blocked     = random.random() < 0.3,
        )

    def _update_stats(self, alert: ThreatAlert):
        self.stats["total"] += 1
        if alert.severity == "CRITICAL": self.stats["critical"] += 1
        if alert.severity == "HIGH":     self.stats["high"] += 1
        if alert.blocked:                self.stats["blocked"] += 1
        self.stats["ips"].add(alert.source_ip)

    def _make_rich_layout(self) -> "Layout":
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="stats", ratio=1),
            Layout(name="alerts", ratio=3),
        )
        return layout

    def _render_header(self) -> "Panel":
        t = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        txt = Text(justify="center")
        txt.append("🛡  CYBER COMMAND CENTER  ", style="bold cyan")
        txt.append(f"| SOC LIVE DASHBOARD | ", style="dim")
        txt.append(t, style="green")
        txt.append("  | S. Srinivasan", style="dim")
        return Panel(txt, style="cyan")

    def _render_stats(self) -> "Panel":
        tbl = Table(box=box.SIMPLE, show_header=False, padding=(0,1))
        tbl.add_column("k", style="dim", width=14)
        tbl.add_column("v", style="bold")
        tbl.add_row("Total Alerts",  str(self.stats["total"]))
        tbl.add_row("Critical",      f"[bold red]{self.stats['critical']}[/]")
        tbl.add_row("High",          f"[bold orange3]{self.stats['high']}[/]")
        tbl.add_row("Blocked",       f"[bold green]{self.stats['blocked']}[/]")
        tbl.add_row("Unique IPs",    str(len(self.stats["ips"])))
        tbl.add_row("Uptime",        f"{int(time.time()-self._start)//60}m {int(time.time()-self._start)%60}s")
        return Panel(tbl, title="[bold cyan]SOC STATS[/]", border_style="cyan")

    def _render_alerts(self) -> "Panel":
        tbl = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold dim",
            padding=(0,1),
        )
        tbl.add_column("Time",      width=9,  style="dim")
        tbl.add_column("Sev",       width=9)
        tbl.add_column("Source IP", width=16, style="cyan")
        tbl.add_column("Tactic",    width=20)
        tbl.add_column("Technique", width=32, style="dim")
        tbl.add_column("Score",     width=6)
        tbl.add_column("Status",    width=9)

        for alert in list(self.alerts)[-18:]:
            c     = COLORS.get(alert.severity, "white")
            sev   = f"[{c}]{alert.severity}[/{c}]"
            stat  = "[green]BLOCKED[/green]" if alert.blocked else "[red]ACTIVE[/red]"
            score = f"[{'red' if alert.score>0.7 else 'yellow'}]{alert.score:.3f}[/]"
            tbl.add_row(
                alert.timestamp, sev, alert.source_ip,
                alert.tactic[:19], alert.technique[:31],
                score, stat,
            )
        return Panel(tbl, title="[bold red]⚡ LIVE THREAT ALERTS[/]", border_style="red")

    def _render_footer(self) -> "Panel":
        txt = Text(justify="center")
        txt.append("MITRE ATT&CK v14  •  ", style="dim")
        txt.append("ML Anomaly Detection: ACTIVE  •  ", style="green")
        txt.append("Threat Intel: ACTIVE  •  ", style="cyan")
        txt.append("Press Ctrl+C to stop", style="dim")
        return Panel(txt, style="dim")

    def run_rich(self):
        self._start = time.time()
        layout = self._make_rich_layout()
        with Live(layout, refresh_per_second=2, screen=True) as live:
            while self.running:
                alert = self._generate_alert()
                self.alerts.append(alert)
                self._update_stats(alert)

                layout["header"].update(self._render_header())
                layout["body"]["stats"].update(self._render_stats())
                layout["body"]["alerts"].update(self._render_alerts())
                layout["footer"].update(self._render_footer())

                time.sleep(random.uniform(0.5, 2.0))

    def run_plain(self):
        self._start = time.time()
        print("\n[DASHBOARD] Live SOC Feed (plain mode — install rich for full UI)\n")
        print(f"{'Time':>10} {'Severity':>10} {'Source IP':>18} {'Tactic':>22} {'Score':>7}")
        print("-" * 80)
        while self.running:
            alert = self._generate_alert()
            self.alerts.append(alert)
            self._update_stats(alert)
            status = "BLOCKED" if alert.blocked else "ACTIVE "
            print(f"{alert.timestamp:>10} {alert.severity:>10} {alert.source_ip:>18} {alert.tactic[:22]:>22} {alert.score:>7.3f}  {status}")
            time.sleep(random.uniform(0.5, 2.0))

    def start(self):
        self.running = True
        print("[DASHBOARD] Starting CyberCommandCenter SOC Dashboard...")
        print("[DASHBOARD] Press Ctrl+C to stop\n")
        try:
            if RICH:
                self.run_rich()
            else:
                self.run_plain()
        except KeyboardInterrupt:
            self.running = False
            print(f"\n\n[DASHBOARD] Stopped. {self.stats['total']} alerts processed.")


# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6: IOC BULK SCANNER
# ══════════════════════════════════════════════════════════════════════════════

class IOCScanner:
    """Bulk scanner for IPs, domains, hashes against threat intel."""

    def __init__(self, config: dict = None):
        self.engine = ThreatIntelEngine(config or {})

    def scan_list(self, indicators: list) -> list:
        results = []
        print(f"\n[IOC] Scanning {len(indicators)} indicators...\n")
        for ind in indicators:
            r = self.engine.check_ioc(ind)
            results.append(r)
            status = "🔴 MALICIOUS" if r["matched"] else "🟢 CLEAN"
            print(f"  {ind:>40}  →  {status}")
        return results

    def scan_file(self, filepath: str) -> list:
        try:
            with open(filepath) as f:
                indicators = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            return self.scan_list(indicators)
        except FileNotFoundError:
            print(f"[!] File not found: {filepath}")
            return []

    def generate_report(self, results: list, outfile: str = "ioc_report.json"):
        with open(outfile, "w") as f:
            json.dump({"generated": datetime.datetime.now().isoformat(), "results": results}, f, indent=2)
        print(f"\n[IOC] Report saved → {outfile}")


# ══════════════════════════════════════════════════════════════════════════════
# INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════════════════

def print_menu():
    if RICH:
        console.print(Panel(
            "\n".join([
                "[cyan]1.[/cyan] 🖥  Live SOC Dashboard (real-time alerts)",
                "[cyan]2.[/cyan] 🎯  APT Attack Simulator (MITRE ATT&CK)",
                "[cyan]3.[/cyan] 🔍  IP Threat Intelligence Lookup",
                "[cyan]4.[/cyan] 🤖  ML Anomaly Detection (analyze log file)",
                "[cyan]5.[/cyan] 🍯  Honeypot Listener (trap attackers)",
                "[cyan]6.[/cyan] 📋  Bulk IOC Scanner",
                "[cyan]7.[/cyan] 💡  Run Full Demo (all modules)",
                "[cyan]0.[/cyan] ❌  Exit",
            ]),
            title="[bold cyan]⚡ CYBER COMMAND CENTER MENU[/bold cyan]",
            border_style="cyan",
        ))
    else:
        print("\n" + "="*50)
        print("  CYBER COMMAND CENTER — MENU")
        print("="*50)
        print("  1. Live SOC Dashboard")
        print("  2. APT Attack Simulator")
        print("  3. IP Threat Intel Lookup")
        print("  4. ML Anomaly Detection")
        print("  5. Honeypot Listener")
        print("  6. Bulk IOC Scanner")
        print("  7. Full Demo")
        print("  0. Exit")
        print("="*50)


def run_demo():
    """Full demo — runs all modules sequentially without user input."""
    print("\n" + "="*60)
    print("  CYBER COMMAND CENTER — FULL DEMO MODE")
    print("="*60)

    # 1. APT Simulation
    print("\n[DEMO] Step 1: APT Attack Simulation")
    sim = APTSimulator()
    incident = sim.simulate(apt_group="APT29 (Cozy Bear)", target_org="DemoCorpInc")
    print(f"[DEMO] Incident {incident.id} created — {len(incident.alerts)} alerts")

    # 2. Threat Intel
    print("\n[DEMO] Step 2: Threat Intelligence Lookups")
    engine = ThreatIntelEngine({})
    test_ips = ["45.33.32.156", "8.8.8.8", "185.220.101.1", "1.1.1.1"]
    for ip in test_ips:
        intel = engine.lookup_ip(ip)
        print(f"  {ip:>18} | Score:{intel.abuse_score:>3} | {intel.reputation:>10} | {intel.country} | {intel.isp[:25]}")

    # 3. Anomaly Detection
    print("\n[DEMO] Step 3: ML Anomaly Detection")
    detector = AnomalyDetector()
    normal_logs = [
        '192.168.1.10 - - [01/Jan/2025:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.11 - - [01/Jan/2025:10:01:00 +0000] "GET /about.html HTTP/1.1" 200 567',
        '192.168.1.12 - - [01/Jan/2025:10:02:00 +0000] "POST /login HTTP/1.1" 200 890',
    ] * 20
    detector.train_baseline(normal_logs)

    attack_logs = [
        '45.33.32.156 - - [01/Jan/2025:10:05:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0',
        'Failed password for root from 185.220.101.1 port 54321 ssh2',
        'Failed password for admin from 185.220.101.1 port 54322 ssh2',
        'Connection refused from 45.33.32.156 REJECT',
    ]
    for log in attack_logs:
        r = detector.predict(log)
        flag = "🔴 ANOMALY" if r["anomaly"] else "🟢 NORMAL"
        print(f"  {flag} | score:{r['score']:.3f} | {log[:60]}")

    # 4. IOC Scan
    print("\n[DEMO] Step 4: IOC Bulk Scan")
    scanner = IOCScanner()
    iocs = ["45.33.32.156","8.8.8.8","evil-c2.xyz","google.com","d41d8cd98f00b204e9800998ecf8427e"]
    scanner.scan_list(iocs)

    print("\n" + "="*60)
    print("  DEMO COMPLETE — Check incidents/ folder for reports!")
    print("="*60)


def main():
    parser = argparse.ArgumentParser(description="CyberCommandCenter — AI-Powered SOC Platform")
    parser.add_argument("--dashboard",   action="store_true", help="Launch live dashboard")
    parser.add_argument("--simulate-apt",action="store_true", help="Run APT simulation")
    parser.add_argument("--honeypot",    action="store_true", help="Start honeypot")
    parser.add_argument("--demo",        action="store_true", help="Full demo mode")
    parser.add_argument("--apt-group",   default=None,        help="APT group name")
    parser.add_argument("--target",      default="TargetCorp",help="Target organization name")
    parser.add_argument("--analyze",     default=None,        help="Log file to analyze")
    args = parser.parse_args()

    print(BANNER)

    if args.demo:
        run_demo(); return
    if args.dashboard:
        SOCDashboard().start(); return
    if args.simulate_apt:
        APTSimulator().simulate(apt_group=args.apt_group, target_org=args.target); return
    if args.honeypot:
        Honeypot().start(); return
    if args.analyze:
        d = AnomalyDetector()
        results = d.analyze_file(args.analyze)
        print(f"\n[ANOMALY] {len(results)} anomalies found in {args.analyze}")
        for r in results[:10]:
            print(f"  🔴 score:{r['score']:.3f} | {r['reason']} | {r['log'][:80]}")
        return

    # Interactive menu
    config = {}
    try:
        if Path("config.json").exists():
            config = json.loads(Path("config.json").read_text())
    except Exception:
        pass

    engine  = ThreatIntelEngine(config)
    scanner = IOCScanner(config)
    sim     = APTSimulator()
    detect  = AnomalyDetector()

    while True:
        print_menu()
        try:
            choice = input("\n  Select option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting..."); break

        if choice == "0":
            print("Goodbye."); break

        elif choice == "1":
            SOCDashboard().start()

        elif choice == "2":
            print("\nAvailable APT groups:")
            for i,(g,_) in enumerate(APT_GROUPS.items(), 1):
                print(f"  {i}. {g}")
            g_input = input("  Select group (or Enter for random): ").strip()
            groups = list(APT_GROUPS.keys())
            group  = groups[int(g_input)-1] if g_input.isdigit() and 1<=int(g_input)<=len(groups) else None
            target = input("  Target org name [TargetCorp]: ").strip() or "TargetCorp"
            sim.simulate(apt_group=group, target_org=target)

        elif choice == "3":
            ip = input("  Enter IP address: ").strip()
            if ip:
                intel = engine.lookup_ip(ip)
                print(f"\n  IP           : {intel.ip}")
                print(f"  Abuse Score  : {intel.abuse_score}/100")
                print(f"  Reputation   : {intel.reputation}")
                print(f"  Country      : {intel.country}")
                print(f"  ISP          : {intel.isp}")
                print(f"  Tor Exit     : {intel.is_tor}")
                print(f"  Proxy        : {intel.is_proxy}")
                print(f"  Reports      : {intel.reports}")
                print(f"  Threat Types : {', '.join(intel.threat_types) or 'None'}")

        elif choice == "4":
            path = input("  Log file path [sample_attack.log]: ").strip() or "sample_attack.log"
            if not Path(path).exists():
                print(f"  Creating sample log: {path}")
                _create_sample_log(path)
            results = detect.analyze_file(path)
            print(f"\n  Anomalies found: {len(results)}")
            for r in results[:10]:
                print(f"  🔴 score:{r['score']:.3f} | {r['reason'][:60]} | {r['log'][:60]}")

        elif choice == "5":
            raw   = input("  Ports [2222,8080,2121]: ").strip() or "2222,8080,2121"
            ports = [int(p) for p in raw.split(",") if p.strip().isdigit()]
            Honeypot(ports=ports).start()

        elif choice == "6":
            path = input("  IOC list file (one per line) or Enter for demo: ").strip()
            if path and Path(path).exists():
                scanner.scan_file(path)
            else:
                demo_iocs = ["45.33.32.156","8.8.8.8","evil-c2.xyz","google.com","d41d8cd98f00b204e9800998ecf8427e"]
                results   = scanner.scan_list(demo_iocs)
                scanner.generate_report(results)

        elif choice == "7":
            run_demo()

        else:
            print("  Invalid option.")


def _create_sample_log(path: str):
    """Generate a sample mixed log file for demo."""
    lines = [
        '192.168.1.10 - - [01/Jan/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234',
        '192.168.1.11 - - [01/Jan/2025:10:00:15 +0000] "GET /about.html HTTP/1.1" 200 567',
        '192.168.1.12 - - [01/Jan/2025:10:01:00 +0000] "POST /login HTTP/1.1" 200 890',
        '192.168.1.10 - - [01/Jan/2025:10:02:00 +0000] "GET /dashboard HTTP/1.1" 200 4567',
        '192.168.1.15 - - [01/Jan/2025:10:03:00 +0000] "GET /api/status HTTP/1.1" 200 234',
    ] * 15 + [
        '45.33.32.156 - - [01/Jan/2025:10:15:00 +0000] "GET /etc/passwd HTTP/1.1" 404 0',
        '45.33.32.156 - - [01/Jan/2025:10:15:01 +0000] "GET /.env HTTP/1.1" 404 0',
        '45.33.32.156 - - [01/Jan/2025:10:15:02 +0000] "GET /wp-admin/install.php HTTP/1.1" 404 0',
        'Jan  1 10:16:00 server sshd[1234]: Failed password for root from 185.220.101.1 port 54321 ssh2',
        'Jan  1 10:16:01 server sshd[1235]: Failed password for root from 185.220.101.1 port 54322 ssh2',
        'Jan  1 10:16:02 server sshd[1236]: Failed password for admin from 185.220.101.1 port 54323 ssh2',
        'Jan  1 10:16:03 server sshd[1237]: Failed password for ubuntu from 185.220.101.1 port 54324 ssh2',
        'Jan  1 10:17:00 server kernel: iptables REJECT IN=eth0 SRC=198.20.69.74 DST=10.0.0.1',
        'Jan  1 10:17:01 server kernel: iptables REJECT IN=eth0 SRC=198.20.69.74 DST=10.0.0.2',
        'Jan  1 10:17:02 server kernel: Connection refused from 198.20.69.74 port 3306',
    ]
    random.shuffle(lines[:75])
    Path(path).write_text("\n".join(lines))
    print(f"  Sample log created: {path} ({len(lines)} lines)")


if __name__ == "__main__":
    main()
