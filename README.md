# Security Monitor

A professional cybersecurity desktop application that provides real-time network threat detection, system monitoring, and file integrity alerting — all in a dark-themed PyQt6 GUI.

## Features

### Network Threat Detection
- **DDoS / Traffic Analysis** — Random Forest + Isolation Forest ML models classify live packets as Safe, Suspicious, or Attack in real time
- **ARP Spoofing** — Detects ARP cache poisoning, gateway MAC hijacks, and ARP floods
- **DNS Anomaly** — Detects DNS tunneling, fast-flux, C2 beaconing, and risky TLDs
- **Brute Force** — Tracks SYN floods to 12 auth services (SSH, RDP, FTP, SMB…), credential stuffing, and password spray

### Host-Based Monitoring
- **Windows Event Log** — Polls Security/System logs for failed logins (4625), new accounts (4720), privilege changes (4732), suspicious processes (4688), new services (7045), and log clearing (1102)
- **File Integrity Monitoring** — SHA-256 baseline of watched directories; alerts on file create/modify/delete
- **Threat Intelligence** — AbuseIPDB reputation checks for attacker IPs (async, 1-hour cache)

### Network Vulnerability Scanner
- Socket-based scanner with banner grabbing across 23 common ports
- Supports single IP, hostname, and CIDR ranges (up to /24)
- Highlights high-risk open ports

### Desktop App
- System tray integration with toast notifications for critical alerts
- Windows Firewall IP blocking (requires Administrator)
- Alert export to JSON
- Simulate Detections panel for testing all detector types without needing real attacks

## Project Structure

```
security_monitor/
├── desktop_app.py          # Main PyQt6 desktop application
├── main_app.py             # Flask REST API (optional web interface)
├── train_model.py          # ML model training script
├── config.py               # Central configuration (loads from .env)
├── rules_config.json       # Rule-based detection thresholds
├── detectors/
│   ├── ddos.py             # DDoS rule engine + ML inference
│   ├── anomaly.py          # Isolation Forest anomaly detector
│   ├── email_phishing.py   # Gemini AI email analysis
│   ├── url_phishing.py     # URL phishing classifier
│   ├── cookie_detector.py  # Cookie-based threat detection
│   ├── arp_monitor.py      # ARP spoofing / flood detection
│   ├── dns_monitor.py      # DNS anomaly detection
│   ├── brute_force.py      # Brute force / password spray detection
│   ├── threat_intel.py     # AbuseIPDB reputation checks
│   ├── event_log.py        # Windows Event Log monitor
│   ├── fim.py              # File Integrity Monitor
│   └── vuln_scanner.py     # Network vulnerability scanner
├── templates/
│   └── index.html          # Flask web dashboard template
├── logs/                   # Application log files
├── reports/                # Project reports and screenshots
├── tests/                  # Additional test scripts
├── cicddos2019_dataset.csv # Training dataset (~147 MB)
├── Phising_dataset_predict.csv
├── ddos_detector_model.joblib  # Trained DDoS classifier
├── anomaly_model.joblib        # Trained anomaly detector
├── fim_baseline.json           # FIM file hash baseline (auto-generated)
├── blocked_ips.json            # Currently blocked IPs
├── .env                        # Secret keys (not in version control)
├── .env.example                # Template for .env
└── requirements.txt
```

## Setup

### 1. Prerequisites

- Python 3.10+
- Windows 10/11 (for Windows Firewall blocking and Event Log monitoring)
- Run as Administrator for IP blocking and packet capture

### 2. Install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

### 3. Configure environment

```bash
copy .env.example .env
```

Edit `.env` and add your keys:

```
GEMINI_API_KEY=your_gemini_key_here     # For email phishing analysis
ABUSEIPDB_API_KEY=your_key_here         # Free at abuseipdb.com
GATEWAY_IP=192.168.1.1                  # Your router's IP (for ARP hijack detection)
```

### 4. Train the ML models

```bash
python train_model.py
```

This reads `cicddos2019_dataset.csv` and saves `ddos_detector_model.joblib` and `anomaly_model.joblib`.

### 5. Run the desktop app

```bash
python desktop_app.py
```

Right-click → **Run as administrator** to enable IP blocking and full packet capture.

## Building a standalone executable

The project includes a full packaging pipeline in `build.py`:

```bash
# Windows — build a folder-based distribution (fast startup)
python build.py

# Build + create a portable ZIP for sharing
python build.py --zip

# Build a single-EXE (simpler, but slower to start)
python build.py --onefile

# Build only (skip Inno Setup installer compilation)
python build.py --noinstaller
```

Output is in `dist/SecurityMonitor/`. Launch with `SecurityMonitor.exe` (run as Administrator for full features).

### Windows Installer (optional)

Install [Inno Setup 6](https://jrsoftware.org/isinfo.php), then:

```bash
python build.py        # automatically compiles installer.iss if ISCC.exe is on PATH
```

This produces `dist/installer/SecurityMonitor_Setup_1.0.0.exe` — a professional one-click installer with desktop shortcut, Start Menu entry, and Npcap dependency check.

### Platform notes

| Platform | Packet capture | Event Log | Firewall blocking |
|---|---|---|---|
| Windows 10/11 | Full (Npcap required) | Full | Full (Admin) |
| Linux | Full (root required) | N/A | N/A |
| macOS | Full (root required) | N/A | N/A |

Download [Npcap](https://npcap.com/#download) for Windows packet capture support.

## Running tests

```bash
pytest test_desktop_app.py -v
```

## Detection Thresholds (rules_config.json)

All rule thresholds are configurable in `rules_config.json`:
- SYN flood: >500 SYN packets/second
- Port scan: >20 unique destination ports/second
- Connection flood: >100 new connections/second
- Attack confidence: ≥70% RF probability

## Threat Intelligence

Sign up at [abuseipdb.com](https://www.abuseipdb.com/account/api) for a free API key (1,000 checks/day). Add it to `.env` as `ABUSEIPDB_API_KEY`. The app caches results for 1 hour to stay within rate limits.

## File Integrity Monitoring

By default, FIM watches the project directory. Add directories to monitor in `.env`:

```
FIM_WATCH_DIRS=C:\Users\YourName\Documents,C:\Windows\System32
```

The baseline is built on first run and saved to `fim_baseline.json`. Subsequent runs alert on any changes.
