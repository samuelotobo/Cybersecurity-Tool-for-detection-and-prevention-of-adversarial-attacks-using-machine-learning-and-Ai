# Project Title: Network Security Monitor System

## CMPE314 — Computer Networks & Security  
## Project Report

**Submitted To:** Course Instructor

**Submitted By:**

### SAMUEL AKPOGHENE OTOBO — 22100896

**GitHub URL:** https://github.com/samuelotobo/Software-Engineering-Project-.git

---

---

# Table of Contents

- Chapter 1: Introduction .............................................................. 4
  - 1.1 Project Overview & Problem Statement ............................ 4
  - 1.2 Project Scope & Objectives .............................................. 5
  - 1.3 Report Structure ............................................................... 6
- Chapter 2: Project Management ................................................. 7
  - 2.1 Team Members & Roles ................................................... 7
  - 2.2 Work Breakdown & Individual Contributions ................... 7
  - 2.3 Chosen Software Process Model & Justification ............... 8
  - 2.4 Project Timeline .............................................................. 8
- Chapter 3: Stakeholder & Requirements Elicitation .................. 9
  - 3.1 Stakeholder Identification ............................................... 9
  - 3.2 Stakeholder Analysis ....................................................... 10
  - 3.3 Requirements Elicitation Techniques Used ...................... 10
- Chapter 4: Requirements Specification ..................................... 12
  - 4.1 Functional Requirements (FRs) ...................................... 12
  - 4.2 Non-Functional Requirements (NFRs) ............................ 15
- Chapter 5: System Modelling .................................................... 17
  - 5.1 Use Case Model .............................................................. 17
  - 5.2 Dynamic Models ............................................................. 20
  - 5.3 Structural Model ............................................................. 21
  - 5.4 Data Flow Model ............................................................ 22
- Chapter 6: Implementation ....................................................... 23
  - 6.1 Technology Stack Details ................................................ 23
  - 6.2 Key Algorithms & Code Snippets ................................... 24
  - 6.3 User Interfaces ............................................................... 30
  - 6.4 Open-Source Libraries Used ........................................... 31
- Chapter 7: Testing ..................................................................... 32
  - 7.1 Unit Testing Approach .................................................... 32
  - 7.2 Test Cases ....................................................................... 33
  - 7.3 Acceptance Testing ........................................................ 35
- Chapter 8: Conclusion ............................................................... 36
  - 8.1 Project Summary ............................................................. 36
  - 8.2 Challenges Faced & Lessons Learned ............................. 37
- References .................................................................................. 39
- Appendices ................................................................................. 39

---

---

# Chapter 1: Introduction

The **Network Security Monitor System** is a Python-based desktop security application developed to provide real-time detection of network-level threats, file system tampering, suspicious system events, and phishing attacks. The system combines machine learning (ML) classification, rule-based heuristics, artificial intelligence (AI) APIs, and packet-level network analysis into a single unified monitoring platform with a professional graphical user interface built in PyQt6.

The project applies software engineering principles — requirements analysis, system modelling, iterative development, automated testing, and structured documentation — to solve a real-world cybersecurity challenge faced by system administrators, network engineers, and security professionals.

---

## 1.1 Project Overview & Problem Statement

Modern computer networks face an ever-growing range of threats. Distributed Denial-of-Service (DDoS) attacks, ARP spoofing, DNS-based Command & Control (C2) channels, brute-force credential attacks, phishing emails, and malicious URL visits are among the most common attack vectors recorded by cybersecurity organisations worldwide. Despite the severity of these threats, most end-users and small-to-medium enterprise (SME) environments lack affordable, integrated, real-time monitoring tools.

**Key problems with existing approaches:**

- Enterprise-grade Security Information and Event Management (SIEM) systems are expensive and complex to configure.
- Open-source tools are fragmented — separate tools for network monitoring, file integrity, phishing detection, and log analysis require significant integration effort.
- Most tools lack a user-friendly interface accessible to administrators without deep security expertise.
- Threshold-based detection systems generate excessive false positives without proper calibration, causing alert fatigue.
- Machine learning models for threat detection are often pre-packaged black boxes without transparency or customisability.

**The Network Security Monitor System addresses these problems by providing:**

- A single desktop application that monitors multiple threat surfaces simultaneously.
- Machine learning models (Random Forest, Isolation Forest, SVM) trained on real network datasets.
- AI-powered phishing analysis via Google's Gemini 2.0 Flash API.
- Real-time packet sniffing and protocol-level inspection using Scapy.
- Integrated threat intelligence lookups via the AbuseIPDB API.
- Carefully calibrated detection thresholds to minimise false positives without sacrificing detection sensitivity.
- A professional dark-themed PyQt6 dashboard accessible to administrators without deep technical expertise.

---

## 1.2 Project Scope & Objectives

### Project Scope

The Network Security Monitor System focuses on providing a real-time, multi-vector threat detection and monitoring platform for desktop use on Windows systems.

**The System WILL:**

- Capture and analyse live network packets in real time using Scapy.
- Detect DDoS attacks using a trained Random Forest ML classifier and a rule-based engine, refined by a second-layer Isolation Forest anomaly detector.
- Detect ARP spoofing and ARP flood attacks by tracking IP-to-MAC mapping changes.
- Detect DNS anomalies including tunnelling, fast-flux C2 domains, suspicious TLDs, and C2 beaconing.
- Detect brute-force and credential-based attacks on authentication services (SSH, RDP, SMTP, SMB, etc.).
- Monitor File Integrity by tracking SHA-256 hashes of watched directories.
- Monitor Windows Security and System Event Logs for suspicious activity, and build per-user behavioural baselines (UEBA) to flag off-hours logins and new-workstation activity.
- Perform Threat Intelligence lookups on attacker IPs via the AbuseIPDB API, and geolocate attacker IPs on an interactive map.
- Analyse email content for phishing indicators using an LLM (Groq primary, Google Gemini fallback).
- Classify URLs as phishing or legitimate using a trained Random Forest model.
- Classify cookies as tracking/malicious using a trained SVM model over live-sniffed `Set-Cookie` headers.
- Inspect TLS Client Hello metadata (SNI, version, cipher suites, JA3 fingerprint) without decrypting traffic.
- Scan hosts and CIDR ranges for open ports and risky services (pure-Python, no external tools).
- Display all alerts in a real-time dashboard with severity indicators, and mirror them to a JWT-authenticated web/mobile companion dashboard for remote viewing.
- Support IP blocking (with an automatic rollback timer) and allow-list management.
- Continuously improve the DDoS classifier from analyst feedback (adaptive retraining) and provide an adversarial-ML lab (evasion testing, feature explainability, model security scoring) for auditing the classifier's own robustness.
- Generate system health and threat statistics.

**The System WILL NOT:**

- Control or modify network infrastructure (routers, firewalls, switches) beyond host-level Windows Firewall rules.
- Integrate with external SIEM systems (Splunk, ELK, etc.) — alerts are exposed via the local log file and the web dashboard's API, not pushed to a SIEM.
- Process encrypted HTTPS payload content (only metadata and handshake traffic).
- Provide GPS or physical location tracking of attackers (IP geolocation is city/country-level only, via a third-party IP database).
- Offer a hosted, multi-organisation SaaS deployment — the web/mobile companion is a LAN-local extension of a single desktop installation, not a cloud service.

### Project Objectives

1. To provide real-time, multi-vector network threat detection in a single application.
2. To apply machine learning for accurate, adaptive DDoS and anomaly detection.
3. To leverage AI APIs for natural language understanding of phishing email content.
4. To minimise false positives through carefully calibrated thresholds and whitelist mechanisms.
5. To provide administrators with an intuitive, professional-grade dark-themed dashboard.
6. To implement file integrity monitoring to detect unauthorised system changes.
7. To monitor Windows Event Logs for signs of privilege escalation, account abuse, and malware activity.
8. To deliver a modular, extensible codebase supporting future integration with additional detectors.

---

## 1.3 Report Structure

This report is organised into the following chapters:

**Chapter 1: Introduction**
Provides a project overview, problem statement, scope, objectives, and report structure.

**Chapter 2: Project Management**
Describes team roles, task distribution, the selected software process model, and the project timeline.

**Chapter 3: Stakeholder & Requirements Elicitation**
Identifies system stakeholders and explains the techniques used to gather system requirements.

**Chapter 4: Requirements Specification**
Presents the functional and non-functional requirements of the system in structured form.

**Chapter 5: System Modelling**
Includes UML-based models — use case diagrams, activity diagrams, sequence diagrams, class diagrams, and data flow diagrams.

**Chapter 6: Implementation**
Explains the technology stack, key detection algorithms with code snippets, database integration, and user interface design.

**Chapter 7: Testing**
Describes the testing approach, test cases, and results from unit and acceptance testing.

**Chapter 8: Conclusion**
Summarises project outcomes, challenges faced, lessons learned, and directions for future work.

---

---

# Chapter 2: Project Management

## 2.1 Team Members & Roles

| Team Member | Primary Role |
|---|---|
| Samuel Akpoghene Otobo | Requirements Analysis & System Design |
| Samuel Akpoghene Otobo | Machine Learning Model Development |
| Samuel Akpoghene Otobo | Network Detection Module Development |
| Samuel Akpoghene Otobo | Desktop UI Design & Implementation (PyQt6) |
| Samuel Akpoghene Otobo | Testing, Debugging & Report Compilation |

---

## 2.2 Work Breakdown & Individual Contributions

| Task | Description | Member |
|---|---|---|
| Stakeholder Analysis | Identified and analysed system stakeholders and their requirements | Samuel Akpoghene Otobo |
| Requirements Gathering | Collected and documented functional and non-functional requirements | Samuel Akpoghene Otobo |
| System Architecture Design | Designed the modular multi-detector architecture | Samuel Akpoghene Otobo |
| ML Model Development | Trained Random Forest (DDoS), Isolation Forest (Anomaly), SVM (Cookie) models | Samuel Akpoghene Otobo |
| Network Detector Development | Implemented ARP, DNS, Brute Force, and DDoS packet-level detectors using Scapy | Samuel Akpoghene Otobo |
| AI Integration | Integrated Google Gemini API for email phishing detection | Samuel Akpoghene Otobo |
| Threat Intelligence | Integrated AbuseIPDB API for IP reputation lookups | Samuel Akpoghene Otobo |
| File Integrity Monitor | Implemented SHA-256 hash-based FIM with exclusion rules | Samuel Akpoghene Otobo |
| Event Log Monitor | Implemented Windows Event Log polling via wevtutil | Samuel Akpoghene Otobo |
| Desktop UI Development | Designed and implemented PyQt6 dark-themed dashboard | Samuel Akpoghene Otobo |
| Threshold Calibration | Audited and tuned all detection thresholds to minimise false positives | Samuel Akpoghene Otobo |
| Testing | Wrote and executed comprehensive demo test suite (demo_test.py) | Samuel Akpoghene Otobo |
| Documentation | Final report formatting and editing | Samuel Akpoghene Otobo |

---

## 2.3 Chosen Software Process Model & Justification

The **Agile (Iterative) software development model** was selected for this project.

### Justification for Choosing Agile

The Agile model was chosen because the system's requirements evolved throughout development. Detection thresholds needed adjustment after real-world testing; new detector modules were added iteratively; and the user interface was refined across multiple sessions based on functionality testing. Agile's iterative nature allowed these changes to be incorporated naturally without disrupting the overall project structure.

### Benefits of Using Agile in This Project

- Each detector module could be developed, tested, and integrated independently.
- Threshold calibration required multiple test-feedback cycles — Agile supported this naturally.
- False positive issues discovered during testing were corrected in subsequent iterations without requiring full restarts.
- The modular architecture aligned with Agile's principle of delivering working software incrementally.
- Rapid prototyping of the PyQt6 UI allowed early feedback on usability before full detector integration.

The project was developed in four major iterations:

1. **Iteration 1** — Core network detectors (ARP, DNS, Brute Force) + Scapy integration.
2. **Iteration 2** — Machine learning models (DDoS, Anomaly) + training pipeline.
3. **Iteration 3** — Desktop UI (PyQt6), dashboard, and alert management.
4. **Iteration 4** — FIM, Event Log monitor, Threat Intelligence, AI phishing, and threshold calibration.

---

## 2.4 Project Timeline

| Phase | Tasks | Duration |
|---|---|---|
| Week 1–2 | Requirements gathering, stakeholder analysis, architecture design | 2 weeks |
| Week 3–4 | Network detector development (ARP, DNS, Brute Force) | 2 weeks |
| Week 5–6 | ML model development and training pipeline | 2 weeks |
| Week 7–8 | PyQt6 desktop UI development | 2 weeks |
| Week 9–10 | FIM, Event Log, Threat Intel, AI phishing integration | 2 weeks |
| Week 11 | Threshold calibration and false-positive audit | 1 week |
| Week 12 | Testing, demo test suite, documentation | 1 week |

---

---

# Chapter 3: Stakeholder & Requirements Elicitation

## 3.1 Stakeholder Identification

Stakeholders are individuals or groups who interact with the system directly or are affected by its operation. The stakeholders of the Network Security Monitor System are categorised into primary and secondary groups.

### Primary Stakeholders

**1. System Administrators**
System administrators are the primary users of the monitoring dashboard. They monitor live threat alerts, manage blocked IPs, configure watched directories for FIM, and review event log activity. Their goal is to detect and respond to security incidents quickly and efficiently.

**2. Network Security Analysts**
Security analysts use the system's threat data — ML-classified network flows, threat intelligence reports, phishing analysis results, and event log anomalies — to investigate potential breaches, conduct incident response, and assess the organisation's threat exposure.

### Secondary Stakeholders

**1. IT Managers**
IT managers use aggregated system reports and health statistics to assess the security posture of their infrastructure and make informed decisions about security investments and policy changes.

**2. Compliance Officers**
Compliance officers rely on the system's event log monitoring (privilege escalation, audit log clearing, new accounts) and FIM capabilities to ensure adherence to security standards such as ISO 27001, PCI-DSS, and GDPR.

**3. End Users / Employees**
End users are indirectly affected by the system. When their machines are monitored, they benefit from faster incident response and reduced exposure to phishing and malware threats.

**4. Developers / Future Maintainers**
Developers who extend or maintain the system require clear documentation, modular architecture, and a well-structured codebase to add new detectors or integrate with external systems.

---

## 3.2 Stakeholder Analysis

| Stakeholder | Interest in the System | Influence | Specific Requirements |
|---|---|---|---|
| System Administrators | Real-time visibility of active threats | High | Live alert dashboard, IP blocking, FIM alerts, severity indicators |
| Security Analysts | Deep threat investigation data | High | ML verdicts, packet metadata, TI lookups, phishing analysis |
| IT Managers | Security posture overview | Medium | Summary statistics, health indicators, alert history |
| Compliance Officers | Audit trail and policy enforcement | Medium | Event log monitoring, FIM reporting, privilege escalation alerts |
| End Users | Safe working environment | Low | Minimal system disruption from monitoring agent |
| Future Developers | Maintainable, extensible codebase | Medium | Modular architecture, documented APIs, clear configuration |

System administrators and security analysts are the most important stakeholders because they interact with the system daily and their requirements directly shaped the design of the dashboard, the detection modules, and the alert management system.

---

## 3.3 Requirements Elicitation Techniques Used

Several requirements elicitation techniques were applied to gather accurate and complete system requirements.

### 1. Brainstorming Sessions

The development team conducted structured brainstorming to identify the full range of threat vectors the system should address. Sessions covered network-layer attacks (DDoS, ARP spoofing, DNS abuse), host-level threats (file tampering, privilege escalation, malicious processes), and application-layer threats (phishing emails and URLs). This produced the initial list of detector modules.

### 2. Research and Literature Review

Published cybersecurity datasets (CIC-DDoS2019, PhishingDataset), academic papers on network anomaly detection, and industry reports (OWASP, MITRE ATT&CK framework) were studied to understand the most common and impactful attack patterns. This informed the selection of features for ML model training and the calibration of detection thresholds.

### 3. Observation and Practical Testing

The team observed real network traffic on the development machine to identify common false-positive sources. For example:
- A machine with an email client, SSH terminal, and local MySQL generated false brute-force alerts.
- DNS queries to Google's CDN (anycast with 10–20 IPs) triggered false fast-flux alerts.
- The FIM baseline file (`fim_baseline.json`) written every 60 seconds caused self-referential alerts.

These observations directly drove threshold adjustments and exclusion rule additions.

### 4. User Persona Development

Two primary user personas were developed:
- **"Alex the Admin"** — a system administrator who wants a clean, real-time dashboard with minimal false alarms, clear severity indicators, and quick access to IP blocking.
- **"Sara the Analyst"** — a security analyst who needs detailed alert metadata (rule name, source IP, timestamp, message) and the ability to drill into ML classification confidence scores.

These personas guided the UI design and the alert data model.

### 5. Analysis of Existing Security Tools

Existing tools including Snort (rule-based IDS), OSSEC (FIM + log analysis), and open-source DDoS detectors were analysed. Key gaps identified — lack of ML integration, poor UI, no AI-powered phishing analysis, high false-positive rates — were used to define the differentiating features of this system.

### Outcome of Requirements Elicitation

The elicitation process defined:
- 15 functional requirements covering all detection, management, and reporting capabilities.
- 15 non-functional requirements covering performance, security, usability, reliability, and scalability.
- The modular detector architecture (one Python class per threat type).
- The PyQt6 tabbed dashboard with dedicated sections for each threat category.
- The false-positive suppression mechanisms (thresholds, cooldowns, CDN whitelists, private IP filters).

---

---

# Chapter 4: Requirements Specification

## 4.1 Functional Requirements (FRs)

### FR-001: Live Network Packet Capture
**ID:** FR-001
**Title:** Live Network Packet Capture
**Description:** The system shall capture live network packets in real time using a background Scapy sniffer thread and route each packet to the appropriate detector modules.

---

### FR-002: DDoS Detection (ML + Rules)
**ID:** FR-002
**Title:** DDoS Detection
**Description:** The system shall classify network flow features using a trained Random Forest classifier and a rule-based engine to detect DDoS attack patterns including SYN floods, UDP floods, and volumetric attacks. The system shall support configurable confidence thresholds.

---

### FR-003: ARP Spoofing & Flood Detection
**ID:** FR-003
**Title:** ARP Spoofing & Flood Detection
**Description:** The system shall monitor ARP broadcasts to detect IP-to-MAC mapping conflicts (cache poisoning), gateway MAC hijacking (critical severity), and ARP flooding (≥ 50 packets per 10 seconds). A 5-minute cooldown shall suppress duplicate spoof alerts for the same IP.

---

### FR-004: DNS Anomaly Detection
**ID:** FR-004
**Title:** DNS Anomaly Detection
**Description:** The system shall detect the following DNS-based threats:
- DNS tunnelling (subdomain label length > 60 characters)
- Suspicious TLDs (.tk, .ml, .gq, .cf, .pw, etc.)
- Fast-flux DNS (> 20 distinct IPs for a single hostname, excluding CDN whitelist)
- C2 beaconing (> 150 queries per minute to a single domain)

---

### FR-005: Brute Force & Credential Attack Detection
**ID:** FR-005
**Title:** Brute Force & Credential Attack Detection
**Description:** The system shall detect brute force attacks on authentication services (SSH, RDP, FTP, Telnet, SMTP, POP3, IMAP, SMB, MySQL, PostgreSQL, VNC, Redis), HTTP credential stuffing (≥ 80 SYN/60 s to port 80/443/8080/8443), and password spray (≥ 6 auth services × ≥ 3 SYNs each). Private/RFC-1918 source IPs shall be ignored.

---

### FR-006: Network Anomaly Detection (Isolation Forest)
**ID:** FR-006
**Title:** Network Anomaly Detection
**Description:** The system shall apply a trained Isolation Forest model to network flow features to detect statistical anomalies that do not match known attack signatures.

---

### FR-007: File Integrity Monitoring (FIM)
**ID:** FR-007
**Title:** File Integrity Monitoring
**Description:** The system shall monitor configured directories by computing SHA-256 hashes of all files at 60-second intervals and alert on file creation, modification, and deletion. Files larger than 50 MB, excluded filenames (fim_baseline.json, security_alerts.log, etc.), excluded suffixes (.pyc, .log, .tmp), and excluded directories (__pycache__, .git, venv) shall be silently skipped.

---

### FR-008: Windows Event Log Monitoring
**ID:** FR-008
**Title:** Windows Event Log Monitoring
**Description:** The system shall poll Windows Security and System event logs every 10 seconds via wevtutil and generate alerts for the following event IDs with calibrated severity: 1102 (Audit Log Cleared — critical), 4625 (Failed Logon — high), 4648 (Explicit Credential Use — medium), 4688 (Suspicious Process — high), 4698 (Scheduled Task Created — medium), 4720 (New Local Account — high), 4724 (Password Reset — low), 4732 (Added to Administrators — critical), 4756 (Universal Group Modified — high), 7045 (New Service Installed — critical).

---

### FR-009: Threat Intelligence Lookups
**ID:** FR-009
**Title:** Threat Intelligence (AbuseIPDB)
**Description:** The system shall perform asynchronous IP reputation lookups against the AbuseIPDB API for externally sourced attacker IPs. Private/RFC-1918 IPs shall be excluded from lookups. Results shall be cached to avoid redundant API calls. The system shall degrade gracefully if no API key is configured.

---

### FR-010: Email Phishing Detection (AI)
**ID:** FR-010
**Title:** Email Phishing Detection
**Description:** The system shall submit email content (subject, body, headers) to an LLM API — Groq (`llama-3.3-70b-versatile`) as the primary provider with Google Gemini 2.0 Flash as a fallback — and display a structured phishing analysis including risk score, identified indicators, and recommendations. The system shall degrade to keyword-only heuristic analysis if neither API key is configured.

---

### FR-011: URL Phishing Detection (ML)
**ID:** FR-011
**Title:** URL Phishing Detection
**Description:** The system shall classify submitted URLs as phishing or legitimate using a trained Random Forest model operating on URL-derived features (length, entropy, special character counts, domain reputation indicators).

---

### FR-012: Real-Time Alert Dashboard
**ID:** FR-012
**Title:** Real-Time Alert Dashboard
**Description:** The system shall display all generated alerts in a tabulated, real-time dashboard showing rule name, severity, source IP, timestamp, and message. Alerts shall be colour-coded by severity (critical — red, high — orange, medium — yellow, low — blue).

---

### FR-013: Alert Filtering and Management
**ID:** FR-013
**Title:** Alert Filtering and Management
**Description:** The system shall allow administrators to filter alerts by severity and category, clear the alert list, and export alerts to the security log file.

---

### FR-014: IP Blocking and Allow-List Management
**ID:** FR-014
**Title:** IP Blocking and Allow-List Management
**Description:** The system shall allow administrators to block specific IP addresses (manually, or automatically from a detector alert) via Windows Firewall rules, with an optional rollback timer that automatically removes a block after a configurable duration. Blocked IPs shall be persisted to `blocked_ips.json` and survive application restarts.

---

### FR-015: System Health Monitoring
**ID:** FR-015
**Title:** System Health Monitoring
**Description:** The system shall display real-time CPU usage, RAM usage, disk usage, and network I/O statistics. A calculated health percentage shall be displayed with colour-coded status (green ≥ 70%, amber ≥ 40%, red < 40%).

---

### FR-016: Cookie / Session Threat Detection
**ID:** FR-016
**Title:** Cookie / Session Threat Detection
**Description:** The system shall sniff live HTTP `Set-Cookie` headers and classify each cookie as benign or tracking/malicious using a trained SVM model over cookie attributes (third-party origin, secure flag, HttpOnly flag, expiry duration).

---

### FR-017: TLS Metadata Inspection
**ID:** FR-017
**Title:** TLS Metadata Inspection (Deep Packet Inspection)
**Description:** The system shall parse TLS Client Hello packets without decrypting traffic, extracting the SNI hostname, negotiated TLS version, offered cipher suites, and a JA3 client fingerprint, to flag unusual or malware-associated TLS clients.

---

### FR-018: Network Vulnerability Scanning
**ID:** FR-018
**Title:** Network Vulnerability Scanning
**Description:** The system shall scan a single IP, hostname, or CIDR range (up to /24) across 23 common ports, perform banner grabbing where possible, and highlight high-risk open ports — using a pure-Python socket scanner with no external tools (e.g. nmap) required.

---

### FR-019: User & Entity Behaviour Analytics (UEBA)
**ID:** FR-019
**Title:** User & Entity Behaviour Analytics
**Description:** The system shall build a per-user activity baseline from Windows Event Log data and alert on behavioural anomalies, including off-hours logins (outside the user's normal working hours) and logins from a new or previously unseen workstation.

---

### FR-020: Network Topology & Geolocation Map
**ID:** FR-020
**Title:** Network Topology & Geolocation Map
**Description:** The system shall geolocate attacker IPs via a free IP geolocation API and render an interactive Leaflet.js map (via the `folium` library) showing attacker locations, saved as a standalone HTML file the administrator can open in any browser.

---

### FR-021: Adaptive Model Retraining
**ID:** FR-021
**Title:** Adaptive Model Retraining from Analyst Feedback
**Description:** The system shall let an administrator label a flow's true verdict (correcting the model), persist labelled samples to a feedback buffer, and retrain a calibrated Random Forest on the combined original + feedback dataset on demand. The system shall evaluate the retrained model against the current model and only replace it if accuracy improves, versioning prior models for rollback. A lightweight online classifier shall blend into live predictions immediately after feedback, ahead of a full retrain.

---

### FR-022: Adversarial ML Security Lab
**ID:** FR-022
**Title:** Adversarial ML Security Lab
**Description:** The system shall provide an academic AI-security workbench with four components: (1) a **Model Analyzer** computing accuracy, F1, confusion matrix, and ROC/PR curves from a dataset sample; (2) a **Feature Explainer** surfacing per-prediction XAI using Random Forest feature importances; (3) an **Adversarial Engine** running a greedy FGSM-style evasion attack against the DDoS classifier's tabular features to test its robustness; and (4) a **Security Scorer** producing a composite AI Security Score (0–100) from the above.

---

### FR-023: Web / Mobile Companion Dashboard
**ID:** FR-023
**Title:** Web / Mobile Companion Dashboard
**Description:** The system shall expose a Flask-based, multi-tenant, JWT-authenticated web API and mobile-responsive dashboard (default port 8080) mirroring live alerts, statistics, and blocked-IP data from the desktop application, for viewing on a phone or browser on the same network. Authentication shall use a demo login (configurable via the `MONITOR_PASSWORD` environment variable) issuing short-lived JWTs; unauthenticated requests to alert/stat endpoints shall be rejected with HTTP 401.

---

### FR-024: QR Code Alert Sharing
**ID:** FR-024
**Title:** QR Code Alert Sharing
**Description:** The system shall generate a QR code encoding a selected alert's details so it can be quickly shared to a mobile device for incident handoff, without requiring the recipient to have network access to the monitored host.

---

### FR-025: File Scanner (USB & Download Monitoring)
**ID:** FR-025
**Title:** File Scanner — USB & Download Monitoring
**Description:** The system shall detect newly inserted removable/USB drives and monitor the downloads folder for new files, performing heuristic analysis and an optional free cloud hash lookup (MalwareBazaar, no API key required) to flag potentially malicious files.

---

## 4.2 Non-Functional Requirements (NFRs)

### Performance Requirements

**NFR-001: Packet Processing Throughput**
The system shall process captured network packets within 50 milliseconds per packet under normal operating conditions to avoid packet queue backlog.

**NFR-002: Dashboard Responsiveness**
All UI updates shall be performed via Qt signals emitted from background threads to ensure the GUI remains responsive during active threat detection.

**NFR-003: Concurrent Detector Operation**
All detector modules (ARP, DNS, Brute Force, DDoS, FIM, Event Log, Threat Intel) shall operate concurrently as independent daemon threads without blocking each other.

---

### Security Requirements

**NFR-004: Secret Management**
All API keys (GROQ_API_KEY, GEMINI_API_KEY, ABUSEIPDB_API_KEY) and the web dashboard's demo password (MONITOR_PASSWORD) shall be loaded exclusively from environment variables via a `.env` file using python-dotenv. Keys shall never be hardcoded in source files, and `.env` shall be excluded from version control via `.gitignore`.

**NFR-005: Minimal Attack Surface**
The monitoring agent shall not open any listening network ports. All external communication shall be outbound-only (AbuseIPDB and Gemini API calls).

**NFR-006: Privilege Separation**
Network packet sniffing requires administrator/root privileges. The application shall clearly communicate when elevated privileges are unavailable and degrade gracefully by disabling packet-level detectors.

---

### Usability Requirements

**NFR-007: Professional Dark-Themed UI**
The desktop interface shall use a professional dark colour palette (backgrounds: #0c1020–#0f1326, accent: #3b82f6) implemented in PyQt6 QSS stylesheets.

**NFR-008: Intuitive Navigation**
The sidebar navigation shall clearly indicate the active section using highlighted buttons (blue accent background) and the dashboard shall be understandable to administrators without cybersecurity expertise.

**NFR-009: Informative Alert Display**
Every alert shall include a human-readable description, severity label, source IP, timestamp, and the specific rule that triggered the alert.

---

### Reliability Requirements

**NFR-010: Graceful Degradation**
If Scapy is unavailable, the ML model is not trained, or an API key is not configured, the system shall disable the affected module and continue operating with the remaining detectors.

**NFR-011: False Positive Minimisation**
All detection thresholds shall be calibrated so that normal office network activity (email clients, browser traffic, SSH sessions, DNS queries) does not trigger alerts under typical conditions.

**NFR-012: Thread Safety**
All shared data structures accessed by multiple detector threads shall be protected by threading locks to prevent race conditions and data corruption.

---

### Maintainability Requirements

**NFR-013: Modular Detector Architecture**
Each threat detector shall be implemented as an independent Python class in its own file under the `detectors/` directory. Adding a new detector shall not require modifying existing detector code.

**NFR-014: Configurable Parameters**
All detection thresholds, watch directories, API endpoints, and operational parameters shall be configurable via environment variables loaded through `config.py`, without modifying source code.

---

### Scalability Requirements

**NFR-015: Extensible Alert Pipeline**
The alert callback system (`on_alert: Callable[[dict], None]`) shall allow new consumers (log file writers, external SIEMs, notification services) to be added without modifying detector code.

---

---

# Chapter 5: System Modelling

## 5.1 Use Case Model

### 5.1.1 Use Case Diagram

**Actors:**
- **Administrator** — Primary user who monitors the dashboard, manages IPs, configures settings.
- **Network Sniffer (Scapy)** — External system that provides live packet data.
- **AbuseIPDB API** — External threat intelligence service.
- **Groq / Google Gemini API** — External LLM services for phishing analysis (Groq primary, Gemini fallback).
- **Windows Event Log** — External system data source (also feeds the UEBA behavioural baseline).
- **IP Geolocation API** — External service used to plot attacker locations on the geo map.
- **MalwareBazaar API** — External free hash-reputation lookup used by the File Scanner.
- **Mobile / Browser Client** — Secondary client that authenticates to the web companion dashboard over the LAN.

**Core Use Cases:**

```
┌─────────────────────────────────────────────────────────────────┐
│                 Network Security Monitor System                 │
│                                                                 │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │  View Live Alerts   │    │  Analyse Email (Phishing) │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │  Block / Allow IP   │    │  Analyse URL (Phishing)   │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │ Configure FIM Dirs  │    │  View System Health       │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │  Filter Alerts      │    │  Train ML Models          │        │
│  └─────────────────────┘    └──────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘

Administrator ──────► View Live Alerts
Administrator ──────► Block / Allow IP
Administrator ──────► Analyse Email (Phishing)
Administrator ──────► Analyse URL (Phishing)
Administrator ──────► Configure FIM Dirs
Administrator ──────► Filter Alerts
Administrator ──────► View System Health
Administrator ──────► Train ML Models

Network Sniffer ───► «triggers» DDoS Detection
Network Sniffer ───► «triggers» ARP Detection
Network Sniffer ───► «triggers» DNS Detection
Network Sniffer ───► «triggers» Brute Force Detection

AbuseIPDB API ─────► «include» Threat Intelligence Lookup
Groq / Gemini API ─► «include» Email Phishing Analysis
Windows Event Log ─► «include» Event Log Monitoring
Windows Event Log ─► «include» UEBA Baseline Building
IP Geolocation API ► «include» Geo Map Rendering
MalwareBazaar API ─► «include» File Scanner Hash Lookup
```

**Extended Use Cases (added as the project grew beyond the original six-tab scope):**

```
┌─────────────────────────────────────────────────────────────────┐
│           Network Security Monitor System — Extended            │
│                                                                 │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │ Scan Vulnerabilities │    │  View Geo Map             │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │ Retrain from Feedback│    │  Run Evasion Test (Adv.)  │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │ View AI Security Score│   │  Login to Web Dashboard   │        │
│  └─────────────────────┘    └──────────────────────────┘        │
│  ┌─────────────────────┐    ┌──────────────────────────┐        │
│  │ Share Alert via QR   │    │  Inspect TLS Fingerprint  │        │
│  └─────────────────────┘    └──────────────────────────┘        │
└─────────────────────────────────────────────────────────────────┘

Administrator ──────► Scan Vulnerabilities
Administrator ──────► Retrain from Feedback
Administrator ──────► View AI Security Score
Administrator ──────► Share Alert via QR
Administrator ──────► View Geo Map
Administrator ──────► Run Evasion Test (Adversarial Lab)
Administrator ──────► Inspect TLS Fingerprint

Mobile / Browser Client ──► Login to Web Dashboard
Mobile / Browser Client ──► «include» View Live Alerts (read-only, remote)
```

---

### 5.1.2 Detailed Use Case Descriptions

**Use Case Name: View Live Alerts**
**Actor:** Administrator
**Pre-condition:** The system is running and at least one detector module is active.
**Post-condition:** The administrator views current security alerts on the dashboard.

Main Success Scenario:
1. The administrator launches the application.
2. The system starts all detector modules in background threads.
3. Detector modules process events and emit alerts via callback functions.
4. The dashboard tab displays alerts in a colour-coded table with severity, source IP, rule name, and timestamp.
5. The administrator reviews and acts on the alerts.

Alternate Flow:
2a. If Scapy is unavailable (no admin rights), packet-based detectors are disabled; FIM and Event Log detectors continue.

---

**Use Case Name: Block / Allow IP**
**Actor:** Administrator
**Pre-condition:** An alert has been raised for a specific source IP.
**Post-condition:** The IP is added to the blocked list and persisted to `blocked_ips.json`.

Main Success Scenario:
1. The administrator views an alert for a suspicious IP address.
2. The administrator selects the IP and clicks "Block IP."
3. The system adds the IP to the blocked list.
4. The system persists the blocked list to `blocked_ips.json`.
5. A confirmation message is displayed.

Alternate Flow:
3a. If the IP is already blocked, the system notifies the administrator and takes no action.

---

**Use Case Name: Analyse Email (Phishing Detection)**
**Actor:** Administrator
**Pre-condition:** GEMINI_API_KEY is configured in the `.env` file.
**Post-condition:** A phishing risk assessment is displayed for the submitted email.

Main Success Scenario:
1. The administrator navigates to the Email Phishing tab.
2. The administrator pastes email subject, body, and headers into the input fields.
3. The administrator clicks "Analyse."
4. The system sends the email content to the Google Gemini 2.0 Flash API.
5. The system displays the AI analysis including risk score, identified phishing indicators, and recommendations.

Alternate Flow:
4a. If the API key is missing or the API call fails, the system displays an error message and suggests configuring the key in `.env`.

---

**Use Case Name: Analyse URL (Phishing Detection)**
**Actor:** Administrator
**Pre-condition:** The URL phishing ML model has been trained.
**Post-condition:** The submitted URL is classified as phishing or legitimate.

Main Success Scenario:
1. The administrator navigates to the URL Phishing tab.
2. The administrator enters a URL in the input field.
3. The administrator clicks "Check URL."
4. The system extracts features from the URL (length, entropy, special characters, subdomain count, etc.).
5. The trained Random Forest model classifies the URL.
6. The result (Phishing / Legitimate) and confidence score are displayed.

Alternate Flow:
4a. If the model is not trained, the system displays a "Model not available — please run training" message.

---

**Use Case Name: Configure File Integrity Monitoring**
**Actor:** Administrator
**Pre-condition:** The FIM module is active.
**Post-condition:** FIM watches the newly configured directories.

Main Success Scenario:
1. The administrator opens the System Monitor tab.
2. The administrator updates the FIM_WATCH_DIRS environment variable in `.env`.
3. The system reloads the configuration on next startup.
4. The FIM module scans the configured directories and establishes a new baseline.
5. Future file changes in those directories generate alerts.

Alternate Flow:
3a. If the configured directory does not exist, the FIM module skips it silently and logs a warning.

---

**Use Case Name: Train ML Models**
**Actor:** Administrator
**Pre-condition:** Training dataset (CIC-DDoS2019 CSV) is available.
**Post-condition:** Trained model file is saved and ready for detection.

Main Success Scenario:
1. The administrator runs `python train_model.py` from the command line.
2. The training script loads the CIC-DDoS2019 dataset.
3. Features are extracted, scaled (StandardScaler), and the Random Forest classifier is trained.
4. The F1-optimal confidence threshold is computed and stored with the model.
5. The model is saved as `ddos_detector_model.joblib`.
6. The DDoS detector loads the model on next application startup.

---

**Use Case Name: Retrain Model from Analyst Feedback (Adaptive Learning)**
**Actor:** Administrator
**Pre-condition:** At least a handful of flows have been labelled as feedback (corrected verdicts).
**Post-condition:** A new candidate model is trained, evaluated, and — if it beats the current model — deployed and versioned.

Main Success Scenario:
1. The administrator opens the Adaptive Training tab and reviews accumulated feedback samples.
2. The administrator triggers a retrain.
3. The system merges the original training data with the (oversampled) feedback data.
4. A new calibrated Random Forest is trained and evaluated against a held-out split.
5. If the new model's F1/accuracy improves on the currently deployed model, it replaces it and the previous model is archived under `model_versions/` for rollback.
6. The administrator sees a before/after metrics comparison.

Alternate Flow:
4a. If fewer than 5 samples of either class exist, the system refuses to retrain and asks for more feedback.
5a. If the new model does not improve on the current one, it is discarded and the current model stays deployed.

---

**Use Case Name: Run Adversarial Evasion Test**
**Actor:** Administrator (security analyst persona)
**Pre-condition:** The DDoS classifier is trained and loaded.
**Post-condition:** The administrator sees whether — and by how much — a known attack profile's features can be perturbed to evade the classifier, plus a composite AI Security Score.

Main Success Scenario:
1. The administrator opens the Adversarial Lab tab.
2. The administrator selects an attack profile (e.g. SYN Flood) and starts the evasion test.
3. The Adversarial Engine greedily perturbs the profile's numeric features (FGSM-style) within realistic bounds, re-scoring against the classifier after each step.
4. The system reports whether evasion succeeded, how many perturbation steps it took, and which features were most responsible (via the Feature Explainer's importances).
5. The Security Scorer combines robustness, accuracy, and calibration into a single 0–100 AI Security Score for the current model.

Alternate Flow:
3a. If the model cannot be evaded within the step budget, the system reports the profile as robust and still shows the closest near-miss found.

---

## 5.2 Dynamic Models

### 5.2.1 Activity Diagram — Packet Detection Workflow

```
[START]
    │
    ▼
Scapy captures raw network packet
    │
    ▼
Route packet to all registered detectors
    ├─────────────────────────────────────────┐
    │                                         │
    ▼                                         ▼
ARP Monitor:                          DNS Monitor:
- Extract src_ip, hwsrc              - Extract query name
- Compare with ARP cache             - Check label length > 60
- Check rate > 50/10 s               - Check TLD in risky set
    │                                - Check flux threshold > 20
    │ [mismatch detected]            - Check rate > 150/min
    ▼                                         │
Generate ARP Alert                  [anomaly detected]
    │                                         ▼
    ▼                                Generate DNS Alert
Brute Force Monitor:                          │
- Check if SYN flag                           ▼
- Check if src_ip is private         Flow Tracker:
- Count SYN/60s per port             - Accumulate flow features
    │                                - When flow complete →
    │ [threshold exceeded]           - DDoS ML predict()
    ▼                                         │
Generate BF Alert                   [attack detected]
                                              ▼
                                    Generate DDoS Alert
    │
    ▼
Alert published via on_alert() callback
    │
    ▼
Dashboard receives alert via Qt signal
    │
    ▼
Alert displayed in real-time table with severity colour
    │
[END]
```

---

### 5.2.2 Sequence Diagram — DDoS Detection Flow

```
Administrator  App (PyQt6)  Sniffer Thread  DDosDetector  Dashboard

     │              │               │               │           │
     │ Launch App   │               │               │           │
     │─────────────►│               │               │           │
     │              │ start()       │               │           │
     │              │──────────────►│               │           │
     │              │               │ sniff(filter) │           │
     │              │               │──────────────►│           │
     │              │               │               │           │
     │              │               │ [packet arrives]          │
     │              │               │ on_packet(pkt)│           │
     │              │               │──────────────►│           │
     │              │               │               │ flow_update│
     │              │               │               │──────────►│
     │              │               │               │           │
     │              │               │               │[flow complete]
     │              │               │               │ predict() │
     │              │               │               │──────────►│
     │              │               │               │           │
     │              │               │               │ verdict=ATTACK
     │              │               │               │◄──────────│
     │              │               │               │           │
     │              │ emit(alert)   │               │           │
     │              │◄──────────────────────────────│           │
     │              │               │               │           │
     │              │ update_table(alert)            │           │
     │              │──────────────────────────────────────────►│
     │              │               │               │           │
     │ [sees alert] │               │               │           │
     │◄─────────────│               │               │           │
```

---

## 5.3 Structural Model

### 5.3.1 Class Diagram

```
┌──────────────────────────────────┐
│          MainWindow (PyQt6)      │
│ - _alert_log: list[dict]         │
│ - _sniffer: SnifferThread        │
│ - _detectors: list               │
│ + _build()                       │
│ + _on_alert(alert: dict)         │
│ + _on_sniffer_status(msg: str)   │
│ + _update_health()               │
└──────────────────────────────────┘
          │ uses (1..*)
          ▼
┌──────────────────────────────────┐
│     SnifferThread (QThread)      │
│ - filter: str                    │
│ - detectors: list                │
│ + run()                          │
│ + stop()                         │
│ + on_packet(pkt)                 │
└──────────────────────────────────┘
          │ routes to
    ┌─────┴──────────────────────────┐
    │                                │
    ▼                                ▼
┌──────────────────┐    ┌────────────────────────┐
│   ARPMonitor     │    │    DNSMonitor           │
│ _FLOOD_THRESH=50 │    │ _FLUX_THRESH=20         │
│ _SPOOF_COOLDOWN  │    │ _RATE_THRESH=150        │
│  =300            │    │ _MAX_LABEL_LEN=60       │
│ + process_packet │    │ + process_packet()      │
│ + get_arp_table  │    └────────────────────────┘
└──────────────────┘
    ▼                                ▼
┌──────────────────┐    ┌────────────────────────┐
│BruteForceDetector│    │    DDosDetector         │
│ _THRESH_AUTH=25  │    │ + model: RandomForest   │
│ _THRESH_HTTP=80  │    │ + scaler: StandardScaler│
│ _SPRAY_PORTS=6   │    │ + predict(features)     │
│ + process_packet │    │ + check_rules(pkt_info) │
└──────────────────┘    └────────────────────────┘
    ▼                                ▼
┌──────────────────┐    ┌────────────────────────┐
│   FIMMonitor     │    │  EventLogMonitor        │
│ _POLL_SECONDS=60 │    │ _POLL_SECONDS=10        │
│ _baseline: dict  │    │ _WATCHED: dict          │
│ + rescan_now()   │    │ + is_available()        │
│ + start()        │    │ + start()               │
└──────────────────┘    └────────────────────────┘
    ▼                                ▼
┌──────────────────┐    ┌────────────────────────┐
│  ThreatIntel     │    │  AnomalyDetector        │
│ + check_ip_async │    │ + model: IsolationForest│
│ + get_cached()   │    │ + score(features)       │
│ + is_ready()     │    └────────────────────────┘
└──────────────────┘
          │ all share
          ▼
┌──────────────────────────────────┐
│         Alert (dict)             │
│ rule_name: str                   │
│ severity: str (critical/high/    │
│           medium/low)            │
│ source_ip: str                   │
│ message: str                     │
│ timestamp: str                   │
│ category: str                    │
└──────────────────────────────────┘
```

---

## 5.4 Data Flow Model

### 5.4.1 Context Diagram

```
                    ┌─────────────────┐
  Raw Packets       │                 │  Alerts, Stats,
 ─────────────────► │    Security     │ ─────────────────►  Administrator
                    │    Monitor      │
 Event Log Data ──► │    System       │
                    │                 │
 IP Reputation ───► │                 │ ──► Blocked IP List
                    └─────────────────┘
         ▲                  │
         │                  ▼
    Gemini API         Log File
   AbuseIPDB API   (security_alerts.log)
```

### 5.4.2 Level-1 DFD

```
User ──► Login Details ──► [1.0 Authenticate / Launch]
                                │
                                ▼
              ┌────────────────────────────────┐
              │    [2.0 Packet Capture]        │
              │    Scapy sniffer thread         │
              └────────────────────────────────┘
                     │             │
          ┌──────────┘             └──────────┐
          ▼                                   ▼
[3.0 Network Detection]          [4.0 System Detection]
- ARP Monitor                    - FIM Monitor
- DNS Monitor                    - Event Log Monitor
- Brute Force Detector           - Anomaly Detector
- DDoS Classifier                         │
          │                               │
          └─────────────┬─────────────────┘
                        ▼
              [5.0 Alert Processing]
              - Severity assignment
              - Deduplication
              - Threat Intel enrichment
                        │
              ┌─────────┴──────────┐
              ▼                    ▼
   [D1 Alert Store]        [6.0 Dashboard Display]
   security_alerts.log     PyQt6 real-time table
              │
              ▼
   [7.0 Report Generation]
   Statistics, health, blocked IPs
```

---

---

# Chapter 6: Implementation

## 6.1 Technology Stack Details

| Layer | Technology | Justification |
|---|---|---|
| Desktop UI | PyQt6 | Cross-platform native Qt GUI; supports signals/slots for thread-safe UI updates |
| Backend / Detection Logic | Python 3.13 | Rich ecosystem for networking, ML, and system APIs; all libraries available |
| ML Classification | scikit-learn (RandomForest, IsolationForest, SVM) | Battle-tested, well-documented ML framework; joblib serialisation for model persistence |
| Packet Capture & Analysis | Scapy | Full control over raw packet inspection at L2/L3/L4; supports ARP, DNS, TCP, UDP, IP |
| AI Phishing Analysis | Google Gemini 2.0 Flash API | Large language model capable of nuanced email phishing reasoning beyond rule-based patterns |
| Threat Intelligence | AbuseIPDB REST API | Free tier provides IP reputation data for 1,000 checks/day; widely trusted in the industry |
| Secret Management | python-dotenv | Industry-standard approach; keys loaded from `.env` file, never stored in source code |
| Data Persistence | JSON files (blocked_ips.json, fim_baseline.json) | Lightweight, human-readable; no database server required for deployment |
| Version Control | Git / GitHub | Standard version control for collaboration and project tracking |
| Diagrams | PlantUML, Draw.io | Professional UML diagram tools for system modelling documentation |

---

## 6.2 Key Algorithms & Code Snippets

### 1. ARP Cache Poisoning Detection

**Purpose:** Tracks IP-to-MAC mappings from live ARP traffic and alerts when a known IP claims a different MAC address, indicating a possible Man-in-the-Middle (MitM) attack.

```python
def process_packet(self, pkt) -> None:
    arp = pkt.getlayer(ARP)
    src_ip  = arp.psrc or ""
    src_mac = (arp.hwsrc or "").lower()

    with self._lock:
        # Flood detection: count ARP packets per MAC per 10 s
        bucket = self._rate.setdefault(src_mac, [])
        self._rate[src_mac] = [t for t in bucket if now - t < self._FLOOD_WINDOW]
        self._rate[src_mac].append(now)
        if len(self._rate[src_mac]) == self._FLOOD_THRESH:
            self._alert_cb({"rule_name": "ARP Flood", "severity": "high", ...})

        # Spoofing detection: compare with known IP→MAC mapping
        known = self._cache.get(src_ip)
        if known is None:
            self._cache[src_ip] = src_mac          # First-seen: learn
        elif known != src_mac:
            last_alert = self._spoof_ts.get(src_ip, 0.0)
            if now - last_alert >= self._SPOOF_COOLDOWN:  # 5-minute cooldown
                self._spoof_ts[src_ip] = now
                is_gw = src_ip == self._gateway_ip
                self._alert_cb({
                    "rule_name": "ARP Spoofing" + (" — Gateway!" if is_gw else ""),
                    "severity":  "critical" if is_gw else "high",
                    "message":   f"ARP cache poisoning: {src_ip} changed MAC "
                                 f"from {known} to {src_mac}",
                })
```

**Key Design Decisions:**
- A 5-minute cooldown (`_SPOOF_COOLDOWN = 300`) prevents alert flooding for the same attacker.
- The flood threshold (`_FLOOD_THRESH = 50`) was raised from 20 to avoid false positives from legitimate ARP activity on large networks.
- Gateway IP is monitored with critical severity since gateway MAC hijacking enables full traffic interception.

---

### 2. Brute Force Detection with Private IP Filter

**Purpose:** Detects credential attacks on authentication services while ignoring the monitored machine's own outgoing connections (which would generate false positives from email clients, SSH sessions, etc.).

```python
def _is_private(ip: str) -> bool:
    """Return True for RFC-1918 / loopback / link-local addresses."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def process_packet(self, pkt) -> None:
    src_ip   = pkt[IP].src
    dst_port = pkt[TCP].dport

    # CRITICAL: skip the machine's own outgoing connections
    if _is_private(src_ip):
        return

    with self._lock:
        # Brute force: count SYN packets to same auth port within 60 s
        self._conn[src_ip][dst_port] = [
            t for t in self._conn[src_ip][dst_port]
            if now - t < _WINDOW
        ]
        self._conn[src_ip][dst_port].append(now)
        count = len(self._conn[src_ip][dst_port])

        if dst_port in _AUTH_PORTS and count == _THRESH_AUTH:  # 25 SYNs
            self._alert_cb({
                "rule_name": f"{_AUTH_PORTS[dst_port]} Brute Force",
                "severity":  "high",
                "message":   f"Brute force: {count} {_AUTH_PORTS[dst_port]} "
                             f"attempts from {src_ip} within {_WINDOW}s",
            })

        # Password spray: one IP hitting 6+ auth services with 3+ SYNs each
        active_auth = [
            p for p in _AUTH_PORTS
            if len(self._conn[src_ip].get(p, [])) >= _SPRAY_MIN_SYN
        ]
        if len(active_auth) == _SPRAY_PORTS:
            self._alert_cb({
                "rule_name": "Password Spray",
                "severity":  "critical",
            })
```

**Key Design Decisions:**
- `_is_private()` uses Python's `ipaddress` module which in Python 3.11+ considers all IANA special-purpose addresses (including TEST-NET ranges) as private.
- The threshold `_THRESH_AUTH = 25` was calibrated to avoid false positives from normal reconnection bursts.
- Password spray requires `_SPRAY_PORTS = 6` services × `_SPRAY_MIN_SYN = 3` SYNs — preventing false positives from machines with multiple legitimate service connections.

---

### 3. DNS Anomaly Detection

**Purpose:** Detects DNS-based attack techniques including data exfiltration via tunnelling, fast-flux botnet infrastructure, C2 beaconing, and queries to high-risk TLDs.

```python
def process_packet(self, pkt) -> None:
    dns  = pkt[DNS]
    qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")

    # 1. DNS Tunneling: abnormally long subdomain labels suggest encoded data
    labels = qname.split(".")
    max_label = max((len(l) for l in labels), default=0)
    if max_label > _MAX_LABEL_LEN:         # threshold: 60 characters
        self._alert_cb({"rule_name": "DNS Tunneling", "severity": "critical", ...})

    # 2. Suspicious TLD check
    for tld in _RISKY_TLDS:
        if qname.endswith(tld):
            self._alert_cb({"rule_name": "Suspicious TLD", "severity": "medium", ...})

    # 3. C2 Beaconing: high query rate to same domain
    parts = qname.split(".")
    domain = ".".join(parts[-2:]) if len(parts) >= 2 else qname
    window = self._query_rate.setdefault(domain, [])
    self._query_rate[domain] = [t for t in window if now - t < 60]
    self._query_rate[domain].append(now)
    if len(self._query_rate[domain]) == _RATE_THRESH:   # 150 queries/min
        self._alert_cb({"rule_name": "DNS C2 Beacon", "severity": "high", ...})

def _check_fast_flux(self, qname: str, rdata: str) -> None:
    # Skip CDN domains — they legitimately have many IPs (anycast)
    parts = qname.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else qname
    if registrable in _CDN_DOMAINS or qname in _CDN_DOMAINS:
        return

    # Track distinct IPs per domain
    self._flux[qname].add(rdata)
    if len(self._flux[qname]) == _FLUX_THRESH:          # 20 distinct IPs
        self._alert_cb({"rule_name": "Fast-Flux DNS", "severity": "high", ...})
```

**Key Design Decisions:**
- `.xyz` was deliberately removed from `_RISKY_TLDS` because Alphabet (Google) uses `abc.xyz` legitimately.
- A 34-domain CDN whitelist prevents fast-flux false positives on Google, Cloudflare, AWS CloudFront, Akamai, etc.
- The C2 beacon threshold (150 queries/minute) was calibrated to avoid alerting on legitimate DNS-based health checks and monitoring agents.

---

### 4. DDoS ML Detection

**Purpose:** Classifies network flows as ATTACK, SUSPICIOUS, or NORMAL using a trained Random Forest model, with a calibrated confidence threshold.

```python
def predict(self, features: dict) -> dict:
    """
    Run ML prediction on a flow feature dict.
    Returns verdict (ATTACK/SUSPICIOUS/NORMAL), confidence, and threshold used.
    """
    if not self.model_ready:
        return {"error": "Model not loaded. Run: python train_model.py"}
    try:
        # Build feature vector from model's stored feature names
        vals = [float(features.get(f, 0)) for f in self.feature_names]
        X    = np.array(vals, dtype=np.float64).reshape(1, -1)
        X_sc = self.scaler.transform(X)

        proba_attack = float(self.model.predict_proba(X_sc)[0][1])
        t            = self.threshold   # F1-optimal threshold from training

        if proba_attack >= t:
            verdict = "ATTACK"
        elif proba_attack >= t * 0.70:
            verdict = "SUSPICIOUS"    # within 30% of threshold → warn
        else:
            verdict = "NORMAL"

        return {
            "verdict":      verdict,
            "confidence":   round(proba_attack * 100, 2),
            "threshold":    round(t * 100, 2),
        }
    except Exception as e:
        return {"error": str(e)}
```

**Key Design Decisions:**
- The confidence threshold is computed during training as the F1-optimal operating point and stored in the `.joblib` model file — it is not hardcoded.
- A "SUSPICIOUS" zone (70–100% of threshold) allows administrators to investigate borderline cases without immediately triggering critical alerts.
- Feature names are stored with the model to ensure consistent feature ordering regardless of input dict key ordering.

---

### 5. File Integrity Monitor (FIM)

**Purpose:** Detects unauthorised file creation, modification, and deletion in watched directories by comparing SHA-256 hashes against a stored baseline.

```python
def _scan_all(self) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for d in self._dirs:
        for f in d.rglob("*"):
            if not f.is_file():
                continue
            # Skip excluded directories (e.g. __pycache__, .git, venv)
            if any(part in _EXCLUDE_DIRS for part in f.parts):
                continue
            # Skip self-referential runtime files
            if f.name in _EXCLUDE_NAMES:    # fim_baseline.json, logs, etc.
                continue
            # Skip transient file types (.pyc, .log, .tmp, .lock)
            if f.suffix.lower() in _EXCLUDE_SUFFIXES:
                continue
            if f.stat().st_size > _MAX_FILE_BYTES:  # skip files > 50 MB
                continue
            h = self._hash_file(f)
            if h:
                hashes[str(f)] = h
    return hashes

@staticmethod
def _hash_file(path: Path) -> str:
    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            sha.update(chunk)
    return sha.hexdigest()
```

**Key Design Decisions:**
- `fim_baseline.json` is in `_EXCLUDE_NAMES` because FIM writes it every 60 seconds — without exclusion it would continuously alert on its own output.
- The default watched directory is `detectors/` (stable Python source files), not the project root, to avoid constant alerts from dynamic runtime files.
- 65 KB read chunks balance memory usage and I/O efficiency for large files.

---

### 6. Windows Event Log Monitor

**Purpose:** Polls the Windows Security and System event logs every 10 seconds for threat-relevant event IDs using the built-in `wevtutil` command-line tool.

```python
_WATCHED: dict[int, tuple[str, str]] = {
    1102: ("Audit Log Cleared",        "critical"),   # log tampering
    4625: ("Failed Logon",             "high"),       # credential attack
    4648: ("Explicit Credential Use",  "medium"),     # pass-the-hash
    4688: ("Process Created",          "medium"),     # suspicious process
    4698: ("Scheduled Task Created",   "medium"),     # persistence (calibrated)
    4720: ("New Local Account",        "high"),       # account creation
    4724: ("Password Reset Attempt",   "low"),        # legitimate but notable
    4732: ("Added to Administrators",  "critical"),   # privilege escalation
    4756: ("Universal Group Modified", "high"),
    7045: ("New Service Installed",    "critical"),   # rootkit/persistence
}

def _poll(self, channel: str) -> None:
    since = (datetime.now(timezone.utc) - timedelta(seconds=25)).strftime(...)
    ids_clause = " or ".join(f"EventID={eid}" for eid in _WATCHED)
    query = f"*[System[({ids_clause}) and TimeCreated[@SystemTime>='{since}']]]"

    result = subprocess.run(
        ["wevtutil", "qe", channel,
         f"/q:{query}", "/f:xml", "/rd:true", "/c:100"],
        capture_output=True, text=True, encoding="utf-8",
        timeout=10,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    # Parse XML response and emit alerts for each matching event
    root = ET.fromstring(f"<Events>{result.stdout}</Events>")
    for event in root.findall("Event"):
        self._process(event)
```

**Key Design Decisions:**
- `CREATE_NO_WINDOW` flag prevents a console window flashing on each 10-second poll.
- Event 4698 (Scheduled Task) was calibrated to "medium" (not "high") because software installers routinely create scheduled tasks.
- Event 4724 (Password Reset) was calibrated to "low" because users frequently reset their own passwords legitimately.
- A deduplication set (`_seen_ids`) based on `EventRecordID` prevents the same event from alerting twice due to overlapping poll windows.

---

## 6.3 User Interfaces

### Dashboard Overview

The main application window uses a **dark-themed PyQt6 interface** with a fixed left sidebar (224 px) and a tabbed main content area. The colour scheme uses dark navy backgrounds (#0c1020, #0f1326) with a blue accent (#3b82f6) for navigation and interactive elements.

**Key UI Components:**

**1. Sidebar Navigation**
- Branded header section with application name and icon
- Navigation buttons with active-state highlighting (blue background + border when selected)
- Status indicators using coloured circles (◉) for sniffer, FIM, and event log status
- Real-time sniffer connection status

**2. Dashboard Tab (Home)**
- Four stat cards displaying total alerts, critical alerts, blocked IPs, and files monitored
- Cards use an icon-on-right layout with large bold metric numbers in threat-colour
- Real-time alert feed table with columns: Severity | Rule Name | Source IP | Timestamp | Message

**3. Network Monitor Tab**
- Real-time packet counter and protocol distribution display
- Per-IP tracker panel showing connection rates, SYN/ACK ratios, and port spread
- Flow classification results with ML confidence scores

**4. Detectors Tab**
- Individual status cards for each detector module (ARP, DNS, BruteForce, DDoS, FIM, EventLog, ThreatIntel)
- Alert counts per detector
- Configuration controls for thresholds

**5. Email Phishing Tab**
- Multi-line text inputs for email subject, body, and headers
- "Analyse" button that calls the Gemini API
- Formatted output panel displaying AI analysis with risk score and indicators

**6. URL Phishing Tab**
- URL input field with "Check URL" button
- Result panel showing ML verdict (PHISHING/LEGITIMATE) and confidence percentage

**7. System Monitor Tab**
- CPU, RAM, Disk, and Network I/O gauges updated every 2 seconds
- Health percentage displayed with dynamic colour (green/amber/red)
- FIM baseline statistics (files monitored, last scan time)

---

## 6.4 Open-Source Libraries Used

| Library | Version | Purpose |
|---|---|---|
| PyQt6 / PyQt6-WebEngine | 6.x | Desktop GUI framework (widgets, signals/slots, QSS styling); embedded browser for the geo map view |
| scikit-learn | 1.x | Random Forest, Isolation Forest, SVM, StandardScaler, joblib model I/O |
| Scapy | 2.x | Raw packet capture, crafting, and protocol dissection (also used for TLS Client Hello and cookie/HTTP header inspection) |
| pandas | 2.x | Dataset loading and feature-frame construction for training and adaptive retraining |
| numpy | 1.x | Numerical arrays for ML feature vector construction |
| joblib | 1.x | Serialisation of trained models (`.joblib`) alongside their scaler, feature names, and optimal threshold |
| python-dotenv | 1.x | Environment variable loading from `.env` files |
| psutil | 5.x | CPU, RAM, disk, and network I/O statistics |
| requests | 2.x | HTTP client for AbuseIPDB, Groq, Gemini, IP-geolocation, and MalwareBazaar API calls |
| Flask / Flask-CORS | 3.x / 4.x | REST API and static file server for the web/mobile companion dashboard |
| PyJWT | 2.x | JSON Web Token issuing/verification for web dashboard authentication |
| folium | 0.17.x | Leaflet.js interactive map generation for attacker geolocation |
| matplotlib | 3.x | Performance/ROC charts in the Adversarial Lab and ML Analysis tabs |
| qrcode[pil] | 7.x | QR code generation for alert sharing |
| plyer | 2.x | Cross-platform desktop toast notifications |
| pyinstaller | 6.x | Packaging the application into a standalone Windows executable |

**Adaptation Process:**
All libraries were used as intended by their authors through documented APIs. No library source code was copied or modified. Custom logic was implemented for:
- The multi-detector alert routing pipeline (now spanning 21 detector modules).
- Threshold calibration and false-positive suppression mechanisms — including a data-driven correction during testing, where a hand-picked "benign traffic" fixture used in the adversarial test suite was replaced with the median feature values of real BENIGN flows sampled from the training dataset, after it was found to trigger a false positive that a hand-crafted vector (not the model itself) was responsible for.
- The PyQt6 QSS dark theme and signal-based thread communication.
- The FIM exclusion system to prevent self-referential alerts.
- The CDN whitelist and private IP filter for brute-force and DNS detectors.
- The adaptive-learning feedback loop (feedback buffer → oversampled retrain → held-out evaluation → versioned rollback).
- The FGSM-style greedy evasion engine and composite AI Security Score for the adversarial ML lab.
- The JWT-based multi-tenant authentication layer for the web/mobile companion dashboard.

---

---

# Chapter 7: Testing

## 7.1 Unit Testing Approach

The Network Security Monitor System is tested at three complementary levels:

1. **Automated regression suite (`pytest`, `tests/`)** — runs in CI-style fashion with a single `pytest` command; asserts on the DDoS classifier's real predict() output (verdict, confidence, threshold) against both attack profiles and a benign-traffic profile, and exercises the adversarial evasion engine. This is the suite a grader or CI pipeline would run.
2. **Manual safe simulation suite (`demo_test.py`)** — a **safe, in-memory simulation approach** exercising every rule-based detector module end-to-end. All tests run without transmitting any real network packets, without requiring administrator privileges, and without making any external API calls.
3. **Manual GUI smoke test (`test_desktop_app.py`)** — instantiates every PyQt6 tab and exercises widgets, signals, and navigation without a human clicking through the app.

`pytest` and `demo_test.py` are the primary, fast-running suites; `test_desktop_app.py` additionally requires a display/Qt platform plugin and is run before releases.

### Testing Strategy

| Dimension | Approach |
|---|---|
| Network packets | Scapy in-memory packet objects constructed with known fields — no real traffic transmitted |
| Attacker IPs | Real public IPs (1.2.3.4, 5.6.7.8, etc.) — not RFC-1918 or documentation ranges which Python 3.11+ marks as private |
| FIM testing | Python `tempfile.mkdtemp()` temporary directory — automatically cleaned up after tests |
| API testing | Tested with empty API key to verify graceful degradation (no live API calls) |
| ML testing | Loaded trained model from disk; hand-crafted feature vectors to test prediction API |

### Testing Tool

```
python demo_test.py              # Full test suite
python demo_test.py --verbose    # Show alert detail for each triggered alert
python demo_test.py --fast       # Skip slow ML tests
```

The test output uses ANSI colour codes (green ✓ for pass, red ✗ for fail, yellow ↷ for skipped) and concludes with a section-by-section summary table.

### Testing Objectives

- Verify that each detector correctly identifies simulated attack patterns.
- Verify that normal/benign traffic does NOT trigger alerts (false-positive checks).
- Verify that detection thresholds are set to calibrated minimum safe values.
- Verify graceful degradation when dependencies (Scapy, ML model, API key) are unavailable.

---

## 7.2 Test Cases

### ARP Spoofing & Flood Detector

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| ARP-01 | First-seen IP should not alert | ARP reply for 10.0.0.10 with MAC aa:bb:cc:11:22:33 | No alert | Pass |
| ARP-02 | ARP cache poisoning detection | Same IP (10.0.0.10) with different MAC ff:ee:dd:44:55:66 | ARP Spoofing alert (HIGH) | Pass |
| ARP-03 | Gateway MAC hijack (critical) | Gateway IP (192.168.1.1) changes MAC | ARP Spoofing — Gateway! alert (CRITICAL) | Pass |
| ARP-04 | ARP flood detection | 52 ARP packets within 10 s from same MAC | ARP Flood alert (HIGH) | Pass |
| ARP-05 | Spoof cooldown suppression | Second MAC change within 5 minutes | No second alert (cooldown active) | Pass |

### DNS Anomaly Detector

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| DNS-01 | Normal query — no alert | Query for www.example.com | No alert | Pass |
| DNS-02 | DNS tunnelling detection | Query with 65-character subdomain label | DNS Tunneling alert (CRITICAL) | Pass |
| DNS-03 | Risky TLD detection | Query for malware-download.tk | Suspicious TLD alert (MEDIUM) | Pass |
| DNS-04 | CDN whitelist — no fast-flux false positive | 25 different IPs for google.com | No alert | Pass |
| DNS-05 | Fast-flux detection | 22 distinct IPs for flux.botnet-c2.com | Fast-Flux DNS alert (HIGH) | Pass |
| DNS-06 | C2 beaconing detection | 155 queries/min to beacon.attacker.io | DNS C2 Beacon alert (HIGH) | Pass |

### Brute Force & Credential Attack Detector

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| BF-01 | Under threshold — no alert | 10 SSH SYN packets from external IP | No alert | Pass |
| BF-02 | SSH brute force detection | 26 SYN packets to port 22 from 1.2.3.4 | SSH Brute Force alert (HIGH) | Pass |
| BF-03 | Private IP src — silently ignored | 30 SYN packets from 192.168.1.100 | No alert | Pass |
| BF-04 | RDP brute force detection | 26 SYN packets to port 3389 from 5.6.7.8 | RDP Brute Force alert (HIGH) | Pass |
| BF-05 | HTTPS credential stuffing | 82 SYN packets to port 443 from 45.33.32.1 | Credential Stuffing alert (MEDIUM) | Pass |
| BF-06 | Password spray detection | 4 SYNs each to 6 auth ports from 180.100.50.1 | Password Spray alert (CRITICAL) | Pass |

### DDoS ML & Anomaly Detection

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| ML-01 | ML predict() API functionality | Sample flow feature dict | Returns valid verdict dict without error | Pass |
| ML-02 | SYN flood pattern classification | Flow: 5000 fwd pkts, 10 bwd pkts, 0 ACKs | ATTACK verdict | Pass |
| ML-03 | Rule engine: oversized packet | Packet length 9000 bytes | Oversized packet alert (MEDIUM) | Pass |
| ML-04 | Isolation Forest: normal traffic | Balanced flow features | Returns score without error | Pass |
| ML-05 | Isolation Forest: outlier | Extreme feature values | Returns anomaly score | Pass |

### DDoS ML & Adversarial Engine — Automated (`pytest`, `tests/test_simulation_detection.py`)

| Test ID | Test Description | Expected Result | Status |
|---|---|---|---|
| PT-01 | `test_model_loads` | Trained DDoS model loads from `ddos_detector_model.joblib` | Pass |
| PT-02 | `test_packet_features_present` | `predict()` result contains `verdict`, `confidence`, `threshold` | Pass |
| PT-03 | `test_syn_flood_detected` | SYN Flood profile classified ATTACK or SUSPICIOUS | Pass |
| PT-04 | `test_udp_flood_detected` | UDP Flood profile classified ATTACK or SUSPICIOUS | Pass |
| PT-05 | `test_detection_rate_threshold` | ≥ 50% of attack profiles detected | Pass |
| PT-06 | `test_benign_not_flagged_as_attack` | Benign traffic profile NOT classified ATTACK | Pass* |
| PT-07 | `test_adversarial_engine_attack` | `AdversarialEngine.attack()` returns a result dict, model loads | Pass |
| PT-08 | `test_confidence_is_numeric` | Confidence score is a float in [0, 100] | Pass |

\* PT-06 initially failed during a testing pass: the hand-picked `BENIGN_PROFILE`
fixture (used by both this test and the Adversarial Lab's evasion baseline)
scored 98.7% attack probability under the trained classifier — not because
the model was wrong (it independently tests at 99.9% accuracy / 100% AUC on
held-out real data), but because the fixture's values did not resemble real
benign network flows. The fixture was corrected to the median feature values
of ~63,000 real BENIGN rows sampled from `cicddos2019_dataset.csv`, after
which it scores 0.36% and the test passes. This is recorded here as a
concrete instance of the false-positive-auditing methodology described in
§7.1 — every "no alert expected" fixture needs to be checked against real
data, not just plausible-sounding numbers.

### File Integrity Monitor (FIM)

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| FIM-01 | First scan on empty directory | Empty temp dir | No alerts | Pass |
| FIM-02 | File modification detection | config.txt content changed | FIM — File Modified alert (HIGH) | Pass |
| FIM-03 | New file detection | new_payload.exe created | FIM — File Created alert (MEDIUM) | Pass |
| FIM-04 | File deletion detection | script.py deleted | FIM — File Deleted alert (MEDIUM) | Pass |
| FIM-05 | .pyc and .log files excluded | module.pyc and debug.log created | No alert | Pass |
| FIM-06 | fim_baseline.json self-exclusion | baseline file present | No self-referential alert | Pass |
| FIM-07 | Exclusion config verification | Check _EXCLUDE_NAMES, _EXCLUDE_SUFFIXES, _EXCLUDE_DIRS | All exclusions confirmed | Pass |

### Threat Intelligence (AbuseIPDB)

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| TI-01 | No API key — graceful degradation | Empty API key | is_ready() returns False | Pass |
| TI-02 | Private IPs silently skipped | 10.0.0.1, 192.168.1.1, 172.16.0.1, 127.0.0.1 | No alerts or API calls | Pass |
| TI-03 | Cache miss for unchecked IP | get_cached("8.8.8.8") | Returns None | Pass |
| TI-04 | API key configuration check | ABUSEIPDB_API_KEY in .env | Configured status reported | Pass |

### Windows Event Log Monitor

| Test ID | Test Description | Input | Expected Result | Status |
|---|---|---|---|---|
| EL-01 | wevtutil availability check | System check | Available / Not available reported | Pass |
| EL-02 | Event 4698 severity calibration | Check _WATCHED[4698] | Severity = "medium" (not "high") | Pass |
| EL-03 | Event 4724 severity calibration | Check _WATCHED[4724] | Severity = "low" (not "medium") | Pass |
| EL-04 | Event 1102 remains critical | Check _WATCHED[1102] | Severity = "critical" | Pass |
| EL-05 | Suspicious process filter active | Check _SUSPICIOUS_PROCS | mimikatz, mshta.exe, etc. present | Pass |
| EL-06 | Event 4625 description format | _describe(4625, ...) | "Failed logon by 'hacker' from ATTACKER-PC (type 3)" | Pass |
| EL-07 | Event 7045 description format | _describe(7045, ...) | "New service installed: EvilRootkit by 'SYSTEM'" | Pass |

### Detection Threshold Sanity Check

| Test ID | Threshold Verified | Minimum Safe Value | Configured Value | Status |
|---|---|---|---|---|
| TH-01 | ARP flood threshold | ≥ 50 pkts / 10 s | 50 | Pass |
| TH-02 | ARP spoof cooldown | ≥ 300 s (5 min) | 300 s | Pass |
| TH-03 | Fast-flux distinct IPs | ≥ 20 | 20 | Pass |
| TH-04 | .xyz not in risky TLDs | — | Confirmed absent | Pass |
| TH-05 | DNS rate threshold | ≥ 100 queries/min | 150 | Pass |
| TH-06 | DNS label length | ≥ 55 chars | 60 | Pass |
| TH-07 | Auth brute force | ≥ 20 SYN / 60 s | 25 | Pass |
| TH-08 | HTTP credential stuffing | ≥ 60 SYN / 60 s | 80 | Pass |
| TH-09 | Password spray ports × SYNs | ≥ 5 services | 6 × 3 | Pass |

**Final Test Results: 49/49 `demo_test.py` checks passed, 8/8 `pytest` automated tests passed — ALL TESTS PASSED**

---

## 7.3 Acceptance Testing

User Acceptance Testing (UAT) was conducted with sample scenarios to evaluate whether the system meets intended requirements and user expectations.

| User Requirement | Test Scenario | Result |
|---|---|---|
| Real-time threat visibility | Simulated ARP attack — alert appeared in dashboard within 1 second | Accepted |
| Low false positive rate | Normal browsing traffic on development machine — no alerts triggered | Accepted |
| Professional UI | Dark-themed dashboard reviewed for clarity and usability | Accepted |
| Correct severity calibration | Password spray correctly classified as CRITICAL, not LOW | Accepted |
| FIM self-exclusion | FIM baseline file not generating continuous false alerts | Accepted |
| Graceful degradation without API key | System starts and runs all non-API detectors successfully | Accepted |
| Phishing email analysis | Email with spoofed sender and urgent language correctly identified | Accepted |
| Event log severity calibration | Scheduled task creation correctly classified as MEDIUM, not HIGH | Accepted |
| Private IP filtering | Machine's own outgoing SSH connections not flagged as brute force | Accepted |
| CDN whitelist | Google DNS queries not flagged as fast-flux | Accepted |

---

---

# Chapter 8: Conclusion

## 8.1 Project Summary

The **Network Security Monitor System** was developed to address the gap between enterprise-grade, expensive SIEM solutions and the fragmented, difficult-to-integrate open-source security tools available to SMEs and individual administrators. The system provides a unified, real-time multi-vector threat detection platform with a professional desktop interface accessible to administrators without deep security expertise.

**Key achievements of the project:**

- Successfully implemented **21 independent detector/engine modules** spanning network (ARP, DNS, Brute Force, DDoS ML, Anomaly, TLS/JA3), host (FIM, Event Log, UEBA), and application-layer (email phishing, URL phishing, cookie tracking, vulnerability scanning, file scanning) threat surfaces, operating concurrently without mutual interference.
- Integrated **machine learning** (Random Forest for DDoS, Isolation Forest for anomaly, SVM for cookie tracking) with rule-based heuristics, producing a hybrid detection pipeline more robust than either approach alone.
- Applied **LLM-based analysis** (Groq `llama-3.3-70b-versatile`, with Google Gemini 2.0 Flash as fallback) for nuanced email phishing analysis — a capability beyond what rule-based or classical ML approaches can provide for natural language phishing detection.
- Built an **adaptive learning loop** that retrains the DDoS classifier from analyst feedback, evaluates the candidate model before deployment, and versions prior models for rollback — going beyond a static, one-time-trained classifier.
- Built an **adversarial ML security lab** (model analyzer, XAI feature explainer, FGSM-style evasion engine, composite AI Security Score) to audit the DDoS classifier's own robustness against adversarial manipulation — directly addressing detection *and* adversarial-robustness evaluation, not detection alone.
- Achieved **49/49 checks passing** in the manual `demo_test.py` simulation suite and **8/8 tests passing** in the automated `pytest` regression suite, covering positive detection, false-positive suppression, and adversarial evasion.
- Conducted a thorough **false-positive audit** spanning both the rule-based detectors and the ML pipeline — fixing 6 major sources of rule-based false alarms (FIM self-reference, brute-force private IP leakage, fast-flux CDN false positives, DNS rate and label thresholds, ARP cooldown absence, password spray minimum-SYN requirement) plus a false positive traced to an unrealistic test fixture in the ML/adversarial test suite (§7.2, PT-06).
- Delivered a **professional dark-themed PyQt6 dashboard** — grown from 6 to 12 tabs — with real-time stat cards, colour-coded severity indicators, system health monitoring, modular tab navigation, and an optional JWT-authenticated web/mobile companion for remote viewing.

The final product is a functional, well-tested security monitoring system with a maintainable modular architecture and thorough documentation.

---

## 8.2 Challenges Faced & Lessons Learned

### Challenges Faced

**1. False Positive Calibration**
The most time-consuming challenge was calibrating detection thresholds to minimise false positives without sacrificing detection sensitivity. Every threshold required analysis of real traffic patterns:
- ARP flood threshold needed to be raised from 20 to 50 for busy office networks.
- Fast-flux detection required a 34-domain CDN whitelist to avoid flagging Google, Cloudflare, and AWS.
- Brute-force detection required a private IP filter to avoid flagging the machine's own SSH/email/SMB connections.
- FIM required careful exclusion rules to prevent self-referential alerts from its own baseline file.

**2. Thread Safety in PyQt6**
The Qt framework strictly prohibits updating UI widgets from non-GUI threads. Implementing the signal-based callback architecture (`pyqtSignal.emit()`) to safely pass alerts from background detector threads to the GUI thread required careful design. Any direct widget modification from a detector thread caused application crashes.

**3. Python 3.11+ `ipaddress.is_private` Change**
During test development, tests using RFC 5737 TEST-NET addresses (203.0.113.x, 198.51.100.x) failed because Python 3.11 expanded `is_private` to include all IANA special-purpose addresses. This required changing test IPs to genuinely routable public addresses — a subtle but impactful compatibility issue.

**4. Scapy Layer Detection Compatibility**
Scapy's DNS layer handling varies between versions and packet sources. Some packets required `getlayer(DNS)` while others required `pkt[DNS]`. Consistent layer access patterns across all detectors required careful testing with diverse packet sources.

**5. FIM Self-Reference Loop**
The FIM module's baseline file (`fim_baseline.json`) was initially inside the watched directory. Since FIM rewrites this file every 60 seconds, it continuously triggered "File Modified" alerts — a self-referential loop. Fixing this required adding the file to `_EXCLUDE_NAMES` AND changing the default watch directory from the project root to the `detectors/` subdirectory.

**6. ML Model Feature Alignment**
The DDoS classifier's feature names are stored with the trained model (in the `.joblib` file). When prediction code passed features in a different order or with different key names, the model received misaligned inputs and produced incorrect verdicts. Fixing this required always looking up feature values by name from the model's stored `feature_names` list.

---

### Lessons Learned

1. **False positive reduction is as important as detection accuracy.** A detector that raises 100 false alarms per day will be ignored or disabled, making it useless. Extensive threshold calibration was the most valuable engineering investment in this project.

2. **Thread-safe UI design must be planned from the start.** Retrofitting signal-based communication into a monolithic UI would be extremely difficult. Designing the callback-to-signal bridge early made detector integration clean.

3. **Test real edge cases, not just happy paths.** The most valuable tests in `demo_test.py` are the false-positive suppression tests — verifying that normal traffic does NOT trigger alerts.

4. **Python version changes can break subtle assumptions.** The `ipaddress.is_private` change in Python 3.11 was not widely documented and only discovered when test cases failed. Pinning Python versions or testing across versions is important.

5. **Modular architecture pays dividends during debugging.** Because each detector is an independent class in its own file, isolating and fixing bugs (like the FIM self-reference or brute-force private IP issue) required changing only one file without affecting other detectors.

6. **Secrets management must be enforced architecturally.** Using `config.py` as a single point of environment variable access, combined with a `.env` file enforced by `.gitignore`, ensures API keys are never accidentally committed to version control.

7. **AI APIs complement but do not replace rule-based and ML detection.** The Gemini API provides excellent nuanced phishing analysis but cannot run on every network packet at millisecond speeds. The hybrid approach — fast rule-based/ML detection for network traffic, AI for email analysis — uses each technology where it is most appropriate.

---

---

# References

1. Pressman, R. S. *Software Engineering: A Practitioner's Approach.* McGraw-Hill Education, 2019.
2. Sommerville, I. *Software Engineering.* Pearson Education, 2016.
3. CICIDS Research Group. *CIC-DDoS2019 Dataset.* Canadian Institute for Cybersecurity, 2019.
4. MITRE Corporation. *ATT&CK Framework — Enterprise Techniques.* https://attack.mitre.org/
5. OWASP Foundation. *OWASP Top 10 Security Risks.* https://owasp.org/Top10/
6. PyQt6 Documentation. *Riverbank Computing Ltd.* https://www.riverbankcomputing.com/static/Docs/PyQt6/
7. scikit-learn Documentation. *scikit-learn.org.* https://scikit-learn.org/stable/
8. Scapy Documentation. *scapy.net.* https://scapy.readthedocs.io/
9. Google AI Documentation. *Gemini API Reference.* https://ai.google.dev/
10. AbuseIPDB Documentation. *AbuseIPDB API v2.* https://www.abuseipdb.com/api.html
11. AbuseIPDB. *Free IP Abuse Database.* https://www.abuseipdb.com/
12. ChatGPT / Claude AI. *Used for code guidance and documentation assistance.*

---

---

# Appendices

## Appendix A: System Architecture Overview

The system grew from an initial 6-tab, 10-detector prototype to its current
form: a 12-tab desktop application backed by 21 detector/engine modules,
plus an optional web/mobile companion. The full layout:

```
security_monitor/
├── desktop_app.py          Main PyQt6 application window and UI (12 tabs)
├── main_app.py              Flask REST API — optional headless web interface
├── config.py                 Centralised configuration (env vars, paths)
├── train_model.py            DDoS Random Forest training pipeline
├── tests/
│   └── test_simulation_detection.py   Automated pytest suite (ML detection + adversarial engine)
├── demo_test.py              Manual safe simulation suite (rule-based detectors, run directly)
├── test_desktop_app.py       Manual GUI smoke test (PyQt6 widgets/signals, run directly)
├── .env                       API keys and runtime config (excluded from Git via .gitignore)
├── ddos_detector_model.joblib       Trained DDoS classifier (RF + scaler + optimal threshold)
├── anomaly_model.joblib             Trained Isolation Forest (benign-only)
├── corrective_layer.joblib          Online SGD classifier for adaptive blending
├── web_dashboard/
│   └── app.py                Flask app: JWT auth, multi-tenant alert relay, mobile UI
└── detectors/
    ├── arp_monitor.py        ARP spoofing and flood detection
    ├── dns_monitor.py        DNS anomaly detection (tunnelling, fast-flux, C2)
    ├── brute_force.py        Brute force, credential stuffing, and password spray detection
    ├── flow_tracker.py       Packet → flow aggregation feeding the DDoS/anomaly models
    ├── ddos.py                DDoS ML classifier + rule engine
    ├── anomaly.py             Isolation Forest anomaly scoring
    ├── ip_tracker.py          Per-IP sliding-window heuristics (SYN:ACK ratio, port spread)
    ├── ip_blocker.py          Windows Firewall auto-blocking with rollback timer
    ├── fim.py                  SHA-256 file integrity monitoring
    ├── event_log.py            Windows Event Log polling (wevtutil)
    ├── ueba.py                 User & entity behaviour analytics (off-hours/new-host logins)
    ├── threat_intel.py         AbuseIPDB IP reputation lookups
    ├── geo_mapper.py            IP geolocation + Leaflet/folium map rendering
    ├── tls_inspector.py         TLS Client Hello metadata + JA3 fingerprinting
    ├── vuln_scanner.py          Socket-based port scanner with banner grabbing
    ├── file_scanner.py          USB/download monitoring + MalwareBazaar hash lookup
    ├── cookie.py                 SVM cookie/session tracking classifier
    ├── email_phishing.py         Groq/Gemini LLM email phishing analysis
    ├── url_phishing.py           Random Forest URL phishing classifier
    ├── adaptive_trainer.py       Feedback-driven retraining + model versioning
    └── adversarial.py            Adversarial ML lab (analyzer, explainer, evasion engine, scorer)
```

**Desktop tabs → primary detector(s):**

| Tab | Backing module(s) |
|---|---|
| Overview | Aggregates all detectors |
| Live Traffic | `flow_tracker.py`, `ddos.py`, `anomaly.py` |
| Threats & Alerts | Alert routing layer (all detectors) |
| System Monitor | `event_log.py`, `fim.py`, `ueba.py`, `threat_intel.py` |
| Blocked IPs | `ip_blocker.py` |
| Test & Analyse | `ddos.py`, `email_phishing.py`, `url_phishing.py`, `vuln_scanner.py`, `threat_intel.py` (simulation harness) |
| ML Analysis | `adversarial.py` (`ModelAnalyzer`) |
| Adaptive Training | `adaptive_trainer.py` |
| Adversarial Lab | `adversarial.py` (`AdversarialEngine`, `FeatureExplainer`, `SecurityScorer`) |
| Geo Map | `geo_mapper.py` |
| File Scanner | `file_scanner.py` |
| Settings | `config.py`, `rules_config.json` |

---

## Appendix B: Detection Thresholds Reference

| Detector | Parameter | Value | Rationale |
|---|---|---|---|
| ARP | Flood threshold | 50 pkts / 10 s | Avoids false alarms on busy networks |
| ARP | Spoof cooldown | 300 s (5 min) | Suppresses repeated alerts for same attacker |
| DNS | Label length | 60 characters | Avoids false alarms from long but legitimate subdomains |
| DNS | Rate threshold | 150 queries / min | Avoids false alarms from DNS-based health checks |
| DNS | Fast-flux threshold | 20 distinct IPs | Avoids false alarms on CDN anycast addresses |
| Brute Force | Auth threshold | 25 SYNs / 60 s | Normal reconnection bursts stay below this |
| Brute Force | HTTP threshold | 80 SYNs / 60 s | Web crawlers and CDN prefetch stay below this |
| Brute Force | Spray ports | 6 auth services | Machines with email + SSH + file share = 3 services max |
| Brute Force | Spray min SYNs | 3 per port | Prevents single-SYN port probes from triggering spray |

---

## Appendix C: Environment Variables Reference

| Variable | Description | Required |
|---|---|---|
| GROQ_API_KEY | Groq API key — primary email phishing analyser (free tier) | Optional |
| GEMINI_API_KEY | Google Gemini API key — fallback email phishing analyser | Optional |
| ABUSEIPDB_API_KEY | AbuseIPDB API key for IP reputation lookups | Optional |
| GATEWAY_IP | Router/gateway IP for critical ARP gateway alert | Optional |
| FIM_WATCH_DIRS | Comma-separated list of directories to monitor | Optional |
| ATTACK_THRESHOLD | ML confidence threshold override (0 = use model's optimal) | Optional |
| FLOW_MIN_PACKETS | Minimum packets before classifying a flow | Optional (default: 5) |
| FLOW_TIMEOUT_S | Flow inactivity timeout in seconds | Optional (default: 10.0) |
| MONITOR_PASSWORD | Demo login password for the web/mobile companion dashboard | Optional (default: "monitor") |
| PORT | Port for the Flask web dashboard / companion API | Optional (default: 5000, companion uses 8080) |

---

## Appendix D: API Endpoints (AbuseIPDB)

| Method | Endpoint | Description |
|---|---|---|
| GET | /api/v2/check?ipAddress={ip} | Check IP abuse confidence score |

---

## Appendix E: Delivered Beyond the Original Scope, and Remaining Future Work

An earlier draft of this report listed several items below as "future
improvements." Over the course of the project they were implemented and
shipped, ahead of the original schedule — they are recorded here for an
accurate history rather than left as stale future work:

- ~~Mobile companion application for remote alert monitoring~~ → delivered as the JWT-authenticated web/mobile companion dashboard (`web_dashboard/`, FR-023).
- ~~QR code-based alert sharing for quick incident handoff~~ → delivered (`utils/qr_share.py`, FR-024).
- ~~Automated IP blocking at OS firewall level with rollback timer~~ → delivered (`detectors/ip_blocker.py`, FR-014).
- ~~Network topology visualisation showing attacker IPs on a map overlay~~ → delivered as the Geo Map tab (`detectors/geo_mapper.py`, FR-020).
- ~~Deep packet inspection for encrypted traffic metadata analysis~~ → delivered as TLS/JA3 fingerprinting (`detectors/tls_inspector.py`, FR-017).
- ~~User behaviour analytics (UEBA) to detect insider threats~~ → delivered (`detectors/ueba.py`, FR-019).
- ~~Web-based dashboard for managing a monitored host remotely~~ → delivered as part of the companion dashboard above (single-host, LAN-local — see note below on remaining scope).

**Genuinely remaining future work:**

- Online payment / subscription model for cloud-based threat feed updates.
- SIEM integration (Splunk, Elastic, or Microsoft Sentinel export).
- Email/SMS notification pipeline for critical alerts.
- True multi-tenant SaaS deployment of the web dashboard across many monitored hosts/organisations (the current companion dashboard is single-host and LAN-local by design).
- Cross-platform packet-capture parity for Linux/macOS (Windows-specific features — Event Log monitoring, Windows Firewall blocking — have no equivalent yet on other platforms).
- Scheduled/automatic model retraining (currently adaptive retraining is analyst-triggered, not time- or drift-triggered).
- Replacing the web dashboard's fixed demo password with per-administrator accounts.
