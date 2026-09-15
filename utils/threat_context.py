"""
Threat Context Knowledge Base.

Maps every rule_name to a rich context dict containing:
  - icon            : emoji category marker
  - category_label  : human-readable threat category
  - what_is_happening: plain-English, non-technical description
  - why_dangerous   : what harm this can cause to you
  - what_to_do      : immediate recommended actions
  - mitre_id        : MITRE ATT&CK technique ID
  - mitre_name      : MITRE ATT&CK technique name
  - spy_risk        : True if this indicates surveillance / spying
  - attack_risk     : True if this is an active attack
  - data_risk       : True if data theft / exfiltration is likely

Used by the web dashboard and desktop app to show rich alert detail.
"""

from __future__ import annotations

_DB: dict[str, dict] = {

    # ── ARP ─────────────────────────────────────────────────────────────────
    "ARP Spoofing": {
        "icon": "🎭",
        "category_label": "Network Interception",
        "what_is_happening": (
            "A device on your network is sending false ARP (Address Resolution Protocol) messages, "
            "claiming to be a device it is not. This lets it intercept traffic meant for another machine."
        ),
        "why_dangerous": (
            "This is a classic Man-in-the-Middle (MitM) attack. The attacker can silently read, "
            "modify, or steal every packet you send — including passwords, messages, and banking data — "
            "even if you think you're talking directly to your router or server."
        ),
        "what_to_do": (
            "1. Immediately block the attacking IP on your network switch.\n"
            "2. Check which device that MAC address belongs to (use 'arp -a' in Command Prompt).\n"
            "3. Enable Dynamic ARP Inspection (DAI) on managed switches.\n"
            "4. If confirmed attack, isolate the device and scan it for malware.\n"
            "5. Change any passwords entered during the suspicious period."
        ),
        "mitre_id": "T1557.002",
        "mitre_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "ARP Spoofing — Gateway!": {
        "icon": "🚨",
        "category_label": "Gateway Hijack — Critical",
        "what_is_happening": (
            "The MAC address of your router/gateway has just been changed by another device on your network. "
            "Your router is now being impersonated — ALL traffic leaving your network passes through the attacker."
        ),
        "why_dangerous": (
            "This is the most severe form of ARP attack. Every device on your network is now sending ALL its "
            "internet traffic through the attacker's machine. They can read passwords, intercept emails, "
            "steal session cookies, inject malicious content into websites, and monitor everything you do online."
        ),
        "what_to_do": (
            "IMMEDIATE ACTION REQUIRED:\n"
            "1. Stop all sensitive activity (banking, work logins) NOW.\n"
            "2. Identify and physically disconnect the attacking device.\n"
            "3. Flush ARP caches on all devices: run 'arp -d *' (Windows) or 'ip neigh flush all' (Linux).\n"
            "4. Change passwords for all accounts used in the last hour.\n"
            "5. Enable Static ARP entries for your gateway on critical machines.\n"
            "6. Report to your IT/security team immediately."
        ),
        "mitre_id": "T1557.002",
        "mitre_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "ARP Flood": {
        "icon": "🌊",
        "category_label": "Denial of Service / Network Scan",
        "what_is_happening": (
            "A device is sending an abnormally high number of ARP broadcast packets — far more than "
            "any legitimate device would generate. This could be a network scanner, a misconfigured device, "
            "or the early stage of an attack."
        ),
        "why_dangerous": (
            "Flooding the network with ARP requests can slow or crash switches (ARP cache overflow), "
            "cause network congestion, and is often the reconnaissance phase before a more targeted attack. "
            "Some malware uses ARP flooding to discover all devices on the network."
        ),
        "what_to_do": (
            "1. Identify the flooding device by its MAC address.\n"
            "2. Check if it's a legitimate scanner (Nessus, Nmap) run by your IT team.\n"
            "3. If unauthorised, block the MAC address on your switch.\n"
            "4. Enable ARP rate limiting on your switch if supported.\n"
            "5. Run a malware scan on the identified device."
        ),
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": False,
    },

    # ── DNS ─────────────────────────────────────────────────────────────────
    "DNS Tunneling": {
        "icon": "🕳",
        "category_label": "Data Exfiltration via DNS",
        "what_is_happening": (
            "DNS queries with unusually long subdomain labels have been detected. Legitimate DNS "
            "subdomains are short (e.g. mail.google.com). Extremely long labels (60+ characters) "
            "are used by attackers to encode and smuggle data inside DNS queries, which most firewalls ignore."
        ),
        "why_dangerous": (
            "DNS tunnelling is used to silently steal data or maintain contact with malware even through "
            "strict firewalls, because DNS port 53 is almost always allowed. Your data, credentials, or "
            "internal documents could be slowly exfiltrated without triggering normal security controls. "
            "It is also used by malware to receive commands from attackers (C2 communication)."
        ),
        "what_to_do": (
            "1. Note the queried domain name in the alert — this is the attacker's domain.\n"
            "2. Block that domain at your DNS firewall/resolver immediately.\n"
            "3. Identify which internal device made that DNS query.\n"
            "4. Run a full malware scan on that device.\n"
            "5. Deploy DNS filtering (e.g. Cisco Umbrella, Pi-hole with threat feeds).\n"
            "6. Check for any sensitive files recently accessed on that machine."
        ),
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "Fast-Flux DNS": {
        "icon": "🌀",
        "category_label": "Botnet / Bulletproof Hosting",
        "what_is_happening": (
            "A single domain is returning a rapidly changing list of IP addresses — far more than any "
            "legitimate service uses. Normal websites use 1–5 IPs. Fast-flux domains rotate through 20+ "
            "IPs to make them impossible to block and to hide malicious infrastructure."
        ),
        "why_dangerous": (
            "Fast-flux is the hallmark of botnet command-and-control (C2) servers, phishing infrastructure, "
            "and bulletproof hosting used by cybercriminals. A device on your network contacting this domain "
            "is likely infected with malware that is receiving instructions from attackers."
        ),
        "what_to_do": (
            "1. Block the fast-flux domain at your DNS resolver immediately.\n"
            "2. Identify which device(s) are querying this domain.\n"
            "3. Isolate those devices from the network.\n"
            "4. Run a full antivirus and rootkit scan.\n"
            "5. Check browser extensions, startup programs, and scheduled tasks for malware.\n"
            "6. Consider reimaging the affected devices if malware is confirmed."
        ),
        "mitre_id": "T1568.001",
        "mitre_name": "Dynamic Resolution: Fast Flux DNS",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "DNS C2 Beacon": {
        "icon": "📡",
        "category_label": "Malware C2 Beaconing",
        "what_is_happening": (
            "A device is making an extremely high number of DNS queries to the same domain in a very short "
            "time — a pattern that matches malware 'checking in' with its command server (C2 beaconing). "
            "Legitimate apps rarely query the same domain 150+ times per minute."
        ),
        "why_dangerous": (
            "This strongly indicates active malware on your network that is maintaining contact with "
            "attackers. The malware may be waiting for commands — to steal files, encrypt your drive "
            "(ransomware), spread to other machines, or launch attacks on others using your network."
        ),
        "what_to_do": (
            "1. Identify the device making these DNS queries immediately.\n"
            "2. Disconnect that device from the network.\n"
            "3. Block the target domain at your DNS server.\n"
            "4. Run malware and rootkit scans on the isolated device.\n"
            "5. Preserve forensic evidence (memory dump, disk image) before cleaning.\n"
            "6. Review what data was accessible from that device in the last 24 hours."
        ),
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS C2",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "Suspicious TLD": {
        "icon": "⚠",
        "category_label": "High-Risk Domain",
        "what_is_happening": (
            "A DNS query was made to a domain using a top-level domain (TLD) that is heavily associated "
            "with malware, phishing, and scam infrastructure (.tk, .ml, .gq, .cf, .pw etc.). "
            "These free or cheap TLDs are almost exclusively used by malicious actors."
        ),
        "why_dangerous": (
            "Domains on these TLDs are routinely used for phishing pages, malware distribution, "
            "and scam sites. If a device on your network is querying one, it may have clicked a "
            "phishing link, been redirected by malware, or is attempting to download a malicious payload."
        ),
        "what_to_do": (
            "1. Check which user/device made the request.\n"
            "2. Ask the user if they recently clicked an email link or pop-up.\n"
            "3. Scan the device for malware.\n"
            "4. Block the specific domain in your DNS filter.\n"
            "5. Consider blocking entire risky TLDs at your DNS level."
        ),
        "mitre_id": "T1566.002",
        "mitre_name": "Phishing: Spearphishing Link",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── Brute Force ──────────────────────────────────────────────────────────
    "SSH Brute Force": {
        "icon": "🔨",
        "category_label": "Credential Attack — SSH",
        "what_is_happening": (
            "An external IP address is repeatedly trying to log into your SSH server (port 22) "
            "with many different username/password combinations. This is an automated attack "
            "trying thousands of common passwords per minute."
        ),
        "why_dangerous": (
            "If successful, the attacker gets full command-line access to your server or computer. "
            "They can steal all files, install ransomware, create backdoors, and use your machine "
            "to attack others. SSH access is essentially the 'master key' to a Linux/Unix system."
        ),
        "what_to_do": (
            "1. Block this IP in your firewall immediately.\n"
            "2. If SSH is not needed externally, close port 22 to the internet.\n"
            "3. Disable password authentication — use SSH keys only (most secure).\n"
            "4. Change SSH to a non-standard port (e.g. 2222) to reduce automated scans.\n"
            "5. Install fail2ban to auto-block repeated failures.\n"
            "6. Enable two-factor authentication for SSH."
        ),
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "RDP Brute Force": {
        "icon": "🖥",
        "category_label": "Credential Attack — Remote Desktop",
        "what_is_happening": (
            "An external IP is repeatedly attempting to log into Windows Remote Desktop (RDP, port 3389). "
            "RDP brute force is one of the most common entry points for ransomware gangs — they scan "
            "the entire internet looking for open RDP ports."
        ),
        "why_dangerous": (
            "If cracked, the attacker gets a full graphical Windows session. Ransomware groups specifically "
            "target RDP because once inside they can manually deploy ransomware, steal backups, disable "
            "antivirus, and encrypt all files for ransom. RDP breaches regularly result in $50,000–$1M+ losses."
        ),
        "what_to_do": (
            "1. Block this IP immediately.\n"
            "2. If RDP is not needed, disable it: System Properties → Remote → Disable Remote Desktop.\n"
            "3. If needed, put RDP behind a VPN — never expose it directly to the internet.\n"
            "4. Enforce account lockout after 5 failed attempts (Group Policy).\n"
            "5. Enable Network Level Authentication (NLA).\n"
            "6. Use a non-standard port and restrict access to known IPs only."
        ),
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing — RDP",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "Password Spray": {
        "icon": "💦",
        "category_label": "Credential Attack — Password Spray",
        "what_is_happening": (
            "A single attacker IP is trying the same few common passwords (like 'Password123' or 'Welcome1') "
            "across many different services simultaneously. Unlike brute force (many passwords on one account), "
            "spray attacks avoid account lockouts by staying below the detection threshold per service."
        ),
        "why_dangerous": (
            "Password spraying is highly effective because many users do reuse simple, common passwords. "
            "It is specifically designed to evade lockout policies. Attackers running sprays often "
            "succeed within minutes on large networks. It is the entry technique used in many major "
            "corporate breaches including Microsoft and SolarWinds."
        ),
        "what_to_do": (
            "1. Block this IP immediately.\n"
            "2. Enforce strong password policies (minimum 12 characters, no common words).\n"
            "3. Enable Multi-Factor Authentication (MFA) on ALL services — this stops spray attacks cold.\n"
            "4. Check if any accounts were successfully logged into from this IP.\n"
            "5. Review authentication logs for the past 24 hours."
        ),
        "mitre_id": "T1110.003",
        "mitre_name": "Brute Force: Password Spraying",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "Credential Stuffing": {
        "icon": "📋",
        "category_label": "Credential Attack — Account Takeover",
        "what_is_happening": (
            "A high volume of login attempts is being made to your web application from a single IP. "
            "Credential stuffing uses username/password pairs stolen from other data breaches — "
            "attackers know that many people reuse passwords across sites."
        ),
        "why_dangerous": (
            "Billions of username/password combinations from past breaches are freely available online. "
            "Attackers automate testing these against your login page. Even a 0.1% success rate can "
            "mean thousands of accounts compromised. Leads to account takeover, data theft, and fraud."
        ),
        "what_to_do": (
            "1. Block this IP and its subnet.\n"
            "2. Implement CAPTCHA or rate limiting on your login page.\n"
            "3. Enable MFA for all user accounts.\n"
            "4. Check if any logins from this IP were successful — reset those passwords.\n"
            "5. Integrate with Have I Been Pwned API to detect breach passwords proactively."
        ),
        "mitre_id": "T1110.004",
        "mitre_name": "Brute Force: Credential Stuffing",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── DDoS / Network ───────────────────────────────────────────────────────
    "SYN Flood": {
        "icon": "🌊",
        "category_label": "Denial of Service — SYN Flood",
        "what_is_happening": (
            "A machine is sending massive numbers of TCP SYN packets (connection requests) without "
            "completing the handshake. This overwhelms your server's connection queue, preventing "
            "legitimate users from connecting."
        ),
        "why_dangerous": (
            "SYN floods are designed to take your services offline. Your web server, database, "
            "or any TCP service becomes unreachable to legitimate users. Attackers use this to "
            "extort businesses, distract security teams during another attack, or simply cause disruption."
        ),
        "what_to_do": (
            "1. Enable SYN cookies on your OS (protects against SYN floods without dropping legitimate connections).\n"
            "2. Rate-limit incoming SYN packets from single IPs at your firewall.\n"
            "3. If from a single IP, block it. If distributed, contact your ISP for upstream filtering.\n"
            "4. Enable DDoS protection at your network edge or use a CDN/scrubbing service (Cloudflare, Akamai)."
        ),
        "mitre_id": "T1499.002",
        "mitre_name": "Endpoint Denial of Service: Service Exhaustion Flood",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": False,
    },

    "Sustained Attack": {
        "icon": "🔴",
        "category_label": "Persistent Threat Actor",
        "what_is_happening": (
            "The same IP address has triggered multiple attack detections in a short time window. "
            "This is not random scanning — this attacker is actively and persistently targeting your network."
        ),
        "why_dangerous": (
            "Repeated verdicts from the same source mean a determined attacker who is not giving up. "
            "They may be trying multiple attack vectors until one succeeds. This level of persistence "
            "is typical of organised criminal groups or targeted intrusion campaigns."
        ),
        "what_to_do": (
            "1. Permanently block this IP at your firewall.\n"
            "2. Report the IP to AbuseIPDB and your ISP's abuse team.\n"
            "3. Review all logs for this IP to understand what they tried.\n"
            "4. Increase monitoring and alerting sensitivity for the next 24 hours.\n"
            "5. Consider engaging a cybersecurity incident response team if attacks continue."
        ),
        "mitre_id": "T1595",
        "mitre_name": "Active Scanning",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "Port Scan": {
        "icon": "🔍",
        "category_label": "Reconnaissance / Pre-Attack",
        "what_is_happening": (
            "An IP address is probing many different ports on your machine in a short time. "
            "Port scanning is how attackers map out which services are running before choosing "
            "which vulnerability to exploit."
        ),
        "why_dangerous": (
            "Port scanning is almost always the first step before an attack. The attacker is "
            "building a map of your exposed services. Once they know what is running (FTP, RDP, "
            "web server, database), they will search for known vulnerabilities to exploit."
        ),
        "what_to_do": (
            "1. Block this IP immediately to prevent follow-up attacks.\n"
            "2. Review which ports are open and close any that aren't needed.\n"
            "3. Enable port knocking or firewall whitelisting for sensitive services.\n"
            "4. The scan result gives you a list of what the attacker now knows — patch those services first."
        ),
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": False,
    },

    "Oversized Packets": {
        "icon": "📦",
        "category_label": "Network Anomaly / Possible Exfiltration",
        "what_is_happening": (
            "Packets significantly larger than the network standard (1500 bytes) have been detected. "
            "While some configurations legitimately use jumbo frames, abnormally large packets from "
            "unexpected sources can indicate data exfiltration or buffer overflow attempts."
        ),
        "why_dangerous": (
            "Attackers use oversized packets to: (a) attempt buffer overflow exploits against network "
            "devices, (b) smuggle large amounts of data in single packets to avoid per-packet "
            "inspection, or (c) cause fragmentation that confuses security tools."
        ),
        "what_to_do": (
            "1. Check if jumbo frames are legitimately configured on your network.\n"
            "2. If unexpected, investigate what data is being sent in these large packets.\n"
            "3. Check the source device for malware.\n"
            "4. Configure your firewall to drop packets exceeding MTU without legitimate jumbo frame config."
        ),
        "mitre_id": "T1030",
        "mitre_name": "Data Transfer Size Limits",
        "spy_risk": False,
        "attack_risk": False,
        "data_risk": True,
    },

    "IP Reputation": {
        "icon": "🏴",
        "category_label": "Known Malicious Host",
        "what_is_happening": (
            "This IP address is listed in the AbuseIPDB threat intelligence database as a known "
            "source of malicious activity — reported by security researchers and victims worldwide."
        ),
        "why_dangerous": (
            "Traffic from known malicious IPs is almost never legitimate. These IPs have been used "
            "for hacking, spamming, malware distribution, or scanning. Any connection from them "
            "to your network warrants immediate investigation."
        ),
        "what_to_do": (
            "1. Block this IP at your firewall immediately.\n"
            "2. Check if any internal device recently connected TO this IP (could indicate malware).\n"
            "3. If a device connected outbound to this IP, treat it as potentially compromised.\n"
            "4. Review the full AbuseIPDB report for details of known malicious activity."
        ),
        "mitre_id": "T1594",
        "mitre_name": "Search Victim-Owned Websites",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── TLS / DPI ────────────────────────────────────────────────────────────
    "Weak TLS Ciphers": {
        "icon": "🔓",
        "category_label": "Encryption Weakness",
        "what_is_happening": (
            "A device on your network is connecting using old, broken encryption algorithms (RC4, "
            "3DES, AES-CBC without forward secrecy). Modern TLS should use AES-GCM or ChaCha20. "
            "Using weak ciphers means your 'encrypted' connection can potentially be decrypted."
        ),
        "why_dangerous": (
            "Weak TLS ciphers mean your encrypted connections may not be truly private. An attacker "
            "who records your network traffic today can decrypt it later as computing power grows. "
            "Some weak ciphers (RC4) can be broken in real time with enough traffic."
        ),
        "what_to_do": (
            "1. Identify the application making this connection — it may be outdated software.\n"
            "2. Update the application or its TLS library.\n"
            "3. If it's a server you control, disable weak cipher suites in your TLS configuration.\n"
            "4. Enforce TLS 1.2+ minimum and disable TLS 1.0/1.1 across your infrastructure."
        ),
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "spy_risk": True,
        "attack_risk": False,
        "data_risk": True,
    },

    "TLS without SNI": {
        "icon": "👻",
        "category_label": "Suspicious Encrypted Connection",
        "what_is_happening": (
            "An HTTPS connection was made to an IP address directly, without sending a Server Name "
            "Indication (SNI) header. Legitimate browsers always send SNI. Connecting without it "
            "means the client is deliberately hiding which server it's connecting to."
        ),
        "why_dangerous": (
            "Malware often connects to its command server by raw IP address to avoid DNS filtering "
            "and domain blacklists. The lack of SNI makes it harder to inspect what the connection "
            "is for. This is a strong indicator of malware C2 traffic or a VPN/proxy being used "
            "to bypass security controls."
        ),
        "what_to_do": (
            "1. Identify which process on the source device is making this connection.\n"
            "2. Use netstat or Process Monitor to find the application.\n"
            "3. If unknown, treat the device as potentially compromised and run a malware scan.\n"
            "4. Block direct IP HTTPS connections at your firewall if not required."
        ),
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "spy_risk": True,
        "attack_risk": False,
        "data_risk": True,
    },

    "Malicious TLS": {
        "icon": "☠",
        "category_label": "Known C2 Framework Detected",
        "what_is_happening": (
            "The TLS fingerprint (JA3 hash) of an encrypted connection on your network exactly matches "
            "a known offensive hacking tool — such as Cobalt Strike, Metasploit, or a banking trojan. "
            "This means a recognised attacker tool is communicating on your network right now."
        ),
        "why_dangerous": (
            "This is one of the most serious alerts possible. Cobalt Strike and Metasploit are professional "
            "penetration testing frameworks routinely weaponised by ransomware gangs and nation-state actors. "
            "If this fingerprint matches, an attacker likely has active control of a device on your network "
            "and is using it as a launchpad for further attacks, data exfiltration, or ransomware deployment."
        ),
        "what_to_do": (
            "TREAT THIS AS AN ACTIVE INCIDENT — DO NOT DELAY:\n"
            "1. Immediately identify which device generated this TLS connection (check the source IP).\n"
            "2. Isolate that device from the network — unplug its cable or disable its Wi-Fi.\n"
            "3. Do NOT shut it down — preserves memory for forensic investigation.\n"
            "4. Block the destination IP at your firewall.\n"
            "5. Alert your incident response team or cybersecurity professional immediately.\n"
            "6. Preserve network logs and memory dumps before any remediation."
        ),
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "TLS Fingerprint Scanning": {
        "icon": "🔎",
        "category_label": "Automated TLS Scanning",
        "what_is_happening": (
            "A single TLS client fingerprint (JA3 hash) has connected to 15+ different destinations. "
            "This pattern matches automated scanners or malware rapidly contacting multiple servers "
            "using the same TLS client configuration."
        ),
        "why_dangerous": (
            "This is typical of botnet malware performing internet-wide scanning, data exfiltration "
            "to multiple backup C2 servers, or an infected machine being used to probe other targets. "
            "A legitimate user's browser would not contact 15+ distinct servers with identical TLS parameters."
        ),
        "what_to_do": (
            "1. Identify the device with this JA3 fingerprint.\n"
            "2. Check which process is generating the connections.\n"
            "3. Run a malware scan — this pattern strongly suggests automated malicious activity.\n"
            "4. Review outbound connection logs for the past 24 hours."
        ),
        "mitre_id": "T1595.001",
        "mitre_name": "Active Scanning: Scanning IP Blocks",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── Event Log ─────────────────────────────────────────────────────────────
    "Audit Log Cleared": {
        "icon": "🗑",
        "category_label": "Evidence Tampering — CRITICAL",
        "what_is_happening": (
            "The Windows Security event log was cleared. This is one of the most serious security "
            "events possible — it destroys the forensic record of everything that has happened on this machine."
        ),
        "why_dangerous": (
            "Attackers clear event logs after a breach to destroy evidence of what they did — "
            "which accounts they used, what files they accessed, what malware they installed. "
            "Legitimate administrators rarely clear security logs. This is a strong indicator "
            "that someone is covering their tracks after a compromise."
        ),
        "what_to_do": (
            "TREAT THIS AS AN ACTIVE INCIDENT:\n"
            "1. Who cleared the log? Check the event data for the username.\n"
            "2. If it was not an authorised administrator, assume breach.\n"
            "3. Take a memory dump and disk image of the system immediately.\n"
            "4. Isolate the machine from the network.\n"
            "5. Engage your incident response team or a forensic specialist.\n"
            "6. Forward event logs to a remote SIEM in real time to prevent future log clearing."
        ),
        "mitre_id": "T1070.001",
        "mitre_name": "Indicator Removal: Clear Windows Event Logs",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "Added to Administrators": {
        "icon": "👑",
        "category_label": "Privilege Escalation",
        "what_is_happening": (
            "A user account has been added to the local Administrators group. Administrator accounts "
            "have unrestricted access to everything on the machine — files, settings, other accounts, and the registry."
        ),
        "why_dangerous": (
            "Attackers add their accounts to the Administrators group to maintain persistent, privileged "
            "access even after a password reset. With admin rights they can install software, create "
            "backdoors, disable antivirus, access encrypted files, and spread to other machines."
        ),
        "what_to_do": (
            "1. Was this change authorised by IT? If not — treat as active compromise.\n"
            "2. Remove the newly added account from Administrators immediately.\n"
            "3. Change the password of any account that was used to make this change.\n"
            "4. Review what actions the new admin account took since being added.\n"
            "5. Enable alerts for all future changes to privileged groups."
        ),
        "mitre_id": "T1098",
        "mitre_name": "Account Manipulation",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "New Service Installed": {
        "icon": "⚙",
        "category_label": "Persistence Mechanism",
        "what_is_happening": (
            "A new Windows service was installed. Services run in the background with elevated privileges "
            "and start automatically with Windows. This is one of the most common ways malware "
            "ensures it survives reboots and remains active even after you log out."
        ),
        "why_dangerous": (
            "Malware installs itself as a service to achieve persistence — it will restart every time "
            "the computer boots. Rootkits, RATs (Remote Access Trojans), ransomware loaders, and "
            "keyloggers commonly use this technique. The service may run as SYSTEM (highest privilege)."
        ),
        "what_to_do": (
            "1. Verify the service name — was this installed by known software you just installed?\n"
            "2. Run 'services.msc' and find the new service — check its executable path.\n"
            "3. Google the executable path — is it a known malicious file?\n"
            "4. If suspicious, stop and disable the service immediately.\n"
            "5. Run antivirus and submit the executable to VirusTotal.\n"
            "6. If confirmed malicious, do not just delete it — preserve evidence and consult forensics."
        ),
        "mitre_id": "T1543.003",
        "mitre_name": "Create or Modify System Process: Windows Service",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "New Local Account": {
        "icon": "👤",
        "category_label": "Backdoor Account Creation",
        "what_is_happening": (
            "A new local user account was created on this machine. Attackers create local accounts "
            "to maintain access even if the account they initially used to break in is discovered and locked."
        ),
        "why_dangerous": (
            "An unauthorised local account is a hidden backdoor. Even if you change all your passwords "
            "and think you've secured the machine, the attacker can still log in with their own account. "
            "It is a persistence technique used by APT groups and ransomware operators."
        ),
        "what_to_do": (
            "1. Review all local accounts: run 'net user' in Command Prompt.\n"
            "2. Is this a new account you or IT created? If not, delete it immediately.\n"
            "3. Check the account's group memberships — is it in Administrators?\n"
            "4. Review what logins the account has had since creation.\n"
            "5. Treat the machine as potentially compromised and investigate further."
        ),
        "mitre_id": "T1136.001",
        "mitre_name": "Create Account: Local Account",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": False,
    },

    "Failed Logon": {
        "icon": "🔐",
        "category_label": "Failed Authentication Attempt",
        "what_is_happening": (
            "A login attempt to this machine failed. A single failure is normal (mistyped password), "
            "but repeated failures indicate a brute force attack or an attacker trying known credentials."
        ),
        "why_dangerous": (
            "Repeated failed logons mean someone is actively trying to break into this machine. "
            "If they succeed, they gain access to everything on the system under that user's account."
        ),
        "what_to_do": (
            "1. Was this you mistyping your own password? No action needed.\n"
            "2. Multiple failures from an external IP? Block that IP immediately.\n"
            "3. Enable account lockout after 5 failed attempts.\n"
            "4. Enable MFA for all accounts.\n"
            "5. Check if the targeted username is a real account — rename default 'Administrator' account."
        ),
        "mitre_id": "T1110",
        "mitre_name": "Brute Force",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": False,
    },

    "Scheduled Task Created": {
        "icon": "⏰",
        "category_label": "Persistence — Scheduled Task",
        "what_is_happening": (
            "A new scheduled task was created on this system. Scheduled tasks can run programs "
            "automatically at specific times or events. Malware uses them to re-launch itself "
            "after being killed, or to run payloads at specific times."
        ),
        "why_dangerous": (
            "Scheduled tasks are a favourite persistence mechanism because they survive reboots, "
            "are easy to hide among many legitimate tasks, and can run with system-level privileges. "
            "Ransomware, RATs, and cryptominers commonly use scheduled tasks."
        ),
        "what_to_do": (
            "1. Open Task Scheduler and find the new task — note its action (what program it runs).\n"
            "2. Was this created by software you just installed? If yes, it may be legitimate.\n"
            "3. If the task runs an unknown executable or script, treat as suspicious.\n"
            "4. Submit the executable to VirusTotal.\n"
            "5. Disable or delete suspicious tasks and investigate the source."
        ),
        "mitre_id": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task",
        "spy_risk": False,
        "attack_risk": False,
        "data_risk": False,
    },

    # ── FIM ─────────────────────────────────────────────────────────────────
    "FIM — File Modified": {
        "icon": "📝",
        "category_label": "File Tampering Detected",
        "what_is_happening": (
            "The SHA-256 hash of a monitored file has changed — meaning its contents have been "
            "altered since the last baseline scan. File integrity monitoring catches changes that "
            "would otherwise be invisible."
        ),
        "why_dangerous": (
            "Unauthorised file modification could mean: malware injected code into a legitimate "
            "program, an attacker modified configuration files to create backdoors, a webshell "
            "was planted in a web server's files, or ransomware has begun encrypting files."
        ),
        "what_to_do": (
            "1. Compare the current file with the previous known-good version (check version control or backup).\n"
            "2. What changed? Added lines of code? Changed configuration? Encrypted content?\n"
            "3. If a system file was modified unexpectedly, treat as potential rootkit activity.\n"
            "4. Run antivirus on the modified file.\n"
            "5. Restore from a clean backup if the modification was not authorised."
        ),
        "mitre_id": "T1565.001",
        "mitre_name": "Data Manipulation: Stored Data Manipulation",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "FIM — File Created": {
        "icon": "📄",
        "category_label": "Unexpected File Appeared",
        "what_is_happening": (
            "A new file has appeared in a monitored directory that was not there during the last scan. "
            "This could be a newly installed file, a downloaded payload, or a file dropped by malware."
        ),
        "why_dangerous": (
            "Malware drops executable files, scripts, or configuration files into system or application "
            "directories. Webshells are planted as PHP/ASP files in web directories. Attackers leave "
            "tools and backdoor files for later use."
        ),
        "what_to_do": (
            "1. Was this file created by you or an installer you ran? If yes, no action needed.\n"
            "2. If unexpected: What is the file type? Is it executable (.exe, .dll, .ps1, .vbs)?\n"
            "3. Do not run an unknown executable — submit it to VirusTotal first.\n"
            "4. Check the file creation timestamp and correlate with other system activity."
        ),
        "mitre_id": "T1105",
        "mitre_name": "Ingress Tool Transfer",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": False,
    },

    "FIM — File Deleted": {
        "icon": "🗑",
        "category_label": "File Deleted from Monitored Directory",
        "what_is_happening": (
            "A previously monitored file has been deleted. While files can be legitimately deleted "
            "during updates or uninstalls, unexpected deletions in system or config directories "
            "warrant investigation."
        ),
        "why_dangerous": (
            "Attackers delete log files, security tool executables, and forensic evidence to cover tracks. "
            "Ransomware deletes shadow copies and backups before encrypting files. Wipers (destructive malware) "
            "systematically delete or corrupt files to cause maximum damage."
        ),
        "what_to_do": (
            "1. Was this deletion expected (uninstaller, update, cleanup)?\n"
            "2. Was it a security tool, log file, or backup that was deleted? High priority.\n"
            "3. Check the Recycle Bin and restore from backup if needed.\n"
            "4. Correlate with other alerts — deletion alongside ARP spoofing or log clearing is very serious."
        ),
        "mitre_id": "T1485",
        "mitre_name": "Data Destruction",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── UEBA ─────────────────────────────────────────────────────────────────
    "UEBA — Off-Hours Login": {
        "icon": "🌙",
        "category_label": "Suspicious User Behaviour",
        "what_is_happening": (
            "A user account logged into the system at an unusual time — outside the normal working "
            "hours pattern established by their previous logins. This could be legitimate (overtime, "
            "travel) but also matches the pattern of compromised account abuse."
        ),
        "why_dangerous": (
            "Attackers who steal credentials prefer to use them late at night or early morning when "
            "fewer people are watching. Off-hours logins are a classic indicator of account compromise. "
            "Many high-profile breaches were only discovered by noticing logins at 3am."
        ),
        "what_to_do": (
            "1. Contact the user directly — were they actually working at that time?\n"
            "2. Check where the login came from (workstation name, IP address).\n"
            "3. If the user was not working, assume account compromise: reset password immediately.\n"
            "4. Enable MFA to prevent future unauthorised logins even with the correct password.\n"
            "5. Review what the account accessed during the off-hours session."
        ),
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    "UEBA — New Workstation": {
        "icon": "💻",
        "category_label": "Login from Unknown Device",
        "what_is_happening": (
            "A user account has logged in from a computer or workstation that this account has never "
            "used before. While this can happen when a user switches computers, it can also indicate "
            "that stolen credentials are being used from an attacker's machine."
        ),
        "why_dangerous": (
            "When credentials are stolen (via phishing, keylogger, or data breach), the attacker "
            "logs in from their own machine — which appears as an unknown workstation. This is "
            "one of the clearest signals of credential theft and unauthorised access."
        ),
        "what_to_do": (
            "1. Verify with the user: are they using a new or borrowed computer?\n"
            "2. If the new workstation is unexpected, reset the account password immediately.\n"
            "3. Enable MFA — a new device login would then require physical device confirmation.\n"
            "4. Check what data the account accessed from the new workstation."
        ),
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "spy_risk": True,
        "attack_risk": False,
        "data_risk": True,
    },

    "UEBA — Failed Logon Spike": {
        "icon": "💥",
        "category_label": "Account Under Attack",
        "what_is_happening": (
            "Multiple failed login attempts for the same user account within 60 seconds. This matches "
            "an automated brute force or credential stuffing attack specifically targeting this account."
        ),
        "why_dangerous": (
            "Your account is being targeted. If the attacker has the right password from a previous "
            "data breach, they may succeed. Even with a unique password, some attackers use GPU-powered "
            "tools that can test millions of combinations per second."
        ),
        "what_to_do": (
            "1. Lock the account temporarily to stop the attack.\n"
            "2. Reset the password to a unique, strong password (20+ characters, password manager).\n"
            "3. Enable MFA immediately.\n"
            "4. Block the attacking IP.\n"
            "5. Check if any attempt succeeded before the lockout."
        ),
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "spy_risk": False,
        "attack_risk": True,
        "data_risk": True,
    },

    "UEBA — Privilege Escalation": {
        "icon": "👑",
        "category_label": "Privilege Escalation Detected",
        "what_is_happening": (
            "The UEBA engine detected a privilege escalation event for a user — they were given "
            "administrator rights unexpectedly based on their normal behaviour profile."
        ),
        "why_dangerous": (
            "Attackers who gain access to a standard user account often immediately try to escalate "
            "to administrator. With admin rights they can do anything — install backdoors, disable "
            "security tools, access all files, and spread across the network."
        ),
        "what_to_do": (
            "1. Was this change approved by IT? If not, reverse it immediately.\n"
            "2. Investigate how the escalation happened — exploit? Social engineering? IT mistake?\n"
            "3. Apply the principle of least privilege — users should only have the access they need.\n"
            "4. Review all actions taken by this account since escalation."
        ),
        "mitre_id": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── Threat Intel ─────────────────────────────────────────────────────────
    "Threat Intelligence Hit": {
        "icon": "🏴",
        "category_label": "Known Malicious IP",
        "what_is_happening": (
            "AbuseIPDB confirmed this IP address has been reported by security researchers as malicious. "
            "It has a history of hacking, scanning, spam, or malware distribution."
        ),
        "why_dangerous": (
            "Traffic to/from known malicious IPs is almost never legitimate. If your device is "
            "contacting this IP, it may be infected with malware phoning home. If this IP is "
            "contacting you, it is actively probing or attacking your systems."
        ),
        "what_to_do": (
            "1. Block this IP permanently at your firewall.\n"
            "2. Check if any internal device connected OUTBOUND to this IP — if so, assume malware infection.\n"
            "3. Check the full AbuseIPDB report for the type of abuse and when it was last reported.\n"
            "4. If a device is infected, quarantine and scan it immediately."
        ),
        "mitre_id": "T1594",
        "mitre_name": "Search Victim-Owned Websites",
        "spy_risk": True,
        "attack_risk": True,
        "data_risk": True,
    },

    # ── IP Blocker ────────────────────────────────────────────────────────────
    "IP Auto-Blocked": {
        "icon": "🔒",
        "category_label": "Automatic Firewall Block Applied",
        "what_is_happening": (
            "The Security Monitor automatically added a Windows Firewall rule to block this IP "
            "address after detecting malicious activity. Both inbound and outbound traffic to this "
            "IP is now blocked at the firewall level."
        ),
        "why_dangerous": (
            "This is a protective action, not a threat itself. The block was triggered because "
            "this IP was involved in a detected attack. The firewall rule prevents further contact."
        ),
        "what_to_do": (
            "1. The block is already in place — no immediate action required.\n"
            "2. The block will automatically expire based on the configured TTL.\n"
            "3. To make it permanent, go to Blocked IPs tab and disable auto-expiry.\n"
            "4. Review the triggering alert to understand what attack this IP was performing."
        ),
        "mitre_id": None,
        "mitre_name": None,
        "spy_risk": False,
        "attack_risk": False,
        "data_risk": False,
    },
}

# ── Default context for unknown rules ────────────────────────────────────────

_DEFAULT = {
    "icon": "⚠",
    "category_label": "Security Alert",
    "what_is_happening": (
        "An anomalous or potentially malicious event was detected on your network or system."
    ),
    "why_dangerous": (
        "This event matches known threat patterns and warrants investigation to determine "
        "whether it represents a real threat to your security."
    ),
    "what_to_do": (
        "1. Review the technical details of this alert.\n"
        "2. Identify which device or user is involved.\n"
        "3. Determine if the activity is legitimate before taking action.\n"
        "4. If in doubt, block the source IP and investigate further."
    ),
    "mitre_id": None,
    "mitre_name": None,
    "spy_risk": False,
    "attack_risk": True,
    "data_risk": False,
}


def get_context(rule_name: str) -> dict:
    """
    Return the threat context for a given rule_name.
    Falls back to _DEFAULT for unknown rules.
    Partial matching: 'SSH Brute Force' matches 'SSH Brute Force' key,
    and 'Telnet Brute Force' matches the brute-force default.
    """
    if rule_name in _DB:
        return _DB[rule_name]

    # Partial / pattern matching for dynamically named rules
    for key, ctx in _DB.items():
        if "Brute Force" in rule_name and "Brute Force" in key and key.endswith("Brute Force"):
            adapted = dict(ctx)
            adapted["what_is_happening"] = ctx["what_is_happening"].replace("SSH", rule_name.split()[0])
            return adapted

    return _DEFAULT


def risk_tags(rule_name: str) -> list[str]:
    """Return a list of risk indicator tags for a rule."""
    ctx = get_context(rule_name)
    tags = []
    if ctx.get("spy_risk"):
        tags.append("🕵 Surveillance Risk")
    if ctx.get("attack_risk"):
        tags.append("⚔ Active Attack")
    if ctx.get("data_risk"):
        tags.append("📤 Data Theft Risk")
    return tags
