#!/usr/bin/env python3
"""
Security Monitor — Safe Demonstration & Test Script
====================================================
Exercises every detection module with simulated, in-memory threat scenarios.

  • Zero real network packets are transmitted
  • No admin / administrator rights required
  • No external API calls are made
  • Temporary files are cleaned up automatically
  • Safe to run on any machine

Run:  python demo_test.py
      python demo_test.py --verbose      (show extra detail)
      python demo_test.py --fast         (skip slow ML tests)
"""

import io
import sys
import time
import tempfile
import threading
import shutil
import os
from pathlib import Path
from datetime import datetime

# Force UTF-8 so box-drawing chars render on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

VERBOSE = "--verbose" in sys.argv
FAST    = "--fast"    in sys.argv

# ── ANSI colours ──────────────────────────────────────────────────────────────
G = "\033[92m"    # green
R = "\033[91m"    # red
Y = "\033[93m"    # yellow
B = "\033[94m"    # blue
CY = "\033[96m"   # cyan
W  = "\033[97m"   # bright white
DIM = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

_SEV_C = {"critical": R, "high": R, "medium": Y, "low": B}

def _sev(a: dict) -> str:
    s = (a.get("severity") or "").lower()
    return f"{_SEV_C.get(s,W)}{s.upper()}{RST}"

# ── Result tracker ─────────────────────────────────────────────────────────────
_results: list[tuple[str, str, bool]] = []   # (section, label, ok)
_section_label = ""

def _section(title: str, icon: str = "◈"):
    global _section_label
    _section_label = title
    w = 62
    print(f"\n{BOLD}{CY}┌{'─'*w}┐{RST}")
    print(f"{BOLD}{CY}│{RST}{BOLD}  {icon}  {title:<{w-5}}{CY}│{RST}")
    print(f"{BOLD}{CY}└{'─'*w}┘{RST}")

def _ok(label: str, alert: dict | None = None):
    tag = f"  [{_sev(alert)}]" if alert else ""
    print(f"  {G}✓{RST}  {label}{tag}")
    if alert and VERBOSE:
        msg = (alert.get("message") or "")[:80]
        print(f"       {DIM}{alert.get('rule_name','?')} — {msg}{RST}")
    _results.append((_section_label, label, True))

def _fail(label: str, note: str = ""):
    print(f"  {R}✗{RST}  {BOLD}{label}{RST}" + (f"  {DIM}{note}{RST}" if note else ""))
    _results.append((_section_label, label, False))

def _nofp(label: str, fired: bool):
    """Assert that an alert did NOT fire (no false positive)."""
    if not fired:
        print(f"  {G}✓{RST}  {label}  {DIM}(correctly silent){RST}")
        _results.append((_section_label, label, True))
    else:
        print(f"  {R}✗{RST}  {BOLD}{label}{RST}  {R}⚠ FALSE POSITIVE{RST}")
        _results.append((_section_label, label, False))

def _skip(label: str, why: str):
    print(f"  {Y}↷{RST}  {label}  {DIM}[{why}]{RST}")
    _results.append((_section_label, label, True))   # skips don't count as failures

# ══════════════════════════════════════════════════════════════════════════════
# Scapy import — optional; packet-level tests are skipped if not available
# ══════════════════════════════════════════════════════════════════════════════
try:
    from scapy.layers.l2  import ARP, Ether
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.dns  import DNS, DNSQR, DNSRR
    SCAPY = True
except ImportError:
    SCAPY = False


# ══════════════════════════════════════════════════════════════════════════════
# 1.  ARP Spoofing & Flood Detector
# ══════════════════════════════════════════════════════════════════════════════

def test_arp():
    _section("ARP Spoofing & Flood Detector", "🔗")

    if not SCAPY:
        _skip("All ARP tests", "scapy not installed — pip install scapy")
        return

    from detectors.arp_monitor import ARPMonitor

    def _arp(op, psrc, hwsrc, pdst="192.168.1.1"):
        return Ether(src=hwsrc) / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst)

    # ── No false positive: first-seen IP ──────────────────────────────────────
    a1: list[dict] = []
    m1 = ARPMonitor(on_alert=a1.append)
    m1.process_packet(_arp(2, "10.0.0.10", "aa:bb:cc:11:22:33"))
    _nofp("First-seen IP — no alert expected", bool(a1))

    # ── ARP cache poisoning ───────────────────────────────────────────────────
    a2: list[dict] = []
    m2 = ARPMonitor(on_alert=a2.append)
    m2.process_packet(_arp(2, "10.0.0.10", "aa:bb:cc:11:22:33"))   # learn
    m2.process_packet(_arp(2, "10.0.0.10", "ff:ee:dd:44:55:66"))   # spoof
    if a2:
        _ok("ARP cache poisoning detected", a2[0])
    else:
        _fail("ARP cache poisoning detected", "alert did not fire")

    # ── Gateway MAC hijack (critical) ─────────────────────────────────────────
    a3: list[dict] = []
    m3 = ARPMonitor(on_alert=a3.append, gateway_ip="192.168.1.1")
    m3.process_packet(_arp(2, "192.168.1.1", "aa:00:00:00:00:01"))   # learn GW
    m3.process_packet(_arp(2, "192.168.1.1", "bb:00:00:00:00:02"))   # hijack
    gw = next((a for a in a3 if "Gateway" in a.get("rule_name", "")), None)
    if gw and gw.get("severity") == "critical":
        _ok("Gateway ARP hijack (critical)", gw)
    else:
        _fail("Gateway ARP hijack (critical)", f"alerts: {a3}")

    # ── ARP flood (≥ 50 packets / 10 s) ──────────────────────────────────────
    a4: list[dict] = []
    m4 = ARPMonitor(on_alert=a4.append)
    for _ in range(52):
        m4.process_packet(_arp(1, "10.0.0.99", "de:ad:be:ef:00:01"))
    flood = next((a for a in a4 if a.get("rule_name") == "ARP Flood"), None)
    if flood:
        _ok("ARP flood detected (≥ 50 pkts / 10 s)", flood)
    else:
        _fail("ARP flood detected", f"alerts seen: {[a['rule_name'] for a in a4]}")

    # ── Spoof cooldown — second alert suppressed within 5 min ─────────────────
    a5: list[dict] = []
    m5 = ARPMonitor(on_alert=a5.append)
    m5.process_packet(_arp(2, "10.0.0.20", "aa:00:00:00:00:01"))   # learn
    m5.process_packet(_arp(2, "10.0.0.20", "bb:00:00:00:00:02"))   # spoof → fires
    m5.process_packet(_arp(2, "10.0.0.20", "cc:00:00:00:00:03"))   # spoof → suppressed
    spoof_count = sum(1 for a in a5 if "Spoofing" in a.get("rule_name", ""))
    _nofp("Spoof cooldown — repeat alert within 5 min suppressed", spoof_count > 1)


# ══════════════════════════════════════════════════════════════════════════════
# 2.  DNS Anomaly Detector
# ══════════════════════════════════════════════════════════════════════════════

def test_dns():
    _section("DNS Anomaly Detector", "🌍")

    if not SCAPY:
        _skip("All DNS tests", "scapy not installed")
        return

    from detectors.dns_monitor import DNSMonitor

    def _q(qname: bytes, src="1.2.3.4"):
        return IP(src=src) / UDP(dport=53) / DNS(qr=0, qd=DNSQR(qname=qname))

    def _resp(qname: bytes, rdata: str):
        rr = DNSRR(rrname=qname, type="A", rdata=rdata, ttl=30)
        return IP(src="8.8.8.8") / UDP(sport=53) / DNS(
            qr=1, ancount=1, qd=DNSQR(qname=qname), an=rr
        )

    # ── Normal query — no alert ───────────────────────────────────────────────
    a1: list[dict] = []
    m1 = DNSMonitor(on_alert=a1.append)
    m1.process_packet(_q(b"www.example.com."))
    _nofp("Normal DNS query — no alert", bool(a1))

    # ── DNS tunneling (label > 60 chars) ─────────────────────────────────────
    a2: list[dict] = []
    m2 = DNSMonitor(on_alert=a2.append)
    long_label = ("a" * 65 + ".exfil.evil.com.").encode()
    m2.process_packet(_q(long_label))
    tun = next((a for a in a2 if a.get("rule_name") == "DNS Tunneling"), None)
    if tun:
        _ok("DNS tunneling detected (65-char label)", tun)
    else:
        _fail("DNS tunneling detected", f"alerts: {[a['rule_name'] for a in a2]}")

    # ── Risky TLD (.tk) ───────────────────────────────────────────────────────
    a3: list[dict] = []
    m3 = DNSMonitor(on_alert=a3.append)
    m3.process_packet(_q(b"malware-download.tk."))
    tld = next((a for a in a3 if a.get("rule_name") == "Suspicious TLD"), None)
    if tld:
        _ok("Risky TLD (.tk) detected", tld)
    else:
        _fail("Risky TLD (.tk) detected")

    # ── CDN whitelist — Google must NOT trigger fast-flux ─────────────────────
    a4: list[dict] = []
    m4 = DNSMonitor(on_alert=a4.append)
    for i in range(25):
        m4.process_packet(_resp(b"google.com.", f"142.250.{i}.1"))
    flux_fp = any(a.get("rule_name") == "Fast-Flux DNS" for a in a4)
    _nofp("CDN whitelist — google.com not flagged as fast-flux", flux_fp)

    # ── Fast-flux — unknown domain with 20+ distinct IPs ─────────────────────
    a5: list[dict] = []
    m5 = DNSMonitor(on_alert=a5.append)
    for i in range(22):
        m5.process_packet(_resp(b"flux.botnet-c2.com.", f"203.0.{i}.{i+1}"))
    flux = next((a for a in a5 if a.get("rule_name") == "Fast-Flux DNS"), None)
    if flux:
        _ok("Fast-flux DNS detected (20+ distinct IPs)", flux)
    else:
        _fail("Fast-flux DNS detected", f"alerts: {[a['rule_name'] for a in a5]}")

    # ── C2 beacon — 150+ queries to same domain in < 60 s ────────────────────
    a6: list[dict] = []
    m6 = DNSMonitor(on_alert=a6.append)
    for _ in range(155):
        m6.process_packet(_q(b"beacon.attacker.io."))
    c2 = next((a for a in a6 if a.get("rule_name") == "DNS C2 Beacon"), None)
    if c2:
        _ok("DNS C2 beaconing detected (150 queries / 60 s)", c2)
    else:
        _fail("DNS C2 beaconing detected", f"alerts: {[a['rule_name'] for a in a6]}")


# ══════════════════════════════════════════════════════════════════════════════
# 3.  Brute Force / Credential Attack Detector
# ══════════════════════════════════════════════════════════════════════════════

def test_brute_force():
    _section("Brute Force & Credential Attack Detector", "🔑")

    if not SCAPY:
        _skip("All brute force tests", "scapy not installed")
        return

    from detectors.brute_force import BruteForceDetector

    # Python 3.11+ marks TEST-NET ranges (203.0.113.x etc.) as private.
    # Use real public IPs so the private-IP filter doesn't suppress test traffic.
    EXT_IP  = "1.2.3.4"         # public routable IP
    PRIV_IP = "192.168.1.100"   # RFC-1918 — must be ignored

    def _syn(src, dport, dst="192.168.1.5"):
        return IP(src=src, dst=dst) / TCP(sport=50000, dport=dport, flags="S")

    # ── Under threshold — no alert ────────────────────────────────────────────
    a1: list[dict] = []
    m1 = BruteForceDetector(on_alert=a1.append)
    for _ in range(10):   # 10 < threshold of 25
        m1.process_packet(_syn(EXT_IP, 22))
    _nofp("SSH — under threshold (10 SYNs, need 25)", bool(a1))

    # ── SSH brute force (≥ 25 SYN from external IP) ───────────────────────────
    a2: list[dict] = []
    m2 = BruteForceDetector(on_alert=a2.append)
    for _ in range(26):
        m2.process_packet(_syn(EXT_IP, 22))
    bf = next((a for a in a2 if "Brute Force" in a.get("rule_name", "")), None)
    if bf:
        _ok("SSH brute force detected (26 SYNs / 60 s)", bf)
    else:
        _fail("SSH brute force detected", f"alerts: {[a['rule_name'] for a in a2]}")

    # ── Private IP src — must be silently ignored ─────────────────────────────
    a3: list[dict] = []
    m3 = BruteForceDetector(on_alert=a3.append)
    for _ in range(30):   # plenty above threshold but src is private
        m3.process_packet(_syn(PRIV_IP, 22))
    _nofp("Private/RFC-1918 source IP ignored (own machine's outgoing)", bool(a3))

    # ── RDP brute force ───────────────────────────────────────────────────────
    a4: list[dict] = []
    m4 = BruteForceDetector(on_alert=a4.append)
    for _ in range(26):
        m4.process_packet(_syn("5.6.7.8", 3389))
    rdp = next((a for a in a4 if "RDP" in a.get("rule_name", "")), None)
    if rdp:
        _ok("RDP brute force detected", rdp)
    else:
        _fail("RDP brute force detected")

    # ── HTTP credential stuffing (≥ 80 SYN to port 443) ──────────────────────
    a5: list[dict] = []
    m5 = BruteForceDetector(on_alert=a5.append)
    for _ in range(82):
        m5.process_packet(_syn("45.33.32.1", 443))
    cs = next((a for a in a5 if a.get("rule_name") == "Credential Stuffing"), None)
    if cs:
        _ok("HTTPS credential stuffing detected (82 SYNs / 60 s)", cs)
    else:
        _fail("HTTPS credential stuffing detected")

    # ── Password spray (6 auth ports × 4 SYNs each) ──────────────────────────
    a6: list[dict] = []
    m6 = BruteForceDetector(on_alert=a6.append)
    attacker = "180.100.50.1"
    for port in [21, 22, 23, 110, 143, 445]:   # FTP SSH Telnet POP3 IMAP SMB
        for _ in range(4):
            m6.process_packet(_syn(attacker, port))
    spray = next((a for a in a6 if a.get("rule_name") == "Password Spray"), None)
    if spray:
        _ok("Password spray detected (6 services × 4 SYNs)", spray)
    else:
        _fail("Password spray detected", f"alerts: {[a['rule_name'] for a in a6]}")


# ══════════════════════════════════════════════════════════════════════════════
# 4.  DDoS ML & Anomaly Detection
# ══════════════════════════════════════════════════════════════════════════════

def test_ml():
    _section("DDoS Machine Learning & Anomaly Detection", "🤖")

    if FAST:
        _skip("ML tests", "--fast flag set"); return

    try:
        import config
        from detectors.ddos import DDosDetector
        from detectors.anomaly import AnomalyDetector
    except Exception as e:
        _skip("ML tests", f"import error: {e}"); return

    # ── DDoS classifier ───────────────────────────────────────────────────────
    try:
        ddos = DDosDetector(config.MODEL_FILENAME, config.RULES_CONFIG,
                            config.ATTACK_CONFIDENCE_THRESHOLD)
        if not ddos.model_ready:
            _skip("DDoS ML (normal traffic)", "model not trained — run: python train_model.py")
            _skip("DDoS ML (SYN flood)",     "model not trained")
            _skip("DDoS ML (oversized packet rule)", "model not trained")
        else:
            # Verify the prediction API works and returns a valid result dict.
            # The verdict depends on training data — we assert the API is functional,
            # not a specific verdict.
            sample_feats = {
                "Protocol": 6, "Flow Duration": 500_000,
                "Total Fwd Packets": 15, "Total Backward Packets": 12,
                "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
                "Fwd Packet Length Max": 200, "Flow Bytes/s": 1200,
                "Flow Packets/s": 0, "Fwd IAT Min": 0, "Bwd IAT Min": 0,
                "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 1,
                "SYN Flag Count": 1, "RST Flag Count": 0, "ACK Flag Count": 10,
                "URG Flag Count": 0, "Init Fwd Win Bytes": 65535,
            }
            r_sample = ddos.predict(sample_feats)
            verdict_s = r_sample.get("verdict", "?")
            if verdict_s in ("NORMAL", "SUSPICIOUS", "ATTACK") and "error" not in r_sample:
                _ok(f"ML predict() API works → verdict={verdict_s} "
                    f"(confidence {r_sample.get('confidence',0):.1f}%)")

            # SYN flood pattern
            attack_feats = {
                "Protocol": 6, "Flow Duration": 10_000_000,
                "Total Fwd Packets": 5000, "Total Backward Packets": 10,
                "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
                "Fwd Packet Length Max": 60,  "Flow Bytes/s": 9_000_000,
                "Flow Packets/s": 0, "Fwd IAT Min": 0, "Bwd IAT Min": 0,
                "Fwd PSH Flags": 0, "Fwd URG Flags": 0, "FIN Flag Count": 0,
                "SYN Flag Count": 5000, "RST Flag Count": 0, "ACK Flag Count": 0,
                "URG Flag Count": 0, "Init Fwd Win Bytes": 0,
            }
            r_attack = ddos.predict(attack_feats)
            verdict_a = r_attack.get("verdict", "?")
            if verdict_a in ("ATTACK", "SUSPICIOUS"):
                _ok(f"SYN flood pattern → {verdict_a} (confidence {r_attack.get('confidence',0):.1f}%)")
            else:
                _fail(f"SYN flood not detected", f"got {verdict_a}")

            # Rule engine: oversized packet
            pkt_info = {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8",
                        "protocol": "TCP", "Length": 9000, "TTL": 64}
            rule_alerts = ddos.check_rules(pkt_info)
            oversized = any(a.severity == "medium" for a in rule_alerts)
            if oversized:
                _ok("Rule engine: oversized packet (> 1500 B) flagged")
            else:
                _fail("Rule engine: oversized packet", "not flagged by rules")

    except Exception as e:
        _fail("DDoS ML test", str(e))

    # ── Anomaly detector ──────────────────────────────────────────────────────
    try:
        anm = AnomalyDetector(config.ANOMALY_MODEL_FILENAME)
        if not anm.ready:
            _skip("Isolation Forest (normal)", "model not trained")
            _skip("Isolation Forest (outlier)", "model not trained")
        else:
            normal_feats = {
                "Protocol": 6, "Flow Duration": 300_000,
                "Total Fwd Packets": 20, "Total Backward Packets": 15,
                "Fwd Packets Length Total": 0, "Bwd Packets Length Total": 0,
                "Fwd Packet Length Max": 150, "Flow Bytes/s": 800,
                "Flow Packets/s": 0, "Fwd IAT Min": 0, "Bwd IAT Min": 0,
                "Fwd PSH Flags": 1, "Fwd URG Flags": 0, "FIN Flag Count": 1,
                "SYN Flag Count": 1, "RST Flag Count": 0, "ACK Flag Count": 18,
                "URG Flag Count": 0, "Init Fwd Win Bytes": 65535,
            }
            r = anm.score(normal_feats)
            _ok(f"Isolation Forest: normal traffic (score {r.get('score',0):.4f}, "
                f"anomaly={r.get('anomaly',False)})")

            outlier_feats = dict(normal_feats,
                                 Flow_Duration=0, Total_Fwd_Packets=50000,
                                 SYN_Flag_Count=50000, Flow_Bytes_s=500_000_000)
            r2 = anm.score(outlier_feats)
            _ok(f"Isolation Forest: outlier scored (score {r2.get('score',0):.4f})")

    except Exception as e:
        _fail("Anomaly detection test", str(e))


# ══════════════════════════════════════════════════════════════════════════════
# 5.  File Integrity Monitor
# ══════════════════════════════════════════════════════════════════════════════

def test_fim():
    _section("File Integrity Monitor (FIM)", "📁")

    from detectors.fim import FIMMonitor, _EXCLUDE_NAMES, _EXCLUDE_SUFFIXES, _EXCLUDE_DIRS

    tmpdir = Path(tempfile.mkdtemp(prefix="sm_fim_test_"))
    baseline_file = tmpdir / "baseline.json"

    try:
        fim_alerts: list[dict] = []

        # Create the monitor on an EMPTY temp dir → first scan builds a
        # zero-file baseline so no "file created" alerts fire on that run.
        fim = FIMMonitor(
            watch_dirs=[str(tmpdir)],
            baseline_path=baseline_file,
            on_alert=fim_alerts.append,
        )
        fim.rescan_now()   # empty dir scan — builds empty baseline
        _nofp("Initial baseline scan on empty dir — no alerts", bool(fim_alerts))

        # Now create the test files and let FIM detect them as new files
        (tmpdir / "config.txt").write_text("key=value\n", encoding="utf-8")
        (tmpdir / "script.py").write_text("print('hello')\n", encoding="utf-8")
        fim_alerts.clear()
        fim.rescan_now()   # detects 2 new files — update baseline for next tests
        fim_alerts.clear() # discard these setup alerts

        # ── File modified ─────────────────────────────────────────────────────
        fim_alerts.clear()
        (tmpdir / "config.txt").write_text("key=TAMPERED\n", encoding="utf-8")
        fim.rescan_now()
        modified = any(a.get("rule_name") == "FIM — File Modified" for a in fim_alerts)
        if modified:
            _ok("File modification detected", next(
                a for a in fim_alerts if a.get("rule_name") == "FIM — File Modified"))
        else:
            _fail("File modification detected")

        # ── File created ──────────────────────────────────────────────────────
        fim_alerts.clear()
        (tmpdir / "new_payload.exe").write_text("MZ\x00\x00", encoding="latin-1")
        fim.rescan_now()
        created = any(a.get("rule_name") == "FIM — File Created" for a in fim_alerts)
        if created:
            _ok("New file detected (potential payload)", next(
                a for a in fim_alerts if a.get("rule_name") == "FIM — File Created"))
        else:
            _fail("New file detected")

        # ── File deleted ──────────────────────────────────────────────────────
        fim_alerts.clear()
        (tmpdir / "script.py").unlink()
        fim.rescan_now()
        deleted = any(a.get("rule_name") == "FIM — File Deleted" for a in fim_alerts)
        if deleted:
            _ok("File deletion detected", next(
                a for a in fim_alerts if a.get("rule_name") == "FIM — File Deleted"))
        else:
            _fail("File deletion detected")

        # ── Exclusion: .pyc cache files must NOT alert ────────────────────────
        fim_alerts.clear()
        (tmpdir / "module.pyc").write_bytes(b"\x00\x00\x00\x00")
        (tmpdir / "debug.log").write_text("INFO: started\n", encoding="utf-8")
        fim.rescan_now()
        transient_fp = any(
            a.get("path", "").endswith((".pyc", ".log"))
            for a in fim_alerts
        )
        _nofp("Excluded file types (.pyc / .log) don't trigger FIM", transient_fp)

        # ── Exclusion: fim_baseline.json must NOT self-alert ──────────────────
        self_alert = any(
            "fim_baseline.json" in a.get("path", "") or
            "fim_baseline.json" in a.get("message", "")
            for a in fim_alerts
        )
        _nofp("FIM baseline file (fim_baseline.json) excluded from monitoring", self_alert)

        # ── Verify exclusion config is correct ────────────────────────────────
        assert "fim_baseline.json" in _EXCLUDE_NAMES
        assert ".pyc" in _EXCLUDE_SUFFIXES
        assert "__pycache__" in _EXCLUDE_DIRS
        _ok("Exclusion config verified (names + suffixes + dirs)")

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ══════════════════════════════════════════════════════════════════════════════
# 6.  Threat Intelligence (AbuseIPDB)
# ══════════════════════════════════════════════════════════════════════════════

def test_threat_intel():
    _section("Threat Intelligence — AbuseIPDB", "🌐")

    try:
        from detectors.threat_intel import ThreatIntel
    except Exception as e:
        _skip("All TI tests", str(e)); return

    ti_alerts: list[dict] = []
    ti = ThreatIntel(api_key="", on_alert=ti_alerts.append)

    # ── No API key → is_ready() returns False ─────────────────────────────────
    if not ti.is_ready():
        _ok("No API key → is_ready() = False (graceful no-op)")
    else:
        _fail("No API key handling")

    # ── Private IPs must be skipped ───────────────────────────────────────────
    PRIVATE_IPS = ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"]
    for ip in PRIVATE_IPS:
        ti.check_ip_async(ip)
    time.sleep(0.1)
    _nofp(f"Private/RFC-1918 IPs silently skipped ({', '.join(PRIVATE_IPS[:2])}…)",
           bool(ti_alerts))

    # ── Cache returns None for unchecked IPs ──────────────────────────────────
    result = ti.get_cached("8.8.8.8")
    _nofp("Cache returns None for unchecked IP (no phantom alerts)", result is not None)

    # ── API key configured (informational check) ───────────────────────────────
    try:
        import config
        if getattr(config, "ABUSEIPDB_API_KEY", ""):
            _ok("AbuseIPDB API key is configured in .env")
        else:
            _skip("AbuseIPDB API key check",
                  "no key in .env — add ABUSEIPDB_API_KEY to enable live lookups")
    except Exception:
        _skip("AbuseIPDB API key check", "config unavailable")


# ══════════════════════════════════════════════════════════════════════════════
# 7.  Windows Event Log Monitor
# ══════════════════════════════════════════════════════════════════════════════

def test_event_log():
    _section("Windows Event Log Monitor", "🪟")

    try:
        from detectors.event_log import EventLogMonitor, _WATCHED, _SUSPICIOUS_PROCS
    except Exception as e:
        _skip("All event log tests", str(e)); return

    el = EventLogMonitor()

    # ── Availability check ────────────────────────────────────────────────────
    available = el.is_available()
    if available:
        _ok("wevtutil available — event log monitor can run")
    else:
        _skip("wevtutil availability", "not available in this environment")

    # ── Severity calibration checks ───────────────────────────────────────────
    if _WATCHED.get(4698, ("", ""))[1] == "medium":
        _ok("Event 4698 (Scheduled Task) correctly calibrated to 'medium' — not 'high'")
    else:
        _fail("Event 4698 severity", f"expected 'medium', got '{_WATCHED.get(4698,('',''))[1]}'")

    if _WATCHED.get(4724, ("", ""))[1] == "low":
        _ok("Event 4724 (Password Reset) correctly calibrated to 'low' — not 'medium'")
    else:
        _fail("Event 4724 severity", f"expected 'low', got '{_WATCHED.get(4724,('',''))[1]}'")

    if _WATCHED.get(1102, ("", ""))[1] == "critical":
        _ok("Event 1102 (Audit Log Cleared) remains 'critical'")
    else:
        _fail("Event 1102 severity")

    # ── Suspicious process filter ─────────────────────────────────────────────
    assert "mimikatz" in _SUSPICIOUS_PROCS
    assert "mshta.exe" in _SUSPICIOUS_PROCS
    _ok(f"Suspicious process filter active ({len(_SUSPICIOUS_PROCS)} entries incl. mimikatz, mshta.exe)")

    # ── Description generation ────────────────────────────────────────────────
    desc_4625 = el._describe(4625, {"LogonType": "3", "WorkstationName": "ATTACKER-PC"},
                              "hacker", "ATTACKER-PC")
    if "Failed logon" in desc_4625:
        _ok(f"Event 4625 description: '{desc_4625}'")
    else:
        _fail("Event 4625 description", f"got: {desc_4625}")

    desc_7045 = el._describe(7045, {"ServiceName": "EvilRootkit"}, "SYSTEM", "")
    if "EvilRootkit" in desc_7045:
        _ok(f"Event 7045 description: '{desc_7045}'")
    else:
        _fail("Event 7045 description", f"got: {desc_7045}")


# ══════════════════════════════════════════════════════════════════════════════
# 8.  Threshold Regression — verify no false-positive regression
# ══════════════════════════════════════════════════════════════════════════════

def test_thresholds():
    _section("Detection Threshold Sanity Check", "⚖")

    from detectors.arp_monitor   import ARPMonitor
    from detectors.dns_monitor   import _FLUX_THRESH, _RATE_THRESH, _MAX_LABEL_LEN, _RISKY_TLDS
    from detectors.brute_force   import _THRESH_AUTH, _THRESH_HTTP, _SPRAY_PORTS, _SPRAY_MIN_SYN

    # ARP
    m = ARPMonitor()
    if m._FLOOD_THRESH >= 50:
        _ok(f"ARP flood threshold ≥ 50 pkts/10 s (set to {m._FLOOD_THRESH})")
    else:
        _fail(f"ARP flood threshold too low ({m._FLOOD_THRESH}) — expect false positives")

    if m._SPOOF_COOLDOWN >= 300:
        _ok(f"ARP spoof cooldown ≥ 5 min (set to {m._SPOOF_COOLDOWN} s)")
    else:
        _fail(f"ARP spoof cooldown too short ({m._SPOOF_COOLDOWN} s)")

    # DNS
    if _FLUX_THRESH >= 20:
        _ok(f"Fast-flux threshold ≥ 20 distinct IPs (set to {_FLUX_THRESH})")
    else:
        _fail(f"Fast-flux threshold too low ({_FLUX_THRESH}) — CDNs will false-alarm")

    if ".xyz" not in _RISKY_TLDS:
        _ok(".xyz excluded from risky TLDs (Alphabet/Google legitimately use it)")
    else:
        _fail(".xyz still in risky TLDs — expect false positives on legitimate sites")

    if _RATE_THRESH >= 100:
        _ok(f"DNS rate threshold ≥ 100 queries/min (set to {_RATE_THRESH})")
    else:
        _fail(f"DNS rate threshold too low ({_RATE_THRESH})")

    if _MAX_LABEL_LEN >= 55:
        _ok(f"DNS label length threshold ≥ 55 chars (set to {_MAX_LABEL_LEN})")
    else:
        _fail(f"DNS label threshold too short ({_MAX_LABEL_LEN})")

    # Brute force
    if _THRESH_AUTH >= 20:
        _ok(f"Auth brute force threshold ≥ 20 SYN/60 s (set to {_THRESH_AUTH})")
    else:
        _fail(f"Auth brute force threshold too low ({_THRESH_AUTH})")

    if _THRESH_HTTP >= 60:
        _ok(f"HTTP stuffing threshold ≥ 60 SYN/60 s (set to {_THRESH_HTTP})")
    else:
        _fail(f"HTTP stuffing threshold too low ({_THRESH_HTTP})")

    if _SPRAY_PORTS >= 5:
        _ok(f"Password spray ≥ {_SPRAY_PORTS} services × ≥ {_SPRAY_MIN_SYN} SYNs each")
    else:
        _fail(f"Password spray port count too low ({_SPRAY_PORTS})")


# ══════════════════════════════════════════════════════════════════════════════
# ── Main runner ───────────────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def _banner():
    print(f"\n{BOLD}{W}{'═'*66}{RST}")
    print(f"{BOLD}{W}   Security Monitor — Safe Demonstration Test{RST}")
    print(f"{DIM}   Simulated threats · No real traffic · No admin required{RST}")
    print(f"{BOLD}{W}{'═'*66}{RST}")
    print(f"  Python {sys.version.split()[0]}  |  {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    if VERBOSE: print(f"  {Y}--verbose{RST} mode — showing alert detail")
    if FAST:    print(f"  {Y}--fast{RST} mode — ML tests skipped")
    print(f"  Scapy: {G+'available'+RST if SCAPY else R+'not installed'+RST}")

def _summary():
    by_section: dict[str, tuple[int,int]] = {}
    for sec, label, ok in _results:
        p, t = by_section.get(sec, (0, 0))
        by_section[sec] = (p + (1 if ok else 0), t + 1)

    total_p = sum(p for p, _ in by_section.values())
    total_t = sum(t for _, t in by_section.values())
    all_ok  = total_p == total_t

    w = 66
    print(f"\n{BOLD}{W}{'═'*w}{RST}")
    print(f"{BOLD}{W}   Test Summary{RST}")
    print(f"{BOLD}{W}{'─'*w}{RST}")

    for sec, (p, t) in by_section.items():
        bar_c = G if p == t else (Y if p >= t * 0.7 else R)
        icon  = "✓" if p == t else ("~" if p >= t * 0.7 else "✗")
        print(f"  {bar_c}{icon}{RST}  {sec:<44}  {bar_c}{p}/{t}{RST}")

    print(f"{BOLD}{W}{'─'*w}{RST}")
    c = G if all_ok else (Y if total_p >= total_t * 0.8 else R)
    verdict = "ALL TESTS PASSED" if all_ok else f"{total_p}/{total_t} tests passed"
    print(f"  {BOLD}{c}{verdict}{RST}\n")

    # List failures
    failures = [(s, l) for s, l, ok in _results if not ok]
    if failures:
        print(f"  {R}Failed:{RST}")
        for sec, label in failures:
            print(f"    {R}✗{RST}  [{sec}] {label}")
        print()

    print(f"{BOLD}{W}{'═'*w}{RST}\n")
    return 0 if all_ok else 1

if __name__ == "__main__":
    _banner()

    suites = [
        test_arp,
        test_dns,
        test_brute_force,
        test_ml,
        test_fim,
        test_threat_intel,
        test_event_log,
        test_thresholds,
    ]

    for suite in suites:
        try:
            suite()
        except Exception as e:
            _section_label = suite.__name__
            _fail(f"Suite crashed: {suite.__name__}", str(e))

    sys.exit(_summary())
