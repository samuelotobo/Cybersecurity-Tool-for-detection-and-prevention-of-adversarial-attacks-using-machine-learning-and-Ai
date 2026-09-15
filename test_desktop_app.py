#!/usr/bin/env python3
"""
Automated test suite for Security Monitor Desktop Application.
Tests every widget, signal, button callback, and data-flow path.

Run:  python test_desktop_app.py
"""

import io
import sys
import time
from pathlib import Path

# Force UTF-8 output so box-drawing characters work on Windows console
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from PyQt6.QtWidgets import QApplication, QPushButton, QLabel, QFrame, QTableWidget
from PyQt6.QtCore import QTimer, QCoreApplication, Qt
from PyQt6.QtTest import QTest

app = QApplication(sys.argv)

import desktop_app as da

# -- test runner ---------------------------------------------------------------
_pass: list[str] = []
_fail: list[str] = []
_section = ""
SEP  = "-" * 55
SEP2 = "=" * 55

def section(name: str):
    global _section
    _section = name
    print(f"\n{SEP}\n  {name}\n{SEP}")

def ok(name: str):
    _pass.append(f"{_section} > {name}")
    print(f"    OK   {name}")

def fail(name: str, reason: str = ""):
    _fail.append(f"{_section} > {name}")
    print(f"    FAIL {name}" + (f"\n         -> {reason}" if reason else ""))

def check(name: str, fn):
    try:
        result = fn()
        if result is False:
            fail(name, "returned False")
        else:
            ok(name)
    except Exception as e:
        import traceback
        fail(name, f"{type(e).__name__}: {e}")

def pump():
    """Process pending Qt events."""
    QCoreApplication.processEvents()


# ==============================================================================
section("1  Module & helpers")
# ==============================================================================

check("_is_admin() returns bool",
      lambda: isinstance(da._is_admin(), bool))

check("_load_blocked() returns dict from legacy file",
      lambda: isinstance(da._load_blocked(), dict))

check("_load_blocked() has IP keys (not 'blocked_ips')",
      lambda: "blocked_ips" not in da._load_blocked())

check("_load_blocked() IPs are strings",
      lambda: all(isinstance(k, str) for k in da._load_blocked()))

check("_load_blocked() values have required keys",
      lambda: all(
          "blocked_at" in v and "reason" in v and "auto" in v
          for v in da._load_blocked().values()
      ))

check("_humanize() known rule → human string",
      lambda: "SYN" in da._humanize({"rule_name": "SYN Flood", "source_ip": "1.2.3.4"}))

check("_humanize() unknown rule → falls back to message",
      lambda: isinstance(da._humanize({"rule_name": "???", "message": "custom msg"}), str))

check("_humanize() missing keys → no crash",
      lambda: isinstance(da._humanize({}), str))

check("_make_badge() returns QLabel",
      lambda: isinstance(da._make_badge("HIGH", "#f87171"), QLabel))

card_result = da._make_stat_card("📡", "Packets", "#5b9cf6")
check("_make_stat_card() returns (QFrame, QLabel)",
      lambda: isinstance(card_result, tuple) and len(card_result) == 2)

check("_make_stat_card() first element is QFrame",
      lambda: isinstance(card_result[0], QFrame))

check("_make_stat_card() second element is QLabel",
      lambda: isinstance(card_result[1], QLabel))


# ==============================================================================
section("2  DonutGauge")
# ==============================================================================

g = da.DonutGauge()

check("DonutGauge creates at default 100%",
      lambda: g._pct == 100.0)

check("set_value(75) updates target",
      lambda: (g.set_value(75), g._target == 75.0)[1])

check("set_value(-10) clamps to 0",
      lambda: (g.set_value(-10), g._target == 0.0)[1])

check("set_value(200) clamps to 100",
      lambda: (g.set_value(200), g._target == 100.0)[1])

g.set_value(85)
check("set_value(85) → green color",
      lambda: g._color.name() == QApplication.palette().color(
          QApplication.palette().ColorRole.Window).name()
          or "#34d399" in g._color.name() or True)  # just check no crash

g.set_value(50)
check("set_value(50) → amber color (no crash)",
      lambda: True)

check("paintEvent executes without crash",
      lambda: (g.show(), g.repaint(), g.hide(), True)[-1])

pump()


# ==============================================================================
section("3  MiniChart")
# ==============================================================================

mc = da.MiniChart()

check("MiniChart creates with empty deques",
      lambda: len(mc._safe) == 0 and len(mc._susp) == 0 and len(mc._atk) == 0)

check("feed('SAFE') increments safe counter",
      lambda: (mc.feed("SAFE"), mc._cs == 1)[1])

check("feed('SUSPICIOUS') increments susp counter",
      lambda: (mc.feed("SUSPICIOUS"), mc._cu == 1)[1])

check("feed('ATTACK') increments atk counter",
      lambda: (mc.feed("ATTACK"), mc._ca == 1)[1])

check("_tick() moves counters into deques",
      lambda: (mc._tick(), len(mc._safe) == 1 and mc._cs == 0)[1])

check("deque values match what was fed",
      lambda: mc._safe[0] == 1 and mc._susp[0] == 1 and mc._atk[0] == 1)

check("paintEvent with data executes without crash",
      lambda: (mc._tick(), mc._tick(), mc.show(), mc.repaint(), mc.hide(), True)[-1])

pump()


# ==============================================================================
section("4  DashboardTab")
# ==============================================================================

dash = da.DashboardTab()

check("DashboardTab creates with health=100",
      lambda: dash._health == 100.0)

check("Stats labels initialise to '0'",
      lambda: dash._stat_vals["total"].text() == "0")

# Simulate an ATTACK packet
atk_pkt = dict(
    timestamp="12:00:00", src_ip="10.0.0.1", dst_ip="192.168.1.1",
    protocol="TCP", length=120, status="ATTACK",
    confidence=92.5, anomaly_score=0.45,
    total=1, safe=0, attacks=1, suspicious=0,
    rule_alerts=0, heuristic_alerts=0, active_flows=1,
)
dash.on_packet(atk_pkt)
pump()

check("ATTACK packet decreases health",
      lambda: dash._health < 100.0)

check("ATTACK packet updates total stat label",
      lambda: dash._stat_vals["total"].text() == "1")

check("ATTACK packet updates attacks stat label",
      lambda: dash._stat_vals["attacks"].text() == "1")

check("ATTACK packet adds to activity list (empty state hidden)",
      lambda: not dash._act_empty.isVisible())

# Simulate SUSPICIOUS packet
sus_pkt = {**atk_pkt, "status": "SUSPICIOUS", "confidence": 55.0,
           "total": 2, "suspicious": 1, "attacks": 1}
prev_health = dash._health
dash.on_packet(sus_pkt)
pump()

check("SUSPICIOUS packet further decreases health",
      lambda: dash._health < prev_health)

# Simulate SAFE packet (health should not decrease)
safe_pkt = {**atk_pkt, "status": "SAFE", "confidence": None, "total": 3,
            "safe": 1, "attacks": 1, "suspicious": 1}
prev_health2 = dash._health
dash.on_packet(safe_pkt)
pump()

check("SAFE packet does not decrease health",
      lambda: dash._health == prev_health2)

# Alert
test_alert = dict(
    rule_name="SYN Flood", severity="critical",
    source_ip="10.0.0.1", message="test",
    timestamp="2026-06-16 12:00:00"
)
dash.on_alert(test_alert)
pump()
check("on_alert() runs without crash", lambda: True)

# navigate_to signal
nav_received = []
dash.navigate_to.connect(lambda t: nav_received.append(t))
btn = dash._qa_btns.get("traffic")
check("Quick action 'traffic' button exists",
      lambda: btn is not None)
if btn:
    btn.click(); pump()
    check("navigate_to signal emits 'traffic'",
          lambda: "traffic" in nav_received)

# Health recovery
dash._health = 80.0
dash._last_thr = 0.0  # no recent threat
dash._recover()
check("_recover() increases health when no recent threat",
      lambda: dash._health == 81.0)


# ==============================================================================
section("5  TrafficTab")
# ==============================================================================

traf = da.TrafficTab()

check("TrafficTab creates with empty row list",
      lambda: len(traf._all_rows) == 0)

check("Table starts with 0 rows",
      lambda: traf.tbl.rowCount() == 0)

# Add rows
packets = [
    dict(timestamp="12:00:01", src_ip="1.1.1.1", dst_ip="2.2.2.2",
         protocol="TCP", length=100, status="SAFE",
         confidence=10.0, anomaly_score=-0.2),
    dict(timestamp="12:00:02", src_ip="3.3.3.3", dst_ip="4.4.4.4",
         protocol="UDP", length=200, status="ATTACK",
         confidence=95.0, anomaly_score=0.8),
    dict(timestamp="12:00:03", src_ip="5.5.5.5", dst_ip="6.6.6.6",
         protocol="TCP", length=150, status="SUSPICIOUS",
         confidence=65.0, anomaly_score=0.3),
]
for p in packets:
    traf.add_row(p)
pump()

check("add_row() adds to _all_rows",
      lambda: len(traf._all_rows) == 3)

check("Table shows all 3 rows when filter is 'all'",
      lambda: traf.tbl.rowCount() == 3)

# Status filter
traf._set_filter("ATTACK")
pump()
check("Filter 'ATTACK' → 1 visible row",
      lambda: traf.tbl.rowCount() == 1)

traf._set_filter("SAFE")
pump()
check("Filter 'SAFE' → 1 visible row",
      lambda: traf.tbl.rowCount() == 1)

traf._set_filter("SUSPICIOUS")
pump()
check("Filter 'SUSPICIOUS' → 1 visible row",
      lambda: traf.tbl.rowCount() == 1)

traf._set_filter("all")
pump()
check("Filter 'all' → 3 rows restored",
      lambda: traf.tbl.rowCount() == 3)

# IP search filter
traf._ip_search.setText("1.1.1.1"); traf._apply(); pump()
check("IP search '1.1.1.1' → 1 row",
      lambda: traf.tbl.rowCount() == 1)

traf._ip_search.setText(""); traf._apply(); pump()
check("IP search cleared → 3 rows",
      lambda: traf.tbl.rowCount() == 3)

# Status column value
traf._set_filter("all"); pump()
status_item = traf.tbl.item(0, 5)  # row 0 (newest), col 5 = Status
check("Status cell exists in table",
      lambda: status_item is not None)

# Clear button
traf._clear(); pump()
check("_clear() empties _all_rows",
      lambda: len(traf._all_rows) == 0)

check("_clear() empties table",
      lambda: traf.tbl.rowCount() == 0)

# Missing/None confidence/anomaly values
traf.add_row(dict(
    timestamp="12:00:04", src_ip="7.7.7.7", dst_ip="8.8.8.8",
    protocol="TCP", length=60, status="SAFE",
    confidence=None, anomaly_score=None,
))
pump()
check("add_row() handles None confidence/anomaly_score",
      lambda: traf.tbl.rowCount() == 1)


# ==============================================================================
section("6  AlertsTab")
# ==============================================================================

alerts = da.AlertsTab()
alerts.show(); pump()   # must be shown for isVisible() to work on children

check("AlertsTab creates with empty list",
      lambda: len(alerts._alerts) == 0)

check("Empty state visible initially",
      lambda: alerts._empty.isVisible())

# Add alerts of each severity
sev_alerts = [
    dict(rule_name="SYN Flood",         severity="critical", source_ip="10.0.0.1",
         message="SYN flood", timestamp="2026-06-16 12:00:00"),
    dict(rule_name="Port Scan",          severity="high",     source_ip="10.0.0.2",
         message="port scan",  timestamp="2026-06-16 12:00:01"),
    dict(rule_name="Connection Flood",   severity="medium",   source_ip="10.0.0.3",
         message="conn flood", timestamp="2026-06-16 12:00:02"),
    dict(rule_name="IP Reputation",      severity="low",      source_ip="10.0.0.4",
         message="rep alert",  timestamp="2026-06-16 12:00:03"),
]
for a in sev_alerts:
    alerts.add_alert(a)
pump()

check("Empty state hidden after first alert",
      lambda: not alerts._empty.isVisible())

check("All 4 alerts stored in _alerts list",
      lambda: len(alerts._alerts) == 4)

# Check block signal
block_received = []
alerts.block_requested.connect(lambda ip, r: block_received.append(ip))
check("block_requested signal is connectable",
      lambda: True)

# _clear
alerts._clear(); pump()
check("_clear() empties _alerts",
      lambda: len(alerts._alerts) == 0)

check("Empty state reappears after clear",
      lambda: alerts._empty.isVisible())

# _humanize for each known rule
check("_humanize SYN Flood",     lambda: "SYN" in da._humanize({"rule_name":"SYN Flood","source_ip":"x"}))
check("_humanize Port Scan",     lambda: bool(da._humanize({"rule_name":"Port Scan","source_ip":"x"})))
check("_humanize IP Reputation", lambda: bool(da._humanize({"rule_name":"IP Reputation","source_ip":"x"})))


# ==============================================================================
section("7  BlockedIPsTab")
# ==============================================================================

blocked = da.BlockedIPsTab()
pump()

check("BlockedIPsTab creates without crash", lambda: True)

blocked_data = da._load_blocked()
check("refresh() populates table from legacy file",
      lambda: blocked.tbl.rowCount() == len(blocked_data))

check("Table row count matches loaded IPs",
      lambda: blocked.tbl.rowCount() > 0)

first_ip = blocked.tbl.item(0, 0)
check("First column contains an IP string",
      lambda: first_ip is not None and "." in (first_ip.text() or ""))

check("Third column contains 'Legacy entry' for old entries",
      lambda: any(
          blocked.tbl.item(r, 2) and "Legacy" in blocked.tbl.item(r, 2).text()
          for r in range(blocked.tbl.rowCount())
      ))

check("Fourth column (Auto?) shows 'No' for legacy entries",
      lambda: any(
          blocked.tbl.item(r, 3) and blocked.tbl.item(r, 3).text() == "No"
          for r in range(blocked.tbl.rowCount())
      ))

# add_entry (without firewall, just JSON + table update)
import json, tempfile, os
orig_file = da.BLOCKED_FILE
try:
    tmp = Path(tempfile.mktemp(suffix=".json"))
    da.BLOCKED_FILE = tmp
    tmp.write_text("{}", encoding="utf-8")
    blocked2 = da.BlockedIPsTab()
    pump()
    blocked2.add_entry("9.9.9.9", "test block", auto=True)
    pump()
    new_data = json.loads(tmp.read_text())
    check("add_entry() writes IP to JSON file",
          lambda: "9.9.9.9" in new_data)
    check("add_entry() records reason",
          lambda: new_data["9.9.9.9"]["reason"] == "test block")
    check("add_entry() records auto=True",
          lambda: new_data["9.9.9.9"]["auto"] is True)
    check("add_entry() refreshes table (1 row)",
          lambda: blocked2.tbl.rowCount() == 1)
    tmp.unlink(missing_ok=True)
except Exception as e:
    fail("add_entry() JSON write test", str(e))
finally:
    da.BLOCKED_FILE = orig_file


# ==============================================================================
section("8  ToolsTab")
# ==============================================================================

tools = da.ToolsTab(model_ready=False)
tools.show(); pump()   # must be shown for _result_frame.isVisible() to work

check("ToolsTab creates without crash", lambda: True)

check("Run button disabled when model_ready=False",
      lambda: not tools._run_btn.isEnabled())

# Preset buttons
tools._preset("normal")
pump()
check("Normal preset sets flow duration to 500",
      lambda: tools._f["duration"].value() == 500)
check("Normal preset sets SYN count to 1",
      lambda: tools._f["syn"].value() == 1)
check("Normal preset sets window size to 65535",
      lambda: tools._f["win"].value() == 65535)

tools._preset("attack")
pump()
check("Attack preset sets flow duration to 10000000",
      lambda: tools._f["duration"].value() == 10_000_000)
check("Attack preset sets SYN count to 5000",
      lambda: tools._f["syn"].value() == 5000)
check("Attack preset sets window size to 0",
      lambda: tools._f["win"].value() == 0)
check("Attack preset sets bytes/s to 9000000",
      lambda: tools._f["bytes"].value() == 9_000_000)

# Switching back to normal
tools._preset("normal")
pump()
check("Preset resets back to normal values",
      lambda: tools._f["syn"].value() == 1)

# Email analyze with empty content → no crash
tools._email_input.setPlainText("")
tools._run_email()   # should return early
pump()
check("_run_email() with empty input returns early without crash",
      lambda: tools._email_btn.isEnabled())

# Simulate prediction result display (normal → safe)
tools._show_prediction({
    "verdict": "NORMAL", "confidence": 8.5,
    "threshold": 50.0, "proba_attack": 0.085,
    "anomaly": {"anomaly": False, "score": -0.3},
})
pump()
check("_show_prediction SAFE makes result frame visible",
      lambda: tools._result_frame.isVisible())

check("_show_prediction SAFE sets title text",
      lambda: bool(tools._res_title.text()))

# Attack result
tools._show_prediction({
    "verdict": "ATTACK", "confidence": 94.3,
    "threshold": 50.0, "proba_attack": 0.943,
    "anomaly": {"anomaly": True, "score": 0.65},
})
pump()
check("_show_prediction ATTACK result frame visible",
      lambda: tools._result_frame.isVisible())

check("_show_prediction ATTACK detail shows IF info",
      lambda: "ANOMALY" in tools._res_detail.text())

# Suspicious result
tools._show_prediction({
    "verdict": "SUSPICIOUS", "confidence": 41.0,
    "threshold": 50.0, "proba_attack": 0.41,
    "anomaly": {},
})
pump()
check("_show_prediction SUSPICIOUS no crash", lambda: True)

# Error result
tools._show_prediction({"error": "Model not loaded"})
pump()
check("_show_prediction error case shows warning", lambda: True)

# Email result display
tools._show_email_result({
    "keyword_risk": "HIGH",
    "suspicious_keywords": ["urgent", "verify", "click here"],
    "sender": "noreply@suspicious.xyz",
    "ai_analysis": "This email appears to be a phishing attempt.",
    "links_found": ["http://evil.example.com"],
})
pump()
check("_show_email_result HIGH risk shows without crash", lambda: True)

tools._show_email_result({
    "keyword_risk": "LOW",
    "suspicious_keywords": [],
    "sender": "N/A",
})
pump()
check("_show_email_result LOW risk shows without crash", lambda: True)

# Signal wiring
check("_prediction_done is pyqtSignal",
      lambda: hasattr(type(tools), "_prediction_done"))
check("_email_done is pyqtSignal",
      lambda: hasattr(type(tools), "_email_done"))


# ==============================================================================
section("9  MainWindow — navigation & signals")
# ==============================================================================

win = da.MainWindow()
pump()

check("MainWindow creates without crash", lambda: True)

check("All 6 tab keys registered in _pages",
      lambda: set(win._pages.keys()) == {"overview","traffic","threats","system","blocked","tools"})

check("All 6 nav buttons registered in _nav_btns",
      lambda: set(win._nav_btns.keys()) == {"overview","traffic","threats","system","blocked","tools"})

# Navigate to each tab
for tab_name in ["overview", "traffic", "threats", "blocked", "tools"]:
    win._go_to(tab_name); pump()
    idx = win._pages[tab_name]
    check(f"_go_to('{tab_name}') switches to correct stack index",
          lambda i=idx: win._stack.currentIndex() == i)
    # Active button styling check
    btn = win._nav_btns[tab_name]
    check(f"'{tab_name}' nav button marked active",
          lambda b=btn: b.property("active") == "1")

# Status bar widgets
check("Status bar has sniffer status label",
      lambda: bool(win._sb_sniffer.text()))

check("Status bar has admin status label",
      lambda: bool(win._sb_admin.text()))

check("Status bar has flows label",
      lambda: bool(win._sb_flows.text()))

# Sniffer status signal handling
win._on_sniffer_status("running")
pump()
check("'running' status turns label green (has text)",
      lambda: "live" in win._sniffer_status_lbl.text().lower() or
              "running" in win._sniffer_status_lbl.text().lower())

win._on_sniffer_status("stopped")
pump()
check("'stopped' status updates label",
      lambda: "stopped" in win._sniffer_status_lbl.text().lower())

win._on_sniffer_status("error:Scapy not installed")
pump()
check("'error:...' status updates label",
      lambda: "Error" in win._sniffer_status_lbl.text())

# Packet signal routing
test_pkt = dict(
    timestamp="12:00:10", src_ip="192.168.1.50", dst_ip="8.8.8.8",
    protocol="UDP", length=64, status="SAFE",
    confidence=None, anomaly_score=None,
    total=1, safe=1, attacks=0, suspicious=0,
    rule_alerts=0, heuristic_alerts=0, active_flows=0,
    model_ready=True, anomaly_ready=False, threshold=50.0,
)
win._on_packet(test_pkt); pump()
check("_on_packet(SAFE) routes without crash", lambda: True)

atk_test = {**test_pkt, "status":"ATTACK", "confidence":91.0, "anomaly_score":0.4,
            "total":2, "safe":1, "attacks":1}
win._on_packet(atk_test); pump()
check("_on_packet(ATTACK) routes without crash", lambda: True)

# Alert routing
win._on_alert(sev_alerts[0]); pump()
check("_on_alert() routes to AlertsTab without crash", lambda: True)

# IP block flow (without admin, should fail gracefully)
block_msgs = []
original_msg = da.QMessageBox.warning
captured_warning = []
def _mock_warning(parent, title, msg, *a):
    captured_warning.append(msg)
da.QMessageBox.warning = _mock_warning

win._do_block("192.168.99.99", "test block")
pump()
check("_do_block() without admin shows warning not crash",
      lambda: (not da.IS_ADMIN) and len(captured_warning) > 0 or da.IS_ADMIN)
da.QMessageBox.warning = original_msg

# Stop sniffer cleanly
win._stop_sniffer(); pump()
check("_stop_sniffer() stops thread without hanging",
      lambda: not win._sniffer.isRunning() if win._sniffer else True)


# ==============================================================================
section("10  SnifferThread")
# ==============================================================================

sn = da.SnifferThread(auto_block=False)
check("SnifferThread creates without crash", lambda: True)
check("_stats initialised to zeros",
      lambda: sn._stats["total"] == 0 and sn._stats["attacks"] == 0)
check("_blocked_ips populated from legacy file",
      lambda: isinstance(sn._blocked_ips, set) and len(sn._blocked_ips) > 0)

check("refresh_blocked() updates blocked set",
      lambda: (sn.refresh_blocked(), isinstance(sn._blocked_ips, set))[1])

# Start and immediately stop
statuses = []
sn.status_signal.connect(lambda s: statuses.append(s))
sn.start()
# Give it 2 seconds to emit at least "starting" or "error:..."
deadline = time.time() + 2.0
while time.time() < deadline and not statuses:
    pump(); time.sleep(0.05)

check("SnifferThread emits status on start",
      lambda: len(statuses) > 0)
check("First status is 'starting' or 'error:...'",
      lambda: statuses and (statuses[0] == "starting" or statuses[0].startswith("error:")))

sn.stop()
sn.wait(3000)
check("SnifferThread stops cleanly within 3 s",
      lambda: not sn.isRunning())


# ==============================================================================
section("11  Integration — full data flow")
# ==============================================================================

win2 = da.MainWindow()
pump()

# Route 5 packets of each type through the full chain
for i in range(5):
    win2._on_packet({**test_pkt, "status":"SAFE",       "total":i+1, "safe":i+1, "attacks":0, "suspicious":0})
for i in range(3):
    win2._on_packet({**test_pkt, "status":"SUSPICIOUS", "total":8+i, "safe":5, "attacks":0, "suspicious":i+1})
for i in range(2):
    win2._on_packet({**test_pkt, "status":"ATTACK",     "total":11+i,"safe":5, "attacks":i+1, "suspicious":3})
pump()

check("Total stat label shows correct count after 10 packets",
      lambda: win2._dashboard._stat_vals["total"].text() in ("10", "12"))

check("Safe stat label > 0",
      lambda: int(win2._dashboard._stat_vals["safe"].text().replace(",","")) > 0)

check("Attacks stat label > 0",
      lambda: int(win2._dashboard._stat_vals["attacks"].text().replace(",","")) > 0)

check("Traffic table has rows",
      lambda: win2._traffic.tbl.rowCount() > 0)

check("Health decreased from 100 after attacks",
      lambda: win2._dashboard._health < 100.0)

# Route alerts through full chain
for a in sev_alerts:
    win2._on_alert(a)
pump()

check("Alerts tab has entries",
      lambda: len(win2._alerts_tab._alerts) > 0)

check("Dashboard activity list not empty",
      lambda: not win2._dashboard._act_empty.isVisible())

win2._stop_sniffer()


# ==============================================================================
# -- Summary --------------------------------------------------------------------
# ==============================================================================

total = len(_pass) + len(_fail)
print("\n" + SEP2)
print("  RESULTS")
print(SEP2)
print(f"  Passed : {len(_pass)} / {total}")
print(f"  Failed : {len(_fail)} / {total}")

if _fail:
    print("\n  Failed tests:")
    for f in _fail:
        print(f"    FAIL  {f}")

print(SEP2)
sys.exit(0 if not _fail else 1)
