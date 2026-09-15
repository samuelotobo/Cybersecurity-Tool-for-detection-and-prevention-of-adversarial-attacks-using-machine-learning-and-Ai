"""
take_screenshots.py
Launches the Security Monitor app (if not running), navigates every sidebar tab
via keyboard simulation, and saves one PNG per tab to reports/project_report_assets/.
Run as:  python reports/take_screenshots.py
"""

import subprocess, sys, time, os
from pathlib import Path

ROOT   = Path(__file__).parent.parent
ASSETS = Path(__file__).parent / "project_report_assets"
ASSETS.mkdir(parents=True, exist_ok=True)

# ── Install guard ────────────────────────────────────────────────────────────
try:
    import pyautogui
    import pygetwindow as gw
    from PIL import ImageGrab, Image
    import win32gui, win32con
except ImportError as e:
    print(f"Missing: {e}\n  pip install pyautogui pygetwindow pillow pywin32")
    sys.exit(1)

pyautogui.FAILSAFE = False
pyautogui.PAUSE    = 0.3

# ── Find or launch the app ───────────────────────────────────────────────────
def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            t = win32gui.GetWindowText(hwnd)
            if "Security Monitor" in t or "SecurityMonitor" in t:
                found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd:
    print("App not running — launching…")
    subprocess.Popen(
        [str(ROOT / ".venv/Scripts/python.exe"), str(ROOT / "desktop_app.py")],
        cwd=str(ROOT),
    )
    for _ in range(20):
        time.sleep(1)
        hwnd = find_hwnd()
        if hwnd:
            break
    if not hwnd:
        print("Could not find app window. Start it manually and re-run.")
        sys.exit(1)

print(f"Found window hwnd={hwnd}")

# ── Bring to foreground and maximise ────────────────────────────────────────
win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
win32gui.SetForegroundWindow(hwnd)
time.sleep(1.5)

def get_rect():
    return win32gui.GetWindowRect(hwnd)

def screenshot(name: str, wait: float = 1.2):
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(wait)
    x1, y1, x2, y2 = get_rect()
    img  = ImageGrab.grab(bbox=(x1, y1, x2, y2), all_screens=True)
    # Slight crop — remove OS window chrome (title bar ~32px)
    img  = img.crop((2, 32, img.width-2, img.height-2))
    path = ASSETS / f"{name}.png"
    img.save(str(path), "PNG")
    kb   = path.stat().st_size // 1024
    print(f"  [{name}]  {img.size[0]}x{img.size[1]}  {kb} KB")
    return str(path)

# ── Sidebar navigation helper ─────────────────────────────────────────────
# The sidebar buttons are stacked vertically. We click by position:
# Get window rect and compute approximate button positions from the top.
def click_sidebar(index: int, extra_wait: float = 0.0):
    """Click the i-th visible sidebar nav button (0-based)."""
    x1, y1, x2, y2 = get_rect()
    # Sidebar is ~220px wide; buttons start ~200px from top, ~52px apart
    sx = x1 + 112          # horizontal centre of sidebar
    sy = y1 + 200 + (index * 52)   # first button top ~200px, 52px spacing
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(0.2)
    pyautogui.click(sx, sy)
    if extra_wait:
        time.sleep(extra_wait)

# ── Take screenshots ──────────────────────────────────────────────────────
# First let the dashboard load fully
print("\nTaking screenshots of each tab…\n")
time.sleep(2)

tabs = [
    # (sidebar_index, filename, extra_wait, description)
    (0,  "ss_01_dashboard",        2.0,  "Dashboard — overview, stat cards, live clock"),
    (1,  "ss_02_live_traffic",     1.5,  "Live Traffic — real-time packet stream"),
    (2,  "ss_03_threats_alerts",   1.5,  "Threats & Alerts — all detections"),
    (3,  "ss_04_system_monitor",   1.5,  "System Monitor — Event Log, FIM, Threat Intel"),
    (4,  "ss_05_geo_map",          3.0,  "Geo Map — attack origin world map"),
    (5,  "ss_06_blocked_ips",      1.2,  "Blocked IPs — firewall management"),
    (6,  "ss_07_file_scanner",     1.5,  "File Scanner — USB, downloads, malware scan"),
    (7,  "ss_08_test_analyse",     1.5,  "Test & Analyse — simulation lab"),
    (8,  "ss_09_ml_analysis",      2.0,  "ML Analysis — model performance metrics"),
    (9,  "ss_10_adaptive_training",1.5,  "Adaptive Training — feedback & retrain"),
    (10, "ss_11_adversarial_lab",  1.5,  "Adversarial Lab — FGSM evasion & XAI"),
    (11, "ss_12_settings",         1.2,  "Settings — configuration panel"),
]

saved = []
for idx, fname, wait, desc in tabs:
    print(f"  > {desc}")
    click_sidebar(idx, extra_wait=wait)
    p = screenshot(fname, wait=0.5)
    saved.append((fname, desc, p))

# ── Bonus: take a screenshot of the DDoS Test sub-tab inside Tools ────────
print("\n  → DDoS Test sub-tab")
# Tools tab is index 7 — already there; click second inner tab (index 1)
x1, y1, x2, y2 = get_rect()
# Inner tab bar is about 200px from top of content area
inner_tab_y = y1 + 260
pyautogui.click(x1 + 450, inner_tab_y)  # approximate position of 2nd inner tab
time.sleep(1.5)
screenshot("ss_08b_ddos_test", wait=0.3)

print("\n  → Simulation Lab sub-tab")
pyautogui.click(x1 + 280, inner_tab_y)  # first inner tab
time.sleep(1.5)
screenshot("ss_08c_simulation_lab", wait=0.3)

print(f"\nAll screenshots saved to: {ASSETS}")
print(f"Files: {[s[0] for s in saved]}")
