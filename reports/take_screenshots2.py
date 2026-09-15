"""
take_screenshots2.py  --  Reliable per-tab screenshot script.
Uses win32api SendMessage for clicks (works even with UAC-elevated windows).
Run: python reports/take_screenshots2.py
"""
import sys, time, ctypes, ctypes.wintypes
from pathlib import Path

try:
    from PIL import ImageGrab
    import win32gui, win32con, win32api
except ImportError as e:
    print(f"Missing: {e}")
    sys.exit(1)

ASSETS = Path(__file__).parent / "project_report_assets"
ASSETS.mkdir(parents=True, exist_ok=True)

# ── Find the window ───────────────────────────────────────────────────────────
def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            t = win32gui.GetWindowText(hwnd)
            if "Security Monitor" in t:
                found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd:
    print("App not found. Launch desktop_app.py first.")
    sys.exit(1)

# Maximise window
win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(1.5)

# ── Helper: click at client-area coordinates using PostMessage ────────────────
def click_client(cx, cy, delay=0.1):
    """Click at client-area coords by converting to screen coords and using pyautogui."""
    import pyautogui
    rect = win32gui.GetWindowRect(hwnd)
    # Get client rect origin relative to screen
    pt = ctypes.wintypes.POINT(cx, cy)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
    try:
        win32gui.SetForegroundWindow(hwnd)
    except Exception:
        pass
    time.sleep(0.15)
    pyautogui.moveTo(pt.x, pt.y, duration=0.1)
    pyautogui.click()
    time.sleep(delay)

# ── Capture window screenshot ─────────────────────────────────────────────────
def screenshot(name: str, wait: float = 1.4):
    time.sleep(wait)
    rect = win32gui.GetWindowRect(hwnd)
    x1, y1, x2, y2 = rect
    img  = ImageGrab.grab(bbox=(x1, y1, x2, y2), all_screens=True)
    img  = img.crop((2, 32, img.width - 2, img.height - 2))
    path = ASSETS / f"{name}.png"
    img.save(str(path), "PNG")
    print(f"  Saved: {name}.png  {img.size[0]}x{img.size[1]}")
    return path

# ── Sidebar button Y positions (client area, no title bar) ───────────────────
# Derived from visual inspection of captured screenshots (1614x963 content area)
# Sidebar center X = 112
SX = 112
TABS = {
    # name           cy   description
    "overview":     (110, "Dashboard overview — stat cards, live clock, quick actions"),
    "traffic":      (152, "Live Traffic — real-time packet stream with ML confidence"),
    "threats":      (194, "Threats & Alerts — colour-coded alert cards"),
    "sysmon":       (236, "System Monitor — Event Log, FIM, Threat Intel"),
    "geomap":       (278, "Geo Map — Leaflet.js attack origin world map"),
    "blocked":      (356, "Blocked IPs — manual block/unblock firewall panel"),
    "filescanner":  (396, "File Scanner — USB monitor, download watcher, MalwareBazaar"),
    "tools":        (476, "Test & Analyse — simulation lab and testing tools"),
    "mlanalysis":   (558, "ML Analysis — model metrics, ROC, confusion matrix"),
    "adaptive":     (598, "Adaptive Training — feedback buffer and retrain pipeline"),
    "adversarial":  (638, "Adversarial Lab — FGSM evasion and XAI explainer"),
    "settings":     (720, "Settings — notifications, detection toggles, whitelist"),
}

print("Taking screenshots of all sidebar tabs...\n")
print(f"Window hwnd={hwnd}")
print(f"Window rect={win32gui.GetWindowRect(hwnd)}\n")

# Always start from Dashboard to establish baseline
click_client(SX, TABS["overview"][0])
screenshot("sc_01_dashboard", wait=2.0)
print("1. Dashboard")

click_client(SX, TABS["traffic"][0])
screenshot("sc_02_live_traffic", wait=1.5)
print("2. Live Traffic")

click_client(SX, TABS["threats"][0])
screenshot("sc_03_threats_alerts", wait=1.5)
print("3. Threats & Alerts")

click_client(SX, TABS["sysmon"][0])
screenshot("sc_04_system_monitor", wait=1.5)
print("4. System Monitor")

click_client(SX, TABS["geomap"][0])
screenshot("sc_05_geo_map", wait=3.0)   # geo map takes longer to load
print("5. Geo Map")

click_client(SX, TABS["blocked"][0])
screenshot("sc_06_blocked_ips", wait=1.5)
print("6. Blocked IPs")

click_client(SX, TABS["filescanner"][0])
screenshot("sc_07_file_scanner", wait=1.5)
print("7. File Scanner")

click_client(SX, TABS["tools"][0])
screenshot("sc_08_test_analyse", wait=1.5)
print("8. Test & Analyse (Simulation Lab)")

click_client(SX, TABS["mlanalysis"][0])
screenshot("sc_09_ml_analysis", wait=2.0)
print("9. ML Analysis")

click_client(SX, TABS["adaptive"][0])
screenshot("sc_10_adaptive_training", wait=1.5)
print("10. Adaptive Training")

click_client(SX, TABS["adversarial"][0])
screenshot("sc_11_adversarial_lab", wait=1.5)
print("11. Adversarial Lab")

click_client(SX, TABS["settings"][0])
screenshot("sc_12_settings", wait=1.5)
print("12. Settings")

# -- Bonus: inner sub-tabs of Test & Analyse --
print("\nCapturing Test & Analyse sub-tabs...")
click_client(SX, TABS["tools"][0])
time.sleep(1.0)
# DDoS Test sub-tab: inner tab bar is at approximately cy=295, tabs start at cx=370
click_client(370, 295)   # second inner tab (DDoS Test)
screenshot("sc_08b_ddos_test", wait=1.5)
print("  8b. DDoS Test sub-tab")

# Threat Test sub-tab
click_client(560, 295)   # fifth inner tab
screenshot("sc_08c_threat_test", wait=1.5)
print("  8c. Threat Test sub-tab")

# ML Analysis - try clicking Compute Metrics to show live charts
click_client(SX, TABS["mlanalysis"][0])
time.sleep(1.0)
click_client(1300, 45)   # "Compute Metrics" button in header
screenshot("sc_09b_ml_computing", wait=8.0)  # wait for compute
print("  9b. ML Analysis with metrics computed")

print("\nAll screenshots complete.")
print(f"Saved to: {ASSETS}")
