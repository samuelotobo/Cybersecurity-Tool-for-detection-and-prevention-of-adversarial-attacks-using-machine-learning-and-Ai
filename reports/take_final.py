"""
take_final.py — Final screenshot script with calibrated positions.
Client origin = (0, 23). Sidebar buttons measured from calibration_shot.png.
Run as admin.
"""
import sys, time, ctypes, ctypes.wintypes
from pathlib import Path
import pyautogui, win32gui, win32con
from PIL import ImageGrab

ASSETS = Path(__file__).parent / "project_report_assets"
ASSETS.mkdir(parents=True, exist_ok=True)
pyautogui.FAILSAFE = False

def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and "Security Monitor" in win32gui.GetWindowText(hwnd):
            found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd:
    Path(__file__).parent.joinpath("screenshot_error.txt").write_text("No window found")
    sys.exit(1)

win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(2.0)
win32gui.SetForegroundWindow(hwnd)
time.sleep(0.5)

def client_to_screen(cx, cy):
    pt = ctypes.wintypes.POINT(cx, cy)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
    return pt.x, pt.y

def snap(name, wait=1.8):
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(wait)
    x1,y1,x2,y2 = win32gui.GetWindowRect(hwnd)
    img = ImageGrab.grab(bbox=(x1,y1,x2,y2), all_screens=True)
    img = img.crop((2, 32, img.width-2, img.height-2))
    img.save(str(ASSETS / f"{name}.png"))

def click(cy, wait=1.8):
    sx, sy = client_to_screen(112, cy)
    pyautogui.moveTo(sx, sy, duration=0.15)
    time.sleep(0.1)
    pyautogui.click()
    time.sleep(wait)

# Calibrated client-Y positions from calibration_shot.png visual measurement
OVERVIEW   = 148
TRAFFIC    = 190
THREATS    = 232
SYSMON     = 274
GEOMAP     = 316
BLOCKED    = 393
FILESCANNER= 434
TOOLS      = 510
ML         = 582
ADAPTIVE   = 622
ADVERSARIAL= 662
SETTINGS   = 736

# ── 1. Dashboard ──────────────────────────────────────────────────────────────
click(OVERVIEW); snap("final_01_dashboard")
# ── 2. Live Traffic ───────────────────────────────────────────────────────────
click(TRAFFIC);  snap("final_02_live_traffic")
# ── 3. Threats & Alerts ───────────────────────────────────────────────────────
click(THREATS);  snap("final_03_threats_alerts")
# ── 4. System Monitor ─────────────────────────────────────────────────────────
click(SYSMON);   snap("final_04_system_monitor")
# ── 5. Geo Map ────────────────────────────────────────────────────────────────
click(GEOMAP);   snap("final_05_geo_map", wait=3.0)
# ── 6. Blocked IPs ────────────────────────────────────────────────────────────
click(BLOCKED);  snap("final_06_blocked_ips")
# ── 7. File Scanner ───────────────────────────────────────────────────────────
click(FILESCANNER); snap("final_07_file_scanner")
# ── 8. Test & Analyse ─────────────────────────────────────────────────────────
click(TOOLS);    snap("final_08_test_analyse")

# Inner sub-tabs: DDoS Test (approx inner tab bar at client_y=295, 2nd tab x≈420)
sx2, sy2 = client_to_screen(420, 295)
pyautogui.moveTo(sx2, sy2, duration=0.15); time.sleep(0.1); pyautogui.click()
snap("final_08b_ddos_test", wait=1.5)

# Simulations (1st inner tab x≈295)
sx3, sy3 = client_to_screen(295, 295)
pyautogui.moveTo(sx3, sy3, duration=0.15); time.sleep(0.1); pyautogui.click()
snap("final_08c_simulations", wait=1.5)

# Vuln Scan (4th inner tab x≈630)
sx4, sy4 = client_to_screen(630, 295)
pyautogui.moveTo(sx4, sy4, duration=0.15); time.sleep(0.1); pyautogui.click()
snap("final_08d_vuln_scan", wait=1.5)

# Threat Test (5th inner tab x≈745)
sx5, sy5 = client_to_screen(745, 295)
pyautogui.moveTo(sx5, sy5, duration=0.15); time.sleep(0.1); pyautogui.click()
snap("final_08e_threat_test", wait=1.5)

# ── 9. ML Analysis ────────────────────────────────────────────────────────────
click(ML);       snap("final_09_ml_analysis")

# ── 10. Adaptive Training ──────────────────────────────────────────────────────
click(ADAPTIVE); snap("final_10_adaptive_training")

# ── 11. Adversarial Lab ────────────────────────────────────────────────────────
click(ADVERSARIAL); snap("final_11_adversarial_lab")

# ── 12. Settings ──────────────────────────────────────────────────────────────
click(SETTINGS); snap("final_12_settings")

Path(__file__).parent.joinpath("screenshot_done.txt").write_text("OK")
