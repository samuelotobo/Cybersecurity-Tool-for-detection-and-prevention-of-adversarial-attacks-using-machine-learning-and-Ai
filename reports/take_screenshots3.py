"""
take_screenshots3.py — Uses ClientToScreen to find exact button positions.
Run as administrator: Start-Process python reports/take_screenshots3.py -Verb RunAs
"""
import sys, time, ctypes, ctypes.wintypes
from pathlib import Path
import pyautogui
from PIL import ImageGrab
import win32gui, win32con

ASSETS = Path(__file__).parent / "project_report_assets"
ASSETS.mkdir(parents=True, exist_ok=True)
pyautogui.FAILSAFE = False

# ── Find window ───────────────────────────────────────────────────────────────
def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            if "Security Monitor" in win32gui.GetWindowText(hwnd):
                found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd:
    print("App not found — launch desktop_app.py first.")
    sys.exit(1)

# Maximise and wait
win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(2.0)
win32gui.SetForegroundWindow(hwnd)
time.sleep(0.5)

# ── Get actual client origin in screen coordinates ────────────────────────────
def client_to_screen(cx, cy):
    pt = ctypes.wintypes.POINT(cx, cy)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
    return pt.x, pt.y

# Print calibration info
wr = win32gui.GetWindowRect(hwnd)
cr = win32gui.GetClientRect(hwnd)
print(f"Window rect  : {wr}")
print(f"Client rect  : {cr}")
origin = client_to_screen(0, 0)
print(f"Client origin: {origin}")
print()

# ── Screenshot ────────────────────────────────────────────────────────────────
def screenshot(name, wait=1.5):
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(wait)
    x1, y1, x2, y2 = win32gui.GetWindowRect(hwnd)
    img = ImageGrab.grab(bbox=(x1, y1, x2, y2), all_screens=True)
    # Crop title bar (approx 32px) and thin border
    img = img.crop((2, 32, img.width - 2, img.height - 2))
    path = ASSETS / f"{name}.png"
    img.save(str(path))
    print(f"  [{name}]  {img.size[0]}x{img.size[1]}")

def click_tab(cy, wait=1.5):
    sx, sy = client_to_screen(112, cy)
    print(f"  clicking screen ({sx}, {sy})")
    pyautogui.moveTo(sx, sy, duration=0.2)
    time.sleep(0.1)
    pyautogui.click()
    time.sleep(wait)

# ── Sidebar Y positions in CLIENT coordinates ────────────────────────────────
# These are measured from the top of the client area (below the title bar)
# Validated by looking at the app sidebar layout
SIDEBAR = {
    "overview":    110,
    "traffic":     150,
    "threats":     190,
    "sysmon":      230,
    "geomap":      270,
    "blocked":     350,
    "filescanner": 390,
    "tools":       468,
    "mlanalysis":  548,
    "adaptive":    588,
    "adversarial": 628,
    "settings":    708,
}

print("=== Starting screenshot capture ===\n")

# Baseline shot without any click
screenshot("sc_00_initial", wait=0.5)

# Click each tab and screenshot
for tab_key, cy in SIDEBAR.items():
    print(f"Navigating to: {tab_key} (cy={cy})")
    click_tab(cy, wait=1.5)
    screenshot(f"sc_{tab_key}", wait=0.3)

print("\nDone. Check ASSETS for results.")
print(f"Path: {ASSETS}")
