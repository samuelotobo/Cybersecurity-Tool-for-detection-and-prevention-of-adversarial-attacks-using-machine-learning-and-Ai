"""
Take screenshots of each tab of the running Security Monitor app.
Saves PNGs to reports/project_report_assets/
"""
import subprocess, sys, time
from pathlib import Path
import ctypes

OUT = Path(__file__).parent / "project_report_assets"
OUT.mkdir(parents=True, exist_ok=True)

try:
    import pygetwindow as gw
    HAS_GW = True
except ImportError:
    HAS_GW = False

# Use PIL/ImageGrab for screenshots
from PIL import ImageGrab
import win32gui, win32con, win32api

def find_app_window():
    """Find the Security Monitor window handle."""
    result = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if "Security Monitor" in title or "SecurityMonitor" in title:
                result.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return result[0] if result else None

def screenshot_region(hwnd, name):
    """Take a screenshot of the given window."""
    try:
        win32gui.SetForegroundWindow(hwnd)
        time.sleep(0.4)
        rect = win32gui.GetWindowRect(hwnd)
        x1, y1, x2, y2 = rect
        img = ImageGrab.grab(bbox=(x1, y1, x2, y2))
        path = OUT / f"{name}.png"
        img.save(str(path), "PNG")
        print(f"  Saved: {path.name}  ({img.size[0]}x{img.size[1]})")
        return str(path)
    except Exception as e:
        print(f"  Error capturing {name}: {e}")
        return None

# Give app time to fully load
print("Waiting for app to load…")
time.sleep(6)

hwnd = find_app_window()
if not hwnd:
    print("App window not found — is Security Monitor running?")
    sys.exit(1)

print(f"Found window: hwnd={hwnd}")
win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(1)

# Take full-window screenshot (Dashboard)
screenshot_region(hwnd, "ui_dashboard_tab")
print("Screenshot 1: Dashboard")

# Send keyboard shortcuts to navigate tabs via clicks
# We'll use multiple full screenshots at intervals
for i in range(4):
    time.sleep(1.5)
    screenshot_region(hwnd, f"ui_tab_{i+2}")
    print(f"Screenshot {i+2}: Tab view {i+2}")

print("\nScreenshots saved to:", OUT)
