"""
take_missing.py — Captures the 3 remaining missing tabs.
Positions derived from observed pattern (each button ~52px apart, shifted from earlier estimates).
"""
import sys, time, ctypes, ctypes.wintypes
from pathlib import Path
import pyautogui, win32gui, win32con
from PIL import ImageGrab

ASSETS = Path(__file__).parent / "project_report_assets"
pyautogui.FAILSAFE = False

def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and "Security Monitor" in win32gui.GetWindowText(hwnd):
            found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd: sys.exit("No window")

win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(2)
win32gui.SetForegroundWindow(hwnd)
time.sleep(0.5)

def ctos(cx, cy):
    pt = ctypes.wintypes.POINT(cx, cy)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
    return pt.x, pt.y

def snap(name, wait=2.0):
    win32gui.SetForegroundWindow(hwnd)
    time.sleep(wait)
    x1,y1,x2,y2 = win32gui.GetWindowRect(hwnd)
    img = ImageGrab.grab(bbox=(x1,y1,x2,y2), all_screens=True)
    img = img.crop((2, 32, img.width-2, img.height-2))
    img.save(str(ASSETS / f"{name}.png"))
    print(f"Saved: {name}.png")

def click(cy, wait=2.0):
    sx, sy = ctos(112, cy)
    pyautogui.moveTo(sx, sy, duration=0.2)
    time.sleep(0.1)
    pyautogui.click()
    time.sleep(wait)

# Derived from pattern: actual position = my_estimate + 52 (one step shift)
# Geo Map: System Monitor confirmed at 316, so Geo Map at 316+52=368
# Adversarial Lab: ML Analysis confirmed at 662, Adversarial at 662+52=714
# Settings: Adaptive Training confirmed at 736, Settings at 736+52=788

print("Geo Map...")
click(368); snap("final_05b_geo_map", wait=3.0)

print("Adversarial Lab...")
click(714); snap("final_11b_adversarial_lab", wait=2.0)

print("Settings...")
click(788); snap("final_12b_settings", wait=2.0)

# Also grab Test & Analyse overview (Simulations tab = first inner tab)
print("Test & Analyse overview...")
click(510); time.sleep(1)   # File Scanner confirmed at 510 = goes to File Scanner...
# Actually Tools is at 510+52=562? Try:
click(562); snap("final_08f_tools_overview", wait=2.0)

Path(__file__).parent.joinpath("missing_done.txt").write_text("done")
print("Done.")
