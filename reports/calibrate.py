"""Calibration script — writes window info to a file so we can read it."""
import sys, time, ctypes, ctypes.wintypes
from pathlib import Path
import win32gui, win32con
from PIL import ImageGrab

OUT = Path(__file__).parent / "calibration.txt"

def find_hwnd():
    found = []
    def cb(hwnd, _):
        if win32gui.IsWindowVisible(hwnd) and "Security Monitor" in win32gui.GetWindowText(hwnd):
            found.append(hwnd)
    win32gui.EnumWindows(cb, None)
    return found[0] if found else None

hwnd = find_hwnd()
if not hwnd:
    OUT.write_text("NO WINDOW FOUND")
    sys.exit(1)

win32gui.ShowWindow(hwnd, win32con.SW_MAXIMIZE)
time.sleep(2)
win32gui.SetForegroundWindow(hwnd)
time.sleep(0.5)

wr = win32gui.GetWindowRect(hwnd)
cr = win32gui.GetClientRect(hwnd)

# Convert client (0,0) to screen
pt = ctypes.wintypes.POINT(0, 0)
ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(pt))
client_origin = (pt.x, pt.y)

# Convert a few Y positions
pts = {}
for cy in [100, 150, 200, 250, 300, 350, 400, 450, 500, 550, 600, 650, 700]:
    p = ctypes.wintypes.POINT(112, cy)
    ctypes.windll.user32.ClientToScreen(hwnd, ctypes.byref(p))
    pts[cy] = (p.x, p.y)

# Take a screenshot of the window to use as reference
x1, y1, x2, y2 = wr
img = ImageGrab.grab(bbox=(x1, y1, x2, y2), all_screens=True)
img = img.crop((2, 32, img.width - 2, img.height - 2))
img.save(str(Path(__file__).parent / "project_report_assets" / "calibration_shot.png"))

info = [
    f"Window rect   : {wr}",
    f"Client rect   : {cr}",
    f"Client origin : {client_origin}",
    "",
    "Screen coords for sidebar clicks (x=112, various y):",
]
for cy, sc in pts.items():
    info.append(f"  client_y={cy:3d}  ->  screen({sc[0]}, {sc[1]})")

OUT.write_text("\n".join(info))
print("\n".join(info))
