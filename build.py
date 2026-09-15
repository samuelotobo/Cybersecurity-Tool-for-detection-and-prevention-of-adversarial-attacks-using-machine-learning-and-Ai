"""
build.py — Security Monitor Desktop packaging script
=====================================================

Usage:
    python build.py                 # Windows installer (.exe via Inno Setup if available)
    python build.py --zip           # Build + create a portable ZIP instead of installer
    python build.py --onefile       # Alternative: single-EXE (slower start, simpler dist)
    python build.py --noinstaller   # Build folder only, skip installer compilation

Platforms:
    Windows  - full feature set (Scapy, Windows Firewall, Event Log, UAC elevation)
    Linux    - partial (Scapy works; Event Log / Firewall features gracefully disabled)
    macOS    - partial (same as Linux)
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT    = Path(__file__).parent.resolve()
HOOKS   = ROOT / "hooks"

# Build outside OneDrive/synced folders to prevent file-locking during PyInstaller cleanup.
# Falls back to the project root if C:\Builds is not available.
_BUILD_BASE = Path(r"C:\Builds\SecurityMonitor") if Path("C:\\Builds").exists() or True else ROOT
_BUILD_BASE.mkdir(parents=True, exist_ok=True)
DIST    = _BUILD_BASE / "dist"
BUILD   = _BUILD_BASE / "build"
OUTDIR  = DIST / "SecurityMonitor"
VERSION = "1.0.0"
APP_NAME = "SecurityMonitor"


# ── Helpers ───────────────────────────────────────────────────────────────────

def run(cmd: list[str], **kw) -> int:
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, **kw)
    return result.returncode


def banner(msg: str) -> None:
    line = "-" * 60
    print(f"\n{line}\n  {msg}\n{line}")


def check_deps() -> bool:
    """Verify required build tools are installed."""
    ok = True
    # (import_name, install_name)
    checks = [
        ("PyInstaller",   "pyinstaller"),
        ("PyQt6",         "PyQt6"),
        ("scapy",         "scapy"),
        ("sklearn",       "scikit-learn"),
        ("numpy",         "numpy"),
        ("pandas",        "pandas"),
        ("matplotlib",    "matplotlib"),
        ("folium",        "folium"),
        ("psutil",        "psutil"),
        ("dotenv",        "python-dotenv"),
        ("joblib",        "joblib"),
        ("requests",      "requests"),
        ("plyer",         "plyer"),
        ("qrcode",        "qrcode"),
    ]
    for import_name, install_name in checks:
        try:
            __import__(import_name)
        except ImportError:
            print(f"  [MISSING] {install_name}  ->  pip install {install_name}")
            ok = False
    return ok


def ensure_hooks() -> None:
    """Create custom PyInstaller hooks folder with Qt WebEngine support."""
    HOOKS.mkdir(exist_ok=True)

    # hook-PyQt6.QtWebEngineWidgets.py — copies QtWebEngineProcess binary
    hook_we = HOOKS / "hook-PyQt6.QtWebEngineWidgets.py"
    hook_we.write_text(
        "from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs\n"
        "datas    = collect_data_files('PyQt6')\n"
        "binaries = collect_dynamic_libs('PyQt6')\n",
        encoding="utf-8",
    )

    # hook-folium.py — folium bundles Leaflet.js templates
    hook_folium = HOOKS / "hook-folium.py"
    hook_folium.write_text(
        "from PyInstaller.utils.hooks import collect_data_files\n"
        "datas = collect_data_files('folium')\n",
        encoding="utf-8",
    )

    # hook-branca.py — branca JS/CSS templates
    hook_branca = HOOKS / "hook-branca.py"
    hook_branca.write_text(
        "from PyInstaller.utils.hooks import collect_data_files\n"
        "datas = collect_data_files('branca')\n",
        encoding="utf-8",
    )

    # hook-matplotlib.py — matplotlib data files
    hook_mpl = HOOKS / "hook-matplotlib.py"
    hook_mpl.write_text(
        "from PyInstaller.utils.hooks import collect_data_files\n"
        "datas = collect_data_files('matplotlib')\n",
        encoding="utf-8",
    )


def copy_runtime_files() -> None:
    """Copy runtime files into the distribution folder after PyInstaller runs."""
    if not OUTDIR.exists():
        print(f"[WARN] Output directory not found: {OUTDIR}")
        return

    # Files that PyInstaller can't auto-detect (generated at runtime or user-provided)
    runtime_extras = [
        ".env.example",   # template so users know what to set
    ]
    for fname in runtime_extras:
        src = ROOT / fname
        if src.exists():
            shutil.copy2(src, OUTDIR / fname)
            print(f"  Copied {fname}")


def build_zip() -> Path:
    """Zip the distribution folder for portable distribution."""
    ts = datetime.now().strftime("%Y%m%d_%H%M")
    plat = {"win32": "Windows", "darwin": "macOS", "linux": "Linux"}.get(
        sys.platform, sys.platform
    )
    zipname = DIST / f"{APP_NAME}_{VERSION}_{plat}_{ts}.zip"
    print(f"\nCreating ZIP -> {zipname}")
    with zipfile.ZipFile(zipname, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for f in OUTDIR.rglob("*"):
            if f.is_file():
                zf.write(f, f.relative_to(DIST))
    size_mb = zipname.stat().st_size / 1_048_576
    print(f"  ZIP created: {zipname.name} ({size_mb:.0f} MB)")
    return zipname


def build_inno_installer() -> bool:
    """
    Compile an Inno Setup installer (Windows only).
    Returns True if the installer was successfully compiled.
    """
    iss_file = ROOT / "installer.iss"
    if not iss_file.exists():
        print("[SKIP] installer.iss not found - skipping installer compilation")
        return False

    # Common Inno Setup installation paths
    iscc_candidates = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files (x86)\Inno Setup 5\ISCC.exe"),
    ]
    iscc = next((p for p in iscc_candidates if p.exists()), None)
    if iscc is None:
        # Try PATH
        iscc_path = shutil.which("iscc") or shutil.which("ISCC")
        if iscc_path:
            iscc = Path(iscc_path)

    if iscc is None:
        print(
            "[INFO] Inno Setup not found - skipping installer.\n"
            "       Install from https://jrsoftware.org/isinfo.php to generate a .exe installer."
        )
        return False

    rc = run([str(iscc), str(iss_file)])
    return rc == 0


def build_appimage() -> bool:
    """Build a Linux AppImage (Linux only, requires appimagetool on PATH)."""
    if shutil.which("appimagetool") is None:
        print(
            "[INFO] appimagetool not found - skipping AppImage.\n"
            "       Download from https://appimage.github.io/appimagetool/"
        )
        return False

    appdir = DIST / f"{APP_NAME}.AppDir"
    if appdir.exists():
        shutil.rmtree(appdir)
    appdir.mkdir(parents=True)

    # Copy distribution into AppDir/usr/bin
    usr_bin = appdir / "usr" / "bin"
    usr_bin.mkdir(parents=True)
    shutil.copytree(OUTDIR, usr_bin / APP_NAME)

    # AppRun entry point
    apprun = appdir / "AppRun"
    apprun.write_text(
        "#!/bin/sh\n"
        f'exec "${{APPDIR}}/usr/bin/{APP_NAME}/{APP_NAME}" "$@"\n',
        encoding="utf-8",
    )
    apprun.chmod(0o755)

    # Desktop file
    desktop = appdir / f"{APP_NAME}.desktop"
    desktop.write_text(
        f"[Desktop Entry]\nType=Application\nName=Security Monitor\n"
        f"Exec={APP_NAME}\nIcon={APP_NAME}\nCategories=Network;Security;\n",
        encoding="utf-8",
    )

    # Copy icon if available
    icon_src = ROOT / "ddos.png"
    if icon_src.exists():
        shutil.copy2(icon_src, appdir / f"{APP_NAME}.png")

    ts = datetime.now().strftime("%Y%m%d_%H%M")
    out_image = DIST / f"{APP_NAME}_{VERSION}_Linux_{ts}.AppImage"
    rc = run(["appimagetool", str(appdir), str(out_image)])
    return rc == 0


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Build Security Monitor Desktop")
    parser.add_argument("--zip",         action="store_true", help="Create portable ZIP after build")
    parser.add_argument("--onefile",     action="store_true", help="Single-EXE build (slow start)")
    parser.add_argument("--noinstaller", action="store_true", help="Skip installer compilation")
    parser.add_argument("--noclear",     action="store_true", help="Keep previous build/ and dist/ folders")
    args = parser.parse_args()

    banner("Security Monitor - Desktop Build")
    print(f"  Platform : {platform.system()} {platform.machine()}")
    print(f"  Python   : {sys.version.split()[0]}")
    print(f"  Version  : {VERSION}")

    # 1. Dependency check
    banner("1 / 5  Checking build dependencies")
    if not check_deps():
        print("\n[ERROR] Install missing packages and retry.")
        sys.exit(1)
    print("  All dependencies present.")

    # 2. Prepare hooks
    banner("2 / 5  Generating PyInstaller hooks")
    ensure_hooks()
    print(f"  Hooks written to {HOOKS}")

    # 3. Clean previous build
    if not args.noclear:
        banner("3 / 5  Cleaning previous build artifacts")
        for d in (BUILD, DIST):
            if d.exists():
                shutil.rmtree(d)
                print(f"  Removed {d}")

    # 4. PyInstaller
    banner("4 / 5  Running PyInstaller")

    if args.onefile:
        # Single-EXE mode — use a temporary modified spec
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm",
            "--onefile",
            "--windowed",
            "--name", APP_NAME,
            "--uac-admin",
            "--hidden-import", "PyQt6.QtWebEngineWidgets",
            "--hidden-import", "folium",
            "--hidden-import", "matplotlib",
            str(ROOT / "desktop_app.py"),
        ]
        icon = ROOT / "ddos.ico"
        if icon.exists():
            cmd += ["--icon", str(icon)]
    else:
        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--noconfirm",
            "--distpath", str(DIST),
            "--workpath", str(BUILD),
            str(ROOT / "desktop_app.spec"),
        ]

    rc = run(cmd)
    if rc != 0:
        print(f"\n[ERROR] PyInstaller failed with exit code {rc}")
        sys.exit(rc)

    # 5. Post-build steps
    banner("5 / 5  Post-build")
    copy_runtime_files()

    if args.zip:
        build_zip()
    elif platform.system() == "Linux":
        build_appimage()
    elif platform.system() == "Windows" and not args.noinstaller:
        build_inno_installer()

    # Summary
    banner("Build complete")
    if OUTDIR.exists():
        file_count = sum(1 for _ in OUTDIR.rglob("*") if _.is_file())
        total_mb   = sum(f.stat().st_size for f in OUTDIR.rglob("*") if f.is_file()) / 1_048_576
        print(f"  Output   : {OUTDIR}")
        print(f"  Files    : {file_count}")
        print(f"  Size     : {total_mb:.0f} MB")
    else:
        print(f"  Output   : {DIST / APP_NAME}.exe  (--onefile mode)")

    print("\nTo run:")
    if platform.system() == "Windows":
        print(f"  {OUTDIR / 'SecurityMonitor.exe'}")
    else:
        print(f"  {OUTDIR / 'SecurityMonitor'}")


if __name__ == "__main__":
    main()
