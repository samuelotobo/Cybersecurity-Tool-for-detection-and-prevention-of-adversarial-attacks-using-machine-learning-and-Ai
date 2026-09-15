@echo off
REM ── Security Monitor — Quick Launch (Windows) ──────────────────────────────
REM Run this file as Administrator for full features (Scapy, IP blocking).
REM Right-click → "Run as administrator"

cd /d "%~dp0"

REM Check if Python is available
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found in PATH.
    echo Install Python 3.11+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Activate virtual environment if present
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [WARN] No .venv found. Running with system Python.
    echo Run: python -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt
)

REM Launch the desktop app
python desktop_app.py
pause
