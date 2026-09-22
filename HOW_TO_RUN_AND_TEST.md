# How to Run & Test — Quick Guide

A short, copy-paste-friendly checklist for getting Security Monitor running and
verifying it works. For full feature documentation see [README.md](README.md).

---

## Option A — Just run it (no Python required)

Fastest path if you only want to see the app working, e.g. for a demo.

1. Download the packaged build from
   [Releases → v1.0.0](https://github.com/samuelotobo/Cybersecurity-Tool-for-detection-and-prevention-of-adversarial-attacks-using-machine-learning-and-Ai/releases/tag/v1.0.0)
   (`SecurityMonitor_1.0.0_Windows_....zip`).
2. Extract the zip anywhere (e.g. Desktop).
3. Right-click `SecurityMonitor.exe` → **Run as administrator**.
4. Click **Yes** on the "Unknown publisher" UAC prompt (the build isn't
   code-signed — expected for a student project) and **Allow** on the
   Windows Firewall prompt.
5. The dashboard should open showing "Your network is healthy". Done.

Skip to [Testing](#testing) below if you also want to run the test suite —
that still needs Python (Option B, steps 1–3).

---

## Option B — Run from source

### Step 1: Prerequisites

- Python 3.10+ (added to PATH)
- [Git LFS](https://git-lfs.com/) — the training CSVs are stored via LFS
- Windows 10/11 recommended for full features (packet capture, firewall
  blocking, Event Log monitoring). Linux/macOS work for everything else
  (run as root for packet capture).

### Step 2: Get the code

```bash
git lfs install                 # once per machine
git clone <your-repo-url>
cd security_monitor
git lfs pull                    # only needed if the CSVs look like tiny text files
```

### Step 3: Install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows. Use `source .venv/bin/activate` on Linux/macOS
pip install -r requirements.txt
```

### Step 4: (Optional) configure API keys

```bash
copy .env.example .env          # Windows. `cp .env.example .env` on Linux/macOS
```

Edit `.env` if you want these optional features — the app runs fine with all
of them blank, it just skips those checks:

| Key | Enables |
|---|---|
| `GROQ_API_KEY` | AI email-phishing analysis (primary) |
| `GEMINI_API_KEY` | AI email-phishing analysis (fallback) |
| `ABUSEIPDB_API_KEY` | Attacker IP reputation lookups |
| `GATEWAY_IP` | Router IP, for ARP gateway-hijack detection |

### Step 5: (Optional) retrain the ML models

Pretrained models (`ddos_detector_model.joblib`, `anomaly_model.joblib`,
`corrective_layer.joblib`) are already included in the repo — **you can skip
this step**. Only run it if you want to regenerate them from the dataset:

```bash
python train_model.py
```

### Step 6: Run the app

```bash
python desktop_app.py
```

Run your terminal **as Administrator** for full features (live packet
capture, Windows Firewall IP blocking). Without admin rights, the GUI still
opens but those two features are disabled.

---

## Testing

### Step 7: Automated test suite

```bash
pytest -v
```

Runs everything in `tests/` — unit/integration tests, no admin rights, no
live network, no GUI window needed. This is what CI / a grader would run.

### Step 8: Manual smoke tests

```bash
python demo_test.py             # exercises every detector with simulated events
python demo_test.py --fast      # same, but skips the slower ML checks
python demo_test.py --verbose   # same, with extra per-test detail
```

Safe to run anywhere: no real packets sent, no admin rights, no external API
calls, temp files auto-cleaned.

```bash
python test_desktop_app.py      # full GUI smoke test — opens the app and
                                 # exercises all 12 tabs, widgets and signals
```

### Step 9: (Optional) build your own standalone .exe

```bash
python build.py --zip
```

Output goes to `C:\Builds\SecurityMonitor\dist\` (built outside the project
folder to dodge OneDrive file-locking during PyInstaller's cleanup step).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| CSVs are a few KB of text instead of real data | `git lfs pull` |
| Test says "DDoS model not loaded" | `python train_model.py` |
| No packet capture / IP blocking doesn't work | Run as Administrator, and install [Npcap](https://npcap.com/#download) |
| `pytest` shows a `.pytest_cache` permission warning | Harmless — the cache plugin is already disabled in `pyproject.toml` |
| UAC says "Unknown publisher" | Expected — the build isn't code-signed. Click Yes to proceed |
