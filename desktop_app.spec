# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for Security Monitor Desktop
#
# Build (folder mode — fast startup, ~350 MB distribution):
#   python build.py
#   -or-
#   pyinstaller desktop_app.spec --noconfirm
#
# Prerequisites:
#   pip install -r requirements.txt
#   pip install pyinstaller

import sys
from pathlib import Path

ROOT = Path(SPECPATH)

# ── Data files bundled into the distribution ───────────────────────────────────
_datas = [
    # Detector package (all Python source + any JSON inside)
    (str(ROOT / 'detectors'),            'detectors'),
    # Web/mobile companion dashboard — desktop_app.py starts this itself on
    # launch (port 8080); its Flask templates/static files aren't .py source
    # so PyInstaller's import analysis won't find them on its own.
    (str(ROOT / 'web_dashboard'),        'web_dashboard'),
    # Core config
    (str(ROOT / 'config.py'),            '.'),
    (str(ROOT / 'rules_config.json'),    '.'),
]

# Optional files — include only if they exist at build time
_optional = [
    ('ddos_detector_model.joblib',    '.'),
    ('anomaly_model.joblib',          '.'),
    ('model_metrics.json',            '.'),      # pre-computed metrics — no 151 MB CSV needed
    ('model_version_history.json',    '.'),      # adaptive training version log
    ('corrective_layer.joblib',       '.'),      # online corrective model (if trained)
    ('Phising_dataset_predict.csv',   '.'),
    ('ddos.ico',                      '.'),
    ('ddos.png',                      '.'),
    ('network_map.html',              '.'),
    ('geo_cache.json',                '.'),
    ('blocked_ips.json',              '.'),
    ('rules_config.json',             '.'),
    ('settings.json',                 '.'),
]
for src, dst in _optional:
    if (ROOT / src).exists():
        _datas.append((str(ROOT / src), dst))

# ── Hidden imports PyInstaller misses ─────────────────────────────────────────
_hidden = [
    # ── scikit-learn internals ──────────────────────────────────────────────
    'sklearn.ensemble._forest',
    'sklearn.ensemble._gb',
    'sklearn.ensemble._weight_boosting',
    'sklearn.tree._classes',
    'sklearn.tree._utils',
    'sklearn.calibration',
    'sklearn.utils._weight_vector',
    'sklearn.neighbors._dist_metrics',
    'sklearn.neighbors.typedefs',
    'sklearn.svm._libsvm',
    'sklearn.svm._libsvm_sparse',
    'sklearn.svm._liblinear',
    'sklearn.linear_model._sag_fast',
    'sklearn.utils._cython_blas',
    'sklearn.utils.murmurhash',
    'sklearn.utils._random',
    'sklearn.utils._logistic_sigmoid',
    # ── joblib / numpy ──────────────────────────────────────────────────────
    'joblib',
    'joblib.externals.loky.backend.managers',
    'numpy.core._multiarray_umath',
    'numpy.core._multiarray_tests',
    # ── pandas ──────────────────────────────────────────────────────────────
    'pandas._libs.interval',
    'pandas._libs.hashtable',
    'pandas._libs.lib',
    # ── matplotlib + Qt backend ─────────────────────────────────────────────
    'matplotlib',
    'matplotlib.backends.backend_qt5agg',
    'matplotlib.backends.backend_agg',
    'matplotlib.backends.backend_qtagg',
    'matplotlib.figure',
    'matplotlib.pyplot',
    # ── scapy ───────────────────────────────────────────────────────────────
    'scapy',
    'scapy.all',
    'scapy.layers.l2',
    'scapy.layers.inet',
    'scapy.layers.inet6',
    'scapy.layers.http',
    'scapy.layers.dns',
    'scapy.layers.tls',
    'scapy.arch.windows',
    'scapy.arch.windows.native',
    # ── PyQt6 ───────────────────────────────────────────────────────────────
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.QtPrintSupport',
    'PyQt6.QtNetwork',
    # ── PyQt6-WebEngine (GeoMap tab) ────────────────────────────────────────
    'PyQt6.QtWebEngineWidgets',
    'PyQt6.QtWebEngineCore',
    'PyQt6.QtWebChannel',
    # ── adaptive training ────────────────────────────────────────────────────
    'detectors.adaptive_trainer',
    # ── folium (geo map HTML generation) ────────────────────────────────────
    'folium',
    'folium.plugins',
    'branca',
    'branca.colormap',
    'branca.element',
    # ── requests / HTTP ─────────────────────────────────────────────────────
    'requests',
    'urllib3',
    'certifi',
    'charset_normalizer',
    # ── dotenv / config ─────────────────────────────────────────────────────
    'dotenv',
    'dotenv.main',
    # ── psutil ──────────────────────────────────────────────────────────────
    'psutil',
    # ── plyer (system tray / toast notifications) ───────────────────────────
    'plyer',
    'plyer.platforms.win.notification',
    # ── qrcode ──────────────────────────────────────────────────────────────
    'qrcode',
    'qrcode.image.pil',
    # ── Pillow (qrcode dependency) ───────────────────────────────────────────
    'PIL',
    'PIL.Image',
    # ── cryptography (requests TLS, scapy TLS) ──────────────────────────────
    'cryptography',
    'cryptography.hazmat.primitives',
    # ── web/mobile companion dashboard (Flask, started by desktop_app.py) ───
    'web_dashboard',
    'web_dashboard.app',
    'flask',
    'flask_cors',
    'werkzeug',
    'jinja2',
    'click',
    'itsdangerous',
    'blinker',
    'jwt',                      # PyJWT
]

a = Analysis(
    [str(ROOT / 'desktop_app.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=_datas,
    hiddenimports=_hidden,
    hookspath=[str(ROOT / 'hooks')],   # custom hooks folder (created by build.py)
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Jupyter / IPython
        'notebook', 'IPython', 'ipykernel',
        # Unused backends
        'tkinter', 'wx',
    ],
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    [],                        # no binaries merged — they go into COLLECT
    exclude_binaries=True,     # onedir mode
    name='SecurityMonitor',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[
        # Qt DLLs should not be UPX-compressed (causes crashes)
        'Qt6*.dll', 'Qt6*.so',
        'qwindows.dll', 'qxcb.so',
    ],
    console=False,             # no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'ddos.ico') if (ROOT / 'ddos.ico').exists() else None,
    # UAC elevation: required for raw packet sniffing + Windows Firewall
    uac_admin=True,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=['Qt6*.dll', 'Qt6*.so', 'qwindows.dll'],
    name='SecurityMonitor',
)
