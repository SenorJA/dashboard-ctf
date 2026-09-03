# -*- mode: python ; coding: utf-8 -*-
#
# PyInstaller spec for MIRV backend.
#
# Build:
#   cd backend
#   pip install pyinstaller
#   pyinstaller mirv-backend.spec
#
# Output: dist/mirv-backend(.exe) — a self-contained HTTP/WS backend.
#   * Bundles built-in skills/ and plugins/ so the packaged binary finds them
#     under sys._MEIPASS (the modules resolve their dirs via __file__).
#   * Bundles ../frontend so the binary can serve the SPA standalone
#     (used when NOT in --tauri-mode).
#   * Run with `--tauri-mode` to omit frontend serving (Tauri WebView takes over).
#
# NOTE: This spec is maintained by hand. If new heavy third-party libs are
# added, add them to hiddenimports or a hook. See backend/build_backend.bat.

import os
import sys

from PyInstaller.utils.hooks import (
    collect_submodules,
    collect_data_files,
    copy_metadata,
)

block_cipher = None
root = os.path.dirname(os.path.abspath(SPEC))

# ── Data files ────────────────────────────────────────────────────────────
# backend/skills (built-in skill playbooks) and backend/plugins (example).
backend_dir = root
frontend_dir = os.path.normpath(os.path.join(root, os.pardir, "frontend"))

datas = [
    (os.path.join(backend_dir, "skills"), "backend/skills"),
    (os.path.join(backend_dir, "plugins"), "backend/plugins"),
]

# Bundle the frontend only when it exists (copy-tree tolerates absence).
# The datas tuple schema: (source, target_dir_under__MEIPASS__).
if os.path.isdir(frontend_dir):
    datas.append((frontend_dir, "frontend"))

# Supabase + pytz + reportlab metadata (needed at import time).
# copy_metadata raises if a package isn't installed — guard each one so the
# spec builds on machines that omit optional dependencies.
def _try_copy_metadata(pkg):
    try:
        return copy_metadata(pkg)
    except Exception:
        return []

for _meta_pkg in ("supabase", "pytz", "reportlab"):
    datas += _try_copy_metadata(_meta_pkg)

# Silence noisy subprocess warnings from these libs.
def _safe_submodules(pkg):
    try:
        return collect_submodules(pkg)
    except Exception:
        return []

hiddenimports = (
    _safe_submodules("supabase")
    + _safe_submodules("reportlab")
    + _safe_submodules("httpx")
    + _safe_submodules("paramiko")
    + _safe_submodules("cryptography")
)

# ── Entry point ───────────────────────────────────────────────────────────
a = Analysis(
    ["main.py"],
    pathex=[backend_dir],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "PyQt5",
        "PySide2",
        "matplotlib",
        "pytest",
        "IPython",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="mirv-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# ── OneDir layout (dist/mirv-backend/) ────────────────────────────────────
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="mirv-backend",
)
