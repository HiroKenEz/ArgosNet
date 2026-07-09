# -*- mode: python ; coding: utf-8 -*-
"""Spécification PyInstaller pour ArgosNet (exécutable Windows autonome).

Build :  pyinstaller argosnet.spec
Sortie : dist/ArgosNet.exe
"""
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Scapy charge dynamiquement ses couches : on force l'inclusion de tous ses modules.
hiddenimports = collect_submodules("scapy")

# Fichiers de données à embarquer (chargés au runtime par chemin relatif).
datas = [
    ("argosnet/core/detection/rules.yaml", "argosnet/core/detection"),
]
# Base OUI de mac-vendor-lookup (résolution constructeur hors-ligne), si présente.
datas += collect_data_files("mac_vendor_lookup")

a = Analysis(
    ["run.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="ArgosNet",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,          # application GUI : pas de fenêtre console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
