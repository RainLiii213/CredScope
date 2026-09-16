# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path


root = Path(SPECPATH)
data_directories = (
    "config",
    "templates",
    "rulepacks",
    "examples",
    "demo_project",
    "demo_custom_rules",
    "demo_baseline",
    "demo_statistics",
)
datas = [(str(root / name), name) for name in data_directories]
entry_script = root / "main.py"  # 薄启动器导入 src.main，保证包内相对导入稳定。

a = Analysis(
    [str(entry_script)],
    pathex=[str(root)],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="CredScope",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=str(root / "build" / "version_info.txt"),
)
