"""生成 Windows 版本资源并构建正式 one-file CredScope.exe。"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from src.version import PRODUCT_NAME, __version__


ROOT = Path(__file__).resolve().parent


def _numeric_version() -> tuple[int, int, int, int]:
    parts = [int(part) for part in __version__.split(".")]
    if len(parts) != 3:
        raise ValueError("__version__ 必须使用 major.minor.patch 格式")
    return parts[0], parts[1], parts[2], 0


def _write_windows_version_info() -> Path:
    version = _numeric_version()
    build_dir = ROOT / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    path = build_dir / "version_info.txt"
    dotted = ".".join(str(part) for part in version)
    path.write_text(
        f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers={version!r}, prodvers={version!r}, mask=0x3f,
    flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[StringFileInfo([StringTable('040904B0', [
    StringStruct('CompanyName', 'CredScope Course Project'),
    StringStruct('FileDescription', '{PRODUCT_NAME} Source Code Credential Security Auditor'),
    StringStruct('FileVersion', '{dotted}'),
    StringStruct('InternalName', '{PRODUCT_NAME}'),
    StringStruct('OriginalFilename', '{PRODUCT_NAME}.exe'),
    StringStruct('ProductName', '{PRODUCT_NAME}'),
    StringStruct('ProductVersion', '{__version__}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])])
""",
        encoding="utf-8",
    )
    return path


def main() -> int:
    _write_windows_version_info()
    subprocess.run(
        [sys.executable, "-m", "PyInstaller", "--clean", "--noconfirm", "CredScope.spec"],
        cwd=ROOT,
        check=True,
    )
    print(f"构建完成: {ROOT / 'dist' / 'CredScope.exe'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
