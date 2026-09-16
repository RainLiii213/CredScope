"""源码运行与 PyInstaller one-file 运行共用的资源路径工具。"""

from __future__ import annotations

import sys
from pathlib import Path


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def resource_root() -> Path:
    """返回只读随包资源根目录。"""

    bundle = getattr(sys, "_MEIPASS", None)
    if is_frozen() and bundle:
        return Path(bundle).resolve()
    return Path(__file__).resolve().parent.parent


def application_root() -> Path:
    """返回可写的程序分发根目录。"""

    if is_frozen():
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def resource_path(*parts: str) -> Path:
    return resource_root().joinpath(*parts)


def application_output_dir() -> Path:
    return application_root() / "output"


def resolve_input_path(path: Path) -> Path:
    """优先使用用户路径；缺失的相对路径可回退到分发或内置资源。"""

    expanded = path.expanduser()
    if expanded.exists() or expanded.is_absolute():
        return expanded.resolve()
    for root in (application_root(), resource_root()):
        candidate = (root / expanded).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.exists():
            return candidate
    return expanded.resolve()
