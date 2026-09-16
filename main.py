"""向后兼容启动器；正式产品代码位于 src 包。"""

from src.main import run


if __name__ == "__main__":
    raise SystemExit(run())

