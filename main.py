"""CredScope 命令行入口。"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from context_detector import ContextConfigError
from reporter import (
    ReportWriteError,
    filter_by_min_level,
    render_cli,
    write_html_report,
    write_json_report,
)
from rule_detector import RuleConfigError
from scanner import ScanPathError, scan_project


VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credscope",
        description="CredScope：在本地审计源代码中的潜在敏感凭据。",
    )
    parser.add_argument("--version", action="version", version=f"CredScope {VERSION}")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="扫描一个项目目录")
    scan.add_argument("path", type=Path, help="待扫描的项目目录")
    scan.add_argument(
        "--report", choices=("none", "json", "html"), default="none",
        help="另外生成 JSON 或 HTML 报告",
    )
    scan.add_argument("--output", type=Path, help="报告输出路径")
    scan.add_argument("--verbose", action="store_true", help="显示详细诊断日志")
    scan.add_argument(
        "--min-level", choices=("low", "medium", "high", "critical"),
        default="low", help="最低展示/报告风险等级",
    )
    scan.add_argument(
        "--exclude", action="append", default=[], metavar="NAME",
        help="额外忽略的目录名，可重复指定",
    )
    return parser


def default_output(report_type: str) -> Path:
    return Path(__file__).resolve().parent / "output" / f"credscope-report.{report_type}"


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        result = scan_project(args.path, excludes=set(args.exclude))
        shown = filter_by_min_level(result, args.min_level)
        print(render_cli(shown))
        if args.report != "none":
            output = args.output or default_output(args.report)
            if args.report == "json":
                write_json_report(shown, output)
            else:
                write_html_report(shown, output)
            print(f"报告已生成: {output.resolve()}")
        return 0
    except (ScanPathError, RuleConfigError, ContextConfigError, ReportWriteError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("扫描已由用户取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(run())
