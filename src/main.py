"""CredScope 命令行入口。"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .baseline import (
    BaselineError,
    apply_baseline,
    create_baseline_data,
    load_baseline,
    write_baseline,
)
from .context_detector import ContextConfigError
from .reporter import (
    ReportWriteError,
    filter_by_min_level,
    render_cli,
    write_html_report,
    write_json_report,
)
from .resource_paths import (
    application_output_dir,
    resource_path,
    resolve_input_path,
)
from .rule_detector import RuleConfigError
from .rule_loader import load_combined_rules, validate_rule_pack
from .scanner import ScanPathError, scan_project
from .version import PRODUCT_NAME, __version__


OFFICIAL_RULEPACKS = {
    "ai": "ai_llm_services.json",
    "devops": "devops_registry.json",
    "web": "web_saas_services.json",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="credscope",
        description="CredScope：在本地审计源代码中的潜在敏感凭据。",
    )
    parser.add_argument(
        "--version", action="version", version=f"{PRODUCT_NAME} {__version__}"
    )
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
    scan.add_argument(
        "--rules", action="append", default=[], type=Path, metavar="FILE",
        help="追加用户 JSON 规则包，可重复指定",
    )
    scan.add_argument(
        "--rulepack", action="append", default=[],
        choices=("ai", "devops", "web", "all"), metavar="PACK",
        help="启用官方规则包：ai、devops、web 或 all；可重复指定",
    )
    scan.add_argument(
        "--baseline", type=Path, metavar="FILE",
        help="与指定 Baseline 比较并标记 NEW / EXISTING / RESOLVED",
    )

    baseline = commands.add_parser("baseline", help="创建或更新 Finding Baseline")
    baseline_commands = baseline.add_subparsers(dest="baseline_command", required=True)
    create = baseline_commands.add_parser("create", help="从当前扫描创建 Baseline")
    create.add_argument("path", type=Path, help="待扫描项目目录")
    create.add_argument("--output", type=Path, help="输出文件，默认为项目根目录下 .credscope-baseline.json")
    create.add_argument("--rules", action="append", default=[], type=Path, metavar="FILE")
    update = baseline_commands.add_parser("update", help="用当前扫描结果更新 Baseline")
    update.add_argument("path", type=Path, help="待扫描项目目录")
    update.add_argument("--file", required=True, type=Path, help="待更新的 Baseline 文件")
    update.add_argument("--rules", action="append", default=[], type=Path, metavar="FILE")

    rules = commands.add_parser("rules", help="校验或列出声明式规则")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    validate = rule_commands.add_parser("validate", help="校验一个 JSON Rule Pack")
    validate.add_argument("file", type=Path)
    list_rules = rule_commands.add_parser("list", help="列出 Built-in 及可选规则包")
    list_rules.add_argument("--rules", action="append", default=[], type=Path, metavar="FILE")

    demo = commands.add_parser("demo", help="运行内置安全演示并生成 JSON/HTML 报告")
    demo.add_argument(
        "--output-dir", type=Path,
        help="演示报告目录，默认为程序目录下 output",
    )
    return parser


def default_output(report_type: str) -> Path:
    return application_output_dir() / f"credscope-report.{report_type}"


def official_rule_paths(selections: list[str]) -> list[Path]:
    """把 CLI 简写映射为稳定顺序的内置规则包路径。"""

    enabled = set(OFFICIAL_RULEPACKS) if "all" in selections else set(selections)
    return [
        resource_path("rulepacks", filename)
        for name, filename in OFFICIAL_RULEPACKS.items()
        if name in enabled
    ]


def combined_rule_paths(rulepacks: list[str], custom_paths: list[Path]) -> list[Path]:
    paths = official_rule_paths(rulepacks)
    seen = {path.resolve() for path in paths}
    for path in custom_paths:
        resolved = resolve_input_path(path)
        if resolved not in seen:
            paths.append(resolved)
            seen.add(resolved)
    return paths


def _render_rule_validation(path: Path) -> int:
    path = resolve_input_path(path)
    report = validate_rule_pack(path)
    print("CredScope Rule Validator")
    print(f"File: {report.path}")
    print(f"Pack: {report.pack_name} {report.version}".rstrip())
    print(f"Rules found: {report.rules_found}")
    print(f"Valid:       {report.valid_count}")
    print(f"Warning:     {report.warning_count}")
    print(f"Invalid:     {report.invalid_count}")
    for issue in report.issues:
        print(f"{issue.level} | {issue.rule_id} | {issue.reason}")
    return 0 if report.is_valid else 2


def _list_rules(custom_paths: list[Path]) -> int:
    config = resource_path("config", "rules.json")
    loaded, reports = load_combined_rules(
        config, [resolve_input_path(path) for path in custom_paths]
    )
    print("CredScope Rules")
    for rule in loaded:
        source = "Built-in" if Path(rule.source).resolve() == config.resolve() else rule.source
        print(f"{rule.id:28} | {rule.name:36} | {source}")
    invalid = sum(report.invalid_count for report in reports)
    for report in reports:
        for issue in report.issues:
            print(f"{issue.level} | {issue.rule_id} | {issue.reason}")
    return 2 if invalid else 0


def _run_baseline_command(args: argparse.Namespace) -> int:
    target = resolve_input_path(args.path)
    rules = [resolve_input_path(path) for path in args.rules]
    result = scan_project(target, custom_rule_paths=rules)
    if args.baseline_command == "create":
        output = args.output or target / ".credscope-baseline.json"
        saved = write_baseline(create_baseline_data(result), output)
        print(f"Baseline 已创建: {saved}")
        print(f"Findings: {len(result.findings)}")
        return 0
    baseline_file = resolve_input_path(args.file)
    original = load_baseline(baseline_file)
    saved = write_baseline(
        create_baseline_data(result, original=original), baseline_file, overwrite=True
    )
    print(f"Baseline 已更新: {saved}")
    print(f"Findings: {len(result.findings)}")
    return 0


def _run_scan_command(args: argparse.Namespace) -> int:
    target = resolve_input_path(args.path)
    result = scan_project(
        target,
        excludes=set(args.exclude),
        custom_rule_paths=combined_rule_paths(args.rulepack, args.rules),
    )
    if args.baseline:
        baseline_path = resolve_input_path(args.baseline)
        apply_baseline(result, load_baseline(baseline_path), baseline_path)
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


def _run_demo(args: argparse.Namespace) -> int:
    target = resource_path("demo_project")
    result = scan_project(target, custom_rule_paths=official_rule_paths(["ai"]))
    print(render_cli(result))
    output_dir = (
        args.output_dir.expanduser().resolve()
        if args.output_dir else application_output_dir()
    )
    json_path = write_json_report(result, output_dir / "demo-report.json")
    html_path = write_html_report(result, output_dir / "demo-dashboard.html")
    rule_ids = {finding.rule_id for finding in result.findings}
    types = {finding.secret_type for finding in result.findings}
    checks = (
        ("Built-in Rule Detector", "github-token" in rule_ids),
        ("Context Detector", "Hardcoded Password" in types),
        ("AI Rule Pack", "anthropic-api-key" in rule_ids),
        ("JSON report", json_path.is_file()),
        ("Offline HTML dashboard", html_path.is_file()),
        ("Masked output", all("*" in item.masked_value for item in result.findings)),
    )
    print("\nDemo 功能检查:")
    for label, passed in checks:
        print(f"  [{'PASS' if passed else 'FAIL'}] {label}")
    print(f"JSON 报告: {json_path.resolve()}")
    print(f"HTML Dashboard: {html_path.resolve()}")
    return 0 if all(passed for _, passed in checks) else 2


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        if args.command == "rules":
            if args.rules_command == "validate":
                return _render_rule_validation(args.file)
            return _list_rules(args.rules)
        if args.command == "baseline":
            return _run_baseline_command(args)
        if args.command == "demo":
            return _run_demo(args)
        return _run_scan_command(args)
    except (
        ScanPathError, RuleConfigError, ContextConfigError, ReportWriteError,
        BaselineError,
    ) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("扫描已由用户取消。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(run())
