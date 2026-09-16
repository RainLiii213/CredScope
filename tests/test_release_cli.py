"""Final Release 易用性、版本和资源路径回归测试。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from src import __version__
from src import main, resource_paths
from src.baseline import create_baseline_data
from src.models import ScanResult, ScanStats
from src.reporter import render_cli, write_html_report


ROOT = Path(__file__).resolve().parents[1]
ENV = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1"}


def cli(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=ENV,
        check=False,
    )


def module_cli(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "src.main", *(str(arg) for arg in args)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=ENV,
        check=False,
    )


def test_version_has_one_python_source(tmp_path: Path) -> None:
    completed = cli("--version")
    assert completed.returncode == 0
    assert completed.stdout.strip() == f"CredScope {__version__}"
    product_files = [*ROOT.glob("*.py"), *(ROOT / "src").glob("*.py")]
    literal_sources = [
        path for path in product_files
        if f'"{__version__}"' in path.read_text(encoding="utf-8")
    ]
    assert literal_sources == [ROOT / "src" / "version.py"]

    result = ScanResult("empty", [], ScanStats())
    assert result.to_dict()["tool"]["version"] == __version__
    assert create_baseline_data(result).to_dict()["tool"]["version"] == __version__
    page = write_html_report(result, tmp_path / "version.html").read_text(encoding="utf-8")
    assert f"CredScope {__version__}" in page


def test_default_report_paths_are_automatic(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(main, "application_output_dir", lambda: tmp_path / "output")
    assert main.default_output("json") == tmp_path / "output" / "credscope-report.json"
    assert main.default_output("html") == tmp_path / "output" / "credscope-report.html"


def test_rulepack_shortcuts_and_all_are_deduplicated() -> None:
    ai = main.official_rule_paths(["ai"])
    all_packs = main.official_rule_paths(["all", "ai"])
    assert [path.name for path in ai] == ["ai_llm_services.json"]
    assert [path.name for path in all_packs] == [
        "ai_llm_services.json", "devops_registry.json", "web_saas_services.json"
    ]
    assert all(path.is_file() for path in all_packs)


def test_scan_rulepack_ai_and_custom_rules_can_combine(tmp_path: Path) -> None:
    project = tmp_path / "项目 with spaces"
    project.mkdir()
    ai_value = "sk-ant-api03-" + "A1b2C3d4E5f6G7h8J9k0LmNoPqRs"
    custom_value = "COURSESRV_A1B2C3D4E5F6G7H8J9K0"
    (project / "配置.py").write_text(
        f'provider = "{ai_value}"\ncourse_token = "{custom_value}"', encoding="utf-8"
    )
    report = tmp_path / "combined.json"
    completed = cli(
        "scan", project, "--rulepack", "ai", "--rules",
        ROOT / "examples" / "custom_rules.template.json",
        "--report", "json", "--output", report,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert {"anthropic-api-key", "example-service-token"} <= {
        item["rule_id"] for item in payload["findings"]
    }
    combined_output = completed.stdout + report.read_text(encoding="utf-8")
    assert ai_value not in combined_output and custom_value not in combined_output


def test_demo_command_generates_both_reports_and_checks(tmp_path: Path) -> None:
    completed = cli("demo", "--output-dir", tmp_path)
    assert completed.returncode == 0, completed.stderr
    json_path = tmp_path / "demo-report.json"
    html_path = tmp_path / "demo-dashboard.html"
    assert json_path.is_file() and html_path.is_file()
    assert completed.stdout.count("[PASS]") == 6
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert any(item["rule_id"] == "anthropic-api-key" for item in payload["findings"])
    assert "{{" not in html_path.read_text(encoding="utf-8")


def test_package_entrypoint_and_compatibility_launcher(tmp_path: Path) -> None:
    module_version = module_cli("--version")
    wrapper_version = cli("--version")
    assert module_version.returncode == wrapper_version.returncode == 0
    assert module_version.stdout == wrapper_version.stdout == f"CredScope {__version__}\n"

    module_demo = module_cli("demo", "--output-dir", tmp_path)
    assert module_demo.returncode == 0, module_demo.stderr
    assert module_demo.stdout.count("[PASS]") == 6

    launcher = (ROOT / "main.py").read_text(encoding="utf-8")
    assert "from src.main import run" in launcher
    assert "scan_project" not in launcher and "build_parser" not in launcher


def test_source_package_resource_layout() -> None:
    assert resource_paths.resource_root() == ROOT
    assert resource_paths.application_root() == ROOT
    expected = (
        ("config", "rules.json"),
        ("templates", "report.html"),
        ("rulepacks", "ai_llm_services.json"),
        ("examples", "custom_rules.template.json"),
    )
    assert all(resource_paths.resource_path(*parts).is_file() for parts in expected)


def test_missing_command_and_invalid_rulepack_are_friendly() -> None:
    missing = cli()
    assert missing.returncode == 2 and "usage:" in missing.stderr.lower()
    invalid = cli("scan", "demo_project", "--rulepack", "unknown")
    assert invalid.returncode == 2 and "invalid choice" in invalid.stderr.lower()


def test_resource_fallback_finds_bundled_relative_assets(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    resolved = resource_paths.resolve_input_path(
        Path("examples") / "custom_rules.template.json"
    )
    assert resolved == ROOT / "examples" / "custom_rules.template.json"


def test_frozen_paths_separate_resources_from_writable_output(monkeypatch, tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    executable = tmp_path / "release" / "CredScope.exe"
    monkeypatch.setattr(resource_paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(resource_paths.sys, "_MEIPASS", str(bundle), raising=False)
    monkeypatch.setattr(resource_paths.sys, "executable", str(executable))
    assert resource_paths.resource_root() == bundle.resolve()
    assert resource_paths.application_output_dir() == executable.parent.resolve() / "output"


def test_cli_banner_uses_full_release_version() -> None:
    result = ScanResult("empty", [], ScanStats())
    assert render_cli(result).splitlines()[0] == (
        f"CredScope {__version__} - Source Code Credential Security Auditor"
    )
