"""v1.1 CLI 端到端测试；全部 Credential fixture 都是无效假数据。"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


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


def test_rules_validate_and_list_commands(tmp_path: Path) -> None:
    valid = cli("rules", "validate", ROOT / "examples" / "custom_rules.template.json")
    assert valid.returncode == 0, valid.stderr
    assert "Valid:       1" in valid.stdout
    listed = cli("rules", "list", "--rules", ROOT / "rulepacks" / "ai_llm_services.json")
    assert listed.returncode == 0, listed.stderr
    assert "github-token" in listed.stdout
    assert "anthropic-api-key" in listed.stdout

    broken = tmp_path / "broken.json"
    broken.write_text("{bad", encoding="utf-8")
    invalid = cli("rules", "validate", broken)
    assert invalid.returncode == 2
    assert "Invalid:     1" in invalid.stdout


def test_scan_with_custom_rules_keeps_builtins(tmp_path: Path) -> None:
    project = tmp_path / "custom"
    project.mkdir()
    fake_custom = "COURSESRV_A1B2C3D4E5F6G7H8J9K0"
    fake_builtin = "CoursePassword2468"
    (project / "app.py").write_text(
        f'course_token = "{fake_custom}"\npassword = "{fake_builtin}"',
        encoding="utf-8",
    )
    output = tmp_path / "custom.json"
    completed = cli(
        "scan", project, "--rules", ROOT / "examples" / "custom_rules.template.json",
        "--report", "json", "--output", output,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    types = {item["secret_type"] for item in payload["findings"]}
    assert "Example Service Token" in types
    assert "Hardcoded Password" in types
    assert fake_custom not in completed.stdout + output.read_text(encoding="utf-8")


def test_baseline_cli_create_compare_and_update(tmp_path: Path) -> None:
    project = tmp_path / "中文项目"
    project.mkdir()
    raw_old = "BaselineCliPassword2468"
    raw_new = "BASELINECLIKEY_A1B2C3D4E5F6"
    source = project / "配置.py"
    source.write_text(f'password = "{raw_old}"', encoding="utf-8")
    baseline = tmp_path / ".credscope-baseline.json"
    created = cli("baseline", "create", project, "--output", baseline)
    assert created.returncode == 0, created.stderr
    assert baseline.exists() and raw_old not in baseline.read_text(encoding="utf-8")

    source.write_text(
        f'# shifted\n\npassword = "{raw_old}"\napi_key = "{raw_new}"',
        encoding="utf-8",
    )
    report = tmp_path / "delta.json"
    compared = cli(
        "scan", project, "--baseline", baseline,
        "--report", "json", "--output", report,
    )
    assert compared.returncode == 0, compared.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["statistics"]["baseline"] == {
        "new": 1, "existing": 1, "resolved": 0,
    }
    assert "Baseline Delta: NEW 1 | EXISTING 1 | RESOLVED 0" in compared.stdout
    assert raw_old not in compared.stdout + report.read_text(encoding="utf-8")
    assert raw_new not in compared.stdout + report.read_text(encoding="utf-8")

    updated = cli("baseline", "update", project, "--file", baseline)
    assert updated.returncode == 0, updated.stderr
    assert len(json.loads(baseline.read_text(encoding="utf-8"))["findings"]) == 2
