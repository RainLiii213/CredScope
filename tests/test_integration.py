from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from src.reporter import render_cli, write_html_report, write_json_report
from src.scanner import ScanPathError, scan_project


ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo_project"
RAW_VALUES = [
    "github_pat_A1B2C3D4E5F6G7H8J9K0LMNOPQ",
    "CourseOnly-Pass-2468",
    "Q7vL2mN9xR4pT8kW3sY6dF1hJ5cB0zAa",
    "postgresql://course_user:FakeDbPass2468@localhost:5432/course_demo",
]


def test_demo_end_to_end_and_reports(tmp_path: Path) -> None:
    result = scan_project(DEMO)
    types = {finding.secret_type for finding in result.findings}
    assert result.stats.files_scanned >= 4
    assert "GitHub Token" in types
    assert "Hardcoded Password" in types
    assert "Database Connection String" in types
    assert len(result.findings) == len(
        {(f.file_path, f.line_number, f.masked_value) for f in result.findings}
    )
    # Demo 中安全 env、placeholder、UUID 所在行不得产生 Finding。
    app_lines = {f.line_number for f in result.findings if f.file_path == "app.py"}
    assert 8 not in app_lines
    assert 9 not in app_lines
    assert 10 not in app_lines

    json_path = write_json_report(result, tmp_path / "report.json")
    html_path = write_html_report(result, tmp_path / "report.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["summary"]["findings"] == len(result.findings)
    combined = json_path.read_text(encoding="utf-8") + html_path.read_text(encoding="utf-8") + render_cli(result)
    for raw in RAW_VALUES:
        assert raw not in combined


def test_chinese_windows_style_path(tmp_path: Path) -> None:
    chinese = tmp_path / "中文项目" / "配置"
    chinese.mkdir(parents=True)
    (chinese / "密钥.py").write_text('password = "课程测试密码2468"', encoding="utf-8")
    result = scan_project(tmp_path / "中文项目")
    assert result.stats.files_scanned == 1
    assert result.findings[0].file_path == "配置/密钥.py"


def test_cli_scan_does_not_crash(tmp_path: Path) -> None:
    output = tmp_path / "cli-report.json"
    completed = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "scan", str(DEMO),
         "--report", "json", "--output", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert output.exists()
    for raw in RAW_VALUES:
        assert raw not in completed.stdout


def test_invalid_scan_paths_are_friendly(tmp_path: Path) -> None:
    try:
        scan_project(tmp_path / "missing")
    except ScanPathError as exc:
        assert "不存在" in str(exc)
    else:
        raise AssertionError("不存在的目录应报错")
    file_path = tmp_path / "one.py"
    file_path.write_text("x = 1", encoding="utf-8")
    try:
        scan_project(file_path)
    except ScanPathError as exc:
        assert "必须是目录" in str(exc)
    else:
        raise AssertionError("文件目标应报错")


def test_dotenv_empty_directory_and_binary_handling(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    empty_result = scan_project(empty)
    assert empty_result.stats.files_scanned == 0
    assert empty_result.findings == []

    project = tmp_path / "mixed"
    project.mkdir()
    (project / ".env").write_text('password="FakeCoursePass99"', encoding="utf-8")
    (project / "image.png").write_bytes(b"\x89PNG\x00fake")
    result = scan_project(project)
    assert result.stats.files_scanned == 1
    assert result.stats.files_skipped == 1
    assert result.findings[0].file_path == ".env"
