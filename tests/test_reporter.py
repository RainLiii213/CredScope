from pathlib import Path

from src.models import Finding, ScanResult, ScanStats
from src.reporter import render_cli, write_html_report, write_json_report


RAW = "NeverWriteThisRawSecret987654321"


def result() -> ScanResult:
    finding = Finding(
        "app.py", 1, 10, "Generic Secret", "Neve************************21",
        75, "HIGH", ["context", "entropy"], ["敏感字段名：secret"], 4.7,
        None, "改用环境变量。",
    )
    return ScanResult("demo", [finding], ScanStats(files_scanned=1, lines_scanned=1))


def test_json_and_html_reports_do_not_leak_raw_secret(tmp_path: Path) -> None:
    json_path = write_json_report(result(), tmp_path / "nested" / "report.json")
    html_path = write_html_report(result(), tmp_path / "report.html")
    cli = render_cli(result())
    assert json_path.exists() and html_path.exists()
    assert RAW not in json_path.read_text(encoding="utf-8")
    assert RAW not in html_path.read_text(encoding="utf-8")
    assert RAW not in cli
    assert "Neve************************21" in cli
