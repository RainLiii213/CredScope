from __future__ import annotations

import json
from pathlib import Path

from src.audit_statistics import build_statistics
from src.models import BaselineRecord, Finding, ScanResult, ScanStats
from src.reporter import render_cli, write_html_report, write_json_report


RAW = "StatisticsRawSecretMustNeverAppear123"


def finding(
    file_path: str,
    secret_type: str,
    score: int,
    severity: str,
    detectors: list[str],
    *,
    status: str | None = None,
) -> Finding:
    return Finding(
        file_path, 1, 1, secret_type, "Stat****************23", score, severity,
        detectors, ["safe evidence"], 4.5 if "entropy" in detectors else None,
        "test-rule", "Rotate it.", "a" * 64, status,
    )


def sample_result() -> ScanResult:
    return ScanResult(
        "demo",
        [
            finding("config.py", "Generic API Key", 100, "CRITICAL", ["rule", "context", "entropy"]),
            finding("config.py", "Hardcoded Password", 70, "HIGH", ["context"]),
            finding("settings.yaml", "Database Connection String", 50, "MEDIUM", ["rule"]),
            finding("low.py", "Generic Secret", 20, "LOW", ["context"]),
        ],
        ScanStats(files_scanned=3, lines_scanned=200, duration_seconds=2.0),
    )


def test_all_distributions_and_scan_speed() -> None:
    stats = build_statistics(sample_result())
    assert stats["severity_distribution"] == {
        "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1,
    }
    assert stats["credential_types"] == {
        "API Credential": 1, "Database Credential": 1,
        "Generic Secret": 1, "Password": 1,
    }
    assert stats["detector_contribution"] == {"rule": 2, "context": 3, "entropy": 1}
    assert stats["risk_score_distribution"] == {
        "80-100": 1, "60-79": 1, "40-59": 1, "20-39": 1,
    }
    assert stats["scan_speed_lines_per_second"] == 100.0


def test_top_risk_files_order() -> None:
    rows = build_statistics(sample_result())["top_risk_files"]
    assert rows[0]["file_path"] == "config.py"
    assert rows[0]["finding_count"] == 2
    assert rows[0]["max_score"] == 100


def test_empty_and_single_finding_statistics() -> None:
    empty = ScanResult("empty", [], ScanStats())
    stats = build_statistics(empty)
    assert sum(stats["severity_distribution"].values()) == 0
    assert stats["top_risk_files"] == []
    assert stats["baseline"] is None
    single = ScanResult(
        "one", [finding("one.py", "Private Key", 80, "CRITICAL", ["rule"])],
        ScanStats(),
    )
    assert build_statistics(single)["credential_types"] == {"Private Key": 1}


def test_baseline_delta() -> None:
    result = sample_result()
    result.baseline_path = "baseline.json"
    result.findings[0].status = "NEW"
    for item in result.findings[1:]:
        item.status = "EXISTING"
    result.resolved_findings = [
        BaselineRecord("b" * 64, "old.py", "Password", "HIGH", 60, ["context"], None, "O***d", 4)
    ]
    assert build_statistics(result)["baseline"] == {"new": 1, "existing": 3, "resolved": 1}


def test_json_statistics_and_html_dashboard(tmp_path: Path) -> None:
    result = sample_result()
    json_path = write_json_report(result, tmp_path / "report.json")
    html_path = write_html_report(result, tmp_path / "report.html")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    page = html_path.read_text(encoding="utf-8")
    assert "statistics" in payload
    assert payload["statistics"]["top_risk_files"][0]["file_path"] == "config.py"
    for title in (
        "Security Audit Dashboard", "Severity Distribution",
        "Credential Type Distribution", "Detector Contribution",
        "Top Risk Files", "Risk Score Distribution",
    ):
        assert title in page
    assert "{{" not in page
    assert RAW not in page + json_path.read_text(encoding="utf-8") + render_cli(result)


def test_baseline_report_status_and_resolved_section(tmp_path: Path) -> None:
    result = sample_result()
    result.baseline_path = "baseline.json"
    result.findings[0].status = "NEW"
    result.findings[1].status = "EXISTING"
    result.resolved_findings = [
        BaselineRecord("c" * 64, "旧配置.py", "Password", "HIGH", 65, ["context"], None, "O***d", 9)
    ]
    page_path = write_html_report(result, tmp_path / "baseline.html")
    json_path = write_json_report(result, tmp_path / "baseline.json")
    page = page_path.read_text(encoding="utf-8")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    cli = render_cli(result)
    assert "Baseline Delta" in page and "Resolved Findings" in page
    assert "NEW" in page and "EXISTING" in page
    assert payload["statistics"]["baseline"]["resolved"] == 1
    assert payload["findings"][0]["status"] == "NEW"
    assert "RESOLVED" in cli
