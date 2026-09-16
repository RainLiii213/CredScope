"""从 ScanResult 派生 Security Audit Summary，不依赖外部数据框架。"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .models import Finding, ScanResult


def credential_category(finding: Finding) -> str:
    name = finding.secret_type.casefold()
    if "private key" in name:
        return "Private Key"
    if "database" in name:
        return "Database Credential"
    if "password" in name or "passwd" in name:
        return "Password"
    if "jwt" in name or "json web token" in name:
        return "JWT"
    if any(term in name for term in ("api", "token", "authorization", "github", "slack", "aws")):
        return "API Credential"
    return "Generic Secret"


def _top_risk_files(findings: list[Finding], limit: int = 5) -> list[dict[str, Any]]:
    grouped: dict[str, list[int]] = defaultdict(list)
    for finding in findings:
        grouped[finding.file_path].append(finding.risk_score)
    rows = [
        {
            "file_path": path,
            "finding_count": len(scores),
            "max_score": max(scores),
            "total_score": sum(scores),
        }
        for path, scores in grouped.items()
    ]
    return sorted(
        rows,
        key=lambda row: (
            -row["finding_count"], -row["max_score"], -row["total_score"],
            row["file_path"].casefold(),
        ),
    )[:limit]


def build_statistics(result: ScanResult) -> dict[str, Any]:
    severity = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    credential_types: Counter[str] = Counter()
    detectors = {"rule": 0, "context": 0, "entropy": 0}
    score_distribution = {"80-100": 0, "60-79": 0, "40-59": 0, "20-39": 0}
    for finding in result.findings:
        severity[finding.severity] += 1
        credential_types[credential_category(finding)] += 1
        for detector in finding.detectors:
            if detector in detectors:
                detectors[detector] += 1
        if finding.risk_score >= 80:
            score_distribution["80-100"] += 1
        elif finding.risk_score >= 60:
            score_distribution["60-79"] += 1
        elif finding.risk_score >= 40:
            score_distribution["40-59"] += 1
        else:
            score_distribution["20-39"] += 1
    duration = result.stats.duration_seconds
    baseline = None
    if result.baseline_path is not None:
        baseline = {
            "new": sum(finding.status == "NEW" for finding in result.findings),
            "existing": sum(
                finding.status == "EXISTING" for finding in result.findings
            ),
            "resolved": len(result.resolved_findings),
        }
    return {
        "scan_speed_lines_per_second": (
            round(result.stats.lines_scanned / duration, 2) if duration > 0 else None
        ),
        "severity_distribution": severity,
        "credential_types": dict(sorted(credential_types.items())),
        "detector_contribution": detectors,
        "top_risk_files": _top_risk_files(result.findings),
        "risk_score_distribution": score_distribution,
        "baseline": baseline,
    }
