"""CLI、JSON 与静态 HTML 报告。"""

from __future__ import annotations

import html
import json
from pathlib import Path

from .audit_statistics import build_statistics
from .models import Finding, ScanResult
from .resource_paths import resource_path
from .risk_engine import SEVERITY_ORDER
from .version import __version__


class ReportWriteError(RuntimeError):
    pass


def filter_by_min_level(result: ScanResult, min_level: str) -> ScanResult:
    threshold = SEVERITY_ORDER[min_level.upper()]
    selected = [
        item for item in result.findings if SEVERITY_ORDER[item.severity] >= threshold
    ]
    resolved = [
        item for item in result.resolved_findings
        if SEVERITY_ORDER.get(item.severity, 0) >= threshold
    ]
    return ScanResult(
        result.target_path,
        selected,
        result.stats,
        result.scanned_at,
        resolved_findings=resolved,
        baseline_path=result.baseline_path,
    )


def render_cli(result: ScanResult) -> str:
    """生成适合普通终端、可重定向且不泄露原值的文本报告。"""

    counts = result.severity_counts
    statistics = build_statistics(result)
    lines = [
        f"CredScope {__version__} - Source Code Credential Security Auditor",
        f"扫描目标: {result.target_path}",
        "进度: 完成 (100%)",
        (
            f"Files scanned: {result.stats.files_scanned} | "
            f"Files skipped: {result.stats.files_skipped} | "
            f"Lines scanned: {result.stats.lines_scanned} | "
            f"Duration: {result.stats.duration_seconds:.3f}s"
        ),
        (
            f"Findings: {len(result.findings)} | CRITICAL {counts['CRITICAL']} | "
            f"HIGH {counts['HIGH']} | MEDIUM {counts['MEDIUM']} | LOW {counts['LOW']}"
        ),
        "提示: Risk Score 是启发式风险分，不是 Secret 为真的概率。",
    ]
    top_types = sorted(
        statistics["credential_types"].items(), key=lambda item: (-item[1], item[0])
    )[:3]
    top_files = statistics["top_risk_files"][:3]
    if top_types:
        lines.append(
            "Top Risk Types: " + ", ".join(f"{name} {count}" for name, count in top_types)
        )
    if top_files:
        lines.append(
            "Top Risk Files: "
            + ", ".join(
                f"{item['file_path']} {item['finding_count']}" for item in top_files
            )
        )
    if statistics["baseline"] is not None:
        delta = statistics["baseline"]
        lines.append(
            f"Baseline Delta: NEW {delta['new']} | EXISTING {delta['existing']} | "
            f"RESOLVED {delta['resolved']}"
        )
    if not result.findings:
        lines.append("未发现达到报告阈值的候选凭据。")
        if result.resolved_findings:
            lines.append("Resolved Findings")
            for item in result.resolved_findings:
                lines.append(
                    f"RESOLVED | {item.severity} | {item.file_path} | "
                    f"{item.secret_type} | {item.masked_value}"
                )
        return "\n".join(lines)
    lines.extend(
        [
            "-" * 112,
            "Severity | Score | File:Line | Type | Masked value",
            "-" * 112,
        ]
    )
    for finding in result.findings:
        lines.extend(
            [
                f"{finding.status + ' ' if finding.status else ''}{finding.severity} | "
                f"{finding.risk_score:3d} | "
                f"{finding.file_path}:{finding.line_number} | "
                f"{finding.secret_type} | {finding.masked_value}",
                f"  Detectors: {', '.join(finding.detectors)}",
                f"  Evidence: {'；'.join(finding.evidence)}",
                f"  Recommendation: {finding.recommendation}",
            ]
        )
    if result.resolved_findings:
        lines.append("-" * 112)
        lines.append("Resolved Findings")
        for item in result.resolved_findings:
            lines.append(
                f"RESOLVED | {item.severity} | {item.file_path} | {item.secret_type} | "
                f"{item.masked_value}"
            )
    return "\n".join(lines)


def write_json_report(result: ScanResult, output_path: Path) -> Path:
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except OSError as exc:
        raise ReportWriteError(f"JSON 报告写入失败 {output_path}: {exc}") from exc
    return output_path


def _finding_html(finding: Finding) -> str:
    evidence = "".join(f"<li>{html.escape(item)}</li>" for item in finding.evidence)
    return f"""
      <article class="finding {finding.severity.lower()}">
        <div class="finding-head"><span class="badge">{finding.status or finding.severity}</span>
          {f'<span class="severity-label">{finding.severity}</span>' if finding.status else ''}
          <strong>{html.escape(finding.secret_type)}</strong><span class="score">{finding.risk_score}/100</span></div>
        <div class="location">{html.escape(finding.file_path)}:{finding.line_number}</div>
        <dl><dt>脱敏值</dt><dd><code>{html.escape(finding.masked_value)}</code></dd>
          <dt>检测器</dt><dd>{html.escape(', '.join(finding.detectors))}</dd>
          <dt>依据</dt><dd><ul>{evidence}</ul></dd>
          <dt>建议</dt><dd>{html.escape(finding.recommendation)}</dd></dl>
      </article>"""


def _bar_chart(values: dict[str, int], empty_text: str = "No data") -> str:
    if not values or max(values.values(), default=0) == 0:
        return f'<p class="empty-chart">{html.escape(empty_text)}</p>'
    maximum = max(values.values())
    rows = []
    for label, value in values.items():
        width = 0 if maximum == 0 else round(value / maximum * 100)
        rows.append(
            '<div class="bar-row">'
            f'<span class="bar-label">{html.escape(str(label))}</span>'
            f'<span class="bar-track"><i style="width:{width}%"></i></span>'
            f'<b>{value}</b></div>'
        )
    return "".join(rows)


def _top_files_chart(rows: list[dict[str, object]]) -> str:
    values = {
        f"{row['file_path']} (max {row['max_score']})": int(row["finding_count"])
        for row in rows
    }
    return _bar_chart(values)


def _resolved_html(result: ScanResult) -> str:
    if not result.resolved_findings:
        return ""
    rows = "".join(
        f'<li><strong>{html.escape(item.severity)}</strong> '
        f'{html.escape(item.file_path)} — {html.escape(item.secret_type)} — '
        f'<code>{html.escape(item.masked_value)}</code></li>'
        for item in result.resolved_findings
    )
    return f'<section class="resolved"><h2>Resolved Findings</h2><ul>{rows}</ul></section>'


def write_html_report(
    result: ScanResult, output_path: Path, template_path: Path | None = None
) -> Path:
    template = template_path or resource_path("templates", "report.html")
    try:
        source = template.read_text(encoding="utf-8")
        counts = result.severity_counts
        statistics = build_statistics(result)
        baseline = statistics["baseline"]
        baseline_section = ""
        if baseline is not None:
            baseline_section = (
                '<section class="panel baseline"><h2>Baseline Delta</h2>'
                '<div class="delta-grid">'
                f'<div><b>{baseline["new"]}</b><span>New</span></div>'
                f'<div><b>{baseline["existing"]}</b><span>Existing</span></div>'
                f'<div><b>{baseline["resolved"]}</b><span>Resolved</span></div>'
                '</div></section>'
            )
        replacements = {
            "{{VERSION}}": __version__,
            "{{TARGET}}": html.escape(result.target_path),
            "{{SCANNED_AT}}": html.escape(result.scanned_at),
            "{{FILES_SCANNED}}": str(result.stats.files_scanned),
            "{{FILES_SKIPPED}}": str(result.stats.files_skipped),
            "{{LINES_SCANNED}}": str(result.stats.lines_scanned),
            "{{DURATION}}": f"{result.stats.duration_seconds:.3f}s",
            "{{SCAN_SPEED}}": (
                f"{statistics['scan_speed_lines_per_second']:.0f} lines/s"
                if statistics["scan_speed_lines_per_second"] is not None else "n/a"
            ),
            "{{TOTAL}}": str(len(result.findings)),
            "{{CRITICAL}}": str(counts["CRITICAL"]),
            "{{HIGH}}": str(counts["HIGH"]),
            "{{MEDIUM}}": str(counts["MEDIUM"]),
            "{{LOW}}": str(counts["LOW"]),
            "{{FINDINGS}}": "\n".join(_finding_html(f) for f in result.findings)
            or '<p class="empty">未发现达到报告阈值的候选凭据。</p>',
            "{{SEVERITY_CHART}}": _bar_chart(statistics["severity_distribution"]),
            "{{TYPE_CHART}}": _bar_chart(statistics["credential_types"]),
            "{{DETECTOR_CHART}}": _bar_chart(statistics["detector_contribution"]),
            "{{TOP_FILES_CHART}}": _top_files_chart(statistics["top_risk_files"]),
            "{{RISK_CHART}}": _bar_chart(statistics["risk_score_distribution"]),
            "{{BASELINE_SECTION}}": baseline_section,
            "{{RESOLVED_FINDINGS}}": _resolved_html(result),
        }
        for marker, value in replacements.items():
            source = source.replace(marker, value)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        normalized = "\n".join(line.rstrip() for line in source.splitlines()) + "\n"
        output_path.write_text(normalized, encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReportWriteError(f"HTML 报告写入失败 {output_path}: {exc}") from exc
    return output_path
