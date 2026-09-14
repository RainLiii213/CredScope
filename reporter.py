"""CLI、JSON 与静态 HTML 报告。"""

from __future__ import annotations

import html
import json
from pathlib import Path

from models import Finding, ScanResult
from risk_engine import SEVERITY_ORDER


class ReportWriteError(RuntimeError):
    pass


def filter_by_min_level(result: ScanResult, min_level: str) -> ScanResult:
    threshold = SEVERITY_ORDER[min_level.upper()]
    selected = [
        item for item in result.findings if SEVERITY_ORDER[item.severity] >= threshold
    ]
    return ScanResult(result.target_path, selected, result.stats, result.scanned_at)


def render_cli(result: ScanResult) -> str:
    """生成适合普通终端、可重定向且不泄露原值的文本报告。"""

    counts = result.severity_counts
    lines = [
        "CredScope v1.0 - 源代码敏感凭据审计",
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
    if not result.findings:
        lines.append("未发现达到报告阈值的候选凭据。")
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
                f"{finding.severity} | {finding.risk_score:3d} | "
                f"{finding.file_path}:{finding.line_number} | "
                f"{finding.secret_type} | {finding.masked_value}",
                f"  Detectors: {', '.join(finding.detectors)}",
                f"  Evidence: {'；'.join(finding.evidence)}",
                f"  Recommendation: {finding.recommendation}",
            ]
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
        <div class="finding-head"><span class="badge">{finding.severity}</span>
          <strong>{html.escape(finding.secret_type)}</strong><span class="score">{finding.risk_score}/100</span></div>
        <div class="location">{html.escape(finding.file_path)}:{finding.line_number}</div>
        <dl><dt>脱敏值</dt><dd><code>{html.escape(finding.masked_value)}</code></dd>
          <dt>检测器</dt><dd>{html.escape(', '.join(finding.detectors))}</dd>
          <dt>依据</dt><dd><ul>{evidence}</ul></dd>
          <dt>建议</dt><dd>{html.escape(finding.recommendation)}</dd></dl>
      </article>"""


def write_html_report(
    result: ScanResult, output_path: Path, template_path: Path | None = None
) -> Path:
    template = template_path or Path(__file__).resolve().parent / "templates" / "report.html"
    try:
        source = template.read_text(encoding="utf-8")
        counts = result.severity_counts
        replacements = {
            "{{TARGET}}": html.escape(result.target_path),
            "{{SCANNED_AT}}": html.escape(result.scanned_at),
            "{{FILES_SCANNED}}": str(result.stats.files_scanned),
            "{{FILES_SKIPPED}}": str(result.stats.files_skipped),
            "{{LINES_SCANNED}}": str(result.stats.lines_scanned),
            "{{DURATION}}": f"{result.stats.duration_seconds:.3f}s",
            "{{TOTAL}}": str(len(result.findings)),
            "{{CRITICAL}}": str(counts["CRITICAL"]),
            "{{HIGH}}": str(counts["HIGH"]),
            "{{MEDIUM}}": str(counts["MEDIUM"]),
            "{{LOW}}": str(counts["LOW"]),
            "{{FINDINGS}}": "\n".join(_finding_html(f) for f in result.findings)
            or '<p class="empty">未发现达到报告阈值的候选凭据。</p>',
        }
        for marker, value in replacements.items():
            source = source.replace(marker, value)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(source, encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ReportWriteError(f"HTML 报告写入失败 {output_path}: {exc}") from exc
    return output_path
