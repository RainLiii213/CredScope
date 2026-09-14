"""CredScope 模块之间共享的数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class SourceFile:
    """一个已被安全读取、可供检测器处理的文本文件。"""

    path: Path
    relative_path: str
    content: str
    size: int

    @property
    def lines(self) -> list[str]:
        return self.content.splitlines()


@dataclass(slots=True)
class CredentialCandidate:
    """检测器产生的内部候选；raw_value 永远不得进入报告或日志。"""

    file_path: str
    line_number: int
    column: int | None
    secret_type: str
    raw_value: str = field(repr=False)
    detectors: set[str] = field(default_factory=set)
    evidence: list[str] = field(default_factory=list)
    entropy: float | None = None
    rule_id: str | None = None
    severity_base: int = 0
    recommendation: str = "将凭据移出源代码，改用环境变量或安全的密钥管理服务。"
    line_text: str = field(default="", repr=False)


@dataclass(slots=True)
class Finding:
    """可安全展示和持久化的审计发现，不包含原始凭据。"""

    file_path: str
    line_number: int
    column: int | None
    secret_type: str
    masked_value: str
    risk_score: int
    severity: str
    detectors: list[str]
    evidence: list[str]
    entropy: float | None
    rule_id: str | None
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "secret_type": self.secret_type,
            "masked_value": self.masked_value,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "detectors": self.detectors,
            "evidence": self.evidence,
            "entropy": self.entropy,
            "rule_id": self.rule_id,
            "recommendation": self.recommendation,
        }


@dataclass(slots=True)
class ScanStats:
    files_discovered: int = 0
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    bytes_scanned: int = 0
    duration_seconds: float = 0.0
    skip_reasons: dict[str, int] = field(default_factory=dict)

    def skipped(self, reason: str) -> None:
        self.files_skipped += 1
        self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_scanned": self.lines_scanned,
            "bytes_scanned": self.bytes_scanned,
            "duration_seconds": round(self.duration_seconds, 4),
            "skip_reasons": dict(self.skip_reasons),
        }


@dataclass(slots=True)
class ScanResult:
    target_path: str
    findings: list[Finding]
    stats: ScanStats
    scanned_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "CredScope", "version": "1.0.0"},
            "target_path": self.target_path,
            "scanned_at": self.scanned_at,
            "summary": {
                "findings": len(self.findings),
                "severity_counts": self.severity_counts,
            },
            "stats": self.stats.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
