"""安全 Baseline 的创建、加载、比较与更新。"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import BaselineRecord, Finding, ScanResult
from .version import PRODUCT_NAME, __version__


BASELINE_FORMAT_VERSION = 1


class BaselineError(RuntimeError):
    pass


@dataclass(slots=True)
class BaselineData:
    created_at: str
    updated_at: str
    target_path: str
    findings: list[BaselineRecord]
    format_version: int = BASELINE_FORMAT_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": PRODUCT_NAME, "version": __version__},
            "baseline_format": self.format_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "target_path": self.target_path,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _record_from_finding(finding: Finding) -> BaselineRecord:
    if not finding.fingerprint:
        raise BaselineError("Finding 缺少 fingerprint，无法安全创建 Baseline")
    return BaselineRecord(
        fingerprint=finding.fingerprint,
        file_path=finding.file_path,
        secret_type=finding.secret_type,
        severity=finding.severity,
        risk_score=finding.risk_score,
        detectors=list(finding.detectors),
        rule_id=finding.rule_id,
        masked_value=finding.masked_value,
        last_line_number=finding.line_number,
    )


def create_baseline_data(
    result: ScanResult, *, original: BaselineData | None = None
) -> BaselineData:
    now = datetime.now(timezone.utc).isoformat()
    return BaselineData(
        created_at=original.created_at if original else now,
        updated_at=now,
        target_path=result.target_path,
        findings=[_record_from_finding(finding) for finding in result.findings],
    )


def write_baseline(
    data: BaselineData, path: Path, *, overwrite: bool = False
) -> Path:
    resolved = path.expanduser().resolve()
    if resolved.exists() and not overwrite:
        raise BaselineError(f"Baseline 已存在，请使用 baseline update：{resolved}")
    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(
            json.dumps(data.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        raise BaselineError(f"Baseline 写入失败 {resolved}: {exc}") from exc
    return resolved


def _record_from_dict(data: Any, index: int) -> BaselineRecord:
    if not isinstance(data, dict):
        raise BaselineError(f"Baseline findings[{index}] 必须是 object")
    required = (
        "fingerprint", "file_path", "secret_type", "severity", "risk_score",
        "detectors", "masked_value",
    )
    missing = [name for name in required if name not in data]
    if missing:
        raise BaselineError(
            f"Baseline findings[{index}] 缺少字段：{', '.join(missing)}"
        )
    fingerprint = data["fingerprint"]
    if not isinstance(fingerprint, str) or len(fingerprint) != 64:
        raise BaselineError(f"Baseline findings[{index}] fingerprint 无效")
    detectors = data["detectors"]
    if not isinstance(detectors, list) or not all(
        isinstance(item, str) for item in detectors
    ):
        raise BaselineError(f"Baseline findings[{index}] detectors 无效")
    try:
        return BaselineRecord(
            fingerprint=fingerprint,
            file_path=str(data["file_path"]),
            secret_type=str(data["secret_type"]),
            severity=str(data["severity"]),
            risk_score=int(data["risk_score"]),
            detectors=list(detectors),
            rule_id=str(data["rule_id"]) if data.get("rule_id") is not None else None,
            masked_value=str(data["masked_value"]),
            last_line_number=(
                int(data["last_line_number"])
                if data.get("last_line_number") is not None
                else None
            ),
        )
    except (TypeError, ValueError) as exc:
        raise BaselineError(f"Baseline findings[{index}] 字段类型无效") from exc


def load_baseline(path: Path) -> BaselineData:
    resolved = path.expanduser().resolve()
    try:
        payload: Any = json.loads(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BaselineError(f"无法读取 Baseline {resolved}: {exc}") from exc
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Baseline JSON 损坏 {resolved}: {exc}") from exc
    if not isinstance(payload, dict):
        raise BaselineError("Baseline 根结构必须是 object")
    if payload.get("baseline_format") != BASELINE_FORMAT_VERSION:
        raise BaselineError(
            f"不支持的 Baseline 格式版本：{payload.get('baseline_format')!r}"
        )
    findings = payload.get("findings")
    if not isinstance(findings, list):
        raise BaselineError("Baseline findings 必须是数组")
    return BaselineData(
        created_at=str(payload.get("created_at", "")),
        updated_at=str(payload.get("updated_at", "")),
        target_path=str(payload.get("target_path", "")),
        findings=[_record_from_dict(item, index) for index, item in enumerate(findings)],
    )


def apply_baseline(
    result: ScanResult, baseline: BaselineData, baseline_path: Path
) -> ScanResult:
    previous = {record.fingerprint: record for record in baseline.findings}
    current_ids: set[str] = set()
    for finding in result.findings:
        current_ids.add(finding.fingerprint)
        finding.status = "EXISTING" if finding.fingerprint in previous else "NEW"
    result.resolved_findings = [
        record for fingerprint, record in previous.items() if fingerprint not in current_ids
    ]
    result.baseline_path = str(baseline_path.expanduser().resolve())
    return result
