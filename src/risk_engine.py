"""候选融合、误报过滤与可解释的启发式风险评分。"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from .filters import CandidateFilter, mask_secret
from .models import CredentialCandidate, Finding


MIN_REPORT_SCORE = 20
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def normalize_code_context(line_text: str, raw_value: str) -> str:
    """移除候选值并规范化空白，供安全、抗行号变化的 Fingerprint 使用。"""

    redacted = line_text.replace(raw_value, "<SECRET>")
    return re.sub(r"\s+", " ", redacted.strip()).casefold()


def finding_fingerprint(
    *,
    file_path: str,
    rule_id: str | None,
    secret_type: str,
    detectors: set[str],
    normalized_context: str,
) -> str:
    identity = "\x1f".join(
        (
            file_path.replace("\\", "/").casefold(),
            (rule_id or secret_type).casefold(),
            ",".join(sorted(detectors)),
            normalized_context,
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def severity_for_score(score: int) -> str | None:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return None


class RiskEngine:
    def __init__(self, candidate_filter: CandidateFilter | None = None) -> None:
        self.filter = candidate_filter or CandidateFilter()

    def evaluate(self, candidates: list[CredentialCandidate]) -> list[Finding]:
        """过滤并融合候选。同一行同一原始值只生成一个 Finding。"""

        accepted = [c for c in candidates if self.filter.rejection_reason(c) is None]
        groups: dict[tuple[str, int, str], list[CredentialCandidate]] = defaultdict(list)
        for candidate in accepted:
            groups[(candidate.file_path, candidate.line_number, candidate.raw_value)].append(
                candidate
            )

        findings: list[Finding] = []
        for group in groups.values():
            finding = self._build_finding(group)
            if finding is not None:
                findings.append(finding)
        return sorted(
            findings,
            key=lambda item: (-item.risk_score, item.file_path.lower(), item.line_number),
        )

    def _build_finding(self, group: list[CredentialCandidate]) -> Finding | None:
        detectors = set().union(*(candidate.detectors for candidate in group))
        # 高熵只能作为 supporting evidence，禁止单独形成报告。
        if detectors == {"entropy"}:
            return None

        rule_candidates = [candidate for candidate in group if "rule" in candidate.detectors]
        context_candidates = [candidate for candidate in group if "context" in candidate.detectors]
        entropy_candidates = [candidate for candidate in group if "entropy" in candidate.detectors]
        score = max((candidate.severity_base for candidate in rule_candidates), default=0)
        if context_candidates:
            score += 25  # 敏感变量名
            score += 15  # 明确的直接字符串赋值
        if entropy_candidates:
            score += 15
        raw_value = group[0].raw_value
        if len(raw_value) >= 20:
            score += 5
        path_lower = group[0].file_path.lower().replace("\\", "/")
        if any(
            hint in path_lower
            for hint in (".env", "config", "settings", "credential", "secret")
        ):
            score += 5
        score = min(100, max(0, score))
        severity = severity_for_score(score)
        if severity is None:
            return None

        evidence: list[str] = []
        for candidate in group:
            for item in candidate.evidence:
                if item not in evidence:
                    evidence.append(item)
        entropy_values = [c.entropy for c in group if c.entropy is not None]
        preferred = max(group, key=lambda c: (c.severity_base, "rule" in c.detectors))
        secret_type = preferred.secret_type
        if secret_type == "High Entropy String" and context_candidates:
            secret_type = context_candidates[0].secret_type

        return Finding(
            file_path=group[0].file_path,
            line_number=group[0].line_number,
            column=min((c.column for c in group if c.column is not None), default=None),
            secret_type=secret_type,
            masked_value=mask_secret(raw_value),
            risk_score=score,
            severity=severity,
            detectors=sorted(detectors),
            evidence=evidence,
            entropy=max(entropy_values) if entropy_values else None,
            rule_id=preferred.rule_id,
            recommendation=preferred.recommendation,
            fingerprint=finding_fingerprint(
                file_path=group[0].file_path,
                rule_id=preferred.rule_id,
                secret_type=secret_type,
                detectors=detectors,
                normalized_context=normalize_code_context(
                    group[0].line_text, raw_value
                ),
            ),
        )
