"""从 JSON 加载、编译并执行格式规则。"""

from __future__ import annotations

from pathlib import Path

from entropy_detector import calculate_entropy
from models import CredentialCandidate, SourceFile
from rule_loader import MAX_MATCH_INPUT, LoadedRule, RuleConfigError, load_builtin_rules


class RuleDetector:
    def __init__(
        self, rules_path: Path | None = None, *, rules: list[LoadedRule] | None = None
    ) -> None:
        if rules is None and rules_path is None:
            raise ValueError("必须提供 rules_path 或已加载的 rules")
        self.rules = rules if rules is not None else load_builtin_rules(rules_path)  # type: ignore[arg-type]

    def detect(self, source: SourceFile) -> list[CredentialCandidate]:
        candidates: list[CredentialCandidate] = []
        for line_number, original_line in enumerate(source.lines, start=1):
            line = original_line[:MAX_MATCH_INPUT]
            lowered = line.lower()
            for rule in self.rules:
                if rule.keywords and not any(word in lowered for word in rule.keywords):
                    continue
                for match in rule.pattern.finditer(line):
                    value = match.group("secret")
                    if not value:
                        continue
                    detectors = {"rule"}
                    evidence = [f"命中规则 {rule.id}（{rule.name}）"]
                    entropy = None
                    if rule.entropy_threshold is not None:
                        entropy = calculate_entropy(value)
                        if entropy >= rule.entropy_threshold:
                            detectors.add("entropy")
                            evidence.append(
                                f"达到规则熵阈值（{entropy:.2f} ≥ {rule.entropy_threshold:.2f}）"
                            )
                    candidates.append(
                        CredentialCandidate(
                            file_path=source.relative_path,
                            line_number=line_number,
                            column=match.start("secret") + 1,
                            secret_type=rule.name,
                            raw_value=value,
                            detectors=detectors,
                            evidence=evidence,
                            entropy=entropy,
                            rule_id=rule.id,
                            severity_base=rule.severity_base,
                            recommendation=rule.recommendation,
                            line_text=original_line,
                        )
                    )
        return candidates
