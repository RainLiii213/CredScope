"""从 JSON 加载、编译并执行格式规则。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from models import CredentialCandidate, SourceFile


class RuleConfigError(RuntimeError):
    pass


@dataclass(slots=True)
class CompiledRule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity_base: int
    keywords: list[str]
    recommendation: str


class RuleDetector:
    def __init__(self, rules_path: Path) -> None:
        self.rules = self._load_rules(rules_path)

    @staticmethod
    def _load_rules(path: Path) -> list[CompiledRule]:
        try:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise RuleConfigError(f"无法加载规则文件 {path}: {exc}") from exc
        rules_data = payload.get("rules", []) if isinstance(payload, dict) else []
        if not rules_data:
            raise RuleConfigError("rules.json 不包含任何规则")
        compiled: list[CompiledRule] = []
        for index, data in enumerate(rules_data, start=1):
            try:
                pattern = re.compile(data["regex"])
                if "secret" not in pattern.groupindex:
                    raise ValueError("regex 必须包含名为 secret 的捕获组")
                compiled.append(
                    CompiledRule(
                        id=str(data["id"]),
                        name=str(data["name"]),
                        pattern=pattern,
                        severity_base=int(data["severity_base"]),
                        keywords=[str(k).lower() for k in data.get("keywords", [])],
                        recommendation=str(data["recommendation"]),
                    )
                )
            except (KeyError, TypeError, ValueError, re.error) as exc:
                raise RuleConfigError(f"第 {index} 条规则无效: {exc}") from exc
        return compiled

    def detect(self, source: SourceFile) -> list[CredentialCandidate]:
        candidates: list[CredentialCandidate] = []
        for line_number, line in enumerate(source.lines, start=1):
            lowered = line.lower()
            for rule in self.rules:
                if rule.keywords and not any(word in lowered for word in rule.keywords):
                    continue
                for match in rule.pattern.finditer(line):
                    value = match.group("secret")
                    candidates.append(
                        CredentialCandidate(
                            file_path=source.relative_path,
                            line_number=line_number,
                            column=match.start("secret") + 1,
                            secret_type=rule.name,
                            raw_value=value,
                            detectors={"rule"},
                            evidence=[f"命中规则 {rule.id}（{rule.name}）"],
                            rule_id=rule.id,
                            severity_base=rule.severity_base,
                            recommendation=rule.recommendation,
                            line_text=line,
                        )
                    )
        return candidates
