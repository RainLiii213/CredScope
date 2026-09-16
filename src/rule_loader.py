"""声明式规则包的加载、校验与安全编译。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_RULES_PER_PACK = 100
MAX_PATTERN_LENGTH = 500
MAX_KEYWORDS = 20
MAX_KEYWORD_LENGTH = 64
MAX_MATCH_INPUT = 8192
RULE_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
MATCH_ALL_PATTERNS = {".*", ".+", "^.*$", "^.+$", "[\\s\\S]*", "[\\s\\S]+"}
NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:\\.|[^)])*(?:\*|\+|\{\d*,?\d*\})(?:\\.|[^)])*\)\s*(?:\*|\+|\{)"
)


class RuleConfigError(RuntimeError):
    """内置规则无法加载时抛出的致命配置错误。"""


@dataclass(slots=True)
class LoadedRule:
    id: str
    name: str
    description: str
    pattern_text: str
    pattern: re.Pattern[str]
    severity_base: int
    keywords: list[str]
    entropy_threshold: float | None
    recommendation: str
    source: str


@dataclass(slots=True)
class RuleIssue:
    level: str
    rule_id: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"level": self.level, "rule_id": self.rule_id, "reason": self.reason}


@dataclass(slots=True)
class RuleValidationReport:
    path: str
    pack_name: str = "Unknown Rule Pack"
    version: str = ""
    rules_found: int = 0
    rules: list[LoadedRule] = field(default_factory=list)
    issues: list[RuleIssue] = field(default_factory=list)

    @property
    def valid_count(self) -> int:
        return len(self.rules)

    @property
    def warning_count(self) -> int:
        return sum(issue.level == "WARNING" for issue in self.issues)

    @property
    def invalid_count(self) -> int:
        return sum(issue.level == "INVALID" for issue in self.issues)

    @property
    def is_valid(self) -> bool:
        return self.invalid_count == 0


def _issue(report: RuleValidationReport, rule_id: str, reason: str) -> None:
    report.issues.append(RuleIssue("INVALID", rule_id, reason))


def _compile_secret_pattern(pattern_text: str) -> re.Pattern[str]:
    preliminary = re.compile(pattern_text)
    if "secret" in preliminary.groupindex:
        return preliminary
    return re.compile(f"(?P<secret>{pattern_text})")


def _validate_rule(
    data: Any,
    index: int,
    source: str,
    known_ids: set[str],
    report: RuleValidationReport,
) -> LoadedRule | None:
    label = f"rule[{index}]"
    if not isinstance(data, dict):
        _issue(report, label, "规则必须是 JSON object")
        return None
    rule_id = data.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        _issue(report, label, "缺少非空字符串字段 id")
        return None
    rule_id = rule_id.strip()
    label = rule_id
    if not RULE_ID_RE.fullmatch(rule_id):
        _issue(report, label, "id 只能使用小写字母、数字和单个连字符分段")
        return None
    if rule_id in known_ids:
        _issue(report, label, f"Rule ID conflict：{rule_id} 已由其他规则源定义")
        return None

    name = data.get("name")
    if not isinstance(name, str) or not name.strip() or len(name.strip()) > 120:
        _issue(report, label, "name 必须是 1–120 字符的非空字符串")
        return None
    pattern_text = data.get("pattern", data.get("regex"))
    if not isinstance(pattern_text, str):
        _issue(report, label, "缺少字符串字段 pattern")
        return None
    pattern_text = pattern_text.strip()
    if not pattern_text:
        _issue(report, label, "pattern 不能为空")
        return None
    if len(pattern_text) > MAX_PATTERN_LENGTH:
        _issue(report, label, f"pattern 超过 {MAX_PATTERN_LENGTH} 字符安全上限")
        return None
    normalized = re.sub(r"\s+", "", pattern_text)
    if normalized in MATCH_ALL_PATTERNS:
        _issue(report, label, "pattern 属于 match-all 表达式，已禁用")
        return None
    if NESTED_QUANTIFIER_RE.search(pattern_text):
        _issue(report, label, "pattern 包含可疑的嵌套无限量词，存在 ReDoS 风险")
        return None
    try:
        pattern = _compile_secret_pattern(pattern_text)
    except re.error as exc:
        _issue(report, label, f"正则表达式无法编译：{exc}")
        return None
    if pattern.search("") is not None:
        _issue(report, label, "pattern 可以匹配空字符串，可能产生无界候选")
        return None

    keywords = data.get("keywords", [])
    if not isinstance(keywords, list) or not all(
        isinstance(keyword, str) for keyword in keywords
    ):
        _issue(report, label, "keywords 必须是字符串数组")
        return None
    if len(keywords) > MAX_KEYWORDS:
        _issue(report, label, f"keywords 数量超过 {MAX_KEYWORDS} 个")
        return None
    clean_keywords = [keyword.strip().lower() for keyword in keywords]
    if any(not keyword or len(keyword) > MAX_KEYWORD_LENGTH for keyword in clean_keywords):
        _issue(report, label, f"keyword 必须为 1–{MAX_KEYWORD_LENGTH} 字符")
        return None

    severity = data.get("severity_base")
    if isinstance(severity, bool) or not isinstance(severity, (int, float)):
        _issue(report, label, "severity_base 必须是数值")
        return None
    if not 20 <= float(severity) <= 100:
        _issue(report, label, "severity_base 必须位于 20–100")
        return None

    entropy_threshold = data.get("entropy_threshold")
    if entropy_threshold is not None:
        if isinstance(entropy_threshold, bool) or not isinstance(
            entropy_threshold, (int, float)
        ):
            _issue(report, label, "entropy_threshold 必须是数值或省略")
            return None
        if not 0.0 <= float(entropy_threshold) <= 8.0:
            _issue(report, label, "entropy_threshold 必须位于 0–8")
            return None

    recommendation = data.get("recommendation")
    if not isinstance(recommendation, str) or not recommendation.strip():
        _issue(report, label, "recommendation 必须是非空字符串")
        return None
    if len(recommendation.strip()) > 500:
        _issue(report, label, "recommendation 超过 500 字符")
        return None
    description = data.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        _issue(report, label, "description 必须是最多 500 字符的字符串")
        return None

    known_ids.add(rule_id)
    return LoadedRule(
        id=rule_id,
        name=name.strip(),
        description=description.strip(),
        pattern_text=pattern_text,
        pattern=pattern,
        severity_base=int(severity),
        keywords=clean_keywords,
        entropy_threshold=float(entropy_threshold) if entropy_threshold is not None else None,
        recommendation=recommendation.strip(),
        source=source,
    )


def validate_rule_pack(
    path: Path,
    *,
    existing_ids: set[str] | None = None,
) -> RuleValidationReport:
    """验证一个规则包；每条无效规则被禁用并记录，而不是执行。"""

    resolved = path.expanduser().resolve()
    report = RuleValidationReport(str(resolved))
    try:
        payload: Any = json.loads(resolved.read_text(encoding="utf-8"))
    except OSError as exc:
        _issue(report, "<pack>", f"无法读取规则文件：{exc}")
        return report
    except (UnicodeError, json.JSONDecodeError) as exc:
        _issue(report, "<pack>", f"不是有效的 UTF-8 JSON：{exc}")
        return report
    if not isinstance(payload, dict):
        _issue(report, "<pack>", "根结构必须是 JSON object")
        return report
    pack_name = payload.get("pack_name", resolved.stem)
    version = payload.get("version", "")
    if not isinstance(pack_name, str) or not pack_name.strip():
        _issue(report, "<pack>", "pack_name 必须是非空字符串")
        pack_name = resolved.stem
    if not isinstance(version, str):
        _issue(report, "<pack>", "version 必须是字符串")
        version = ""
    report.pack_name = pack_name.strip()
    report.version = version.strip()
    rules_data = payload.get("rules")
    if not isinstance(rules_data, list):
        _issue(report, "<pack>", "rules 必须是数组")
        return report
    report.rules_found = len(rules_data)
    if len(rules_data) > MAX_RULES_PER_PACK:
        _issue(report, "<pack>", f"规则总量超过 {MAX_RULES_PER_PACK} 条")
        return report
    known_ids = set(existing_ids or set())
    for index, data in enumerate(rules_data, start=1):
        rule = _validate_rule(data, index, str(resolved), known_ids, report)
        if rule is not None:
            report.rules.append(rule)
    return report


def load_builtin_rules(path: Path) -> list[LoadedRule]:
    report = validate_rule_pack(path)
    if report.invalid_count:
        reasons = "; ".join(issue.reason for issue in report.issues)
        pack_failure = any(issue.rule_id == "<pack>" for issue in report.issues)
        prefix = "无法加载规则文件" if pack_failure else "内置规则配置无效"
        raise RuleConfigError(f"{prefix} {path}: {reasons}")
    if not report.rules:
        raise RuleConfigError("rules.json 不包含任何规则")
    return report.rules


def load_combined_rules(
    builtin_path: Path, custom_paths: list[Path] | None = None
) -> tuple[list[LoadedRule], list[RuleValidationReport]]:
    """按 Built-in → Rule Pack 顺序合并，冲突规则默认拒绝。"""

    rules = load_builtin_rules(builtin_path)
    known_ids = {rule.id for rule in rules}
    reports: list[RuleValidationReport] = []
    for path in custom_paths or []:
        report = validate_rule_pack(path, existing_ids=known_ids)
        reports.append(report)
        rules.extend(report.rules)
        known_ids.update(rule.id for rule in report.rules)
    return rules, reports
