"""Custom Rule 测试中的所有 token 都是人工构造且不可用的假数据。"""

from __future__ import annotations

import json
from pathlib import Path

from models import SourceFile
from rule_detector import RuleDetector
from rule_loader import (
    MAX_KEYWORDS,
    MAX_PATTERN_LENGTH,
    MAX_RULES_PER_PACK,
    load_combined_rules,
    validate_rule_pack,
)


ROOT = Path(__file__).resolve().parents[1]
BUILTIN = ROOT / "config" / "rules.json"


def valid_rule(rule_id: str = "course-service-token") -> dict:
    return {
        "id": rule_id,
        "name": "Course Service Token",
        "description": "Fictional course-only format.",
        "pattern": r"COURSE_[A-Za-z0-9]{20,}",
        "keywords": [],
        "severity_base": 60,
        "entropy_threshold": 3.0,
        "recommendation": "Rotate the fake course token.",
    }


def write_pack(path: Path, rules: list[object]) -> Path:
    path.write_text(
        json.dumps({"pack_name": "Tests", "version": "1.0", "rules": rules}),
        encoding="utf-8",
    )
    return path


def test_valid_custom_rule_and_detection(tmp_path: Path) -> None:
    path = write_pack(tmp_path / "rules.json", [valid_rule()])
    report = validate_rule_pack(path)
    assert report.is_valid and report.valid_count == 1
    detector = RuleDetector(rules=report.rules)
    fake = "COURSE_A1B2C3D4E5F6G7H8J9K0"
    source = SourceFile(Path("a.py"), "a.py", f'token = "{fake}"', len(fake))
    assert detector.detect(source)[0].rule_id == "course-service-token"


def test_builtin_and_multiple_custom_packs_merge(tmp_path: Path) -> None:
    first = write_pack(tmp_path / "first.json", [valid_rule("first-token")])
    second = write_pack(tmp_path / "second.json", [valid_rule("second-token")])
    rules, reports = load_combined_rules(BUILTIN, [first, second])
    ids = {rule.id for rule in rules}
    assert "github-token" in ids
    assert {"first-token", "second-token"} <= ids
    assert len(reports) == 2


def test_rule_id_conflicts_are_rejected(tmp_path: Path) -> None:
    path = write_pack(tmp_path / "conflict.json", [valid_rule("github-token")])
    rules, reports = load_combined_rules(BUILTIN, [path])
    assert sum(rule.id == "github-token" for rule in rules) == 1
    assert reports[0].invalid_count == 1
    assert "conflict" in reports[0].issues[0].reason.lower()


def test_invalid_json_and_root_structure(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{broken", encoding="utf-8")
    assert validate_rule_pack(bad).invalid_count == 1
    bad.write_text("[]", encoding="utf-8")
    assert validate_rule_pack(bad).invalid_count == 1


def test_missing_required_fields(tmp_path: Path) -> None:
    report = validate_rule_pack(write_pack(tmp_path / "missing.json", [{"id": "x"}]))
    assert report.invalid_count == 1 and report.valid_count == 0


def test_invalid_empty_match_all_and_long_regex(tmp_path: Path) -> None:
    variants = ["(", "", ".*", "a?", "a" * (MAX_PATTERN_LENGTH + 1), "(?:a+)+"]
    for index, pattern in enumerate(variants):
        rule = valid_rule(f"bad-pattern-{index}")
        rule["pattern"] = pattern
        report = validate_rule_pack(write_pack(tmp_path / f"p{index}.json", [rule]))
        assert report.invalid_count == 1, pattern


def test_invalid_keywords(tmp_path: Path) -> None:
    variants: list[object] = ["token", [1], ["x"] * (MAX_KEYWORDS + 1), ["x" * 65]]
    for index, keywords in enumerate(variants):
        rule = valid_rule(f"bad-keywords-{index}")
        rule["keywords"] = keywords
        report = validate_rule_pack(write_pack(tmp_path / f"k{index}.json", [rule]))
        assert report.invalid_count == 1


def test_invalid_severity_and_entropy_threshold(tmp_path: Path) -> None:
    for index, severity in enumerate(("high", True, 19, 101)):
        rule = valid_rule(f"bad-severity-{index}")
        rule["severity_base"] = severity
        assert validate_rule_pack(write_pack(tmp_path / f"s{index}.json", [rule])).invalid_count == 1
    for index, threshold in enumerate(("high", True, -1, 9)):
        rule = valid_rule(f"bad-entropy-{index}")
        rule["entropy_threshold"] = threshold
        assert validate_rule_pack(write_pack(tmp_path / f"e{index}.json", [rule])).invalid_count == 1


def test_rule_loader_never_executes_user_fields(tmp_path: Path) -> None:
    marker = tmp_path / "must-not-exist.txt"
    rule = valid_rule()
    rule["python"] = f"open({str(marker)!r}, 'w').write('bad')"
    report = validate_rule_pack(write_pack(tmp_path / "declarative.json", [rule]))
    assert report.valid_count == 1
    assert not marker.exists()


def test_oversized_pack_is_rejected(tmp_path: Path) -> None:
    rules = [valid_rule(f"many-{index}") for index in range(MAX_RULES_PER_PACK + 1)]
    report = validate_rule_pack(write_pack(tmp_path / "too-many.json", rules))
    assert report.invalid_count == 1
    assert report.valid_count == 0


def test_invalid_custom_rule_does_not_disable_builtins(tmp_path: Path) -> None:
    invalid = valid_rule("unsafe-custom")
    invalid["pattern"] = "(?:a+)+"
    path = write_pack(tmp_path / "unsafe.json", [invalid])
    rules, reports = load_combined_rules(BUILTIN, [path])
    assert "github-token" in {rule.id for rule in rules}
    assert "unsafe-custom" not in {rule.id for rule in rules}
    assert reports[0].invalid_count == 1
