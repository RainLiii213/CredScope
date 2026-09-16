from pathlib import Path

from src.models import SourceFile
from src.rule_detector import RuleConfigError, RuleDetector


ROOT = Path(__file__).resolve().parents[1]


def source(text: str) -> SourceFile:
    return SourceFile(Path("sample.py"), "sample.py", text, len(text))


def test_specific_rules_match_fake_values() -> None:
    detector = RuleDetector(ROOT / "config" / "rules.json")
    text = (
        'token = "github_pat_A1B2C3D4E5F6G7H8J9K0LMNOPQ"\n'
        'url = "postgresql://course:FakePass99@localhost/demo"'
    )
    names = {candidate.secret_type for candidate in detector.detect(source(text))}
    assert "GitHub Token" in names
    assert "Database Connection String" in names


def test_normal_text_does_not_match() -> None:
    detector = RuleDetector(ROOT / "config" / "rules.json")
    assert detector.detect(source('message = "hello world"')) == []


def test_broken_and_empty_rules_are_rejected(tmp_path: Path) -> None:
    broken = tmp_path / "rules.json"
    broken.write_text("{bad", encoding="utf-8")
    try:
        RuleDetector(broken)
    except RuleConfigError as exc:
        assert "无法加载规则文件" in str(exc)
    else:
        raise AssertionError("损坏规则应被拒绝")
    broken.write_text('{"rules": []}', encoding="utf-8")
    try:
        RuleDetector(broken)
    except RuleConfigError as exc:
        assert "不包含任何规则" in str(exc)
    else:
        raise AssertionError("空规则应被拒绝")
