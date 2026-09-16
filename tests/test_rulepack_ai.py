"""AI rule pack fixtures are fake and intentionally unusable."""

from pathlib import Path

from src.models import SourceFile
from src.rule_detector import RuleDetector
from src.rule_loader import validate_rule_pack


PACK = Path(__file__).resolve().parents[1] / "rulepacks" / "ai_llm_services.json"
FAKES = {
    "anthropic-api-key": "sk-ant-api03-A1b2C3d4E5f6G7h8J9k0LmNoPqRs",
    "huggingface-user-token": "hf_A1b2C3d4E5f6G7h8J9k0",
    "replicate-api-token": "r8_A1b2C3d4E5f6G7h8J9k0LmNoPqRsTuVwXyZ12",
}


def test_every_ai_rule_matches_one_fake() -> None:
    report = validate_rule_pack(PACK)
    assert report.is_valid and report.valid_count == len(FAKES)
    detector = RuleDetector(rules=report.rules)
    for rule_id, value in FAKES.items():
        source = SourceFile(Path("ai.py"), "ai.py", value, len(value))
        assert {item.rule_id for item in detector.detect(source)} == {rule_id}


def test_ai_pack_negative_examples() -> None:
    report = validate_rule_pack(PACK)
    detector = RuleDetector(rules=report.rules)
    text = "sk-ant-short hf_public_model r8_too_short"
    source = SourceFile(Path("safe.py"), "safe.py", text, len(text))
    assert detector.detect(source) == []
