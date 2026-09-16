"""Web/SaaS rule pack fixtures are fake and intentionally unusable."""

from pathlib import Path

from src.models import SourceFile
from src.rule_detector import RuleDetector
from src.rule_loader import validate_rule_pack


PACK = Path(__file__).resolve().parents[1] / "rulepacks" / "web_saas_services.json"
FAKES = {
    "stripe-secret-key": "sk_" + "live_A1b2C3d4E5f6G7h8J9k0LmNo",
    "shopify-access-token": "shpat_A1b2C3d4E5f6G7h8J9k0LmNo",
}


def test_every_web_rule_matches_one_fake() -> None:
    report = validate_rule_pack(PACK)
    assert report.is_valid and report.valid_count == len(FAKES)
    detector = RuleDetector(rules=report.rules)
    for rule_id, value in FAKES.items():
        source = SourceFile(Path("web.py"), "web.py", value, len(value))
        assert {item.rule_id for item in detector.detect(source)} == {rule_id}


def test_web_pack_excludes_public_and_similar_values() -> None:
    detector = RuleDetector(rules=validate_rule_pack(PACK).rules)
    text = "pk_live_A1b2C3d4E5f6G7h8J9k0LmNo shpat_short"
    source = SourceFile(Path("safe.js"), "safe.js", text, len(text))
    assert detector.detect(source) == []
