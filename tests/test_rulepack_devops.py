"""DevOps rule pack fixtures are fake and intentionally unusable."""

from pathlib import Path

from src.models import SourceFile
from src.rule_detector import RuleDetector
from src.rule_loader import validate_rule_pack


PACK = Path(__file__).resolve().parents[1] / "rulepacks" / "devops_registry.json"
FAKES = {
    "gitlab-access-token": "glpat-" + "A1b2C3d4E5f6G7h8J9k0",
    "pypi-api-token": "pypi-A1b2C3d4E5f6G7h8J9k0LmNoPqRsTuVw",
    "hcp-terraform-token": "abcDEF.atlasv1.A1b2C3d4E5f6G7h8J9k0LmNo",
}


def test_every_devops_rule_matches_one_fake() -> None:
    report = validate_rule_pack(PACK)
    assert report.is_valid and report.valid_count == len(FAKES)
    detector = RuleDetector(rules=report.rules)
    for rule_id, value in FAKES.items():
        source = SourceFile(Path("ci.yml"), "ci.yml", value, len(value))
        assert {item.rule_id for item in detector.detect(source)} == {rule_id}


def test_devops_pack_negative_examples() -> None:
    detector = RuleDetector(rules=validate_rule_pack(PACK).rules)
    text = "glpat-short pypi-project-name atlasv1 documentation"
    source = SourceFile(Path("safe.md"), "safe.md", text, len(text))
    assert detector.detect(source) == []
