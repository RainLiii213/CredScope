from src.models import CredentialCandidate
from src.risk_engine import RiskEngine, severity_for_score


VALUE = "Q7vL2mN9xR4pT8kW3sY6dF1hJ5cB0zAa"


def make(detector: str, **kwargs) -> CredentialCandidate:
    defaults = dict(
        file_path="app.py",
        line_number=3,
        column=18,
        secret_type="Generic Secret",
        raw_value=VALUE,
        detectors={detector},
        evidence=[detector],
        line_text=f'client_secret = "{VALUE}"',
    )
    defaults.update(kwargs)
    return CredentialCandidate(**defaults)


def test_multi_detector_fusion_and_exact_score() -> None:
    candidates = [
        make("context"),
        make("entropy", entropy=4.8, secret_type="High Entropy String"),
    ]
    findings = RiskEngine().evaluate(candidates)
    assert len(findings) == 1
    assert findings[0].detectors == ["context", "entropy"]
    assert findings[0].risk_score == 60  # 25 + 15 + 15 + 长度 5
    assert findings[0].severity == "HIGH"


def test_duplicate_candidates_are_not_duplicate_findings() -> None:
    findings = RiskEngine().evaluate([make("context"), make("context")])
    assert len(findings) == 1


def test_entropy_alone_never_reports() -> None:
    assert RiskEngine().evaluate([make("entropy", entropy=5.0)]) == []


def test_rule_score_caps_at_100() -> None:
    findings = RiskEngine().evaluate(
        [
            make("rule", severity_base=80, rule_id="private-key"),
            make("context"),
            make("entropy", entropy=5.0),
        ]
    )
    assert findings[0].risk_score == 100


def test_severity_boundaries() -> None:
    assert severity_for_score(100) == "CRITICAL"
    assert severity_for_score(80) == "CRITICAL"
    assert severity_for_score(79) == "HIGH"
    assert severity_for_score(60) == "HIGH"
    assert severity_for_score(59) == "MEDIUM"
    assert severity_for_score(40) == "MEDIUM"
    assert severity_for_score(39) == "LOW"
    assert severity_for_score(20) == "LOW"
    assert severity_for_score(19) is None
