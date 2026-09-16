from pathlib import Path

from src.entropy_detector import EntropyDetector, calculate_entropy
from src.models import SourceFile


def test_entropy_edge_cases() -> None:
    assert calculate_entropy("") == 0.0
    assert calculate_entropy("aaaaaaaa") == 0.0
    assert calculate_entropy("hello") < 3.0
    assert calculate_entropy("Q7vL2mN9xR4pT8kW3sY6dF1hJ5cB0zAa") > 4.0


def test_detector_emits_supporting_candidate_for_assignment() -> None:
    value = "Q7vL2mN9xR4pT8kW3sY6dF1hJ5cB0zAa"
    text = f'client_secret = "{value}"'
    source = SourceFile(Path("a.py"), "a.py", text, len(text))
    candidates = EntropyDetector().detect(source)
    assert len(candidates) == 1
    assert candidates[0].detectors == {"entropy"}


def test_repetitive_long_string_is_not_high_entropy() -> None:
    text = 'value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    source = SourceFile(Path("a.py"), "a.py", text, len(text))
    assert EntropyDetector().detect(source) == []
