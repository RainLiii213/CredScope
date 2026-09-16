from src.filters import (
    CandidateFilter,
    is_environment_reference,
    is_placeholder,
    is_uuid,
    mask_secret,
)
from src.models import CredentialCandidate


def candidate(value: str, line: str = "") -> CredentialCandidate:
    return CredentialCandidate("a.py", 1, 1, "Secret", value, line_text=line)


def test_placeholder_filter() -> None:
    assert is_placeholder("your_api_key_here")
    assert is_placeholder("CHANGE_ME")
    assert is_placeholder("xxxxxx")
    assert CandidateFilter().rejection_reason(candidate("demo")) == "placeholder"


def test_uuid_and_environment_reference_filters() -> None:
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert is_uuid(uuid)
    assert CandidateFilter().rejection_reason(candidate(uuid)) == "UUID"
    line = 'api_key = os.getenv("API_KEY")'
    assert is_environment_reference(line)
    assert CandidateFilter().rejection_reason(candidate("API_KEY", line)) == "environment reference"


def test_normal_secret_is_not_filtered_and_masking_is_safe() -> None:
    value = "Q7vL2mN9xR4pT8kW3sY6dF1hJ5cB0zAa"
    assert CandidateFilter().rejection_reason(candidate(value)) is None
    masked = mask_secret(value)
    assert value not in masked
    assert masked.startswith(value[:4]) and masked.endswith(value[-2:])
    assert mask_secret("abc") == "***"
