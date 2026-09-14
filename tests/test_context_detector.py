from pathlib import Path

from context_detector import ContextDetector
from models import SourceFile


ROOT = Path(__file__).resolve().parents[1]


def detect(text: str):
    source = SourceFile(Path("app.py"), "app.py", text, len(text))
    return ContextDetector(ROOT / "config" / "keywords.json").detect(source)


def test_hardcoded_password_is_detected() -> None:
    findings = detect('password = "abc123"')
    assert len(findings) == 1
    assert findings[0].secret_type == "Hardcoded Password"


def test_environment_lookup_is_not_detected() -> None:
    assert detect('password = os.getenv("PASSWORD")') == []
    assert detect('token = os.environ["SAFE_TOKEN"]') == []


def test_normal_variable_is_not_detected() -> None:
    assert detect('display_name = "Ada Lovelace"') == []
    assert detect('author = "Ada Lovelace"') == []
    assert detect('tokenizer = "ordinary-component"') == []


def test_snake_and_camel_case_sensitive_names_are_detected() -> None:
    assert len(detect('db_password = "abc123"')) == 1
    assert len(detect('secretKey = "abc123"')) == 1
