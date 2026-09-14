"""误报过滤与统一的 Secret 脱敏函数。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from models import CredentialCandidate


PLACEHOLDER_VALUES = {
    "example", "sample", "demo", "dummy", "test", "fake", "placeholder",
    "changeme", "change_me", "your_api_key", "your_api_key_here",
    "your_token", "your_token_here", "replace_me", "replace_with_your_key",
}
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
ENV_REFERENCE_RE = re.compile(
    r"(?:os\.(?:getenv|environ)|getenv|process\.env|System\.getenv|\$\{[A-Z_][A-Z0-9_]*\})"
)


def _normalized(value: str) -> str:
    return re.sub(r"[\s\-]+", "_", value.strip().strip("'\"").lower())


def is_placeholder(value: str) -> bool:
    """识别明确的示例/占位值，避免对包含 test 的真实格式做子串误判。"""

    normalized = _normalized(value)
    if normalized in PLACEHOLDER_VALUES:
        return True
    if re.fullmatch(r"[xX*._-]{5,}", value.strip()):
        return True
    if normalized.startswith(("your_", "example_", "sample_", "dummy_")):
        return True
    return normalized.endswith(("_here", "_placeholder"))


def is_uuid(value: str) -> bool:
    return bool(UUID_RE.fullmatch(value.strip()))


def is_environment_reference(text: str) -> bool:
    return bool(ENV_REFERENCE_RE.search(text))


@dataclass(slots=True)
class CandidateFilter:
    """集中执行候选过滤；allowlist 仅保存调用者明确提供的完整值。"""

    allowlist: set[str] = field(default_factory=set, repr=False)

    def rejection_reason(self, candidate: CredentialCandidate) -> str | None:
        if candidate.raw_value in self.allowlist:
            return "allowlist"
        if is_environment_reference(candidate.line_text):
            return "environment reference"
        if is_uuid(candidate.raw_value):
            return "UUID"
        if is_placeholder(candidate.raw_value):
            return "placeholder"
        return None


def mask_secret(secret: str) -> str:
    """返回不可逆的展示形式；所有 Reporter 必须只使用此函数的结果。"""

    value = secret.strip()
    if not value:
        return ""
    if "PRIVATE KEY" in value.upper():
        return "-----BEGIN P******** K**-----"
    length = len(value)
    if length <= 4:
        return "*" * length
    if length <= 8:
        return value[0] + "*" * (length - 2) + value[-1]
    prefix = min(4, max(2, length // 6))
    suffix = min(2, max(1, length // 8))
    return value[:prefix] + "*" * (length - prefix - suffix) + value[-suffix:]
