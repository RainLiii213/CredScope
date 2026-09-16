"""Shannon 信息熵计算与支持性高熵证据检测。"""

from __future__ import annotations

import math
import re
from collections import Counter

from .models import CredentialCandidate, SourceFile


ENTROPY_THRESHOLD = 4.0
MIN_ENTROPY_LENGTH = 20
QUOTED_STRING_RE = re.compile(r"(?P<quote>['\"])(?P<value>[A-Za-z0-9_+./=~-]{20,})(?P=quote)")
ASSIGNMENT_HINT_RE = re.compile(r"(?:=|:)\s*['\"]")


def calculate_entropy(text: str) -> float:
    """计算字符串的 Shannon entropy（bits per character）。"""

    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )


class EntropyDetector:
    """产生高熵支持证据；风险引擎不会单凭此检测器报告。"""

    def __init__(
        self, threshold: float = ENTROPY_THRESHOLD, min_length: int = MIN_ENTROPY_LENGTH
    ) -> None:
        self.threshold = threshold
        self.min_length = min_length

    def detect(self, source: SourceFile) -> list[CredentialCandidate]:
        candidates: list[CredentialCandidate] = []
        for line_number, line in enumerate(source.lines, start=1):
            if not ASSIGNMENT_HINT_RE.search(line):
                continue
            for match in QUOTED_STRING_RE.finditer(line):
                value = match.group("value")
                if len(value) < self.min_length:
                    continue
                entropy = calculate_entropy(value)
                if entropy < self.threshold:
                    continue
                candidates.append(
                    CredentialCandidate(
                        file_path=source.relative_path,
                        line_number=line_number,
                        column=match.start("value") + 1,
                        secret_type="High Entropy String",
                        raw_value=value,
                        detectors={"entropy"},
                        evidence=[f"字符串 Shannon 熵较高（{entropy:.2f} bits/char）"],
                        entropy=entropy,
                        line_text=line,
                    )
                )
        return candidates
