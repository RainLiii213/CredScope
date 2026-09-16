"""基于敏感字段名和直接字符串赋值的上下文检测器。"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .filters import is_environment_reference
from .models import CredentialCandidate, SourceFile


class ContextConfigError(RuntimeError):
    pass


class ContextDetector:
    def __init__(self, keywords_path: Path) -> None:
        try:
            data = json.loads(keywords_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ContextConfigError(f"无法加载关键词配置 {keywords_path}: {exc}") from exc
        keywords = data.get("sensitive_keywords", [])
        if not isinstance(keywords, list) or not keywords:
            raise ContextConfigError("keywords.json 中 sensitive_keywords 必须是非空列表")
        self.keywords = {str(item).lower() for item in keywords}
        self.pattern = re.compile(
            r"(?i)(?P<name>[A-Za-z_][\w.-]*)"
            r"\s*(?:=|:)\s*(?P<quote>['\"])(?P<value>[^'\"\r\n]+)(?P=quote)"
        )

    def detect(self, source: SourceFile) -> list[CredentialCandidate]:
        candidates: list[CredentialCandidate] = []
        for line_number, line in enumerate(source.lines, start=1):
            if is_environment_reference(line):
                continue
            for match in self.pattern.finditer(line):
                name = match.group("name")
                if not self._is_sensitive_name(name):
                    continue
                value = match.group("value")
                candidates.append(
                    CredentialCandidate(
                        file_path=source.relative_path,
                        line_number=line_number,
                        column=match.start("value") + 1,
                        secret_type=self._secret_type(name),
                        raw_value=value,
                        detectors={"context"},
                        evidence=[
                            f"敏感字段名：{name}",
                            "检测到直接写入源码的字符串",
                        ],
                        recommendation="避免硬编码敏感值；改用环境变量或安全的密钥管理服务。",
                        line_text=line,
                    )
                )
        return candidates

    def _is_sensitive_name(self, name: str) -> bool:
        # 先拆分 snake/kebab/dotted/camelCase，避免 author 因包含 auth 而误报。
        separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
        normalized = separated.lower()
        parts = {part for part in re.split(r"[^a-z0-9]+", normalized) if part}
        for keyword in self.keywords:
            if keyword in parts:
                return True
            if "_" in keyword and keyword in normalized:
                return True
        return False

    @staticmethod
    def _secret_type(name: str) -> str:
        lowered = name.lower()
        if any(item in lowered for item in ("password", "passwd", "pwd")):
            return "Hardcoded Password"
        if "private_key" in lowered:
            return "Private Key Value"
        if "token" in lowered:
            return "Hardcoded Token"
        if "api" in lowered and "key" in lowered:
            return "Generic API Key"
        return "Generic Secret"
