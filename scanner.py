"""安全文件发现与 CredScope 扫描主流程。"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from context_detector import ContextDetector
from entropy_detector import EntropyDetector
from filters import CandidateFilter
from models import CredentialCandidate, ScanResult, ScanStats, SourceFile
from risk_engine import RiskEngine
from rule_loader import load_combined_rules
from rule_detector import RuleDetector


LOGGER = logging.getLogger(__name__)
MAX_FILE_SIZE = 2 * 1024 * 1024
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".json",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env", ".txt", ".md",
    ".sh", ".ps1",
}
KNOWN_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".pdf",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".exe", ".dll",
    ".so", ".zip", ".rar", ".7z", ".tar", ".gz", ".db", ".sqlite",
    ".sqlite3", ".pkl", ".pickle", ".pt", ".pth", ".onnx", ".bin",
}


class ScanPathError(ValueError):
    pass


class FileScanner:
    def __init__(
        self,
        root: Path,
        ignore_file: Path,
        excludes: set[str] | None = None,
        max_file_size: int = MAX_FILE_SIZE,
    ) -> None:
        self.root = root.expanduser().resolve()
        self.max_file_size = max_file_size
        self.ignored_names = self._load_ignores(ignore_file)
        self.ignored_names.update(excludes or set())

    @staticmethod
    def _load_ignores(path: Path) -> set[str]:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ScanPathError(f"无法读取忽略配置 {path}: {exc}") from exc
        return {
            line.strip().rstrip("/\\")
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        }

    def validate(self) -> None:
        if not self.root.exists():
            raise ScanPathError(f"扫描目录不存在：{self.root}")
        if not self.root.is_dir():
            raise ScanPathError(f"扫描目标必须是目录，而不是文件：{self.root}")

    def collect(self, stats: ScanStats) -> list[SourceFile]:
        self.validate()
        sources: list[SourceFile] = []
        try:
            paths = self.root.rglob("*")
            for path in paths:
                if not path.is_file():
                    continue
                stats.files_discovered += 1
                relative = path.relative_to(self.root)
                if path.name.lower() == ".credscope-baseline.json":
                    stats.skipped("baseline file")
                    continue
                ignored_part = next(
                    (part for part in relative.parts[:-1] if part in self.ignored_names), None
                )
                if ignored_part:
                    stats.skipped("ignored path")
                    continue
                suffix = path.suffix.lower()
                name_lower = path.name.lower()
                is_dotenv = name_lower == ".env" or name_lower.startswith(".env.")
                if suffix in KNOWN_BINARY_EXTENSIONS or (
                    suffix not in SUPPORTED_EXTENSIONS and not is_dotenv
                ):
                    stats.skipped("unsupported type")
                    continue
                try:
                    size = path.stat().st_size
                except OSError as exc:
                    LOGGER.warning("无法读取文件属性 %s：%s", path, exc)
                    stats.skipped("stat error")
                    continue
                if size > self.max_file_size:
                    stats.skipped("too large")
                    continue
                source = self._read_source(path, relative.as_posix(), size)
                if source is None:
                    stats.skipped("unreadable or binary")
                    continue
                sources.append(source)
                stats.files_scanned += 1
                stats.lines_scanned += len(source.lines)
                stats.bytes_scanned += size
        except OSError as exc:
            LOGGER.warning("遍历目录时遇到问题 %s：%s", self.root, exc)
        return sources

    @staticmethod
    def _read_source(path: Path, relative_path: str, size: int) -> SourceFile | None:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            LOGGER.warning("无法读取文件 %s：%s", path, exc)
            return None
        if b"\x00" in raw[:8192]:
            LOGGER.debug("跳过疑似二进制文件：%s", path)
            return None
        for encoding in ("utf-8-sig", "utf-8", "gb18030"):
            try:
                return SourceFile(path, relative_path, raw.decode(encoding), size)
            except UnicodeDecodeError:
                continue
        LOGGER.warning("文件编码无法识别，已跳过：%s", path)
        return None


def scan_project(
    target: Path,
    *,
    excludes: set[str] | None = None,
    allowlist: set[str] | None = None,
    config_dir: Path | None = None,
    custom_rule_paths: list[Path] | None = None,
) -> ScanResult:
    """运行完整的本地扫描管线并返回不含原始 Secret 的结果。"""

    started = time.perf_counter()
    base_dir = Path(__file__).resolve().parent
    config = config_dir or base_dir / "config"
    stats = ScanStats()
    sources = FileScanner(
        target,
        config / "default_ignore.txt",
        excludes=excludes,
    ).collect(stats)
    rules, validation_reports = load_combined_rules(
        config / "rules.json", custom_rule_paths
    )
    for report in validation_reports:
        for issue in report.issues:
            LOGGER.warning(
                "规则包 %s [%s] %s：%s",
                report.path,
                issue.level,
                issue.rule_id,
                issue.reason,
            )
    detectors = (
        RuleDetector(rules=rules),
        ContextDetector(config / "keywords.json"),
        EntropyDetector(),
    )
    candidates: list[CredentialCandidate] = []
    for source in sources:
        for detector in detectors:
            try:
                candidates.extend(detector.detect(source))
            except (ValueError, RuntimeError, re.error) as exc:
                # 单一检测器处理单一文件失败时继续扫描；不记录源码内容。
                LOGGER.warning(
                    "检测器 %s 处理 %s 失败：%s",
                    detector.__class__.__name__,
                    source.relative_path,
                    exc,
                )
    findings = RiskEngine(CandidateFilter(allowlist or set())).evaluate(candidates)
    stats.duration_seconds = time.perf_counter() - started
    return ScanResult(str(Path(target).expanduser().resolve()), findings, stats)
