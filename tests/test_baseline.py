"""Baseline 测试只使用人工构造的无效假凭据。"""

from __future__ import annotations

import json
from pathlib import Path

from src.baseline import (
    BaselineError,
    apply_baseline,
    create_baseline_data,
    load_baseline,
    write_baseline,
)
from src.scanner import scan_project


RAW = "CourseBaselinePassword2468"


def write_project(root: Path, *, prefix: str = "", include_old: bool = True, include_new: bool = False) -> None:
    root.mkdir(parents=True, exist_ok=True)
    lines = [prefix]
    if include_old:
        lines.append(f'password = "{RAW}"')
    if include_new:
        lines.append('api_key = "NEWCOURSEKEY_A1B2C3D4E5F6"')
    (root / "配置.py").write_text("\n".join(lines), encoding="utf-8")


def baseline_for(project: Path, path: Path):
    result = scan_project(project)
    write_baseline(create_baseline_data(result), path)
    return load_baseline(path)


def test_create_load_and_no_raw_secret(tmp_path: Path) -> None:
    project = tmp_path / "中文项目"
    write_project(project)
    path = tmp_path / ".credscope-baseline.json"
    baseline = baseline_for(project, path)
    assert len(baseline.findings) == 1
    serialized = path.read_text(encoding="utf-8")
    assert RAW not in serialized
    assert "配置.py" in serialized


def test_same_and_line_shifted_finding_are_existing(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_project(project)
    path = tmp_path / "baseline.json"
    baseline = baseline_for(project, path)
    same = apply_baseline(scan_project(project), baseline, path)
    assert same.findings[0].status == "EXISTING"
    write_project(project, prefix="# 新增注释\n\n")
    shifted = apply_baseline(scan_project(project), baseline, path)
    assert shifted.findings[0].line_number > same.findings[0].line_number
    assert shifted.findings[0].status == "EXISTING"


def test_new_and_resolved_findings(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_project(project)
    path = tmp_path / "baseline.json"
    baseline = baseline_for(project, path)
    write_project(project, include_old=True, include_new=True)
    compared = apply_baseline(scan_project(project), baseline, path)
    assert {finding.status for finding in compared.findings} == {"NEW", "EXISTING"}
    write_project(project, include_old=False, include_new=True)
    resolved = apply_baseline(scan_project(project), baseline, path)
    assert [finding.status for finding in resolved.findings] == ["NEW"]
    assert len(resolved.resolved_findings) == 1


def test_empty_and_broken_baseline(tmp_path: Path) -> None:
    empty_path = tmp_path / "empty.json"
    empty_path.write_text(
        json.dumps({
            "baseline_format": 1, "created_at": "", "updated_at": "",
            "target_path": "", "findings": [],
        }),
        encoding="utf-8",
    )
    assert load_baseline(empty_path).findings == []
    broken = tmp_path / "broken.json"
    broken.write_text("{bad", encoding="utf-8")
    try:
        load_baseline(broken)
    except BaselineError as exc:
        assert "损坏" in str(exc)
    else:
        raise AssertionError("损坏 Baseline 必须报错")


def test_normal_scan_coexists_without_status(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_project(project)
    result = scan_project(project)
    assert result.baseline_path is None
    assert result.findings[0].status is None


def test_baseline_update_preserves_created_at(tmp_path: Path) -> None:
    project = tmp_path / "project"
    write_project(project)
    path = tmp_path / "baseline.json"
    original = baseline_for(project, path)
    write_project(project, include_new=True)
    updated = create_baseline_data(scan_project(project), original=original)
    write_baseline(updated, path, overwrite=True)
    loaded = load_baseline(path)
    assert loaded.created_at == original.created_at
    assert len(loaded.findings) == 2
