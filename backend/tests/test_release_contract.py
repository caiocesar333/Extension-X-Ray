from __future__ import annotations

import json
import tomllib
from pathlib import Path

import pytest
from pydantic import ValidationError

from app import __version__
from app.analyzer import ExtensionAnalyzer
from app.ci import load_report
from app.config import ReaSettings
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer


ROOT = Path(__file__).resolve().parents[2]


def test_release_versions_are_synchronized() -> None:
    project = tomllib.loads((ROOT / "backend" / "pyproject.toml").read_text(encoding="utf-8"))
    package = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    package_lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))

    assert __version__ == "1.0.0"
    assert project["project"]["version"] == __version__
    assert package["version"] == __version__
    assert package_lock["version"] == __version__
    assert package_lock["packages"][""]["version"] == __version__


@pytest.mark.parametrize(
    ("fixture_name", "analyzer", "expected_schema"),
    [
        (
            "benign_vsix",
            ExtensionAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled"))),
            "1.0.0",
        ),
        (
            "benign_repository",
            RepositoryAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled"))),
            "1.1.0",
        ),
    ],
)
def test_v05_report_schemas_remain_supported_and_unknown_versions_fail_closed(
    fixture_name: str,
    analyzer: ExtensionAnalyzer | RepositoryAnalyzer,
    expected_schema: str,
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> None:
    report = analyzer.analyze(request.getfixturevalue(fixture_name)).model_dump(mode="json")
    compatible_path = tmp_path / f"{fixture_name}.json"
    compatible_path.write_text(json.dumps(report), encoding="utf-8")

    assert load_report(compatible_path).schema_version == expected_schema

    report["schema_version"] = "99.0.0"
    incompatible_path = tmp_path / f"unsupported-{fixture_name}.json"
    incompatible_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValidationError, match="schema_version"):
        load_report(incompatible_path)
