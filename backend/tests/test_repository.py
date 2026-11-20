from __future__ import annotations

import json
from pathlib import Path

import app.repository_analyzer as repository_analyzer_module
from app.config import ReaSettings
from app.models import RepositoryAnalysisReport
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer

from conftest import build_vsix


def disabled_analyzer() -> RepositoryAnalyzer:
    return RepositoryAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled")))


def repository_zip(tmp_path: Path, files: dict[str, str]) -> Path:
    path = tmp_path / "repository.zip"
    path.write_bytes(
        build_vsix(
            {
                "repo/package.json": json.dumps({"name": "hardening-fixture", "version": "1.0.0"}),
                **{f"repo/{name}": content for name, content in files.items()},
            }
        )
    )
    return path


def test_benign_repository_has_no_security_findings(benign_repository: Path) -> None:
    report = disabled_analyzer().analyze(benign_repository)

    assert report.analysis_kind == "repository"
    assert report.repository.name == "benign-repository"
    assert report.repository.package_manager == "npm"
    assert report.repository.ecosystems == ["javascript"]
    assert report.repository.workflow_count == 1
    assert report.findings == []


def test_repository_detects_supply_chain_and_crypto_patterns(suspicious_repository: Path) -> None:
    report = disabled_analyzer().analyze(suspicious_repository)
    rule_ids = {finding.rule_id for finding in report.findings}

    expected_rules = {
        "REP-DLX-001",
        "REP-CI-001",
        "REP-CI-003",
        "REP-DEV-001",
        "REP-NPM-002",
        "CRYPTO-SECRET-001",
        "CRYPTO-WALLET-001",
        "CRYPTO-TX-001",
        "CRYPTO-CLIP-001",
        "EXR-PROC-001",
        "EXR-ENV-001",
        "EXR-NET-001",
    }
    assert expected_rules.issubset(rule_ids), expected_rules - rule_ids
    assert all("synthetic alpha beta" not in (finding.evidence.snippet or "") for finding in report.findings)
    assert report.repository.scripts["postinstall"].startswith("curl")
    assert report.repository.security_config_files


def test_repository_report_round_trips_schema(suspicious_repository: Path) -> None:
    report = disabled_analyzer().analyze(suspicious_repository)
    restored = RepositoryAnalysisReport.model_validate_json(report.model_dump_json())

    assert restored.sha256 == report.sha256
    assert "repository" in RepositoryAnalysisReport.model_json_schema()["properties"]


def test_long_prose_assignment_is_not_treated_as_a_seed_phrase(tmp_path: Path) -> None:
    archive = repository_zip(
        tmp_path,
        {
            "src/example.js": (
                "const recoveryPhrase = 'this sentence is intentionally verbose and documents harmless "
                "behavior without containing a valid recovery phrase value';\n"
            )
        },
    )

    report = disabled_analyzer().analyze(archive)

    assert "CRYPTO-SECRET-001" not in {finding.rule_id for finding in report.findings}


def test_privileged_workflow_requires_checkout_and_run_in_same_job(tmp_path: Path) -> None:
    pinned_sha = "a" * 40
    archive = repository_zip(
        tmp_path,
        {
            ".github/workflows/split.yml": f"""on: pull_request_target
jobs:
  checkout:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{pinned_sha}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
  command:
    runs-on: ubuntu-latest
    steps:
      - run: echo safe
"""
        },
    )

    report = disabled_analyzer().analyze(archive)

    assert "REP-CI-001" not in {finding.rule_id for finding in report.findings}


def test_multiline_workflow_script_injection_is_detected(tmp_path: Path) -> None:
    archive = repository_zip(
        tmp_path,
        {
            ".github/workflows/injection.yml": """on: issues
jobs:
  echo:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.issue.title }}"
"""
        },
    )

    report = disabled_analyzer().analyze(archive)

    assert "REP-CI-002" in {finding.rule_id for finding in report.findings}


def test_combined_repository_findings_are_capped(
    suspicious_repository: Path,
    monkeypatch,
) -> None:
    monkeypatch.setattr(repository_analyzer_module, "_MAX_COMBINED_FINDINGS", 3)

    report = disabled_analyzer().analyze(suspicious_repository)

    assert len(report.findings) == 3
    assert any("capped at 3" in limitation for limitation in report.limitations)
