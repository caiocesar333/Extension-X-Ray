from __future__ import annotations

from pathlib import Path

from app.config import ReaSettings
from app.models import RepositoryAnalysisReport
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer


def disabled_analyzer() -> RepositoryAnalyzer:
    return RepositoryAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled")))


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
