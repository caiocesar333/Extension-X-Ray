from __future__ import annotations

from pathlib import Path

from app.analyzer import ExtensionAnalyzer
from app.config import ReaSettings
from app.models import AnalysisReport, Severity
from app.rea import ReaAdapter


def disabled_analyzer() -> ExtensionAnalyzer:
    return ExtensionAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled")))


def test_benign_extension_has_no_security_findings(benign_vsix: Path) -> None:
    report = disabled_analyzer().analyze(benign_vsix)

    assert report.extension.name == "synthetic-safe-extension"
    assert report.extension.commands[0].command == "xray.hello"
    assert report.findings == []
    assert report.rea.status == "disabled"
    assert report.archive.file_count == 4


def test_detects_security_relevant_patterns(suspicious_vsix: Path) -> None:
    report = disabled_analyzer().analyze(suspicious_vsix)
    rule_ids = {finding.rule_id for finding in report.findings}

    assert {
        "EXR-PROC-001",
        "EXR-DYN-001",
        "EXR-ENV-001",
        "EXR-NET-001",
        "EXR-FS-001",
        "EXR-TX-001",
        "EXR-DLX-001",
        "EXR-CAP-001",
    }.issubset(rule_ids)
    assert report.severity_counts[Severity.critical] >= 2
    assert all(finding.evidence.summary for finding in report.findings)
    assert all(finding.location and finding.location.line for finding in report.findings)


def test_report_round_trips_through_public_schema(suspicious_vsix: Path) -> None:
    report = disabled_analyzer().analyze(suspicious_vsix)
    serialized = report.model_dump_json()

    restored = AnalysisReport.model_validate_json(serialized)
    assert restored.schema_version == "1.0.0"
    assert restored.sha256 == report.sha256
    assert "extension" in AnalysisReport.model_json_schema()["properties"]


def test_rea_unavailable_falls_back_to_native_analysis(suspicious_vsix: Path) -> None:
    adapter = ReaAdapter(ReaSettings(mode="auto", command="definitely-not-a-real-rea-command"))
    report = ExtensionAnalyzer(rea=adapter).analyze(suspicious_vsix)

    assert report.rea.status == "unavailable"
    assert report.rea.used is False
    assert report.findings
    assert any("REA enrichment was unavailable" in item for item in report.limitations)

