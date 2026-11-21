from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from app.ci import (
    PolicyConfig,
    compare_reports,
    evaluate_policy,
    finding_fingerprint,
    load_policy,
    report_to_sarif,
)
from app.config import ReaSettings
from app.models import Confidence
from app.rea import ReaAdapter
from app.repository_analyzer import RepositoryAnalyzer

from conftest import build_vsix


def analyzer() -> RepositoryAnalyzer:
    return RepositoryAnalyzer(rea=ReaAdapter(ReaSettings(mode="disabled")))


def test_fingerprint_survives_line_shift_and_archive_root_rename(suspicious_repository: Path) -> None:
    baseline = analyzer().analyze(suspicious_repository)
    current = baseline.model_copy(deep=True)
    current.report_id = "current-report"
    for file in current.files:
        file.path = file.path.replace("suspicious-repository/", "renamed-root/", 1)
    for finding in current.findings:
        if finding.location:
            finding.location.file = finding.location.file.replace(
                "suspicious-repository/",
                "renamed-root/",
                1,
            )
            if finding.location.line:
                finding.location.line += 20

    assert finding_fingerprint(current, current.findings[0]) == finding_fingerprint(
        baseline,
        baseline.findings[0],
    )
    difference = compare_reports(current, baseline)
    assert difference.new_count == 0
    assert difference.resolved_count == 0
    assert difference.unchanged_count == len(current.findings)


def test_report_diff_classifies_new_resolved_and_unchanged(suspicious_repository: Path) -> None:
    baseline = analyzer().analyze(suspicious_repository)
    current = baseline.model_copy(deep=True)
    current.report_id = "current-report"
    replacement = current.findings[0].model_copy(deep=True)
    replacement.id = "new-finding"
    replacement.rule_id = "TEST-NEW-001"
    replacement.title = "New synthetic signal"
    current.findings = [*current.findings[1:], replacement]

    difference = compare_reports(current, baseline)

    assert difference.new_count == 1
    assert difference.resolved_count == 1
    assert difference.unchanged_count == len(baseline.findings) - 1
    assert difference.new_findings[0].rule_id == "TEST-NEW-001"


def test_policy_applies_threshold_rules_ignores_and_baseline(suspicious_repository: Path) -> None:
    report = analyzer().analyze(suspicious_repository)
    policy = PolicyConfig(
        fail_on="critical",
        minimum_confidence=Confidence.high,
        ignore_rules=["REP-DLX-001"],
        deny_rules=["SCM-TYPO-001"],
    )

    evaluation = evaluate_policy(report, policy, policy_source="test")
    baselined = evaluate_policy(report, policy, baseline=report, policy_source="test")

    assert evaluation.passed is False
    assert any(item.rule_id == "SCM-TYPO-001" for item in evaluation.violations)
    assert all(item.rule_id != "REP-DLX-001" for item in evaluation.violations)
    assert baselined.passed is True
    assert baselined.considered_findings == 0
    assert baselined.existing_findings == len(report.findings)


def test_load_policy_rejects_unknown_and_overlapping_rules(tmp_path: Path) -> None:
    valid = tmp_path / "policy.toml"
    valid.write_text(
        'schema_version = "1"\n[policy]\nfail_on = "high"\nminimum_confidence = "medium"\n',
        encoding="utf-8",
    )
    assert load_policy(valid).fail_on == "high"

    overlap = tmp_path / "overlap.toml"
    overlap.write_text(
        '[policy]\ndeny_rules = ["EXR-PROC-001"]\nignore_rules = ["EXR-PROC-001"]\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="both denied and ignored"):
        load_policy(overlap)

    unknown = tmp_path / "unknown.toml"
    unknown.write_text('[policy]\ntrust_score = 100\n', encoding="utf-8")
    with pytest.raises(ValueError, match="Extra inputs"):
        load_policy(unknown)


def test_sarif_contains_rules_locations_fingerprints_and_baseline_state(
    suspicious_repository: Path,
) -> None:
    report = analyzer().analyze(suspicious_repository)
    document = report_to_sarif(report, baseline=report)
    run = document["runs"][0]
    results = run["results"]

    assert document["version"] == "2.1.0"
    assert run["tool"]["driver"]["semanticVersion"] == "1.0.0"
    assert len(results) == len(report.findings)
    assert results[0]["baselineState"] == "unchanged"
    assert results[0]["partialFingerprints"]["primaryLocationLineHash"]
    assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert not results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        "suspicious-repository/"
    )
    workflow_result = next(item for item in results if item["ruleId"] == "REP-CI-001")
    assert workflow_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
        ".github/workflows/"
    )

    locationless = report.model_copy(deep=True)
    locationless.findings = [locationless.findings[0]]
    locationless.findings[0].location = None
    locationless_result = report_to_sarif(locationless)["runs"][0]["results"][0]
    assert "locations" not in locationless_result


def test_reusable_workflow_pins_external_actions_and_uses_its_own_sha() -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "extension-xray-reusable.yml"
    ).read_text(encoding="utf-8")
    references = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)

    assert references
    assert all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", reference) for reference in references)
    assert "repository: ${{ job.workflow_repository }}" in workflow
    assert "ref: ${{ job.workflow_sha }}" in workflow


def test_all_workflows_pin_external_actions_to_full_commits() -> None:
    workflows = (Path(__file__).resolve().parents[2] / ".github" / "workflows").glob("*.yml")
    references = [
        reference
        for workflow in workflows
        for reference in re.findall(
            r"^\s*uses:\s*([^\s#]+)",
            workflow.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    ]

    assert references
    assert all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", reference) for reference in references)


def test_reusable_workflow_does_not_trigger_its_own_ci_rules(tmp_path: Path) -> None:
    workflow = (
        Path(__file__).resolve().parents[2]
        / ".github"
        / "workflows"
        / "extension-xray-reusable.yml"
    ).read_text(encoding="utf-8")
    archive = tmp_path / "workflow.zip"
    archive.write_bytes(build_vsix({
        "repo/package.json": json.dumps({"name": "workflow-test", "version": "1.0.0"}),
        "repo/.github/workflows/extension-xray-reusable.yml": workflow,
    }))

    report = analyzer().analyze(archive)
    rules = {finding.rule_id for finding in report.findings}

    assert "REP-CI-003" not in rules
    assert not {"SCM-CI-001", "SCM-CI-002", "SCM-CI-003"} & rules
