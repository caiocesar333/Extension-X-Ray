from __future__ import annotations

import json
from pathlib import Path

from app.cli import run


def test_cli_writes_report_sarif_and_policy_result_for_benign_repository(
    benign_repository: Path,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"
    policy_path = tmp_path / "policy-result.json"

    exit_code = run([
        str(benign_repository),
        "--kind", "repository",
        "--no-rea",
        "--output", str(report_path),
        "--sarif", str(sarif_path),
        "--policy-output", str(policy_path),
        "--fail-on", "high",
    ])

    assert exit_code == 0
    assert json.loads(report_path.read_text(encoding="utf-8"))["analysis_kind"] == "repository"
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert json.loads(policy_path.read_text(encoding="utf-8"))["passed"] is True


def test_cli_returns_one_after_writing_outputs_when_policy_fails(
    suspicious_repository: Path,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    sarif_path = tmp_path / "report.sarif"

    exit_code = run([
        str(suspicious_repository),
        "--kind", "repository",
        "--no-rea",
        "--output", str(report_path),
        "--sarif", str(sarif_path),
        "--fail-on", "high",
        "--min-confidence", "medium",
    ])

    assert exit_code == 1
    assert report_path.is_file()
    assert sarif_path.is_file()
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]["results"]


def test_cli_can_diff_existing_reports_and_ignore_baselined_findings(
    suspicious_repository: Path,
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    diff_path = tmp_path / "diff.json"
    policy_path = tmp_path / "policy.json"
    assert run([
        str(suspicious_repository),
        "--kind", "repository",
        "--no-rea",
        "--output", str(report_path),
    ]) == 0

    exit_code = run([
        str(report_path),
        "--kind", "report",
        "--baseline", str(report_path),
        "--diff-output", str(diff_path),
        "--policy-output", str(policy_path),
        "--fail-on", "critical",
    ])

    difference = json.loads(diff_path.read_text(encoding="utf-8"))
    evaluation = json.loads(policy_path.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert difference["new_count"] == 0
    assert difference["resolved_count"] == 0
    assert difference["unchanged_count"] > 0
    assert evaluation["baseline_used"] is True
    assert evaluation["considered_findings"] == 0


def test_cli_returns_two_for_invalid_policy(benign_repository: Path, tmp_path: Path) -> None:
    invalid_policy = tmp_path / "invalid.toml"
    invalid_policy.write_text('[policy]\nfail_on = "everything"\n', encoding="utf-8")

    exit_code = run([
        str(benign_repository),
        "--kind", "repository",
        "--no-rea",
        "--policy", str(invalid_policy),
    ])

    assert exit_code == 2
