from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from typing import Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import __version__
from .models import (
    AnalysisReport,
    Confidence,
    Finding,
    RepositoryAnalysisReport,
    Severity,
    SourceLocation,
)

Report = AnalysisReport | RepositoryAnalysisReport
FailThreshold = Literal["off", "critical", "high", "medium", "low", "info"]

_MAX_REPORT_BYTES = 50 * 1024 * 1024
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9-]{2,63}$")
_SEVERITY_RANK = {
    Severity.info: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}
_CONFIDENCE_RANK = {
    Confidence.low: 0,
    Confidence.medium: 1,
    Confidence.high: 2,
}
_SARIF_LEVEL = {
    Severity.critical: "error",
    Severity.high: "error",
    Severity.medium: "warning",
    Severity.low: "note",
    Severity.info: "note",
}


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    fail_on: FailThreshold = "off"
    minimum_confidence: Confidence = Confidence.low
    deny_rules: list[str] = Field(default_factory=list)
    ignore_rules: list[str] = Field(default_factory=list)

    @field_validator("deny_rules", "ignore_rules")
    @classmethod
    def _validate_rule_ids(cls, values: list[str]) -> list[str]:
        result: list[str] = []
        for value in values:
            normalized = value.strip().upper()
            if not _RULE_ID.fullmatch(normalized):
                raise ValueError(f"invalid rule ID: {value!r}")
            if normalized not in result:
                result.append(normalized)
        return result

    @model_validator(mode="after")
    def _rules_do_not_overlap(self) -> PolicyConfig:
        overlap = sorted(set(self.deny_rules) & set(self.ignore_rules))
        if overlap:
            raise ValueError(f"rules cannot be both denied and ignored: {', '.join(overlap)}")
        return self


class DiffFinding(BaseModel):
    fingerprint: str
    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    location: SourceLocation | None = None
    summary: str


class ReportDifference(BaseModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    analysis_kind: Literal["extension", "repository"]
    baseline_report_id: str
    current_report_id: str
    new_count: int
    unchanged_count: int
    resolved_count: int
    new_findings: list[DiffFinding] = Field(default_factory=list)
    unchanged_findings: list[DiffFinding] = Field(default_factory=list)
    resolved_findings: list[DiffFinding] = Field(default_factory=list)


class PolicyViolation(BaseModel):
    fingerprint: str
    rule_id: str
    severity: Severity
    confidence: Confidence
    reason: str


class PolicyEvaluation(BaseModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    passed: bool
    policy_source: str
    fail_on: FailThreshold
    minimum_confidence: Confidence
    baseline_used: bool
    total_findings: int
    considered_findings: int
    existing_findings: int
    ignored_findings: int
    violation_count: int
    violations: list[PolicyViolation] = Field(default_factory=list)


def _read_document(path: Path, *, maximum: int = _MAX_REPORT_BYTES) -> object:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise ValueError(f"cannot read {path}: {error}") from error
    if size > maximum:
        raise ValueError(f"{path} exceeds the {maximum}-byte input limit")
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON in {path}: {error}") from error


def load_report(path: Path) -> Report:
    document = _read_document(path)
    if not isinstance(document, dict):
        raise ValueError(f"report must be a JSON object: {path}")
    analysis_kind = document.get("analysis_kind")
    if analysis_kind == "extension":
        return AnalysisReport.model_validate(document)
    if analysis_kind == "repository":
        return RepositoryAnalysisReport.model_validate(document)
    raise ValueError(f"unsupported or missing analysis_kind in {path}")


def load_policy(path: Path) -> PolicyConfig:
    try:
        size = path.stat().st_size
        if size > 1024 * 1024:
            raise ValueError("policy exceeds the 1 MiB input limit")
        document = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"invalid policy file {path}: {error}") from error
    allowed_root = {"schema_version", "policy"}
    unknown_root = sorted(set(document) - allowed_root)
    if unknown_root:
        raise ValueError(f"unknown policy keys: {', '.join(unknown_root)}")
    raw_policy = document.get("policy")
    if not isinstance(raw_policy, dict):
        raise ValueError("policy file must contain a [policy] table")
    return PolicyConfig.model_validate({
        "schema_version": document.get("schema_version", "1"),
        **raw_policy,
    })


def _archive_prefix(report: Report) -> str | None:
    paths = [PurePosixPath(item.path.replace("\\", "/")) for item in report.files]
    if not paths or any(len(path.parts) < 2 for path in paths):
        return None
    roots = {path.parts[0] for path in paths}
    return next(iter(roots)) if len(roots) == 1 else None


def normalized_finding_path(report: Report, finding: Finding) -> str:
    if finding.location is None:
        return ""
    path = finding.location.file.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    path = path.lstrip("/")
    prefix = _archive_prefix(report)
    if prefix and path.startswith(f"{prefix}/"):
        path = path[len(prefix) + 1:]
    return str(PurePosixPath(path))


def finding_fingerprint(report: Report, finding: Finding) -> str:
    path = normalized_finding_path(report, finding)
    summary = " ".join(finding.evidence.summary.split())
    snippet = " ".join((finding.evidence.snippet or "").split())
    canonical = "\n".join((finding.rule_id, path.casefold(), summary, snippet))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _diff_finding(report: Report, finding: Finding) -> DiffFinding:
    location = finding.location.model_copy() if finding.location else None
    if location:
        location.file = normalized_finding_path(report, finding)
    return DiffFinding(
        fingerprint=finding_fingerprint(report, finding),
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        location=location,
        summary=finding.evidence.summary,
    )


def compare_reports(current: Report, baseline: Report) -> ReportDifference:
    if current.analysis_kind != baseline.analysis_kind:
        raise ValueError("baseline and current reports must have the same analysis_kind")
    baseline_buckets: dict[str, deque[DiffFinding]] = defaultdict(deque)
    for finding in baseline.findings:
        entry = _diff_finding(baseline, finding)
        baseline_buckets[entry.fingerprint].append(entry)

    new: list[DiffFinding] = []
    unchanged: list[DiffFinding] = []
    for finding in current.findings:
        entry = _diff_finding(current, finding)
        if baseline_buckets[entry.fingerprint]:
            baseline_buckets[entry.fingerprint].popleft()
            unchanged.append(entry)
        else:
            new.append(entry)
    resolved = [entry for bucket in baseline_buckets.values() for entry in bucket]
    return ReportDifference(
        analysis_kind=current.analysis_kind,
        baseline_report_id=baseline.report_id,
        current_report_id=current.report_id,
        new_count=len(new),
        unchanged_count=len(unchanged),
        resolved_count=len(resolved),
        new_findings=new,
        unchanged_findings=unchanged,
        resolved_findings=resolved,
    )


def evaluate_policy(
    report: Report,
    policy: PolicyConfig,
    *,
    baseline: Report | None = None,
    policy_source: str = "built-in",
) -> PolicyEvaluation:
    if baseline is not None:
        difference = compare_reports(report, baseline)
        considered = difference.new_findings
        existing_count = difference.unchanged_count
    else:
        considered = [_diff_finding(report, finding) for finding in report.findings]
        existing_count = 0

    denied = set(policy.deny_rules)
    ignored = set(policy.ignore_rules)
    minimum_confidence = _CONFIDENCE_RANK[policy.minimum_confidence]
    threshold = None if policy.fail_on == "off" else _SEVERITY_RANK[Severity(policy.fail_on)]
    ignored_count = 0
    violations: list[PolicyViolation] = []
    for finding in considered:
        if finding.rule_id in ignored:
            ignored_count += 1
            continue
        reason: str | None = None
        if finding.rule_id in denied:
            reason = "rule is explicitly denied"
        elif (
            threshold is not None
            and _SEVERITY_RANK[finding.severity] >= threshold
            and _CONFIDENCE_RANK[finding.confidence] >= minimum_confidence
        ):
            reason = (
                f"severity is at least {policy.fail_on} and confidence is at least "
                f"{policy.minimum_confidence.value}"
            )
        if reason:
            violations.append(PolicyViolation(
                fingerprint=finding.fingerprint,
                rule_id=finding.rule_id,
                severity=finding.severity,
                confidence=finding.confidence,
                reason=reason,
            ))
    return PolicyEvaluation(
        passed=not violations,
        policy_source=policy_source,
        fail_on=policy.fail_on,
        minimum_confidence=policy.minimum_confidence,
        baseline_used=baseline is not None,
        total_findings=len(report.findings),
        considered_findings=len(considered),
        existing_findings=existing_count,
        ignored_findings=ignored_count,
        violation_count=len(violations),
        violations=violations,
    )


def _sarif_uri(path: str) -> str:
    return quote(path.replace("\\", "/"), safe="/._~-:@")


def _sarif_location(report: Report, finding: Finding) -> list[dict[str, object]]:
    if finding.location is None or not finding.location.file:
        return []
    physical: dict[str, object] = {
        "artifactLocation": {"uri": _sarif_uri(normalized_finding_path(report, finding))},
    }
    if finding.location.line:
        region: dict[str, int] = {"startLine": max(1, finding.location.line)}
        if finding.location.column:
            region["startColumn"] = max(1, finding.location.column)
        physical["region"] = region
    return [{"physicalLocation": physical}]


def report_to_sarif(report: Report, *, baseline: Report | None = None) -> dict[str, object]:
    if baseline is not None and baseline.analysis_kind != report.analysis_kind:
        raise ValueError("baseline and current reports must have the same analysis_kind")

    first_by_rule: dict[str, Finding] = {}
    for finding in report.findings:
        first_by_rule.setdefault(finding.rule_id, finding)
    ordered_rules = sorted(first_by_rule)
    rule_indices = {rule_id: index for index, rule_id in enumerate(ordered_rules)}
    rules = [
        {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": first_by_rule[rule_id].title},
            "fullDescription": {"text": first_by_rule[rule_id].description},
            "help": {
                "text": first_by_rule[rule_id].guidance,
                "markdown": first_by_rule[rule_id].guidance,
            },
            "defaultConfiguration": {"level": _SARIF_LEVEL[first_by_rule[rule_id].severity]},
            "properties": {"tags": first_by_rule[rule_id].tags},
        }
        for rule_id in ordered_rules
    ]

    baseline_fingerprints: dict[str, int] = defaultdict(int)
    if baseline is not None:
        for finding in baseline.findings:
            baseline_fingerprints[finding_fingerprint(baseline, finding)] += 1

    results: list[dict[str, object]] = []
    for finding in report.findings:
        fingerprint = finding_fingerprint(report, finding)
        locations = _sarif_location(report, finding)
        result: dict[str, object] = {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_indices[finding.rule_id],
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.title}. {finding.evidence.summary}"},
            "partialFingerprints": {
                "primaryLocationLineHash": fingerprint,
                "extensionXray/v1": fingerprint,
            },
            "properties": {
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "source": finding.source,
                "tags": finding.tags,
                "potentialImpact": finding.potential_impact,
            },
        }
        if locations:
            result["locations"] = locations
        if baseline is not None:
            if baseline_fingerprints[fingerprint] > 0:
                result["baselineState"] = "unchanged"
                baseline_fingerprints[fingerprint] -= 1
            else:
                result["baselineState"] = "new"
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Extension X-Ray",
                    "semanticVersion": __version__,
                    "informationUri": "https://github.com/caiocesar333/Extension-X-Ray",
                    "rules": rules,
                }
            },
            "automationDetails": {"id": f"extension-xray/{report.analysis_kind}"},
            "invocations": [{"executionSuccessful": True}],
            "results": results,
            "properties": {
                "reportId": report.report_id,
                "analysisKind": report.analysis_kind,
                "sourceFilename": report.source_filename,
                "artifactSha256": report.sha256,
            },
        }],
    }
