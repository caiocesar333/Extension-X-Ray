from __future__ import annotations

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from .analyzer import _merge_graphs
from .archive import SafeVsixInspector
from .config import ArchiveLimits
from .models import FileEntry, RepositoryAnalysisReport, Severity
from .rea import ReaAdapter
from .repository_metadata import read_repository_metadata
from .repository_scanner import scan_repository
from .scanner import scan_sources

_MAX_COMBINED_FINDINGS = 500


def _source_scope(files: list[FileEntry]) -> list[FileEntry]:
    return [
        entry
        for entry in files
        if "node_modules" not in PurePosixPath(entry.path).parts
        and ".git" not in PurePosixPath(entry.path).parts
    ]


class RepositoryAnalyzer:
    def __init__(
        self,
        *,
        limits: ArchiveLimits | None = None,
        rea: ReaAdapter | None = None,
    ) -> None:
        self.limits = limits or ArchiveLimits.from_env()
        self.inspector = SafeVsixInspector(
            self.limits,
            artifact_label="repository ZIP",
            malformed_code="malformed_repository",
            archive_format="repository ZIP",
        )
        self.rea = rea or ReaAdapter()

    def analyze(self, archive_path: Path, source_filename: str | None = None) -> RepositoryAnalysisReport:
        filename = source_filename or archive_path.name
        with tempfile.TemporaryDirectory(prefix="repo-xray-") as temporary:
            root = Path(temporary) / "repository"
            extracted = self.inspector.extract(archive_path, root)
            scoped_files = _source_scope(extracted.files)
            metadata = read_repository_metadata(root, extracted.files, filename, self.limits)
            native = scan_sources(root, scoped_files)
            repository_scan = scan_repository(root, extracted.files)
            rea_result = self.rea.analyze(root, scoped_files)
            unique_findings = {finding.id: finding for finding in (*native.findings, *repository_scan.findings)}
            severity_order = {Severity.critical: 0, Severity.high: 1, Severity.medium: 2, Severity.low: 3, Severity.info: 4}
            all_findings = sorted(
                unique_findings.values(),
                key=lambda finding: (
                    severity_order[finding.severity],
                    finding.location.file if finding.location else "",
                    finding.location.line if finding.location and finding.location.line else 0,
                    finding.rule_id,
                ),
            )
            limitations = [*native.limitations, *repository_scan.limitations]
            findings = all_findings[:_MAX_COMBINED_FINDINGS]
            if len(all_findings) > len(findings):
                limitations.append(
                    f"Combined repository findings were capped at {_MAX_COMBINED_FINDINGS} results."
                )
            if rea_result.limitation:
                limitations.append(rea_result.limitation)
            limitations.extend((
                "Repository analysis is static and cannot prove runtime reachability or malicious intent.",
                "Crypto Guard flow tracking is bounded, intra-file, and limited to common JavaScript, TypeScript, and Python assignment/call forms.",
                "Package managers, lifecycle scripts, hooks, submodules, builds, tests, and repository code were not executed.",
                "Known-vulnerability and online reputation data are outside the current offline analysis scope.",
            ))
            counts = {severity: 0 for severity in Severity}
            for finding in findings:
                counts[finding.severity] += 1
            return RepositoryAnalysisReport(
                report_id=str(uuid.uuid4()),
                generated_at=datetime.now(UTC),
                source_filename=filename[:500],
                sha256=extracted.sha256,
                repository=metadata,
                archive=extracted.archive,
                severity_counts=counts,
                findings=findings,
                files=extracted.files,
                modules=_merge_graphs(native.modules, rea_result.modules),
                rea=rea_result.status,
                limitations=limitations,
            )

