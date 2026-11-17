from __future__ import annotations

import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .archive import SafeVsixInspector
from .config import ArchiveLimits
from .metadata import read_extension_metadata
from .models import AnalysisReport, ModuleGraph, Severity
from .rea import ReaAdapter
from .scanner import scan_sources


def _merge_graphs(native: ModuleGraph, enriched: ModuleGraph | None) -> ModuleGraph:
    if enriched is None:
        return native
    nodes = {node.id: node for node in (*native.nodes, *enriched.nodes)}
    edges = {
        (edge.source, edge.target, edge.specifier): edge
        for edge in (*native.edges, *enriched.edges)
    }
    return ModuleGraph(nodes=list(nodes.values()), edges=list(edges.values()), source="native+rea")


class ExtensionAnalyzer:
    def __init__(
        self,
        *,
        limits: ArchiveLimits | None = None,
        rea: ReaAdapter | None = None,
    ) -> None:
        self.limits = limits or ArchiveLimits.from_env()
        self.inspector = SafeVsixInspector(self.limits)
        self.rea = rea or ReaAdapter()

    def analyze(self, vsix_path: Path, source_filename: str | None = None) -> AnalysisReport:
        with tempfile.TemporaryDirectory(prefix="extension-xray-") as temporary:
            root = Path(temporary) / "extension"
            extracted = self.inspector.extract(vsix_path, root)
            metadata = read_extension_metadata(root, extracted.files, self.limits)
            native = scan_sources(root, extracted.files)
            rea_result = self.rea.analyze(root, extracted.files)
            limitations = list(native.limitations)
            if rea_result.limitation:
                limitations.append(rea_result.limitation)
            limitations.extend(
                (
                    "Static analysis cannot prove runtime reachability or malicious intent.",
                    "Dependencies referenced by the extension are inventoried but not installed or executed.",
                )
            )
            counts = {severity: 0 for severity in Severity}
            for finding in native.findings:
                counts[finding.severity] += 1
            return AnalysisReport(
                report_id=str(uuid.uuid4()),
                generated_at=datetime.now(UTC),
                source_filename=(source_filename or vsix_path.name)[:500],
                sha256=extracted.sha256,
                extension=metadata,
                archive=extracted.archive,
                severity_counts=counts,
                findings=native.findings,
                files=extracted.files,
                modules=_merge_graphs(native.modules, rea_result.modules),
                rea=rea_result.status,
                limitations=limitations,
            )

