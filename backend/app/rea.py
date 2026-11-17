from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .config import ReaSettings
from .errors import XRayError
from .models import FileEntry, ModuleEdge, ModuleGraph, ModuleNode, ReaStatus

_MAX_OUTPUT_BYTES = 12 * 1024 * 1024


@dataclass(slots=True)
class ReaAnalysis:
    status: ReaStatus
    modules: ModuleGraph | None = None
    limitation: str | None = None


def _walk(value: Any, *, max_items: int = 50_000) -> Iterator[dict[str, Any]]:
    pending: list[Any] = [value]
    visited = 0
    while pending and visited < max_items:
        current = pending.pop()
        visited += 1
        if isinstance(current, dict):
            yield current
            pending.extend(current.values())
        elif isinstance(current, list):
            pending.extend(current)


def _first_string(document: Any, names: set[str]) -> str | None:
    for item in _walk(document):
        for name in names:
            value = item.get(name)
            if isinstance(value, str) and value:
                return value[:1_000]
    return None


def _extract_graph(document: Any) -> ModuleGraph | None:
    """Parse only explicitly identified REA graph nodes and edges.

    REA output is untrusted and versioned. Unknown shapes are ignored instead of
    guessing at their meaning.
    """
    graph: dict[str, Any] | None = None
    for item in _walk(document):
        candidate = item.get("graph")
        if isinstance(candidate, dict) and isinstance(candidate.get("nodes"), list):
            graph = candidate
            break
    if graph is None:
        return None

    nodes: dict[str, ModuleNode] = {}
    rea_to_report_id: dict[str, str] = {}
    for raw in graph.get("nodes", [])[:10_000]:
        if not isinstance(raw, dict):
            continue
        raw_id = raw.get("id") or raw.get("node_id")
        kind = raw.get("kind") or raw.get("type")
        properties = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
        path = raw.get("path") or properties.get("path")
        label = raw.get("label") or raw.get("name") or properties.get("name")
        if not isinstance(raw_id, str) or not isinstance(kind, str):
            continue
        kind_text = kind.lower()
        if not any(token in kind_text for token in ("module", "source", "javascript", "asset")):
            continue
        if not isinstance(path, str):
            path = None
        if not isinstance(label, str):
            label = Path(path).name if path else kind
        report_id = f"rea-{raw_id}"[:300]
        rea_to_report_id[raw_id] = report_id
        nodes[report_id] = ModuleNode(
            id=report_id,
            label=label[:500],
            path=path[:1_000] if path else None,
            kind="rea",
        )

    edges: list[ModuleEdge] = []
    for raw in graph.get("edges", [])[:20_000]:
        if not isinstance(raw, dict):
            continue
        source = raw.get("source") or raw.get("from")
        target = raw.get("target") or raw.get("to")
        if source not in rea_to_report_id or target not in rea_to_report_id:
            continue
        relation = raw.get("specifier") or raw.get("kind") or raw.get("type") or "rea-relation"
        edges.append(
            ModuleEdge(
                source=rea_to_report_id[source],
                target=rea_to_report_id[target],
                specifier=str(relation)[:500],
            )
        )
    if not nodes:
        return None
    return ModuleGraph(nodes=list(nodes.values()), edges=edges, source="rea")


class ReaAdapter:
    def __init__(self, settings: ReaSettings | None = None) -> None:
        self.settings = settings or ReaSettings.from_env()
        self._probe: tuple[list[str] | None, str | None] | None = None

    def _command_prefix(self) -> list[str] | None:
        resolved = shutil.which(self.settings.command)
        if resolved is None:
            return None
        if os.name != "nt" or Path(resolved).suffix.lower() not in {".cmd", ".bat", ".ps1"}:
            return [resolved]
        # npm exposes command shims on Windows. CreateProcess cannot launch a
        # .cmd directly, while passing untrusted source paths through cmd.exe
        # would add shell parsing. The sibling PowerShell shim preserves argv.
        powershell = shutil.which("powershell.exe")
        ps1_launcher = Path(resolved).with_suffix(".ps1")
        if powershell and ps1_launcher.is_file():
            return [
                powershell,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ps1_launcher),
            ]
        return None

    def probe(self) -> tuple[list[str] | None, str | None]:
        if self._probe is not None:
            return self._probe
        if self.settings.mode == "disabled":
            self._probe = (None, None)
            return self._probe
        command = self._command_prefix()
        if command is None:
            self._probe = (None, None)
            return self._probe
        try:
            completed = subprocess.run(
                [*command, "--version"],
                capture_output=True,
                check=False,
                text=True,
                timeout=min(max(self.settings.timeout_seconds, 5.0), 15.0),
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except (OSError, subprocess.SubprocessError):
            self._probe = (None, None)
            return self._probe
        version = completed.stdout.strip()[:100] if completed.returncode == 0 else None
        self._probe = (command if version else None, version)
        return self._probe

    def status(self) -> ReaStatus:
        command, version = self.probe()
        if self.settings.mode == "disabled":
            return ReaStatus(
                available=False,
                used=False,
                status="disabled",
                message="REA integration was disabled by configuration.",
            )
        return ReaStatus(
            available=command is not None,
            used=False,
            status="available" if command else "unavailable",
            version=version,
            message=(
                "REA CLI is available for bounded static JavaScript analysis."
                if command
                else "REA CLI is unavailable; native static analysis remains active."
            ),
        )

    def analyze(self, root: Path, files: list[FileEntry]) -> ReaAnalysis:
        command, version = self.probe()
        if self.settings.mode == "disabled":
            return ReaAnalysis(status=self.status())
        if command is None:
            if self.settings.mode == "required":
                raise XRayError("rea_unavailable", "REA is required but its CLI is unavailable", status_code=503)
            return ReaAnalysis(
                status=self.status(),
                limitation="REA enrichment was unavailable; the report uses the independent native scanner.",
            )

        candidates = [
            entry.path
            for entry in files
            if entry.kind in {"javascript", "typescript", "json"} and entry.size <= 2 * 1024 * 1024
        ]
        selected = candidates[: self.settings.max_source_files]
        if not selected:
            return ReaAnalysis(
                status=ReaStatus(
                    available=True,
                    used=False,
                    status="not_applicable",
                    version=version,
                    message="REA found no bounded JavaScript, TypeScript, or JSON source files to analyze.",
                )
            )

        args = [
            *command,
            "analyze-javascript-application",
            str(root.resolve()),
            "--artifact-format",
            "directory",
            "--integrity-policy",
            "fail",
            "--max-heap-mb",
            "256",
            "--analysis-timeout-ms",
            str(max(1, int(self.settings.timeout_seconds * 800))),
            "--max-semantic-nodes",
            "4000",
            "--max-semantic-nodes-per-file",
            "1000",
            "--max-semantic-unknowns",
            "4000",
            "--max-semantic-unknowns-per-file",
            "1000",
        ]
        for path in selected:
            args.extend(("--source-path", path))
        args.extend(("--format", "json"))
        try:
            completed = subprocess.run(
                args,
                capture_output=True,
                check=False,
                timeout=self.settings.timeout_seconds,
                shell=False,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
        except subprocess.TimeoutExpired:
            return self._failure(version, "timeout", "REA timed out; native static analysis was retained.")
        except OSError:
            return self._failure(version, "error", "REA could not be started; native static analysis was retained.")

        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()
            suffix = f" ({detail[-1][:240]})" if detail else ""
            return self._failure(version, "error", f"REA analysis failed{suffix}; native analysis was retained.")
        if len(completed.stdout) > _MAX_OUTPUT_BYTES:
            return self._failure(version, "output_limit", "REA output exceeded the parsing limit; native analysis was retained.")
        try:
            document = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._failure(version, "invalid_output", "REA returned invalid JSON; native analysis was retained.")

        evidence_id = _first_string(document, {"evidence_id", "parent_evidence_id"})
        graph = _extract_graph(document)
        message = "REA completed bounded static analysis without executing extension code."
        if len(candidates) > len(selected):
            message += f" Source selection was capped at {len(selected)} files."
        return ReaAnalysis(
            status=ReaStatus(
                available=True,
                used=True,
                status="completed",
                version=version,
                message=message,
                evidence_id=evidence_id,
                analyzed_files=len(selected),
            ),
            modules=graph,
            limitation=(
                f"REA source selection was capped at {len(selected)} of {len(candidates)} eligible files."
                if len(candidates) > len(selected)
                else None
            ),
        )

    @staticmethod
    def _failure(version: str | None, status: str, message: str) -> ReaAnalysis:
        return ReaAnalysis(
            status=ReaStatus(
                available=True,
                used=False,
                status=status,
                version=version,
                message=message,
            ),
            limitation=message,
        )

