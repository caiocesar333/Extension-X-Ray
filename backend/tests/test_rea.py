from __future__ import annotations

import json
import subprocess
from pathlib import Path

from app.config import ReaSettings
from app.models import FileEntry
from app.rea import ReaAdapter


def test_rea_probe_honors_bounded_configured_timeout(monkeypatch) -> None:
    adapter = ReaAdapter(ReaSettings(mode="auto", timeout_seconds=25))
    observed: dict[str, float] = {}
    monkeypatch.setattr(adapter, "_command_prefix", lambda: ["rea"])

    def fake_run(*args, **kwargs):
        observed["timeout"] = kwargs["timeout"]
        return subprocess.CompletedProcess(args[0], 0, "6.7.0\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert adapter.probe()[1] == "6.7.0"
    assert observed["timeout"] == 25


def test_rea_adapter_parses_only_structured_graph_output(monkeypatch, tmp_path: Path) -> None:
    adapter = ReaAdapter(ReaSettings(mode="auto", timeout_seconds=5))
    monkeypatch.setattr(adapter, "probe", lambda: (["rea"], "6.7.0"))
    evidence_id = "ev_" + "a" * 64
    payload = {
        "evidence_id": evidence_id,
        "normalized_result": {
            "graph": {
                "nodes": [
                    {"id": "one", "kind": "javascript-module", "path": "extension/index.js", "label": "index.js"},
                    {"id": "ignored", "kind": "unrelated-record", "label": "ignore me"},
                ],
                "edges": [],
            }
        },
    }
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, json.dumps(payload).encode(), b""),
    )
    source = tmp_path / "extension" / "index.js"
    source.parent.mkdir(parents=True)
    source.write_text("exports.activate = () => undefined", encoding="utf-8")

    result = adapter.analyze(
        tmp_path,
        [
            FileEntry(
                path="extension/index.js",
                size=source.stat().st_size,
                compressed_size=10,
                sha256="b" * 64,
                kind="javascript",
            )
        ],
    )

    assert result.status.used is True
    assert result.status.evidence_id == evidence_id
    assert result.modules is not None
    assert [node.path for node in result.modules.nodes] == ["extension/index.js"]

