# Reproducible demo

## Generate fixtures

From the repository root after backend installation:

```powershell
.\.venv\Scripts\python .\samples\generate_fixtures.py
```

The generator creates benign and suspicious VSIX files plus benign and suspicious repository ZIPs. They contain no real credentials, live exfiltration destination, or harmful payload. `example.invalid` is reserved for documentation, and the mnemonic-like text is synthetic.

## CLI path

```powershell
.\.venv\Scripts\python -m app.cli .\samples\suspicious-extension.vsix --output .\reports\suspicious-extension.json
.\.venv\Scripts\python -m app.cli .\samples\benign-extension.vsix --no-rea --output .\reports\benign-extension.json
.\.venv\Scripts\python -m app.cli .\samples\suspicious-repository.zip --kind repository --output .\reports\suspicious-repository.json
.\.venv\Scripts\python -m app.cli .\samples\benign-repository.zip --kind repository --no-rea --output .\reports\benign-repository.json
```

Expected suspicious repository observations:

- `analysis_kind=repository` and metadata for `synthetic-crypto-stealer-patterns`;
- critical lifecycle download/execution and privileged-workflow signals;
- mutable Action, VS Code task, and dev-container findings;
- wallet-path, wallet/network, clipboard, and redacted possible-secret findings;
- Crypto Guard 2 evidence for an encoded key, wallet environment access, alias-based network flow, and process-argument flow;
- a CycloneDX 1.6 BOM with three npm components, lockfile integrity/provenance metrics, a conservative typo signal, and an offline OSV match for the synthetic `elliptic@6.5.3` dependency;
- explicit REA completion when available, otherwise a fallback limitation;
- a valid repository schema `1.1.0` report that round-trips through `RepositoryAnalysisReport`.

Expected benign repository observations:

- JavaScript/npm ecosystem and manifest inventory;
- the Action reference is an immutable synthetic full SHA;
- zero repository security-rule matches;
- `rea.status=disabled`, proving the native fallback works independently.

The VSIX fixtures preserve the original analyzer behavior: the suspicious sample produces process, dynamic execution, environment, network, sensitive-path, and combination evidence, while the benign sample produces no findings.

## CI Guard path

Generate a SARIF file and observe policy exit code `1` for the suspicious repository:

```powershell
.\.venv\Scripts\python -m app.cli .\samples\suspicious-repository.zip --kind repository --no-rea --output .\reports\ci-report.json --sarif .\reports\ci-report.sarif --policy .\examples\extension-xray.toml --policy-output .\reports\policy.json
$LASTEXITCODE
```

Use the generated report as its own baseline and verify that the same findings no longer fail the policy:

```powershell
.\.venv\Scripts\python -m app.cli .\reports\ci-report.json --kind report --baseline .\reports\ci-report.json --diff-output .\reports\ci-diff.json --policy .\examples\extension-xray.toml --policy-output .\reports\baselined-policy.json
$LASTEXITCODE
```

Expected values are exit code `1` for the first command and `0` for the baselined comparison, with `new_count=0` and `resolved_count=0` in `ci-diff.json`.

## Dashboard path

Start both development servers from the README and open `http://localhost:5173`.

Manual checks:

1. In **Extension VSIX** mode, upload `samples/suspicious-extension.vsix` and confirm the extension summary.
2. Start a new scan, select **Repository ZIP**, and upload `samples/suspicious-repository.zip`.
3. Confirm repository name, dependency/workflow metrics, ecosystem/script tags, and severity counts.
4. Select findings and verify exact evidence, source location, impact, and guidance; the possible mnemonic must be redacted.
5. Search the inventory and inspect the dependency tab.
6. Download JSON and verify that `analysis_kind` and artifact-specific metadata are preserved.
7. At a narrow viewport width, confirm cards and evidence stack without horizontal page overflow.

Do not install dependencies or run any script from the suspicious fixture. The application does not require doing so.
