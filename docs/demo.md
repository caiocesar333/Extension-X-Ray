# Reproducible demo

## Generate fixtures

From the repository root after backend installation:

```powershell
.\.venv\Scripts\python .\samples\generate_fixtures.py
```

The generator creates two local fixtures. They contain no real credentials, live exfiltration destination, or harmful payload. `example.invalid` is reserved for documentation.

## CLI path

```powershell
.\.venv\Scripts\python -m app.cli .\samples\suspicious-extension.vsix --output .\reports\suspicious-report.json
.\.venv\Scripts\python -m app.cli .\samples\benign-extension.vsix --no-rea --output .\reports\benign-fallback-report.json
```

Expected suspicious report observations:

- metadata for `synthetic-suspicious-extension`;
- source locations for process, dynamic execution, environment, network, and sensitive-path rules;
- explicit combination findings without claiming maliciousness;
- a genuine REA completion/status when the CLI is available, otherwise an explicit fallback limitation;
- a valid `1.0.0` report that round-trips through `AnalysisReport`.

Expected benign report observations:

- metadata, file inventory, hash, and module reference to `vscode`;
- zero security-rule matches for the synthetic source;
- `rea.status=disabled`, proving native fallback is independently usable.

## Dashboard path

Start both development servers as documented in the README, open `http://localhost:5173`, and upload `samples/suspicious-extension.vsix`.

Manual checks:

1. Upload progress is visible and the extension summary appears.
2. Severity distribution and counts match the findings table.
3. Selecting a finding shows its exact evidence, location, impact, and guidance.
4. File search filters the inventory.
5. The dependency tab renders a static module graph.
6. Download JSON produces the same report contract.
7. At narrow viewport width, cards and evidence stack without horizontal page overflow.

