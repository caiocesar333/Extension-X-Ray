# Extension X-Ray

Extension X-Ray is a local-first static security analyzer for Visual Studio Code and Cursor extension packages. Upload a `.vsix` and it produces an evidence-backed report of security-relevant capabilities without executing extension code, installing its dependencies, or sending source to a remote service.

The report deliberately avoids a generic “trust score.” An API import can be legitimate; findings explain the observed pattern, confidence, context, impact, and what a reviewer should investigate.

## What the MVP includes

- Bounded, manual ZIP extraction with traversal, link, duplicate-path, entry-count, file-size, decompression, and compression-ratio defenses.
- SHA-256 identity, VSIX metadata, declared commands and dependencies, and a complete bounded file inventory.
- Native static rules for process creation, dynamic execution, sensitive paths, environment access, network APIs, transmission combinations, obfuscation, and download/execute combinations.
- Optional REA 6.7 static JavaScript enrichment with availability detection, strict timeouts, bounded source selection, structured parsing, and native fallback.
- Responsive React/Tailwind dashboard with severity context, findings and evidence, file inventory, dependency graph, and JSON download.
- Synthetic benign and suspicious fixtures; pytest and Vitest coverage for security boundaries, API behavior, fallback, components, and schema round-tripping.

## Requirements

- Python 3.13 or newer
- Node.js 20 or newer and npm
- Optional: REA CLI 6.7 (`rea`) for JavaScript enrichment

No native disassembler is required. Extension X-Ray never installs VSIX dependencies.

## Install

From the repository root on PowerShell:

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".\backend[dev]"
Set-Location frontend
npm install
Set-Location ..
```

On macOS/Linux, replace the Python commands with `python3.13 -m venv .venv` and `.venv/bin/python`.

## Run

Terminal 1:

```powershell
.\.venv\Scripts\python -m uvicorn app.main:app --app-dir backend --reload
```

Terminal 2:

```powershell
Set-Location frontend
npm run dev
```

Open `http://localhost:5173`. The Vite development server proxies `/api` to `http://127.0.0.1:8000`.

## Reproduce the demo

```powershell
.\.venv\Scripts\python .\samples\generate_fixtures.py
.\.venv\Scripts\python -m app.cli .\samples\suspicious-extension.vsix --output .\reports\suspicious-report.json
.\.venv\Scripts\python -m app.cli .\samples\benign-extension.vsix --no-rea --output .\reports\benign-fallback-report.json
```

The first report uses REA when the verified CLI is available. The second explicitly demonstrates the independent fallback. You can also upload either fixture in the dashboard. See [docs/demo.md](docs/demo.md) for the expected observations.

## Validation commands

```powershell
.\.venv\Scripts\python -m pytest backend
Set-Location frontend
npm run typecheck
npm run lint
npm run test -- --run
npm run build
```

## Configuration

All limits have secure defaults:

| Variable | Default | Purpose |
| --- | ---: | --- |
| `XRAY_MAX_UPLOAD_BYTES` | 25 MiB | Maximum compressed upload |
| `XRAY_MAX_ENTRIES` | 5,000 | Maximum ZIP members |
| `XRAY_MAX_FILE_BYTES` | 15 MiB | Maximum expanded member |
| `XRAY_MAX_UNCOMPRESSED_BYTES` | 100 MiB | Maximum total expansion |
| `XRAY_MAX_COMPRESSION_RATIO` | 200 | Per-file bomb heuristic |
| `XRAY_REA_MODE` | `auto` | `auto`, `disabled`, or `required` |
| `XRAY_REA_COMMAND` | `rea` | Existing REA executable |
| `XRAY_REA_TIMEOUT_SECONDS` | 15 | Hard adapter timeout |
| `XRAY_REA_MAX_SOURCE_FILES` | 150 | REA source-selection cap |
| `XRAY_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated local origins |

## API

- `POST /api/v1/analyze` — multipart field `file`, returning schema `1.0.0`
- `GET /api/v1/health` — service and REA availability
- `GET /api/v1/report-schema` — generated JSON Schema
- Interactive local documentation: `http://127.0.0.1:8000/docs`

## Security model and limitations

Static findings identify review-worthy capabilities, not intent or runtime reachability. Source files over the native scan limit are reported as limitations. REA analysis is also static; its Evidence identifier is retained only when present in genuine output. See [SECURITY.md](SECURITY.md), [architecture](docs/architecture.md), and the [rule catalog](docs/security-rules.md).

