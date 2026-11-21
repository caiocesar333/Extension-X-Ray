# Extension X-Ray

Extension X-Ray v0.4.0 is a local-first static security analyzer for two artifact types:

- Visual Studio Code and Cursor `.vsix` packages;
- source repository `.zip` archives, including install hooks, GitHub Actions, editor/dev-container automation, and crypto-wallet risk patterns.

It produces evidence-backed reports without executing uploaded code, installing dependencies, running hooks, checking out submodules, or sending source to a remote service. Findings describe observed behavior and confidence; there is deliberately no generic “trust score.”

## What v0.4.0 includes

- Bounded ZIP extraction with traversal, link, duplicate-path, entry-count, file-size, decompression, and compression-ratio defenses.
- SHA-256 identity, bounded metadata, complete admitted-file inventory, and literal JavaScript/TypeScript module relationships.
- Existing VSIX capability rules for process creation, dynamic execution, sensitive paths, environment access, network APIs, obfuscation, and dangerous combinations.
- Repo X-Ray rules for npm lifecycle scripts, download-to-interpreter commands, privileged or injectable GitHub Actions, mutable action references, VS Code tasks, and dev-container lifecycle commands.
- Crypto Guard 2 with bounded intra-file JavaScript/TypeScript/Python flow tracking through aliases and transformations into network or process sinks.
- Wallet-family paths for Bitcoin, Ethereum, Solana, Electrum, Exodus, Atomic Wallet, and common browser wallets; encoded-key and wallet-environment signals.
- Clipboard replacement requires a cryptocurrency address or address-bearing variable to reach the write call; possible secret evidence is redacted across all scanners.
- Supply Chain 2 generates a CycloneDX 1.6 SBOM from npm lockfiles, validates resolved versions and strong SRI hashes, and highlights install scripts, external registries, direct URL/Git dependencies, and conservative typo candidates.
- Offline OSV advisory matching supports enumerated versions and `SEMVER` ranges. The bundled crypto-focused seed snapshot is deliberately marked incomplete and can be replaced with `XRAY_ADVISORY_DB`.
- GitHub Actions supply-chain correlations cover `permissions: write-all`, OIDC credentials combined with mutable Actions, and direct secret interpolation into scripts.
- Hardening for valid seed-phrase word counts, same-job GitHub Actions correlation, multiline workflow injection, bounded combined findings, artifact-specific errors, and visible upload rejection.
- Optional REA 6.7 static JavaScript enrichment with strict timeouts, bounded source selection, structured parsing, and independent native fallback.
- Responsive React/Tailwind dashboard with VSIX/repository modes, severity context, evidence, inventory, dependency graph, and JSON download.
- Synthetic benign and suspicious fixtures plus backend and frontend regression tests.

## Requirements

- Python 3.13 or newer
- Node.js 20 or newer and npm
- Optional: REA CLI 6.7 (`rea`) for JavaScript enrichment

No package manager is invoked for uploaded artifacts. No native disassembler is required for JavaScript/TypeScript source analysis.

## Install

From the repository root on PowerShell:

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python -m pip install -e ".\backend[dev]"
Set-Location frontend
npm install
Set-Location ..
```

On macOS/Linux, use an available Python 3.13+ interpreter and `.venv/bin/python`.

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

Open `http://localhost:5173`. Select **Extension VSIX** or **Repository ZIP** before uploading. Vite proxies `/api` to `http://127.0.0.1:8000`.

## Reproduce the demo

```powershell
.\.venv\Scripts\python .\samples\generate_fixtures.py
.\.venv\Scripts\python -m app.cli .\samples\suspicious-extension.vsix --output .\reports\suspicious-extension.json
.\.venv\Scripts\python -m app.cli .\samples\benign-extension.vsix --no-rea --output .\reports\benign-extension.json
.\.venv\Scripts\python -m app.cli .\samples\suspicious-repository.zip --kind repository --output .\reports\suspicious-repository.json
.\.venv\Scripts\python -m app.cli .\samples\benign-repository.zip --kind repository --no-rea --output .\reports\benign-repository.json
```

REA is used when its verified CLI is available unless `--no-rea` is supplied. See [docs/demo.md](docs/demo.md) for expected observations and manual checks.

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
| `XRAY_ADVISORY_DB` | bundled curated snapshot | Local OSV JSON list or Extension X-Ray advisory envelope |
| `XRAY_MAX_ADVISORY_BYTES` | 10 MiB | Maximum offline advisory file size |
| `XRAY_MAX_ADVISORIES` | 50,000 | Maximum parsed advisory records |
| `XRAY_MAX_SBOM_COMPONENTS` | 2,000 | Maximum CycloneDX components in a report |
| `XRAY_CORS_ORIGINS` | `http://localhost:5173` | Comma-separated local origins |

## API

- `POST /api/v1/analyze` — multipart `file` containing a `.vsix`
- `POST /api/v1/analyze-repository` — multipart `file` containing a repository `.zip`
- `GET /api/v1/health` — service version and REA availability
- `GET /api/v1/report-schema` — VSIX report JSON Schema
- `GET /api/v1/repository-report-schema` — repository report JSON Schema
- `GET /docs` — interactive local OpenAPI documentation

The VSIX report remains schema `1.0.0`; the repository report is schema `1.1.0` with CycloneDX and supply-chain fields. Both include `analysis_kind` as a discriminator. The application version is `0.4.0`.

## Security model and limitations

The repository scanner is an offline first-pass reviewer, not a sandbox or malware verdict. Advisory results are limited by the configured snapshot; no registry, advisory, provenance, or reputation request occurs during analysis. Static evidence cannot prove reachability, intent, or an end-to-end data flow, and a clean result is not a guarantee. The interchange formats follow the [OSV schema](https://ossf.github.io/osv-schema/) and [CycloneDX 1.6 JSON specification](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json). See [SECURITY.md](SECURITY.md), [architecture](docs/architecture.md), and the [rule catalog](docs/security-rules.md).
