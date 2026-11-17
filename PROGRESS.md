# Extension X-Ray progress

Updated: 2026-11-17

## Plan

- [x] Inspect the repository, runtime, and installed REA capabilities.
- [x] Implement secure VSIX ingestion, metadata parsing, static rules, reports, and API.
- [x] Implement the React/Tailwind dashboard and JSON export.
- [x] Add synthetic fixtures, backend/frontend tests, and documentation.
- [x] Run the complete validation matrix and resolve failures.

## Environment observations

- Repository started with only `TASK.md` and empty product directories.
- Python 3.15 is available through `py -3.15` (the plain `python` command is 3.11).
- Node.js 24.21.0 and npm 11.19.0 are available.
- REA CLI 6.7.0 is installed and its `analyze-javascript-application` command and schema were verified.
- REA MCP 6.7.0 is connected and exposes 207 tools. A read-only `binary_session` call succeeded. The application uses the verified CLI command because a standalone FastAPI process is not an MCP client; it retains an explicit native fallback.
- Static JavaScript analysis does not require Hopper or Ghidra. Those native providers are not installed and are not needed for VSIX source analysis.

## Security decisions

- Uploaded extensions are never executed and package managers/lifecycle scripts are never invoked.
- REA receives only an already validated, bounded, temporary extraction tree.
- Archive extraction is manual, path-contained, size-limited, duplicate-aware, and rejects links/special entries.
- REA output is treated as untrusted data and only bounded, recognized fields are used.

## Validation log

- Python syntax compilation: passed on Python 3.15.2.
- Backend: `20 passed` on Python 3.15.2. One upstream Starlette warning notes that its `TestClient` still uses the deprecated `httpx` integration.
- Frontend typecheck: passed.
- Frontend ESLint: passed.
- Frontend Vitest: `4 passed` across 3 files.
- Frontend production build: passed with Vite 6.4.6; output is approximately 173 kB JavaScript / 18 kB CSS before gzip.
- Generated both synthetic VSIX fixtures locally.
- Suspicious fixture: schema 1.0.0 validated, 8 native findings, REA 6.7.0 status `completed`, genuine CLI Evidence ID retained.
- Benign fixture with `--no-rea`: schema 1.0.0 validated, zero findings, REA status `disabled`.
- REA MCP smoke test: parsed 1 JavaScript file from 2 selected sources without execution, reported 6 findings and 17 bounded semantic unknowns. Summary Evidence: `ev_3b5e6f500459c67e4604687dbbd831c14480d9bbcebe60435a9e052679ae1fb7`; parent analysis Evidence: `ev_6008c9c0fd07fe62cb5fee5cce697b5ac89fc1d78b9d0fa146e781b1a307f09c`.
- JSON reports were round-tripped through the Pydantic `AnalysisReport` model.
- Full HTTP upload smoke test: `200`, schema 1.0.0, 8 findings, and REA status `completed` for the suspicious fixture.

## Remaining limitations

- Static evidence does not establish runtime reachability or intent.
- Native regex rules are deliberately independent from REA and can produce false positives or negatives.
- REA reported partial semantic-family coverage for the synthetic suspicious source; those unknowns are not promoted to findings.
- Native binaries inside VSIX packages are inventoried but not decompiled in this MVP.

