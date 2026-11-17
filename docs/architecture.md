# Architecture

## Data flow

1. The React client sends one `.vsix` as multipart data to the local FastAPI service.
2. The API streams the upload into an isolated temporary directory while enforcing the compressed limit.
3. `SafeVsixInspector` validates ZIP structure and manually expands each admitted member into a second isolated directory.
4. Metadata extraction reads only the bounded `extension/package.json` (or root fallback).
5. The native scanner reads bounded JavaScript/TypeScript sources, produces traceable findings, and reconstructs literal module imports.
6. In `auto` or `required` mode, the REA adapter gives the validated tree and exact bounded source list to `analyze-javascript-application`. It never executes the extension.
7. Recognized REA graph data is merged with, but never replaces, native results. Errors become explicit status and limitations.
8. Pydantic emits report schema `1.0.0`; the dashboard renders it and can download it unchanged.
9. Both temporary directories are removed when the request ends, including error paths.

## Backend modules

- `archive.py`: admission, containment, extraction, hashing, and inventory.
- `metadata.py`: bounded manifest normalization.
- `scanner.py`: native rules, evidence locations, capability combinations, dependency graph.
- `rea.py`: CLI discovery, timeout/resource arguments, output validation, graceful fallback.
- `analyzer.py`: orchestration and report construction.
- `main.py`: streaming HTTP boundary, API errors, CORS, health, and JSON Schema.
- `cli.py`: reproducible local report generation.

## Frontend modules

- `services/api.ts`: one typed API boundary and structured error handling.
- `UploadZone`: drag/drop and file selection.
- `SeverityOverview`: contextual distribution, not a trust score.
- `FindingsPanel` / `EvidenceViewer`: rule evidence and investigation guidance.
- `FileInventory`: searchable archive contents and hashes.
- `ModuleGraph`: bounded visual projection; complete data stays in JSON.

## Trust boundaries

The HTTP filename, ZIP metadata, manifest, source text, and REA output are untrusted. React text interpolation escapes displayed values. No untrusted HTML is injected. The only child process is the operator-installed REA CLI with fixed command structure and no shell.

