# Architecture

## Data flow

1. The React client selects VSIX or repository mode and sends one artifact to the matching local FastAPI endpoint.
2. The API streams the upload into an isolated temporary directory while enforcing the compressed-size limit.
3. The shared archive inspector validates ZIP structure and manually expands admitted members into a second isolated directory.
4. The selected analyzer reads bounded metadata: `extension/package.json` for VSIX or the shallowest non-`node_modules` `package.json` plus repository manifest inventory.
5. The native source scanner reads bounded JavaScript/TypeScript and reconstructs literal imports. Repository mode also scans package scripts, workflows, editor/dev-container configuration, shell patterns, and crypto-related correlations.
6. In `auto` or `required` mode, the REA adapter receives only the validated tree and bounded source list. It performs static JavaScript analysis; it does not run repository or extension code.
7. Recognized REA graph data is merged with, but never replaces, native results. Errors become explicit status and limitations.
8. Pydantic emits a discriminator-bearing report; the dashboard renders it and can download it unchanged.
9. Upload and extraction directories are removed when the request ends, including error paths.

```text
browser -> FastAPI upload boundary -> bounded ZIP extraction
                                      |-> VSIX metadata -> native scan -+
                                      |                                |-> report -> dashboard/JSON
                                      +-> repository metadata/rules ---+
                                                       |-> optional REA-+
```

## Backend modules

- `archive.py`: admission, containment, extraction, hashing, and inventory shared by both artifact types.
- `metadata.py`: bounded VSIX manifest normalization.
- `repository_metadata.py`: ecosystem, manifest, scripts, workflow, and workspace metadata.
- `scanner.py`: common source rules, evidence locations, capability combinations, and dependency graph.
- `repository_scanner.py`: supply-chain, CI, workspace automation, and Crypto Guard rules.
- `rea.py`: CLI discovery, timeout/resource arguments, output validation, and fallback.
- `analyzer.py` / `repository_analyzer.py`: artifact-specific orchestration and report construction.
- `main.py`: streaming HTTP boundary, API errors, CORS, health, and JSON Schemas.
- `cli.py`: reproducible local report generation selected by `--kind`.

## Frontend modules

- `services/api.ts`: typed endpoint selection and structured error handling.
- `UploadZone`: mode-aware drag/drop and file selection.
- `SeverityOverview`: contextual distribution, not a trust score.
- `FindingsPanel`: evidence and investigation guidance.
- `FileInventory`: searchable admitted archive contents and hashes.
- `ModuleGraph`: bounded visual projection; complete data stays in JSON.

## Trust boundaries

The HTTP filename, ZIP metadata, manifests, scripts, source text, workflow configuration, and REA output are untrusted. React interpolation escapes displayed values; no untrusted HTML is injected. The only child process is the operator-installed REA CLI with a fixed command structure and no shell. Package managers and artifact commands are never child processes.
