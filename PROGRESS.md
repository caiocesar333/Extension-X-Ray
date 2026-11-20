# Extension X-Ray progress

Updated: 2026-11-20

## v0.2.0 plan

- [x] Preserve the complete v0.1.0 VSIX analysis and API flow.
- [x] Add safe repository ZIP ingestion, metadata, API, CLI, and report schema.
- [x] Detect package lifecycle, download/execute, GitHub Actions, VS Code, and dev-container risks.
- [x] Add Crypto Guard rules with sensitive-evidence redaction and correlation findings.
- [x] Add a typed repository dashboard mode and JSON export.
- [x] Add benign/suspicious repository fixtures and backend/frontend regression coverage.
- [x] Update version metadata, security boundaries, architecture, rule catalog, and demo instructions.
- [x] Run the complete validation matrix and resolve failures.

## Delivered behavior

- `POST /api/v1/analyze` remains the VSIX endpoint; `POST /api/v1/analyze-repository` accepts repository ZIPs.
- Both analyzers use the same bounded, contained ZIP extraction and temporary cleanup path.
- Repository metadata inventories ecosystems, manifests, package manager, scripts, declared dependency count, workflows, and workspace/automation configuration.
- Repository rules cover npm lifecycle hooks, direct download-to-interpreter commands, privileged/injectable workflows, mutable Actions, VS Code tasks, and dev-container lifecycle commands.
- Crypto Guard covers wallet storage paths, possible private material, wallet/network colocation, and clipboard address replacement. Possible key or recovery-phrase evidence is redacted before report output.
- Repository source and REA scopes exclude `.git` and `node_modules`; the tool never runs package managers, hooks, submodules, builds, tests, or uploaded code.
- The dashboard selects VSIX or repository mode and renders artifact-specific metadata through a discriminated TypeScript report union.
- Application/backend/frontend version metadata is `0.2.0`; JSON report schema remains `1.0.0` with an `analysis_kind` discriminator.

## Environment observations

- Python 3.15 is available through `py -3.15`; plain `python` is 3.11 and is not compatible with the installed local Python 3.15 dependency binaries.
- Node.js 24.21.0 and npm 11.19.0 are available.
- REA CLI 6.7.0 is installed. On this host, even the version probe can approach 15 seconds; the probe now honors explicitly configured timeouts up to a bounded 30-second ceiling.
- REA MCP 6.7.0 was previously verified as connected with a harmless read-only operation. The standalone FastAPI application correctly uses the local CLI adapter because it is not an MCP client.

## Validation log

- Python syntax compilation: passed for backend, tests, and fixture generator on Python 3.15.
- Backend: `26 passed` with one upstream Starlette `TestClient`/`httpx` deprecation warning.
- Frontend TypeScript typecheck: passed.
- Frontend ESLint: passed.
- Frontend Vitest: `6 passed` across 3 files.
- Frontend production build: passed with Vite 6.4.6; output was 175.12 kB JavaScript and 18.07 kB CSS before gzip.
- Generated four local synthetic fixtures: benign/suspicious VSIX and benign/suspicious repository ZIP.
- Suspicious VSIX CLI analysis: 8 findings; REA 6.7.0 completed on 2 sources with Evidence ID `ev_94a8151b44016ad44eaf3ccb3e80ef2faea179dc7bc5f466c07a533540f12a58`.
- Suspicious repository CLI analysis: 16 findings; REA 6.7.0 completed on 6 sources with Evidence ID `ev_b55cdf3fe85a14a3df2950776fc7d65cf2ebf172a707207f6839a092097a06db`.
- Benign VSIX and repository analyses with `--no-rea`: zero findings and explicit `disabled` REA status.
- All four JSON reports validated through their Pydantic report models. The synthetic mnemonic-like value was absent from serialized repository findings.
- Full repository HTTP upload smoke test: `200`, `analysis_kind=repository`, 16 findings, and REA status `completed`/`used=true`.
- REA timeout fallback was also observed under intentional parallel contention; native findings remained intact.
- `git diff --check`: passed. Encoding and stale-reference scan found no product-source mojibake or obsolete client API names.

The successful REA smoke tests used `XRAY_REA_TIMEOUT_SECONDS=60` because this machine's CLI startup is unusually slow. The adapter's internal probe remains capped at 30 seconds and all analysis calls retain a hard configured timeout.

## Remaining limitations

- Static evidence does not establish runtime reachability, intent, or a complete data flow.
- Pattern rules can produce false positives and false negatives; repository findings require human review.
- Dependency CVE resolution, package provenance, and online reputation are outside the offline v0.2.0 scope.
- REA enriches JavaScript/TypeScript structure but does not replace native repository rules.
- Native binaries are inventoried but not decompiled in this release.
- A clean report is not a security guarantee.
