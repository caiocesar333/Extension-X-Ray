# Extension X-Ray progress

Updated: 2026-11-21

## v0.2.1 hardening plan

- [x] Preserve the v0.2.0 VSIX/repository API and report contracts.
- [x] Reduce recovery-phrase false positives without exposing matching evidence.
- [x] Correlate privileged GitHub Actions behavior inside the same job.
- [x] Detect direct event interpolation in inline and multiline workflow scripts.
- [x] Add repository-specific archive errors and a combined finding limit.
- [x] Explain rejected frontend file types instead of silently ignoring them.
- [x] Add regression coverage, update documentation, and run the complete validation matrix.

## v0.2.1 delivered behavior

- `CRYPTO-SECRET-001` now requires a standard 12, 15, 18, 21, or 24-word phrase-like assignment; private-key markers remain independently detected. Evidence stays redacted.
- `REP-CI-001` now requires `actions/checkout`, a pull-request head ref, and a `run` step in the same job under `pull_request_target`, reducing cross-job false positives.
- `REP-CI-002` now inspects YAML block scripts such as `run: |` in addition to one-line commands.
- Repository reports retain the 500 highest-priority combined findings and record an explicit limitation when truncated.
- Malformed repository uploads now return `malformed_repository` and repository-specific text; the existing VSIX error contract is unchanged.
- Wrong `.vsix`/`.zip` selections now produce a visible dashboard alert without calling the API.
- Backend/frontend/package metadata is `0.2.1`; report schema remains `1.0.0` with the existing `analysis_kind` discriminator.

## Preserved v0.2.0 baseline

- Safe bounded ZIP ingestion, SHA-256 identity, temporary cleanup, and no artifact execution.
- VSIX static capabilities plus repository lifecycle, download/execute, GitHub Actions, VS Code, dev-container, wallet, network, and clipboard rules.
- Optional bounded REA enrichment with independent native fallback.
- Typed VSIX/repository dashboard, evidence viewer, inventory, module graph, and JSON export.
- Package managers, hooks, submodules, builds, tests, workflows, and uploaded code are never executed.

## Environment observations

- Python 3.15 is available through `py -3.15`; plain `python` is 3.11 and is incompatible with the installed local Python 3.15 dependency binaries.
- Node.js 24.21.0 and npm 11.19.0 are available.
- REA CLI 6.7.0 is installed. The standalone application uses its local CLI adapter; the previously verified MCP connection is not required by FastAPI.

## v0.2.1 validation log

- Python syntax compilation: passed for backend, tests, and fixture generator.
- Backend: `31 passed` with one upstream Starlette `TestClient`/`httpx` deprecation warning.
- Frontend TypeScript typecheck and ESLint: passed.
- Frontend Vitest: `7 passed` across 3 files.
- Frontend production build: passed with Vite 6.4.6; output was 175.20 kB JavaScript and 18.07 kB CSS before gzip.
- Generated benign/suspicious VSIX and repository ZIP fixtures.
- Suspicious VSIX fallback analysis: 8 findings; benign VSIX: zero findings.
- Suspicious repository analysis: 16 findings; REA 6.7.0 completed on 6 sources with Evidence ID `ev_5aceac9b47972cbbb3f4e9a3732442fe87107dd809c87f29ef7fb6ebb3ce629b`.
- Benign repository fallback analysis: zero findings.
- All four JSON reports validated through their Pydantic models; the synthetic recovery phrase was absent from serialized output.
- Regression coverage includes long-prose false positives, cross-job workflows, multiline injection, combined limits, repository errors, and frontend rejection behavior.

## Remaining limitations

- Static evidence does not establish runtime reachability, intent, or a complete data flow.
- Pattern rules can produce false positives and false negatives; repository findings require human review.
- Recovery-phrase detection validates shape and word count, not membership in a language-specific BIP-39 dictionary.
- Dependency CVE resolution, package provenance, and online reputation remain outside the offline v0.2.1 scope.
- REA enriches JavaScript/TypeScript structure but does not replace native repository rules.
- Native binaries are inventoried but not decompiled, and a clean report is not a security guarantee.
