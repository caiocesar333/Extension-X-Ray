# Extension X-Ray progress

Updated: 2026-11-21

## v0.4.0 Supply Chain 2 plan

- [x] Build a bounded npm lockfile inventory without invoking a package manager.
- [x] Emit a downloadable CycloneDX 1.6 software bill of materials.
- [x] Validate direct dependency coverage, exact-version agreement, resolved origins, and strong SRI integrity.
- [x] Detect install-script, direct Git/URL/file/link/workspace, and conservative typosquatting signals.
- [x] Match locked npm versions against a bounded offline OSV snapshot.
- [x] Add GitHub Actions supply-chain correlations for broad permissions, OIDC, mutable Actions, and secret interpolation.
- [x] Add a typed Supply Chain dashboard with advisory context, metrics, component inventory, and BOM download.
- [x] Update fixtures, documentation, version metadata, report schema, and regression tests.
- [x] Run the complete backend/frontend, CLI, REA, JSON, redaction, build, and HTTP validation matrix.

## v0.4.0 delivered behavior

- `supply_chain.py` parses npm `package-lock.json` v1/v2/v3 within archive and output caps; it never installs, resolves, or executes a package.
- Repository reports use schema `1.1.0` and embed a CycloneDX 1.6 BOM with package URLs, scope, admitted lockfile provenance, and valid SHA-256/384/512 hashes when present. Unscoped components omit the optional CycloneDX `group` property instead of emitting `null`.
- Lockfile rules cover missing lockfiles, missing direct packages, exact manifest/lock disagreement, missing or invalid strong integrity, external artifact hosts, and dependencies marked with install scripts.
- Direct dependency rules cover Git, GitHub/GitLab/Bitbucket, HTTP(S), file, link, and workspace sources. The typo signal is deliberately limited to one edit or an adjacent transposition against a small curated package list and remains low confidence.
- Offline OSV matching supports enumerated versions and `SEMVER` events including `introduced`, `fixed`, `last_affected`, and `limit`. Missing, malformed, oversized, or capped databases produce explicit report limitations.
- The bundled snapshot is a clearly labeled, incomplete crypto-relevant seed containing `GHSA-r9p9-mrjm-926w` / `CVE-2020-28498` for `elliptic` before `6.5.4`; operators can supply a broader local JSON file through `XRAY_ADVISORY_DB`.
- GitHub Actions rules identify `permissions: write-all`, an OIDC write token combined with mutable Actions, and direct `secrets.*` interpolation into a `run` block.
- Supply-chain evidence redacts credential-bearing URLs and token/password assignments before summaries, snippets, or finding IDs are emitted.
- The dashboard exposes lockfile metrics, snapshot date and coverage, advisory matches, resolved components, and an independent `*.cdx.json` download.
- Application/backend/frontend metadata is `0.4.0`; the VSIX schema remains `1.0.0` for compatibility.

## Preserved baseline

- Safe bounded ZIP ingestion, SHA-256 identity, isolated temporary extraction, cleanup, and no artifact execution.
- VSIX capability rules plus repository lifecycle, download/execute, GitHub Actions, VS Code, dev-container, and Crypto Guard 2 analysis.
- Optional bounded REA enrichment with an independent native fallback.
- Typed VSIX/repository dashboard, evidence viewer, inventory, dependency graph, and full-report JSON export.
- Package managers, hooks, submodules, builds, tests, workflows, and uploaded code are never executed.

## Environment observations

- Python 3.15 is available in `.venv`; plain system Python remains unsuitable for the installed local binary dependencies.
- Node.js 24.21.0, npm 11.19.0, and Vite 6.4.6 are available.
- REA CLI 6.7.0 completed the bounded suspicious-repository analysis. The standalone FastAPI service uses the verified CLI adapter and does not require the MCP connection.
- The managed Windows sandbox blocks Python-created temporary directories and esbuild subprocesses. The affected validation commands were rerun outside that sandbox without changing application behavior.

## v0.4.0 validation log

- Python syntax compilation: passed for backend, tests, and the fixture generator.
- Backend: `49 passed`; the only warning is the upstream Starlette `TestClient`/`httpx` deprecation.
- Frontend TypeScript typecheck and ESLint: passed.
- Frontend Vitest: `7 passed` across 3 files.
- Frontend production build: passed; 1,584 modules transformed, with 180.99 kB JavaScript and 19.16 kB CSS before gzip.
- Regenerated benign/suspicious VSIX and repository ZIP fixtures.
- Suspicious VSIX analysis: 8 findings; benign VSIX fallback: zero findings.
- Suspicious repository analysis: 27 findings, 3 SBOM components, 2 valid integrity hashes, 1 missing integrity value, 1 external origin, 1 install-script package, and 1 offline advisory match.
- REA 6.7.0 completed the suspicious repository scan on 7 sources with Evidence ID `ev_5cbb2c87dc5fcc2ac1eab01a2a12803322701b95f69223041767ec5c3b81e5fd`.
- Benign repository fallback analysis: zero findings, 1 SBOM component, and no advisory matches.
- All four JSON reports round-tripped through their Pydantic models. The synthetic recovery phrase, encoded key, registry password, and registry token were absent from serialized findings/reports.
- HTTP smoke test: health `200` with version `0.4.0`; repository upload `200`, schema `1.1.0`, 27 findings, 3 SBOM components, and REA `completed`/`used=true`.

## Remaining limitations

- Static evidence does not establish runtime reachability, malicious intent, or complete interprocedural data flow.
- Crypto propagation remains intra-file and syntax-bounded; object properties, callbacks, reflection, dynamic dispatch, and cross-module state may not resolve.
- CycloneDX components describe lockfile records and hashes, not independently downloaded or verified artifacts.
- The bundled OSV seed is intentionally incomplete and will become stale; production use requires a maintained offline database and an explicit refresh process.
- Advisory matching supports exact semantic versions and common OSV `SEMVER` events, not every ecosystem-specific version edge case.
- Registry ownership, npm provenance attestations, signatures, maintainer reputation, and online revocation are not checked.
- Typosquatting and pattern rules can produce false positives or false negatives and always require human review.
- REA enriches JavaScript/TypeScript structure but does not replace native rules; native binaries are inventoried but not decompiled.
- A clean report is not a security guarantee.
