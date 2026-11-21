# Extension X-Ray progress

Updated: 2026-11-21

## v1.0.0 stabilization plan

- [x] Declare the stable CLI, HTTP, report, policy, SARIF, rule-ID, fingerprint, exit-code, and no-execution surfaces.
- [x] Synchronize backend, package, frontend, lockfile, OpenAPI, health, and SARIF version metadata.
- [x] Constrain report models to the explicitly supported VSIX `1.0.0` and repository `1.1.0` schemas.
- [x] Preserve v0.5 report compatibility and fail closed for unknown report schema versions.
- [x] Add `extension-xray --version` and automated release-contract regression tests.
- [x] Add a least-privilege CI workflow with immutable Action pins and backend/frontend release gates.
- [x] Harden Python package metadata and verify the built wheel contents.
- [x] Remove known frontend test-toolchain advisories without changing application behavior.
- [x] Add changelog, compatibility policy, and repeatable release checklist.
- [x] Run the complete backend, frontend, package, fixture, REA, HTTP, CI-policy, baseline, SARIF, schema, and redaction matrix.

## v1.0.0 delivered behavior

- Application, backend package, frontend package, OpenAPI, health, CLI, and SARIF tool metadata now report `1.0.0`.
- `extension-xray --version` provides a scriptable version probe. The release test prevents backend, frontend, and lockfile versions from drifting.
- VSIX report schema `1.0.0` and repository report schema `1.1.0` remain unchanged from v0.5 and are now represented as literal backend and frontend contracts. Unknown versions are rejected during report loading.
- `docs/compatibility.md` defines the v1 public surface, independent document versioning, patch/minor/major evolution rules, rule-ID expectations, and the detection-results boundary.
- `CHANGELOG.md` records the delivered milestones, while `docs/release.md` defines preparation, verification, packaging, commit, and immutable-tag requirements.
- `.github/workflows/ci.yml` runs backend and frontend gates with read-only repository permissions, disabled checkout credential persistence, and full-SHA pins for every external Action.
- Python project metadata now includes stable-release classifiers, discovery keywords, and repository/documentation/issue links. The wheel retains the CLI entry point and bundled offline advisory snapshot.
- Vitest moved from 2.1.9 to 4.1.12. The new lock graph removes the vulnerable nested Vite/esbuild, mocker, and tinypool versions while retaining Node 20 compatibility.

## v1.0.0 validation log

- Backend: `67 passed`; the only warning is the upstream FastAPI/Starlette `TestClient` migration notice from `httpx` to `httpx2`.
- Editable package installation, `extension-xray --version`, package metadata version, and `pip check`: passed at `1.0.0`.
- Wheel build: passed; `extension_xray-1.0.0-py3-none-any.whl` contains 22 files, including the CLI metadata and bundled offline advisory database.
- Clean frontend `npm ci`: passed with Vitest `4.1.12`; `npm audit` reported zero vulnerabilities.
- Frontend TypeScript typecheck and ESLint: passed.
- Frontend Vitest: `7 passed` across 3 files.
- Frontend production build: passed; 1,584 modules transformed, with 180.99 kB JavaScript and 19.16 kB CSS before gzip.
- Suspicious VSIX: 8 findings; REA 6.7.0 completed on 2 sources with Evidence ID `ev_2318a9e313962df53e3a2e6026c05e1e1409d5c30aa610680775acc722c51d0e`.
- Suspicious repository: 27 findings and 3 SBOM components; REA 6.7.0 completed on 7 sources with Evidence ID `ev_a6db0566fe3fcfb26036338d5cae9bb25605a034b2696af36a6af011fed63d6e`.
- Benign VSIX and repository native-fallback analyses: zero findings.
- All four generated reports round-tripped through the strict Pydantic models; unknown schema versions failed closed in regression coverage.
- Synthetic recovery-phrase and encoded-key values were absent from the suspicious serialized reports.
- CI policy smoke: exit `1` after writing report, SARIF, and policy output; 17 violations from 27 considered findings.
- Baseline smoke: exit `0`, 0 new, 27 unchanged, 0 resolved, and no policy violations.
- Operational-error smoke: a missing report returned exit `2` with a bounded message.
- SARIF smoke: version 2.1.0, tool version `1.0.0`, 27 results, and 26 rule descriptors.
- HTTP smoke: health/schema endpoints and both upload routes returned `200`; health reported `1.0.0`, VSIX produced 8 findings, repository produced 27, and both suspicious uploads completed REA enrichment.
- The main frontend dev server kept its esbuild executable open, so its local `node_modules` could not be replaced atomically. The release lock was instead verified through a clean isolated `npm ci`, test, audit, and build without interrupting the user's server.

## v0.5.0 CI Guard plan

- [x] Emit SARIF 2.1.0 with rule metadata, archive-relative locations, and stable partial fingerprints.
- [x] Add bounded, versioned TOML policy with severity, confidence, deny-rule, and ignore-rule controls.
- [x] Compare current and baseline reports as new, unchanged, and resolved findings.
- [x] Apply policy only to new findings when a baseline is present without removing existing findings from JSON or SARIF.
- [x] Define stable CLI exit codes for pass, policy violation, and operational/configuration failure.
- [x] Support SARIF, diff, policy-result, and report-only CLI workflows.
- [x] Add a reusable GitHub Actions workflow with immutable external Action pins and post-upload policy enforcement.
- [x] Exclude a committed Extension X-Ray baseline from repository content rules.
- [x] Update version metadata, examples, security documentation, architecture, and demo instructions.
- [x] Run backend/frontend, CLI, workflow, REA, JSON, redaction, build, and HTTP validation.

## v0.5.0 delivered behavior

- `ci.py` owns bounded report/policy loading, normalized finding fingerprints, multiset report comparison, policy evaluation, and SARIF serialization.
- SARIF 2.1.0 includes rule descriptors, severity-derived levels, confidence/impact properties, archive-relative URI-encoded locations, and `primaryLocationLineHash`. Locationless findings remain valid JSON/policy inputs and omit the empty SARIF `locations` property.
- Fingerprints use rule ID, normalized path, redacted summary, and redacted snippet. Line numbers and a single archive wrapper directory are excluded so ordinary line movement and differently named source archives remain stable.
- `.extension-xray.toml` supports `fail_on`, `minimum_confidence`, `deny_rules`, and `ignore_rules`. Unknown fields, invalid rule IDs, and deny/ignore overlap fail closed as configuration errors.
- `.extension-xray-baseline.json` is discovered automatically. Existing findings remain in full outputs but are excluded from policy failure; diff output records new, unchanged, and resolved entries.
- `--kind report` converts or compares already generated reports without rescanning an artifact. `--no-policy` and `--no-baseline` provide explicit control over automatic discovery.
- Exit code `0` means analysis and policy passed, `1` means outputs were written but policy rejected findings, and `2` means analysis/configuration did not complete.
- The reusable workflow checks out caller and analyzer separately, installs only the analyzer, archives only tracked target files, never runs target setup/build/test code, uploads SARIF through a pinned CodeQL Action, and enforces the saved scan outcome afterward.
- Reusable-workflow source is resolved through `job.workflow_repository` and `job.workflow_sha`; all external Actions are pinned to full 40-character commit SHAs.
- A standard committed baseline is inventoried but excluded from repository source rules so archived evidence cannot be rediscovered as current code.
- Application/backend/frontend metadata is `0.5.0`. VSIX report schema remains `1.0.0`, repository report schema remains `1.1.0`, and CI diff/policy documents use `1.0.0`.

## Preserved baseline

- Safe bounded ZIP ingestion, SHA-256 identity, isolated temporary extraction, cleanup, and no uploaded artifact execution.
- VSIX capability rules, Repo X-Ray automation checks, Crypto Guard 2 flow signals, and Supply Chain 2 SBOM/advisory analysis.
- Optional bounded REA enrichment with independent native fallback.
- Typed dashboard, evidence viewer, inventory, dependency graph, CycloneDX download, and report JSON export.
- Package managers, hooks, submodules, builds, tests, workflows, and uploaded code are never executed.

## Environment observations

- Python 3.15 is active in `.venv`; Node.js 24.21.0, npm 11.19.0, and Vite 6.4.6 are available.
- REA CLI 6.7.0 completed both suspicious synthetic analyses. The CI workflow deliberately uses the native fallback to avoid requiring REA on hosted runners.
- The managed Windows sandbox blocks Python-created temporary directories and esbuild subprocesses. Affected validation commands were rerun outside that sandbox without changing application behavior.
- The reusable workflow YAML parsed successfully as one `workflow_call` trigger, one job, and eight steps.

## v0.5.0 validation log

- Python syntax compilation: passed for backend, tests, and fixture generator.
- Backend: `61 passed`; the only warning is the upstream Starlette `TestClient`/`httpx` deprecation.
- Frontend TypeScript typecheck and ESLint: passed.
- Frontend Vitest: `7 passed` across 3 files.
- Frontend production build: passed; 1,584 modules transformed, with 180.99 kB JavaScript and 19.16 kB CSS before gzip.
- Regenerated and analyzed all four documented synthetic artifacts.
- Suspicious VSIX: 8 findings; REA 6.7.0 completed on 2 sources with Evidence ID `ev_90818b03d88752e5263e9b2e92bc12fc6546dcc12aa31e12529d66c847c73e71`.
- Suspicious repository: 27 findings; REA 6.7.0 completed on 7 sources with Evidence ID `ev_a877eafc3e06601eaf03594696ac7179c77058eab562b2519066d3e9d6d04ccb`.
- Benign VSIX and repository native-fallback analyses: zero findings.
- All four JSON reports round-tripped through their Pydantic models; the synthetic recovery phrase and encoded key were absent from serialized reports.
- CI policy smoke: exit `1` after writing report, SARIF, and policy output; 17 violations from 27 considered findings.
- Baseline smoke: exit `0`, 0 new, 27 unchanged, 0 resolved, and only `unchanged` SARIF baseline states.
- Operational-error smoke: a missing input returned exit `2` with a bounded error message.
- SARIF smoke: version 2.1.0, 27 results, 26 rule descriptors, `.github` paths preserved, and no synthetic secret values.
- HTTP smoke: health `200` with version `0.5.0`; repository upload `200`, schema `1.1.0`, 27 findings, 3 SBOM components, and REA `completed`.

## Remaining limitations

- Static findings still do not establish runtime reachability, malicious intent, or complete interprocedural data flow.
- Fingerprints intentionally change when evidence summary/snippet changes; they are stable identifiers, not semantic equivalence proofs.
- A baseline or ignore rule is accepted risk and can hide policy failure if reviewed carelessly. Both require security review and protected-branch controls.
- GitHub Code Scanning cannot display a SARIF result without a source location, although JSON policy evaluation still includes it.
- SARIF upload from fork pull requests is skipped because their token cannot receive `security-events: write`; local policy enforcement still runs.
- The reusable workflow's self-checkout context is GitHub Cloud-specific. Older GitHub Enterprise Server versions require explicit pinned CLI steps.
- The bundled OSV seed remains intentionally incomplete and must be refreshed or replaced for production coverage.
- Registry ownership, npm attestations/signatures, maintainer reputation, and online revocation are not verified.
- A clean or baselined report is not a security guarantee.
