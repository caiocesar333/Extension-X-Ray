# Extension X-Ray progress

Updated: 2026-11-21

## v0.3.0 Crypto Guard 2 plan

- [x] Separate crypto analysis and redaction into a dedicated bounded module.
- [x] Track sensitive values through common assignments, aliases, and transformations.
- [x] Distinguish resolved network flow from unresolved same-file proximity.
- [x] Detect wallet-sensitive values reaching process arguments.
- [x] Expand wallet families, encoded-key, environment, and clipboard detection.
- [x] Support common JavaScript/TypeScript and Python crypto-flow forms.
- [x] Prevent parallel native findings from leaking secret-shaped evidence.
- [x] Update fixtures, documentation, version metadata, and regression tests.
- [x] Run the full validation matrix, REA path, report validation, and HTTP smoke test.

## v0.3.0 delivered behavior

- `crypto_guard.py` owns wallet-family sources, secret-shape recognition, evidence redaction, bounded propagation, and crypto sinks.
- `CRYPTO-TX-001` now requires a bounded intra-file flow into a network call. `CRYPTO-PROX-001` represents unresolved colocation without claiming exfiltration.
- `CRYPTO-PROC-001` tracks wallet-sensitive variables into process execution arguments.
- `CRYPTO-SECRET-002` detects private-key-named hex/base58 values, and `CRYPTO-ENV-001` identifies wallet-secret-named environment access.
- Wallet paths cover Bitcoin, Ethereum, Solana, Electrum, Exodus, Atomic Wallet, and common Chromium browser-wallet extension IDs.
- Clipboard replacement requires an address literal or address-bearing variable to reach the clipboard write call; an unrelated address elsewhere in the file no longer triggers it.
- Assignment/alias tracking supports common JavaScript/TypeScript and Python forms for up to four propagation rounds, with `requests`, `httpx`, `urllib`, `subprocess`, `os.system`, and `pyperclip` coverage.
- Secret redaction is shared with the common source scanner, so a parallel `EXR-*` finding cannot expose a key-shaped value.
- Backend/frontend/package metadata is `0.3.0`; report schema remains `1.0.0` and existing endpoints remain compatible.

## Preserved baseline

- Safe bounded ZIP ingestion, SHA-256 identity, temporary cleanup, and no artifact execution.
- VSIX capability rules and repository lifecycle, download/execute, GitHub Actions, VS Code, and dev-container analysis.
- Optional bounded REA enrichment with independent native fallback.
- Typed VSIX/repository dashboard, evidence viewer, inventory, dependency graph, and JSON export.
- Package managers, hooks, submodules, builds, tests, workflows, and uploaded code are never executed.

## Environment observations

- Python 3.15 is available through `py -3.15`; plain `python` is 3.11 and is incompatible with the installed local Python 3.15 dependency binaries.
- Node.js 24.21.0 and npm 11.19.0 are available.
- REA CLI 6.7.0 is installed and completed the bounded suspicious-repository analysis. FastAPI uses the local CLI adapter; the previously verified MCP connection is not required by the standalone service.

## v0.3.0 validation log

- Python syntax compilation: passed for backend, tests, and fixture generator.
- Backend: `41 passed` with one upstream Starlette `TestClient`/`httpx` deprecation warning.
- Frontend TypeScript typecheck and ESLint: passed.
- Frontend Vitest: `7 passed` across 3 files.
- Frontend production build: passed with Vite 6.4.6; output was 175.20 kB JavaScript and 18.07 kB CSS before gzip.
- Generated benign/suspicious VSIX and repository ZIP fixtures.
- Suspicious VSIX fallback analysis: 8 findings; benign VSIX: zero findings.
- Suspicious repository analysis: 20 findings; REA 6.7.0 completed on 7 sources with Evidence ID `ev_7b38d03c5dd51032b09dba8d676b8990389c618dc41cbf342d0960f101e4bd05`.
- Benign repository fallback analysis: zero findings.
- All four JSON reports validated through their Pydantic models; the synthetic recovery phrase and encoded key were absent from serialized output.
- HTTP smoke test: health `200`/version `0.3.0`; repository upload `200`, 20 findings, REA `completed` and `used=true`.
- Regression coverage includes resolved versus proximity flow, aliases/encoding, process arguments, JavaScript/Python environment sources, browser-wallet paths, encoded-key redaction, precise clipboard writes, and cross-scanner redaction.

## Remaining limitations

- Static evidence does not establish runtime reachability, intent, or a complete interprocedural data flow.
- Crypto propagation is intra-file and syntax-bounded; object properties, callbacks, reflection, dynamic dispatch, and cross-module state may not resolve.
- Key-shape detection validates variable context and encoding length, not cryptographic validity.
- Pattern rules can still produce false positives and false negatives; findings require human review.
- Dependency CVE resolution, package provenance, and online reputation remain outside the offline v0.3.0 scope.
- REA enriches JavaScript/TypeScript structure but does not replace native repository rules.
- Native binaries are inventoried but not decompiled, and a clean report is not a security guarantee.
