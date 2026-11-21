# Security rule catalog

Rules identify evidence that merits review. A match is not a malware verdict.

## Common source rules

| Rule | Severity | Signal |
| --- | --- | --- |
| `EXR-PROC-001` | High | Calls associated with `child_process` execution APIs |
| `EXR-DYN-001` | High | `eval` or dynamic `Function` construction |
| `EXR-FS-001` | High | Filesystem API and sensitive path in the same source file |
| `EXR-ENV-001` | Medium | Process/Deno environment access |
| `EXR-NET-001` | Medium | `fetch`, WebSocket, HTTP(S), or common request APIs |
| `EXR-OBF-001` | Medium | Dense escapes, long base64-like strings, or dynamic character construction |
| `EXR-TX-001` | Critical | Sensitive source and outbound network capability in the same file |
| `EXR-DLX-001` | Critical | Network and process execution capabilities in the same file |
| `EXR-CAP-001` | High | Network and dynamic JavaScript execution in the same file |

## Repository supply-chain and automation rules

| Rule | Severity | Signal |
| --- | --- | --- |
| `REP-NPM-001` | Medium | npm lifecycle script (`preinstall`, `install`, `postinstall`, or `prepare`) |
| `REP-NPM-002` | Critical | Lifecycle script also contains network/download execution behavior |
| `REP-DLX-001` | Critical | Download piped or chained directly into an interpreter |
| `REP-CI-001` | Critical | `pull_request_target`, pull-request-head checkout, and command execution in the same job |
| `REP-CI-002` | High | Attacker-influenced GitHub event text interpolated directly into inline or multiline `run` |
| `REP-CI-003` | Medium | Third-party GitHub Action not pinned to a full 40-character commit SHA |
| `REP-IDE-001` | Medium | Committed VS Code task with a command or dependency |
| `REP-DEV-001` | High | Dev-container setup/start lifecycle command |

## Crypto Guard rules

| Rule | Severity | Signal |
| --- | --- | --- |
| `CRYPTO-SECRET-001` | Critical | Private-key marker or 12/15/18/21/24-word recovery-phrase-like assignment; evidence is redacted |
| `CRYPTO-SECRET-002` | Critical | Private-key-named assignment with a hex/base58 wallet-key-like value; evidence is redacted |
| `CRYPTO-ENV-001` | Medium | Environment variable name indicates a wallet key, seed, mnemonic, or recovery phrase |
| `CRYPTO-WALLET-001` | High | Bitcoin, Ethereum, Solana, Electrum, Exodus, Atomic, or browser-wallet storage path |
| `CRYPTO-TX-001` | Critical | Bounded intra-file tracking connects wallet-sensitive input to a network call |
| `CRYPTO-PROX-001` | High | Wallet-sensitive and network capabilities are colocated without a resolved bounded flow |
| `CRYPTO-PROC-001` | Critical | Bounded intra-file tracking connects wallet-sensitive input to process arguments |
| `CRYPTO-CLIP-001` | Critical | Clipboard read followed by a write of an address literal or tracked address-bearing variable |

Combination rules raise review priority but still describe proximity, not a proven end-to-end data flow. Every finding carries a file/line when available, bounded evidence, confidence, possible impact, and an investigation step.

Crypto flow rules are stronger than proximity rules but remain static: they track common assignments and aliases for at most four propagation rounds inside one file. They do not resolve arbitrary object properties, dynamic dispatch, reflection, or cross-module state.

## Supply Chain 2 rules

| Rule | Severity | Signal |
| --- | --- | --- |
| `SCM-ADV-001` | Advisory severity | Locked npm version matches the configured offline OSV snapshot |
| `SCM-LOCK-000` | High | Dependencies are declared without `package-lock.json` |
| `SCM-LOCK-001` | High | Direct dependency is missing from the lockfile |
| `SCM-LOCK-002` | High | Exact manifest version disagrees with the resolved lockfile version |
| `SCM-LOCK-003` | Medium | Lock entry lacks a valid SHA-256/384/512 SRI digest |
| `SCM-PROV-001` | High | Locked artifact resolves outside recognized npm/yarn registry hosts |
| `SCM-NPM-001` | Medium | Lockfile marks a dependency as having an install script |
| `SCM-NPM-002` | High | Direct dependency uses Git, URL, file, link, or workspace source |
| `SCM-TYPO-001` | Medium/low confidence | Dependency is one edit or adjacent transposition from a curated popular package |
| `SCM-CI-001` | High | Workflow grants `permissions: write-all` |
| `SCM-CI-002` | High | `id-token: write` is combined with an Action not pinned to a full SHA |
| `SCM-CI-003` | High | A `secrets.*` expression is interpolated directly into a `run` script |

Advisory matching is only as complete and current as the local snapshot. Typosquatting uses a deliberately small popular-name set and low confidence; it is an investigation prompt, not proof of impersonation.

Repository reports are capped at 500 combined native and repository-specific findings. When the cap is reached, the report records an explicit limitation.

## Adding a rule

Keep patterns narrow, bound emitted findings, redact possible secrets before hashing or reporting, and add positive and benign regression cases. Prefer semantic REA evidence when genuinely present, but preserve native behavior when REA is unavailable. Update this catalog whenever a rule ID or meaning changes.
