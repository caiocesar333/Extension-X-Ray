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
| `REP-CI-001` | Critical | `pull_request_target`, pull-request-head checkout, and command execution in one workflow |
| `REP-CI-002` | High | Attacker-influenced GitHub event text interpolated directly into `run` |
| `REP-CI-003` | Medium | Third-party GitHub Action not pinned to a full 40-character commit SHA |
| `REP-IDE-001` | Medium | Committed VS Code task with a command or dependency |
| `REP-DEV-001` | High | Dev-container setup/start lifecycle command |

## Crypto Guard rules

| Rule | Severity | Signal |
| --- | --- | --- |
| `CRYPTO-SECRET-001` | Critical | Private-key marker or recovery-phrase-like assignment; evidence is redacted |
| `CRYPTO-WALLET-001` | High | Reference to common wallet, keystore, or signing-identity storage |
| `CRYPTO-TX-001` | Critical | Wallet-sensitive source and network capability in the same file |
| `CRYPTO-CLIP-001` | Critical | Clipboard read/write plus a cryptocurrency address pattern in the same file |

Combination rules raise review priority but still describe proximity, not a proven end-to-end data flow. Every finding carries a file/line when available, bounded evidence, confidence, possible impact, and an investigation step.

## Adding a rule

Keep patterns narrow, bound emitted findings, redact possible secrets before hashing or reporting, and add positive and benign regression cases. Prefer semantic REA evidence when genuinely present, but preserve native behavior when REA is unavailable. Update this catalog whenever a rule ID or meaning changes.
