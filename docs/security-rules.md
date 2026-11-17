# Security rule catalog

Rules identify evidence that merits review. A match is not a malware verdict.

| Rule | Default severity | Signal |
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

Combination rules raise review priority but still describe proximity, not a proven end-to-end data flow. Every finding carries a file/line when available, the matched snippet, confidence, possible impact, and a concrete investigation step.

## Adding a rule

Keep patterns narrow, bound the number of emitted findings, avoid embedding secrets in evidence, and add both positive and benign regression cases. Prefer semantic REA evidence when it is genuinely present, but preserve native behavior when REA is unavailable.

