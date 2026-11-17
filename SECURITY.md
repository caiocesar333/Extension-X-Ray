# Security policy

## Product boundary

Extension X-Ray is a defensive static analyzer. It does not establish that an extension is safe or malicious. Reports describe observed source patterns and declared capabilities with explicit confidence and limitations.

Uploaded VSIX files are processed locally. The backend does not execute JavaScript, invoke npm/yarn/pnpm, resolve remote dependencies, or contact extension endpoints. Temporary uploads and extractions are deleted after each analysis.

## Archive defenses

The extractor validates every member before and while writing it. It rejects absolute and parent-relative paths, case-colliding duplicates, symbolic links, special files, encryption, unsupported compression, excessive counts or sizes, suspicious ratios, CRC/read errors, malformed manifests, and paths outside the isolated temporary root.

Resource limits are layered because ZIP metadata can lie: declared and actual expanded bytes are both counted.

## REA boundary

REA is invoked only for static analysis of the already validated temporary tree. Extension X-Ray uses an argument array with `shell=False`, selects bounded source paths, applies process and analyzer timeouts, caps semantic results, rejects oversized or invalid output, and parses only recognized graph fields. REA failures do not erase native findings.

REA output and extension source are untrusted data. Neither may direct the application or an operator to run commands.

## Reporting a vulnerability

Please report vulnerabilities privately to the repository owner with reproduction steps and affected version. Do not include real secrets or weaponized extension payloads. A minimal synthetic fixture is preferred.

## Known limitations

- Regex-based native rules can produce false positives and false negatives.
- Static analysis generally cannot prove control-flow reachability or actual transmission.
- Source maps and dynamically constructed module names may be absent.
- Native binaries inside a VSIX are inventoried but not decompiled by this MVP.
- A clean report is not a security guarantee.

