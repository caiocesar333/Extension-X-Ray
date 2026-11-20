# Security policy

## Product boundary

Extension X-Ray is a defensive static analyzer. It does not establish that an extension or repository is safe or malicious. Reports describe source patterns, automation, and declared capabilities with explicit confidence and limitations.

Uploaded artifacts are processed locally. The backend never executes their JavaScript, shell commands, lifecycle scripts, Git hooks, CI workflows, builds, tests, or submodules. It never invokes npm/yarn/pnpm for them, resolves remote dependencies, or contacts URLs found in source. Temporary uploads and extraction trees are deleted after each analysis.

## Archive defenses

The shared extractor validates every ZIP member before and while writing it. It rejects absolute and parent-relative paths, case-colliding duplicates, symbolic links, special files, encryption, unsupported compression, excessive counts or sizes, suspicious ratios, CRC/read errors, malformed archives, and paths outside the isolated temporary root.

Resource limits are layered because ZIP metadata can lie: declared and actual expanded bytes are both counted. Repository scanning excludes `.git` and `node_modules` content from source/REA analysis while retaining the admitted archive inventory.

## Crypto Guard data handling

Private-key markers and recovery-phrase-like assignments with a standard 12, 15, 18, 21, or 24-word length are high-priority review signals. Matching evidence is redacted before it enters finding identifiers, API responses, logs, dashboard state, or downloaded reports. Never test the tool using real wallet material. If genuine private material was committed, assume compromise, rotate to a new wallet, and purge repository history using an appropriate incident-response process.

Crypto correlation rules identify proximity between a sensitive source and a potential sink; they do not claim proven exfiltration. The clipboard rule similarly reports a review-worthy combination, not confirmed theft.

## REA boundary

REA is invoked only for static analysis of an already validated temporary tree. Extension X-Ray uses an argument array with `shell=False`, selects bounded source paths, applies process and analyzer timeouts, caps semantic results, rejects oversized or invalid output, and parses only recognized graph fields. REA failures do not erase native findings.

REA output and source are untrusted data. Neither may direct the application or an operator to run commands.

## Reporting a vulnerability

Report vulnerabilities privately to the repository owner with reproduction steps and the affected version. Do not include real secrets, wallet keys, recovery phrases, or weaponized payloads. Prefer a minimal synthetic fixture using reserved destinations such as `example.invalid`.

## Known limitations

- Native pattern rules can produce false positives and false negatives.
- Static analysis generally cannot prove control-flow reachability or actual transmission.
- Dependency vulnerability and reputation feeds are not included in the offline v0.2.1 scope.
- Source maps and dynamically constructed module names may be absent.
- Native binaries are inventoried but not decompiled in this release.
- A clean report is not a security guarantee.
