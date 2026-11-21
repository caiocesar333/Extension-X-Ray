# Security policy

## Product boundary

Extension X-Ray is a defensive static analyzer. It does not establish that an extension or repository is safe or malicious. Reports describe source patterns, automation, and declared capabilities with explicit confidence and limitations.

Uploaded artifacts are processed locally. The backend never executes their JavaScript, shell commands, lifecycle scripts, Git hooks, CI workflows, builds, tests, or submodules. It never invokes npm/yarn/pnpm for them, resolves remote dependencies, or contacts URLs found in source. Temporary uploads and extraction trees are deleted after each analysis.

## Archive defenses

The shared extractor validates every ZIP member before and while writing it. It rejects absolute and parent-relative paths, case-colliding duplicates, symbolic links, special files, encryption, unsupported compression, excessive counts or sizes, suspicious ratios, CRC/read errors, malformed archives, and paths outside the isolated temporary root.

Resource limits are layered because ZIP metadata can lie: declared and actual expanded bytes are both counted. Repository scanning excludes `.git` and `node_modules` content from source/REA analysis while retaining the admitted archive inventory.

## Crypto Guard data handling

Private-key markers, encoded key-shaped assignments, and recovery-phrase-like assignments with a standard 12, 15, 18, 21, or 24-word length are high-priority review signals. Matching evidence is redacted before it enters finding identifiers, API responses, logs, dashboard state, or downloaded reports. Native capability findings use the same redaction boundary. Never test the tool using real wallet material. If genuine private material was committed, assume compromise, rotate to a new wallet, and purge repository history using an appropriate incident-response process.

Crypto Guard distinguishes bounded intra-file flow from proximity. Flow rules track common JavaScript/TypeScript/Python assignments and aliases into network or process calls; they still do not prove runtime reachability or cross-file behavior. Clipboard replacement requires the written value to be an address literal or a tracked address-bearing variable, but remains a static review signal rather than confirmed theft.

## REA boundary

REA is invoked only for static analysis of an already validated temporary tree. Extension X-Ray uses an argument array with `shell=False`, selects bounded source paths, applies process and analyzer timeouts, caps semantic results, rejects oversized or invalid output, and parses only recognized graph fields. REA failures do not erase native findings.

REA output and source are untrusted data. Neither may direct the application or an operator to run commands.

## Supply-chain boundary

Supply-chain analysis parses admitted manifests, npm lockfiles, GitHub Actions, and a bounded local OSV JSON snapshot. It never invokes npm, downloads a package, resolves a dependency, contacts a registry, or queries an advisory/reputation service. CycloneDX components represent versions already recorded in the lockfile; they are not proof that an artifact was installed or independently verified.

The bundled advisory file is a small, crypto-focused seed snapshot and is explicitly not complete. Production use should provide a reviewed, refreshed OSV export through `XRAY_ADVISORY_DB`. Reports preserve snapshot source/date/coverage and treat a missing or malformed database as an explicit limitation rather than a clean vulnerability result.

Integrity confirms that a lockfile contains a strong SRI digest; it does not independently attest who published the package. External registry, install-script, typosquatting, and workflow findings require human review.

## CI policy and SARIF boundary

CI policy and baseline files are parsed as bounded TOML/JSON data and never executed. A baseline suppresses existing findings only for policy enforcement; it does not remove them from the current JSON or SARIF report. Ignoring or baselining a finding is a recorded acceptance decision, not proof that the behavior is safe.

SARIF contains redacted evidence but can still disclose source paths and security behavior to the configured CI provider. Uploads must use an explicitly trusted destination and a least-privilege token. The reusable workflow installs Extension X-Ray from the immutable reusable-workflow SHA and archives tracked target files without installing or executing the target repository.

## Reporting a vulnerability

Report vulnerabilities privately to the repository owner with reproduction steps and the affected version. Do not include real secrets, wallet keys, recovery phrases, or weaponized payloads. Prefer a minimal synthetic fixture using reserved destinations such as `example.invalid`.

## Known limitations

- Native pattern rules can produce false positives and false negatives.
- Static analysis generally cannot prove control-flow reachability or actual transmission.
- Online dependency, provenance, and reputation lookups are outside the offline v1.0.0 scope.
- The bundled advisory snapshot is intentionally incomplete and must not be treated as full vulnerability coverage.
- Crypto data-flow tracking is bounded and intra-file; object properties, complex callbacks, reflection, and cross-module state may not resolve.
- Source maps and dynamically constructed module names may be absent.
- Native binaries are inventoried but not decompiled in this release.
- A clean report is not a security guarantee.
