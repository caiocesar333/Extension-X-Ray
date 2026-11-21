# Changelog

This file records user-visible Extension X-Ray changes. Application releases follow Semantic Versioning from v1.0.0 onward; report and policy formats carry their own schema versions.

## 1.0.0 - 2026-11-21

- Declared the stable CLI, HTTP API, report, policy, SARIF, and exit-code contracts.
- Kept v0.5 report compatibility: VSIX schema `1.0.0` and repository schema `1.1.0`.
- Reject unknown report schema versions instead of interpreting them as compatible.
- Added `extension-xray --version` and synchronized release metadata checks.
- Added pinned backend and frontend CI gates for tests, typecheck, lint, package verification, and production build.
- Upgraded Vitest to 4.1.12, removing the known advisories present in the previous test-toolchain lock graph.
- Added compatibility and release documentation.

## 0.5.0 - 2026-11-21

- Added CI Guard with SARIF 2.1.0, TOML policy, baselines, report diffs, stable fingerprints, exit codes, and a reusable GitHub Actions workflow.

## 0.4.0 - 2026-11-21

- Added Supply Chain 2 with CycloneDX 1.6 SBOMs, npm lockfile integrity checks, offline OSV matching, and GitHub Actions correlations.

## 0.3.0 - 2026-11-21

- Added Crypto Guard 2 with redacted wallet-secret signals and bounded JavaScript, TypeScript, and Python flow tracking.

## 0.2.1 - 2026-11-21

- Hardened repository analysis, evidence redaction, and false-positive controls.

## 0.2.0 - 2026-11-20

- Added Repo X-Ray and initial crypto-focused repository rules.

## 0.1.0 - 2026-11-18

- Delivered the local-first VSIX analyzer, REA enrichment, dashboard, synthetic fixtures, and secure archive ingestion MVP.
