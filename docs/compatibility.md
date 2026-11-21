# Compatibility contract

Extension X-Ray v1.0.0 declares the public surface that application Semantic Versioning protects. The application version and document schema versions are independent: an application release may support several document schemas without renaming them.

## Stable public surface

The v1 public surface consists of:

- the `extension-xray` command, its documented options, and exit codes `0`, `1`, and `2`;
- the `/api/v1` HTTP routes, request shapes, response models, and structured Extension X-Ray errors;
- VSIX report schema `1.0.0` and repository report schema `1.1.0`;
- CI diff and policy-result schema `1.0.0`, TOML policy schema `1`, and SARIF 2.1.0 output;
- rule IDs, finding fingerprints, and the documented security boundary that uploaded content is never executed.

The JSON Schema endpoints are the machine-readable source of truth for report fields. `analysis_kind` selects the report family. `--kind report` accepts only explicitly supported schema versions and returns operational exit code `2` for an unknown version.

Reports produced by v0.5.0 already use VSIX schema `1.0.0` or repository schema `1.1.0` and remain valid v1 inputs. Consumers should branch on both `analysis_kind` and `schema_version`, retain unknown fields only if their own parser permits them, and reject unknown major schema versions.

## Versioning after v1

- `1.0.x` is reserved for backward-compatible fixes, hardening, rule calibration, documentation, and dependency maintenance.
- `1.x.0` may add scanners, rules, endpoints, CLI options, or optional output formats while preserving the v1 public surface.
- `2.0.0` is required to remove or rename a public field or option, change an existing field type or exit-code meaning, repurpose a rule ID, or otherwise require a v1 consumer to change.

Every released version is immutable. A fix after a tag receives a new version rather than moving the tag.

## Schema and detection evolution

A report shape change receives a new report schema version even when the application change is backward compatible. The loader supports only schemas listed above until support for another version is implemented and tested. Schema versions are not automatically tied to the application version.

Detection results are evidence, not an ABI: finding counts, severity, confidence, and evidence can change as false positives are fixed or analysis improves. Existing rule IDs are not reused for unrelated behavior. A retired rule remains documented in the changelog. Fingerprints are stable for the normalized inputs documented in [CI Guard](ci.md), but materially changed evidence intentionally produces a new fingerprint.

## Support policy

The v1 line supports Python 3.13 or newer and Node.js 20 or newer for dashboard development. REA is optional unless `XRAY_REA_MODE=required`; its absence in the default mode preserves native scanning. The offline and no-execution boundaries in [SECURITY.md](../SECURITY.md) are compatibility commitments, not implementation details.
