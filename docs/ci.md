# CI Guard

Extension X-Ray v1.0.0 freezes the automation contract without changing the VSIX or repository report schemas introduced before v1. Artifact analysis still happens before policy evaluation, and report, SARIF, diff, and policy outputs are written before a policy failure returns exit code `1`.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Analysis completed and the effective policy passed |
| `1` | Analysis completed, outputs were written, and the effective policy failed |
| `2` | Input, configuration, baseline, archive, or analysis error |

Argument parser errors also use code `2`. A missing REA installation is not an operational error in the default `auto` mode because the independent native scanner remains active.

## Policy

Copy `examples/extension-xray.toml` to `.extension-xray.toml` in the repository being scanned. The CLI discovers that filename in its working directory.

```toml
schema_version = "1"

[policy]
fail_on = "high"
minimum_confidence = "medium"
deny_rules = ["CRYPTO-TX-001", "REP-DLX-001"]
ignore_rules = ["SCM-TYPO-001"]
```

`fail_on` accepts `off`, `critical`, `high`, `medium`, `low`, or `info`. The threshold only considers findings at or above `minimum_confidence`. `deny_rules` always fail regardless of severity or confidence. `ignore_rules` are excluded from both mechanisms, and a rule cannot appear in both lists.

CLI flags override the threshold and minimum confidence and extend rule lists:

```powershell
extension-xray .\repository.zip --kind repository --no-rea `
  --policy .\policy.toml `
  --fail-on critical `
  --deny-rule SCM-ADV-001 `
  --ignore-rule SCM-TYPO-001 `
  --policy-output .\policy-result.json
```

Use `--no-policy` when generating or reviewing a report independently of the discovered policy.

## Baseline and diff

A baseline is a normal Extension X-Ray JSON report. Create the first baseline without applying an older baseline or policy:

```powershell
extension-xray .\repository.zip --kind repository --no-rea `
  --output .\.extension-xray-baseline.json `
  --no-baseline --no-policy
```

When `.extension-xray-baseline.json` exists in the working directory, policy evaluation considers only new findings. The full current finding set is still included in JSON and SARIF so external systems can track unchanged and resolved alerts correctly.

Use an explicit baseline and diff output when comparing reports from two commits or releases:

```powershell
extension-xray .\current-report.json --kind report `
  --baseline .\previous-report.json `
  --diff-output .\report-diff.json `
  --sarif .\current.sarif `
  --fail-on high
```

Fingerprints include the rule, normalized archive-relative path, evidence summary, and redacted snippet. Line numbers and a single archive root directory are excluded, so ordinary line movement and differently named checkout roots do not turn every finding into a new one. Material evidence changes intentionally produce a new fingerprint.

Use `--no-baseline` to disable automatic discovery. Refreshing a baseline is an explicit risk-acceptance change and should receive security review like a policy change.

## SARIF

`--sarif` writes [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html). Each result includes its rule descriptor, severity-derived SARIF level, archive-relative location, confidence and impact properties, and stable `primaryLocationLineHash`. With a baseline, current results are marked `new` or `unchanged`.

[GitHub Code Scanning SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support) requires at least one location to display an alert. Extension X-Ray findings normally include one; findings without a location remain in JSON and policy evaluation even if a SARIF viewer cannot annotate them.

## Reusable GitHub Actions workflow

Call the workflow by an immutable Extension X-Ray commit SHA, which [GitHub documents as the safest reusable-workflow reference](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#calling-a-reusable-workflow):

```yaml
name: Extension X-Ray

on:
  pull_request:
  push:
    branches: [main]

jobs:
  xray:
    permissions:
      contents: read
      security-events: write
    uses: caiocesar333/Extension-X-Ray/.github/workflows/extension-xray-reusable.yml@REPLACE_WITH_FULL_COMMIT_SHA
    with:
      fail-on: high
      minimum-confidence: medium
      upload-sarif: true
```

The reusable workflow:

1. checks out the caller repository;
2. checks out Extension X-Ray from the exact reusable-workflow SHA;
3. archives only tracked files with `git archive`;
4. installs the trusted analyzer, never the target repository;
5. runs the native scanner without REA;
6. uploads SARIF when the caller grants `security-events: write`;
7. enforces the saved policy result after the upload attempt.

SARIF upload is skipped for pull requests from forks because their token cannot receive the required write permission. Policy enforcement still runs. GitHub Enterprise Server instances that do not expose `job.workflow_repository` and `job.workflow_sha` should use the documented CLI steps directly and pin the analyzer checkout manually.

## Security boundaries

- A policy or baseline is local input, not an instruction to execute code.
- The workflow does not run package installation, build, test, lifecycle, hook, or source commands from the target repository.
- SARIF contains already-redacted evidence. It can still reveal repository paths and security behavior, so treat it as security-sensitive build output.
- An ignored or baselined finding is accepted risk, not proof that the behavior is safe.
