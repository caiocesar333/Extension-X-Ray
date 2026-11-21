from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .analyzer import ExtensionAnalyzer
from .ci import (
    PolicyConfig,
    compare_reports,
    evaluate_policy,
    load_policy,
    load_report,
    report_to_sarif,
)
from .config import ReaSettings
from .errors import XRayError
from .models import Confidence
from .rea import ReaAdapter
from .repository_analyzer import RepositoryAnalyzer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze an artifact or process an existing Extension X-Ray report",
    )
    parser.add_argument("input", type=Path, help="Path to a .vsix, repository .zip, or report .json")
    parser.add_argument("--output", "-o", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--sarif", type=Path, help="Write a SARIF 2.1.0 result file")
    parser.add_argument("--baseline", type=Path, help="Compare against an earlier Extension X-Ray report")
    parser.add_argument("--no-baseline", action="store_true", help="Disable automatic baseline discovery")
    parser.add_argument("--diff-output", type=Path, help="Write the baseline comparison as JSON")
    parser.add_argument("--policy", type=Path, help="Load a TOML policy (default: .extension-xray.toml when present)")
    parser.add_argument("--no-policy", action="store_true", help="Disable automatic policy discovery")
    parser.add_argument("--policy-output", type=Path, help="Write the policy evaluation as JSON")
    parser.add_argument(
        "--fail-on",
        choices=("off", "critical", "high", "medium", "low", "info"),
        help="Override the policy severity threshold",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        help="Override the minimum confidence used by the severity threshold",
    )
    parser.add_argument("--deny-rule", action="append", default=[], help="Always fail on this rule ID")
    parser.add_argument("--ignore-rule", action="append", default=[], help="Exclude this rule ID from policy failure")
    parser.add_argument("--no-rea", action="store_true", help="Disable REA enrichment")
    parser.add_argument(
        "--kind",
        choices=("extension", "repository", "report"),
        default="extension",
        help="Input type (default: extension; report skips artifact analysis)",
    )
    return parser


def _write_json(path: Path, document: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _resolved_optional_path(explicit: Path | None, default_name: str) -> Path | None:
    if explicit is not None:
        return explicit
    candidate = Path(default_name)
    return candidate if candidate.is_file() else None


def run(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.input.is_file():
        print(f"Extension X-Ray error: input does not exist: {args.input}", file=sys.stderr)
        return 2
    try:
        if args.baseline and args.no_baseline:
            raise ValueError("--baseline and --no-baseline cannot be combined")
        if args.policy and args.no_policy:
            raise ValueError("--policy and --no-policy cannot be combined")
        if args.kind == "report":
            report = load_report(args.input)
        else:
            settings = ReaSettings(mode="disabled") if args.no_rea else ReaSettings.from_env()
            rea = ReaAdapter(settings)
            report = (
                RepositoryAnalyzer(rea=rea).analyze(args.input)
                if args.kind == "repository"
                else ExtensionAnalyzer(rea=rea).analyze(args.input)
            )

        baseline_path = (
            None
            if args.no_baseline
            else _resolved_optional_path(args.baseline, ".extension-xray-baseline.json")
        )
        baseline = load_report(baseline_path) if baseline_path else None
        difference = compare_reports(report, baseline) if baseline else None
        if args.diff_output and difference is None:
            raise ValueError("--diff-output requires --baseline or .extension-xray-baseline.json")

        policy_path = (
            None
            if args.no_policy
            else _resolved_optional_path(args.policy, ".extension-xray.toml")
        )
        policy = load_policy(policy_path) if policy_path else PolicyConfig()
        updates: dict[str, object] = {}
        if args.fail_on:
            updates["fail_on"] = args.fail_on
        if args.min_confidence:
            updates["minimum_confidence"] = Confidence(args.min_confidence)
        if args.deny_rule:
            updates["deny_rules"] = [*policy.deny_rules, *args.deny_rule]
        if args.ignore_rule:
            updates["ignore_rules"] = [*policy.ignore_rules, *args.ignore_rule]
        if updates:
            policy = PolicyConfig.model_validate({**policy.model_dump(), **updates})
        evaluation = evaluate_policy(
            report,
            policy,
            baseline=baseline,
            policy_source=str(policy_path) if policy_path else "built-in/CLI",
        )

        report_document = report.model_dump(mode="json")
        if args.output:
            _write_json(args.output, report_document)
            print(f"Report written to {args.output}", file=sys.stderr)
        elif args.kind != "report" or not any((args.sarif, args.diff_output, args.policy_output)):
            print(json.dumps(report_document, indent=2, ensure_ascii=False))
        if args.sarif:
            _write_json(args.sarif, report_to_sarif(report, baseline=baseline))
            print(f"SARIF written to {args.sarif}", file=sys.stderr)
        if args.diff_output and difference:
            _write_json(args.diff_output, difference.model_dump(mode="json"))
            print(f"Diff written to {args.diff_output}", file=sys.stderr)
        if args.policy_output:
            _write_json(args.policy_output, evaluation.model_dump(mode="json"))
            print(f"Policy evaluation written to {args.policy_output}", file=sys.stderr)

        status = "passed" if evaluation.passed else "failed"
        print(
            f"Policy {status}: {evaluation.violation_count} violation(s), "
            f"{evaluation.considered_findings} finding(s) considered",
            file=sys.stderr,
        )
        return 0 if evaluation.passed else 1
    except (OSError, ValueError, ValidationError, XRayError) as error:
        print(f"Extension X-Ray error: {error}", file=sys.stderr)
        return 2
    except Exception as error:  # Defensive CLI boundary: preserve the documented operational exit code.
        print(f"Extension X-Ray error: analysis failed: {error}", file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()

