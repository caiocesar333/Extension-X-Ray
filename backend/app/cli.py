from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import ExtensionAnalyzer
from .config import ReaSettings
from .rea import ReaAdapter
from .repository_analyzer import RepositoryAnalyzer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a VSIX or repository ZIP without executing it")
    parser.add_argument("input", type=Path, help="Path to a local .vsix or repository .zip file")
    parser.add_argument("--output", "-o", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--no-rea", action="store_true", help="Disable REA enrichment")
    parser.add_argument(
        "--kind",
        choices=("extension", "repository"),
        default="extension",
        help="Artifact type to analyze (default: extension)",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    if not args.input.is_file():
        raise SystemExit(f"Input does not exist: {args.input}")
    settings = ReaSettings(mode="disabled") if args.no_rea else ReaSettings.from_env()
    rea = ReaAdapter(settings)
    report = (
        RepositoryAnalyzer(rea=rea).analyze(args.input)
        if args.kind == "repository"
        else ExtensionAnalyzer(rea=rea).analyze(args.input)
    )
    serialized = json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(serialized)


if __name__ == "__main__":
    main()

