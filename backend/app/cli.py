from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzer import ExtensionAnalyzer
from .config import ReaSettings
from .rea import ReaAdapter


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze a VSIX without executing it")
    parser.add_argument("input", type=Path, help="Path to a local .vsix file")
    parser.add_argument("--output", "-o", type=Path, help="Write the JSON report to this path")
    parser.add_argument("--no-rea", action="store_true", help="Disable REA enrichment")
    return parser


def main() -> None:
    args = _parser().parse_args()
    if not args.input.is_file():
        raise SystemExit(f"Input does not exist: {args.input}")
    settings = ReaSettings(mode="disabled") if args.no_rea else ReaSettings.from_env()
    report = ExtensionAnalyzer(rea=ReaAdapter(settings)).analyze(args.input)
    serialized = json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(serialized)


if __name__ == "__main__":
    main()

