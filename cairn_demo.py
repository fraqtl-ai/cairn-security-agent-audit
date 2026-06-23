#!/usr/bin/env python3
"""Run the bundled CAIRN Security Agent Audit sample."""

from __future__ import annotations

import argparse
import sys
from importlib import resources
from pathlib import Path

import cairn_pilot_from_raw_logs


def bundled_sample_path() -> Path:
    sample = resources.files("cairn_security_agent_audit").joinpath("samples/pentest_trace_sample.jsonl")
    with resources.as_file(sample) as path:
        return Path(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bundled CAIRN Security Agent Audit demo.")
    parser.add_argument("--out", default="report", help="Report output directory.")
    parser.add_argument("--price-input-per-m", type=float, default=3.0)
    parser.add_argument("--json-only", action="store_true", help="Print full audit JSON to stdout and skip files.")
    parser.add_argument("--html", action="store_true", help="Also write report.html.")
    args = parser.parse_args()

    sample = bundled_sample_path()
    argv = [
        "cairn-audit",
        "--input",
        str(sample),
        "--price-input-per-m",
        str(args.price_input_per_m),
    ]
    if args.json_only:
        argv.append("--json-only")
    else:
        argv.extend(["--out", args.out])
        if args.html:
            argv.append("--html")

    sys.argv = argv
    cairn_pilot_from_raw_logs.main()

    if not args.json_only:
        out = Path(args.out)
        print("\nCAIRN sample audit complete.\n")
        print("Written:")
        print(f"  {out / 'summary.json'}")
        print(f"  {out / 'summary.md'}")
        if args.html:
            print(f"  {out / 'report.html'}")
        print(f"  {out / 'normalization_summary.json'}")


if __name__ == "__main__":
    main()
