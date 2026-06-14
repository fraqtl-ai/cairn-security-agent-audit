#!/usr/bin/env python3
"""One-command CAIRN Security Agent Audit flow.

Raw JSON/JSONL/parquet-ish security-agent traces first get normalized into
CAIRN's audit schema, then a local report is generated.

Example:
    python cairn_pilot_from_raw_logs.py --input logs.jsonl --out report --price-input-per-m 3.0
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent
PILOT = ROOT / "pilot"
if str(PILOT) not in sys.path:
    sys.path.insert(0, str(PILOT))

import ingest_agent_trace  # type: ignore
import cairn_audit_agent_logs as audit


def write_normalized_trace(records: list[dict], path: Path, keep_output_text: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            row = dict(record)
            if not keep_output_text:
                row.pop("stdout", None)
                row.pop("stderr", None)
            f.write(json.dumps(row, sort_keys=True) + "\n")


def events_from_records(records: list[dict]) -> list[audit.Event]:
    events: list[audit.Event] = []
    for idx, record in enumerate(records):
        event = audit.normalize_row(record, idx, "cleaned_trace")
        if event is not None:
            events.append(event)
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize security-agent logs, then run the CAIRN local audit report.")
    parser.add_argument("--input", type=Path, required=True, help="Raw JSON, JSONL, parquet, or directory of logs.")
    parser.add_argument("--out", type=Path, required=True, help="Report output directory.")
    parser.add_argument("--source", default="auto", help="Reserved for compatibility; auto is recommended.")
    parser.add_argument("--glob", default=None, help="Glob when --input is a directory.")
    parser.add_argument("--max-rows", type=int, default=0)
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--readonly-cache-only", action="store_true")
    parser.add_argument("--price-input-per-m", type=float, default=0.0)
    parser.add_argument(
        "--drop-output-text",
        action="store_true",
        help="Write a compact cleaned trace without raw stdout/stderr. Delta-serving savings will be limited.",
    )
    parser.add_argument(
        "--no-cleaned-trace",
        action="store_true",
        help="Do not write cleaned_trace.jsonl. Use this for larger public runs where only compact receipts should persist.",
    )
    args = parser.parse_args()

    loaded: list[tuple[Path, dict]] = []
    for path, obj in ingest_agent_trace.iter_input(args.input, args.glob):
        loaded.append((path, obj))
        if args.max_rows and len(loaded) >= args.max_rows:
            break

    ingest_args = SimpleNamespace(
        readonly_cache_only=args.readonly_cache_only,
        max_records=args.max_records,
    )
    records, ingest_stats = ingest_agent_trace.convert_objects(loaded, args.source, ingest_args)

    args.out.mkdir(parents=True, exist_ok=True)
    normalized_path = args.out / "cleaned_trace.jsonl"
    if args.no_cleaned_trace:
        events = events_from_records(records)
    else:
        write_normalized_trace(records, normalized_path, keep_output_text=not args.drop_output_text)
        events = audit.load_events(normalized_path)
    result = audit.analyze(events, args.price_input_per_m)
    result["normalization"] = {
        **ingest_stats,
        "cleaned_trace": "" if args.no_cleaned_trace else str(normalized_path),
        "output_text_retained": not args.drop_output_text,
        "cleaned_trace_written": not args.no_cleaned_trace,
    }

    audit.write_json(args.out / "summary.json", result)
    audit.write_markdown(args.out / "summary.md", result, args.input)
    audit.write_html(args.out / "report.html", result, args.input)
    (args.out / "normalization_summary.json").write_text(
        json.dumps(result["normalization"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    if args.no_cleaned_trace:
        print("cleaned trace -> skipped")
    else:
        print(f"cleaned trace -> {normalized_path}")
    print(f"report -> {args.out}")


if __name__ == "__main__":
    main()
