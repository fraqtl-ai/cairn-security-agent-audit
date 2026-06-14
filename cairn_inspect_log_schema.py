#!/usr/bin/env python3
"""Inspect unfamiliar security-agent logs before CAIRN normalization."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


SESSION_HINTS = ("session", "thread", "conversation", "trace", "run", "trajectory")
TOOL_HINTS = ("tool", "function", "action", "command", "cmd", "input")
OUTPUT_HINTS = ("output", "stdout", "stderr", "result", "observation", "content", "response")
TOKEN_HINTS = ("token", "tokens", "bytes")
PROVENANCE_HINTS = ("tenant", "workspace", "auth", "route", "prompt", "model", "target", "session", "host", "ip", "fingerprint", "version")


def load_rows(path: Path, limit: int) -> list[dict[str, Any]]:
    if path.suffix.lower() in {".parquet", ".pq"}:
        try:
            import pandas as pd  # type: ignore
        except Exception as exc:
            raise SystemExit(
                "Parquet inspection requires pandas plus pyarrow or fastparquet. "
                "Install one parquet engine, or convert a small sample to JSONL first."
            ) from exc
        frame = pd.read_parquet(path)
        if limit:
            frame = frame.head(limit)
        return [row for row in frame.to_dict(orient="records") if isinstance(row, dict)]

    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    rows: list[dict[str, Any]] = []
    if stripped[:1] in "[{":
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                rows = [x for x in parsed if isinstance(x, dict)]
            elif isinstance(parsed, dict):
                for key in ("events", "records", "logs", "trace", "messages", "trajectory"):
                    if isinstance(parsed.get(key), list):
                        rows = [x for x in parsed[key] if isinstance(x, dict)]
                        break
                if not rows:
                    rows = [parsed]
            return rows[:limit]
        except json.JSONDecodeError:
            pass

    for line in text.splitlines():
        if len(rows) >= limit:
            break
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def walk(value: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, Any]]:
    if depth > 4:
        return []
    if isinstance(value, dict):
        out: list[tuple[str, Any]] = []
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.append((path, child))
            out.extend(walk(child, path, depth + 1))
        return out
    if isinstance(value, list) and value and isinstance(value[0], dict):
        return walk(value[0], f"{prefix}[]" if prefix else "[]", depth + 1)
    return []


def short_type(value: Any) -> str:
    if isinstance(value, str):
        return f"str[{len(value)}]"
    if isinstance(value, list):
        return f"list[{len(value)}]"
    if isinstance(value, dict):
        return f"dict[{len(value)}]"
    return type(value).__name__


def likely(paths: Counter[str], hints: tuple[str, ...]) -> list[str]:
    rows = []
    for path, count in paths.items():
        low = path.lower()
        if any(hint in low for hint in hints):
            rows.append((path, count))
    rows.sort(key=lambda x: (-x[1], x[0]))
    return [f"{path} ({count})" for path, count in rows[:20]]


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect a JSON/JSONL security-agent log schema before CAIRN ingestion.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--sample", type=int, default=200)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    rows = load_rows(args.input, args.sample)
    paths: Counter[str] = Counter()
    examples: dict[str, str] = {}
    for row in rows:
        for path, value in walk(row):
            paths[path] += 1
            examples.setdefault(path, short_type(value))

    report = {
        "input": str(args.input),
        "rows_sampled": len(rows),
        "top_paths": [{"path": p, "count": c, "type": examples.get(p, "")} for p, c in paths.most_common(80)],
        "likely_session_fields": likely(paths, SESSION_HINTS),
        "likely_tool_input_fields": likely(paths, TOOL_HINTS),
        "likely_output_fields": likely(paths, OUTPUT_HINTS),
        "likely_token_or_size_fields": likely(paths, TOKEN_HINTS),
        "likely_provenance_fields": likely(paths, PROVENANCE_HINTS),
        "read": (
            "Use this before pilot ingestion to understand a security-agent export. "
            "If fields are ambiguous, an AI cleaner should map these paths into CAIRN's cleaned JSONL schema locally."
        ),
    }

    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
