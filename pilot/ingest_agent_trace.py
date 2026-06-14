#!/usr/bin/env python3
"""Normalize security-agent logs into CAIRN audit records.

This shareable pilot package intentionally supports a small set of practical
formats:

- JSONL with one tool event per line
- JSON arrays of tool events
- JSON objects with ``events`` / ``records`` / ``logs`` / ``trace`` lists
- pentest benchmark logs with ``steps[].thought/action/observation``
- directories containing JSON or JSONL files

The normalized output is local-only and audit-only. It is not used to execute
pentest actions or serve cached outputs.
"""

from __future__ import annotations

import argparse
import glob as globlib
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "cairn_security_agent_trace_v0"


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def approx_tokens(text: str) -> int:
    size = len(text.encode("utf-8", errors="replace"))
    return max(1, (size + 3) // 4) if size else 0


def first_present(obj: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        value = obj.get(key)
        if value not in (None, ""):
            return value
    return default


def stringify(value: Any) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return " ".join(stringify(item) for item in value if item not in (None, ""))
    if isinstance(value, dict):
        return stable_json(value)
    return str(value)


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def rows_from_json_object(obj: Any) -> list[dict[str, Any]]:
    if isinstance(obj, list):
        return [row for row in obj if isinstance(row, dict)]
    if not isinstance(obj, dict):
        return []
    for key in ("events", "records", "logs", "trace", "messages", "trajectory"):
        value = obj.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return [obj]


def iter_input(path: Path, pattern: str | None = None) -> Iterable[tuple[Path, dict[str, Any]]]:
    paths: list[Path]
    if path.is_dir():
        glob_pattern = pattern or "*.json*"
        paths = [Path(p) for p in sorted(globlib.glob(str(path / glob_pattern)))]
    else:
        paths = [path]

    for item in paths:
        suffix = item.suffix.lower()
        if suffix in {".jsonl", ".ndjson"}:
            for row in iter_jsonl(item):
                yield item, row
            continue
        if suffix in {".parquet", ".pq"}:
            try:
                import pandas as pd  # type: ignore
            except Exception as exc:
                raise SystemExit(
                    "Parquet input requires pandas plus pyarrow or fastparquet. "
                    "Convert a small sample to JSONL if those packages are unavailable."
                ) from exc
            frame = pd.read_parquet(item)
            for row in frame.to_dict(orient="records"):
                if isinstance(row, dict):
                    yield item, row
            continue
        try:
            parsed = json.loads(item.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        for row in rows_from_json_object(parsed):
            yield item, row


def parse_action(action: Any) -> tuple[str, str]:
    text = stringify(action).strip()
    if not text:
        return "unknown", ""
    match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\((.*)\)\s*$", text, re.DOTALL)
    if match:
        name = match.group(1)
        body = match.group(2).strip()
        return name, body.strip("\"'")
    if text.lower().startswith("action:"):
        return parse_action(text.split(":", 1)[1].strip())
    return text.split()[0], text


def output_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("output", "observation", "stdout", "stderr", "result", "response", "content"):
        value = row.get(key)
        if value not in (None, ""):
            parts.append(stringify(value))
    return "\n".join(parts)


def state_value(row: dict[str, Any], path: Path, session_id: str, step_index: int) -> str:
    for key in ("target_state", "session_state", "state", "provenance", "fingerprint"):
        value = row.get(key)
        if value not in (None, ""):
            return stringify(value)
    target = first_present(row, ("target", "host", "ip", "url", "workspace"), "")
    return sha256_text(f"{path}:{session_id}:{target}:{step_index // 4}")[:16]


def normalize_direct_event(path: Path, row: dict[str, Any], index: int) -> dict[str, Any]:
    session_id = stringify(first_present(row, ("session_id", "run_id", "trace_id", "trajectory_id", "conversation_id"), path.stem))
    tool_name = stringify(first_present(row, ("tool", "tool_name", "action_name", "function", "name"), "security_tool"))
    command_text = stringify(first_present(row, ("command", "command_text", "cmd", "action", "tool_input", "input", "query"), ""))
    out = output_text(row)
    before_state = state_value(row.get("before", row) if isinstance(row.get("before"), dict) else row, path, session_id, index)
    after_state = state_value(row.get("after", row) if isinstance(row.get("after"), dict) else row, path, session_id, index)
    output_tokens = first_present(row, ("output_tokens", "tokens", "token_count", "response_tokens"), None)

    return {
        "schema": SCHEMA,
        "source": "security_agent_log",
        "session_id": session_id,
        "step_index": int(first_present(row, ("step", "step_index", "index"), index) or index),
        "tool_name": tool_name,
        "command_text": command_text or tool_name,
        "stdout": out,
        "stderr": stringify(row.get("stderr", "")),
        "output_tokens": int(output_tokens) if isinstance(output_tokens, (int, float)) else approx_tokens(out),
        "before": {"fingerprint": before_state},
        "after": {"fingerprint": after_state},
        "metadata": {"input_file": str(path), "original_shape": "direct_event"},
    }


def normalize_pentest_steps(path: Path, row: dict[str, Any], args: argparse.Namespace) -> list[dict[str, Any]]:
    steps = row.get("steps")
    if not isinstance(steps, list):
        return []
    session_id = stringify(first_present(row, ("session_id", "run_id", "id", "task_id", "name"), path.stem))
    target = stringify(first_present(row, ("target", "host", "ip", "machine", "scenario"), path.stem))
    records: list[dict[str, Any]] = []
    state_epoch = 0
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        action_name, command = parse_action(first_present(step, ("action", "tool", "command", "cmd"), ""))
        observation = stringify(first_present(step, ("observation", "output", "result", "stdout", "stderr"), ""))
        if action_name in {"SSHConnect", "WriteFile", "ExecuteBash"}:
            state_epoch += 1
        before = sha256_text(f"{target}:{session_id}:{state_epoch}")[:16]
        after_epoch = state_epoch + 1 if action_name in {"SSHConnect", "WriteFile"} else state_epoch
        after = sha256_text(f"{target}:{session_id}:{after_epoch}")[:16]
        records.append(
            {
                "schema": SCHEMA,
                "source": "pentest_steps",
                "session_id": session_id,
                "step_index": idx,
                "tool_name": action_name or "security_tool",
                "command_text": command or action_name or "unknown",
                "stdout": observation,
                "stderr": "",
                "output_tokens": approx_tokens(observation),
                "before": {"fingerprint": before, "target": target},
                "after": {"fingerprint": after, "target": target},
                "metadata": {"input_file": str(path), "original_shape": "steps"},
            }
        )
        state_epoch = after_epoch
        if args.max_records and len(records) >= args.max_records:
            break
    return records


def convert_objects(items: list[tuple[Path, dict[str, Any]]], source: str, args: argparse.Namespace) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    stats: dict[str, Any] = {"input_objects": len(items), "records": 0, "sources": {}}
    for index, (path, row) in enumerate(items):
        converted = normalize_pentest_steps(path, row, args)
        if not converted:
            converted = [normalize_direct_event(path, row, index)]
        for record in converted:
            records.append(record)
            src = record.get("source", "security_agent_log")
            stats["sources"][src] = stats["sources"].get(src, 0) + 1
            if args.max_records and len(records) >= args.max_records:
                stats["records"] = len(records)
                return records, stats
    stats["records"] = len(records)
    return records, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize security-agent JSON/JSONL traces for CAIRN audit.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--glob", default=None)
    parser.add_argument("--max-records", type=int, default=0)
    parser.add_argument("--source", default="auto", help="Reserved for compatibility; auto is recommended.")
    args = parser.parse_args()

    loaded = list(iter_input(args.input, args.glob))
    records, stats = convert_objects(loaded, args.source, args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print(json.dumps(stats, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
