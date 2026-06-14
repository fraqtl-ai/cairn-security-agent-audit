#!/usr/bin/env python3
"""CAIRN local audit for AI-agent JSON/JSONL tool traces.

This is product v0: an offline audit only. It does not serve cached outputs.

Example:
    python cairn_audit_agent_logs.py --input logs.jsonl --out report --price-input-per-m 3.0
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import html
import json
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ENVELOPE_TOKENS = 16
BYTES_PER_TOKEN = 4
MAX_EXAMPLES = 20
VOLATILE_FAMILIES = {
    "date",
    "ps",
    "top",
    "uptime",
    "curl",
    "wget",
    "pbcopy",
    "open",
    "sleep",
    "kill",
    "say",
    "osascript",
}
PROTECTED_FIELDS = (
    "tenant",
    "workspace",
    "auth_scope",
    "route",
    "system_prompt_version",
    "prompt_version",
    "model",
    "model_family",
    "tool_version",
    "tool_schema_version",
    "repo_state",
    "repo_state_fingerprint",
    "corpus_version",
    "evidence_hash",
    "recent_user_correction",
    "active_session_variables",
)


@dataclass
class Event:
    index: int
    session_id: str
    family: str
    tool_name: str
    command_text: str
    cwd: str
    output_text: str
    output_hash: str
    output_tokens: int
    protected: dict[str, str]
    raw_shape: str

    @property
    def work_key(self) -> tuple[str, str, str]:
        return (self.cwd, self.family, self.command_text)


def approx_tokens(text: str = "", byte_count: int | None = None) -> int:
    if byte_count is None:
        byte_count = len(text.encode("utf-8", errors="replace"))
    return max(1, (byte_count + BYTES_PER_TOKEN - 1) // BYTES_PER_TOKEN) if byte_count else 0


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def first_present(obj: dict[str, Any], keys: tuple[str, ...], default: Any = "") -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return default


def nested_get(obj: dict[str, Any], path: tuple[str, ...], default: Any = "") -> Any:
    cur: Any = obj
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur if cur not in (None, "") else default


def command_head(text: str, tool_name: str = "") -> str:
    shell_wrappers = {"bash", "sh", "zsh", "shell", "execute_bash", "terminal"}
    if tool_name and str(tool_name).strip() not in shell_wrappers:
        tool = Path(str(tool_name).strip()).name
        if tool:
            return tool
    clean = re.sub(r"^\s*cd\s+[^&;]+\s*&&\s*", "", str(text).strip())
    clean = re.sub(r"^\s*\d{1,3}(?:\.\d{1,3}){3}\s+\$\s*", "", clean)
    if not clean:
        return "unknown"
    parts = clean.split()
    return Path(parts[0]).name if parts else "unknown"


def command_text_from_row(row: dict[str, Any]) -> str:
    direct = first_present(
        row,
        (
            "command_text",
            "command",
            "cmd",
            "input",
            "tool_input",
            "query",
            "name",
        ),
    )
    if isinstance(direct, list):
        return " ".join(map(str, direct))
    if isinstance(direct, dict):
        for key in ("command", "cmd", "query", "input", "path"):
            if direct.get(key):
                value = direct[key]
                return " ".join(map(str, value)) if isinstance(value, list) else str(value)
        return stable_json(direct)
    if direct:
        return str(direct)

    payload = row.get("payload") or {}
    if isinstance(payload, dict):
        parsed = payload.get("parsed_cmd") or []
        if parsed and isinstance(parsed, list) and isinstance(parsed[0], dict) and parsed[0].get("cmd"):
            return str(parsed[0]["cmd"])
        raw = payload.get("command") or []
        if isinstance(raw, list):
            if len(raw) >= 3 and str(raw[0]).endswith(("zsh", "bash", "sh")):
                return str(raw[2])
            return " ".join(map(str, raw))
    return ""


def output_text_from_row(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("output", "observation", "content", "result", "stdout", "stderr", "aggregated_output"):
        value = row.get(key)
        if value not in (None, ""):
            parts.append(value if isinstance(value, str) else stable_json(value))
    payload = row.get("payload") or {}
    if isinstance(payload, dict):
        for key in ("aggregated_output", "stdout", "stderr", "output", "observation"):
            value = payload.get(key)
            if value not in (None, ""):
                parts.append(value if isinstance(value, str) else stable_json(value))
    return "\n".join(parts)


def output_hash_from_row(row: dict[str, Any], output_text: str) -> str:
    stdout_hash = row.get("stdout_sha256")
    stderr_hash = row.get("stderr_sha256")
    exit_code = row.get("exit_code")
    if stdout_hash or stderr_hash:
        return stable_json({"exit_code": exit_code, "stdout_sha256": stdout_hash, "stderr_sha256": stderr_hash})
    explicit = first_present(row, ("output_sha256", "output_hash", "response_hash", "content_hash"), "")
    if explicit:
        return str(explicit)
    return sha256_text(output_text)


def output_tokens_from_row(row: dict[str, Any], output_text: str) -> int:
    tokens = first_present(row, ("output_tokens", "tokens", "token_count", "response_tokens"), None)
    if isinstance(tokens, (int, float)) and tokens >= 0:
        return int(tokens)
    stdout_bytes = row.get("stdout_bytes")
    stderr_bytes = row.get("stderr_bytes")
    if isinstance(stdout_bytes, (int, float)) or isinstance(stderr_bytes, (int, float)):
        return approx_tokens(byte_count=int(stdout_bytes or 0) + int(stderr_bytes or 0))
    return approx_tokens(output_text)


def protected_from_row(row: dict[str, Any], cwd: str, tool_name: str) -> dict[str, str]:
    protected: dict[str, str] = {"cwd": str(cwd), "tool_name": str(tool_name)}
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    before = row.get("before") if isinstance(row.get("before"), dict) else {}
    after = row.get("after") if isinstance(row.get("after"), dict) else {}

    for field in PROTECTED_FIELDS:
        value = first_present(row, (field,), "")
        if value == "":
            value = metadata.get(field, "")
        if value == "" and field in {"repo_state", "repo_state_fingerprint"}:
            value = first_present(before, ("fingerprint", "repo_state", "repo_state_fingerprint"), "")
        if value != "":
            protected[field] = stable_json(value) if isinstance(value, (dict, list)) else str(value)

    for field in ("repo", "dataset", "license"):
        value = metadata.get(field, "")
        if value != "":
            protected[field] = str(value)

    for field in ("git_head", "git_diff_hash", "tracked_tree_hash"):
        value = first_present(before, (field,), "")
        if value != "":
            protected[field] = str(value)

    recent_changed = bool(row.get("mutated_repo_state") or row.get("recent_state_changed"))
    if recent_changed:
        protected["recent_state_changed"] = "true"
    if after and before and before.get("fingerprint") and after.get("fingerprint") != before.get("fingerprint"):
        protected["recent_state_changed"] = "true"
    return protected


def infer_session_id(row: dict[str, Any], fallback: str) -> str:
    value = first_present(row, ("session_id", "conversation_id", "thread_id", "trace_id", "run_id", "trajectory_id"), "")
    if value:
        return str(value)
    value = nested_get(row, ("metadata", "session_id"), "")
    return str(value or fallback)


def normalize_row(row: dict[str, Any], index: int, fallback_session: str) -> Event | None:
    command = command_text_from_row(row).strip()
    tool_name = str(first_present(row, ("tool_name", "tool", "name"), "") or "")
    if not command and tool_name:
        command = tool_name
    if not command:
        return None
    family = command_head(command, tool_name)
    source = str(row.get("source") or row.get("schema") or row.get("type") or "generic_json")
    security_sources = {"autopenbench", "security_agent_log", "pentest_steps", "cairn_security_agent_trace_v0"}
    if family in VOLATILE_FAMILIES and source not in security_sources:
        return None
    output_text = output_text_from_row(row)
    tokens = output_tokens_from_row(row, output_text)
    cwd = str(first_present(row, ("cwd", "working_dir", "repo_root"), "") or nested_get(row, ("before", "cwd"), ""))
    return Event(
        index=index,
        session_id=infer_session_id(row, fallback_session),
        family=family,
        tool_name=tool_name or family,
        command_text=command,
        cwd=cwd,
        output_text=output_text,
        output_hash=output_hash_from_row(row, output_text),
        output_tokens=tokens,
        protected=protected_from_row(row, cwd, tool_name or family),
        raw_shape=source,
    )


def load_objects(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if not stripped:
        return []
    if stripped[0] in "[{":
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)]
            if isinstance(parsed, dict):
                for key in ("events", "records", "logs", "trace", "messages"):
                    if isinstance(parsed.get(key), list):
                        return [x for x in parsed[key] if isinstance(x, dict)]
                return [parsed]
        except json.JSONDecodeError:
            pass

    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{line_no}: invalid JSONL line: {exc}") from exc
        if isinstance(value, dict):
            rows.append(value)
    return rows


def load_events(path: Path) -> list[Event]:
    raw = load_objects(path)
    events: list[Event] = []
    fallback_session = path.stem
    for idx, row in enumerate(raw):
        event = normalize_row(row, idx, fallback_session)
        if event is not None:
            events.append(event)
    return events


def delta_tokens(prev: str, curr: str) -> int:
    if prev == curr:
        return ENVELOPE_TOKENS
    diff = "\n".join(difflib.unified_diff(prev.splitlines(), curr.splitlines(), lineterm="", n=1))
    return ENVELOPE_TOKENS + approx_tokens(diff)


def protected_violations(prev: Event, curr: Event) -> list[str]:
    keys = sorted(set(prev.protected) | set(curr.protected))
    violations: list[str] = []
    for key in keys:
        if prev.protected.get(key, "") != curr.protected.get(key, ""):
            violations.append(key)
    return violations


def pct(n: int | float, d: int | float) -> float:
    return float(n) / float(d) if d else 0.0


def money(tokens: int, price_per_m: float) -> float:
    return tokens * price_per_m / 1_000_000.0


def recommended_action(summary: dict[str, Any]) -> str:
    ratio = summary["avoided_token_ratio_on_reread_traffic"]
    carried = summary["cumulative_carried_context_tokens_avoided"]
    blocks = summary["protected_lane_blocks"]
    rereads = summary["re_reads"]
    if rereads == 0:
        return "No pilot signal yet: provide a larger day/week of agent tool traces with outputs."
    if ratio >= 0.30 and carried > 0:
        return "Run a one-week local pilot with the same audit and prioritize delta-serving integration for top repeated families."
    if blocks > 0:
        return "Keep audit-only mode and add stronger provenance fields before any serving; stale exact-cache risk is visible."
    if ratio >= 0.10:
        return "Useful feature signal: audit a larger trace and inspect the top repeated families before integration work."
    return "Weak savings signal on this trace: collect broader logs or target a different workflow."


def analyze(events: list[Event], price_input_per_m: float) -> dict[str, Any]:
    by_session: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_session[event.session_id].append(event)

    totals = {
        "sessions": len(by_session),
        "events": len(events),
        "re_reads": 0,
        "re_read_output_tokens": 0,
        "served_tokens_after_cairn_policy": 0,
        "point_tokens_avoided": 0,
        "cumulative_carried_context_tokens_avoided": 0,
        "exact_cache_opportunities": 0,
        "delta_serve_opportunities": 0,
        "protected_lane_blocks": 0,
        "block_reuse_actions": 0,
        "live_call_actions": 0,
        "exact_cache_stale_risk_events": 0,
        "identical_rereads": 0,
        "false_hits": 0,
        "stale_serves": 0,
    }
    family_rows: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "events": 0,
            "re_reads": 0,
            "re_read_output_tokens": 0,
            "point_tokens_avoided": 0,
            "cumulative_carried_context_tokens_avoided": 0,
            "exact_cache_opportunities": 0,
            "delta_serve_opportunities": 0,
            "protected_lane_blocks": 0,
        }
    )
    action_counts = Counter()
    repeat_counter = Counter()
    shape_counter = Counter(event.raw_shape for event in events)
    examples: list[dict[str, Any]] = []

    for session_events in by_session.values():
        last_seen: dict[tuple[str, str, str], Event] = {}
        for idx, event in enumerate(session_events):
            family_rows[event.family]["events"] += 1
            prev = last_seen.get(event.work_key)
            if prev is None:
                action_counts["LIVE_CALL"] += 1
                totals["live_call_actions"] += 1
                last_seen[event.work_key] = event
                continue

            repeat_counter[(event.family, event.command_text)] += 1
            full_tokens = max(1, event.output_tokens)
            totals["re_reads"] += 1
            totals["re_read_output_tokens"] += full_tokens
            family = family_rows[event.family]
            family["re_reads"] += 1
            family["re_read_output_tokens"] += full_tokens

            violations = protected_violations(prev, event)
            same_output = prev.output_hash == event.output_hash
            if same_output:
                totals["identical_rereads"] += 1
            if violations:
                totals["protected_lane_blocks"] += 1
                family["protected_lane_blocks"] += 1
                totals["exact_cache_stale_risk_events"] += 1

            if not violations and same_output:
                action = "EXACT_CACHE"
                served = min(full_tokens, ENVELOPE_TOKENS)
                totals["exact_cache_opportunities"] += 1
                family["exact_cache_opportunities"] += 1
            elif prev.output_text and event.output_text:
                action = "DELTA_SERVE"
                served = min(full_tokens, delta_tokens(prev.output_text, event.output_text))
                totals["delta_serve_opportunities"] += 1
                family["delta_serve_opportunities"] += 1
            else:
                action = "BLOCK_REUSE"
                served = full_tokens
                totals["block_reuse_actions"] += 1
            action_counts[action] += 1

            avoided = max(0, full_tokens - served)
            carried = avoided * max(0, len(session_events) - idx - 1)
            totals["served_tokens_after_cairn_policy"] += served
            totals["point_tokens_avoided"] += avoided
            totals["cumulative_carried_context_tokens_avoided"] += carried
            family["point_tokens_avoided"] += avoided
            family["cumulative_carried_context_tokens_avoided"] += carried

            if len(examples) < MAX_EXAMPLES and (avoided > 0 or violations):
                examples.append(
                    {
                        "session_id": event.session_id,
                        "event_index": event.index,
                        "family": event.family,
                        "command_text": event.command_text[:500],
                        "action": action,
                        "full_tokens": full_tokens,
                        "served_tokens": served,
                        "point_tokens_avoided": avoided,
                        "protected_lane_violations": violations[:12],
                        "same_output_hash": same_output,
                    }
                )
            last_seen[event.work_key] = event

    top_families = []
    for family, row in family_rows.items():
        if row["events"] <= 0:
            continue
        item = {"family": family, **row}
        item["repeated_work_share"] = pct(row["re_reads"], row["events"])
        item["avoided_token_ratio_on_rereads"] = pct(row["point_tokens_avoided"], row["re_read_output_tokens"])
        top_families.append(item)
    top_families.sort(key=lambda r: r["cumulative_carried_context_tokens_avoided"], reverse=True)

    top_repeated_commands = [
        {"family": family, "command_text": command[:500], "re_reads": count}
        for (family, command), count in repeat_counter.most_common(20)
    ]

    summary = {
        **totals,
        "repeated_work_percent": 100.0 * pct(totals["re_reads"], totals["events"]),
        "avoided_token_ratio_on_reread_traffic": pct(totals["point_tokens_avoided"], totals["re_read_output_tokens"]),
        "context_multiplier_on_avoided_tokens": pct(
            totals["cumulative_carried_context_tokens_avoided"], totals["point_tokens_avoided"]
        ),
        "estimated_point_input_dollars_saved": money(totals["point_tokens_avoided"], price_input_per_m),
        "estimated_carried_context_input_dollars_saved": money(
            totals["cumulative_carried_context_tokens_avoided"], price_input_per_m
        ),
        "price_input_per_million_tokens": price_input_per_m,
    }
    summary["recommended_next_action"] = recommended_action(summary)

    return {
        "schema": "cairn_agent_log_audit_v0",
        "generated_at_unix": int(time.time()),
        "policy": (
            "Offline audit only. EXACT_CACHE is counted only when protected fields and output hash match. "
            "DELTA_SERVE is counted only when prior and current live output text are present. "
            "Changed protected fields are reported as stale exact-cache risk, not served."
        ),
        "token_estimator": "explicit output_tokens if present, otherwise bytes/4 proxy",
        "summary": summary,
        "actions": {
            "LIVE_CALL": action_counts["LIVE_CALL"],
            "DELTA_SERVE": action_counts["DELTA_SERVE"],
            "EXACT_CACHE": action_counts["EXACT_CACHE"],
            "BLOCK_REUSE": action_counts["BLOCK_REUSE"],
        },
        "input_shapes": dict(shape_counter),
        "top_repeated_families": top_families[:20],
        "top_repeated_commands": top_repeated_commands,
        "top_examples": examples,
        "caveats": [
            "This is an audit, not auto-serving.",
            "Dollar savings use the provided input-token price and should be treated as a trace-local estimate.",
            "Logs without live output text can show exact-cache opportunities and stale risk, but not delta-serving savings.",
            "Protected-lane quality depends on the provenance fields present in the input logs.",
        ],
    }


def fmt_int(value: int | float) -> str:
    return f"{int(value):,}"


def fmt_pct(value: float) -> str:
    return f"{100.0 * value:.2f}%"


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_markdown(path: Path, result: dict[str, Any], input_path: Path) -> None:
    s = result["summary"]
    lines = [
        "# CAIRN Agent Log Audit",
        "",
        f"Input: `{input_path}`",
        "",
        "## Summary",
        "",
        f"- Events audited: `{fmt_int(s['events'])}`",
        f"- Sessions: `{fmt_int(s['sessions'])}`",
        f"- Re-reads: `{fmt_int(s['re_reads'])}` (`{s['repeated_work_percent']:.2f}%` of events)",
        f"- Re-read output tokens: `{fmt_int(s['re_read_output_tokens'])}`",
        f"- Point tokens avoided: `{fmt_int(s['point_tokens_avoided'])}`",
        f"- Cumulative carried-context tokens avoided: `{fmt_int(s['cumulative_carried_context_tokens_avoided'])}`",
        f"- Avoided-token ratio on re-read traffic: `{fmt_pct(s['avoided_token_ratio_on_reread_traffic'])}`",
        f"- Context multiplier on avoided tokens: `{s['context_multiplier_on_avoided_tokens']:.2f}x`",
        f"- Estimated point-token input savings: `${s['estimated_point_input_dollars_saved']:.4f}`",
        f"- Estimated carried-context input savings: `${s['estimated_carried_context_input_dollars_saved']:.4f}`",
        "",
        "## Actions",
        "",
    ]
    for action, count in result["actions"].items():
        lines.append(f"- `{action}`: `{fmt_int(count)}`")
    lines.extend(
        [
            "",
            "## Safety",
            "",
            f"- Protected-lane blocks: `{fmt_int(s['protected_lane_blocks'])}`",
            f"- Exact-cache stale-risk events: `{fmt_int(s['exact_cache_stale_risk_events'])}`",
            f"- Stale serves counted: `{fmt_int(s['stale_serves'])}`",
            f"- False hits counted: `{fmt_int(s['false_hits'])}`",
            "",
            "## Top Repeated Families",
            "",
            "| Family | Re-reads | Point Tokens Avoided | Carried-Context Tokens Avoided | Avoided Ratio |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for row in result["top_repeated_families"][:12]:
        lines.append(
            f"| `{row['family']}` | {fmt_int(row['re_reads'])} | "
            f"{fmt_int(row['point_tokens_avoided'])} | "
            f"{fmt_int(row['cumulative_carried_context_tokens_avoided'])} | "
            f"{fmt_pct(row['avoided_token_ratio_on_rereads'])} |"
        )
    lines.extend(["", "## Top Examples", ""])
    for ex in result["top_examples"][:10]:
        lines.append(
            f"- `{ex['action']}` `{ex['family']}` saved `{fmt_int(ex['point_tokens_avoided'])}` tokens; "
            f"violations: `{', '.join(ex['protected_lane_violations']) or 'none'}`; "
            f"command: `{ex['command_text']}`"
        )
    lines.extend(["", "## Recommended Next Action", "", s["recommended_next_action"], "", "## Caveats", ""])
    for caveat in result["caveats"]:
        lines.append(f"- {caveat}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_html(path: Path, result: dict[str, Any], input_path: Path) -> None:
    s = result["summary"]
    family_rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(row['family'])}</td>"
        f"<td>{fmt_int(row['re_reads'])}</td>"
        f"<td>{fmt_int(row['point_tokens_avoided'])}</td>"
        f"<td>{fmt_int(row['cumulative_carried_context_tokens_avoided'])}</td>"
        f"<td>{fmt_pct(row['avoided_token_ratio_on_rereads'])}</td>"
        "</tr>"
        for row in result["top_repeated_families"][:12]
    )
    examples = "\n".join(
        "<li>"
        f"<strong>{html.escape(ex['action'])}</strong> "
        f"{html.escape(ex['family'])}: saved {fmt_int(ex['point_tokens_avoided'])} tokens; "
        f"violations: {html.escape(', '.join(ex['protected_lane_violations']) or 'none')}; "
        f"<code>{html.escape(ex['command_text'])}</code>"
        "</li>"
        for ex in result["top_examples"][:10]
    )
    html_text = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CAIRN Agent Log Audit</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 32px; color: #17202a; }}
    main {{ max-width: 1040px; margin: 0 auto; }}
    h1, h2 {{ letter-spacing: 0; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }}
    .metric {{ border: 1px solid #d8dee4; border-radius: 8px; padding: 14px; }}
    .label {{ color: #57606a; font-size: 13px; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border-bottom: 1px solid #d8dee4; padding: 8px; text-align: right; }}
    th:first-child, td:first-child {{ text-align: left; }}
    code {{ background: #f6f8fa; padding: 2px 4px; border-radius: 4px; }}
    .note {{ background: #f6f8fa; border-left: 4px solid #57606a; padding: 12px 14px; }}
  </style>
</head>
<body>
<main>
  <h1>CAIRN Agent Log Audit</h1>
  <p>Input: <code>{html.escape(str(input_path))}</code></p>
  <section class="grid">
    <div class="metric"><div class="label">Events</div><div class="value">{fmt_int(s['events'])}</div></div>
    <div class="metric"><div class="label">Re-reads</div><div class="value">{fmt_int(s['re_reads'])}</div></div>
    <div class="metric"><div class="label">Repeated work</div><div class="value">{s['repeated_work_percent']:.2f}%</div></div>
    <div class="metric"><div class="label">Avoided ratio on re-reads</div><div class="value">{fmt_pct(s['avoided_token_ratio_on_reread_traffic'])}</div></div>
    <div class="metric"><div class="label">Point tokens avoided</div><div class="value">{fmt_int(s['point_tokens_avoided'])}</div></div>
    <div class="metric"><div class="label">Carried-context tokens avoided</div><div class="value">{fmt_int(s['cumulative_carried_context_tokens_avoided'])}</div></div>
  </section>
  <h2>Actions</h2>
  <p><code>LIVE_CALL</code> {fmt_int(result['actions']['LIVE_CALL'])} ·
     <code>DELTA_SERVE</code> {fmt_int(result['actions']['DELTA_SERVE'])} ·
     <code>EXACT_CACHE</code> {fmt_int(result['actions']['EXACT_CACHE'])} ·
     <code>BLOCK_REUSE</code> {fmt_int(result['actions']['BLOCK_REUSE'])}</p>
  <h2>Safety</h2>
  <p>Protected-lane blocks: <strong>{fmt_int(s['protected_lane_blocks'])}</strong>.
     Exact-cache stale-risk events: <strong>{fmt_int(s['exact_cache_stale_risk_events'])}</strong>.
     Stale serves counted: <strong>{fmt_int(s['stale_serves'])}</strong>.</p>
  <h2>Top Repeated Families</h2>
  <table>
    <thead><tr><th>Family</th><th>Re-reads</th><th>Point avoided</th><th>Carried avoided</th><th>Avoided ratio</th></tr></thead>
    <tbody>{family_rows}</tbody>
  </table>
  <h2>Examples</h2>
  <ul>{examples}</ul>
  <h2>Recommended Next Action</h2>
  <p class="note">{html.escape(s['recommended_next_action'])}</p>
</main>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit local AI-agent JSON/JSONL logs for CAIRN protected reuse signals.")
    parser.add_argument("--input", type=Path, required=True, help="JSON or JSONL trace file.")
    parser.add_argument("--out", type=Path, required=True, help="Report output directory.")
    parser.add_argument("--price-input-per-m", type=float, default=0.0, help="Input-token price per 1M tokens.")
    args = parser.parse_args()

    events = load_events(args.input)
    result = analyze(events, args.price_input_per_m)

    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / "summary.json", result)
    write_markdown(args.out / "summary.md", result, args.input)
    write_html(args.out / "report.html", result, args.input)
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    print(f"report -> {args.out}")


if __name__ == "__main__":
    main()
