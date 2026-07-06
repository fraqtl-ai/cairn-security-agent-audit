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
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ENVELOPE_TOKENS = 16
BYTES_PER_TOKEN = 4
MAX_EXAMPLES = 20

# USD per 1M tokens. "input" = fresh input tokens; "cached_input" = provider
# prompt-cache READ price. Prices drift — verify against the provider pricing
# page before quoting a dollar figure externally.
MODEL_PRICES: dict[str, dict[str, float]] = {
    "claude-opus-4.5": {"input": 5.00, "cached_input": 0.50},
    "claude-opus-4.1": {"input": 15.00, "cached_input": 1.50},
    "claude-sonnet-4.5": {"input": 3.00, "cached_input": 0.30},
    "claude-sonnet-4": {"input": 3.00, "cached_input": 0.30},
    "claude-haiku-4.5": {"input": 1.00, "cached_input": 0.10},
    "gpt-5": {"input": 1.25, "cached_input": 0.125},
    "gpt-5-mini": {"input": 0.25, "cached_input": 0.025},
    "gpt-4.1": {"input": 2.00, "cached_input": 0.50},
    "gpt-4.1-mini": {"input": 0.40, "cached_input": 0.10},
    "gpt-4o": {"input": 2.50, "cached_input": 1.25},
    "o3": {"input": 2.00, "cached_input": 0.50},
}
# When no cached-input price is known, assume the provider caches carried
# context at the cheapest common rate (Anthropic cache-read = 0.1x input).
# This makes the net-of-provider-cache figure a conservative floor.
DEFAULT_CACHED_INPUT_RATIO = 0.1

_TOKEN_ENCODER: Any = None
_TOKEN_ESTIMATOR_NAME = "bytes/4"


def configure_tokenizer(mode: str = "auto") -> str:
    """Select the token estimator: 'bytes', 'tiktoken', or 'auto' (tiktoken if installed)."""
    global _TOKEN_ENCODER, _TOKEN_ESTIMATOR_NAME
    if mode not in {"auto", "tiktoken", "bytes"}:
        raise ValueError(f"unknown tokenizer mode: {mode!r}")
    if mode == "bytes":
        _TOKEN_ENCODER = None
        _TOKEN_ESTIMATOR_NAME = "bytes/4"
        return _TOKEN_ESTIMATOR_NAME
    try:
        import tiktoken

        _TOKEN_ENCODER = tiktoken.get_encoding("o200k_base")
        _TOKEN_ESTIMATOR_NAME = "tiktoken:o200k_base"
    except Exception as exc:
        if mode == "tiktoken":
            raise SystemExit(
                "tiktoken requested but unavailable "
                f"({exc}); install with: pip install 'cairn-security-agent-audit[tokens]'"
            )
        _TOKEN_ENCODER = None
        _TOKEN_ESTIMATOR_NAME = "bytes/4"
    return _TOKEN_ESTIMATOR_NAME


def token_estimator_name() -> str:
    return _TOKEN_ESTIMATOR_NAME
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
    ts: float | None = None
    has_output: bool = False
    has_output_text: bool = False
    user_id: str = ""

    @property
    def work_key(self) -> tuple[str, str, str]:
        return (self.cwd, self.family, self.command_text)


def approx_tokens(text: str = "", byte_count: int | None = None) -> int:
    if _TOKEN_ENCODER is not None and byte_count is None:
        if not text:
            return 0
        try:
            return max(1, len(_TOKEN_ENCODER.encode(text, disallowed_special=())))
        except Exception:
            pass
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


def infer_user_id(row: dict[str, Any]) -> str:
    value = first_present(row, ("user_id", "user", "username", "actor", "developer_id", "email"), "")
    if isinstance(value, dict):
        value = first_present(value, ("id", "email", "name"), "")
    if not value:
        for path in (("metadata", "user_id"), ("metadata", "user"), ("metadata", "email")):
            value = nested_get(row, path, "")
            if value:
                break
    return str(value or "")


def infer_session_id(row: dict[str, Any], fallback: str) -> str:
    value = first_present(row, ("session_id", "conversation_id", "thread_id", "trace_id", "run_id", "trajectory_id"), "")
    if value:
        return str(value)
    value = nested_get(row, ("metadata", "session_id"), "")
    return str(value or fallback)


def parse_timestamp(row: dict[str, Any]) -> float | None:
    raw = first_present(
        row,
        ("timestamp", "ts", "time", "created_at", "start_time", "started_at", "event_time", "@timestamp"),
        None,
    )
    if raw in (None, ""):
        raw = nested_get(row, ("metadata", "timestamp"), None)
    if raw in (None, "") or isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        return float(raw)
    text = str(raw).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def normalize_row(
    row: dict[str, Any],
    index: int,
    fallback_session: str,
    skip_stats: dict[str, int] | None = None,
) -> Event | None:
    command = command_text_from_row(row).strip()
    tool_name = str(first_present(row, ("tool_name", "tool", "name"), "") or "")
    if not command and tool_name:
        command = tool_name
    if not command:
        if skip_stats is not None:
            skip_stats["no_recognizable_command"] = skip_stats.get("no_recognizable_command", 0) + 1
        return None
    family = command_head(command, tool_name)
    source = str(row.get("source") or row.get("schema") or row.get("type") or "generic_json")
    security_sources = {"autopenbench", "security_agent_log", "pentest_steps", "cairn_security_agent_trace_v0"}
    if family in VOLATILE_FAMILIES and source not in security_sources:
        if skip_stats is not None:
            skip_stats["volatile_family_excluded"] = skip_stats.get("volatile_family_excluded", 0) + 1
        return None
    output_text = output_text_from_row(row)
    tokens = output_tokens_from_row(row, output_text)
    explicit_output_hash = first_present(
        row, ("stdout_sha256", "stderr_sha256", "output_sha256", "output_hash", "response_hash", "content_hash"), ""
    )
    has_output = bool(output_text) or bool(explicit_output_hash)
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
        ts=parse_timestamp(row),
        has_output=has_output,
        has_output_text=bool(output_text),
        user_id=infer_user_id(row),
    )


def load_objects(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.lstrip()
    if not stripped:
        return [], []
    if stripped[0] in "[{":
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)], []
            if isinstance(parsed, dict):
                for key in ("events", "records", "logs", "trace", "messages"):
                    if isinstance(parsed.get(key), list):
                        return [x for x in parsed[key] if isinstance(x, dict)], []
                return [parsed], []
        except json.JSONDecodeError:
            pass

    rows: list[dict[str, Any]] = []
    malformed: list[str] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed.append(f"{path.name}:{line_no}: {exc}")
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows, malformed


def load_events_with_stats(path: Path) -> tuple[list[Event], list[str], dict[str, int]]:
    raw, malformed = load_objects(path)
    events: list[Event] = []
    skip_stats: dict[str, int] = {}
    fallback_session = path.stem
    for idx, row in enumerate(raw):
        event = normalize_row(row, idx, fallback_session, skip_stats)
        if event is not None:
            events.append(event)
    return events, malformed, skip_stats


def load_events_verbose(path: Path) -> tuple[list[Event], list[str]]:
    events, malformed, _ = load_events_with_stats(path)
    return events, malformed


def load_events(path: Path) -> list[Event]:
    events, _ = load_events_verbose(path)
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


def resolve_prices(
    price_input_per_m: float,
    price_cached_input_per_m: float | None,
    model: str,
) -> tuple[float, float, str]:
    """Return (input price, cached-input price, provenance note) per 1M tokens."""
    source = "flags"
    if model:
        key = model.strip().lower()
        table = MODEL_PRICES.get(key)
        if table is None:
            for name, row in MODEL_PRICES.items():
                if key.startswith(name):
                    table = row
                    break
        if table is not None:
            if not price_input_per_m:
                price_input_per_m = table["input"]
            if price_cached_input_per_m is None:
                price_cached_input_per_m = table["cached_input"]
            source = f"built-in price table for {model} (verify against provider pricing page)"
        else:
            source = f"flags (model {model!r} not in built-in price table)"
    if price_cached_input_per_m is None:
        price_cached_input_per_m = price_input_per_m * DEFAULT_CACHED_INPUT_RATIO
        source += f"; cached-input defaulted to {DEFAULT_CACHED_INPUT_RATIO:.0%} of input"
    return price_input_per_m, price_cached_input_per_m, source


def recommended_action(summary: dict[str, Any]) -> str:
    ratio = summary["avoided_token_ratio_on_reread_traffic"]
    carried = summary["cumulative_carried_context_tokens_avoided"]
    blocks = summary["protected_lane_blocks"]
    rereads = summary["re_reads"]
    if rereads == 0:
        return "No pilot signal yet: provide a larger day/week of agent tool traces with outputs."
    if summary.get("false_hits", 0) > 0:
        return (
            "Do not exact-cache on provenance alone yet: some provenance-matched re-reads changed output "
            "(see false-hit rate). Delta-serve or strengthen protected fields, then re-audit."
        )
    if ratio >= 0.30 and carried > 0:
        return "Run a one-week local pilot with the same audit and prioritize delta-serving integration for top repeated families."
    if blocks > 0:
        return "Keep audit-only mode and add stronger provenance fields before any serving; stale exact-cache risk is visible."
    if ratio >= 0.10:
        return "Useful feature signal: audit a larger trace and inspect the top repeated families before integration work."
    return "Weak savings signal on this trace: collect broader logs or target a different workflow."


def provenance_safety_note(summary: dict[str, Any]) -> str:
    decidable = summary["provenance_decidable_rereads"]
    false_hits = summary["false_hits"]
    if decidable == 0:
        return "No decidable re-reads yet (need repeated work with observable outputs on both sides)."
    if false_hits == 0:
        return (
            f"0 of {decidable} provenance-matched re-reads changed output: on this trace the provenance "
            "fingerprint is a safe exact-cache key (0.00% false-hit risk)."
        )
    rate = 100.0 * summary["provenance_exact_cache_false_hit_rate"]
    return (
        f"{false_hits} of {decidable} provenance-matched re-reads had CHANGED output ({rate:.2f}% false-hit risk): "
        "provenance alone is not a safe exact-cache key here; delta-serve/verify or strengthen protected fields "
        "before exact-cache serving."
    )


def analyze(
    events: list[Event],
    price_input_per_m: float = 0.0,
    price_cached_input_per_m: float | None = None,
    model: str = "",
) -> dict[str, Any]:
    price_input_per_m, price_cached_input_per_m, price_source = resolve_prices(
        price_input_per_m, price_cached_input_per_m, model
    )
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
        "provenance_decidable_rereads": 0,
        "false_hits": 0,
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
    user_rows: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "events": 0,
            "re_reads": 0,
            "re_read_output_tokens": 0,
            "point_tokens_avoided": 0,
            "cumulative_carried_context_tokens_avoided": 0,
        }
    )
    action_counts = Counter()
    repeat_counter = Counter()
    shape_counter = Counter(event.raw_shape for event in events)
    examples: list[dict[str, Any]] = []

    for raw_session_events in by_session.values():
        # Repeat detection depends on chronological order. Sort by timestamp when
        # every event in the session carries one; otherwise preserve input order.
        if raw_session_events and all(e.ts is not None for e in raw_session_events):
            session_events = sorted(raw_session_events, key=lambda e: (e.ts, e.index))
        else:
            session_events = raw_session_events
        last_seen: dict[tuple[str, str, str], Event] = {}
        for idx, event in enumerate(session_events):
            family_rows[event.family]["events"] += 1
            user = user_rows[event.user_id or "(unattributed)"]
            user["events"] += 1
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
            user["re_reads"] += 1
            user["re_read_output_tokens"] += full_tokens

            violations = protected_violations(prev, event)
            both_have_output = prev.has_output and event.has_output
            both_have_text = prev.has_output_text and event.has_output_text
            same_output = both_have_output and prev.output_hash == event.output_hash
            if same_output:
                totals["identical_rereads"] += 1
            if violations:
                totals["protected_lane_blocks"] += 1
                family["protected_lane_blocks"] += 1
                totals["exact_cache_stale_risk_events"] += 1

            if not violations and same_output:
                # Provenance matched and output was identical: exact-cache is safe.
                action = "EXACT_CACHE"
                served = min(full_tokens, ENVELOPE_TOKENS)
                totals["exact_cache_opportunities"] += 1
                family["exact_cache_opportunities"] += 1
                totals["provenance_decidable_rereads"] += 1
            elif not violations and both_have_output:
                # Provenance matched but output CHANGED: a naive provenance-only exact
                # cache would have served a stale/wrong result. This is the real
                # false-hit signal, counted whether or not the raw text is present.
                totals["false_hits"] += 1
                totals["provenance_decidable_rereads"] += 1
                if both_have_text:
                    # CAIRN delta-serves the change instead of exact-caching.
                    action = "DELTA_SERVE"
                    served = min(full_tokens, delta_tokens(prev.output_text, event.output_text))
                    totals["delta_serve_opportunities"] += 1
                    family["delta_serve_opportunities"] += 1
                else:
                    # Output changed but only hashes are observable: the delta cannot
                    # be reconstructed, so no savings are claimed.
                    action = "BLOCK_REUSE"
                    served = full_tokens
                    totals["block_reuse_actions"] += 1
            elif violations and both_have_text:
                # Provenance changed and both outputs present: delta-serve the change.
                action = "DELTA_SERVE"
                served = min(full_tokens, delta_tokens(prev.output_text, event.output_text))
                totals["delta_serve_opportunities"] += 1
                family["delta_serve_opportunities"] += 1
            else:
                # Cannot certify reuse (output missing or not reconstructable): claim nothing.
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
            user["point_tokens_avoided"] += avoided
            user["cumulative_carried_context_tokens_avoided"] += carried

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

    top_users = []
    for user_id, row in user_rows.items():
        if row["events"] <= 0:
            continue
        item = {"user_id": user_id, **row}
        item["repeated_work_share"] = pct(row["re_reads"], row["events"])
        top_users.append(item)
    top_users.sort(key=lambda r: r["cumulative_carried_context_tokens_avoided"], reverse=True)

    point = totals["point_tokens_avoided"]
    carried = totals["cumulative_carried_context_tokens_avoided"]
    summary = {
        **totals,
        "repeated_work_percent": 100.0 * pct(totals["re_reads"], totals["events"]),
        "avoided_token_ratio_on_reread_traffic": pct(totals["point_tokens_avoided"], totals["re_read_output_tokens"]),
        "context_multiplier_on_avoided_tokens": pct(
            totals["cumulative_carried_context_tokens_avoided"], totals["point_tokens_avoided"]
        ),
        "provenance_exact_cache_false_hit_rate": pct(totals["false_hits"], totals["provenance_decidable_rereads"]),
        "attributed_users": sum(1 for u in top_users if u["user_id"] != "(unattributed)"),
        "estimated_point_input_dollars_saved": money(point, price_input_per_m),
        "estimated_carried_context_input_dollars_saved": money(carried, price_input_per_m),
        # Upper bound: every avoided token priced at the fresh input rate
        # (assumes the buyer uses no provider prompt caching at all).
        "estimated_total_dollars_saved_no_provider_cache": money(point + carried, price_input_per_m),
        # Conservative floor: carried-context tokens are stable-prefix traffic the
        # provider prompt cache would mostly have served at the cached-input rate,
        # so they are priced at cached-input; point tokens are fresh output that a
        # prefix cache can never serve, so they stay at the full input rate.
        "estimated_total_dollars_saved_net_of_provider_cache": (
            money(point, price_input_per_m) + money(carried, price_cached_input_per_m)
        ),
        "price_input_per_million_tokens": price_input_per_m,
        "price_cached_input_per_million_tokens": price_cached_input_per_m,
        "price_source": price_source,
    }
    summary["recommended_next_action"] = recommended_action(summary)
    summary["provenance_safety_note"] = provenance_safety_note(summary)

    return {
        "schema": "cairn_agent_log_audit_v0",
        "generated_at_unix": int(time.time()),
        "policy": (
            "Offline audit only. EXACT_CACHE is counted only when protected fields AND output hash match. "
            "When protected fields match but output changed, it is counted as an exact-cache FALSE-HIT "
            "(a naive provenance-only cache would have served a stale result) and delta-served instead. "
            "DELTA_SERVE requires observable output text on both sides; when output changed but only hashes "
            "are observable, the false hit is still counted but NO savings are claimed (BLOCK_REUSE). "
            "Changed protected fields are reported as stale exact-cache risk, not served. "
            "Events are ordered by timestamp within a session when timestamps are present."
        ),
        "token_estimator": f"explicit output_tokens if present, otherwise {token_estimator_name()}",
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
        "top_users": top_users[:20],
        "top_examples": examples,
        "caveats": [
            "This is an audit, not auto-serving.",
            "Dollar savings use the provided input-token price and should be treated as a trace-local estimate.",
            "Carried-context tokens avoided is an upper-bound model (avoided x remaining events in session), not a measured value.",
            "Two dollar figures are reported: 'no_provider_cache' prices everything at the fresh input rate; "
            "'net_of_provider_cache' prices carried-context tokens at the provider prompt-cache READ rate, because "
            "stable-prefix context would mostly have been provider cache hits anyway. Quote the net figure to teams "
            "already using provider prompt caching; it is the defensible floor. Note provider caches are prefix-bound "
            "and short-TTL: they cannot reuse work across runs, sessions, or users the way certified recycling can.",
            "Logs without live output text can show exact-cache opportunities, stale risk, and false hits, but never delta-serving savings.",
            "False-hit rate = how often a provenance-only exact cache would have served a CHANGED output; 0% means provenance is a safe key on this trace.",
            "Sparse logs (missing cwd/model/user fields) can only overstate caution (more blocks, higher false-hit rate), never overstate savings.",
            "Protected-lane quality depends on the provenance fields present in the input logs.",
            "Per-user rows appear when traces carry user_id/user/actor/email fields; otherwise usage is (unattributed).",
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
        f"- Estimated total savings (no provider prompt cache): `${s['estimated_total_dollars_saved_no_provider_cache']:.4f}`",
        f"- Estimated total savings (net of provider prompt cache): `${s['estimated_total_dollars_saved_net_of_provider_cache']:.4f}`",
        f"- Prices: input `${s['price_input_per_million_tokens']:.2f}`/M, cached input "
        f"`${s['price_cached_input_per_million_tokens']:.2f}`/M ({s['price_source']})",
        f"- Token estimator: {result.get('token_estimator', 'bytes/4')}",
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
            f"- Protected-lane blocks (provenance change caught): `{fmt_int(s['protected_lane_blocks'])}`",
            f"- Exact-cache stale-risk events: `{fmt_int(s['exact_cache_stale_risk_events'])}`",
            f"- Provenance-matched re-reads (decidable): `{fmt_int(s['provenance_decidable_rereads'])}`",
            f"- Exact-cache false-hits (provenance matched, output changed): "
            f"`{fmt_int(s['false_hits'])}` (`{fmt_pct(s['provenance_exact_cache_false_hit_rate'])}`)",
            f"- {s['provenance_safety_note']}",
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
    attributed = [u for u in result.get("top_users", []) if u["user_id"] != "(unattributed)"]
    if attributed:
        lines.extend(
            [
                "",
                "## Token Usage by User",
                "",
                "| User | Events | Re-reads | Point Tokens Avoided | Carried-Context Tokens Avoided |",
                "|---|---:|---:|---:|---:|",
            ]
        )
        for row in result["top_users"][:12]:
            lines.append(
                f"| `{row['user_id']}` | {fmt_int(row['events'])} | {fmt_int(row['re_reads'])} | "
                f"{fmt_int(row['point_tokens_avoided'])} | "
                f"{fmt_int(row['cumulative_carried_context_tokens_avoided'])} |"
            )
    quality = result.get("input_quality") or {}
    skipped = quality.get("rows_skipped") or {}
    if quality:
        lines.extend(["", "## Input Quality", ""])
        lines.append(f"- Malformed lines skipped: `{fmt_int(quality.get('malformed_lines_skipped', 0))}`")
        for reason, count in sorted(skipped.items()):
            lines.append(f"- Rows skipped ({reason.replace('_', ' ')}): `{fmt_int(count)}`")
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
    """Console-grade local dashboard. Self-contained: system fonts, no JS, no network."""
    s = result["summary"]
    actions = result["actions"]
    price_in = s["price_input_per_million_tokens"]
    price_cached = s["price_cached_input_per_million_tokens"]

    def esc(v: Any) -> str:
        return html.escape(str(v))

    def user_dollars(row: dict[str, Any]) -> float:
        return money(row["point_tokens_avoided"], price_in) + money(
            row["cumulative_carried_context_tokens_avoided"], price_cached
        )

    re_reads = s["re_reads"]
    seg = {k: actions.get(k, 0) for k in ("EXACT_CACHE", "DELTA_SERVE", "BLOCK_REUSE")}
    seg_total = sum(seg.values())

    def flexval(n: int) -> str:
        return f"{max(n, seg_total * 0.04):.2f}" if seg_total else "1"

    fhr = s["provenance_exact_cache_false_hit_rate"]
    fh_color = "var(--teal)" if s["false_hits"] == 0 and s["provenance_decidable_rereads"] > 0 else (
        "var(--pink)" if s["false_hits"] else "var(--dim)")

    kpis = [
        ("tool calls audited", fmt_int(s["events"]), f"{fmt_int(s['sessions'])} sessions", "var(--text)"),
        ("re-reads of prior work", fmt_int(re_reads), f"{s['repeated_work_percent']:.1f}% of events", "var(--text)"),
        ("certified exact-cache", fmt_int(s["exact_cache_opportunities"]), "provenance + output identity", "var(--teal)"),
        ("false-hit rate", fmt_pct(fhr), f"{fmt_int(s['false_hits'])} of {fmt_int(s['provenance_decidable_rereads'])} decidable", fh_color),
        ("saved · net of provider cache", f"${s['estimated_total_dollars_saved_net_of_provider_cache']:,.2f}",
         f"${s['estimated_total_dollars_saved_no_provider_cache']:,.2f} upper bound", "var(--gold)"),
        ("tokens avoidable", fmt_int(s["point_tokens_avoided"]),
         f"{fmt_int(s['cumulative_carried_context_tokens_avoided'])} carried (upper bound)", "var(--text)"),
    ]
    kpi_html = "\n".join(
        f'<div class="kpi"><div class="lab">{esc(lab)}</div>'
        f'<div class="val" style="color:{color}">{esc(val)}</div>'
        f'<div class="sub">{esc(sub)}</div></div>'
        for lab, val, sub, color in kpis
    )

    if seg_total:
        funnel_html = (
            f'<div class="funnel">'
            f'<div class="f-cert" style="flex:{flexval(seg["EXACT_CACHE"])}">CERTIFIED {fmt_int(seg["EXACT_CACHE"])}</div>'
            f'<div class="f-delta" style="flex:{flexval(seg["DELTA_SERVE"])}">DELTA {fmt_int(seg["DELTA_SERVE"])}</div>'
            f'<div class="f-block" style="flex:{flexval(seg["BLOCK_REUSE"])}">BLOCKED {fmt_int(seg["BLOCK_REUSE"])}</div>'
            f"</div>"
            f'<p class="cap">Of {fmt_int(re_reads)} re-reads: certified exact reuse · changed output served as a diff · '
            f"unprovable or stale-risk, re-run live. The blocked share is what a naive cache would have served stale.</p>"
        )
    else:
        funnel_html = '<p class="cap">No repeated work detected on this trace yet — audit a larger day/week of traces.</p>'

    users = [u for u in result.get("top_users", []) if u["user_id"] != "(unattributed)"]
    users_html = ""
    if users:
        rows = "\n".join(
            "<tr>"
            f"<td>{esc(u['user_id'])}</td><td>{fmt_int(u['events'])}</td><td>{fmt_int(u['re_reads'])}</td>"
            f"<td>{fmt_int(u['point_tokens_avoided'])}</td>"
            f"<td>{fmt_int(u['cumulative_carried_context_tokens_avoided'])}</td>"
            f'<td class="money">${user_dollars(u):,.2f}</td>'
            "</tr>"
            for u in users[:12]
        )
        users_html = (
            '<section class="panel"><h2>Spend by user</h2><div class="tw"><table>'
            "<thead><tr><th>User</th><th>Events</th><th>Re-reads</th><th>Point avoided</th>"
            "<th>Carried avoided</th><th>Saved (net)</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></div></section>"
        )

    fam_rows = "\n".join(
        "<tr>"
        f"<td>{esc(row['family'])}</td><td>{fmt_int(row['re_reads'])}</td>"
        f"<td>{fmt_int(row['point_tokens_avoided'])}</td>"
        f"<td>{fmt_int(row['cumulative_carried_context_tokens_avoided'])}</td>"
        f"<td>{fmt_pct(row['avoided_token_ratio_on_rereads'])}</td>"
        "</tr>"
        for row in result["top_repeated_families"][:12]
    ) or '<tr><td colspan="5" class="empty">no repeated families yet</td></tr>'

    chip_class = {"EXACT_CACHE": "c-cert", "DELTA_SERVE": "c-delta", "BLOCK_REUSE": "c-block", "LIVE_CALL": "c-live"}
    examples_html = "\n".join(
        f'<div class="ev"><span class="chip {chip_class.get(ex["action"], "c-live")}">{esc(ex["action"].replace("_", " "))}</span>'
        f"<code>{esc(ex['command_text'][:110])}</code>"
        f'<span class="amt">−{fmt_int(ex["point_tokens_avoided"])} tok</span></div>'
        for ex in result["top_examples"][:8]
    ) or '<p class="cap">no reuse examples on this trace yet</p>'

    quality = result.get("input_quality") or {}
    skipped = quality.get("rows_skipped") or {}
    quality_bits = [f"malformed lines skipped: {fmt_int(quality.get('malformed_lines_skipped', 0))}"] + [
        f"{k.replace('_', ' ')}: {fmt_int(v)}" for k, v in sorted(skipped.items())
    ]
    caveats_html = "\n".join(f"<li>{esc(c)}</li>" for c in result.get("caveats", []))
    generated = time.strftime("%Y-%m-%d %H:%M", time.localtime(result.get("generated_at_unix", time.time())))

    html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CAIRN audit receipt — {esc(Path(str(input_path)).name)}</title>
<style>
:root{{--bg:#05070d;--bg2:#090c15;--bg3:#0d1120;--purple:#8b7fff;--purple-bright:#c4b8ff;
--text:#dde2ef;--dim:#6b7490;--border:#161c2e;--border2:#1e2740;
--teal:#4ecda4;--pink:#ff6b8a;--gold:#ffa726;
--mono:"SF Mono",Menlo,Consolas,monospace;--sans:"Avenir Next",Avenir,"Segoe UI",system-ui,sans-serif}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--sans);line-height:1.6;padding:34px 20px 60px}}
.wrap{{max-width:1080px;margin:0 auto}}
header{{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:8px}}
.stones{{display:flex;flex-direction:column;align-items:center;gap:2px}}
.stones i{{display:block;border-radius:999px;background:linear-gradient(180deg,var(--purple-bright),var(--purple))}}
.stones .t{{width:10px;height:4px}}.stones .m{{width:16px;height:5px}}.stones .b{{width:22px;height:5px}}
h1{{font-size:19px;font-weight:600;letter-spacing:.08em}}
h1 small{{color:var(--dim);font-weight:400;letter-spacing:0;margin-left:8px;font-size:13px}}
.meta{{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--dim);text-align:right;line-height:1.7}}
.src{{font-family:var(--mono);font-size:11.5px;color:var(--dim);margin-bottom:22px;word-break:break-all}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:14px}}
.kpi{{background:var(--bg3);border:1px solid var(--border2);border-radius:7px;padding:13px 15px}}
.kpi .lab{{font-size:10px;letter-spacing:.14em;text-transform:uppercase;color:var(--dim)}}
.kpi .val{{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:21px;margin-top:6px}}
.kpi .sub{{font-size:11px;color:var(--dim);margin-top:3px}}
.panel{{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:17px 19px;margin-bottom:14px}}
h2{{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim);font-weight:600;margin-bottom:12px}}
.funnel{{display:flex;height:32px;border-radius:5px;overflow:hidden;gap:2px;font-family:var(--mono);font-size:10.5px}}
.funnel div{{display:flex;align-items:center;justify-content:center;min-width:0;overflow:hidden;white-space:nowrap;border-radius:2px}}
.f-cert{{background:rgba(78,205,164,.25);color:#9fe6cb}}
.f-delta{{background:rgba(255,167,38,.18);color:#ffcb7d}}
.f-block{{background:rgba(255,107,138,.18);color:#ff9aac}}
.cap{{font-size:12px;color:var(--dim);margin-top:10px}}
.note{{border-left:3px solid var(--purple);background:var(--bg3);padding:11px 14px;border-radius:0 5px 5px 0;font-size:13.5px}}
.note.warn{{border-left-color:var(--pink)}}
.note.ok{{border-left-color:var(--teal)}}
.cols{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
@media(max-width:900px){{.cols{{grid-template-columns:1fr}}}}
.tw{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;min-width:460px}}
th{{font-size:9.5px;letter-spacing:.13em;text-transform:uppercase;color:var(--dim);text-align:right;padding:7px 9px;border-bottom:1px solid var(--border2);font-weight:600}}
td{{font-family:var(--mono);font-variant-numeric:tabular-nums;text-align:right;padding:7px 9px;border-bottom:1px solid var(--border);color:var(--text)}}
th:first-child,td:first-child{{text-align:left}}
td:first-child{{font-family:var(--sans)}}
tr:last-child td{{border-bottom:none}}
td.money{{color:var(--teal)}}
td.empty{{color:var(--dim);text-align:center}}
.ev{{display:flex;gap:10px;align-items:baseline;padding:8px 10px;background:var(--bg3);border:1px solid var(--border);border-radius:5px;margin-bottom:7px;font-size:12px}}
.chip{{flex:none;font-family:var(--mono);font-size:9.5px;letter-spacing:.06em;padding:3px 8px;border-radius:3px}}
.c-cert{{background:rgba(78,205,164,.12);color:var(--teal)}}
.c-delta{{background:rgba(255,167,38,.12);color:var(--gold)}}
.c-block{{background:rgba(255,107,138,.12);color:var(--pink)}}
.c-live{{background:rgba(139,127,255,.12);color:var(--purple-bright)}}
.ev code{{font-family:var(--mono);font-size:11.5px;color:#aeb8cc;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}}
.ev .amt{{margin-left:auto;flex:none;font-family:var(--mono);color:var(--dim);font-size:11px}}
.fine{{font-size:11.5px;color:var(--dim);line-height:1.7}}
.fine ul{{margin:8px 0 0 18px}}
footer{{margin-top:20px;font-family:var(--mono);font-size:10.5px;color:var(--dim);display:flex;gap:16px;flex-wrap:wrap}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="stones" aria-hidden="true"><i class="t"></i><i class="m"></i><i class="b"></i></span>
    <h1>CAIRN<small>audit receipt · a fraQtl product</small></h1>
    <div class="meta">generated {esc(generated)}<br>read-only · local-only</div>
  </header>
  <div class="src">input: {esc(input_path)}</div>

  <section class="kpis">{kpi_html}</section>

  <section class="panel"><h2>Certification funnel — repeated work</h2>{funnel_html}</section>

  <section class="panel"><h2>Safety</h2>
    <div class="note {'ok' if s['false_hits'] == 0 and s['provenance_decidable_rereads'] > 0 else ('warn' if s['false_hits'] else '')}">{esc(s['provenance_safety_note'])}</div>
    <p class="cap">Protected-lane blocks (provenance drift caught): {fmt_int(s['protected_lane_blocks'])} ·
    identical re-reads: {fmt_int(s['identical_rereads'])} ·
    stale-risk events: {fmt_int(s['exact_cache_stale_risk_events'])}</p>
  </section>

  {users_html}

  <div class="cols">
    <section class="panel"><h2>Top repeated tool families</h2><div class="tw"><table>
      <thead><tr><th>Family</th><th>Re-reads</th><th>Point avoided</th><th>Carried avoided</th><th>Avoided ratio</th></tr></thead>
      <tbody>{fam_rows}</tbody></table></div></section>
    <section class="panel"><h2>Reuse decisions — examples</h2>{examples_html}</section>
  </div>

  <section class="panel"><h2>Recommended next action</h2>
    <div class="note">{esc(s['recommended_next_action'])}</div>
    <p class="cap">Prices: input ${price_in:,.2f}/M · cached input ${price_cached:,.2f}/M ({esc(s['price_source'])}) ·
    token estimator: {esc(result.get('token_estimator', 'bytes/4'))}</p>
  </section>

  <section class="panel fine"><h2>Method &amp; caveats</h2>
    <div>{esc(' · '.join(quality_bits))}</div>
    <ul>{caveats_html}</ul>
  </section>

  <footer><span>schema {esc(result.get('schema', ''))}</span><span>CAIRN is a fraQtl product</span>
  <span>github.com/fraqtl-ai/cairn-security-agent-audit</span></footer>
</div>
</body>
</html>
"""
    path.write_text(html_text, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit local AI-agent JSON/JSONL logs for CAIRN protected reuse signals.")
    parser.add_argument("--input", type=Path, required=True, help="JSON or JSONL trace file.")
    parser.add_argument("--out", type=Path, required=True, help="Report output directory.")
    parser.add_argument("--price-input-per-m", type=float, default=0.0, help="Input-token price per 1M tokens.")
    parser.add_argument(
        "--price-cached-input-per-m",
        type=float,
        default=None,
        help="Provider prompt-cache READ price per 1M tokens (defaults to model table or 10%% of input).",
    )
    parser.add_argument(
        "--model",
        default="",
        help=f"Model name for the built-in price table ({', '.join(sorted(MODEL_PRICES))}).",
    )
    parser.add_argument(
        "--tokenizer",
        choices=("auto", "tiktoken", "bytes"),
        default="auto",
        help="Token estimator: tiktoken o200k_base when available (auto), or bytes/4.",
    )
    args = parser.parse_args()

    configure_tokenizer(args.tokenizer)
    events, malformed, skip_stats = load_events_with_stats(args.input)
    result = analyze(
        events,
        args.price_input_per_m,
        price_cached_input_per_m=args.price_cached_input_per_m,
        model=args.model,
    )
    result["input_quality"] = {
        "malformed_lines_skipped": len(malformed),
        "examples": malformed[:5],
        "rows_skipped": skip_stats,
    }

    args.out.mkdir(parents=True, exist_ok=True)
    write_json(args.out / "summary.json", result)
    write_markdown(args.out / "summary.md", result, args.input)
    write_html(args.out / "report.html", result, args.input)
    print(json.dumps(result["summary"], indent=2, sort_keys=True))
    if malformed:
        print(f"note: skipped {len(malformed)} malformed line(s)")
    print(f"report -> {args.out}")


if __name__ == "__main__":
    main()
