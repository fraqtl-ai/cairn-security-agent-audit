#!/usr/bin/env python3
"""CAIRN shadow mode for coding agents (Claude Code hook adapter).

Records every tool call an agent makes (read-only; nothing is served or
modified), then audits the recorded trace with the CAIRN engine to produce a
certified-reuse receipt for YOUR OWN sessions.

Usage:
    cairn-shadow install            # print the Claude Code hook config to add
    cairn-shadow install --write    # merge it into ~/.claude/settings.json (backs up first)
    cairn-shadow record             # stdin hook handler (Claude Code calls this)
    cairn-shadow report [--model claude-sonnet-4.5] [--day YYYY-MM-DD]
    cairn-shadow status             # how much has been recorded
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import cairn_audit_agent_logs as audit

SHADOW_DIR = Path(os.environ.get("CAIRN_SHADOW_DIR", Path.home() / ".cairn" / "shadow"))

HOOK_SNIPPET = {
    "hooks": {
        "PostToolUse": [
            {
                "matcher": "",
                "hooks": [{"type": "command", "command": "cairn-shadow record"}],
            }
        ]
    }
}


def _stringify(value) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def cmd_install(write: bool) -> int:
    snippet = json.dumps(HOOK_SNIPPET, indent=2)
    if not write:
        print("Add this to ~/.claude/settings.json (empty matcher = all tools),")
        print("or re-run with --write to merge it automatically:\n")
        print(snippet)
        return 0
    settings_path = Path.home() / ".claude" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings = {}
    if settings_path.exists():
        backup = settings_path.with_suffix(f".json.cairn-backup-{int(time.time())}")
        backup.write_bytes(settings_path.read_bytes())
        print(f"backed up existing settings -> {backup}")
        try:
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("existing settings.json is not valid JSON; not touching it", file=sys.stderr)
            return 1
    post = settings.setdefault("hooks", {}).setdefault("PostToolUse", [])
    already = any(
        h.get("command", "").startswith("cairn-shadow")
        for entry in post
        for h in entry.get("hooks", [])
    )
    if already:
        print("cairn-shadow hook already installed; nothing to do")
        return 0
    post.append(HOOK_SNIPPET["hooks"]["PostToolUse"][0])
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"installed PostToolUse hook -> {settings_path}")
    print(f"recording to {SHADOW_DIR} (shadow mode: read-only, local-only)")
    return 0


def _first(event: dict, *keys):
    for k in keys:
        v = event.get(k)
        if v not in (None, ""):
            return v
    return None


def cmd_record() -> int:
    """Read one tool event from stdin, append a normalized row. Never blocks the agent.

    Engine-agnostic: accepts Claude Code hook payloads and the common field
    aliases other agents use (OpenHands / LangChain / custom loggers)."""
    try:
        event = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0  # malformed payload; stay silent, never break the agent
    if not isinstance(event, dict):
        return 0
    row = {
        "source": str(_first(event, "source", "agent", "engine") or "agent_shadow"),
        "schema": "cairn_shadow_v0",
        "ts": _first(event, "ts", "timestamp", "time") or time.time(),
        "session_id": str(_first(event, "session_id", "conversation_id", "thread_id", "run_id") or "unknown-session"),
        "tool_name": str(_first(event, "tool_name", "tool", "name", "action") or ""),
        "tool_input": _first(event, "tool_input", "input", "arguments", "args", "command"),
        "output": _stringify(_first(event, "tool_response", "output", "result", "observation", "response")),
        "cwd": str(_first(event, "cwd", "working_dir", "workspace") or ""),
        "user_id": str(_first(event, "user_id", "user", "actor") or os.environ.get("USER", "")),
    }
    try:
        SHADOW_DIR.mkdir(parents=True, exist_ok=True)
        day = time.strftime("%Y-%m-%d")
        with (SHADOW_DIR / f"{day}.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")
    except OSError:
        pass  # recording must never interfere with the agent
    return 0


def _trace_files(day: str | None) -> list[Path]:
    if day:
        p = SHADOW_DIR / f"{day}.jsonl"
        return [p] if p.exists() else []
    return sorted(SHADOW_DIR.glob("*.jsonl"))


def cmd_report(day: str | None, model: str, price: float, cached: float | None, out: str | None) -> int:
    files = _trace_files(day)
    if not files:
        print(f"no shadow traces found in {SHADOW_DIR} — install the hook and use your agent first")
        return 1
    events: list[audit.Event] = []
    malformed = 0
    skip_stats: dict[str, int] = {}
    for path in files:
        evs, mal, sk = audit.load_events_with_stats(path)
        for k, v in sk.items():
            skip_stats[k] = skip_stats.get(k, 0) + v
        events.extend(evs)
        malformed += len(mal)
    result = audit.analyze(events, price, price_cached_input_per_m=cached, model=model)
    result["input_quality"] = {"malformed_lines_skipped": malformed, "rows_skipped": skip_stats}
    result["shadow"] = {"files": [str(p) for p in files], "mode": "read-only"}
    s = result["summary"]
    print(json.dumps(s, indent=2, sort_keys=True))
    print()
    print(f"CAIRN shadow receipt — {len(files)} day(s), {s['events']} tool calls")
    print(f"  re-reads: {s['re_reads']} ({s['repeated_work_percent']:.1f}%)")
    print(f"  certified exact-cache: {s['exact_cache_opportunities']}  |  "
          f"false hits blocked: {s['false_hits']} "
          f"({100.0 * s['provenance_exact_cache_false_hit_rate']:.1f}% of decidable)")
    print(f"  tokens avoidable: {s['point_tokens_avoided']:,} point / "
          f"{s['cumulative_carried_context_tokens_avoided']:,} carried (upper bound)")
    print(f"  est. savings: ${s['estimated_total_dollars_saved_net_of_provider_cache']:.2f} "
          f"net of provider prompt cache (${s['estimated_total_dollars_saved_no_provider_cache']:.2f} upper bound)")
    if out:
        out_dir = Path(out)
        out_dir.mkdir(parents=True, exist_ok=True)
        audit.write_json(out_dir / "summary.json", result)
        audit.write_markdown(out_dir / "summary.md", result, files[-1])
        print(f"  receipt -> {out_dir}/summary.md")
    return 0


def redact_result(result: dict) -> None:
    """Strip raw command text from a result in place (privacy mode for shared reports)."""
    for row in result.get("top_repeated_commands", []):
        row["command_text"] = "[redacted]"
    for ex in result.get("top_examples", []):
        ex["command_text"] = "[redacted]"
    result["redacted"] = True


def _collect_inputs(specs: list[str]) -> list[tuple[str, list[Path]]]:
    """Parse NAME=PATH (or bare PATH) specs into (label, trace files) pairs."""
    sources: list[tuple[str, list[Path]]] = []
    for spec in specs:
        label, sep, raw = spec.partition("=")
        if not sep:
            label, raw = "", spec
        p = Path(raw).expanduser()
        if p.is_dir():
            files = sorted(p.glob("*.jsonl"))
        elif p.exists():
            files = [p]
        else:
            files = []
        if not files:
            print(f"warning: no traces found for {spec!r}", file=sys.stderr)
            continue
        sources.append((label, files))
    return sources


def cmd_team_report(
    specs: list[str],
    model: str,
    price: float,
    cached: float | None,
    out: str,
    open_browser: bool,
    redact: bool = False,
) -> int:
    """Merge several devs' shadow traces into one fleet report (per-dev usage and dollars)."""
    sources = _collect_inputs(specs)
    if not sources:
        print("no traces found — pass dev shadow dirs or .jsonl files (optionally NAME=PATH)")
        return 1
    events: list[audit.Event] = []
    malformed = 0
    skip_stats: dict[str, int] = {}
    for label, files in sources:
        for f in files:
            evs, mal, sk = audit.load_events_with_stats(f)
            malformed += len(mal)
            for k, v in sk.items():
                skip_stats[k] = skip_stats.get(k, 0) + v
            for e in evs:
                if label:
                    e.user_id = label
                    e.session_id = f"{label}:{e.session_id}"
                events.append(e)

    result = audit.analyze(events, price, price_cached_input_per_m=cached, model=model)
    result["input_quality"] = {"malformed_lines_skipped": malformed, "rows_skipped": skip_stats}
    if redact:
        redact_result(result)
    result["team"] = {
        "sources": [{"label": label or "(user_id from trace)", "files": len(files)} for label, files in sources],
        "mode": "one-shot merge (continuous team collection is part of CAIRN Runtime)",
    }

    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    audit.write_json(out_dir / "summary.json", result)
    audit.write_markdown(out_dir / "summary.md", result, Path(",".join(s for s in specs)[:120]))
    audit.write_html(out_dir / "report.html", result, Path("team: " + ", ".join(specs)[:110]))

    s = result["summary"]
    price_in = s["price_input_per_million_tokens"]
    price_c = s["price_cached_input_per_million_tokens"]
    print(f"CAIRN team receipt — {len(sources)} dev(s), {s['events']} tool calls, "
          f"{s['re_reads']} re-reads ({s['repeated_work_percent']:.1f}%)")
    print(f"  fleet false-hit rate: {100.0 * s['provenance_exact_cache_false_hit_rate']:.1f}% of decidable  |  "
          f"certified exact-cache: {s['exact_cache_opportunities']}")
    print(f"  fleet savings: ${s['estimated_total_dollars_saved_net_of_provider_cache']:.2f} net of provider "
          f"prompt cache (${s['estimated_total_dollars_saved_no_provider_cache']:.2f} upper bound)\n")
    print(f"  {'dev':<18}{'events':>8}{'re-reads':>10}{'certified':>11}{'saved(net)':>12}")
    for u in result["top_users"][:15]:
        dollars = (u["point_tokens_avoided"] * price_in + u["cumulative_carried_context_tokens_avoided"] * price_c) / 1e6
        print(f"  {u['user_id']:<18}{u['events']:>8,}{u['re_reads']:>10,}{'':>11}{dollars:>11,.2f}$")
    print(f"\n  report -> {out_dir / 'report.html'}")
    if open_browser:
        import webbrowser

        webbrowser.open((out_dir / "report.html").resolve().as_uri())
    return 0


def cmd_status() -> int:
    files = _trace_files(None)
    total = sum(1 for p in files for _ in p.open(encoding="utf-8"))
    print(f"shadow dir: {SHADOW_DIR}")
    print(f"days recorded: {len(files)}  |  tool calls recorded: {total}")
    for p in files[-7:]:
        n = sum(1 for _ in p.open(encoding="utf-8"))
        print(f"  {p.name}: {n}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="CAIRN shadow mode: record agent tool calls, audit your own sessions.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_install = sub.add_parser("install", help="show or write the Claude Code hook config")
    p_install.add_argument("--write", action="store_true", help="merge into ~/.claude/settings.json (with backup)")
    sub.add_parser("record", help="stdin hook handler (called by the agent)")
    p_report = sub.add_parser("report", help="audit recorded sessions and print the receipt")
    p_report.add_argument("--day", default=None, help="YYYY-MM-DD (default: all recorded days)")
    p_report.add_argument("--model", default="claude-sonnet-4.5")
    p_report.add_argument("--price-input-per-m", type=float, default=0.0)
    p_report.add_argument("--price-cached-input-per-m", type=float, default=None)
    p_report.add_argument("--out", default=None, help="also write summary.json/summary.md here")
    p_report.add_argument("--tokenizer", choices=("auto", "tiktoken", "bytes"), default="auto")
    sub.add_parser("status", help="show what has been recorded")
    p_team = sub.add_parser(
        "team-report",
        help="merge multiple devs' traces into one fleet report (engine-agnostic: any JSONL the audit ingests)",
    )
    p_team.add_argument("inputs", nargs="+", help="dev traces: dir or .jsonl, optionally NAME=PATH to label the dev")
    p_team.add_argument("--out", default="team_report", help="output directory (default: team_report)")
    p_team.add_argument("--model", default="claude-sonnet-4.5")
    p_team.add_argument("--price-input-per-m", type=float, default=0.0)
    p_team.add_argument("--price-cached-input-per-m", type=float, default=None)
    p_team.add_argument("--tokenizer", choices=("auto", "tiktoken", "bytes"), default="auto")
    p_team.add_argument("--open", action="store_true", help="open the fleet report in the browser")
    p_team.add_argument("--redact", action="store_true",
                        help="strip raw command text from the report (aggregate metrics only; for sharing)")
    args = parser.parse_args()

    if args.cmd == "install":
        raise SystemExit(cmd_install(args.write))
    if args.cmd == "record":
        raise SystemExit(cmd_record())
    if args.cmd == "report":
        audit.configure_tokenizer(args.tokenizer)
        raise SystemExit(
            cmd_report(args.day, args.model, args.price_input_per_m, args.price_cached_input_per_m, args.out)
        )
    if args.cmd == "status":
        raise SystemExit(cmd_status())
    if args.cmd == "team-report":
        audit.configure_tokenizer(args.tokenizer)
        raise SystemExit(
            cmd_team_report(
                args.inputs, args.model, args.price_input_per_m,
                args.price_cached_input_per_m, args.out, args.open, args.redact,
            )
        )


if __name__ == "__main__":
    main()
