#!/usr/bin/env python3
"""Correctness tests for the CAIRN audit engine (cairn_audit_agent_logs).

Focus: the safe-reuse decision must be provably correct — especially the
exact-cache false-hit counterfactual, protected-lane blocking, the empty-output
guard, and chronological ordering.

Runs two ways:
    pytest tests/test_audit_engine.py
    python3 tests/test_audit_engine.py      # no pytest required
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cairn_audit_agent_logs as audit  # noqa: E402


def run(rows: list[dict], price: float = 0.0) -> dict:
    events = []
    for i, row in enumerate(rows):
        ev = audit.normalize_row(row, i, row.get("session_id", "sess"))
        if ev is not None:
            events.append(ev)
    return audit.analyze(events, price)


# --- core action classification -------------------------------------------------

def test_first_sighting_is_live_call():
    res = run([{"session_id": "s", "command": "nmap host", "output": "A", "model": "m1"}])
    assert res["actions"]["LIVE_CALL"] == 1
    assert res["summary"]["re_reads"] == 0


def test_exact_cache_when_provenance_and_output_match():
    rows = [
        {"session_id": "s", "command": "nmap host", "output": "RESULT", "model": "m1"},
        {"session_id": "s", "command": "nmap host", "output": "RESULT", "model": "m1"},
    ]
    s = run(rows)["summary"]
    assert s["re_reads"] == 1
    assert s["exact_cache_opportunities"] == 1
    assert s["false_hits"] == 0
    assert s["provenance_decidable_rereads"] == 1
    assert s["provenance_exact_cache_false_hit_rate"] == 0.0


def test_false_hit_when_provenance_matches_but_output_changed():
    """THE flagship correctness metric: provenance matched, output differed ->
    a naive provenance-only exact cache would have served a stale/wrong result."""
    rows = [
        {"session_id": "s", "command": "nmap host", "output": "OPEN: 22", "model": "m1"},
        {"session_id": "s", "command": "nmap host", "output": "OPEN: 22,80", "model": "m1"},
    ]
    res = run(rows)
    s = res["summary"]
    assert s["false_hits"] == 1
    assert s["exact_cache_opportunities"] == 0
    assert s["provenance_decidable_rereads"] == 1
    assert s["provenance_exact_cache_false_hit_rate"] == 1.0
    assert res["actions"]["DELTA_SERVE"] == 1
    assert s["protected_lane_blocks"] == 0  # provenance did NOT change; this is a false hit, not a block
    assert "false-hit risk" in s["provenance_safety_note"]


def test_protected_change_is_block_not_false_hit():
    """Protected field changed -> stale risk caught by the provenance lane; must
    NOT be counted as a false hit (the lane did its job)."""
    rows = [
        {"session_id": "s", "command": "nmap host", "output": "SAME", "model": "m1"},
        {"session_id": "s", "command": "nmap host", "output": "SAME", "model": "m2"},
    ]
    s = run(rows)["summary"]
    assert s["protected_lane_blocks"] == 1
    assert s["exact_cache_stale_risk_events"] == 1
    assert s["false_hits"] == 0
    assert s["exact_cache_opportunities"] == 0
    assert s["provenance_decidable_rereads"] == 0  # violation -> not a decidable exact-cache candidate


def test_empty_output_is_not_a_false_exact_cache():
    """Two events both missing output must not coincidentally count as identical
    exact-cache hits (both hash the empty string)."""
    rows = [
        {"session_id": "s", "command": "nmap host", "model": "m1"},
        {"session_id": "s", "command": "nmap host", "model": "m1"},
    ]
    res = run(rows)
    s = res["summary"]
    assert s["exact_cache_opportunities"] == 0
    assert s["identical_rereads"] == 0
    assert s["false_hits"] == 0
    assert res["actions"]["BLOCK_REUSE"] == 1


def test_events_ordered_by_timestamp_within_session():
    """Repeat detection must use chronological order, not file order.
    Chronological: v1(100) -> v2(200) -> v1(300) gives 2 output changes.
    File order here is scrambled (200, 300, 100)."""
    rows = [
        {"session_id": "s", "command": "scan t", "output": "v2", "model": "m1", "ts": 200},
        {"session_id": "s", "command": "scan t", "output": "v1", "model": "m1", "ts": 300},
        {"session_id": "s", "command": "scan t", "output": "v1", "model": "m1", "ts": 100},
    ]
    s = run(rows)["summary"]
    # chronological A(v1,100) B(v2,200) C(v1,300): B!=A and C!=B => 2 false hits
    assert s["re_reads"] == 2
    assert s["false_hits"] == 2
    assert s["exact_cache_opportunities"] == 0


def test_iso_timestamp_parses_and_orders():
    rows = [
        {"session_id": "s", "command": "scan t", "output": "b", "model": "m1", "timestamp": "2026-01-01T00:00:02Z"},
        {"session_id": "s", "command": "scan t", "output": "a", "model": "m1", "timestamp": "2026-01-01T00:00:01Z"},
    ]
    s = run(rows)["summary"]
    assert s["re_reads"] == 1
    assert s["false_hits"] == 1  # a(1) then b(2): output changed


# --- robustness -----------------------------------------------------------------

def test_malformed_jsonl_line_is_skipped_not_fatal():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "trace.jsonl"
        p.write_text(
            '{"command": "nmap a", "output": "A"}\n'
            "this is not json\n"
            '{"command": "nmap a", "output": "A"}\n',
            encoding="utf-8",
        )
        events, malformed = audit.load_events_verbose(p)
        assert len(events) == 2
        assert len(malformed) == 1


def test_load_events_backward_compatible_returns_list():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "trace.jsonl"
        p.write_text('{"command": "nmap a", "output": "A"}\n', encoding="utf-8")
        events = audit.load_events(p)
        assert isinstance(events, list)
        assert all(isinstance(e, audit.Event) for e in events)


# --- token math -----------------------------------------------------------------

def test_token_estimator_bytes_over_four():
    assert audit.approx_tokens("") == 0
    assert audit.approx_tokens("abcd") == 1       # 4 bytes -> 1
    assert audit.approx_tokens("abcde") == 2      # 5 bytes -> 2
    assert audit.approx_tokens(byte_count=8) == 2


def test_explicit_output_tokens_win_over_proxy():
    row = {"session_id": "s", "command": "nmap a", "output": "x" * 400, "output_tokens": 7}
    ev = audit.normalize_row(row, 0, "s")
    assert ev.output_tokens == 7


# --- summary contract -----------------------------------------------------------

def test_summary_exposes_new_safety_fields():
    s = run([{"session_id": "s", "command": "nmap a", "output": "A", "model": "m1"}])["summary"]
    for key in (
        "false_hits",
        "provenance_decidable_rereads",
        "provenance_exact_cache_false_hit_rate",
        "provenance_safety_note",
    ):
        assert key in s


# --- standalone runner (no pytest needed) ---------------------------------------

def _main() -> int:
    tests = sorted(
        (name, obj)
        for name, obj in globals().items()
        if name.startswith("test_") and callable(obj)
    )
    failures = 0
    for name, fn in tests:
        try:
            fn()
            print(f"PASS {name}")
        except AssertionError as exc:
            failures += 1
            print(f"FAIL {name}: {exc}")
        except Exception as exc:  # noqa: BLE001
            failures += 1
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_main())
