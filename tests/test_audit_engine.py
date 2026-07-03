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


def run(rows: list[dict], price: float = 0.0, **kwargs) -> dict:
    events = []
    for i, row in enumerate(rows):
        ev = audit.normalize_row(row, i, row.get("session_id", "sess"))
        if ev is not None:
            events.append(ev)
    return audit.analyze(events, price, **kwargs)


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


# --- hash-only traces: false hits are counted, savings are never invented --------

def test_hash_only_changed_output_blocks_and_counts_false_hit():
    """Rows carry output hashes but no text. If the hash changed, the false hit is
    real signal — but a delta cannot be reconstructed from hashes, so no savings
    may be claimed. Regression test for the delta_tokens('', '') == 16 overclaim."""
    rows = [
        {"session_id": "s", "command": "nmap host", "model": "m1",
         "stdout_sha256": "aaa", "stdout_bytes": 4000},
        {"session_id": "s", "command": "nmap host", "model": "m1",
         "stdout_sha256": "bbb", "stdout_bytes": 4000},
    ]
    res = run(rows)
    s = res["summary"]
    assert s["false_hits"] == 1
    assert s["provenance_decidable_rereads"] == 1
    assert res["actions"]["BLOCK_REUSE"] == 1
    assert res["actions"]["DELTA_SERVE"] == 0
    assert s["point_tokens_avoided"] == 0
    assert s["cumulative_carried_context_tokens_avoided"] == 0


def test_hash_only_identical_output_is_exact_cache_opportunity():
    rows = [
        {"session_id": "s", "command": "nmap host", "model": "m1",
         "stdout_sha256": "aaa", "stdout_bytes": 4000},
        {"session_id": "s", "command": "nmap host", "model": "m1",
         "stdout_sha256": "aaa", "stdout_bytes": 4000},
    ]
    res = run(rows)
    s = res["summary"]
    assert s["exact_cache_opportunities"] == 1
    assert s["false_hits"] == 0
    assert s["point_tokens_avoided"] == 1000 - 16  # 4000 bytes -> 1000 tokens, minus envelope


def test_provenance_violation_without_text_blocks():
    rows = [
        {"session_id": "s", "command": "nmap host", "model": "m1",
         "stdout_sha256": "aaa", "stdout_bytes": 4000},
        {"session_id": "s", "command": "nmap host", "model": "m2",
         "stdout_sha256": "bbb", "stdout_bytes": 4000},
    ]
    res = run(rows)
    assert res["actions"]["BLOCK_REUSE"] == 1
    assert res["summary"]["point_tokens_avoided"] == 0
    assert res["summary"]["protected_lane_blocks"] == 1


# --- dollar math: provider prompt-cache counterfactual ---------------------------

def test_net_of_provider_cache_dollar_math():
    """3-event session: A, A(identical), B. The re-read at index 1 avoids
    output_tokens-16 point tokens; 1 event remains -> carried == avoided.
    input $10/M, cached $1/M."""
    rows = [
        {"session_id": "s", "command": "cat f", "output": "X", "output_tokens": 1016, "model": "m1"},
        {"session_id": "s", "command": "cat f", "output": "X", "output_tokens": 1016, "model": "m1"},
        {"session_id": "s", "command": "ls", "output": "Y", "output_tokens": 5, "model": "m1"},
    ]
    s = run(rows, price=10.0, price_cached_input_per_m=1.0)["summary"]
    assert s["point_tokens_avoided"] == 1000
    assert s["cumulative_carried_context_tokens_avoided"] == 1000
    assert abs(s["estimated_total_dollars_saved_no_provider_cache"] - 0.020) < 1e-9
    assert abs(s["estimated_total_dollars_saved_net_of_provider_cache"] - 0.011) < 1e-9
    assert s["price_cached_input_per_million_tokens"] == 1.0


def test_cached_price_defaults_to_ratio_of_input():
    s = run([{"session_id": "s", "command": "ls", "output": "A"}], price=10.0)["summary"]
    assert abs(s["price_cached_input_per_million_tokens"] - 10.0 * audit.DEFAULT_CACHED_INPUT_RATIO) < 1e-9
    assert "cached-input defaulted" in s["price_source"]


def test_model_price_table_resolves_prices():
    s = run([{"session_id": "s", "command": "ls", "output": "A"}], model="claude-sonnet-4.5")["summary"]
    expected = audit.MODEL_PRICES["claude-sonnet-4.5"]
    assert s["price_input_per_million_tokens"] == expected["input"]
    assert s["price_cached_input_per_million_tokens"] == expected["cached_input"]
    assert "built-in price table" in s["price_source"]


# --- per-user attribution ---------------------------------------------------------

def test_per_user_token_breakdown():
    rows = [
        {"session_id": "s", "command": "cat f", "output": "X" * 400, "model": "m1", "user_id": "alice"},
        {"session_id": "s", "command": "cat f", "output": "X" * 400, "model": "m1", "user_id": "alice"},
        {"session_id": "s", "command": "ls d", "output": "Y", "model": "m1", "user_id": "bob"},
    ]
    res = run(rows)
    users = {u["user_id"]: u for u in res["top_users"]}
    assert users["alice"]["re_reads"] == 1
    assert users["alice"]["point_tokens_avoided"] > 0
    assert users["bob"]["re_reads"] == 0
    assert res["summary"]["attributed_users"] == 2


# --- skipped-row accounting -------------------------------------------------------

def test_skipped_rows_are_counted():
    stats: dict[str, int] = {}
    assert audit.normalize_row({"foo": "bar"}, 0, "s", stats) is None
    assert audit.normalize_row({"command": "date"}, 1, "s", stats) is None  # volatile family
    assert audit.normalize_row({"command": "nmap h", "output": "A"}, 2, "s", stats) is not None
    assert stats == {"no_recognizable_command": 1, "volatile_family_excluded": 1}


# --- tokenizer configuration ------------------------------------------------------

def test_tokenizer_bytes_mode_is_default_and_deterministic():
    audit.configure_tokenizer("bytes")
    assert audit.token_estimator_name() == "bytes/4"
    assert audit.approx_tokens("abcdefgh") == 2


def test_tokenizer_tiktoken_when_available():
    try:
        import tiktoken  # noqa: F401
    except ImportError:
        return  # optional dependency not installed; covered in CI with extras
    try:
        name = audit.configure_tokenizer("tiktoken")
        assert name == "tiktoken:o200k_base"
        assert audit.approx_tokens("hello world, this is CAIRN") > 0
        assert audit.approx_tokens("") == 0
    finally:
        audit.configure_tokenizer("bytes")


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
