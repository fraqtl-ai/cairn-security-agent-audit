# What To Expect From The Audit

This repo is the evaluation package for CAIRN Security Agent Audit.

It is meant to answer one question quickly:

```text
Do these AI-pentest traces contain enough repeated tool-output/context work to
justify a protected runtime integration later?
```

## What You See First

Run the sample:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input samples/pentest_trace_sample.jsonl \
  --out report \
  --price-input-per-m 3.0
```

Open:

```text
report/report.html
```

The report shows:

- total tool events audited,
- repeated tool-output work,
- top repeated tool families,
- exact-cache stale-risk events,
- protected-lane blocks,
- `DELTA_SERVE` opportunities,
- `EXACT_CACHE` opportunities,
- estimated token savings,
- concrete examples.

## Trying Your Own Logs

Preferred input is JSONL with one tool event per line:

```json
{"session_id":"run-1","step":1,"tool":"shell","command":"nmap -sV 10.0.0.5","output":"PORT 22 open ssh...","output_tokens":900,"before":{"fingerprint":"target-a"},"after":{"fingerprint":"target-a"}}
```

Run:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input your_trace.jsonl \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

For a directory:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input logs/ \
  --glob '*.json' \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

If the format is unfamiliar, inspect it first:

```bash
python3 cairn_inspect_log_schema.py \
  --input your_trace.jsonl \
  --out report/schema_inspection.json
```

## What A Good Result Looks Like

A strong signal usually has:

```text
high repeated-work %
large repeated outputs
clear top tool families
protected-lane blocks
DELTA_SERVE opportunities
0 stale serves
0 false hits
```

Example from the included public AutoPenBench report:

```text
2,764 tool events audited
1,031 re-reads
37.30% repeated work
548,335 point tokens avoided
3,698,589 carried-context tokens avoided
1,016 protected-lane blocks
0 stale serves
0 false hits
```

Top repeated families in that public run included:

```text
nmap, curl, ssh, msfconsole, searchsploit, find, cat
```

## How To Read The Actions

`LIVE_CALL`

```text
First time seeing this work, or not enough evidence to reuse safely.
```

`EXACT_CACHE`

```text
Same work repeated and protected state still matches. Exact reuse would be safe.
```

`DELTA_SERVE`

```text
The agent is repeating related output, but protected state changed or exact
replay is not the right safety choice. Prior output can still help shrink the
context/reporting burden while staying live-aware.
```

`BLOCK_REUSE`

```text
Repeated work exists, but reuse should be blocked.
```

## What The Pilot Decides

The first audit does not require integration.

Decision rule:

```text
No repeated-work signal -> stop.
Meaningful repeated-work signal -> choose one high-volume tool family and scope
a protected runtime pilot.
```

The runtime product direction is:

```text
agent tool call
  -> observe command/action + target/session state
  -> exact cache only when safe
  -> delta-serve when appropriate
  -> live fallback when state changed or uncertain
  -> report savings and blocked stale replay
```

This repo is step one: prove the signal from existing traces.

