<p align="center">
  <img src="docs/logo.png" alt="fraQtl" width="150"/>
</p>

<h1 align="center">CAIRN Security Agent Audit</h1>

<p align="center">
  Local/offline audit for AI-pentest traces: repeated tool-output work, stale replay risk, protected-lane blocks, and token-savings reports.
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#try-your-own-logs">Try your logs</a> ·
  <a href="#what-the-report-shows">Report output</a> ·
  <a href="#product-direction">Product direction</a>
</p>

---

CAIRN audits traces from security agents that call scanners, shells, exploit
frameworks, HTTP clients, search tools, and file inspection commands.

It answers one practical question:

```text
Are AI-pentest agents repeatedly re-reading expensive tool outputs, and where
would exact replay be stale or unsafe because target/session state changed?
```

This repository is the public evaluation package. It is local, CLI-first, and
audit-only. It does not run pentests, does not need live target access, and does
not auto-serve cached outputs.

> **Demo/evaluation scope:** this repo is the audit slice of CAIRN, not the full
> runtime product. The protected runtime sidecar, production serving layer,
> deeper grouping roadmap, and broader fraQtl optimization work are not included
> here. Use this repo to test whether a repeated-work signal exists in your
> AI-pentest traces.

## What It Does

Given JSON/JSONL security-agent logs, CAIRN:

- normalizes trace records into a common audit schema,
- groups repeated tool-output/context work,
- compares protected target/session state,
- marks exact-cache stale-risk events,
- classifies `LIVE_CALL`, `EXACT_CACHE`, `DELTA_SERVE`, and `BLOCK_REUSE`,
- estimates point-token and carried-context savings,
- writes `summary.json`, `summary.md`, and `report.html`.

## Quickstart

Clone:

```bash
git clone https://github.com/fraqtl-ai/cairn-security-agent-audit.git
cd cairn-security-agent-audit
```

Run the included pentest sample:

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

The sample produces a small report with repeated `nmap`, `curl`, and shell/file
read examples. For a larger public benchmark report, open:

```text
examples/autopenbench/report.html
```

## Try Your Own Logs

If your trace is JSONL:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input your_trace.jsonl \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

If your trace is one JSON file:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input your_trace.json \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

If your traces are a directory of JSON logs:

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input logs/ \
  --glob '*.json' \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

Outputs:

```text
report/summary.json
report/summary.md
report/report.html
report/normalization_summary.json
```

## Input Shape

Preferred input is one JSON object per tool event:

```json
{"session_id":"run-1","step":1,"tool":"shell","command":"nmap -sV 10.0.0.5","output":"PORT 22 open ssh...","output_tokens":900,"before":{"fingerprint":"target-a"},"after":{"fingerprint":"target-a"}}
```

Useful fields:

```text
session_id or run_id
step index or timestamp
tool/action name
command/action text
stdout/stderr/observation/output text
target/session/provenance hints if available
input/output token counts if available
```

If you do not know whether your export has the right fields, inspect the shape:

```bash
python3 cairn_inspect_log_schema.py \
  --input your_trace.jsonl \
  --out report/schema_inspection.json
```

You can share `report/schema_inspection.json` or one redacted example row
without sharing raw logs.

If output or observation text is missing, CAIRN can still show repeated-work and
stale-risk structure, but token-savings and delta-serving estimates will be
weaker. If target/session fingerprints are missing, CAIRN can still run with
conservative proxy fingerprints, but real fingerprints make the protected-lane
analysis stronger.

## What The Report Shows

The report is designed to be readable by product and engineering teams:

| Area | What CAIRN reports |
|---|---|
| Repeated work | Events audited, re-reads, repeated-work percentage |
| Tool families | Top repeated commands/tools by carried-context savings |
| Safety | Protected-lane blocks and exact-cache stale-risk events |
| Opportunities | `EXACT_CACHE`, `DELTA_SERVE`, `LIVE_CALL`, `BLOCK_REUSE` |
| Savings | Point tokens avoided, carried-context tokens avoided, dollar estimate |
| Examples | Concrete commands/actions that created the signal |

Public reference result from AutoPenBench / genai-pentest-paper logs:

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
Related output repeated, but exact replay is not the right safety choice.
Prior output can still shrink context/reporting burden while staying live-aware.
```

`BLOCK_REUSE`

```text
Repeated work exists, but reuse should be blocked.
```

## Product Direction

This repository is the audit slice, not the full CAIRN runtime product.

Design-partner path:

1. **Offline audit**: run CAIRN on existing AI-pentest traces and measure the
   repeated-work signal.
2. **Local dashboard**: review repeated tool families, stale-risk examples, and
   savings over time without raw logs leaving the customer environment.
3. **Protected runtime sidecar**: integrate around one high-volume tool family.
   CAIRN observes tool calls plus target/session state, exact-caches only inside
   safe provenance cells, delta-serves when appropriate, and falls back live when
   state changed or is uncertain.

The goal is not to replay pentest results blindly. The goal is to reduce
repeated context/tool-output cost while refusing stale replay across protected
target/session changes.

## Boundaries

CAIRN Security Agent Audit is:

- local,
- audit-only,
- trace/report oriented,
- designed to avoid stale replay.

It is not a vulnerability scanner, pentest runner, live target automation, or
production serving layer.

## License

Evaluation package. Copyright fraQtl. Do not redistribute without permission.
