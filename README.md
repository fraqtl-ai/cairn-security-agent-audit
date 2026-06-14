# CAIRN Security Agent Audit

Local/offline audit for AI-pentest traces.

CAIRN finds repeated tool-output/context work, reports where exact replay would
be stale or unsafe, and estimates safe context savings. It is built for traces
from security agents that call scanners, shells, exploit frameworks, search
tools, HTTP clients, and file inspection commands.

This package is evaluation-only. It does not run pentests, does not need live
target access, and does not auto-serve cached outputs.

## What It Produces

Given JSON/JSONL security-agent logs, CAIRN writes:

```text
report/summary.json
report/summary.md
report/report.html
report/normalization_summary.json
```

The report includes:

- repeated-work percentage,
- top repeated command/tool families,
- exact-cache stale-risk events,
- protected target/session-state blocks,
- `DELTA_SERVE` opportunities,
- `EXACT_CACHE` opportunities,
- point tokens avoided,
- cumulative carried-context tokens avoided,
- estimated savings using user-provided model prices,
- concrete examples.

## Quickstart

Clone:

```bash
git clone https://github.com/fraqtl-ai/cairn-security-agent-audit.git
cd cairn-security-agent-audit
```

Run the included sample:

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

What to look for:

```text
docs/WHAT_TO_EXPECT.md
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

Then open:

```text
report/report.html
```

The JSON and Markdown outputs are:

```text
report/summary.json
report/summary.md
report/normalization_summary.json
```

## Inspect An Unknown Export

If you do not know whether your export has the right fields, inspect the shape
first:

```bash
python3 cairn_inspect_log_schema.py \
  --input your_trace.jsonl \
  --out report/schema_inspection.json
```

You can share `report/schema_inspection.json` or one redacted example row
without sharing raw logs.

Useful fields are:

```text
session_id or run_id
step index or timestamp
tool/action name
command/action text
stdout/stderr/observation/output text
target/session/provenance hints if available
input/output token counts if available
```

If the trace shape is different, map it into the simple JSONL format shown in
`samples/pentest_trace_sample.jsonl`.

Minimal JSONL example:

```json
{"session_id":"run-1","step":1,"tool":"shell","command":"nmap -sV 10.0.0.5","output":"PORT 22 open ssh...","output_tokens":900,"before":{"fingerprint":"target-a"},"after":{"fingerprint":"target-a"}}
```

If output or observation text is missing, CAIRN can still show repeated-work and
stale-risk structure, but token-savings and delta-serving estimates will be
weaker.

If target/session fingerprints are missing, CAIRN can still run with
conservative proxy fingerprints, but real fingerprints make the protected-lane
analysis stronger.

## Public Reference Result

The included example report is from public AutoPenBench / genai-pentest-paper
experiment logs, not customer traffic.

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

Open:

```text
examples/autopenbench/report.html
```

## Pilot Shape

The first pilot is an offline audit:

```text
20-50 representative AI-pentest runs, or a day/week of traces
raw logs stay in the customer's environment
review only the generated report
```

Decision rule:

```text
If there is no repeated-work signal, stop.
If there is signal, pick one high-volume repeated tool family and scope a
protected pilot.
```

## Boundaries

CAIRN Security Agent Audit is:

- local,
- audit-only,
- trace/report oriented,
- designed to avoid stale replay.

It is not a vulnerability scanner, pentest runner, or live target automation.

## License

Evaluation package. Copyright fraQtl. Do not redistribute without permission.
