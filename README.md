<p align="center">
  <img src="docs/logo.png" alt="fraQtl" width="150"/>
</p>

<h1 align="center">CAIRN Security Agent Audit</h1>

<p align="center">
  Local/offline audit for AI-pentest traces: repeated tool-output work, stale replay risk, protected-lane blocks, and token-savings reports.
</p>

<p align="center">
  <a href="docs/CACHE_CONTROL_FOR_SECURITY_AGENTS.md">Proof page</a> ·
  <a href="OPEN_CORE.md">Open-core</a> ·
  <a href="#quickstart">Quickstart</a> ·
  <a href="#try-your-own-logs">Try your logs</a> ·
  <a href="#have-different-logs">One redacted event</a> ·
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

This repository is the free, open-source audit slice of CAIRN. It is local, CLI-first, and
audit-only. It does not run pentests, does not need live target access, and does
not auto-serve cached outputs. The commercial CAIRN Runtime is a separate protected sidecar for production reuse decisions.

CAIRN is cache-control for security agents, not generic caching:

```text
Agent trace
  -> normalize tool events
  -> compare protected target/session state
  -> choose the safest action

same work + same protected state      -> EXACT_CACHE
related work + changed/partial state  -> DELTA_SERVE
uncertain or first-seen work           -> LIVE_CALL
unsafe protected-state mismatch        -> BLOCK_REUSE
```

> **Open-core scope:** this repo is the open audit slice of CAIRN, not the full
> runtime product. The protected runtime sidecar, production serving layer,
> enterprise dashboard/history, custom mappers, support, and commercial deployment
> are not included here. Use this repo to test whether a repeated-work signal
> exists in your AI-pentest traces.

## What It Does

Given JSON/JSONL security-agent logs, CAIRN:

- normalizes trace records into a common audit schema,
- groups repeated tool-output/context work,
- compares protected target/session state,
- marks exact-cache stale-risk events,
- classifies `LIVE_CALL`, `EXACT_CACHE`, `DELTA_SERVE`, and `BLOCK_REUSE`,
- estimates point-token and carried-context savings,
- writes terminal JSON plus `summary.json` and `summary.md`; `report.html` is optional with `--html`.

## Quickstart

Install from the repo:

```bash
git clone https://github.com/fraqtl-ai/cairn-security-agent-audit.git
cd cairn-security-agent-audit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

After PyPI release, this becomes:

```bash
pip install cairn-security-agent-audit
```

Run the included pentest sample:

```bash
cairn-demo
```

Terminal-only JSON:

```bash
cairn-demo --json-only | less
```

From a repo clone, `./demo.sh` also works without installing.

The sample prints a JSON summary in the terminal and writes JSON/Markdown receipts. For a larger public benchmark HTML example, open:

```text
examples/autopenbench/report.html
```

## Try Your Own Logs

If your trace is JSONL:

```bash
cairn-audit \
  --input your_trace.jsonl \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

If your trace is one JSON file:

```bash
cairn-audit \
  --input your_trace.json \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

If your traces are a directory of JSON logs:

```bash
cairn-audit \
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
cairn-inspect \
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

## Have Different Logs?

If your logs do not map cleanly, do not prepare a full export first. Send or inspect one redacted event instead. The minimum useful shape is:

```text
session_id, timestamp or step, tool name, tool input/command, output/observation, target/session state if available
```

See [One Redacted Event](docs/ONE_REDACTED_EVENT.md) for exactly what to share and what to redact. One event is enough to adapt the mapper; the full audit can still run locally inside your environment.

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

## Open-Core Model

This repository is MIT-licensed and contains the local audit slice: CLI, schema inspector, sample traces, and JSON/Markdown report generation. HTML output is available, but the main product path is terminal-first.

The paid/commercial layer is CAIRN Runtime: a protected sidecar for production reuse decisions, custom trace mappers, dashboard/history, deployment support, and enterprise licensing.

See [Open-Core Model](OPEN_CORE.md).

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

MIT License. See [LICENSE](LICENSE).

Commercial CAIRN Runtime, private integrations, managed deployments, support, and enterprise licensing are separate from this open audit package. See [Open-Core Model](OPEN_CORE.md).
