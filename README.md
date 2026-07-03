# CAIRN Security Agent Audit

Terminal-first local audit for AI security-agent traces.

CAIRN finds repeated scanner/shell/enrichment output in agent traces, flags stale replay risk when target/session/entity state changes, and reports where reuse should be exact, partial, blocked, or live.

```text
pip install cairn-security-agent-audit
cairn-demo
```

CAIRN is audit-only. It does not run pentests, connect to live targets, upload logs, or serve cached outputs.

## Why This Exists

Security agents often re-read long tool outputs:

- scanner output: `nmap`, `nuclei`, `ffuf`, `httpx`
- shell and file-inspection output
- exploit-framework observations
- SOC enrichment and investigation results
- target/session/environment metadata

Blind caching is unsafe because the target, auth context, session, workspace, or entity state may have changed. CAIRN audits the trace and separates useful repeated work from stale replay risk.

## Install

```bash
pip install cairn-security-agent-audit
```

With exact tokenization (tiktoken) instead of the bytes/4 proxy:

```bash
pip install 'cairn-security-agent-audit[tokens]'
```

From source:

```bash
git clone https://github.com/fraqtl-ai/cairn-security-agent-audit.git
cd cairn-security-agent-audit
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

## Run The Demo

```bash
cairn-demo
```

This prints a JSON summary in the terminal and writes:

```text
report/summary.json
report/summary.md
report/normalization_summary.json
```

Pure terminal JSON:

```bash
cairn-demo --json-only | less
```

Optional HTML:

```bash
cairn-demo --html
```

## Audit Your Own Logs

JSONL trace:

```bash
cairn-audit \
  --input your_trace.jsonl \
  --out report \
  --model claude-sonnet-4.5
```

`--model` resolves input and cached-input prices from a built-in table
(override with `--price-input-per-m` / `--price-cached-input-per-m`; verify
prices against the provider pricing page before quoting anyone).
`--tokenizer tiktoken` uses exact o200k_base token counts when installed.

Directory of JSON logs:

```bash
cairn-audit \
  --input logs/ \
  --glob '*.json' \
  --out report \
  --price-input-per-m 3.0
```

Terminal-only JSON receipt:

```bash
cairn-audit \
  --input your_trace.jsonl \
  --price-input-per-m 3.0 \
  --json-only > cairn-summary.json

cat cairn-summary.json
```

Skip writing the normalized trace for larger or sensitive runs:

```bash
cairn-audit \
  --input your_trace.jsonl \
  --out report \
  --no-cleaned-trace
```

## Inspect Unknown Log Shapes

If your logs do not map cleanly, inspect the schema first:

```bash
cairn-inspect \
  --input your_trace.jsonl \
  --out schema_inspection.json

cat schema_inspection.json
```

If mapping is still unclear, one redacted event is enough to adapt the mapper. See [One Redacted Event](docs/ONE_REDACTED_EVENT.md).

## Input Shape

Preferred input is one JSON object per tool event:

```json
{
  "session_id": "run-1",
  "step": 1,
  "tool": "shell",
  "command": "nmap -sV 10.0.0.5",
  "output": "PORT 22 open ssh...",
  "output_tokens": 900,
  "before": {"fingerprint": "target-a"},
  "after": {"fingerprint": "target-a"}
}
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

If fingerprints are unavailable, CAIRN infers conservative proxy fingerprints. Real target/session fingerprints make the protected-state analysis stronger.

## Output

CAIRN reports:

| Area | What CAIRN reports |
|---|---|
| Repeated work | Events audited, re-reads, repeated-work percentage |
| Tool families | Top repeated commands/tools by carried-context savings |
| Safety | Protected-lane blocks and exact-cache stale-risk events |
| Actions | `LIVE_CALL`, `EXACT_CACHE`, `DELTA_SERVE`, `BLOCK_REUSE` |
| Savings | Point tokens avoided, carried-context tokens avoided, estimated dollars |
| Receipts | Concrete commands/actions behind the signal |

Example summary fields:

```json
{
  "events": 8,
  "re_reads": 4,
  "repeated_work_percent": 50.0,
  "exact_cache_opportunities": 3,
  "delta_serve_opportunities": 1,
  "exact_cache_stale_risk_events": 1,
  "provenance_decidable_rereads": 3,
  "false_hits": 0,
  "provenance_exact_cache_false_hit_rate": 0.0,
  "point_tokens_avoided": 346,
  "cumulative_carried_context_tokens_avoided": 954,
  "estimated_total_dollars_saved_no_provider_cache": 0.0039,
  "estimated_total_dollars_saved_net_of_provider_cache": 0.0013
}
```

The false-hit rate is measured, not assumed: whenever protected provenance
matched but the output hash changed, a naive provenance-only cache would have
served a stale result. CAIRN counts it, reports it, and refuses to exact-cache.
Two dollar figures are reported: the upper bound (no provider prompt caching)
and a conservative floor that prices carried context at the provider
prompt-cache read rate.

## Action Policy

```text
same work + same protected state      -> EXACT_CACHE
related work + changed/partial state  -> DELTA_SERVE
uncertain or first-seen work           -> LIVE_CALL
unsafe protected-state mismatch        -> BLOCK_REUSE
```

## Public Reference Results

Measured with this engine (v0.2.0, bytes/4 estimator) on public traces.

AutoPenBench / genai-pentest-paper security-agent logs:

```text
2,881 tool events audited
834 re-reads (28.95% repeated work)
87.01% avoided-token ratio on re-read traffic
822 protected-lane blocks (stale replay risk caught)
false-hit rate: 1 of 12 provenance-matched re-reads (8.33%)
```

Coding-agent corpora (Kwai SWE-smith 66k + NVIDIA SWE-Hero OpenHands,
4.15M tool commands, 97k sessions):

```text
437,013 re-reads
50,632 certified exact-cache hits (provenance AND output hash matched)
294,824 protected-lane blocks
false-hit rate: 64.39% of provenance-matched re-reads had CHANGED output
  (Kwai 70.86%, NVIDIA 10.47%)
88.9M point tokens avoided; 2.15B carried-context tokens avoided (upper bound)
```

The false-hit result is the headline: on real agent traces, a cache keyed on
anything short of output identity would silently serve stale results most of
the time. That is why CAIRN certifies reuse instead of assuming it.

Read these as offline audit-policy results, not production-serving claims.

## Open-Core Boundary

This repository is the free MIT-licensed audit slice:

- terminal CLI
- schema inspector
- bundled sample trace
- JSON/Markdown receipts
- optional HTML report
- repeated-work and stale-replay audit

The paid/commercial product is CAIRN Runtime:

- protected sidecar beside an agent or tool gateway
- production exact-cache / delta-serve / live-call / block decisions
- custom trace mappers and protected-state fingerprints
- dashboard/history across runs
- deployment support and enterprise licensing

The intended funnel is:

```text
run local audit -> find repeated-work signal -> scope one runtime pilot around one high-volume tool family
```

## Safety Boundary

CAIRN Security Agent Audit is not a vulnerability scanner, pentest runner, exploit framework, or autonomous security tool. It analyzes existing logs only.

## Links

- GitHub: https://github.com/fraqtl-ai/cairn-security-agent-audit
- PyPI: https://pypi.org/project/cairn-security-agent-audit/
- Proof page: [Cache-Control For Security Agents](docs/CACHE_CONTROL_FOR_SECURITY_AGENTS.md)
- Log formats: [Security-Agent Log Formats](docs/LOG_FORMATS.md)
- One redacted event: [One Redacted Event](docs/ONE_REDACTED_EVENT.md)

## License

MIT License. See [LICENSE](LICENSE).
