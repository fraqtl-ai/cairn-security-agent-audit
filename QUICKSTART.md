# Quickstart

## 1. Install Locally From The Repo

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

After PyPI release, this becomes:

```bash
pip install cairn-security-agent-audit
```

## 2. Run The Sample In The Terminal

```bash
cairn-demo
```

This prints the audit summary and writes:

```text
report/summary.json
report/summary.md
report/normalization_summary.json
```

Terminal-only JSON:

```bash
cairn-demo --json-only | less
```

## 3. Run Your Own JSONL

```bash
cairn-audit \
  --input your_trace.jsonl \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

Terminal-only JSON:

```bash
cairn-audit \
  --input your_trace.jsonl \
  --price-input-per-m 3.0 \
  --json-only > cairn-summary.json
```

## 4. Run A Directory

```bash
cairn-audit \
  --input logs/ \
  --glob '*.json' \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

## 5. Inspect Unknown Logs First

```bash
cairn-inspect \
  --input your_trace.jsonl \
  --out schema_inspection.json
```

## 6. Expected Input Shape

One JSON object per tool event:

```json
{"session_id":"run-1","step":1,"tool":"shell","command":"nmap -sV 10.0.0.5","output":"PORT 22 open ssh...","output_tokens":900,"before":{"fingerprint":"target-a"},"after":{"fingerprint":"target-a"}}
```

Minimum useful fields:

```text
session_id
tool or action
command
output or observation
before/after fingerprint if available
```

If fingerprints are unavailable, CAIRN will infer a conservative proxy from the
trace shape. Real target/session fingerprints make the protected-lane result
stronger.
