# Quickstart

## 1. Run The Sample

```bash
./demo.sh
```

Equivalent CLI command:

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

## 2. Run Your Own JSONL

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input your_trace.jsonl \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

## 3. Run A Directory

```bash
python3 cairn_pilot_from_raw_logs.py \
  --input logs/ \
  --glob '*.json' \
  --out report \
  --price-input-per-m 3.0 \
  --no-cleaned-trace
```

## 4. Expected Input Shape

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

