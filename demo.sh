#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="${1:-report}"

python3 cairn_pilot_from_raw_logs.py \
  --input samples/pentest_trace_sample.jsonl \
  --out "$OUT_DIR" \
  --price-input-per-m 3.0

cat <<MSG

CAIRN sample audit complete.

Open:
  $OUT_DIR/report.html

Also written:
  $OUT_DIR/summary.md
  $OUT_DIR/summary.json
  $OUT_DIR/normalization_summary.json
MSG
