# Security-Agent Log Formats

CAIRN Security Agent Audit accepts JSON, JSONL, and directories of JSON logs.

The preferred format is one tool event per JSONL line.

## Preferred JSONL

```json
{"session_id":"run-1","step":1,"tool":"shell","command":"nmap -sV 10.0.0.5","output":"PORT 22 open ssh...","output_tokens":900,"before":{"fingerprint":"target-a"},"after":{"fingerprint":"target-a"}}
```

Useful fields:

- `session_id` or `run_id`
- `step`, `step_index`, or timestamp
- `tool`, `tool_name`, `action`, or `function`
- `command`, `command_text`, `cmd`, or `tool_input`
- `output`, `observation`, `stdout`, `stderr`, or `result`
- `output_tokens`, `tokens`, or byte counts if available
- `before.fingerprint` and `after.fingerprint` if target/session state is available

## Pentest Step Logs

CAIRN also accepts JSON logs shaped like:

```json
{
  "run_id": "run-1",
  "target": "10.0.0.5",
  "steps": [
    {
      "thought": "Scan the target",
      "action": "ExecuteBash(nmap -sV 10.0.0.5)",
      "observation": "PORT 22 open ssh..."
    }
  ]
}
```

This is common in benchmark and agent-experiment logs.

## What Strong Provenance Looks Like

The strongest audit includes a target/session fingerprint before and after each
tool call:

```json
"before": {"fingerprint": "target-session-state-before"},
"after": {"fingerprint": "target-session-state-after"}
```

Examples:

- target id or scenario id,
- authenticated session id,
- shell/session id,
- scan snapshot id,
- exploit framework workspace id,
- environment version,
- any internal trace state hash.

If these fields are missing, CAIRN can still run a first audit with conservative
proxy fingerprints, but real target/session fingerprints make the stale-replay
and protected-lane analysis stronger.

## Output Text Matters

For delta-serving measurement, CAIRN needs the actual observation/output text,
not only a hash. If raw output is too sensitive, run the audit fully inside the
customer environment and share only the generated report.

## Unknown Formats

Inspect the shape first:

```bash
python3 cairn_inspect_log_schema.py \
  --input raw_logs.jsonl \
  --out report/schema_inspection.json
```

Then either run directly or map the fields into the preferred JSONL format.

