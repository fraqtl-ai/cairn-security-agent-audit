# One Redacted Event

If your logs do not map cleanly to CAIRN yet, do not prepare a full trace first.
One tiny redacted event is enough to adapt the mapper.

## Minimum Useful Shape

Send one JSON or JSONL record with the fields closest to these:

```json
{
  "session_id": "redacted-run-1",
  "timestamp": "2026-06-21T12:00:00Z",
  "step": 12,
  "tool": "nmap",
  "input": "nmap -sV REDACTED_TARGET",
  "output": "PORT 22/tcp open ssh ... REDACTED",
  "target": "redacted-target-or-asset-id",
  "before": {"fingerprint": "state-before-redacted"},
  "after": {"fingerprint": "state-after-redacted"}
}
```

Use whatever field names your system already emits. The mapper can adapt to names such as `tool_name`, `action`, `command`, `stdout`, `stderr`, `observation`, `result`, `run_id`, or `trace_id`.

## What To Redact

Redact anything sensitive before sharing a sample event:

- real IPs, domains, hostnames, tenant names, usernames, passwords, tokens, keys, cookies, and session IDs;
- exploit payloads or target-specific findings that should not leave your environment;
- customer, account, repo, or workspace identifiers.

Good replacements are stable placeholders such as `REDACTED_TARGET_A`, `REDACTED_SESSION_1`, or `REDACTED_TOKEN`.

## What Matters Most

For a useful first mapper pass, preserve the structure even if values are redacted:

- one run/session identifier;
- one step number or timestamp;
- the tool or action name;
- the tool input or command;
- the output or observation text, even shortened;
- any target/session/environment state fields before and after the call.

If raw output cannot be shared at all, send the schema inspection instead:

```bash
python3 cairn_inspect_log_schema.py \
  --input your_trace.jsonl \
  --out report/schema_inspection.json
```

Then share only:

```text
report/schema_inspection.json
```

## Why One Event Is Enough

The first goal is not to score your system. It is only to answer:

```text
Can CAIRN read this trace format without forcing your team to re-export logs?
```

Once the mapper fits, the full audit can still run locally inside your environment. Raw logs do not need to leave your machine.
