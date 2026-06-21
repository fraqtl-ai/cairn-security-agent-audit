# CAIRN: Cache-Control For Security Agents

CAIRN is a local audit for AI-agent traces. It finds repeated tool-output work, checks protected target/session state, and reports where reuse should be exact, partial, blocked, or live.

This is not generic semantic caching. Security-agent workflows are state-sensitive: a scanner result, shell output, exploit attempt, or session observation can become stale when the target, auth context, workspace, or environment changes.

## The Problem

Security agents repeatedly inspect the same kind of evidence:

- scanner output such as `nmap`, `nuclei`, `ffuf`, or `httpx`;
- shell and file-inspection output;
- exploit-framework state;
- SOC enrichment and investigation results;
- target/session/environment metadata.

A naive cache can save tokens but risks replaying stale observations. CAIRN audits the trace first and separates useful repeated work from unsafe replay.

## The Action Policy

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

## What The Public Audit Shows

The public package ships with a small pentest sample and an AutoPenBench-style example report.

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

Read this as an audit-policy result: the package reports where exact replay would be stale and counts safe opportunities under the protected-lane policy. It is not a claim that production serving is already integrated.

## How To Try It

Run the sample locally:

```bash
git clone https://github.com/fraqtl-ai/cairn-security-agent-audit.git
cd cairn-security-agent-audit
python3 cairn_pilot_from_raw_logs.py \
  --input samples/pentest_trace_sample.jsonl \
  --out report \
  --price-input-per-m 3.0
```

Open:

```text
report/report.html
```

If your logs use a different shape, do not prepare a full export first. Send one redacted event or run the schema inspector. See [One Redacted Event](ONE_REDACTED_EVENT.md).

## Design-Partner Path

1. Offline audit on an existing trace or one sample event.
2. Mapper adaptation for the trace format.
3. Local report review: repeated work, stale replay risk, top tool families.
4. Runtime pilot only if the audit finds a repeated-work signal.
5. First runtime scope should be one high-volume tool family, such as `nmap`, `httpx`, `ffuf`, `nuclei`, `ssh`, or SOC enrichment calls.

Raw logs should stay in the customer environment. The public repo is the offline audit slice, not the full CAIRN runtime.
