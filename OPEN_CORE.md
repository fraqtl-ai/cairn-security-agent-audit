# Open-Core Model

CAIRN uses an open-core model.

## Free / Open Source

This public repository contains the local audit slice:

- CLI audit for JSON/JSONL/folder traces,
- dependency-free local UI,
- schema inspector,
- sample pentest trace,
- AutoPenBench-style example report,
- repeated-work and stale-replay report generation,
- basic action classification: `LIVE_CALL`, `EXACT_CACHE`, `DELTA_SERVE`, `BLOCK_REUSE`.

Use it to answer one question:

```text
Do my security-agent traces contain repeated tool-output work where safe reuse
or delta-serving could reduce context cost without stale replay?
```

## Paid / Commercial

Commercial CAIRN work starts after the audit finds a useful signal:

- runtime sidecar beside an agent or tool gateway,
- production-safe reuse decisions,
- custom trace mappers and protected-state fingerprints,
- dashboard/history across runs,
- integration around one high-volume tool family,
- receipts for every reuse/block/fallback decision,
- support, SLAs, and private deployment.

The first paid pilot should be narrow. Examples:

```text
nmap reuse policy for AI-pentest agents
SOC enrichment reuse policy for AI analysts
httpx/ffuf/nuclei trace audit and runtime pilot
```

## Funnel

1. Run the open audit locally.
2. Review `summary.md`, `summary.json`, and `report.html`.
3. If the repeated-work signal is meaningful, scope one commercial runtime pilot.
4. Keep raw logs inside the customer environment unless explicitly agreed.
