# CAIRN Audit Terms

This repository is the open-source audit slice of CAIRN Security Agent Audit.
It is licensed under the MIT License. See [LICENSE](LICENSE).

You may use this package to:

- run local/offline audits on internal security-agent traces,
- inspect generated reports,
- adapt the audit scripts for your own trace formats,
- share and redistribute this audit package under the MIT License.

## What This Repository Is

This package is audit-only. It normalizes trace logs, identifies repeated
agent/tool-output work, checks protected target/session state when available,
and writes local reports.

It does not execute pentest actions, connect to live targets, serve cached
outputs, or make production runtime decisions.

## Commercial CAIRN Runtime

The following are not included in this repository:

- protected runtime sidecar,
- production serving layer,
- enterprise dashboard/history,
- hosted or managed deployment,
- private/custom trace mappers,
- support, SLAs, or implementation services,
- advanced protected-reuse policies beyond the public audit slice.

If the audit shows a repeated-work signal in your traces, the commercial path is
a scoped CAIRN Runtime pilot around one high-volume tool family or workflow.

## Safety Boundary

This project is not a vulnerability scanner, pentest runner, exploit framework,
or autonomous security tool. It analyzes existing logs only.
