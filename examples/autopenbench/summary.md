# CAIRN Agent Log Audit

Input: `/Users/samuelsalfati/Documents/Projects/Cairn/data/genai-pentest-paper/logs/experiments`

## Summary

- Events audited: `2,881`
- Sessions: `116`
- Re-reads: `834` (`28.95%` of events)
- Re-read output tokens: `625,336`
- Point tokens avoided: `544,122`
- Cumulative carried-context tokens avoided: `3,645,608`
- Avoided-token ratio on re-read traffic: `87.01%`
- Context multiplier on avoided tokens: `6.70x`
- Estimated point-token input savings: `$1.6324`
- Estimated carried-context input savings: `$10.9368`
- Estimated total savings (no provider prompt cache): `$12.5692`
- Estimated total savings (net of provider prompt cache): `$2.7260`
- Prices: input `$3.00`/M, cached input `$0.30`/M (built-in price table for claude-sonnet-4.5 (verify against provider pricing page))
- Token estimator: explicit output_tokens if present, otherwise bytes/4

## Actions

- `LIVE_CALL`: `2,047`
- `DELTA_SERVE`: `823`
- `EXACT_CACHE`: `11`
- `BLOCK_REUSE`: `0`

## Safety

- Protected-lane blocks (provenance change caught): `822`
- Exact-cache stale-risk events: `822`
- Provenance-matched re-reads (decidable): `12`
- Exact-cache false-hits (provenance matched, output changed): `1` (`8.33%`)
- 1 of 12 provenance-matched re-reads had CHANGED output (8.33% false-hit risk): provenance alone is not a safe exact-cache key here; delta-serve/verify or strengthen protected fields before exact-cache serving.

## Top Repeated Families

| Family | Re-reads | Point Tokens Avoided | Carried-Context Tokens Avoided | Avoided Ratio |
|---|---:|---:|---:|---:|
| `ExecuteBash` | 771 | 538,002 | 3,538,678 | 87.14% |
| `SSHConnect` | 41 | 3,137 | 80,318 | 72.94% |
| `WriteFile` | 7 | 2,544 | 26,235 | 95.78% |
| `FinalAnswer` | 14 | 377 | 377 | 42.17% |
| `str` | 1 | 62 | 0 | 79.49% |

## Input Quality

- Malformed lines skipped: `0`

## Top Examples

- `DELTA_SERVE` `ExecuteBash` saved `245` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.0.5' cmd='nmap -sV 192.168.1.0`
- `DELTA_SERVE` `SSHConnect` saved `388` tokens; violations: `repo_state, repo_state_fingerprint`; command: `ssh_ipaddr='192.168.1.0' ssh_port=22 ssh_username='student' ssh_password='password`
- `DELTA_SERVE` `ExecuteBash` saved `292` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.1.0' cmd='sudo -l`
- `DELTA_SERVE` `ExecuteBash` saved `387` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.1.0' cmd='cat /root/flag`
- `DELTA_SERVE` `ExecuteBash` saved `164` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.0.5' cmd='nmap -sS -sV 192.168.1.0/24`
- `DELTA_SERVE` `ExecuteBash` saved `0` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.0.5' cmd='hydra -l student -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1`
- `DELTA_SERVE` `ExecuteBash` saved `248` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.0.5' cmd='hydra -l student -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1`
- `DELTA_SERVE` `SSHConnect` saved `306` tokens; violations: `repo_state, repo_state_fingerprint`; command: `ssh_ipaddr='192.168.1.1' ssh_port=22 ssh_username='student' ssh_password='password`
- `DELTA_SERVE` `ExecuteBash` saved `340` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.1.1' cmd='find / -type f -perm -o=w 2>/dev/null`
- `DELTA_SERVE` `ExecuteBash` saved `648` tokens; violations: `repo_state, repo_state_fingerprint`; command: `machine_ipaddr='192.168.1.1' cmd='find /home/student /dev/shm /tmp /var/tmp -writable -type f -user root 2>/dev/null`

## Recommended Next Action

Do not exact-cache on provenance alone yet: some provenance-matched re-reads changed output (see false-hit rate). Delta-serve or strengthen protected fields, then re-audit.

## Caveats

- This is an audit, not auto-serving.
- Dollar savings use the provided input-token price and should be treated as a trace-local estimate.
- Carried-context tokens avoided is an upper-bound model (avoided x remaining events in session), not a measured value.
- Two dollar figures are reported: 'no_provider_cache' prices everything at the fresh input rate; 'net_of_provider_cache' prices carried-context tokens at the provider prompt-cache READ rate, because stable-prefix context would mostly have been provider cache hits anyway. Quote the net figure to teams already using provider prompt caching; it is the defensible floor. Note provider caches are prefix-bound and short-TTL: they cannot reuse work across runs, sessions, or users the way certified recycling can.
- Logs without live output text can show exact-cache opportunities, stale risk, and false hits, but never delta-serving savings.
- False-hit rate = how often a provenance-only exact cache would have served a CHANGED output; 0% means provenance is a safe key on this trace.
- Sparse logs (missing cwd/model/user fields) can only overstate caution (more blocks, higher false-hit rate), never overstate savings.
- Protected-lane quality depends on the provenance fields present in the input logs.
- Per-user rows appear when traces carry user_id/user/actor/email fields; otherwise usage is (unattributed).
