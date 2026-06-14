# CAIRN Agent Log Audit

Input: `data/genai-pentest-paper/logs/experiments`

## Summary

- Events audited: `2,764`
- Sessions: `115`
- Re-reads: `1,031` (`37.30%` of events)
- Re-read output tokens: `676,284`
- Point tokens avoided: `548,335`
- Cumulative carried-context tokens avoided: `3,698,589`
- Avoided-token ratio on re-read traffic: `81.08%`
- Context multiplier on avoided tokens: `6.75x`
- Estimated point-token input savings: `$1.6450`
- Estimated carried-context input savings: `$11.0958`

## Actions

- `LIVE_CALL`: `1,733`
- `DELTA_SERVE`: `1,018`
- `EXACT_CACHE`: `13`
- `BLOCK_REUSE`: `0`

## Safety

- Protected-lane blocks: `1,016`
- Exact-cache stale-risk events: `1,016`
- Stale serves counted: `0`
- False hits counted: `0`

## Top Repeated Families

| Family | Re-reads | Point Tokens Avoided | Carried-Context Tokens Avoided | Avoided Ratio |
|---|---:|---:|---:|---:|
| `search` | 40 | 379,078 | 1,305,231 | 99.44% |
| `curl` | 137 | 35,462 | 512,861 | 55.79% |
| `unknown` | 142 | 18,289 | 251,793 | 37.62% |
| `nmap` | 52 | 10,167 | 208,973 | 86.44% |
| `set` | 126 | 10,154 | 201,954 | 65.55% |
| `use` | 31 | 7,681 | 173,623 | 80.32% |
| `python3` | 62 | 11,310 | 155,406 | 42.84% |
| `run` | 66 | 6,623 | 92,589 | 45.99% |
| `msfconsole` | 30 | 2,846 | 83,156 | 18.45% |
| `ssh` | 68 | 3,037 | 78,928 | 38.77% |
| `searchsploit` | 7 | 2,896 | 76,401 | 78.82% |
| `find` | 32 | 4,605 | 75,229 | 76.36% |

## Top Examples

- `DELTA_SERVE` `nmap` saved `242` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.0.5 $ nmap -sV 192.168.1.0`
- `DELTA_SERVE` `ssh` saved `385` tokens; violations: `repo_state, repo_state_fingerprint`; command: `ssh student@192.168.1.0:`
- `DELTA_SERVE` `sudo` saved `289` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.1.0 $ sudo -l`
- `DELTA_SERVE` `cat` saved `384` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.1.0 $ cat /root/flag`
- `DELTA_SERVE` `nmap` saved `161` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.0.5 $ nmap -sS -sV 192.168.1.0/24`
- `DELTA_SERVE` `hydra` saved `0` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.0.5 $ hydra -l student -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1`
- `DELTA_SERVE` `hydra` saved `244` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.0.5 $ hydra -l student -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1`
- `DELTA_SERVE` `ssh` saved `0` tokens; violations: `repo_state, repo_state_fingerprint`; command: `ssh student@192.168.1.1:`
- `DELTA_SERVE` `ssh` saved `302` tokens; violations: `repo_state, repo_state_fingerprint`; command: `ssh student@192.168.1.1:`
- `DELTA_SERVE` `find` saved `336` tokens; violations: `repo_state, repo_state_fingerprint`; command: `192.168.1.1 $ find / -type f -perm -o=w 2>/dev/null`

## Recommended Next Action

Run a one-week local pilot with the same audit and prioritize delta-serving integration for top repeated families.

## Caveats

- This is an audit, not auto-serving.
- Dollar savings use the provided input-token price and should be treated as a trace-local estimate.
- Logs without live output text can show exact-cache opportunities and stale risk, but not delta-serving savings.
- Protected-lane quality depends on the provenance fields present in the input logs.
