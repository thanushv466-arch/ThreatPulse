# Architecture notes

## The event schema

Every parser produces the same `Event` (see `sentinel/schema.py`):

| Field | Meaning |
|---|---|
| `ts` | Epoch seconds, UTC |
| `source` | Which parser produced it: `sshd`, `nginx`, `ufw`, `zeek`, `windows` |
| `host` | The machine that wrote the line |
| `action` | Normalized verb: `ssh_login`, `http_request`, `fw_block`, `network_flow`, `process_start`, `user_created`, `group_member_added`, `audit_log_cleared`, `sudo_command`, `win_logon` |
| `outcome` | `success` or `failure` |
| `src_ip`, `dst_ip`, `dst_port`, `user` | The usual suspects |
| `raw` | The untouched original line, kept as evidence |
| `extra` | Source-specific fields: `url_decoded`, `user_agent`, `status`, `bytes_out`, `command_line`, `decoded_command`, `parent_process`, and enrichment tags `src_internal`, `dst_internal`, `dst_intel` |

This is the same idea as Elastic Common Schema or Splunk CIM, at toy scale:
normalize once, detect everywhere.

## Parsing gotchas handled

- **Syslog has no year.** `Sep 18 14:02:11` could be any year. The parser
  assumes the current year and rolls back one if that lands in the future
  (a Dec 31 log read on Jan 1). `--year` overrides it.
- **Time zones.** nginx timestamps carry an offset; everything is converted
  to UTC epoch on the way in so sources can be merged and compared.
- **Windows 4732.** `TargetUserName` is the *group*, not the user who was
  added. The member is in `MemberName`. Easy to get backwards.
- **Double URL encoding.** `%2527` decodes to `%27`, then to `'`. The parser
  decodes until stable, capped at three passes.
- **`ipaddress.is_private` is not "internal".** Python reports the RFC 5737
  documentation ranges as private. Internal networks are an explicit list.

## Engine state and memory

Threshold and sequence rules keep a deque of recent matching events per
`(rule, group key)`. Each deque is trimmed as the window slides, so memory
is bounded by window size times event rate, not by total log volume. Events
are expected in time order; `ingest_files` merges all sources and sorts
before feeding the engine, the way a SIEM indexes many sources onto one
timeline.

## Correlation

1. Resolve the alert's entity: an internal IP becomes its asset hostname.
2. Join the open incident for that entity if its last alert was within an hour.
3. Otherwise, if the alert has no source IP, join the open incident that most
   recently touched the same host.
4. Otherwise open a new incident.

Risk is recomputed on every new alert: severity points per distinct rule,
multiplied by 10% per additional ATT&CK tactic, plus bonuses for threat intel
hits and critical assets, passed through `100 * (1 - e^(-x/70))`.

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/summary` | Counts, severity split, ATT&CK matrix, timeline |
| GET | `/api/alerts?status=&severity=` | Alert queue |
| GET | `/api/alerts/<id>` | Alert with evidence lines, rule and playbook |
| POST | `/api/alerts/<id>/status` | Acknowledge, close, or mark false positive |
| GET | `/api/incidents` | Incidents ranked by risk |
| GET | `/api/events/search?q=` | Log search |
| GET | `/api/rules` | Detection catalog |
| POST | `/api/contain`, `/api/release` | Simulated containment |
| GET | `/api/blocklist.txt` | Blocklist as plain text |
| POST | `/api/simulate` | Play an attack scenario into the live pipeline |
