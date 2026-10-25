---
name: logging-detection-response
description: What to log, how to alert, and an incident response loop that limits breach damage.
tags: detection, response, breach
---
## Log (structured, timestamped, tamper-resistant)
- Authn success/failure, MFA events, password/recovery changes, privilege and permission changes, authz denials, admin actions, data export/bulk reads, config changes, API key creation, unusual volumes, outbound connection anomalies.
- Include who, what object, from where, result, request ID. Exclude secrets and raw PII.
- Ship off-host to append-only storage; separate who can write logs from who can read/delete. Time-sync (NTP). Retain per policy and regulation.

## Detect
- Alert on: impossible travel, new device + privilege change, spikes in 401/403/404, mass downloads, new admin, disabled logging, MFA reset, token use from new ASN, dormant-account use, data egress to new destinations, CI secret access from unusual jobs.
- Honeytokens/canaries in repos, buckets, databases. Review KEV and vendor advisories weekly (check_known_exploited).

## Respond (rehearsed before you need it)
1. Prepare: owners, on-call, contact tree, legal/PR contacts, offline copy of the runbook, forensic-ready logging, tested backups.
2. Detect and triage: severity, scope hypothesis. Preserve evidence (snapshots, logs) before cleanup.
3. Contain: isolate hosts, revoke sessions/tokens/keys, disable compromised accounts, block IOCs. Rotate credentials of everything the intruder could have touched.
4. Eradicate and recover: remove persistence, patch root cause, restore from known-good, monitor closely.
5. Notify: regulators and individuals within legal deadlines (privacy-compliance), customers, partners.
6. Learn: blameless review, fix detection gaps, update runbook, tabletop twice a year.
- Assume attackers use AI to move faster: shorten detection-to-containment targets and automate containment for high-confidence signals.
