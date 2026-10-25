---
name: ransomware-resilience
description: Prevent, contain, and recover from ransomware and extortion, including double-extortion data theft.
tags: org, response, breach
---
Modern ransomware steals data first, then encrypts, so backups alone no longer save you; you need to prevent theft too.

## Prevent initial access
- Patch internet-facing systems fast (KEV first: check_known_exploited); remove or hide VPNs/RDP/management ports; MFA everywhere, phishing-resistant for admins and remote access.
- Email and endpoint: filtering, attachment/macro blocking, EDR with tamper protection, application allowlisting, block known-vulnerable drivers.
- Credential hygiene: no password reuse, privileged access workstations, tiered admin model, LAPS for local admin passwords, disable legacy auth (NTLM/SMBv1), protect LSASS.
- Third parties and MSPs: scoped, MFA-protected, monitored access; they are a common entry route.

## Limit spread and theft
- Network segmentation, east-west filtering, restricted SMB/RDP between workstations, separate backup and management networks.
- Least privilege and short-lived admin; monitor for mass file access/renames, shadow-copy deletion, new GPOs, security-tool tampering, unusual use of rclone/MEGA/cloud sync, large outbound transfers.
- Egress control and DLP on crown-jewel data; honeytoken files that alert when touched.

## Recover
- 3-2-1-1-0 backups: 3 copies, 2 media, 1 offsite, 1 offline or immutable, 0 errors on restore tests. Backup credentials separate from domain admin. Test full restores and measure RTO/RPO.
- Golden images and infrastructure-as-code to rebuild quickly; documented dependency order; offline copy of the IR plan, contact tree, and key credentials in a break-glass vault.
- Rehearse: tabletop with executives and legal; decide in advance the stance on payment (consult counsel, law enforcement, and sanctions rules); out-of-band communications channel because email may be compromised.

## During an incident
Isolate affected segments (do not power off if forensics memory is needed), preserve evidence, engage IR retainer and counsel, notify insurer and law enforcement, rotate all credentials reachable from compromised hosts including Kerberos krbtgt twice, rebuild rather than clean, validate data theft scope, and meet notification deadlines (privacy-compliance).
