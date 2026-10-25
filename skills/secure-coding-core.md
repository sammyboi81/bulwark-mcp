---
name: secure-coding-core
description: Baseline rules for any code you write - OWASP Top 10 mapped to concrete habits.
tags: core, web, owasp
---
Read this first for any build. Then load the specific skills for the task (skills_for_task).

## Principles
- Deny by default. Validate input, encode output, least privilege, fail closed, defense in depth.
- Never trust: user input, headers, cookies, file names, webhooks, third-party API responses, model output, retrieved documents.
- Prefer boring, audited libraries over hand-rolled security code (auth, crypto, sessions, sanitizers, parsers).
- Secure defaults must be the easy path: the insecure option should need a deliberate flag.

## OWASP Top 10 -> habits
- Broken access control: check authorization per object on the server (authz-access-control). Never rely on hidden UI or client-side checks.
- Cryptographic failures: TLS 1.2+ everywhere, modern AEAD, no home-made crypto, no secrets in plaintext at rest (cryptography-essentials).
- Injection: parameterized queries, no shell strings, contextual output encoding (input-validation-injection).
- Insecure design: threat model before building (threat-modeling); abuse cases beside use cases.
- Security misconfiguration: no default creds, debug off, least-open cloud/network config, hardened headers (cloud-iac-security, web-frontend-security).
- Vulnerable and outdated components: lockfiles, scanning, SBOM, update cadence (supply-chain-security).
- Identification and authentication failures: passkeys/MFA, breached-password checks, rate limits (authn-session-management).
- Software and data integrity failures: signed artifacts, pinned CI, no unsafe deserialization (ci-cd-pipeline-security).
- Logging and monitoring failures: log security events, alert on them (logging-detection-response).
- SSRF and unsafe resource consumption: allowlist outbound hosts, cap sizes/time/cost.

## Definition of done for security
1. Threat model sketched, top threats mitigated. 2. Checklist run (secure_coding_checklist). 3. scan_code plus a real SAST/secret scan clean. 4. Dependencies checked (check_package_vulns). 5. Tests for authz boundaries and the injection points. 6. No new secret in repo or logs.
