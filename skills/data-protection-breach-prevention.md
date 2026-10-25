---
name: data-protection-breach-prevention
description: Prevent data breaches and limit damage - minimization, classification, encryption, access, exfil controls, backups.
tags: data, breach, core
---
The cheapest data to protect is data you never collected.

1. Minimize and expire: collect only what a feature needs; set retention per data class; delete on schedule (including logs, backups, analytics copies, AI training/RAG stores). Pseudonymize or aggregate where possible.
2. Classify: public / internal / confidential / regulated (PII, PHI, PCI, credentials, secrets). Label data stores and fields; policy follows the label.
3. Map data flows: where it enters, is stored, is copied (warehouse, search index, vector DB, logs, support tools, third parties, AI providers). Breaches happen in the forgotten copies.
4. Encrypt: TLS in transit, strong encryption at rest, field-level/application encryption for the crown jewels (SSNs, payment, health, auth secrets), keys in KMS/HSM (cryptography-essentials). Tokenize card data or use a PCI-compliant processor so you never hold PANs.
5. Access: least privilege, just-in-time elevation, MFA, no shared accounts, quarterly access reviews, immediate offboarding. Separate production data from dev/test; use synthetic or masked data in non-prod.
6. Limit bulk access: query/row caps, export approvals, rate limits on read APIs, DLP on egress, alert on mass reads and large transfers; watch service accounts and API keys, which are common breach vectors.
7. Secure the edges: SaaS misconfig (public links, open buckets, over-shared drives), third-party/vendor access (scope, review, contract breach-notice terms), OAuth app consent hygiene.
8. Backups: encrypted, access-restricted, immutable/offline copy, restore-tested. Backups are also a copy of your breach surface.
9. Logging that proves scope: record who read what so you can bound a breach (reduces notification scope and cost).
10. Support and ops tooling: customer-support impersonation and admin consoles are prime targets; audit them, require step-up, mask sensitive fields by default.
11. AI systems: no sensitive data in prompts/logs unless necessary; per-user authorization in RAG; vendor retention/training terms; scrub model outputs (llm-app-security).
12. Plan the bad day: IR runbook, legal counsel on call, forensics retainer, pre-drafted notices, breach-deadline calendar (privacy-compliance), cyber insurance requirements met.
