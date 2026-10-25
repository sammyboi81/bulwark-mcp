---
name: threat-modeling
description: A lightweight, repeatable threat-modeling method with STRIDE, attack trees, abuse cases, and AI-specific threats.
tags: design, core, ai
---
Do it early, keep it small, repeat when the design changes. The threat_model tool returns a worksheet; this skill explains how to use it well.

## Four questions (Shostack)
1. What are we building? Draw a data-flow diagram: actors, processes, data stores, external services, trust boundaries (browser/server, service/service, tenant/tenant, human/model).
2. What can go wrong? STRIDE every element and boundary crossing; write attacker stories ("a malicious tenant guesses another tenant's invoice ID").
3. What are we going to do about it? Mitigate, eliminate, transfer, or accept - with an owner. Prefer eliminating the feature or data over adding controls.
4. Did we do a good job? Tests, abuse-case checks, review, red team, monitoring for each mitigation.

## Tips
- Start from assets and crown jewels: what would hurt most if stolen, altered, or unavailable?
- Rank with likelihood x impact (or DREAD-like simple scoring); handle the top 5 first.
- Use attack trees for the scariest goals (e.g., "steal all customer data": via SQLi, stolen admin token, misconfigured bucket, insider, vendor).
- Abuse cases beside use cases: rate abuse, enumeration, scraping, free-tier farming, refund/coupon fraud, automated account creation.
- Include non-code boundaries: CI/CD, package registries, developer laptops, support tooling, third-party SaaS, backups.
- AI systems: add prompt-injection paths, tool/agent permissions, data leakage through output, RAG/memory poisoning, model and plugin supply chain, cost/denial-of-wallet (llm-app-security, mcp-agent-security). Map to MITRE ATLAS.
- Attacker-side AI: assume reconnaissance, phishing, and exploit development are cheap and fast (ai-driven-attack-defense).
- Output: a short document with the diagram, top threats, mitigations, tests, residual risk, owner, review date. Store it with the code; update in the PR that changes the design.
- Tools: OWASP Threat Dragon, pytm, Microsoft Threat Modeling Tool (vet and pin).
