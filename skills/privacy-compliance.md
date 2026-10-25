---
name: privacy-compliance
description: Practical map of privacy and security regulations and breach-notification duties (not legal advice).
tags: compliance, data, breach
---
Not legal advice: confirm current requirements for your jurisdictions and industry with counsel. Deadlines and thresholds change.

## Frameworks (what they push you to build)
- GDPR / UK GDPR: lawful basis, minimization, DPIAs, data-subject rights (access, erasure, portability), processor contracts, security of processing (Art. 32), breach notification to the regulator without undue delay and where feasible within 72 hours of awareness; notify individuals when high risk.
- CCPA/CPRA and US state privacy laws: notice, opt-out of sale/sharing, sensitive-data limits, deletion/access rights; private right of action for certain breaches; state breach-notification laws exist in all 50 states, with varying deadlines.
- HIPAA (US health): Security Rule safeguards, BAAs with vendors, breach notification (individuals without unreasonable delay, no later than 60 days).
- PCI DSS v4.x (payments): do not store sensitive authentication data; segment the cardholder environment; MFA, logging, scanning; reduce scope with hosted payment fields/tokenization.
- SOC 2 / ISO 27001: control frameworks customers ask for; map your controls (access, change management, logging, vendor risk, IR) and keep evidence.
- NIS2 (EU essential/important entities), DORA (EU financial): risk management, incident reporting on short timelines (early warning within 24h under NIS2), supply-chain oversight.
- SEC (US public companies): material cybersecurity incidents disclosed on Form 8-K within four business days of a materiality determination; annual risk-management disclosure.
- EU AI Act and NIST AI RMF: risk classification, transparency, data governance, and security expectations for AI systems.
- Children's data (COPPA, GDPR-K, age-appropriate design codes): extra consent and minimization duties.

## Engineering checklist
- Data inventory and records of processing; privacy by default; consent capture with audit trail; honor deletion across replicas, backups policies, and AI/vector stores.
- Vendor management: DPAs, security questionnaires, subprocessor list, breach-notice clauses, exit plans.
- Cross-border transfer mechanism where required.
- Breach readiness: decision tree for what counts as a notifiable breach, owner for each regulator, pre-approved notice templates, evidence preservation, a deadline calendar starting at awareness time.
- Keep audit evidence automated (access reviews, vulnerability SLAs, backup tests, training).
