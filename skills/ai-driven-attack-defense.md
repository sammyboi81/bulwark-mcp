---
name: ai-driven-attack-defense
description: Defending against attackers who use AI - phishing, voice/video deepfakes, automated vuln discovery, adaptive malware, agentic intrusion.
tags: ai, org, breach, defense
---
Attackers use AI to cut cost and time, not to invent new physics. Same breach paths, more volume, better polish, faster iteration. Verify current reports via recent_ai_threat_sources (this is a baseline, not a feed).

## What changes
- Phishing and social engineering: fluent, personalized, multilingual lures at scale; cloned phishing sites in minutes; AI-written pretexts using scraped LinkedIn/social data.
- Voice and video deepfakes: CEO/CFO fraud calls, help-desk impersonation for password/MFA resets, fake job candidates and fake vendors.
- Recon and vulnerability discovery: LLM-assisted code and config analysis, faster exploit development after a patch or advisory drops (shrinking patch window).
- Credential attacks: smarter stuffing, evasion of naive bot rules, AI-solved CAPTCHAs.
- Malware and tooling: easier variant generation, polymorphism, scripted intrusion chains; agentic tools that run recon-to-exfil steps with less operator skill.
- Attacks ON your AI: prompt injection, poisoned RAG/tools/MCP servers, model/package supply chain (llm-app-security, mcp-agent-security).

## Defenses that still work (prioritized)
1. Phishing-resistant MFA (passkeys/FIDO2) for everyone; mandatory for admins, finance, IT, source control, cloud consoles. Passwords+SMS/OTP can be proxied by phishing kits.
2. Out-of-band verification for high-risk requests: payments, bank-detail changes, credential/MFA resets, data exports, wire approvals. Call back on a known number; use a pre-agreed passphrase; two-person approval. Never trust voice, video, or caller ID alone.
3. Help-desk hardening: strong identity proofing, no resets on a single call, manager/ticket confirmation, notify the user, cooldown on new MFA enrollment.
4. Patch speed: track CISA KEV (check_known_exploited) and EPSS; internet-facing KEV fixes in days; virtual patch/WAF while patching; kill unnecessary exposure.
5. Reduce attack surface: inventory internet-facing assets, close unused ports, remove stale DNS/subdomains, SSO everywhere.
6. Least privilege, segmentation, and short-lived credentials so one compromised account can't reach everything (authz-access-control).
7. Email/domain: SPF, DKIM, DMARC at reject; display-name and lookalike-domain protection; link rewriting/sandboxing; mark external mail.
8. Detection and response speed: EDR on endpoints, centralized logging, UEBA-style anomaly alerts, automated containment, 24x7 coverage or MDR (logging-detection-response).
9. Resilience: offline immutable backups, tested restores, exercised IR plan (ransomware-resilience).
10. Training that matches reality: short, frequent, scenario-based (deepfake call, urgent-CEO request, MFA fatigue); report-phish button; reward reporting; no blame.
11. Public footprint hygiene: limit staff detail on org charts/social posts that fuel pretexting; watermark/verify official comms; brand and lookalike-domain monitoring.
12. Use AI defensively too: triage alerts, summarize logs, review code, but with human approval for response actions and the same least-privilege controls.

## Build-time guidance
- Assume your login, signup, reset, and support flows are attacked by automated, adaptive agents: rate limit by multiple signals, require step-up for risky actions, protect SMS/OTP sending from toll fraud.
- Don't use "knowledge-based" or voice-biometric verification as the sole control.
- Ship secure by default; assume your code will be read and fuzzed by AI within hours of release. Run SAST/fuzzing yourself first (vetted-open-source-tools).
