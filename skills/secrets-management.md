---
name: secrets-management
description: Keep credentials out of code and logs; detect, rotate, and shrink the blast radius.
tags: core, secrets, breach
---
Stolen credentials remain a leading cause of breaches; AI-assisted attackers also mine public repos, CI logs and AI-tool configs for keys within minutes of exposure.

- Never commit secrets, including to private repos, test fixtures, notebooks, Docker layers, or `.env` files. Commit `.env.example` only.
- Store in a secret manager (cloud KMS/Secrets Manager, Vault, Doppler, 1Password CLI); inject at runtime. Prefer short-lived, workload-identity credentials (OIDC federation, IAM roles) over long-lived keys.
- Scope each secret to one purpose and least privilege; separate per environment; rotate on a schedule and immediately on suspicion. Make rotation a tested runbook, not a heroic act.
- Detect: pre-commit hook + CI scan (gitleaks, TruffleHog; vetted-open-source-tools) + GitHub secret scanning/push protection. Scan history, not just HEAD.
- If a secret leaks: revoke/rotate FIRST (deleting the commit does not help; assume it was scraped), then investigate use in provider logs, then clean history.
- Checking whether a secret is set must never print it: test existence/length/hash prefix only.
- Logs and errors: redact tokens, Authorization headers, cookies, connection strings, and PII; never log request bodies blindly.
- Keep secrets out of URLs, command-line args (visible in process lists), crash dumps, and client bundles.
- Developer machines and agents: AI coding tools and MCP configs often hold tokens; keep them in a keychain, scope them narrowly, and don't paste secrets into prompts.
- Use canary tokens/honeytokens to get early warning of theft.
