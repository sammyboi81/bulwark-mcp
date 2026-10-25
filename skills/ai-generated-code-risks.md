---
name: ai-generated-code-risks
description: Pitfalls specific to AI-written code - hallucinated packages, insecure defaults, over-trust - and a review routine.
tags: ai, supply-chain, review
---
AI-written code is plausible, not verified. Research and incident reports show a meaningful share of generated code carries vulnerabilities, and models invent package names.

- Slopsquatting: models hallucinate dependency names; attackers register them with malware. Before adding ANY package: confirm it exists on the registry, check age, downloads, maintainer, repo link, and run check_package_vulns. Treat brand-new or unknown packages as hostile; prefer the standard library or well-known libraries.
- Common flaws to hunt: missing authorization on new routes, SQL built with f-strings, disabled TLS verification "to make it work", wildcard CORS, hardcoded example secrets, weak hashing for passwords, `eval`/`exec`, unsafe deserialization, outdated API usage, debug flags left on, overly broad IAM/CORS/CSP "for now", copied insecure snippets.
- Passing tests prove little: add negative tests (unauthorized, malformed, hostile input, other tenant).
- Run scan_code, SAST (Opengrep), a secrets scan (gitleaks), and a dependency scan on every AI-generated change, automatically in CI.
- Review as if from an unknown contributor: read every line that touches auth, crypto, input parsing, file/network/process access, and infra config. Ask the model to threat-model its own output, then verify independently.
- Prompt for security: state the stack, trust boundaries, and requirements ("parameterized queries, per-object authz, no new dependencies without justification"). Provide secure examples. Don't paste secrets or customer data into prompts.
- Agent hygiene: scoped credentials, sandbox, no auto-merge, human approval for installs and deploys (mcp-agent-security).
- Rule files (CLAUDE.md, .cursorrules, AGENTS.md) and repo content are instruction channels: review them in PRs; hidden Unicode or HTML comments can smuggle instructions to coding agents.
- Keep humans accountable: a named owner approves each merge.
