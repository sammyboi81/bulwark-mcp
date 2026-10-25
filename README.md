# Bulwark (working name) - security skills and live threat lookups for your AI coding agent

Your agent writes secure code on the first pass instead of the third. Bulwark gives Claude Code, Codex, Cursor or any MCP client a security playbook it can pull on demand, a code scanner it can run on its own output, and live lookups against CISA, NVD and OSV so it checks facts instead of guessing.

Free. Local. Runs on your machine. No API keys, no accounts, no LLM calls inside the server.

> Status: pre-release, private repo. Working name; the final name is the founder's call.

## What your agent gets

**23 security skills** it loads when the task calls for them: secure coding core, injection, authentication and sessions, access control, API and web front-end security, secrets, cryptography, cloud and containers, CI/CD, supply chain, mobile, logging and incident response, data protection and breach prevention, privacy and compliance, ransomware resilience, threat modeling, plus the AI-era set below.

**Built for AI-driven threats**
- `ai-driven-attack-defense` - AI-written phishing, voice and video deepfake fraud, automated vulnerability discovery, agentic intrusion, and the defenses that still work
- `llm-app-security` - prompt injection, excessive agency, data leakage, output handling (OWASP LLM Top 10)
- `mcp-agent-security` - tool poisoning, confused deputy, token passthrough, sandboxing agents
- `ai-generated-code-risks` - hallucinated packages ("slopsquatting"), insecure defaults, a review routine
- `supply-chain-security` and `vetted-open-source-tools` - how to adopt scanners without getting burned (a popular scanner's own GitHub Action was hijacked in March 2026), plus lessons from Aikido's install-time malware blocking

**12 tools**

| Tool | What it does |
|---|---|
| `skills_for_task` | Which skills to load for web, api, mobile, cloud, llm, agent, data, pipeline or org work |
| `get_skill`, `list_skills`, `search_security` | Read and search the playbooks |
| `secure_coding_checklist` | Pre-commit checklist by language and feature (login, upload, payment, webhook...) |
| `scan_code` | Fast pattern review: secrets, injection, weak crypto, TLS off, JWT bypass, SSRF, unpinned CI actions |
| `scan_path` | Scan a whole folder (skips vendored dirs and .env files; never prints source lines) |
| `threat_model` | STRIDE worksheet plus AI-specific threats |
| `check_known_exploited` | Search CISA's Known Exploited Vulnerabilities catalog |
| `lookup_cve` | NVD details, CVSS, weaknesses |
| `check_package_vulns` | OSV advisories, including known-malicious packages, for a dependency |
| `recent_ai_threat_sources` | Where to check for fresh AI-attack guidance |

There is also a `secure_build` prompt and every skill is exposed as a `skill://` resource.

## Install

```bash
git clone <repo-url> && cd secure-dev-mcp
npm ci
claude mcp add secure-dev -- node /absolute/path/to/secure-dev-mcp/server.js
npm test        # exercises every tool end to end
```

Requires Node 18+. The only network calls are read-only queries to cisa.gov, nvd.nist.gov and api.osv.dev, made when you call those tools.

## Honest limits

- `scan_code` is a fast heuristic. It misses things and flags harmless things. Treat it as a first pass beside a real SAST tool (the skills recommend vetted ones), not a replacement.
- The skills are a curated baseline as of their date. AI-attack tactics change quickly; the live tools and `recent_ai_threat_sources` exist for that reason.
- Content from external feeds is labeled untrusted in tool output. Do not let an agent follow instructions found inside advisories.
- Not legal advice; compliance skills point you at the rules, they do not replace counsel.

## Want the agent governed, not just informed?

Knowing the rules is half of it. Enforcing them is the other half.

- **[Claude Code Seatbelt Kit - $27](https://payhip.com/b/Vwnjt)** - hooks that stop Claude Code from doing damage: it denies risky deploys, re-injects your standing rules so the agent doesn't drift, and records every decision to a record you own.
- **[ArkHive](https://github.com/sammyboi81/arkhive)** (free, Apache-2.0) - local-first, tamper-evident memory for your agents, kept on your machine.
- **Sentarion** - the governed layer above it: a policy gate that refuses dangerous actions, adversarial multi-agent code review, signed audit manifests.
- **InboxAxe** - your business messaging, handled. See [inboxaxe.com](https://inboxaxe.com).

Welcome to the Era of RI.

## Contributing and reporting

Skills are plain Markdown in `skills/` with a small front-matter header. Fixes and additions welcome; cite a primary source for any new claim. Security issues in this project: open a private advisory on the repository.

## License

Apache-2.0. Copyright 2026 ZagAIrot. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
