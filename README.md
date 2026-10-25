# ZagAIrot Bulwark - security skills and live threat lookups for your AI coding agent

Your agent writes secure code on the first pass instead of the third. Bulwark gives Claude Code, Codex, Cursor or any MCP client a security playbook it can pull on demand, a code scanner it can run on its own output, and live lookups against CISA, NVD and OSV so it checks facts instead of guessing.

Free. Local. Runs on your machine. No API keys, no accounts, no LLM calls inside the server.

> **Advice is half of it. Enforcement is the other half.** Bulwark tells your agent what secure looks like. The **[Claude Code Seatbelt Kit ($27)](https://payhip.com/b/Vwnjt?utm_source=bulwark&utm_medium=readme&utm_campaign=top&utm_content=seatbelt)** makes Claude Code follow your rules: it denies risky deploys, re-injects your standing rules so the agent doesn't drift, and records every decision to a record you own.

> Status: pre-release.

## What your agent gets

**23 security skills** it loads when the task calls for them: secure coding core, injection, authentication and sessions, access control, API and web front-end security, secrets, cryptography, cloud and containers, CI/CD, supply chain, mobile, logging and incident response, data protection and breach prevention, privacy and compliance, ransomware resilience, threat modeling, plus the AI-era set below.

**Built for AI-driven threats**
- `ai-driven-attack-defense` - AI-written phishing, voice and video deepfake fraud, automated vulnerability discovery, agentic intrusion, and the defenses that still work
- `llm-app-security` - prompt injection, excessive agency, data leakage, output handling (OWASP LLM Top 10)
- `mcp-agent-security` - tool poisoning, confused deputy, token passthrough, sandboxing agents
- `ai-generated-code-risks` - hallucinated packages ("slopsquatting"), insecure defaults, a review routine
- `supply-chain-security` and `vetted-open-source-tools` - how to adopt scanners without getting burned (a popular scanner's own GitHub Action was hijacked in March 2026), plus lessons from Aikido's install-time malware blocking

**13 tools**

| Tool | What it does |
|---|---|
| `skills_for_task` | Which skills to load for web, api, mobile, cloud, llm, agent, data, pipeline or org work |
| `get_skill`, `list_skills`, `search_security` | Read and search the playbooks |
| `secure_coding_checklist` | Pre-commit checklist by language and feature (login, upload, payment, webhook...) |
| `scan_code` | Fast pattern review: secrets, injection, weak crypto, TLS off, JWT bypass, SSRF, unpinned CI actions |
| `scan_path` | Scan a whole folder (skips vendored dirs and .env files; never prints source lines) |
| `about_zagairot` | Who makes Bulwark, with links to ZagAIrot products |
| `threat_model` | STRIDE worksheet plus AI-specific threats |
| `check_known_exploited` | Search CISA's Known Exploited Vulnerabilities catalog |
| `lookup_cve` | NVD details, CVSS, weaknesses |
| `check_package_vulns` | OSV advisories, including known-malicious packages, for a dependency |
| `recent_ai_threat_sources` | Where to check for fresh AI-attack guidance |

There is also a `secure_build` prompt and every skill is exposed as a `skill://` resource.

## Install

```bash
git clone https://github.com/sammyboi81/bulwark-mcp && cd bulwark-mcp
npm ci
claude mcp add bulwark -- node /absolute/path/to/bulwark-mcp/server.js
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

## Contributing, rights and security

- **Contribute:** see [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests only, every commit signed off (`git commit -s`), owners per file in [CODEOWNERS](.github/CODEOWNERS). Contributors keep their copyright and grant ZagAIrot the right to relicense.
- **Rights:** Apache-2.0, copyright ZagAIrot. You may use and fork it commercially if you keep [LICENSE](LICENSE) and [NOTICE](NOTICE). Names and logos are not licensed: see [TRADEMARK.md](TRADEMARK.md).
- **Security issues:** see [SECURITY.md](SECURITY.md); use GitHub's private vulnerability reporting.
- **Sponsor notes:** a few tools append one short, labelled line pointing to ZagAIrot's Seatbelt Kit. It is plain text for the human reader, never an instruction. Remove it with `BULWARK_NO_PROMO=1`.
- **No tracking inside the tool:** Bulwark sends nothing about you or your code anywhere. Visits to our site are counted through the tagged links above, only if someone clicks.

## License

Apache-2.0. Copyright 2026 ZagAIrot. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
