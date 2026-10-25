---
name: vetted-open-source-tools
description: Time-tested open source security tools, how to adopt them without getting burned, and how Aikido approaches it.
tags: tools, supply-chain, ai
---
Snapshot checked 2026-10-24 via GitHub metadata: all listed projects active (pushed within days), none archived. Re-check before adopting; licenses matter for redistribution.

## Adoption rules (security tools are high-value targets)
1. Pin by commit SHA / image digest; never `latest` or a movable tag. (Trivy, March 2026: tags on trivy-action were rewritten to ship a credential stealer into pipelines.)
2. Verify release signatures/checksums (Cosign/Sigstore, GPG, SHA-256 from a second channel) before running a downloaded binary. Never `curl | sh`.
3. Give the tool least privilege: read-only token, no deploy secrets in the same job, restricted egress.
4. Prefer tools with open governance, multiple maintainers, signed immutable releases, provenance, and a responsive security policy. Check OpenSSF Scorecard.
5. Diversify: independent scanners disagree; one compromised tool shouldn't be your only control.
6. Upgrade deliberately with a cooldown, reading release notes.

## Recommended (license as reported by GitHub)
- Secrets: Gitleaks (MIT) fast pre-commit/CI; TruffleHog (AGPL-3.0) verifies whether found secrets are live; Betterleaks (Aikido-affiliated) is a newer entrant - evaluate.
- SAST: Opengrep (LGPL-2.1, community fork of Semgrep CE maintained by several AppSec firms including Aikido) and Semgrep CE (LGPL-2.1; its registry rules have separate licensing - read the terms).
- Dependencies/SCA: OSV-Scanner (Apache-2.0, Google) against the OSV database; Grype (Apache-2.0) vulnerability matching; Syft (Apache-2.0) SBOM generation.
- Containers/IaC: Trivy (Apache-2.0) is widely used but was compromised in March 2026 - if used, only pinned post-incident versions with verified signatures, never via mutable tags; run Grype/Syft/Checkov alongside.
- Supply chain posture: OpenSSF Scorecard (Apache-2.0) scores repos; Cosign/Sigstore (Apache-2.0) signing and verification; SLSA framework for provenance.
- Install-time malware blocking: Aikido Safe Chain (open source; npm + PyPI malware checks against Aikido Intel; 48h default package-age gate; wraps npm, npx, yarn, pnpm, bun, pip, uv, poetry, pipx, pdm). Verify its license file yourself - GitHub reports it as non-standard.
- Runtime app protection: Aikido Zen in-app firewall (Node, Python, PHP, Java, .NET, Ruby) blocks injection/SSRF/bots from inside the app; evaluate against your threat model.
- AI red-teaming: garak (NVIDIA), PyRIT (Microsoft), promptfoo - run in isolated environments with throwaway credentials.
- Free standards: OWASP ASVS, Cheat Sheet Series, MASVS/MASTG, API Top 10, LLM Top 10; MITRE ATT&CK/ATLAS; NIST SSDF and AI RMF; CISA KEV; FIRST EPSS.

## How Aikido approaches it (what to borrow)
- Intel feed: a continuously updated open database of malicious packages and undisclosed vulnerabilities; automated detection with human validation of high-severity cases.
- Block at the point of install (proxy/wrapper), not after the fact, and catch transitive dependencies too.
- Cooldown: treat very new package versions as unverified; let urgent security fixes through after confirming them clean.
- Tokenless and free at the developer edge to drive adoption; mirrorable feed (`malwareListBaseUrl`) for enterprises; shims for CI.
- Contribute to open engines (Opengrep, Zen, Safe Chain) while selling the platform that unifies findings. Lesson: ship the free enforcement piece, monetize the management layer.
- Caveat: speed and coverage figures come from Aikido's own material, not independent testing.

## Malware-in-the-tool checklist
Before trusting any third-party repo: recent commits by known authors? unexpected obfuscated code or install scripts? binary blobs? network calls on install? star-farming? typosquatted org name? Compare against official docs links; run check_package_vulns for MAL-* advisories.
