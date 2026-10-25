---
name: supply-chain-security
description: Stop malicious or vulnerable dependencies - lockfiles, malware feeds, age gates, SBOM, provenance, typosquatting.
tags: supply-chain, core, breach
---
Package registries are attacked at industrial scale (Aikido reports its Intel feed flags up to ~100,000 malicious packages a day across ecosystems; worms have hit npm; trusted tooling itself was compromised in the March 2026 Trivy incident).

## Before adding a dependency
- Do you need it? Fewer, smaller dependencies mean less attack surface.
- Verify identity: exact name (typosquats like `reqeusts`), org/scope, repo link matches the registry page, maintainer history, release cadence, download count, age. check_package_vulns includes malicious-package advisories (MAL-*).
- Check health: OpenSSF Scorecard, open security issues, archived status, bus factor, license.

## Install-time defenses
- Lockfile always committed; install with `npm ci`, `pip install --require-hashes`, `cargo --locked`, `go mod verify`.
- Minimum release age (cooldown): don't install versions younger than ~48h-7d; most malicious releases are caught within hours or days. Use pnpm `minimumReleaseAge`, Renovate `minimumReleaseAge`, or Aikido Safe Chain (default 48h).
- Malware blocking: wrap installs with Aikido Safe Chain (npm, yarn, pnpm, bun, pip, uv, poetry, pipx) or route through a registry proxy that blocks known-malicious packages.
- Disable lifecycle scripts for untrusted installs (`npm config set ignore-scripts true`, allowlist the few that need them). Many npm attacks run in postinstall.
- Private registries/proxies with allowlists; scoped internal names and registry pinning defeat dependency confusion.

## Continuous
- SBOM (CycloneDX/SPDX via Syft) per build; scan with OSV-Scanner/Grype; subscribe to advisories; track CISA KEV (check_known_exploited) and EPSS to prioritize.
- Patch SLAs: KEV/actively exploited - hours to days; critical - 7d; high - 30d.
- Automated update PRs (Dependabot/Renovate) with CI, pinning actions by SHA.
- Verify artifacts: Sigstore/Cosign signatures, npm provenance, PyPI trusted publishing attestations, SLSA level targets.
- Publish safely yourself: 2FA/passkeys, trusted publishing via OIDC (no long-lived tokens), least-privileged maintainers, release from CI only.
- Incident: if a malicious version was installed, assume secrets on that machine/CI are stolen - rotate everything reachable, rebuild from clean.
