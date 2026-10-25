---
name: ci-cd-pipeline-security
description: Harden build pipelines - pinned actions, least-privilege tokens, OIDC, provenance, no secret exfiltration.
tags: cicd, supply-chain, core
---
CI is a prime target: it holds secrets and ships to production. March 2026: attackers force-pushed malicious code onto 75 of 76 version tags of the Trivy GitHub Action, stealing CI secrets while the scan still looked normal. Mutable tags are not integrity.

- Pin every third-party action and image to a full commit SHA or digest (not @v1, not :latest). Let Dependabot/Renovate propose bumps as reviewed PRs. Add a `# vX.Y.Z` comment for humans.
- Least privilege: `permissions: contents: read` at workflow top, grant per-job; separate deploy jobs; protected environments with required reviewers for production.
- Secrets: prefer OIDC federation to cloud over stored keys; scope secrets to the environment/job that needs them; never expose to PRs from forks; avoid `pull_request_target` with untrusted checkout; mask outputs.
- Script injection: never interpolate `${{ github.event.* }}` (titles, branch names, bodies) into `run:`; pass via env and quote.
- Protect branches: required reviews, status checks, no force-push, CODEOWNERS on workflows and infra.
- Runners: ephemeral, isolated, no long-lived credentials on self-hosted runners, egress-restricted where possible.
- Artifacts: build reproducibly where feasible; generate SBOM and SLSA provenance; sign (Sigstore Cosign); verify signature/provenance before deploy.
- Dependencies: lockfiles, `npm ci`, hash-pinned pip (`--require-hashes`), minimum package age, malware-checking install wrapper (supply-chain-security, vetted-open-source-tools).
- Security tools in CI run from pinned, verified versions and with minimal permissions; a compromised scanner has your secrets.
- Monitor: alert on workflow file changes, new secrets use, unusual egress, new tokens; run OpenSSF Scorecard on your repos.
- Treat AI coding agents in CI like any untrusted contributor: no write tokens, review all output.
