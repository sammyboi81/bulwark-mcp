---
name: mcp-agent-security
description: Securing MCP servers, tool use, and autonomous coding agents - tool poisoning, confused deputy, token passthrough, sandboxing.
tags: ai, mcp, agents
---
## Using MCP servers and agent tools
- Every MCP server is code running with your privileges plus text that steers your agent. Vet it like a dependency: known maintainer, source reviewed, pinned version/commit, minimal permissions, no auto-update (rug-pull risk).
- Tool poisoning: tool names, descriptions, and results can contain hidden instructions. Review tool descriptions on install and on change; prefer servers whose definitions you can diff and hash-pin.
- Cross-server shadowing: one server's text can manipulate how the agent uses another's tools. Limit simultaneously enabled servers; separate high-privilege tools (email, shell, cloud) from servers that ingest web content.
- Approvals: keep per-call confirmation for write/exec/network tools; avoid blanket "always allow"; allowlist narrow command patterns instead.
- Credentials: scoped, short-lived, per-server; no long-lived admin tokens in MCP configs; store in the OS keychain; never let tool output echo secrets.
- Sandboxing: run agents and servers in containers/VMs or OS sandboxes with restricted filesystem, no ambient credentials, egress allowlist. Never run unvetted `npx`/`uvx` servers on a machine holding production keys.
- Audit: log tool calls with arguments; alert on reads of ~/.ssh, .env, cloud credential files, and on unexpected outbound connections.

## Building MCP servers
- Authenticate remote servers (OAuth 2.1 with PKCE); validate token audience; NEVER pass client tokens through to downstream APIs (confused deputy) - use server-owned scoped credentials or token exchange; per-user consent for each downstream.
- Authorize per tool and per resource using the end user's identity; deny by default.
- Validate all tool arguments with schemas; avoid shelling out; prevent path traversal and SSRF in tools that read files/URLs; cap sizes, time, rate.
- Treat anything returned from external sources as untrusted data and mark it so the client can; never return secrets.
- Local stdio servers: don't open network ports; if HTTP, bind to 127.0.0.1, check Origin/Host (DNS rebinding), require auth.
- Dependency hygiene: minimal dependencies, lockfile, signed releases, SBOM, provenance, secrets scanning in CI.
- Keep tool descriptions accurate and stable; version them; changelog security-relevant changes.

## Autonomous coding agents
- Run in a throwaway worktree/branch/container; review diffs before merge; require CI and human review; no direct prod access; budget and loop limits.
- Agents install packages: route through a malware-blocking, age-gated registry proxy (supply-chain-security) and verify every new dependency name exists (ai-generated-code-risks).
