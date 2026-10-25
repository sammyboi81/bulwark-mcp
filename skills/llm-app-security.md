---
name: llm-app-security
description: Building LLM-powered apps safely - prompt injection, excessive agency, data leakage, output handling (OWASP LLM Top 10).
tags: ai, llm, core
---
Prompt injection is unsolved: you cannot reliably stop a model from following hostile text. Design so a fully hijacked model can do little harm.

## Threat model
- Direct injection (user text) and INDIRECT injection (web pages, emails, PDFs, tickets, repos, tool output, retrieved chunks, image text, file metadata). Assume any content a model reads can carry instructions.
- Lethal trifecta: private data + untrusted content + an exfiltration channel (network, links, images, email send). Remove at least one leg.

## Controls
- Least privilege and least agency: the model gets only the tools, data, and credentials this task needs, scoped to the requesting user (never a shared god key). Read-only by default.
- Human approval for side effects: sending, paying, deleting, publishing, deploying, permission changes, anything irreversible. Show the exact action and parameters, not the model's summary.
- Separate trust zones: a model that reads untrusted content gets no powerful tools (quarantined/dual-LLM or planner/executor split); pass only structured, validated results across the boundary.
- Treat model output as untrusted input: encode for the sink (HTML, SQL, shell, URL); never `eval` it; parameterize any query it composes; validate tool-call arguments against schemas and allowlists.
- Exfiltration paths: block or sanitize markdown images/links to arbitrary domains, restrict egress to allowlisted hosts, strip query-string data from rendered URLs, disable auto-fetch of model-supplied URLs.
- Secrets never in prompts or system prompts (they will leak). System prompts are not a security boundary.
- RAG: authorize at retrieval time per user (filter by ACL before the model sees chunks); tag and sandbox sources; guard the ingestion pipeline against poisoning; log what was retrieved.
- Memory/long-term state: treat as a persistence channel for injection; scope per user, allow review/deletion.
- Limits: per-user rate, token, tool-call, and cost budgets (unbounded consumption / denial-of-wallet); max loop depth for agents; timeouts.
- Guardrail classifiers are defense in depth only. Measure with red-team suites (garak, PyRIT, promptfoo - pinned) and re-test on every model or prompt change.
- Model supply chain: pin model versions, verify checksums, avoid pickle-based weights (use safetensors), vet third-party plugins, tools, and MCP servers (mcp-agent-security).
- Privacy: minimize personal data sent to providers; contract for no-training/retention terms; redact; region controls.
- Monitor: log prompts/tool calls (redacted) for abuse detection; alert on anomalous tool use; keep a kill switch per tool and per agent.
- Evaluate against the OWASP Top 10 for LLM Applications (GenAI Security Project) and MITRE ATLAS; consult recent_ai_threat_sources.
