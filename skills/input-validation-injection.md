---
name: input-validation-injection
description: Stop SQLi, XSS, command/template injection, SSRF, path traversal, XXE, deserialization.
tags: core, web, injection
---
## Validate at the boundary
- Allowlist over denylist. Parse into typed objects (schema validation) and reject on failure; do not "clean" and continue.
- Bound everything: length, size, depth, count, numeric range, time. Reject unknown fields (stops mass assignment).
- Canonicalize before checking (Unicode normalization, URL decoding once, resolved paths).

## Per class
- SQL/NoSQL: parameterized queries or a query builder; ORMs are safe only when you avoid raw string fragments. Never concatenate identifiers; map them from an allowlist. NoSQL: reject objects where a string is expected ({"$ne": ...}).
- OS command: avoid shelling out. Use library APIs. If needed: argument arrays, no shell, absolute binary path, allowlisted values, no leading '-' from users (use `--`).
- XSS: encode for the exact context (HTML body, attribute, JS, URL, CSS). Use framework auto-escaping; treat raw-HTML sinks as hazardous. Sanitize rich text with DOMPurify. Add CSP (web-frontend-security).
- Template injection: never build templates from user text; sandboxed engines only.
- SSRF: allowlist destination hosts/schemes; resolve DNS and block private, loopback, link-local (169.254.169.254 cloud metadata), and re-check after redirects; disable redirects when possible; use IMDSv2 and egress filtering.
- Path traversal / uploads: join to a base dir, resolve, verify the result stays inside; generate server-side filenames; check magic bytes; store outside webroot; set size limits; never serve user uploads from your main origin.
- XXE: disable DTDs and external entities in every XML parser.
- Deserialization: never deserialize untrusted native formats (pickle, Java serialization, PHP unserialize, .NET BinaryFormatter, YAML load). Use JSON with schema, or signed+allowlisted types.
- Open redirect: only redirect to relative paths or allowlisted hosts.
- ReDoS: avoid nested quantifiers on user input; use linear-time regex engines (RE2) or cap length.
- Log injection: strip CR/LF from logged user values; use structured logging.
- Prompt injection is also injection: see llm-app-security.
