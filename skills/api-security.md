---
name: api-security
description: REST/GraphQL/webhook API hardening against the OWASP API Top 10.
tags: api, web
---
- Authenticate every endpoint (OAuth2/OIDC or scoped tokens); authorize per object and per function (BOLA/BFLA); see authz-access-control.
- Schema-validate requests and responses (OpenAPI/JSON Schema); reject unknown fields; return only needed fields (excessive data exposure) - use explicit response DTOs, never serialize raw DB rows.
- Rate limit and quota per identity, per IP, per endpoint; cap payload size, pagination (max page size), batch/GraphQL aliases, depth and complexity, and file sizes. Timeouts everywhere.
- GraphQL: disable introspection and suggestions in production if not public, limit depth/cost, persisted queries, per-field authz.
- Business logic abuse: protect high-value flows (signup, checkout, referrals, password reset, coupon, SMS/OTP sending) with step limits, idempotency keys, anomaly scoring; AI agents can automate abuse at scale.
- Inventory: keep an owned list of all endpoints and versions; retire old versions (shadow/zombie APIs); never expose debug/admin/actuator routes.
- Webhooks: verify HMAC over the raw body, constant-time compare, timestamp tolerance + replay cache, fast ack and async processing; outbound webhooks signed, SSRF-safe.
- SSRF-safe URL fetchers (see input-validation-injection). TLS only; HSTS; no secrets in query strings.
- Consume third-party APIs defensively: validate their responses, set timeouts, don't follow redirects blindly, least-privilege keys.
- Errors: consistent, generic, no stack traces; correct status codes; no user enumeration.
- Log API access with identity and object IDs; alert on enumeration patterns (sequential ID walking).
