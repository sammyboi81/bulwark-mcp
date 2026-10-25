---
name: authz-access-control
description: Authorization design - object-level checks, IDOR/BOLA, RBAC/ABAC, tenant isolation, agent permissions.
tags: auth, web, api, core
---
Broken access control is the top web risk. Authentication says who; authorization says what, per object, every time.

- Enforce on the server, in one central policy layer, on every request and every object (not just "is logged in").
- IDOR/BOLA: when loading /orders/123, query by (id AND owner/tenant), or load and then check ownership. Unguessable IDs are not authorization.
- Function-level: admin routes, internal endpoints, and GraphQL fields/mutations each need explicit checks. Deny by default; new routes start locked.
- Mass assignment: bind only allowlisted fields; never bind straight from request into a model (role, isAdmin, tenantId, price).
- Multi-tenancy: tenant ID from the session, never from the request; database-level isolation (row-level security) where possible; include tenant in every cache key.
- RBAC for coarse roles, ABAC/ReBAC (e.g., relationship checks) for fine-grained; keep policy declarative and testable. Separate duties for destructive/financial actions; two-person approval for the most dangerous.
- Privilege changes are audited and require step-up authentication.
- Service-to-service: mTLS or signed workload identity, scoped tokens per service, no shared god credentials. Cloud: least-privilege IAM, no wildcard actions/resources.
- Tests: for every endpoint write a negative test with a second user/tenant and with no auth. Automate in CI.
- Agents and tools act with the user's permissions at most, usually less; see mcp-agent-security.
