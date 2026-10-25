---
name: web-frontend-security
description: Browser-side defenses - CSP, headers, cookies, CORS, CSRF, clickjacking, third-party scripts.
tags: web, frontend
---
- Content-Security-Policy: start strict - `default-src 'self'; script-src 'self' 'nonce-<random per response>' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`. Report-only first, then enforce. Avoid 'unsafe-inline'/'unsafe-eval'.
- Strict-Transport-Security: max-age>=31536000; includeSubDomains; (preload when ready).
- X-Content-Type-Options: nosniff. Referrer-Policy: strict-origin-when-cross-origin. Permissions-Policy: disable unused features. Cross-Origin-Opener-Policy: same-origin; Cross-Origin-Resource-Policy as appropriate.
- Clickjacking: CSP frame-ancestors (plus X-Frame-Options: DENY for legacy).
- CORS: explicit origin allowlist reflecting only trusted origins; never `*` with credentials; do not treat CORS as an auth mechanism.
- CSRF: SameSite cookies + CSRF tokens or double-submit for state changes; require custom header/JSON content type for APIs; verify Origin/Sec-Fetch-Site.
- Cookies: HttpOnly, Secure, SameSite, __Host- prefix, minimal scope. Do not store tokens in localStorage if XSS would hand them over; prefer HttpOnly cookies.
- XSS: framework escaping on; ban raw-HTML sinks via lint; DOMPurify for user HTML; Trusted Types where supported.
- Third-party scripts: self-host, Subresource Integrity on any CDN asset, minimize tags; each script is a supply-chain dependency (Magecart-style skimmers).
- Never put secrets or internal-only logic in the bundle; assume everything shipped is public. Source maps off in production or access-controlled.
- Don't leak: disable directory listing, verbose errors, framework version banners; set cache-control: no-store on sensitive responses.
- postMessage: check event.origin and shape. Validate redirect/next parameters.
