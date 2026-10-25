---
name: authn-session-management
description: Login, passwords, passkeys, MFA, sessions, JWTs, resets - and defenses against AI-scaled credential attacks.
tags: auth, web, api, ai
---
## Credentials
- Offer passkeys (WebAuthn) first; they are phishing-resistant, which matters now that AI makes phishing pages and lures cheap and convincing.
- Passwords if you must: argon2id (tuned to ~100-500ms), or scrypt/bcrypt (cost >= 12). Unique salt per hash (libraries do this). Never SHA/MD5 alone. Optional server-side pepper in an HSM/KMS.
- Length over complexity: allow 64+ chars, allow paste and password managers, no forced rotation without evidence of compromise. Reject passwords found in breach corpora (k-anonymity range APIs) and common lists.
- MFA: prefer passkeys/FIDO2 > TOTP app > push with number matching > SMS (last resort). Admin and money-moving actions require phishing-resistant MFA. Rate-limit MFA attempts; beware MFA fatigue.
- Recovery is the weak link: reset tokens single-use, 15-60 min life, high entropy, stored hashed, same response for existing and unknown accounts; invalidate sessions and notify the user after reset; never allow support staff to bypass on voice/email alone (voice cloning and deepfakes defeat "knowledge" checks).

## Brute force and credential stuffing
- Rate limit per account, per IP, and per device/fingerprint; progressive delays; temporary lock with alerting; bot defenses on login/signup/reset; watch for distributed low-and-slow attempts across many accounts.
- Uniform error text and timing for bad user vs bad password.

## Sessions
- Server-generated random session IDs (>=128 bits CSPRNG), rotate on login and privilege change, absolute and idle timeouts, revoke on logout/password change.
- Cookies: HttpOnly, Secure, SameSite=Lax/Strict, __Host- prefix. CSRF tokens (or SameSite plus origin checks) for cookie-authenticated state changes.
- Re-authenticate for sensitive actions (step-up).

## Tokens / JWT
- Pin the algorithm server-side; reject "none"; verify signature, iss, aud, exp, nbf. Short access-token lifetime (5-15 min); refresh tokens rotated, bound, revocable, stored hashed. Do not put secrets/PII in JWT payloads. Prefer opaque tokens with server lookup when you need instant revocation.
- OAuth/OIDC: authorization code + PKCE, exact redirect URI match, state/nonce, no implicit flow, validate ID token.
- API keys: prefix + random, stored hashed, scoped, rotatable, shown once.
