---
name: cryptography-essentials
description: Which primitives to use, how, and what to avoid; key management and post-quantum readiness.
tags: crypto, core, data
---
Don't invent crypto. Use high-level, audited libraries (libsodium, Tink, WebCrypto, language-native crypto modules).

- In transit: TLS 1.3 (1.2 minimum), strong ciphers, HSTS, valid certs with automated renewal; mTLS between internal services where practical.
- At rest: AES-256-GCM or ChaCha20-Poly1305 (AEAD). Never ECB; never reuse a nonce/IV with the same key; use random 96-bit nonces only within safe limits or a misuse-resistant mode (AES-GCM-SIV, XChaCha20-Poly1305).
- Hashing: SHA-256/SHA-512/SHA-3/BLAKE2/3 for integrity. MD5/SHA-1 are broken for security use. Passwords: argon2id/scrypt/bcrypt only (authn-session-management).
- MACs/signatures: HMAC-SHA-256; Ed25519 or ECDSA P-256; RSA >= 2048 (3072 preferred) with PSS/OAEP. Compare MACs in constant time.
- Key exchange: X25519/ECDH P-256. Key derivation: HKDF; for passwords, a password KDF.
- Randomness: OS CSPRNG only (secrets, crypto.randomBytes, SecureRandom, crypto/rand). Never Math.random/rand for tokens or keys.
- Key management: keys in KMS/HSM; envelope encryption; separate keys per purpose/tenant/environment; rotation and versioning; least-privilege decrypt permission; never log or hardcode keys; backups of keys protected separately.
- Certificates and tokens: automate rotation; monitor expiry; verify full chain and hostname; don't disable verification.
- Post-quantum: inventory where RSA/ECC protect long-lived secrets ("harvest now, decrypt later"); adopt hybrid ML-KEM (FIPS 203) key exchange as libraries and TLS stacks support it; plan for ML-DSA (FIPS 204) signatures. Keep crypto agile (algorithm identifiers, not hardcoded).
- Tokenize/encrypt the most sensitive fields (payment, health, government IDs) at the application layer in addition to disk encryption.
