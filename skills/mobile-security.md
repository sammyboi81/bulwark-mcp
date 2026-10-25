---
name: mobile-security
description: iOS/Android app hardening - storage, transport, auth, binary protection (OWASP MASVS).
tags: mobile
---
- Use OWASP MASVS/MASTG as the checklist. The device and app binary are attacker-controlled: never trust client logic, never embed secrets (API keys, signing keys); anything shipped can be extracted.
- Storage: Keychain (iOS) / Keystore + EncryptedSharedPreferences (Android) for tokens; no sensitive data in logs, backups, screenshots (FLAG_SECURE), clipboard, or world-readable files.
- Transport: TLS only; certificate pinning with backup pins for high-risk apps; no cleartext traffic; ATS/Network Security Config strict.
- Auth: OAuth2 authorization code + PKCE via system browser (ASWebAuthenticationSession/Custom Tabs), not embedded WebViews; biometrics unlock a Keystore-bound key, not a boolean flag; short-lived tokens, server-side revocation.
- Deep links / intents / URL schemes: validate and treat as untrusted input; verified App Links/Universal Links; no sensitive actions without confirmation.
- WebViews: disable JS bridges unless essential, restrict origins, no file access, no universal access from file URLs.
- Platform integrity: Play Integrity / App Attest signals are inputs to server risk decisions, not proof.
- Binary: R8/obfuscation raises cost only; root/jailbreak detection is bypassable; keep real controls server-side.
- Updates: supported OS minimums, dependency scanning (SDKs are supply chain), signed builds, protected signing keys.
- Privacy: minimal permissions, purpose strings, data minimization, consent (privacy-compliance).
