# Threat Model (v1)

## 1. Scope and assumptions

Scope includes desktop app, future mobile apps, CLI/TUI, browser extension, and sync backend.
Assume modern OS protections are available but not perfect.

Out of scope for v1:

- fully compromised unlocked endpoint
- hardware side-channel attacks
- nation-state grade physical lab attacks

## 2. Assets to protect

- master password
- derived keys (KEK, DEK)
- decrypted credential payloads
- sync auth tokens
- vault metadata that could reveal behavior patterns

## 3. Trust boundaries

- client device boundary (process memory, local DB, key material handling)
- network boundary (client to sync provider)
- backend storage boundary (ciphertext only)
- extension runtime boundary (browser sandbox and permissions)

## 4. Adversaries

- attacker with stolen database dump from backend
- passive/active network attacker
- attacker with temporary access to locked device files
- malicious or over-privileged local software (clipboard, keylogging risk)
- abusive authenticated user in a multi-vault future scenario

## 5. Security goals

1. Credential confidentiality: plaintext secrets never reach backend.
2. Integrity: tampering with ciphertext or metadata is detected.
3. Availability: authenticated sync remains available; transient network failures are retried with backoff.
4. Deterministic recovery: clients can converge after reconnect.

## 6. Threats and mitigations

### T1: Offline brute-force against stolen vault data

- Mitigations:
  - Argon2id with strong defaults and per-vault salt
  - tunable KDF profile and future rekey migration
  - no plaintext secret storage

### T2: Backend breach and bulk exfiltration

- Mitigations:
  - zero-knowledge model (ciphertext only)
  - per-entry AEAD encryption and integrity tags
  - minimal plaintext metadata

### T3: MITM or transport tampering

- Mitigations:
  - TLS-only transport
  - strict certificate validation via platform defaults
  - AEAD integrity checks after decrypt

### T4: Local data leakage from clipboard

- Mitigations:
  - clipboard auto-clear timer
  - explicit user action for copy
  - avoid automatic copy on reveal

### T5: Sync replay or duplicate submissions

- Mitigations:
  - idempotent `change_id`
  - monotonic cursor protocol
  - deterministic merge tie-breakers

### T6: Secrets leaked through logs/crash reports

- Mitigations:
  - structured logging with redaction policy
  - never log decrypted payloads or master password inputs
  - audit logging statements during review

## 7. Baseline security requirements

- lock timeout in GUI clients
- session keys held in memory only while unlocked
- secure random generation for salts/nonces/keys
- dependency and advisory scanning in CI
- release artifacts should be signed

## 8. Open risks and future hardening

- keylogging on compromised endpoint remains partially unmitigated
- memory scraping risk reduced but not eliminated
- sync availability now depends on Supabase uptime and valid auth sessions
- future hardening:
  - biometric unlock and secure enclave/keystore integration
  - memory zeroization where practical
  - optional passkey-based auth to sync provider
  - independent security review before public release
