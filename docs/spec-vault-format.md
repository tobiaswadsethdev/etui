# Vault Format Specification (v1)

## 1. Scope

This document defines the on-disk and sync-safe encrypted vault format for all clients
(desktop, mobile, CLI/TUI, and browser extension).

Goals:

- stable cross-client format
- zero-knowledge server compatibility
- explicit versioning and migration path

## 2. Versioning

- Top-level field: `schema_version` (integer)
- Initial version in this spec: `1`
- Any breaking format change requires a new schema version and a migration in `vault-core`

Rules:

- Clients may read older versions only if a known migration path exists.
- Clients must not write unknown future versions.
- Migration is deterministic and side-effect free until commit.

## 3. Cryptography profile (v1)

### 3.1 KDF

- Algorithm: `Argon2id`
- Inputs: master password + per-vault random `salt`
- Output: key-encryption key (KEK)
- Parameters (stored with vault metadata):
  - `memory_kib`
  - `iterations`
  - `parallelism`
  - `salt_b64`

Default profile target (subject to benchmark tuning per platform):

- `memory_kib`: 65536
- `iterations`: 3
- `parallelism`: 1
- `salt_len`: 16 bytes

### 3.2 Payload encryption

- Algorithm: `XChaCha20-Poly1305`
- Nonce: 24 random bytes per encrypted payload
- AAD: optional, reserved for future context binding
- Ciphertext includes AEAD auth tag

### 3.3 Key model

- Master password derives KEK via Argon2id.
- Vault data encryption key (DEK) is random and used for entry encryption.
- DEK is stored encrypted with KEK (`wrapped_dek`).

## 4. Canonical top-level envelope

All fields are UTF-8 JSON keys, snake_case.

```json
{
  "schema_version": 1,
  "vault_id": "4f45ad64-3b7d-4f0a-a4cb-f6f4cb7a3c00",
  "created_at": "2026-03-18T11:00:00Z",
  "updated_at": "2026-03-18T11:05:00Z",
  "kdf": {
    "algorithm": "argon2id",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1,
    "salt_b64": "..."
  },
  "cipher": {
    "algorithm": "xchacha20poly1305",
    "wrapped_dek_b64": "...",
    "wrapped_dek_nonce_b64": "..."
  }
}
```

## 5. Entry record model

The storage and sync layer keep records as encrypted blobs plus minimal non-sensitive metadata.

Required plaintext metadata per record:

- `entry_id` (UUID)
- `vault_id` (UUID)
- `updated_at` (RFC3339 UTC)
- `tombstone` (boolean)

Encrypted payload (inside ciphertext):

- `title`
- `site`
- `username`
- `password`
- `notes`
- `tags` (array)
- `custom_fields` (array of key/value pairs)

Record envelope example:

```json
{
  "entry_id": "95b07f7e-c6d3-4e78-a42e-2c252ba66de8",
  "vault_id": "4f45ad64-3b7d-4f0a-a4cb-f6f4cb7a3c00",
  "updated_at": "2026-03-18T11:06:00Z",
  "tombstone": false,
  "nonce_b64": "...",
  "ciphertext_b64": "..."
}
```

## 6. Serialization rules

- JSON is the canonical interchange format for now.
- Timestamps use RFC3339 UTC with `Z` suffix.
- Binary data uses standard base64.
- UUIDs are lowercase canonical string representation.

## 7. Migration policy

- Migrations live in `vault-core` and are covered by golden tests.
- Migration function signature conceptually: `vN -> vN+1`.
- No in-place destructive migration without backup capability.
- Exported backups include explicit `schema_version`.

## 8. Compatibility contract

- All clients must pass shared format compatibility tests.
- Unknown optional fields must be ignored.
- Unknown required fields fail closed with explicit error.
