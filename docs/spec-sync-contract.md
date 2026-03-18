# Sync Contract Specification (v1)

## 1. Scope

This document defines the local-first sync contract used by all clients and sync providers.
It is backend-agnostic, with a concrete Supabase profile in the appendix.

## 2. Local-first model

Core invariants:

- Writes commit to local encrypted storage first.
- Sync runs asynchronously (push then pull).
- Server stores ciphertext and minimal metadata only.
- Merge behavior is deterministic.

Expected result: eventual convergence for clients with the same authorized vault.

## 3. Entities

- `vault_id`: UUID for vault namespace
- `device_id`: UUID for client instance
- `change_id`: UUID idempotency key per change
- `cursor`: opaque server-issued token for incremental pulls

## 4. Change record envelope

```json
{
  "change_id": "f5fca282-5c07-4a9e-a5e7-764c1ce00d4a",
  "vault_id": "4f45ad64-3b7d-4f0a-a4cb-f6f4cb7a3c00",
  "entry_id": "95b07f7e-c6d3-4e78-a42e-2c252ba66de8",
  "device_id": "cdf61558-d1f3-4029-8f1d-59b6adb3322a",
  "logical_ts": 1700000000123,
  "updated_at": "2026-03-18T11:06:00Z",
  "tombstone": false,
  "nonce_b64": "...",
  "ciphertext_b64": "..."
}
```

Notes:

- `logical_ts` is client-generated monotonic clock for deterministic merge tie-breaks.
- `change_id` ensures idempotent pushes.

## 5. API contract

### 5.1 Push

`push_changes(request) -> response`

Request:

```json
{
  "vault_id": "...",
  "device_id": "...",
  "base_cursor": "opaque-or-null",
  "changes": ["change-record", "..."]
}
```

Response:

```json
{
  "accepted_change_ids": ["..."],
  "rejected": [{ "change_id": "...", "reason": "..." }],
  "next_cursor": "opaque"
}
```

Requirements:

- Duplicate `change_id` is accepted as success (idempotent).
- Partial accept is allowed; caller retries rejected changes selectively.

### 5.2 Pull

`pull_changes(request) -> response`

Request:

```json
{
  "vault_id": "...",
  "since_cursor": "opaque-or-null",
  "limit": 500
}
```

Response:

```json
{
  "changes": ["change-record", "..."],
  "next_cursor": "opaque",
  "has_more": false
}
```

Requirements:

- Results are in stable server order.
- Pagination must not skip or duplicate changes for a valid cursor.

## 6. Merge policy (v1)

Merge key is `(vault_id, entry_id)`.

Resolution order:

1. Higher `logical_ts` wins.
2. If equal, higher `updated_at` wins.
3. If equal, lexical compare on `change_id` wins (final deterministic tie-breaker).

Tombstones:

- A tombstone is a delete marker and participates in merge like any other change.
- Re-creation of same `entry_id` is allowed only with a newer winning change.

## 7. Error model

Common error categories:

- `unauthorized` (invalid session/token)
- `forbidden` (vault access denied)
- `invalid_request` (schema/field validation)
- `stale_cursor` (cursor expired or invalid)
- `rate_limited` (retry with backoff)
- `transient` (network/backend temporary failure)

Retry guidance:

- retry on `transient` and `rate_limited` with exponential backoff + jitter
- on `stale_cursor`, reset to `since_cursor = null` and perform full re-pull

## 8. Security constraints

- Server never receives master password or plaintext credential data.
- Transport requires TLS.
- Logs must redact ciphertext payload fields by default.

## 9. Supabase profile (appendix)

Suggested tables:

- `vault_changes`
  - `vault_id` UUID
  - `change_id` UUID (unique)
  - `entry_id` UUID
  - `device_id` UUID
  - `logical_ts` BIGINT
  - `updated_at` TIMESTAMPTZ
  - `tombstone` BOOLEAN
  - `nonce_b64` TEXT
  - `ciphertext_b64` TEXT
  - `server_seq` BIGINT GENERATED ALWAYS AS IDENTITY

Indexes:

- unique `(vault_id, change_id)`
- `(vault_id, server_seq)` for pull pagination
- `(vault_id, entry_id)` for merge materialization queries

RLS expectations:

- authenticated user must be explicitly mapped to permitted `vault_id`
- deny all by default, grant least privilege
