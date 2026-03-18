# Password Manager Implementation Plan

## 1) Product Direction

Build a local-first, zero-knowledge password manager with native UIs per client:

- Desktop: Tauri app (initial client)
- iOS: SwiftUI app (future)
- Android: Kotlin app (future)
- CLI: Rust binary (future)
- TUI: Rust terminal UI (future)
- Browser extension: standalone WebExtension (future)

The shared source of truth is a Rust core and stable cross-client specs.

## 2) Core Technical Decisions

### 2.1 Architecture

Use ports/adapters (hexagonal) architecture:

- `vault-core` defines domain models, crypto workflows, sync logic, and interfaces
- Storage and sync are plugin adapters behind interfaces
- UI clients never call Supabase directly; they use core-defined boundaries

### 2.2 Sync topology

Local-first on every client:

- Reads/writes happen against local encrypted store immediately
- Background sync pushes/pulls encrypted changes
- Backend stores ciphertext + minimal metadata only
- Deterministic conflict resolution in core

### 2.3 Security model

- Master password never leaves device
- KDF: Argon2id with per-vault random salt and versioned parameters
- Encryption: XChaCha20-Poly1305 (AEAD)
- Per-entry nonce/IV, secure random generation
- Lock timeout and clipboard auto-clear in all GUI clients
- Versioned vault format + migration engine

## 3) Repository Layout (Target)

```text
crates/
  vault-core/
  vault-cli/                # phase 3+
  vault-tui/                # phase 3+
  storage-sqlite/
  sync-supabase/
apps/
  desktop-tauri/
  ios-swiftui/              # phase 4+
  android-kotlin/           # phase 4+
  browser-extension/        # phase 4+
docs/
  spec-vault-format.md
  spec-sync-contract.md
  threat-model.md
  adr/                      # architecture decision records
```

## 4) Core Interfaces (Initial)

Define in `crates/vault-core`:

- `VaultRepository`
  - create/open vault
  - list/get/create/update/delete entries
  - record and fetch sync cursor/state
- `KeyMaterialStore`
  - persist non-secret metadata (salt, kdf params, vault id)
  - store no plaintext secrets
- `SyncProvider`
  - push encrypted change set
  - pull encrypted change set since cursor
- `Clock` and `Rng`
  - injectable for deterministic tests

Keep these interfaces stable and adapter-friendly.

## 5) Data and Crypto Spec (Must lock early)

### 5.1 Vault format (v1)

- `schema_version`
- `vault_id`
- `kdf`: algorithm + params + salt
- `entries`: encrypted blobs with nonce and auth tag
- `metadata`: minimal non-sensitive fields only (e.g., timestamps, tombstone)

### 5.2 Entry model

Encrypted payload includes:

- title/site
- username
- password
- notes
- custom fields
- tags

Non-sensitive index fields should be minimal and optional.

### 5.3 Sync contract

- append-only encrypted change log or versioned records
- server cursor for incremental pulls
- idempotent push semantics
- deterministic merge policy (default: per-field latest-write by logical timestamp)

## 6) Milestones

### Phase 0 - Foundation (Now)

1. Create repo structure and workspace
2. Write specs:
   - `docs/spec-vault-format.md`
   - `docs/spec-sync-contract.md`
   - `docs/threat-model.md`
3. Add ADRs for key decisions:
   - local-first sync
   - zero-knowledge backend
   - Rust core + native UI clients

### Phase 1 - Core + Local Desktop MVP

1. Implement `vault-core` domain and crypto primitives
2. Implement `storage-sqlite` adapter
3. Build desktop Tauri app with minimal UI:
   - unlock/create vault
   - list/search entries
   - create/edit/delete entry
   - copy secret + clipboard clear timer
4. Implement lock timeout and session state
5. Add unit and integration tests

Exit criteria:

- Fully functional offline desktop vault
- No plaintext secret persistence

### Phase 2 - Supabase Sync Adapter

1. Implement `sync-supabase` adapter behind `SyncProvider`
2. Add background sync loop in desktop app
3. Handle conflicts and retries
4. Add observability/logging (without leaking secrets)

Exit criteria:

- Two desktop clients can converge via sync
- Offline edits reconcile correctly

### Phase 3 - Secondary Rust Clients

1. Implement `vault-cli`
2. Implement `vault-tui`
3. Reuse core + adapters; no business logic in clients

Exit criteria:

- CLI/TUI parity for core vault operations

### Phase 4 - Mobile + Extension

1. Generate UniFFI bindings for Swift/Kotlin from Rust core API surface
2. Build iOS SwiftUI shell and Android Kotlin shell
3. Build standalone browser extension (local encrypted cache + sync)
4. Add compatibility tests against shared specs and vectors

Exit criteria:

- iOS/Android/extension can read and sync same vault format

## 7) Testing Strategy

### 7.1 Core

- Crypto test vectors (golden files)
- KDF parameter migration tests
- Deterministic merge/conflict tests
- Property tests for serialization/decryption round-trips

### 7.2 Adapter contract tests

All `VaultRepository` and `SyncProvider` implementations must pass a common test suite.

### 7.3 End-to-end

- Desktop unlock/create/import/export flows
- Multi-device sync convergence scenarios
- Offline/online transition scenarios

## 8) Operational and Security Checklist

- Never log plaintext credentials
- Memory hygiene for sensitive buffers where practical
- Secure defaults for Argon2id params with device-tunable profile
- Database encryption-at-rest is additive; app-layer encryption is mandatory
- Signed release artifacts and reproducible build notes

## 9) Deferred Scope (Explicitly later)

- Autofill integrations
- Biometric unlock and secure enclave integration
- Shared vaults/organization support
- Self-hosted sync server (post-Supabase)
- Advanced breach monitoring features

## 10) Immediate Next Actions

1. Scaffold Rust workspace (`vault-core`, `storage-sqlite`, `sync-supabase`, `apps/desktop-tauri`)
2. Author the 3 spec docs in `docs/`
3. Implement minimal `vault-core` API and first unit tests
4. Build desktop unlock + CRUD flow against local SQLite only

## 11) Progress Update (2026-03-18)

Completed so far:

- Step 1 done: Rust workspace scaffolded with initial crates and Tauri desktop shell.
- Step 1 done: Bun-based frontend scaffold created and verified with `bun run build`.
- Step 1 done: Workspace compiles with `cargo check --workspace` after adding Tauri icon/config fixes.
- Step 2 done: Added `docs/spec-vault-format.md`.
- Step 2 done: Added `docs/spec-sync-contract.md`.
- Step 2 done: Added `docs/threat-model.md`.
- Step 3 done: Added minimal `vault-core` application API in `crates/vault-core/src/service.rs`.
- Step 3 done: Added first `vault-core` unit tests for CRUD flow, input validation, and sync cursor persistence.
- Validation: `cargo test -p vault-core` passes and `cargo check --workspace` passes.
- Step 4 done: Implemented a functional `storage-sqlite` adapter with schema initialization, vault bootstrap, entry CRUD, and sync cursor persistence.
- Step 4 done: Connected desktop Tauri backend commands to `vault-core` + SQLite repository.
- Step 4 done: Replaced placeholder frontend with unlock/list/create/get/delete flow wired through Tauri invoke commands.
- Validation: `cargo check --workspace`, `cargo test -p vault-core`, and `bun run build` pass.
- Step 4 enhancement done: Added real cryptography flow (Argon2id + XChaCha20-Poly1305) for entry payload encryption/decryption.
- Step 4 enhancement done: Added persistent vault crypto metadata storage in SQLite with password verifier.
- Step 4 enhancement done: Updated desktop UI from base64 payload input to real credential fields (title, username, password, notes).
- Validation: `cargo check --workspace`, `cargo test -p vault-core` (5 tests), and `bun run build` pass.
- Step 4 hardening done: Added `storage-sqlite` integration/contract coverage for entry CRUD semantics, entry ordering, sync cursor round-trip, default vault stability, and crypto metadata persistence.
- Step 4 hardening done: Implemented desktop lock timeout enforcement in Tauri backend session handling (5-minute idle timeout).
- Step 4 hardening done: Implemented explicit password copy action in desktop UI with 30-second clipboard auto-clear timer.
- Validation: `cargo check --workspace`, `cargo test --workspace`, and `bun run build` pass.

Current status:

- Foundation phase is in progress.
- Next active task: start Phase 2 by implementing `sync-supabase` behind `SyncProvider` and define first sync adapter contract tests.
