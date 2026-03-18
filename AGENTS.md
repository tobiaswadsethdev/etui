# AGENTS.md

## Project Overview

This repository is a cross-platform password manager with:

- Rust core as source of truth (`crates/vault-core`)
- Adapter crates for storage and sync (`crates/storage-sqlite`, `crates/sync-supabase`)
- Desktop client in Tauri (`apps/desktop-tauri`)
- Future native clients: iOS (SwiftUI), Android (Kotlin), CLI/TUI, standalone browser extension

Architecture is local-first and zero-knowledge.

Read first:

- `PLAN.md`
- `docs/spec-vault-format.md`
- `docs/spec-sync-contract.md`
- `docs/threat-model.md`

## Core Principles

1. **Do not break zero-knowledge model**
   - Never send/store plaintext credentials outside client memory.
   - Backend stores ciphertext + minimal metadata only.

2. **Keep logic in Rust core**
   - Business rules, crypto, migrations, and merge behavior belong in `vault-core`.
   - UI and adapters should stay thin.

3. **Respect ports/adapters boundaries**
   - UI must not call Supabase directly.
   - Use core interfaces (`VaultRepository`, `SyncProvider`, etc.).

4. **Local-first always**
   - Writes land locally first.
   - Sync is async and idempotent.
   - Deterministic merge behavior required.

## Repository Conventions

- JS package manager: **bun** (for `apps/desktop-tauri`)
- Rust toolchain: stable (see `rust-toolchain.toml`)
- Avoid introducing new frameworks unless requested.
- Keep edits minimal and focused; preserve existing structure.

## Security Requirements (Non-Negotiable)

- Master password never leaves device.
- KDF: Argon2id with per-vault salt and stored params.
- Encryption: XChaCha20-Poly1305 with unique nonce per encrypted payload.
- Never log secrets, keys, plaintext entries, or raw password fields.
- Preserve lock timeout and clipboard-clear behavior in UI work.
- Fail closed on unknown required schema fields.

## Implementation Guidance

When implementing features:

1. Update or validate specs first if format/sync/security behavior changes.
2. Implement in `vault-core` before client code.
3. Add/adjust adapter behavior only through core interfaces.
4. Keep desktop-specific behavior under `apps/desktop-tauri`.
5. Add tests with every behavior change.

## Testing and Validation

Preferred validation sequence:

1. `cargo check --workspace`
2. `cargo test --workspace`
3. `bun install` (if needed)
4. `bun run build` in `apps/desktop-tauri`

If Linux Tauri build fails, verify system deps (webkit2gtk, libsoup, gtk/cairo/pango stack).

## Specs and Compatibility

Any change to encrypted format or sync behavior must include:

- Spec update in `docs/spec-vault-format.md` and/or `docs/spec-sync-contract.md`
- Migration note (if schema version impact)
- Compatibility test updates

Do not silently change wire formats or encrypted payload structure.

## Out of Scope Unless Requested

- Autofill integrations
- Shared org vaults
- Biometric/secure enclave features
- Self-hosted sync backend

## Agent Workflow Expectations

- Read `PLAN.md` and docs before coding.
- Propose small, reviewable increments.
- Prefer clarity over cleverness.
- Surface tradeoffs explicitly for security-sensitive decisions.
- Do not commit or push unless explicitly requested.

## Documentation Maintenance (Required)

- Keep `PLAN.md` current whenever implementation progress changes.
- Keep `README.md` current whenever setup steps, architecture status, or user-visible capabilities change.
- For feature work, update both docs in the same change set when relevant:
  - `PLAN.md`: progress/status and next active task
  - `README.md`: what exists now and how to run/validate
- If a change affects security, format, or sync behavior, also update the relevant spec docs under `docs/`.
