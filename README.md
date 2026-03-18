# etui

`etui` is an authenticated, zero-knowledge password manager project.

Current focus is a cross-platform desktop app (Tauri) backed by a Rust core, with architecture planned for future native iOS (SwiftUI), Android (Kotlin), CLI/TUI, and standalone browser extension clients.

## What exists today

- Rust workspace with core and adapters:
  - `crates/etui-core`
  - `crates/storage-sqlite`
  - `crates/sync-supabase` (authenticated RPC adapter)
- Desktop app scaffold and working local flow:
  - `apps/etui-desktop`
  - unlock/lock vault, encrypted entry create/list/get/delete
  - backend-enforced idle lock timeout (5 minutes)
  - explicit password copy action with clipboard auto-clear timer (30 seconds)
- Initial specs and threat model:
  - `docs/spec-vault-format.md`
  - `docs/spec-sync-contract.md`
  - `docs/threat-model.md`
  - `docs/supabase-schema.sql`
- Storage adapter integration coverage:
  - `crates/storage-sqlite` contract-style tests for CRUD, ordering, cursor persistence, and crypto metadata round-trip
- Sync adapter coverage:
  - `crates/sync-supabase` tests for authenticated push/pull request handling

## Security model

- Master password never leaves the device.
- KDF: Argon2id (per-vault salt + stored params).
- Encryption: XChaCha20-Poly1305 per encrypted payload.
- GUI session lock timeout and clipboard auto-clear behavior are enforced.
- Backend/sync is intended to store ciphertext + minimal metadata only.
- Supabase Auth is used for user identity and API authorization; auth is separate from encryption keys.

## Sync adapter configuration

`sync-supabase` expects these environment variables:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SUPABASE_ACCESS_TOKEN`

The adapter calls authenticated RPC endpoints:

- `/rest/v1/rpc/etui_push_changes`
- `/rest/v1/rpc/etui_pull_changes`

## Repository layout

```text
.
├── apps/
│   └── etui-desktop/
├── crates/
│   ├── etui-core/
│   ├── storage-sqlite/
│   └── sync-supabase/
├── docs/
├── AGENTS.md
├── PLAN.md
└── README.md
```

## Prerequisites

- Rust stable toolchain (`cargo`, `rustc`)
- Bun (`bun`)
- Linux Tauri system dependencies (GTK/WebKit stack)

On Linux, if Tauri checks fail, verify packages like `webkit2gtk`, `libsoup`, `gtk3`, `cairo`, `pango`, and related development libraries are installed.

## Getting started

1) Install frontend dependencies:

```bash
cd apps/etui-desktop
bun install
```

2) Validate the workspace:

```bash
cargo check --workspace
cargo test --workspace
```

3) Build desktop frontend:

```bash
cd apps/etui-desktop
bun run build
```

4) Run desktop app in dev mode:

```bash
cd apps/etui-desktop
bun run tauri dev
```

## Project plan

Active implementation milestones and progress are tracked in `PLAN.md`.

## Notes for contributors and AI agents

- Read `AGENTS.md` before making changes.
- Keep all business logic and security-sensitive behavior in `etui-core`.
- Update specs when format/sync behavior changes.
