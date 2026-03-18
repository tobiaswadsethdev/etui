#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Serialize;
use storage_sqlite::SqliteVaultRepository;
use tauri::State;
use uuid::Uuid;
use vault_core::crypto::{initialize_crypto_metadata, unlock_with_password, UnlockedVault};
use vault_core::model::EntryPayload;
use vault_core::service::VaultService;

struct AppState {
    repository: Arc<SqliteVaultRepository>,
    service: VaultService<Arc<SqliteVaultRepository>>,
    vault_id: Uuid,
    session: Mutex<Option<UnlockedVault>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionInfo {
    vault_id: String,
    entry_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntrySummary {
    id: String,
    title: String,
    username: String,
    updated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryDetail {
    id: String,
    title: String,
    username: String,
    password: String,
    notes: String,
    updated_at: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewEntryInput {
    title: String,
    username: String,
    password: String,
    notes: String,
}

#[tauri::command]
async fn unlock_vault(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<SessionInfo, String> {
    if master_password.trim().is_empty() {
        return Err("master password is required".to_owned());
    }

    let metadata = state
        .repository
        .load_crypto_metadata(state.vault_id)
        .map_err(|error| error.to_string())?;

    let unlocked = match metadata {
        Some(metadata) => unlock_with_password(master_password.trim(), &metadata)
            .map_err(|error| error.to_string())?,
        None => {
            let (metadata, unlocked) = initialize_crypto_metadata(master_password.trim())
                .map_err(|error| error.to_string())?;
            state
                .repository
                .save_crypto_metadata(state.vault_id, &metadata)
                .map_err(|error| error.to_string())?;
            unlocked
        }
    };

    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "failed to acquire session lock".to_owned())?;
        *session = Some(unlocked);
    }

    let entries = state
        .service
        .list_entries(state.vault_id)
        .await
        .map_err(|error| error.to_string())?;

    Ok(SessionInfo {
        vault_id: state.vault_id.to_string(),
        entry_count: entries.len(),
    })
}

#[tauri::command]
async fn lock_vault(state: State<'_, AppState>) -> Result<(), String> {
    let mut session = state
        .session
        .lock()
        .map_err(|_| "failed to acquire session lock".to_owned())?;
    *session = None;
    Ok(())
}

#[tauri::command]
async fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>, String> {
    let unlocked = require_unlocked(&state)?;
    let entries = state
        .service
        .list_entries(state.vault_id)
        .await
        .map_err(|error| error.to_string())?;

    let mut summaries = Vec::with_capacity(entries.len());
    for entry in entries {
        let payload = unlocked
            .decrypt_entry_payload(&entry.ciphertext, entry.nonce)
            .map_err(|_| "failed to decrypt entry; wrong password or corrupted data".to_owned())?;

        summaries.push(EntrySummary {
            id: entry.id.to_string(),
            title: payload.title,
            username: payload.username,
            updated_at: entry.updated_at.to_rfc3339(),
        });
    }

    Ok(summaries)
}

#[tauri::command]
async fn create_entry(
    state: State<'_, AppState>,
    input: NewEntryInput,
) -> Result<EntryDetail, String> {
    let unlocked = require_unlocked(&state)?;

    if input.title.trim().is_empty() {
        return Err("title is required".to_owned());
    }

    if input.password.trim().is_empty() {
        return Err("password is required".to_owned());
    }

    let payload = EntryPayload {
        title: input.title.trim().to_owned(),
        username: input.username.trim().to_owned(),
        password: input.password,
        notes: input.notes.trim().to_owned(),
    };

    let (ciphertext, nonce) = unlocked
        .encrypt_entry_payload(&payload)
        .map_err(|error| error.to_string())?;

    let entry = state
        .service
        .upsert_encrypted_entry(state.vault_id, ciphertext, nonce)
        .await
        .map_err(|error| error.to_string())?;

    Ok(EntryDetail {
        id: entry.id.to_string(),
        title: payload.title,
        username: payload.username,
        password: payload.password,
        notes: payload.notes,
        updated_at: entry.updated_at.to_rfc3339(),
    })
}

#[tauri::command]
async fn get_entry(
    state: State<'_, AppState>,
    entry_id: String,
) -> Result<Option<EntryDetail>, String> {
    let unlocked = require_unlocked(&state)?;
    let entry_id =
        Uuid::parse_str(entry_id.trim()).map_err(|_| "entry id must be a valid UUID".to_owned())?;

    let entry = state
        .service
        .get_entry(state.vault_id, entry_id)
        .await
        .map_err(|error| error.to_string())?;

    if let Some(entry) = entry {
        let payload = unlocked
            .decrypt_entry_payload(&entry.ciphertext, entry.nonce)
            .map_err(|_| "failed to decrypt entry; wrong password or corrupted data".to_owned())?;

        Ok(Some(EntryDetail {
            id: entry.id.to_string(),
            title: payload.title,
            username: payload.username,
            password: payload.password,
            notes: payload.notes,
            updated_at: entry.updated_at.to_rfc3339(),
        }))
    } else {
        Ok(None)
    }
}

#[tauri::command]
async fn delete_entry(state: State<'_, AppState>, entry_id: String) -> Result<(), String> {
    require_unlocked(&state)?;

    let entry_id =
        Uuid::parse_str(entry_id.trim()).map_err(|_| "entry id must be a valid UUID".to_owned())?;
    state
        .service
        .delete_entry(state.vault_id, entry_id)
        .await
        .map_err(|error| error.to_string())
}

fn require_unlocked(state: &State<'_, AppState>) -> Result<UnlockedVault, String> {
    let session = state
        .session
        .lock()
        .map_err(|_| "failed to acquire session lock".to_owned())?;
    session.clone().ok_or_else(|| "vault is locked".to_owned())
}

fn database_path() -> anyhow::Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    Ok(cwd.join("vault-local.sqlite3"))
}

fn main() {
    let database_path = database_path().expect("failed to determine local database path");
    let repository = Arc::new(
        SqliteVaultRepository::new(&database_path).expect("failed to initialize sqlite repository"),
    );
    let vault_id = repository
        .ensure_default_vault()
        .expect("failed to create default vault");

    let state = AppState {
        service: VaultService::new(Arc::clone(&repository)),
        repository,
        vault_id,
        session: Mutex::new(None),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            unlock_vault,
            lock_vault,
            list_entries,
            create_entry,
            get_entry,
            delete_entry
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
