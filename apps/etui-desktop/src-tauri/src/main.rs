#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use etui_core::crypto::{initialize_crypto_metadata, unlock_with_password, UnlockedVault};
use etui_core::model::EntryPayload;
use etui_core::service::VaultService;
use serde::Serialize;
use storage_sqlite::SqliteVaultRepository;
use tauri::State;
use uuid::Uuid;

const LOCK_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Default)]
struct SessionState {
    unlocked: Option<UnlockedVault>,
    last_activity: Option<SystemTime>,
}

struct AppState {
    repository: Arc<SqliteVaultRepository>,
    service: VaultService<Arc<SqliteVaultRepository>>,
    vault_id: Uuid,
    session: Mutex<SessionState>,
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
        *session = SessionState {
            unlocked: Some(unlocked),
            last_activity: Some(SystemTime::now()),
        };
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
    *session = SessionState::default();
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
    let mut session = state
        .session
        .lock()
        .map_err(|_| "failed to acquire session lock".to_owned())?;
    let unlocked = session
        .unlocked
        .clone()
        .ok_or_else(|| "vault is locked".to_owned())?;

    let now = SystemTime::now();
    if session
        .last_activity
        .map(|last_activity| has_timed_out(last_activity, now, LOCK_TIMEOUT))
        .unwrap_or(false)
    {
        *session = SessionState::default();
        return Err("vault is locked".to_owned());
    }

    session.last_activity = Some(now);
    Ok(unlocked)
}

fn has_timed_out(last_activity: SystemTime, now: SystemTime, timeout: Duration) -> bool {
    match now.duration_since(last_activity) {
        Ok(idle_for) => idle_for >= timeout,
        Err(_) => false,
    }
}

fn database_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = std::env::var_os("ETUI_DATABASE_PATH") {
        return Ok(PathBuf::from(path));
    }

    let app_data_dir = app_data_dir()?;
    std::fs::create_dir_all(&app_data_dir).with_context(|| {
        format!(
            "failed to create application data directory at {}",
            app_data_dir.display()
        )
    })?;

    let database_path = app_data_dir.join("etui-local.sqlite3");
    migrate_legacy_database(&database_path)?;
    Ok(database_path)
}

fn app_data_dir() -> anyhow::Result<PathBuf> {
    if cfg!(target_os = "windows") {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            return Ok(PathBuf::from(local_app_data).join("etui"));
        }
    }

    if cfg!(target_os = "macos") {
        if let Some(home) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("etui"));
        }
    }

    if let Some(xdg_data_home) = std::env::var_os("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg_data_home).join("etui"));
    }

    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("etui"));
    }

    let cwd = std::env::current_dir()?;
    Ok(cwd.join(".etui"))
}

fn migrate_legacy_database(database_path: &Path) -> anyhow::Result<()> {
    if database_path.exists() {
        return Ok(());
    }

    let legacy_path = std::env::current_dir()?.join("etui-local.sqlite3");
    if !legacy_path.exists() {
        return Ok(());
    }

    match std::fs::rename(&legacy_path, database_path) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(&legacy_path, database_path).with_context(|| {
                format!(
                    "failed to migrate legacy database from {} to {}",
                    legacy_path.display(),
                    database_path.display()
                )
            })?;
            std::fs::remove_file(&legacy_path).with_context(|| {
                format!(
                    "failed to remove legacy database after migration at {}",
                    legacy_path.display()
                )
            })?;
            Ok(())
        }
    }
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
        session: Mutex::new(SessionState::default()),
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

#[cfg(test)]
mod tests {
    use super::has_timed_out;
    use std::time::{Duration, SystemTime};

    #[test]
    fn timeout_is_triggered_when_idle_reaches_threshold() {
        let base = SystemTime::UNIX_EPOCH;
        let timeout = Duration::from_secs(300);
        let now = base + timeout;

        assert!(has_timed_out(base, now, timeout));
    }

    #[test]
    fn timeout_is_not_triggered_for_shorter_idle_period() {
        let base = SystemTime::UNIX_EPOCH;
        let timeout = Duration::from_secs(300);
        let now = base + Duration::from_secs(299);

        assert!(!has_timed_out(base, now, timeout));
    }
}
