#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use etui_core::crypto::{initialize_crypto_metadata, unlock_with_password, UnlockedVault};
use etui_core::model::EntryPayload;
use etui_core::service::VaultService;
use reqwest::{Client, StatusCode};
use serde::Serialize;
use storage_sqlite::SqliteVaultRepository;
use sync_supabase::{SupabaseConfig, SupabaseSyncProvider};
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
    vault_id: Mutex<Uuid>,
    session: Mutex<SessionState>,
    supabase: Mutex<Option<SupabaseState>>,
}

struct SupabaseState {
    auth_client: Client,
    base_url: String,
    publishable_key: String,
    sync_provider: SupabaseSyncProvider,
    auth_session: Option<SupabaseAuthSession>,
}

struct SupabaseAuthSession {
    user_id: String,
    email: Option<String>,
    expires_at: SystemTime,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthSessionStatus {
    configured: bool,
    authenticated: bool,
    user_id: Option<String>,
    email: Option<String>,
    expires_in_seconds: Option<u64>,
}

#[derive(Debug, serde::Deserialize)]
struct SupabaseSignInResponse {
    access_token: String,
    expires_in: u64,
    user: SupabaseUser,
}

#[derive(Debug, serde::Deserialize)]
struct SupabaseUser {
    id: String,
    email: Option<String>,
}

#[tauri::command]
async fn unlock_vault(
    state: State<'_, AppState>,
    master_password: String,
) -> Result<SessionInfo, String> {
    ensure_auth_for_unlock(&state)?;

    if master_password.trim().is_empty() {
        return Err("master password is required".to_owned());
    }

    let vault_id = active_vault_id(&state)?;

    let metadata = state
        .repository
        .load_crypto_metadata(vault_id)
        .map_err(|error| error.to_string())?;

    let unlocked = match metadata {
        Some(metadata) => unlock_with_password(master_password.trim(), &metadata)
            .map_err(|error| error.to_string())?,
        None => {
            let (metadata, unlocked) = initialize_crypto_metadata(master_password.trim())
                .map_err(|error| error.to_string())?;
            state
                .repository
                .save_crypto_metadata(vault_id, &metadata)
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
        .list_entries(vault_id)
        .await
        .map_err(|error| error.to_string())?;

    Ok(SessionInfo {
        vault_id: vault_id.to_string(),
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
async fn auth_sign_in(
    state: State<'_, AppState>,
    email: String,
    password: String,
) -> Result<AuthSessionStatus, String> {
    if email.trim().is_empty() {
        return Err("email is required".to_owned());
    }

    if password.is_empty() {
        return Err("password is required".to_owned());
    }

    let (auth_client, base_url, publishable_key) = {
        let supabase_guard = state
            .supabase
            .lock()
            .map_err(|_| "failed to acquire supabase state lock".to_owned())?;
        let supabase = supabase_guard.as_ref().ok_or_else(|| {
            "supabase is not configured; set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY".to_owned()
        })?;

        (
            supabase.auth_client.clone(),
            supabase.base_url.clone(),
            supabase.publishable_key.clone(),
        )
    };

    let token_url = format!("{}/auth/v1/token?grant_type=password", base_url);
    let response = auth_client
        .post(token_url)
        .header("apikey", publishable_key)
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "email": email.trim(),
            "password": password,
        }))
        .send()
        .await
        .map_err(|error| format!("failed to reach Supabase auth endpoint: {error}"))?;

    if response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::BAD_REQUEST
    {
        return Err("invalid email or password".to_owned());
    }

    if !response.status().is_success() {
        let status = response.status().as_u16();
        return Err(format!("supabase sign-in failed with status {status}"));
    }

    let payload: SupabaseSignInResponse = response
        .json()
        .await
        .map_err(|error| format!("failed to parse Supabase sign-in response: {error}"))?;

    let now = SystemTime::now();
    let expires_at = now
        .checked_add(Duration::from_secs(payload.expires_in))
        .ok_or_else(|| "failed to compute session expiration".to_owned())?;
    let user_vault_id = vault_id_for_user(&payload.user.id);

    state
        .repository
        .ensure_vault(user_vault_id)
        .map_err(|error| format!("failed to initialize user vault: {error}"))?;

    {
        let mut vault_id = state
            .vault_id
            .lock()
            .map_err(|_| "failed to acquire vault id lock".to_owned())?;
        *vault_id = user_vault_id;
    }

    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "failed to acquire session lock".to_owned())?;
        *session = SessionState::default();
    }

    let mut supabase_guard = state
        .supabase
        .lock()
        .map_err(|_| "failed to acquire supabase state lock".to_owned())?;
    let supabase = supabase_guard.as_mut().ok_or_else(|| {
        "supabase is not configured; set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY".to_owned()
    })?;

    supabase
        .sync_provider
        .set_access_token(payload.access_token.clone());
    supabase.auth_session = Some(SupabaseAuthSession {
        user_id: payload.user.id,
        email: payload.user.email,
        expires_at,
    });

    Ok(auth_status_from_supabase(Some(supabase), now))
}

#[tauri::command]
async fn auth_sign_out(state: State<'_, AppState>) -> Result<AuthSessionStatus, String> {
    let mut supabase_guard = state
        .supabase
        .lock()
        .map_err(|_| "failed to acquire supabase state lock".to_owned())?;

    if let Some(supabase) = supabase_guard.as_mut() {
        supabase.auth_session = None;
        supabase.sync_provider.clear_access_token();

        let mut session = state
            .session
            .lock()
            .map_err(|_| "failed to acquire session lock".to_owned())?;
        *session = SessionState::default();

        let default_vault_id = state
            .repository
            .ensure_default_vault()
            .map_err(|error| format!("failed to restore default vault: {error}"))?;
        let mut vault_id = state
            .vault_id
            .lock()
            .map_err(|_| "failed to acquire vault id lock".to_owned())?;
        *vault_id = default_vault_id;

        return Ok(auth_status_from_supabase(Some(supabase), SystemTime::now()));
    }

    Ok(AuthSessionStatus {
        configured: false,
        authenticated: false,
        user_id: None,
        email: None,
        expires_in_seconds: None,
    })
}

#[tauri::command]
async fn auth_session_status(state: State<'_, AppState>) -> Result<AuthSessionStatus, String> {
    let mut supabase_guard = state
        .supabase
        .lock()
        .map_err(|_| "failed to acquire supabase state lock".to_owned())?;
    let now = SystemTime::now();

    if let Some(supabase) = supabase_guard.as_mut() {
        if supabase
            .auth_session
            .as_ref()
            .map(|session| now >= session.expires_at)
            .unwrap_or(false)
        {
            supabase.auth_session = None;
            supabase.sync_provider.clear_access_token();

            let mut session = state
                .session
                .lock()
                .map_err(|_| "failed to acquire session lock".to_owned())?;
            *session = SessionState::default();
        }

        return Ok(auth_status_from_supabase(Some(supabase), now));
    }

    Ok(AuthSessionStatus {
        configured: false,
        authenticated: false,
        user_id: None,
        email: None,
        expires_in_seconds: None,
    })
}

#[tauri::command]
async fn list_entries(state: State<'_, AppState>) -> Result<Vec<EntrySummary>, String> {
    let unlocked = require_unlocked(&state)?;
    let vault_id = active_vault_id(&state)?;
    let entries = state
        .service
        .list_entries(vault_id)
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
    let vault_id = active_vault_id(&state)?;

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
        .upsert_encrypted_entry(vault_id, ciphertext, nonce)
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
    let vault_id = active_vault_id(&state)?;
    let entry_id =
        Uuid::parse_str(entry_id.trim()).map_err(|_| "entry id must be a valid UUID".to_owned())?;

    let entry = state
        .service
        .get_entry(vault_id, entry_id)
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
    let vault_id = active_vault_id(&state)?;

    let entry_id =
        Uuid::parse_str(entry_id.trim()).map_err(|_| "entry id must be a valid UUID".to_owned())?;
    state
        .service
        .delete_entry(vault_id, entry_id)
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

fn active_vault_id(state: &State<'_, AppState>) -> Result<Uuid, String> {
    let vault_id = state
        .vault_id
        .lock()
        .map_err(|_| "failed to acquire vault id lock".to_owned())?;
    Ok(*vault_id)
}

fn ensure_auth_for_unlock(state: &State<'_, AppState>) -> Result<(), String> {
    let mut supabase = state
        .supabase
        .lock()
        .map_err(|_| "failed to acquire supabase state lock".to_owned())?;

    if let Some(supabase) = supabase.as_mut() {
        if supabase
            .auth_session
            .as_ref()
            .map(|session| SystemTime::now() >= session.expires_at)
            .unwrap_or(false)
        {
            supabase.auth_session = None;
            supabase.sync_provider.clear_access_token();
        }

        if supabase.auth_session.is_none() {
            return Err("sign in to Supabase before unlocking your vault".to_owned());
        }
    }

    Ok(())
}

fn vault_id_for_user(user_id: &str) -> Uuid {
    let namespace = format!("etui:supabase-user:{user_id}");
    Uuid::new_v5(&Uuid::NAMESPACE_URL, namespace.as_bytes())
}

fn has_timed_out(last_activity: SystemTime, now: SystemTime, timeout: Duration) -> bool {
    match now.duration_since(last_activity) {
        Ok(idle_for) => idle_for >= timeout,
        Err(_) => false,
    }
}

fn auth_status_from_supabase(
    supabase: Option<&SupabaseState>,
    now: SystemTime,
) -> AuthSessionStatus {
    if let Some(supabase) = supabase {
        if let Some(session) = &supabase.auth_session {
            let expires_in_seconds = session
                .expires_at
                .duration_since(now)
                .ok()
                .map(|duration| duration.as_secs());

            return AuthSessionStatus {
                configured: true,
                authenticated: true,
                user_id: Some(session.user_id.clone()),
                email: session.email.clone(),
                expires_in_seconds,
            };
        }

        return AuthSessionStatus {
            configured: true,
            authenticated: false,
            user_id: None,
            email: None,
            expires_in_seconds: None,
        };
    }

    AuthSessionStatus {
        configured: false,
        authenticated: false,
        user_id: None,
        email: None,
        expires_in_seconds: None,
    }
}

fn initialize_supabase_state() -> Option<SupabaseState> {
    let config = match SupabaseConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("supabase auth disabled: {error}");
            return None;
        }
    };

    let auth_client = match Client::builder().timeout(config.timeout).build() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("supabase auth disabled: failed to build auth client: {error}");
            return None;
        }
    };

    let sync_provider = match SupabaseSyncProvider::new(config.clone()) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("supabase sync disabled: failed to initialize provider: {error}");
            return None;
        }
    };

    Some(SupabaseState {
        auth_client,
        base_url: config.url.trim_end_matches('/').to_owned(),
        publishable_key: config.publishable_key,
        sync_provider,
        auth_session: None,
    })
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
        vault_id: Mutex::new(vault_id),
        session: Mutex::new(SessionState::default()),
        supabase: Mutex::new(initialize_supabase_state()),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            unlock_vault,
            auth_sign_in,
            auth_sign_out,
            auth_session_status,
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
