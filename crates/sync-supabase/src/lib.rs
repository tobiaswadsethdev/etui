use std::env;
use std::time::Duration;

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::{DateTime, Utc};
use etui_core::model::{Entry, VaultId};
use etui_core::ports::{EncryptedChangeSet, SyncProvider};
use etui_core::sync::SyncCursor;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const PUSH_RPC_PATH: &str = "/rest/v1/rpc/etui_push_changes";
const PULL_RPC_PATH: &str = "/rest/v1/rpc/etui_pull_changes";

#[derive(Debug, Clone)]
pub struct SupabaseConfig {
    pub url: String,
    pub anon_key: String,
    pub access_token: String,
    pub timeout: Duration,
}

impl SupabaseConfig {
    pub fn from_env() -> Result<Self, SupabaseSyncError> {
        let url = env::var("SUPABASE_URL").map_err(|_| SupabaseSyncError::MissingConfig {
            variable: "SUPABASE_URL",
        })?;
        let anon_key =
            env::var("SUPABASE_ANON_KEY").map_err(|_| SupabaseSyncError::MissingConfig {
                variable: "SUPABASE_ANON_KEY",
            })?;
        let access_token =
            env::var("SUPABASE_ACCESS_TOKEN").map_err(|_| SupabaseSyncError::MissingConfig {
                variable: "SUPABASE_ACCESS_TOKEN",
            })?;

        Ok(Self {
            url,
            anon_key,
            access_token,
            timeout: Duration::from_secs(15),
        })
    }
}

#[derive(Debug, Error)]
pub enum SupabaseSyncError {
    #[error("missing required Supabase config: {variable}")]
    MissingConfig { variable: &'static str },
    #[error("sync unauthorized: Supabase token is invalid or expired")]
    Unauthorized,
    #[error("sync forbidden: Supabase policy denied access")]
    Forbidden,
    #[error("invalid sync request")]
    InvalidRequest,
    #[error("sync cursor is stale or invalid")]
    StaleCursor,
    #[error("sync request was rate-limited")]
    RateLimited,
    #[error("transient sync backend failure")]
    Transient,
    #[error("unexpected sync response status: {status}")]
    UnexpectedStatus { status: u16 },
    #[error("invalid sync response format")]
    InvalidResponse,
}

pub struct SupabaseSyncProvider {
    client: Client,
    base_url: String,
    anon_key: String,
    access_token: String,
}

impl SupabaseSyncProvider {
    pub fn new(config: SupabaseConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .context("failed to build supabase http client")?;

        Ok(Self {
            client,
            base_url: config.url.trim_end_matches('/').to_owned(),
            anon_key: config.anon_key,
            access_token: config.access_token,
        })
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let config = SupabaseConfig::from_env()?;
        Self::new(config)
    }

    fn rpc_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn ensure_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }

        let error: SupabaseSyncError = match status {
            StatusCode::UNAUTHORIZED => SupabaseSyncError::Unauthorized,
            StatusCode::FORBIDDEN => SupabaseSyncError::Forbidden,
            StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY => {
                SupabaseSyncError::InvalidRequest
            }
            StatusCode::CONFLICT => SupabaseSyncError::StaleCursor,
            StatusCode::TOO_MANY_REQUESTS => SupabaseSyncError::RateLimited,
            status if status.is_server_error() => SupabaseSyncError::Transient,
            _ => SupabaseSyncError::UnexpectedStatus {
                status: status.as_u16(),
            },
        };

        Err(error.into())
    }

    fn map_entry_to_change(entry: Entry) -> PushChange {
        let change_id = Self::change_id_for_entry(&entry);
        PushChange {
            change_id,
            entry_id: entry.id,
            updated_at: entry.updated_at,
            nonce_b64: BASE64.encode(entry.nonce),
            ciphertext_b64: BASE64.encode(entry.ciphertext),
        }
    }

    fn change_id_for_entry(entry: &Entry) -> Uuid {
        let material = format!(
            "{}:{}:{}:{}",
            entry.id,
            entry.updated_at.to_rfc3339(),
            BASE64.encode(entry.nonce),
            BASE64.encode(&entry.ciphertext)
        );
        Uuid::new_v5(&Uuid::NAMESPACE_OID, material.as_bytes())
    }

    fn map_change_to_entry(vault_id: VaultId, change: PullChange) -> anyhow::Result<Entry> {
        let nonce_bytes = BASE64
            .decode(change.nonce_b64)
            .context("failed to decode nonce from sync response")?;
        let nonce: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| anyhow!("decoded nonce has invalid length"))?;

        let ciphertext = BASE64
            .decode(change.ciphertext_b64)
            .context("failed to decode ciphertext from sync response")?;

        Ok(Entry {
            id: change.entry_id,
            vault_id,
            updated_at: change.updated_at,
            ciphertext,
            nonce,
        })
    }
}

#[async_trait]
impl SyncProvider for SupabaseSyncProvider {
    async fn push_changes(
        &self,
        vault_id: VaultId,
        changes: EncryptedChangeSet,
    ) -> anyhow::Result<()> {
        let request = PushRequest {
            p_vault_id: vault_id,
            p_changes: changes
                .entries
                .into_iter()
                .map(Self::map_entry_to_change)
                .collect(),
        };

        let response = self
            .client
            .post(self.rpc_url(PUSH_RPC_PATH))
            .header("apikey", &self.anon_key)
            .bearer_auth(&self.access_token)
            .json(&request)
            .send()
            .await
            .context("failed to send Supabase push request")?;

        let _ = Self::ensure_success(response).await?;
        Ok(())
    }

    async fn pull_changes(
        &self,
        vault_id: VaultId,
        cursor: Option<SyncCursor>,
    ) -> anyhow::Result<(EncryptedChangeSet, Option<SyncCursor>)> {
        let request = PullRequest {
            p_vault_id: vault_id,
            p_since_cursor: cursor.map(|cursor| cursor.0),
        };

        let response = self
            .client
            .post(self.rpc_url(PULL_RPC_PATH))
            .header("apikey", &self.anon_key)
            .bearer_auth(&self.access_token)
            .json(&request)
            .send()
            .await
            .context("failed to send Supabase pull request")?;

        let response = Self::ensure_success(response).await?;
        let payload: PullResponseEnvelope = response
            .json()
            .await
            .context("failed to parse Supabase pull response")?;

        let response = payload.into_pull_response()?;
        let entries = response
            .changes
            .into_iter()
            .map(|change| Self::map_change_to_entry(vault_id, change))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok((
            EncryptedChangeSet { entries },
            response.next_cursor.map(SyncCursor),
        ))
    }
}

#[derive(Debug, Serialize)]
struct PushRequest {
    p_vault_id: VaultId,
    p_changes: Vec<PushChange>,
}

#[derive(Debug, Serialize)]
struct PushChange {
    change_id: Uuid,
    entry_id: Uuid,
    updated_at: DateTime<Utc>,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[derive(Debug, Serialize)]
struct PullRequest {
    p_vault_id: VaultId,
    p_since_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum PullResponseEnvelope {
    Object(PullResponse),
    SingleRow(Vec<PullResponse>),
}

impl PullResponseEnvelope {
    fn into_pull_response(self) -> anyhow::Result<PullResponse> {
        match self {
            Self::Object(payload) => Ok(payload),
            Self::SingleRow(mut rows) => rows.pop().ok_or_else(|| {
                let error: anyhow::Error = SupabaseSyncError::InvalidResponse.into();
                error
            }),
        }
    }
}

#[derive(Debug, Deserialize)]
struct PullResponse {
    changes: Vec<PullChange>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PullChange {
    entry_id: Uuid,
    updated_at: DateTime<Utc>,
    nonce_b64: String,
    ciphertext_b64: String,
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use chrono::Utc;
    use etui_core::model::Entry;
    use etui_core::ports::{EncryptedChangeSet, SyncProvider};
    use etui_core::sync::SyncCursor;
    use mockito::{Matcher, Server};
    use uuid::Uuid;

    use super::{SupabaseConfig, SupabaseSyncProvider};

    fn test_provider(url: String) -> SupabaseSyncProvider {
        let config = SupabaseConfig {
            url,
            anon_key: "test-anon-key".to_owned(),
            access_token: "test-access-token".to_owned(),
            timeout: std::time::Duration::from_secs(5),
        };
        SupabaseSyncProvider::new(config).expect("provider initializes")
    }

    #[tokio::test]
    async fn push_changes_sends_authenticated_rpc_request() {
        let mut server = Server::new_async().await;
        let vault_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let updated_at = Utc::now();
        let entry = Entry {
            id: entry_id,
            vault_id,
            updated_at,
            ciphertext: vec![1, 2, 3],
            nonce: [7; 24],
        };
        let change_id = SupabaseSyncProvider::change_id_for_entry(&entry);

        let nonce_b64 = BASE64.encode([7_u8; 24]);
        let ciphertext_b64 = BASE64.encode([1_u8, 2, 3]);

        let mock = server
            .mock("POST", "/rest/v1/rpc/etui_push_changes")
            .match_header("apikey", "test-anon-key")
            .match_header("authorization", "Bearer test-access-token")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "p_vault_id": vault_id,
                "p_changes": [{
                    "change_id": change_id,
                    "entry_id": entry_id,
                    "updated_at": updated_at,
                    "nonce_b64": nonce_b64,
                    "ciphertext_b64": ciphertext_b64
                }]
            })))
            .with_status(200)
            .create_async()
            .await;

        let provider = test_provider(server.url());
        provider
            .push_changes(
                vault_id,
                EncryptedChangeSet {
                    entries: vec![entry],
                },
            )
            .await
            .expect("push succeeds");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn pull_changes_decodes_entries_and_cursor() {
        let mut server = Server::new_async().await;
        let vault_id = Uuid::new_v4();
        let entry_id = Uuid::new_v4();
        let updated_at = Utc::now();

        let mock = server
            .mock("POST", "/rest/v1/rpc/etui_pull_changes")
            .match_header("apikey", "test-anon-key")
            .match_header("authorization", "Bearer test-access-token")
            .match_body(Matcher::PartialJson(serde_json::json!({
                "p_vault_id": vault_id,
                "p_since_cursor": "cursor-1"
            })))
            .with_status(200)
            .with_body(
                serde_json::json!({
                    "changes": [{
                        "entry_id": entry_id,
                        "updated_at": updated_at,
                        "nonce_b64": BASE64.encode([9_u8; 24]),
                        "ciphertext_b64": BASE64.encode([4_u8, 5, 6])
                    }],
                    "next_cursor": "cursor-2"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let provider = test_provider(server.url());
        let (changes, next_cursor) = provider
            .pull_changes(vault_id, Some(SyncCursor("cursor-1".to_owned())))
            .await
            .expect("pull succeeds");

        assert_eq!(changes.entries.len(), 1);
        assert_eq!(changes.entries[0].id, entry_id);
        assert_eq!(changes.entries[0].vault_id, vault_id);
        assert_eq!(changes.entries[0].nonce, [9; 24]);
        assert_eq!(changes.entries[0].ciphertext, vec![4, 5, 6]);
        assert_eq!(next_cursor, Some(SyncCursor("cursor-2".to_owned())));

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn unauthorized_pull_maps_to_auth_error() {
        let mut server = Server::new_async().await;
        let vault_id = Uuid::new_v4();

        let mock = server
            .mock("POST", "/rest/v1/rpc/etui_pull_changes")
            .with_status(401)
            .create_async()
            .await;

        let provider = test_provider(server.url());
        let error = provider
            .pull_changes(vault_id, None)
            .await
            .expect_err("unauthorized response returns error");

        assert!(error.to_string().contains("unauthorized"));
        mock.assert_async().await;
    }
}
