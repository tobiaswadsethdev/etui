use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type VaultId = Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub id: Uuid,
    pub vault_id: VaultId,
    pub updated_at: DateTime<Utc>,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EntryPayload {
    pub title: String,
    pub username: String,
    pub password: String,
    pub notes: String,
}
