use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::model::{Entry, VaultId};
use crate::sync::SyncCursor;

#[derive(Debug, Clone)]
pub struct NewEntry {
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
}

#[derive(Debug, Clone)]
pub struct EncryptedChangeSet {
    pub entries: Vec<Entry>,
}

#[async_trait]
pub trait VaultRepository: Send + Sync {
    async fn create_vault(&self) -> anyhow::Result<VaultId>;
    async fn list_entries(&self, vault_id: VaultId) -> anyhow::Result<Vec<Entry>>;
    async fn get_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<Option<Entry>>;
    async fn upsert_entry(&self, vault_id: VaultId, entry: NewEntry) -> anyhow::Result<Entry>;
    async fn delete_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<()>;
    async fn get_sync_cursor(&self, vault_id: VaultId) -> anyhow::Result<Option<SyncCursor>>;
    async fn set_sync_cursor(&self, vault_id: VaultId, cursor: SyncCursor) -> anyhow::Result<()>;
}

#[async_trait]
pub trait KeyMaterialStore: Send + Sync {
    async fn save_kdf_metadata(&self, vault_id: VaultId, encoded: String) -> anyhow::Result<()>;
    async fn load_kdf_metadata(&self, vault_id: VaultId) -> anyhow::Result<Option<String>>;
}

#[async_trait]
pub trait SyncProvider: Send + Sync {
    async fn push_changes(
        &self,
        vault_id: VaultId,
        changes: EncryptedChangeSet,
    ) -> anyhow::Result<()>;
    async fn pull_changes(
        &self,
        vault_id: VaultId,
        cursor: Option<SyncCursor>,
    ) -> anyhow::Result<(EncryptedChangeSet, Option<SyncCursor>)>;
}

#[async_trait]
impl<T> VaultRepository for Arc<T>
where
    T: VaultRepository + ?Sized,
{
    async fn create_vault(&self) -> anyhow::Result<VaultId> {
        self.as_ref().create_vault().await
    }

    async fn list_entries(&self, vault_id: VaultId) -> anyhow::Result<Vec<Entry>> {
        self.as_ref().list_entries(vault_id).await
    }

    async fn get_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<Option<Entry>> {
        self.as_ref().get_entry(vault_id, entry_id).await
    }

    async fn upsert_entry(&self, vault_id: VaultId, entry: NewEntry) -> anyhow::Result<Entry> {
        self.as_ref().upsert_entry(vault_id, entry).await
    }

    async fn delete_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<()> {
        self.as_ref().delete_entry(vault_id, entry_id).await
    }

    async fn get_sync_cursor(&self, vault_id: VaultId) -> anyhow::Result<Option<SyncCursor>> {
        self.as_ref().get_sync_cursor(vault_id).await
    }

    async fn set_sync_cursor(&self, vault_id: VaultId, cursor: SyncCursor) -> anyhow::Result<()> {
        self.as_ref().set_sync_cursor(vault_id, cursor).await
    }
}
