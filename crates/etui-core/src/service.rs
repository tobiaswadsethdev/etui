use thiserror::Error;
use uuid::Uuid;

use crate::model::{Entry, VaultId};
use crate::ports::{NewEntry, VaultRepository};
use crate::sync::SyncCursor;

#[derive(Debug, Error)]
pub enum VaultServiceError {
    #[error("entry ciphertext must not be empty")]
    EmptyCiphertext,
}

pub struct VaultService<R: VaultRepository> {
    repository: R,
}

impl<R: VaultRepository> VaultService<R> {
    #[must_use]
    pub fn new(repository: R) -> Self {
        Self { repository }
    }

    pub async fn create_vault(&self) -> anyhow::Result<VaultId> {
        self.repository.create_vault().await
    }

    pub async fn list_entries(&self, vault_id: VaultId) -> anyhow::Result<Vec<Entry>> {
        self.repository.list_entries(vault_id).await
    }

    pub async fn get_entry(
        &self,
        vault_id: VaultId,
        entry_id: Uuid,
    ) -> anyhow::Result<Option<Entry>> {
        self.repository.get_entry(vault_id, entry_id).await
    }

    pub async fn upsert_encrypted_entry(
        &self,
        vault_id: VaultId,
        ciphertext: Vec<u8>,
        nonce: [u8; 24],
    ) -> anyhow::Result<Entry> {
        if ciphertext.is_empty() {
            return Err(VaultServiceError::EmptyCiphertext.into());
        }

        self.repository
            .upsert_entry(vault_id, NewEntry { ciphertext, nonce })
            .await
    }

    pub async fn delete_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<()> {
        self.repository.delete_entry(vault_id, entry_id).await
    }

    pub async fn get_sync_cursor(&self, vault_id: VaultId) -> anyhow::Result<Option<SyncCursor>> {
        self.repository.get_sync_cursor(vault_id).await
    }

    pub async fn set_sync_cursor(
        &self,
        vault_id: VaultId,
        cursor: SyncCursor,
    ) -> anyhow::Result<()> {
        self.repository.set_sync_cursor(vault_id, cursor).await
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use anyhow::Context;
    use async_trait::async_trait;
    use chrono::Utc;
    use tokio::sync::Mutex;
    use uuid::Uuid;

    use super::VaultService;
    use crate::model::{Entry, VaultId};
    use crate::ports::{NewEntry, VaultRepository};
    use crate::sync::SyncCursor;

    #[derive(Default, Clone)]
    struct InMemoryVaultRepository {
        state: Arc<Mutex<InMemoryState>>,
    }

    #[derive(Default)]
    struct InMemoryState {
        entries_by_vault: HashMap<VaultId, HashMap<Uuid, Entry>>,
        sync_cursors: HashMap<VaultId, SyncCursor>,
    }

    #[async_trait]
    impl VaultRepository for InMemoryVaultRepository {
        async fn create_vault(&self) -> anyhow::Result<VaultId> {
            let vault_id = Uuid::new_v4();
            let mut state = self.state.lock().await;
            state.entries_by_vault.entry(vault_id).or_default();
            Ok(vault_id)
        }

        async fn list_entries(&self, vault_id: VaultId) -> anyhow::Result<Vec<Entry>> {
            let state = self.state.lock().await;
            let entries = state
                .entries_by_vault
                .get(&vault_id)
                .map(|entries| entries.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            Ok(entries)
        }

        async fn get_entry(
            &self,
            vault_id: VaultId,
            entry_id: Uuid,
        ) -> anyhow::Result<Option<Entry>> {
            let state = self.state.lock().await;
            Ok(state
                .entries_by_vault
                .get(&vault_id)
                .and_then(|entries| entries.get(&entry_id).cloned()))
        }

        async fn upsert_entry(&self, vault_id: VaultId, entry: NewEntry) -> anyhow::Result<Entry> {
            let mut state = self.state.lock().await;
            let bucket = state
                .entries_by_vault
                .get_mut(&vault_id)
                .context("vault does not exist")?;

            let entry_id = Uuid::new_v4();
            let record = Entry {
                id: entry_id,
                vault_id,
                updated_at: Utc::now(),
                ciphertext: entry.ciphertext,
                nonce: entry.nonce,
            };

            bucket.insert(entry_id, record.clone());
            Ok(record)
        }

        async fn delete_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<()> {
            let mut state = self.state.lock().await;
            if let Some(entries) = state.entries_by_vault.get_mut(&vault_id) {
                entries.remove(&entry_id);
            }
            Ok(())
        }

        async fn get_sync_cursor(&self, vault_id: VaultId) -> anyhow::Result<Option<SyncCursor>> {
            let state = self.state.lock().await;
            Ok(state.sync_cursors.get(&vault_id).cloned())
        }

        async fn set_sync_cursor(
            &self,
            vault_id: VaultId,
            cursor: SyncCursor,
        ) -> anyhow::Result<()> {
            let mut state = self.state.lock().await;
            state.sync_cursors.insert(vault_id, cursor);
            Ok(())
        }
    }

    #[tokio::test]
    async fn creates_vault_and_performs_entry_crud() {
        let service = VaultService::new(InMemoryVaultRepository::default());
        let vault_id = service.create_vault().await.expect("vault is created");

        let created = service
            .upsert_encrypted_entry(vault_id, vec![1, 2, 3], [7; 24])
            .await
            .expect("entry is created");

        let loaded = service
            .get_entry(vault_id, created.id)
            .await
            .expect("entry lookup succeeds")
            .expect("entry exists");

        assert_eq!(loaded.ciphertext, vec![1, 2, 3]);
        assert_eq!(loaded.nonce, [7; 24]);

        let listed = service
            .list_entries(vault_id)
            .await
            .expect("listing entries succeeds");
        assert_eq!(listed.len(), 1);

        service
            .delete_entry(vault_id, created.id)
            .await
            .expect("entry delete succeeds");

        let after_delete = service
            .get_entry(vault_id, created.id)
            .await
            .expect("entry lookup succeeds");
        assert!(after_delete.is_none());
    }

    #[tokio::test]
    async fn rejects_empty_ciphertext() {
        let service = VaultService::new(InMemoryVaultRepository::default());
        let vault_id = service.create_vault().await.expect("vault is created");

        let error = service
            .upsert_encrypted_entry(vault_id, Vec::new(), [0; 24])
            .await
            .expect_err("empty ciphertext is rejected");

        assert!(
            error
                .to_string()
                .contains("entry ciphertext must not be empty"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn persists_sync_cursor() {
        let service = VaultService::new(InMemoryVaultRepository::default());
        let vault_id = service.create_vault().await.expect("vault is created");
        let cursor = SyncCursor("cursor-v1".to_owned());

        service
            .set_sync_cursor(vault_id, cursor.clone())
            .await
            .expect("set cursor succeeds");

        let loaded = service
            .get_sync_cursor(vault_id)
            .await
            .expect("get cursor succeeds");

        assert_eq!(loaded, Some(cursor));
    }
}
