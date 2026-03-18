use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use etui_core::crypto::CryptoMetadata;
use etui_core::model::{Entry, VaultId};
use etui_core::ports::{NewEntry, VaultRepository};
use etui_core::sync::SyncCursor;
use rusqlite::{params, Connection};
use uuid::Uuid;

pub struct SqliteVaultRepository {
    connection: Mutex<Connection>,
}

impl SqliteVaultRepository {
    pub fn new(path: &Path) -> anyhow::Result<Self> {
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open sqlite database at {}", path.display()))?;

        let repository = Self {
            connection: Mutex::new(connection),
        };
        repository.initialize_schema()?;

        Ok(repository)
    }

    pub fn ensure_default_vault(&self) -> anyhow::Result<VaultId> {
        let mut connection = self.connection()?;
        if let Some(vault_id) = Self::select_first_vault_id(&mut connection)? {
            return Ok(vault_id);
        }

        let vault_id = Uuid::new_v4();
        connection.execute(
            "INSERT INTO vaults (id, created_at) VALUES (?1, ?2)",
            params![vault_id.to_string(), Utc::now().to_rfc3339()],
        )?;

        Ok(vault_id)
    }

    fn initialize_schema(&self) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute_batch(
            "
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS vaults (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS entries (
                id TEXT PRIMARY KEY,
                vault_id TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_entries_vault_updated
                ON entries(vault_id, updated_at DESC);

            CREATE TABLE IF NOT EXISTS sync_state (
                vault_id TEXT PRIMARY KEY,
                cursor TEXT NOT NULL,
                FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vault_crypto (
                vault_id TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                kdf_memory_kib INTEGER NOT NULL,
                kdf_iterations INTEGER NOT NULL,
                kdf_parallelism INTEGER NOT NULL,
                verifier_nonce BLOB NOT NULL,
                verifier_ciphertext BLOB NOT NULL,
                FOREIGN KEY(vault_id) REFERENCES vaults(id) ON DELETE CASCADE
            );
            ",
        )?;

        Ok(())
    }

    fn select_first_vault_id(connection: &mut Connection) -> anyhow::Result<Option<VaultId>> {
        let mut statement =
            connection.prepare("SELECT id FROM vaults ORDER BY created_at ASC LIMIT 1")?;
        let row = statement.query_row([], |row| row.get::<_, String>(0));

        match row {
            Ok(id) => {
                Ok(Some(Uuid::parse_str(&id).with_context(|| {
                    format!("invalid vault id in database: {id}")
                })?))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    fn connection(&self) -> anyhow::Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("sqlite connection lock was poisoned"))
    }

    fn row_to_entry(
        id: String,
        vault_id: String,
        updated_at: String,
        ciphertext: Vec<u8>,
        nonce_bytes: Vec<u8>,
    ) -> anyhow::Result<Entry> {
        let id =
            Uuid::parse_str(&id).with_context(|| format!("invalid entry id in database: {id}"))?;
        let vault_id = Uuid::parse_str(&vault_id)
            .with_context(|| format!("invalid vault id in database: {vault_id}"))?;
        let updated_at = DateTime::parse_from_rfc3339(&updated_at)
            .with_context(|| format!("invalid updated_at timestamp in database: {updated_at}"))?
            .with_timezone(&Utc);

        let nonce: [u8; 24] = nonce_bytes
            .try_into()
            .map_err(|_| anyhow!("invalid nonce length in database; expected 24 bytes"))?;

        Ok(Entry {
            id,
            vault_id,
            updated_at,
            ciphertext,
            nonce,
        })
    }

    pub fn load_crypto_metadata(
        &self,
        vault_id: VaultId,
    ) -> anyhow::Result<Option<CryptoMetadata>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "
            SELECT salt, kdf_memory_kib, kdf_iterations, kdf_parallelism, verifier_nonce, verifier_ciphertext
            FROM vault_crypto
            WHERE vault_id = ?1
            LIMIT 1
            ",
        )?;

        let row = statement.query_row(params![vault_id.to_string()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, u32>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        });

        match row {
            Ok((
                salt,
                memory_kib,
                iterations,
                parallelism,
                verifier_nonce,
                verifier_ciphertext,
            )) => {
                let salt: [u8; 16] = salt
                    .try_into()
                    .map_err(|_| anyhow!("invalid salt length in database; expected 16 bytes"))?;
                let verifier_nonce: [u8; 24] = verifier_nonce.try_into().map_err(|_| {
                    anyhow!("invalid verifier nonce length in database; expected 24 bytes")
                })?;

                Ok(Some(CryptoMetadata {
                    kdf: etui_core::crypto::KdfParams {
                        memory_kib,
                        iterations,
                        parallelism,
                    },
                    salt,
                    verifier_nonce,
                    verifier_ciphertext,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn save_crypto_metadata(
        &self,
        vault_id: VaultId,
        metadata: &CryptoMetadata,
    ) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "
            INSERT INTO vault_crypto (
                vault_id,
                salt,
                kdf_memory_kib,
                kdf_iterations,
                kdf_parallelism,
                verifier_nonce,
                verifier_ciphertext
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(vault_id) DO UPDATE SET
                salt = excluded.salt,
                kdf_memory_kib = excluded.kdf_memory_kib,
                kdf_iterations = excluded.kdf_iterations,
                kdf_parallelism = excluded.kdf_parallelism,
                verifier_nonce = excluded.verifier_nonce,
                verifier_ciphertext = excluded.verifier_ciphertext
            ",
            params![
                vault_id.to_string(),
                metadata.salt.to_vec(),
                metadata.kdf.memory_kib,
                metadata.kdf.iterations,
                metadata.kdf.parallelism,
                metadata.verifier_nonce.to_vec(),
                metadata.verifier_ciphertext.clone(),
            ],
        )?;

        Ok(())
    }
}

#[async_trait]
impl VaultRepository for SqliteVaultRepository {
    async fn create_vault(&self) -> anyhow::Result<VaultId> {
        let vault_id = Uuid::new_v4();
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO vaults (id, created_at) VALUES (?1, ?2)",
            params![vault_id.to_string(), Utc::now().to_rfc3339()],
        )?;

        Ok(vault_id)
    }

    async fn list_entries(&self, vault_id: VaultId) -> anyhow::Result<Vec<Entry>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "
            SELECT id, vault_id, updated_at, ciphertext, nonce
            FROM entries
            WHERE vault_id = ?1
            ORDER BY updated_at DESC
            ",
        )?;

        let mut rows = statement.query(params![vault_id.to_string()])?;
        let mut entries = Vec::new();

        while let Some(row) = rows.next()? {
            let entry = Self::row_to_entry(
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            )?;
            entries.push(entry);
        }

        Ok(entries)
    }

    async fn get_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<Option<Entry>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "
            SELECT id, vault_id, updated_at, ciphertext, nonce
            FROM entries
            WHERE vault_id = ?1 AND id = ?2
            LIMIT 1
            ",
        )?;

        let row = statement.query_row(params![vault_id.to_string(), entry_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        });

        match row {
            Ok((id, row_vault_id, updated_at, ciphertext, nonce)) => Ok(Some(Self::row_to_entry(
                id,
                row_vault_id,
                updated_at,
                ciphertext,
                nonce,
            )?)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn upsert_entry(&self, vault_id: VaultId, entry: NewEntry) -> anyhow::Result<Entry> {
        let entry_id = Uuid::new_v4();
        let updated_at = Utc::now();
        let ciphertext = entry.ciphertext;
        let nonce = entry.nonce;

        let connection = self.connection()?;
        connection.execute(
            "
            INSERT INTO entries (id, vault_id, updated_at, ciphertext, nonce)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ",
            params![
                entry_id.to_string(),
                vault_id.to_string(),
                updated_at.to_rfc3339(),
                ciphertext,
                nonce.to_vec(),
            ],
        )?;

        Ok(Entry {
            id: entry_id,
            vault_id,
            updated_at,
            ciphertext: connection
                .query_row(
                    "SELECT ciphertext FROM entries WHERE id = ?1",
                    params![entry_id.to_string()],
                    |row| row.get(0),
                )
                .context("failed to read inserted ciphertext")?,
            nonce,
        })
    }

    async fn delete_entry(&self, vault_id: VaultId, entry_id: Uuid) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "DELETE FROM entries WHERE vault_id = ?1 AND id = ?2",
            params![vault_id.to_string(), entry_id.to_string()],
        )?;
        Ok(())
    }

    async fn get_sync_cursor(&self, vault_id: VaultId) -> anyhow::Result<Option<SyncCursor>> {
        let connection = self.connection()?;
        let mut statement =
            connection.prepare("SELECT cursor FROM sync_state WHERE vault_id = ?1 LIMIT 1")?;
        let row = statement.query_row(params![vault_id.to_string()], |row| row.get::<_, String>(0));

        match row {
            Ok(cursor) => Ok(Some(SyncCursor(cursor))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    async fn set_sync_cursor(&self, vault_id: VaultId, cursor: SyncCursor) -> anyhow::Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "
            INSERT INTO sync_state (vault_id, cursor)
            VALUES (?1, ?2)
            ON CONFLICT(vault_id) DO UPDATE SET cursor = excluded.cursor
            ",
            params![vault_id.to_string(), cursor.0],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use etui_core::crypto::initialize_crypto_metadata;
    use etui_core::ports::VaultRepository;
    use etui_core::sync::SyncCursor;
    use tempfile::TempDir;
    use tokio::time::{sleep, Duration};

    use super::SqliteVaultRepository;

    fn test_db_path() -> anyhow::Result<(TempDir, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("vault.sqlite3");
        Ok((dir, path))
    }

    #[tokio::test]
    async fn repository_contract_entry_crud_and_listing() {
        let (_temp_dir, db_path) = test_db_path().expect("temp path is created");
        let repository = SqliteVaultRepository::new(&db_path).expect("repository initializes");
        let vault_id = repository
            .ensure_default_vault()
            .expect("default vault is created");

        let created = repository
            .upsert_entry(
                vault_id,
                etui_core::ports::NewEntry {
                    ciphertext: vec![1, 2, 3],
                    nonce: [11; 24],
                },
            )
            .await
            .expect("entry is created");

        sleep(Duration::from_millis(2)).await;

        let newer = repository
            .upsert_entry(
                vault_id,
                etui_core::ports::NewEntry {
                    ciphertext: vec![4, 5, 6],
                    nonce: [22; 24],
                },
            )
            .await
            .expect("second entry is created");

        let loaded = repository
            .get_entry(vault_id, created.id)
            .await
            .expect("entry lookup succeeds")
            .expect("entry exists");
        assert_eq!(loaded.ciphertext, vec![1, 2, 3]);
        assert_eq!(loaded.nonce, [11; 24]);

        let listed = repository
            .list_entries(vault_id)
            .await
            .expect("listing succeeds");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, newer.id);
        assert_eq!(listed[1].id, created.id);

        repository
            .delete_entry(vault_id, created.id)
            .await
            .expect("delete succeeds");

        let deleted = repository
            .get_entry(vault_id, created.id)
            .await
            .expect("entry lookup succeeds");
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn repository_contract_sync_cursor_roundtrip() {
        let (_temp_dir, db_path) = test_db_path().expect("temp path is created");
        let repository = SqliteVaultRepository::new(&db_path).expect("repository initializes");
        let vault_id = repository
            .ensure_default_vault()
            .expect("default vault is created");

        let initial = repository
            .get_sync_cursor(vault_id)
            .await
            .expect("cursor lookup succeeds");
        assert!(initial.is_none());

        let cursor = SyncCursor("cursor-v1".to_owned());
        repository
            .set_sync_cursor(vault_id, cursor.clone())
            .await
            .expect("cursor is persisted");

        let loaded = repository
            .get_sync_cursor(vault_id)
            .await
            .expect("cursor lookup succeeds");
        assert_eq!(loaded, Some(cursor));
    }

    #[tokio::test]
    async fn default_vault_is_stable_across_calls() {
        let (_temp_dir, db_path) = test_db_path().expect("temp path is created");
        let repository = SqliteVaultRepository::new(&db_path).expect("repository initializes");

        let first = repository
            .ensure_default_vault()
            .expect("default vault exists");
        let second = repository
            .ensure_default_vault()
            .expect("default vault exists");

        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn crypto_metadata_roundtrip() {
        let (_temp_dir, db_path) = test_db_path().expect("temp path is created");
        let repository = SqliteVaultRepository::new(&db_path).expect("repository initializes");
        let vault_id = repository
            .ensure_default_vault()
            .expect("default vault is created");

        let (metadata, _) =
            initialize_crypto_metadata("test-master-password").expect("metadata initializes");

        repository
            .save_crypto_metadata(vault_id, &metadata)
            .expect("metadata saves");

        let loaded = repository
            .load_crypto_metadata(vault_id)
            .expect("metadata loads")
            .expect("metadata exists");

        assert_eq!(loaded.kdf.memory_kib, metadata.kdf.memory_kib);
        assert_eq!(loaded.kdf.iterations, metadata.kdf.iterations);
        assert_eq!(loaded.kdf.parallelism, metadata.kdf.parallelism);
        assert_eq!(loaded.salt, metadata.salt);
        assert_eq!(loaded.verifier_nonce, metadata.verifier_nonce);
        assert_eq!(loaded.verifier_ciphertext, metadata.verifier_ciphertext);
    }

    #[tokio::test]
    async fn crypto_metadata_is_absent_before_save() {
        let (_temp_dir, db_path) = test_db_path().expect("temp path is created");
        let repository = SqliteVaultRepository::new(&db_path).expect("repository initializes");
        let vault_id = repository
            .ensure_default_vault()
            .expect("default vault is created");

        let loaded = repository
            .load_crypto_metadata(vault_id)
            .expect("metadata lookup succeeds");

        assert!(loaded.is_none());
    }
}
