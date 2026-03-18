use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::EntryPayload;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const VERIFIER_VALUE: &[u8] = b"vault-verifier-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CryptoMetadata {
    pub kdf: KdfParams,
    pub salt: [u8; SALT_LEN],
    pub verifier_nonce: [u8; 24],
    pub verifier_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnlockedVault {
    key: [u8; KEY_LEN],
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid argon2 parameters")]
    InvalidKdfParameters,
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed")]
    Decryption,
    #[error("invalid vault credentials")]
    InvalidCredentials,
    #[error("payload serialization failed")]
    PayloadSerialization,
    #[error("payload deserialization failed")]
    PayloadDeserialization,
}

pub fn initialize_crypto_metadata(
    master_password: &str,
) -> Result<(CryptoMetadata, UnlockedVault), CryptoError> {
    let mut salt = [0_u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);

    let kdf = KdfParams::default();
    let key = derive_key(master_password, &salt, &kdf)?;
    let unlocked = UnlockedVault { key };

    let mut verifier_nonce = [0_u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut verifier_nonce);

    let verifier_ciphertext = encrypt_bytes(&unlocked.key, VERIFIER_VALUE, verifier_nonce)?;

    let metadata = CryptoMetadata {
        kdf,
        salt,
        verifier_nonce,
        verifier_ciphertext,
    };

    Ok((metadata, unlocked))
}

pub fn unlock_with_password(
    master_password: &str,
    metadata: &CryptoMetadata,
) -> Result<UnlockedVault, CryptoError> {
    let key = derive_key(master_password, &metadata.salt, &metadata.kdf)?;
    let verifier_plaintext =
        decrypt_bytes(&key, &metadata.verifier_ciphertext, metadata.verifier_nonce)
            .map_err(|_| CryptoError::InvalidCredentials)?;

    if verifier_plaintext != VERIFIER_VALUE {
        return Err(CryptoError::InvalidCredentials);
    }

    Ok(UnlockedVault { key })
}

impl UnlockedVault {
    pub fn encrypt_entry_payload(
        &self,
        payload: &EntryPayload,
    ) -> Result<(Vec<u8>, [u8; 24]), CryptoError> {
        let plaintext =
            serde_json::to_vec(payload).map_err(|_| CryptoError::PayloadSerialization)?;
        let mut nonce = [0_u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = encrypt_bytes(&self.key, &plaintext, nonce)?;
        Ok((ciphertext, nonce))
    }

    pub fn decrypt_entry_payload(
        &self,
        ciphertext: &[u8],
        nonce: [u8; 24],
    ) -> Result<EntryPayload, CryptoError> {
        let plaintext = decrypt_bytes(&self.key, ciphertext, nonce)?;
        serde_json::from_slice(&plaintext).map_err(|_| CryptoError::PayloadDeserialization)
    }
}

fn derive_key(
    master_password: &str,
    salt: &[u8; SALT_LEN],
    kdf: &KdfParams,
) -> Result<[u8; KEY_LEN], CryptoError> {
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidKdfParameters)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

fn encrypt_bytes(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::Encryption)
}

fn decrypt_bytes(
    key: &[u8; KEY_LEN],
    ciphertext: &[u8],
    nonce: [u8; 24],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(XNonce::from_slice(&nonce), ciphertext)
        .map_err(|_| CryptoError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::{initialize_crypto_metadata, unlock_with_password};
    use crate::model::EntryPayload;

    #[test]
    fn encrypts_and_decrypts_payload() {
        let (metadata, unlocked) =
            initialize_crypto_metadata("master-secret").expect("metadata is created");
        let verified = unlock_with_password("master-secret", &metadata).expect("unlock succeeds");

        let payload = EntryPayload {
            title: "Example".to_owned(),
            username: "alice".to_owned(),
            password: "s3cret".to_owned(),
            notes: "note".to_owned(),
        };

        let (ciphertext, nonce) = unlocked
            .encrypt_entry_payload(&payload)
            .expect("encryption succeeds");
        let decrypted = verified
            .decrypt_entry_payload(&ciphertext, nonce)
            .expect("decryption succeeds");

        assert_eq!(decrypted, payload);
    }

    #[test]
    fn rejects_wrong_password() {
        let (metadata, _) =
            initialize_crypto_metadata("master-secret").expect("metadata is created");
        let error =
            unlock_with_password("wrong", &metadata).expect_err("wrong password is rejected");
        assert_eq!(error.to_string(), "invalid vault credentials");
    }
}
