//! Local filesystem / in-memory ML-KEM key provider.

use std::collections::HashMap;
use std::path::Path;
use std::sync::RwLock;

use async_trait::async_trait;

use crate::crypto::kem::{self, SEED_LEN, SecretKey};
use crate::crypto::{PublicKey, SharedSecret, generate_keypair};
use crate::error::{Error, Result};
use crate::key::{KeyId, KeyProvider, PublicKeyMaterial};

const KEY_FILE_MAGIC: &[u8; 6] = b"PQKEY\x01";

struct KeyEntry {
    secret: SecretKey,
    public: PublicKey,
}

/// Key provider that holds ML-KEM seeds in process memory.
///
/// Suitable for development, Celld embedding, and simple deployments. Private
/// keys are never written to object storage by this crate.
///
/// # Examples
///
/// ```
/// use pq_objectstore::key::{KeyId, LocalKeyProvider};
///
/// let id = KeyId::new("workspace-a-v1").unwrap();
/// let provider = LocalKeyProvider::generate(id).unwrap();
/// ```
pub struct LocalKeyProvider {
    keys: RwLock<HashMap<KeyId, KeyEntry>>,
}

impl LocalKeyProvider {
    /// Create an empty provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
        }
    }

    /// Generate a fresh keypair under `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if `key_id` is invalid (via [`KeyId`]).
    pub fn generate(key_id: KeyId) -> Result<Self> {
        let provider = Self::new();
        provider.insert_generated(key_id)?;
        Ok(provider)
    }

    /// Insert a newly generated keypair for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if a key with the same ID already exists.
    pub fn insert_generated(&self, key_id: KeyId) -> Result<PublicKey> {
        let (secret, public) = generate_keypair();
        self.insert(key_id, secret, public.clone())?;
        Ok(public)
    }

    /// Insert an existing seed and public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the key ID is already present.
    pub fn insert(&self, key_id: KeyId, secret: SecretKey, public: PublicKey) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        if keys.contains_key(&key_id) {
            return Err(Error::config(format!("key id already present: {key_id}")));
        }
        keys.insert(key_id, KeyEntry { secret, public });
        Ok(())
    }

    /// Insert a key from a 64-byte seed, deriving the public key.
    pub fn insert_seed(&self, key_id: KeyId, seed: &[u8]) -> Result<PublicKey> {
        let secret = SecretKey::from_seed(seed)?;
        let (_, public) = kem::keypair_from_seed(&secret);
        self.insert(key_id, secret, public.clone())?;
        Ok(public)
    }

    /// List known key IDs.
    pub fn key_ids(&self) -> Result<Vec<KeyId>> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        Ok(keys.keys().cloned().collect())
    }

    /// Persist a single key to `path`.
    ///
    /// File format: `PQKEY\x01` || key_id_len_u16 || key_id || seed\[64\].
    ///
    /// # Security
    ///
    /// The file contains private key material. Restrict filesystem permissions
    /// appropriately.
    pub fn save_key(&self, key_id: &KeyId, path: impl AsRef<Path>) -> Result<()> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        let id_bytes = key_id.as_str().as_bytes();
        let mut buf = Vec::with_capacity(6 + 2 + id_bytes.len() + SEED_LEN);
        buf.extend_from_slice(KEY_FILE_MAGIC);
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(id_bytes);
        buf.extend_from_slice(entry.secret.as_bytes());
        std::fs::write(path, buf)?;
        Ok(())
    }

    /// Load a key file previously written by [`Self::save_key`].
    pub fn load_key(&self, path: impl AsRef<Path>) -> Result<KeyId> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 6 + 2 + 1 + SEED_LEN {
            return Err(Error::invalid_header("key file too short"));
        }
        if &bytes[..6] != KEY_FILE_MAGIC {
            return Err(Error::invalid_header("invalid key file magic"));
        }
        let id_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        let id_end = 8 + id_len;
        let seed_end = id_end + SEED_LEN;
        if bytes.len() != seed_end {
            return Err(Error::invalid_header("invalid key file length"));
        }
        let key_id = KeyId::new(
            std::str::from_utf8(&bytes[8..id_end])
                .map_err(|_| Error::invalid_header("key id not utf-8"))?,
        )?;
        self.insert_seed(key_id.clone(), &bytes[id_end..seed_end])?;
        Ok(key_id)
    }
}

impl Default for LocalKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LocalKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.keys.read().map(|g| g.len()).unwrap_or(0);
        f.debug_struct("LocalKeyProvider")
            .field("keys", &count)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKeyMaterial> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        keys.get(key_id)
            .map(|e| e.public.clone())
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))
    }

    async fn decapsulate(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SharedSecret> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        kem::decapsulate(&entry.secret, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn generate_and_decapsulate() {
        let id = KeyId::new("k1").unwrap();
        let provider = LocalKeyProvider::generate(id.clone()).unwrap();
        let pk = provider.public_key(&id).await.unwrap();
        let (ct, ss1) = crate::crypto::encapsulate(&pk).unwrap();
        let ss2 = provider.decapsulate(&id, &ct).await.unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[tokio::test]
    async fn save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key.bin");
        let id = KeyId::new("workspace-a-v1").unwrap();
        let provider = LocalKeyProvider::generate(id.clone()).unwrap();
        provider.save_key(&id, &path).unwrap();

        let loaded = LocalKeyProvider::new();
        let loaded_id = loaded.load_key(&path).unwrap();
        assert_eq!(loaded_id, id);
        let pk = loaded.public_key(&id).await.unwrap();
        let (ct, ss1) = crate::crypto::encapsulate(&pk).unwrap();
        let ss2 = loaded.decapsulate(&id, &ct).await.unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}
