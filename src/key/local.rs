//! Local filesystem / in-memory ML-KEM key provider.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::crypto::kem::{self, SecretKey};
use crate::crypto::{PublicKey, SharedSecret, generate_keypair};
use crate::error::{Error, Result};
use crate::key::KeyId;

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

#[cfg(not(target_arch = "wasm32"))]
use crate::crypto::kem::{PUBLIC_KEY_LEN, SEED_LEN};

#[cfg(feature = "store")]
use crate::key::{KeyProvider, PublicKeyMaterial};
#[cfg(feature = "store")]
use async_trait::async_trait;

#[cfg(not(target_arch = "wasm32"))]
const KEY_FILE_MAGIC: &[u8; 6] = b"PQKEY\x01";

/// Public-only recipient file. The 64-byte seed is not present.
#[cfg(not(target_arch = "wasm32"))]
const RECIPIENT_FILE_MAGIC: &[u8; 6] = b"PQREC\x01";

struct KeyEntry {
    secret: Option<SecretKey>,
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
    pub fn generate(key_id: KeyId) -> Result<Self> {
        let provider = Self::new();
        provider.insert_generated(key_id)?;
        Ok(provider)
    }

    /// Insert a newly generated keypair for `key_id`.
    pub fn insert_generated(&self, key_id: KeyId) -> Result<PublicKey> {
        let (secret, public) = generate_keypair();
        self.insert(key_id, secret, public.clone())?;
        Ok(public)
    }

    /// Insert an existing seed and public key.
    pub fn insert(&self, key_id: KeyId, secret: SecretKey, public: PublicKey) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        if keys.contains_key(&key_id) {
            return Err(Error::config(format!("key id already present: {key_id}")));
        }
        keys.insert(
            key_id,
            KeyEntry {
                secret: Some(secret),
                public,
            },
        );
        Ok(())
    }

    /// Insert a public encapsulation key with no private key.
    ///
    /// The provider can encrypt to `key_id`. Decapsulation fails until a
    /// private key is inserted for the same id on a machine that holds the seed.
    pub fn insert_public(&self, key_id: KeyId, public: PublicKey) -> Result<()> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        if keys.contains_key(&key_id) {
            return Err(Error::config(format!("key id already present: {key_id}")));
        }
        keys.insert(
            key_id,
            KeyEntry {
                secret: None,
                public,
            },
        );
        Ok(())
    }

    /// Insert a key from a 64-byte seed, deriving the public key.
    pub fn insert_seed(&self, key_id: KeyId, seed: &[u8]) -> Result<PublicKey> {
        let secret = SecretKey::from_seed(seed)?;
        let (_, public) = kem::keypair_from_seed(&secret);
        self.insert(key_id, secret, public.clone())?;
        Ok(public)
    }

    /// Fetch the public key for `key_id` (sync).
    pub fn get_public_key(&self, key_id: &KeyId) -> Result<PublicKey> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        keys.get(key_id)
            .map(|e| e.public.clone())
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))
    }

    /// Borrow the secret seed for `key_id` by cloning into a new [`SecretKey`].
    pub fn get_secret_key(&self, key_id: &KeyId) -> Result<SecretKey> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        let secret = entry
            .secret
            .as_ref()
            .ok_or_else(|| Error::crypto("private key is not loaded for this key id"))?;
        SecretKey::from_seed(secret.as_bytes())
    }

    /// Decapsulate with the secret for `key_id` (sync).
    pub fn decapsulate_sync(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SharedSecret> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        let secret = entry
            .secret
            .as_ref()
            .ok_or_else(|| Error::crypto("private key is not loaded for this key id"))?;
        kem::decapsulate(secret, ciphertext)
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
    /// Unavailable on `wasm32` (no filesystem).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save_key(&self, key_id: &KeyId, path: impl AsRef<Path>) -> Result<()> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        let secret = entry
            .secret
            .as_ref()
            .ok_or_else(|| Error::crypto("private key is not loaded for this key id"))?;
        let id_bytes = key_id.as_str().as_bytes();
        let mut buf = Vec::with_capacity(6 + 2 + id_bytes.len() + SEED_LEN);
        buf.extend_from_slice(KEY_FILE_MAGIC);
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(id_bytes);
        buf.extend_from_slice(secret.as_bytes());
        std::fs::write(path, buf)?;
        Ok(())
    }

    /// Write a recipient file containing `key_id` and the public key only.
    ///
    /// Copy this file to a backup host. That host can encrypt with
    /// [`Self::load_recipient`]. The 64-byte seed stays in the key file from
    /// [`Self::save_key`] on the machine that decrypts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnknownKey`] if `key_id` is not loaded, or [`Error::Io`]
    /// if the file cannot be written.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save_recipient(&self, key_id: &KeyId, path: impl AsRef<Path>) -> Result<()> {
        let keys = self
            .keys
            .read()
            .map_err(|_| Error::crypto("key provider lock poisoned"))?;
        let entry = keys
            .get(key_id)
            .ok_or_else(|| Error::UnknownKey(key_id.to_string()))?;
        let id_bytes = key_id.as_str().as_bytes();
        let mut buf = Vec::with_capacity(6 + 2 + id_bytes.len() + PUBLIC_KEY_LEN);
        buf.extend_from_slice(RECIPIENT_FILE_MAGIC);
        buf.extend_from_slice(&(id_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(id_bytes);
        buf.extend_from_slice(entry.public.as_bytes());
        std::fs::write(path, buf)?;
        Ok(())
    }

    /// Load a recipient file written by [`Self::save_recipient`].
    ///
    /// The loaded key can encapsulate (encrypt). It cannot decapsulate.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeader`] if the file is not a recipient file, or
    /// [`Error::Config`] if the key id is already present.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_recipient(&self, path: impl AsRef<Path>) -> Result<KeyId> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < 6 + 2 + 1 + PUBLIC_KEY_LEN {
            return Err(Error::invalid_header("recipient file too short"));
        }
        if &bytes[..6] != RECIPIENT_FILE_MAGIC {
            return Err(Error::invalid_header("invalid recipient file magic"));
        }
        let id_len = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
        let id_end = 8 + id_len;
        let key_end = id_end + PUBLIC_KEY_LEN;
        if bytes.len() != key_end {
            return Err(Error::invalid_header("invalid recipient file length"));
        }
        let key_id = KeyId::new(
            std::str::from_utf8(&bytes[8..id_end])
                .map_err(|_| Error::invalid_header("key id not utf-8"))?,
        )?;
        let public = PublicKey::from_bytes(&bytes[id_end..key_end])?;
        self.insert_public(key_id.clone(), public)?;
        Ok(key_id)
    }

    /// Load a key file previously written by [`Self::save_key`].
    #[cfg(not(target_arch = "wasm32"))]
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

#[cfg(feature = "store")]
#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKeyMaterial> {
        self.get_public_key(key_id)
    }

    async fn decapsulate(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SharedSecret> {
        self.decapsulate_sync(key_id, ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_decapsulate_sync() {
        let id = KeyId::new("k1").unwrap();
        let provider = LocalKeyProvider::generate(id.clone()).unwrap();
        let pk = provider.get_public_key(&id).unwrap();
        let (ct, ss1) = crate::crypto::encapsulate(&pk).unwrap();
        let ss2 = provider.decapsulate_sync(&id, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[cfg(all(feature = "store", not(target_arch = "wasm32")))]
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

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn recipient_file_has_no_seed() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.bin");
        let recipient_path = dir.path().join("recipient.pk");
        let id = KeyId::new("backup-v1").unwrap();
        let provider = LocalKeyProvider::generate(id.clone()).unwrap();
        let seed = provider.get_secret_key(&id).unwrap();
        provider.save_key(&id, &key_path).unwrap();
        provider.save_recipient(&id, &recipient_path).unwrap();

        let recipient_bytes = std::fs::read(&recipient_path).unwrap();
        assert!(
            !recipient_bytes
                .windows(seed.as_bytes().len())
                .any(|window| window == seed.as_bytes())
        );

        let recipient = LocalKeyProvider::new();
        assert_eq!(recipient.load_recipient(&recipient_path).unwrap(), id);
        let pk = recipient.get_public_key(&id).unwrap();
        let (ct, ss1) = crate::crypto::encapsulate(&pk).unwrap();
        let err = recipient.decapsulate_sync(&id, &ct).unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));

        let full = LocalKeyProvider::new();
        full.load_key(&key_path).unwrap();
        let ss2 = full.decapsulate_sync(&id, &ct).unwrap();
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        assert!(full.load_recipient(&key_path).is_err());
    }
}
