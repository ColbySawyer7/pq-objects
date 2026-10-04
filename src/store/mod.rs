//! High-level encrypted object store API.

mod decrypt;
mod encrypt;

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::backend::{BackendMetadata, ObjectBackend};

pub use crate::backend::{ListPage, ListedObject};
use crate::crypto::CipherSuite;
use crate::error::{Error, Result};
use crate::key::{KeyId, KeyProvider};

pub use decrypt::EncryptedReader;

/// Result of a successful encrypted put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    /// Object key that was written.
    pub key: String,
    /// Key ID used to protect the object.
    pub key_id: KeyId,
    /// Cipher suite written into the object header.
    pub suite: CipherSuite,
    /// Ciphertext size in bytes.
    ///
    /// A finished upload reports this value from [`EncryptedObjectStore::head`]
    /// as [`ObjectMetadata::content_length`]. A missing object or a different
    /// length means the upload did not finish.
    pub content_length: u64,
}

/// Object metadata visible without decrypting the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMetadata {
    /// Ciphertext size in bytes, if known.
    pub content_length: Option<u64>,
    /// Backend entity tag, if any.
    pub etag: Option<String>,
}

impl From<BackendMetadata> for ObjectMetadata {
    fn from(value: BackendMetadata) -> Self {
        Self {
            content_length: value.content_length,
            etag: value.etag,
        }
    }
}

/// Primary async trait for encrypted object operations.
#[async_trait]
pub trait EncryptedObjectStore: Send + Sync {
    /// Encrypt `reader` and store the ciphertext under `key`.
    ///
    /// Ciphertext is produced as the backend reads it. The plaintext is not
    /// copied into a temporary ciphertext file.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] on cryptographic failure, or [`Error::Backend`]
    /// if the store rejects the write.
    ///
    /// # Security
    ///
    /// A fresh data-encryption key is generated for each object.
    async fn put<R>(&self, key: &str, reader: R) -> Result<PutResult>
    where
        R: AsyncRead + Send + Unpin;

    /// Download and decrypt the object at `key`.
    ///
    /// The reader yields plaintext as STREAM frames are authenticated. It does
    /// not buffer the whole ciphertext or the whole plaintext.
    async fn get(&self, key: &str) -> Result<EncryptedReader>;

    /// Delete the object at `key`.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Fetch ciphertext metadata without decrypting.
    async fn head(&self, key: &str) -> Result<ObjectMetadata>;

    /// List ciphertext objects whose keys start with `prefix`.
    ///
    /// Pass [`ListPage::continuation_token`] from the previous page to continue.
    /// `None` starts at the first key. Each [`ListedObject::size`] is the
    /// ciphertext length.
    async fn list(&self, prefix: &str, continuation_token: Option<&str>) -> Result<ListPage>;
}

/// Post-quantum encrypted object store.
///
/// Construct with [`PqObjectStore::builder`].
pub struct PqObjectStore {
    backend: Arc<dyn ObjectBackend>,
    keys: Arc<dyn KeyProvider>,
    write_key_id: KeyId,
}

impl std::fmt::Debug for PqObjectStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqObjectStore")
            .field("write_key_id", &self.write_key_id)
            .finish_non_exhaustive()
    }
}

impl PqObjectStore {
    /// Start building a store.
    #[must_use]
    pub fn builder() -> PqObjectStoreBuilder {
        PqObjectStoreBuilder::default()
    }

    /// Key ID used for new writes.
    #[must_use]
    pub fn write_key_id(&self) -> &KeyId {
        &self.write_key_id
    }

    /// Encrypt and upload raw bytes.
    pub async fn put_bytes(&self, key: &str, bytes: impl AsRef<[u8]>) -> Result<PutResult> {
        let owned = bytes.as_ref().to_vec();
        self.put(key, std::io::Cursor::new(owned)).await
    }

    /// Download and decrypt into a byte buffer.
    ///
    /// Prefer [`Self::get_file`] for objects that should not be held in memory.
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let mut reader = self.get(key).await?;
        let mut out = Vec::new();
        reader
            .read_to_end(&mut out)
            .await
            .map_err(crate::error::error_from_io)?;
        Ok(out)
    }

    /// Encrypt and upload a filesystem file.
    ///
    /// Plaintext is read from `path` and ciphertext is streamed to the backend.
    /// A second full copy of the file is not written locally.
    pub async fn put_file(&self, key: &str, path: impl AsRef<Path>) -> Result<PutResult> {
        let file = tokio::fs::File::open(path).await?;
        self.put(key, file).await
    }

    /// Download, decrypt, and write plaintext to a filesystem path.
    ///
    /// Plaintext is written as it is decrypted, one STREAM chunk at a time.
    pub async fn get_file(&self, key: &str, path: impl AsRef<Path>) -> Result<()> {
        let mut reader = self.get(key).await?;
        let mut file = tokio::fs::File::create(path).await?;
        tokio::io::copy(&mut reader, &mut file)
            .await
            .map_err(crate::error::error_from_io)?;
        Ok(())
    }

    /// Return whether an object exists (via `head`).
    pub async fn exists(&self, key: &str) -> Result<bool> {
        match self.head(key).await {
            Ok(_) => Ok(true),
            Err(Error::Backend(msg))
                if msg.contains("not found")
                    || msg.contains("NoSuchKey")
                    || msg.contains("404") =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }
}

#[async_trait]
impl EncryptedObjectStore for PqObjectStore {
    /// Stores an encrypted object.
    ///
    /// The plaintext reader is encrypted in STREAM chunks and that ciphertext
    /// is pulled by the backend. No full ciphertext file is written first.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] if encryption fails.
    ///
    /// Returns [`Error::Backend`] if the underlying object store rejects the write.
    ///
    /// # Security
    ///
    /// A fresh data-encryption key is generated for each object.
    async fn put<R>(&self, key: &str, reader: R) -> Result<PutResult>
    where
        R: AsyncRead + Send + Unpin,
    {
        let public = self.keys.public_key(&self.write_key_id).await?;
        let stream = encrypt::CiphertextStream::start(&self.write_key_id, &public, reader)?;
        let key_id = stream.key_id().clone();
        let suite = stream.suite();
        #[cfg(feature = "tracing")]
        tracing::debug!(
            object_key = %key,
            key_id = %key_id,
            "encrypted put"
        );
        let content_length = self.backend.put(key, Box::pin(stream)).await?;
        Ok(PutResult {
            key: key.to_string(),
            key_id,
            suite,
            content_length,
        })
    }

    async fn get(&self, key: &str) -> Result<EncryptedReader> {
        let body = self.backend.get(key).await?;
        decrypt::open_body(self.keys.as_ref(), body).await
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMetadata> {
        self.backend.head(key).await.map(ObjectMetadata::from)
    }

    async fn list(&self, prefix: &str, continuation_token: Option<&str>) -> Result<ListPage> {
        self.backend.list(prefix, continuation_token).await
    }
}

/// Builder for [`PqObjectStore`].
#[derive(Default)]
pub struct PqObjectStoreBuilder {
    backend: Option<Arc<dyn ObjectBackend>>,
    keys: Option<Arc<dyn KeyProvider>>,
    key_id: Option<Result<KeyId>>,
}

impl PqObjectStoreBuilder {
    /// Set the untrusted object backend.
    #[must_use]
    pub fn backend(mut self, backend: impl ObjectBackend + 'static) -> Self {
        self.backend = Some(Arc::new(backend));
        self
    }

    /// Set a shared backend handle.
    #[must_use]
    pub fn backend_arc(mut self, backend: Arc<dyn ObjectBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    /// Set the key provider used for encapsulation / decapsulation.
    #[must_use]
    pub fn key_provider(mut self, keys: impl KeyProvider + 'static) -> Self {
        self.keys = Some(Arc::new(keys));
        self
    }

    /// Set a shared key provider handle.
    #[must_use]
    pub fn key_provider_arc(mut self, keys: Arc<dyn KeyProvider>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Set the key ID used for new writes.
    ///
    /// Reads still honor the key ID embedded in each object header.
    ///
    /// # Errors
    ///
    /// Invalid key IDs are reported when [`Self::build`] is called.
    #[must_use]
    pub fn key_id(mut self, key_id: impl AsRef<str>) -> Self {
        self.key_id = Some(KeyId::new(key_id));
        self
    }

    /// Set a pre-validated key ID used for new writes.
    #[must_use]
    pub fn key_id_validated(mut self, key_id: KeyId) -> Self {
        self.key_id = Some(Ok(key_id));
        self
    }

    /// Build the store.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if backend, key provider, or key ID is missing.
    pub fn build(self) -> Result<PqObjectStore> {
        Ok(PqObjectStore {
            backend: self
                .backend
                .ok_or_else(|| Error::config("backend is required"))?,
            keys: self
                .keys
                .ok_or_else(|| Error::config("key provider is required"))?,
            write_key_id: self
                .key_id
                .ok_or_else(|| Error::config("key_id is required"))??,
        })
    }
}

#[cfg(all(test, feature = "local-keys"))]
mod tests {
    use super::*;
    use crate::backend::MemoryBackend;
    use crate::crypto::stream::CHUNK_PLAINTEXT_SIZE;
    use crate::key::LocalKeyProvider;

    async fn test_store() -> PqObjectStore {
        let key_id = KeyId::new("workspace-a-v1").unwrap();
        let keys = LocalKeyProvider::generate(key_id.clone()).unwrap();
        PqObjectStore::builder()
            .backend(MemoryBackend::new())
            .key_provider(keys)
            .key_id_validated(key_id)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn put_get_round_trip() {
        let store = test_store().await;
        store
            .put_bytes("agents/1/mem.bin", b"hello pq")
            .await
            .unwrap();
        let out = store.get_bytes("agents/1/mem.bin").await.unwrap();
        assert_eq!(out, b"hello pq");
    }

    #[tokio::test]
    async fn zero_length_object() {
        let store = test_store().await;
        store.put_bytes("empty", b"").await.unwrap();
        let out = store.get_bytes("empty").await.unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn backend_never_receives_plaintext() {
        let backend = Arc::new(MemoryBackend::new());
        let key_id = KeyId::new("workspace-a-v1").unwrap();
        let keys = LocalKeyProvider::generate(key_id.clone()).unwrap();
        let store = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider(keys)
            .key_id_validated(key_id)
            .build()
            .unwrap();

        let marker = b"PLAINTEXT_SECRET_MARKER_42";
        store.put_bytes("obj", marker).await.unwrap();
        let raw = backend.get_raw("obj").expect("stored");
        assert!(!raw.windows(marker.len()).any(|w| w == marker));
        assert_eq!(&raw[..4], b"PQOS");
        let recovered = store.get_bytes("obj").await.unwrap();
        assert_eq!(recovered, marker);
    }

    #[tokio::test]
    async fn modified_ciphertext_fails() {
        let backend = Arc::new(MemoryBackend::new());
        let key_id = KeyId::new("k").unwrap();
        let keys = LocalKeyProvider::generate(key_id.clone()).unwrap();
        let store = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider(keys)
            .key_id_validated(key_id)
            .build()
            .unwrap();
        store.put_bytes("obj", b"data").await.unwrap();
        let mut raw = backend.get_raw("obj").unwrap().to_vec();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        let stream = futures::stream::once(async move {
            Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(raw))
        });
        backend.put("obj", Box::pin(stream)).await.unwrap();
        let err = store.get_bytes("obj").await.unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    #[tokio::test]
    async fn key_rotation_reads_old_key() {
        let backend = Arc::new(MemoryBackend::new());
        let keys = LocalKeyProvider::new();
        let v1 = KeyId::new("workspace-123-v1").unwrap();
        let v2 = KeyId::new("workspace-123-v2").unwrap();
        keys.insert_generated(v1.clone()).unwrap();
        keys.insert_generated(v2.clone()).unwrap();
        let keys = Arc::new(keys);

        let store_v1 = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider_arc(keys.clone())
            .key_id_validated(v1)
            .build()
            .unwrap();
        store_v1.put_bytes("obj", b"old").await.unwrap();

        let store_v2 = PqObjectStore::builder()
            .backend_arc(backend)
            .key_provider_arc(keys)
            .key_id_validated(v2)
            .build()
            .unwrap();
        let out = store_v2.get_bytes("obj").await.unwrap();
        assert_eq!(out, b"old");
        store_v2.put_bytes("obj2", b"new").await.unwrap();
        assert_eq!(store_v2.get_bytes("obj2").await.unwrap(), b"new");
    }

    #[tokio::test]
    async fn unique_ciphertext_per_put() {
        let backend = Arc::new(MemoryBackend::new());
        let key_id = KeyId::new("k").unwrap();
        let keys = LocalKeyProvider::generate(key_id.clone()).unwrap();
        let store = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider(keys)
            .key_id_validated(key_id)
            .build()
            .unwrap();
        store.put_bytes("a", b"same").await.unwrap();
        store.put_bytes("b", b"same").await.unwrap();
        let a = backend.get_raw("a").unwrap();
        let b = backend.get_raw("b").unwrap();
        assert_ne!(a, b);
    }

    #[tokio::test]
    async fn large_chunk_boundary() {
        let store = test_store().await;
        for size in [CHUNK_PLAINTEXT_SIZE, CHUNK_PLAINTEXT_SIZE + 100] {
            let mut data = vec![0u8; size];
            for (i, b) in data.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            let key = format!("big-{size}");
            store.put_bytes(&key, &data).await.unwrap();
            let out = store.get_bytes(&key).await.unwrap();
            assert_eq!(out, data);
        }
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let backend = Arc::new(MemoryBackend::new());
        let id1 = KeyId::new("a-v1").unwrap();
        let keys1 = LocalKeyProvider::generate(id1.clone()).unwrap();
        let store1 = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider(keys1)
            .key_id_validated(id1.clone())
            .build()
            .unwrap();
        store1.put_bytes("obj", b"secret").await.unwrap();

        let keys2 = LocalKeyProvider::generate(id1).unwrap();
        let store2 = PqObjectStore::builder()
            .backend_arc(backend)
            .key_provider(keys2)
            .key_id("a-v1")
            .build()
            .unwrap();
        let err = store2.get_bytes("obj").await.unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }

    #[tokio::test]
    async fn delete_and_head() {
        let store = test_store().await;
        store.put_bytes("x", b"y").await.unwrap();
        assert!(store.exists("x").await.unwrap());
        let meta = store.head("x").await.unwrap();
        assert!(meta.content_length.unwrap() > 4);
        store.delete("x").await.unwrap();
        assert!(!store.exists("x").await.unwrap());
    }

    #[tokio::test]
    async fn put_reports_ciphertext_len() {
        let store = test_store().await;
        let put = store.put_bytes("obj", b"payload").await.unwrap();
        let meta = store.head("obj").await.unwrap();
        assert_eq!(Some(put.content_length), meta.content_length);
        assert!(put.content_length > b"payload".len() as u64);
    }

    #[tokio::test]
    async fn list_prefix_returns_ciphertext_sizes() {
        let store = test_store().await;
        let a = store.put_bytes("backups/a", b"one").await.unwrap();
        let b = store.put_bytes("backups/b", b"two-two").await.unwrap();
        store.put_bytes("other/c", b"skip").await.unwrap();
        let page = store.list("backups/", None).await.unwrap();
        assert!(page.continuation_token.is_none());
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "backups/a");
        assert_eq!(page.objects[0].size, a.content_length);
        assert_eq!(page.objects[1].key, "backups/b");
        assert_eq!(page.objects[1].size, b.content_length);
    }

    #[tokio::test]
    async fn file_round_trip_streams_plaintext() {
        let store = test_store().await;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("in.bin");
        let dst = dir.path().join("out.bin");
        let mut data = vec![0u8; CHUNK_PLAINTEXT_SIZE * 2 + 50];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        tokio::fs::write(&src, &data).await.unwrap();
        let put = store.put_file("archive", &src).await.unwrap();
        assert!(put.content_length > data.len() as u64);
        let meta = store.head("archive").await.unwrap();
        assert_eq!(Some(put.content_length), meta.content_length);
        store.get_file("archive", &dst).await.unwrap();
        let out = tokio::fs::read(&dst).await.unwrap();
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn recipient_can_encrypt_but_not_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("host.key");
        let recipient_path = dir.path().join("backup.pk");
        let id = KeyId::new("sunday-backup").unwrap();
        let owner = LocalKeyProvider::generate(id.clone()).unwrap();
        owner.save_key(&id, &key_path).unwrap();
        owner.save_recipient(&id, &recipient_path).unwrap();

        let backend = Arc::new(MemoryBackend::new());
        let recipient = LocalKeyProvider::new();
        recipient.load_recipient(&recipient_path).unwrap();
        let backup = PqObjectStore::builder()
            .backend_arc(backend.clone())
            .key_provider(recipient)
            .key_id_validated(id.clone())
            .build()
            .unwrap();
        backup.put_bytes("db", b"influx").await.unwrap();
        let err = backup.get_bytes("db").await.unwrap_err();
        assert!(matches!(err, Error::Crypto(_)));

        let restore_keys = LocalKeyProvider::new();
        restore_keys.load_key(&key_path).unwrap();
        let restore = PqObjectStore::builder()
            .backend_arc(backend)
            .key_provider(restore_keys)
            .key_id_validated(id)
            .build()
            .unwrap();
        assert_eq!(restore.get_bytes("db").await.unwrap(), b"influx");
    }
}
