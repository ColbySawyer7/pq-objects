//! High-level encrypted object store API.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::StreamExt;
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

use crate::backend::{BackendMetadata, ObjectBackend};
use crate::crypto::cipher::{DataEncryptionKey, wrap_dek};
use crate::crypto::stream::{CHUNK_PLAINTEXT_SIZE, encrypt_chunk, generate_stream_nonce_prefix};
use crate::crypto::{CipherSuite, encapsulate};
use crate::error::{Error, Result};
use crate::format::{ObjectHeader, encode_chunk_frame};
use crate::key::{KeyId, KeyProvider};

/// Result of a successful encrypted put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutResult {
    /// Object key that was written.
    pub key: String,
    /// Key ID used to protect the object.
    pub key_id: KeyId,
    /// Cipher suite written into the object header.
    pub suite: CipherSuite,
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
    async fn get(&self, key: &str) -> Result<EncryptedReader>;

    /// Delete the object at `key`.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Fetch ciphertext metadata without decrypting.
    async fn head(&self, key: &str) -> Result<ObjectMetadata>;
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
        let public = self.keys.public_key(&self.write_key_id).await?;
        let ciphertext = crate::seal::seal(bytes.as_ref(), &public, &self.write_key_id)?;
        let stream = futures::stream::once(async move {
            Ok::<bytes::Bytes, std::io::Error>(bytes::Bytes::from(ciphertext))
        });
        self.backend.put(key, Box::pin(stream)).await?;
        Ok(PutResult {
            key: key.to_string(),
            key_id: self.write_key_id.clone(),
            suite: CipherSuite::MlKem768Aes256GcmV1,
        })
    }

    /// Download and decrypt into a byte buffer.
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>> {
        let mut reader = self.get(key).await?;
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await?;
        Ok(out)
    }

    /// Encrypt and upload a filesystem file.
    pub async fn put_file(&self, key: &str, path: impl AsRef<Path>) -> Result<PutResult> {
        let file = tokio::fs::File::open(path).await?;
        self.put(key, file).await
    }

    /// Download, decrypt, and write to a filesystem path.
    pub async fn get_file(&self, key: &str, path: impl AsRef<Path>) -> Result<()> {
        let mut reader = self.get(key).await?;
        let mut file = tokio::fs::File::create(path).await?;
        tokio::io::copy(&mut reader, &mut file).await?;
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

    async fn encrypt_to_tempfile<R>(
        &self,
        mut reader: R,
    ) -> Result<(ObjectHeader, tempfile::NamedTempFile)>
    where
        R: AsyncRead + Send + Unpin,
    {
        use tokio::io::AsyncWriteExt;

        let public = self.keys.public_key(&self.write_key_id).await?;
        let (kem_ct, shared) = encapsulate(&public)?;
        let dek = DataEncryptionKey::generate();

        let header_for_aad = ObjectHeader::new_v1(
            self.write_key_id.clone(),
            kem_ct.clone(),
            [0u8; 12],
            [0u8; 48],
            [0u8; 8],
        );
        let aad = header_for_aad.aad();
        let (wrap_nonce, wrapped_dek) = wrap_dek(&shared, &dek, &aad)?;
        let stream_prefix = generate_stream_nonce_prefix();

        let header = ObjectHeader::new_v1(
            self.write_key_id.clone(),
            kem_ct,
            wrap_nonce,
            wrapped_dek,
            stream_prefix,
        );
        debug_assert_eq!(header.aad(), aad);

        let tmp = tempfile::NamedTempFile::new()?;
        let mut writer = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(tmp.path())
            .await?;
        writer.write_all(&header.encode()).await?;

        let mut buf = vec![0u8; CHUNK_PLAINTEXT_SIZE];
        let mut filled = 0usize;
        let mut counter = 0u32;

        loop {
            let n = reader.read(&mut buf[filled..]).await?;
            if n == 0 {
                let ct = encrypt_chunk(&dek, &stream_prefix, counter, true, &buf[..filled], &aad)?;
                writer.write_all(&encode_chunk_frame(&ct)?).await?;
                break;
            }
            filled += n;
            if filled == CHUNK_PLAINTEXT_SIZE {
                let ct = encrypt_chunk(&dek, &stream_prefix, counter, false, &buf[..], &aad)?;
                writer.write_all(&encode_chunk_frame(&ct)?).await?;
                counter = counter
                    .checked_add(1)
                    .ok_or_else(|| Error::crypto("chunk counter overflow"))?;
                filled = 0;
            }
        }
        writer.flush().await?;
        drop(writer);

        Ok((header, tmp))
    }

    async fn decrypt_object(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let header = crate::seal::peek_header(ciphertext)?;
        let shared = self
            .keys
            .decapsulate(&header.key_id, &header.kem_ciphertext)
            .await?;
        crate::seal::open_with_shared(ciphertext, &shared)
    }
}

#[async_trait]
impl EncryptedObjectStore for PqObjectStore {
    /// Stores an encrypted object.
    ///
    /// The input stream is encrypted before any object data is transmitted to
    /// the backing object store.
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
        let (header, tmp) = self.encrypt_to_tempfile(reader).await?;
        // Encryption used bounded chunk memory and spilled ciphertext to a
        // tempfile. Backends may still buffer the body for Content-Length;
        // multipart upload is a follow-up for fully constant-RAM S3 puts.
        let file = tokio::fs::File::open(tmp.path()).await?;
        let stream = tokio_util::io::ReaderStream::new(file);
        #[cfg(feature = "tracing")]
        tracing::debug!(
            object_key = %key,
            key_id = %header.key_id,
            format_version = header.version,
            "encrypted put"
        );
        self.backend.put(key, Box::pin(stream)).await?;
        // Keep tempfile alive until upload finishes.
        drop(tmp);
        Ok(PutResult {
            key: key.to_string(),
            key_id: header.key_id,
            suite: header.suite,
        })
    }

    async fn get(&self, key: &str) -> Result<EncryptedReader> {
        let mut body = self.backend.get(key).await?;
        let mut ciphertext = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(Error::from)?;
            ciphertext.extend_from_slice(&chunk);
        }
        let (header, _) = ObjectHeader::decode(&ciphertext)?;
        let plaintext = self.decrypt_object(&ciphertext).await?;
        Ok(EncryptedReader {
            inner: std::io::Cursor::new(plaintext),
            header: Some(header),
        })
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    async fn head(&self, key: &str) -> Result<ObjectMetadata> {
        self.backend.head(key).await.map(ObjectMetadata::from)
    }
}

/// Decrypting reader returned by [`PqObjectStore::get`].
///
/// Currently buffers decrypted plaintext after download. The public type is an
/// [`AsyncRead`] so callers can treat it as a stream.
pub struct EncryptedReader {
    inner: std::io::Cursor<Vec<u8>>,
    header: Option<ObjectHeader>,
}

impl EncryptedReader {
    /// Object header parsed from the ciphertext.
    #[must_use]
    pub fn header(&self) -> Option<&ObjectHeader> {
        self.header.as_ref()
    }
}

impl AsyncRead for EncryptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match std::io::Read::read(&mut self.inner, unfilled) {
            Ok(n) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
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
        // overwrite
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
        let mut data = vec![0u8; CHUNK_PLAINTEXT_SIZE + 100];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        store.put_bytes("big", &data).await.unwrap();
        let out = store.get_bytes("big").await.unwrap();
        assert_eq!(out, data);
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
}
