//! In-memory object backend for tests and local embedding.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;

use super::{BackendMetadata, BackendReader, ObjectBackend};
use crate::error::{Error, Result};

/// Thread-safe in-memory object store.
///
/// Useful for unit tests and verifying that plaintext never reaches the
/// backend.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    objects: Mutex<HashMap<String, Bytes>>,
}

impl MemoryBackend {
    /// Create an empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return a snapshot of stored object bytes for testing.
    pub fn get_raw(&self, key: &str) -> Option<Bytes> {
        self.objects.lock().ok().and_then(|g| g.get(key).cloned())
    }

    /// List all object keys currently stored.
    pub fn keys(&self) -> Vec<String> {
        self.objects
            .lock()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default()
    }
}

#[async_trait]
impl ObjectBackend for MemoryBackend {
    async fn put(&self, key: &str, mut body: BackendReader) -> Result<()> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(Error::from)?;
            buf.extend_from_slice(&chunk);
        }
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        objects.insert(key.to_string(), Bytes::from(buf));
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<BackendReader> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        let bytes = objects
            .get(key)
            .cloned()
            .ok_or_else(|| Error::backend(format!("object not found: {key}")))?;
        let stream = futures::stream::once(async move { Ok::<Bytes, std::io::Error>(bytes) });
        Ok(Box::pin(stream))
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        objects.remove(key);
        Ok(())
    }

    async fn head(&self, key: &str) -> Result<BackendMetadata> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        let bytes = objects
            .get(key)
            .ok_or_else(|| Error::backend(format!("object not found: {key}")))?;
        Ok(BackendMetadata {
            content_length: Some(bytes.len() as u64),
            etag: None,
        })
    }
}
