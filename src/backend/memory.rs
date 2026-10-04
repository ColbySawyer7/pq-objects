//! In-memory object backend for tests and local embedding.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;

use super::{BackendBody, BackendMetadata, BackendReader, ListPage, ListedObject, ObjectBackend};
use crate::error::{Error, Result};

/// Keys returned by one [`MemoryBackend`] list call.
const LIST_PAGE_SIZE: usize = 1000;

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
    async fn put(&self, key: &str, mut body: BackendReader<'_>) -> Result<u64> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(crate::error::error_from_io)?;
            buf.extend_from_slice(&chunk);
        }
        let len = buf.len() as u64;
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        objects.insert(key.to_string(), Bytes::from(buf));
        Ok(len)
    }

    async fn get(&self, key: &str) -> Result<BackendBody> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        let bytes = objects
            .get(key)
            .cloned()
            .ok_or_else(|| Error::backend(format!("object not found: {key}")))?;
        Ok(Box::new(std::io::Cursor::new(bytes)))
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

    async fn list(&self, prefix: &str, continuation_token: Option<&str>) -> Result<ListPage> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| Error::backend("memory backend lock poisoned"))?;
        let entries = objects
            .iter()
            .map(|(key, bytes)| (key.clone(), bytes.len() as u64))
            .collect::<Vec<_>>();
        drop(objects);
        Ok(list_page(
            &entries,
            prefix,
            continuation_token,
            LIST_PAGE_SIZE,
        ))
    }
}

pub(crate) fn list_page(
    entries: &[(String, u64)],
    prefix: &str,
    continuation_token: Option<&str>,
    page_size: usize,
) -> ListPage {
    let mut matched = entries
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .collect::<Vec<_>>();
    matched.sort_by(|a, b| a.0.cmp(&b.0));

    let start = match continuation_token {
        None => 0,
        Some(token) => match matched.iter().position(|(key, _)| key.as_str() == token) {
            Some(index) => index + 1,
            None => matched
                .iter()
                .position(|(key, _)| key.as_str() > token)
                .unwrap_or(matched.len()),
        },
    };

    if page_size == 0 || start >= matched.len() {
        return ListPage {
            objects: Vec::new(),
            continuation_token: None,
        };
    }

    let end = (start + page_size).min(matched.len());
    let objects = matched[start..end]
        .iter()
        .map(|(key, size)| ListedObject {
            key: (*key).clone(),
            size: *size,
        })
        .collect();
    let continuation_token = if end < matched.len() {
        Some(matched[end - 1].0.clone())
    } else {
        None
    };
    ListPage {
        objects,
        continuation_token,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_pages_by_prefix() {
        let entries = vec![
            ("p/a".to_string(), 1),
            ("p/c".to_string(), 3),
            ("q/d".to_string(), 4),
            ("p/b".to_string(), 2),
        ];
        let page = list_page(&entries, "p/", None, 2);
        assert_eq!(
            page.objects,
            vec![
                ListedObject {
                    key: "p/a".to_string(),
                    size: 1,
                },
                ListedObject {
                    key: "p/b".to_string(),
                    size: 2,
                },
            ]
        );
        let page = list_page(&entries, "p/", page.continuation_token.as_deref(), 2);
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "p/c");
        assert_eq!(page.objects[0].size, 3);
        assert!(page.continuation_token.is_none());
    }
}
