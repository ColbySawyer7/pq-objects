//! Object storage backends.
//!
//! Backends are untrusted ciphertext stores. The public API does not expose
//! AWS SDK types.

mod memory;

#[cfg(feature = "s3")]
mod s3;

pub use memory::MemoryBackend;

#[cfg(feature = "s3")]
pub use s3::{S3Backend, S3BackendBuilder};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::BoxStream;

use crate::error::Result;

/// Streaming body accepted by backends.
pub type BackendReader = BoxStream<'static, std::result::Result<Bytes, std::io::Error>>;

/// Metadata returned by [`ObjectBackend::head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendMetadata {
    /// Object size in bytes, if known.
    pub content_length: Option<u64>,
    /// Opaque backend entity tag, if any.
    pub etag: Option<String>,
}

/// Low-level untrusted object store interface.
#[async_trait]
pub trait ObjectBackend: Send + Sync {
    /// Store an object body under `key`.
    async fn put(&self, key: &str, body: BackendReader) -> Result<()>;

    /// Fetch an object body.
    async fn get(&self, key: &str) -> Result<BackendReader>;

    /// Delete an object.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Fetch object metadata without returning the body.
    async fn head(&self, key: &str) -> Result<BackendMetadata>;
}
