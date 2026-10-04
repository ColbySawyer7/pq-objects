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

/// Streaming body accepted by [`ObjectBackend::put`].
///
/// The lifetime lets an encrypting stream own a caller-supplied reader for the
/// duration of the put without first copying the ciphertext.
pub type BackendReader<'a> = BoxStream<'a, std::result::Result<Bytes, std::io::Error>>;

/// Ciphertext body returned by [`ObjectBackend::get`].
pub type BackendBody = Box<dyn tokio::io::AsyncRead + Send + Unpin>;

/// Metadata returned by [`ObjectBackend::head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendMetadata {
    /// Object size in bytes, if known.
    pub content_length: Option<u64>,
    /// Opaque backend entity tag, if any.
    pub etag: Option<String>,
}

/// One object returned by [`ObjectBackend::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedObject {
    /// Object key.
    pub key: String,
    /// Ciphertext size in bytes.
    pub size: u64,
}

/// One page of [`ObjectBackend::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPage {
    /// Objects in this page, in backend order.
    pub objects: Vec<ListedObject>,
    /// Opaque token for the next page. `None` when this is the last page.
    pub continuation_token: Option<String>,
}

/// Low-level untrusted object store interface.
#[async_trait]
pub trait ObjectBackend: Send + Sync {
    /// Store an object body under `key`.
    ///
    /// Returns the number of bytes written. Callers that stream ciphertext use
    /// this as the ciphertext size.
    async fn put(&self, key: &str, body: BackendReader<'_>) -> Result<u64>;

    /// Fetch an object body.
    ///
    /// The reader yields ciphertext as the backend receives it.
    async fn get(&self, key: &str) -> Result<BackendBody>;

    /// Delete an object.
    async fn delete(&self, key: &str) -> Result<()>;

    /// Fetch object metadata without returning the body.
    async fn head(&self, key: &str) -> Result<BackendMetadata>;

    /// List keys that start with `prefix`.
    ///
    /// `continuation_token` is the previous page's [`ListPage::continuation_token`].
    /// Pass `None` to start at the first key. Tokens are opaque.
    async fn list(&self, prefix: &str, continuation_token: Option<&str>) -> Result<ListPage>;
}
