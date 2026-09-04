//! # pq-objectstore
//!
//! Post-quantum encrypted object storage for Rust.
//!
//! `pq-objectstore` encrypts data locally before writing it to an S3-compatible
//! object store. The storage provider is treated as an **untrusted ciphertext
//! store**.
//!
//! ## Quick Start
//!
//! ```no_run
//! use pq_objectstore::{
//!     PqObjectStore,
//!     backend::MemoryBackend,
//!     key::{KeyId, LocalKeyProvider},
//! };
//!
//! # async fn example() -> pq_objectstore::Result<()> {
//! let key_id = KeyId::new("workspace-a-v1")?;
//! let keys = LocalKeyProvider::generate(key_id.clone())?;
//!
//! let store = PqObjectStore::builder()
//!     .backend(MemoryBackend::new())
//!     .key_provider(keys)
//!     .key_id_validated(key_id)
//!     .build()?;
//!
//! store.put_bytes("agents/123/memory.bin", b"secret").await?;
//! let plaintext = store.get_bytes("agents/123/memory.bin").await?;
//! assert_eq!(plaintext, b"secret");
//! # Ok(())
//! # }
//! ```
//!
//! ## Architecture
//!
//! Each object receives a unique AES-256-GCM data-encryption key (DEK). That DEK
//! is wrapped using an ML-KEM-768 shared secret derived from a long-lived key
//! supplied by a [`KeyProvider`]. Object payloads are encrypted with a chunked
//! STREAM construction so large objects can be processed with bounded memory at
//! the crypto layer.
//!
//! ## Security Model
//!
//! The backend learns ciphertext, object keys/paths, and sizes — not plaintext
//! contents or data-encryption keys. See `SECURITY.md` for the full threat
//! model.
//!
//! ## Key Management
//!
//! Private ML-KEM keys are supplied through a [`KeyProvider`]. The initial
//! implementation is [`key::LocalKeyProvider`]. Writes use the configured active
//! key ID; reads resolve the key ID recorded in each object header, enabling
//! rotation without rewriting historical objects.
//!
//! ## Object Format
//!
//! Encrypted objects begin with a versioned `PQOS` header. The binary layout is
//! documented in [`mod@format`].
//!
//! ## Features
//!
//! - `s3` (default): Cloudflare R2 / AWS S3 / MinIO / RustFS backend
//! - `local-keys` (default): [`key::LocalKeyProvider`]
//! - `tracing`: optional structured logging (never logs secrets)
//!
//! ## Examples
//!
//! See the `examples` directory for R2, MinIO, and local-key walkthroughs.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod backend;
pub mod crypto;
pub mod error;
pub mod format;
pub mod key;
pub mod store;

pub use error::{Error, Result};
pub use key::{KeyId, KeyProvider};
pub use store::{
    EncryptedObjectStore, EncryptedReader, ObjectMetadata, PqObjectStore, PqObjectStoreBuilder,
    PutResult,
};

#[cfg(feature = "local-keys")]
pub use key::LocalKeyProvider;
