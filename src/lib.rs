//! # pq-objectstore
//!
//! Post-quantum encrypted object storage for Rust.
//!
//! `pq-objectstore` encrypts data locally before writing it to an S3-compatible
//! object store — or, with the sync [`mod@seal`] API, returns PQOS ciphertext bytes
//! for another runtime (TypeScript / Cloudflare Workers) to store on R2.
//!
//! ## Quick Start (Rust store)
//!
//! ```no_run
//! # #[cfg(all(feature = "store", feature = "local-keys"))]
//! # {
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
//! # }
//! ```
//!
//! ## Quick Start (seal bytes / wasm)
//!
//! ```
//! use pq_objectstore::crypto::generate_keypair;
//! use pq_objectstore::key::KeyId;
//! use pq_objectstore::seal::{open, seal};
//!
//! let (secret, public) = generate_keypair();
//! let key_id = KeyId::new("workspace-a-v1").unwrap();
//! let ciphertext = seal(b"secret", &public, &key_id).unwrap();
//! assert_eq!(open(&ciphertext, &secret).unwrap(), b"secret");
//! ```
//!
//! ## Architecture
//!
//! Each object receives a unique AES-256-GCM data-encryption key (DEK). That DEK
//! is wrapped using an ML-KEM-768 shared secret derived from a long-lived key.
//! Object payloads use a chunked STREAM construction.
//!
//! ## Features
//!
//! - `store` (default): async [`PqObjectStore`] + backends
//! - `s3` (default): Cloudflare R2 / AWS S3 / MinIO / RustFS backend
//! - `local-keys` (default): [`key::LocalKeyProvider`]
//! - `wasm`: `wasm-bindgen` exports for Workers / Next.js (`seal` / `open`)
//! - `tracing`: optional structured logging (never logs secrets)

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

pub mod crypto;
pub mod error;
pub mod format;
pub mod key;
pub mod seal;

#[cfg(feature = "store")]
pub mod backend;
#[cfg(feature = "store")]
pub mod store;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{Error, Result};
pub use key::KeyId;
pub use seal::{SealInfo, open, peek_header, seal, seal_with_info};

#[cfg(feature = "store")]
pub use key::KeyProvider;
#[cfg(feature = "store")]
pub use store::{
    EncryptedObjectStore, EncryptedReader, ObjectMetadata, PqObjectStore, PqObjectStoreBuilder,
    PutResult,
};

#[cfg(feature = "local-keys")]
pub use key::LocalKeyProvider;
