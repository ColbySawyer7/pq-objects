//! Cryptographic primitives used by encrypted objects.
//!
//! The only suite shipped in v0.1 is [`CipherSuite::MlKem768Aes256GcmV1`]:
//! ML-KEM-768 protects a per-object AES-256-GCM data-encryption key, and
//! AES-256-GCM STREAM encrypts the object payload in fixed-size chunks.

pub(crate) mod cipher;
pub(crate) mod kem;
pub(crate) mod stream;
mod suite;

pub use cipher::{DataEncryptionKey, unwrap_dek, wrap_dek};
pub use kem::{PublicKey, SecretKey, SharedSecret, encapsulate, generate_keypair};
pub use stream::{CHUNK_PLAINTEXT_SIZE, decrypt_chunk, encrypt_chunk, stream_nonce};
pub use suite::CipherSuite;
