//! [`KeyProvider`] trait for long-lived ML-KEM keys.

use async_trait::async_trait;

use crate::crypto::{PublicKey, SharedSecret};
use crate::error::Result;
use crate::key::KeyId;

/// Public key material returned by a provider.
pub type PublicKeyMaterial = PublicKey;

/// Supplies public keys for encryption and private-key operations for decryption.
///
/// Storage code never observes where private keys live. Implementations must
/// keep private key material outside object storage. A provider loaded from a
/// recipient file can encrypt; decapsulation fails until the private key is
/// loaded on the machine that decrypts.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Fetch the public encapsulation key for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownKey`] if the key ID is not available.
    async fn public_key(&self, key_id: &KeyId) -> Result<PublicKeyMaterial>;

    /// Decapsulate an ML-KEM ciphertext for `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownKey`] if the private key is unavailable,
    /// or [`crate::Error::Crypto`] if decapsulation fails.
    ///
    /// # Security
    ///
    /// The returned shared secret must be zeroized by the caller after use.
    async fn decapsulate(&self, key_id: &KeyId, ciphertext: &[u8]) -> Result<SharedSecret>;
}
