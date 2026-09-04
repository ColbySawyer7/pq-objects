//! AES-256-GCM data-encryption key wrapping.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce as GcmNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::kem::SharedSecret;
use crate::error::{Error, Result};

/// Length of a data-encryption key in bytes.
pub const DEK_LEN: usize = 32;

/// Length of the AES-GCM wrap nonce in bytes.
pub const WRAP_NONCE_LEN: usize = 12;

/// Length of a wrapped DEK (ciphertext + tag).
pub const WRAPPED_DEK_LEN: usize = DEK_LEN + 16;

/// Per-object AES-256 data-encryption key.
///
/// Exists only in memory for as long as needed and is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey([u8; DEK_LEN]);

impl DataEncryptionKey {
    /// Generate a fresh random DEK from the OS CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        use rand::{TryRng, rngs::SysRng};
        let mut bytes = [0u8; DEK_LEN];
        SysRng.try_fill_bytes(&mut bytes).expect("OS RNG failed");
        Self(bytes)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != DEK_LEN {
            return Err(Error::crypto("invalid DEK length"));
        }
        let mut out = [0u8; DEK_LEN];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; DEK_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for DataEncryptionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataEncryptionKey([REDACTED])")
    }
}

/// Wrap `dek` under the ML-KEM shared secret using AES-256-GCM.
///
/// Returns `(wrap_nonce, wrapped_dek)` where `wrapped_dek` is 48 bytes.
///
/// # Security
///
/// `aad` should bind header fields (magic, version, suite, key id) so a wrapped
/// DEK cannot be transplanted into a different object header.
pub fn wrap_dek(
    shared: &SharedSecret,
    dek: &DataEncryptionKey,
    aad: &[u8],
) -> Result<([u8; WRAP_NONCE_LEN], [u8; WRAPPED_DEK_LEN])> {
    let key = Key::<Aes256Gcm>::try_from(shared.as_bytes().as_slice())
        .map_err(|_| Error::crypto("invalid wrap key"))?;
    let cipher = Aes256Gcm::new(&key);
    use rand::{TryRng, rngs::SysRng};
    let mut nonce_bytes = [0u8; WRAP_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| Error::crypto("OS RNG failed"))?;
    let nonce = GcmNonce::<aes_gcm::aead::consts::U12>::try_from(nonce_bytes.as_slice())
        .map_err(|_| Error::crypto("invalid wrap nonce"))?;

    let ct = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: dek.as_bytes(),
                aad,
            },
        )
        .map_err(|_| Error::crypto("DEK wrap failed"))?;
    if ct.len() != WRAPPED_DEK_LEN {
        return Err(Error::crypto("unexpected wrapped DEK length"));
    }
    let mut wrapped = [0u8; WRAPPED_DEK_LEN];
    wrapped.copy_from_slice(&ct);
    Ok((nonce_bytes, wrapped))
}

/// Unwrap a DEK previously produced by [`wrap_dek`].
///
/// # Errors
///
/// Returns [`Error::AuthenticationFailed`] if the ciphertext was modified or
/// the shared secret / AAD do not match.
pub fn unwrap_dek(
    shared: &SharedSecret,
    wrap_nonce: &[u8],
    wrapped_dek: &[u8],
    aad: &[u8],
) -> Result<DataEncryptionKey> {
    if wrap_nonce.len() != WRAP_NONCE_LEN || wrapped_dek.len() != WRAPPED_DEK_LEN {
        return Err(Error::invalid_header("invalid wrapped DEK framing"));
    }
    let key = Key::<Aes256Gcm>::try_from(shared.as_bytes().as_slice())
        .map_err(|_| Error::crypto("invalid wrap key"))?;
    let cipher = Aes256Gcm::new(&key);
    let nonce = GcmNonce::<aes_gcm::aead::consts::U12>::try_from(wrap_nonce)
        .map_err(|_| Error::crypto("invalid wrap nonce"))?;
    let pt = cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: wrapped_dek,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    DataEncryptionKey::from_bytes(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::generate_keypair;
    use crate::crypto::{encapsulate, kem::decapsulate};

    #[test]
    fn wrap_round_trip() {
        let (sk, pk) = generate_keypair();
        let (ct, ss) = encapsulate(&pk).unwrap();
        let ss2 = decapsulate(&sk, &ct).unwrap();
        let dek = DataEncryptionKey::generate();
        let aad = b"pqos-aad";
        let (nonce, wrapped) = wrap_dek(&ss, &dek, aad).unwrap();
        let recovered = unwrap_dek(&ss2, &nonce, &wrapped, aad).unwrap();
        assert_eq!(dek.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn wrap_aad_mismatch_fails() {
        let (_, pk) = generate_keypair();
        let (_, ss) = encapsulate(&pk).unwrap();
        let dek = DataEncryptionKey::generate();
        let (nonce, wrapped) = wrap_dek(&ss, &dek, b"aad-a").unwrap();
        let err = unwrap_dek(&ss, &nonce, &wrapped, b"aad-b").unwrap_err();
        assert!(matches!(err, Error::AuthenticationFailed));
    }
}
