//! Chunked AES-256-GCM STREAM construction for object payloads.
//!
//! Each plaintext chunk is at most [`CHUNK_PLAINTEXT_SIZE`] bytes. Nonces are
//! derived from an 8-byte stream prefix and a 32-bit chunk counter. The final
//! chunk sets the high bit of the counter (age/STREAM-style).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce as GcmNonce};

use super::cipher::DataEncryptionKey;
use crate::error::{Error, Result};

/// Maximum plaintext bytes per encrypted chunk.
pub const CHUNK_PLAINTEXT_SIZE: usize = 64 * 1024;

/// AES-GCM authentication tag length.
pub const TAG_LEN: usize = 16;

/// Stream nonce prefix stored in the object header.
pub const STREAM_NONCE_PREFIX_LEN: usize = 8;

/// Build a 12-byte AES-GCM nonce for chunk `counter`.
///
/// When `is_final` is true, the high bit of the counter is set.
#[must_use]
pub fn stream_nonce(
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    counter: u32,
    is_final: bool,
) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    let mut c = counter;
    if is_final {
        c |= 1 << 31;
    }
    nonce[8..].copy_from_slice(&c.to_be_bytes());
    nonce
}

/// Encrypt one plaintext chunk.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if AES-GCM encryption fails.
pub fn encrypt_chunk(
    dek: &DataEncryptionKey,
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    counter: u32,
    is_final: bool,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if plaintext.len() > CHUNK_PLAINTEXT_SIZE {
        return Err(Error::crypto("plaintext chunk exceeds maximum size"));
    }
    if !is_final && plaintext.len() != CHUNK_PLAINTEXT_SIZE {
        return Err(Error::crypto(
            "non-final chunks must be exactly CHUNK_PLAINTEXT_SIZE bytes",
        ));
    }
    let key = Key::<Aes256Gcm>::try_from(dek.as_bytes().as_slice())
        .map_err(|_| Error::crypto("invalid DEK"))?;
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = stream_nonce(prefix, counter, is_final);
    let nonce = GcmNonce::<aes_gcm::aead::consts::U12>::try_from(nonce_bytes.as_slice())
        .map_err(|_| Error::crypto("invalid stream nonce"))?;
    cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::crypto("chunk encryption failed"))
}

/// Decrypt one ciphertext chunk (including the trailing tag).
///
/// # Errors
///
/// Returns [`Error::AuthenticationFailed`] on tag mismatch or tampering.
pub fn decrypt_chunk(
    dek: &DataEncryptionKey,
    prefix: &[u8; STREAM_NONCE_PREFIX_LEN],
    counter: u32,
    is_final: bool,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::AuthenticationFailed);
    }
    let max_ct = CHUNK_PLAINTEXT_SIZE + TAG_LEN;
    if ciphertext.len() > max_ct {
        return Err(Error::invalid_header("ciphertext chunk too large"));
    }
    if !is_final && ciphertext.len() != max_ct {
        return Err(Error::AuthenticationFailed);
    }
    let key = Key::<Aes256Gcm>::try_from(dek.as_bytes().as_slice())
        .map_err(|_| Error::crypto("invalid DEK"))?;
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = stream_nonce(prefix, counter, is_final);
    let nonce = GcmNonce::<aes_gcm::aead::consts::U12>::try_from(nonce_bytes.as_slice())
        .map_err(|_| Error::crypto("invalid stream nonce"))?;
    cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)
}

/// Generate a random 8-byte stream nonce prefix.
#[must_use]
pub fn generate_stream_nonce_prefix() -> [u8; STREAM_NONCE_PREFIX_LEN] {
    use rand::{TryRng, rngs::SysRng};
    let mut prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
    SysRng.try_fill_bytes(&mut prefix).expect("OS RNG failed");
    prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::cipher::DataEncryptionKey;

    #[test]
    fn chunk_round_trip_and_tamper() {
        let dek = DataEncryptionKey::generate();
        let prefix = generate_stream_nonce_prefix();
        let aad = b"stream-aad";
        let pt = b"hello streaming world";
        let ct = encrypt_chunk(&dek, &prefix, 0, true, pt, aad).unwrap();
        let out = decrypt_chunk(&dek, &prefix, 0, true, &ct, aad).unwrap();
        assert_eq!(out, pt);

        let mut bad = ct.clone();
        bad[0] ^= 0x01;
        assert!(matches!(
            decrypt_chunk(&dek, &prefix, 0, true, &bad, aad),
            Err(Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn duplicate_encryption_differs() {
        let dek = DataEncryptionKey::generate();
        let aad = b"aad";
        let pt = vec![7u8; 100];
        let p1 = generate_stream_nonce_prefix();
        let p2 = generate_stream_nonce_prefix();
        let c1 = encrypt_chunk(&dek, &p1, 0, true, &pt, aad).unwrap();
        let c2 = encrypt_chunk(&dek, &p2, 0, true, &pt, aad).unwrap();
        assert_ne!(c1, c2);
    }
}
