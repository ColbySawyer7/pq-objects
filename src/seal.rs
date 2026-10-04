//! Sync byte seal/open API (no object backend).
//!
//! Use this when storage is owned by another runtime — for example a
//! TypeScript Cloudflare Worker that writes ciphertext to R2:
//!
//! ```text
//! Rust/wasm:  seal(plaintext) -> PQOS bytes
//! JS/Worker:  env.MY_BUCKET.put(key, ciphertext)
//! JS/Worker:  ciphertext = await env.MY_BUCKET.get(key)
//! Rust/wasm:  open(ciphertext) -> plaintext
//! ```
//!
//! For the full TypeScript Worker cookbook (init, secrets, PUT/GET handlers),
//! see the crate root docs: [pq_objectstore](crate).
//!
//! When building for the browser / Workers, enable the [`crate::wasm`] module
//! (`--features wasm`) instead of calling these Rust functions directly.
use crate::crypto::cipher::{DataEncryptionKey, unwrap_dek, wrap_dek};
use crate::crypto::kem::{self, PublicKey, SecretKey};
use crate::crypto::stream::{
    CHUNK_PLAINTEXT_SIZE, decrypt_chunk, encrypt_chunk, generate_stream_nonce_prefix,
};
use crate::crypto::{CipherSuite, encapsulate};
use crate::error::{Error, Result};
use crate::format::{ObjectHeader, encode_chunk_frame, read_chunk_frame};
use crate::key::KeyId;

/// Result metadata from [`seal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealInfo {
    /// Key ID written into the object header.
    pub key_id: KeyId,
    /// Cipher suite used.
    pub suite: CipherSuite,
    /// Total ciphertext length in bytes.
    pub ciphertext_len: usize,
}

/// Encrypt `plaintext` into a versioned PQOS object.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if encapsulation or encryption fails, or
/// [`Error::Config`] if `key_id` is invalid when constructed elsewhere.
///
/// # Security
///
/// Generates a fresh DEK per call. Ciphertexts for identical plaintexts differ.
///
/// # Examples
///
/// ```
/// use pq_objectstore::crypto::generate_keypair;
/// use pq_objectstore::key::KeyId;
/// use pq_objectstore::seal::{open, seal};
///
/// let (secret, public) = generate_keypair();
/// let key_id = KeyId::new("workspace-a-v1").unwrap();
/// let ct = seal(b"hello", &public, &key_id).unwrap();
/// assert_eq!(open(&ct, &secret).unwrap(), b"hello");
/// ```
pub fn seal(plaintext: &[u8], recipient: &PublicKey, key_id: &KeyId) -> Result<Vec<u8>> {
    let (kem_ct, shared) = encapsulate(recipient)?;
    let dek = DataEncryptionKey::generate();

    let header_for_aad = ObjectHeader::new_v1(
        key_id.clone(),
        kem_ct.clone(),
        [0u8; 12],
        [0u8; 48],
        [0u8; 8],
    );
    let aad = header_for_aad.aad();
    let (wrap_nonce, wrapped_dek) = wrap_dek(&shared, &dek, &aad)?;
    let stream_prefix = generate_stream_nonce_prefix();

    let header = ObjectHeader::new_v1(
        key_id.clone(),
        kem_ct,
        wrap_nonce,
        wrapped_dek,
        stream_prefix,
    );
    debug_assert_eq!(header.aad(), aad);

    let mut out = header.encode();
    let mut offset = 0usize;
    let mut counter = 0u32;

    if plaintext.is_empty() {
        let ct = encrypt_chunk(&dek, &stream_prefix, counter, true, &[], &aad)?;
        out.extend_from_slice(&encode_chunk_frame(&ct)?);
        return Ok(out);
    }

    while offset < plaintext.len() {
        let remaining = plaintext.len() - offset;
        let take = remaining.min(CHUNK_PLAINTEXT_SIZE);
        let is_final = take == remaining;
        let chunk = &plaintext[offset..offset + take];
        let ct = encrypt_chunk(&dek, &stream_prefix, counter, is_final, chunk, &aad)?;
        out.extend_from_slice(&encode_chunk_frame(&ct)?);
        offset += take;
        if !is_final {
            counter = counter
                .checked_add(1)
                .ok_or_else(|| Error::crypto("chunk counter overflow"))?;
        }
    }

    Ok(out)
}

/// Encrypt and return ciphertext plus seal metadata.
pub fn seal_with_info(
    plaintext: &[u8],
    recipient: &PublicKey,
    key_id: &KeyId,
) -> Result<(Vec<u8>, SealInfo)> {
    let ciphertext = seal(plaintext, recipient, key_id)?;
    Ok((
        ciphertext.clone(),
        SealInfo {
            key_id: key_id.clone(),
            suite: CipherSuite::MlKem768Aes256GcmV1,
            ciphertext_len: ciphertext.len(),
        },
    ))
}

/// Decrypt a PQOS object using the recipient's ML-KEM secret seed.
///
/// # Errors
///
/// Returns [`Error::InvalidHeader`] / [`Error::UnsupportedVersion`] for bad
/// framing, or [`Error::AuthenticationFailed`] if the ciphertext was modified
/// or `secret` does not match the encapsulating public key.
pub fn open(ciphertext: &[u8], secret: &SecretKey) -> Result<Vec<u8>> {
    let (header, body) = ObjectHeader::decode(ciphertext)?;
    let shared = kem::decapsulate(secret, &header.kem_ciphertext)?;
    decrypt_body(&header, body, &shared)
}

/// Read the object header without decrypting the payload.
///
/// Useful for key rotation: inspect [`ObjectHeader::key_id`] then select the
/// matching secret before calling [`open`].
pub fn peek_header(ciphertext: &[u8]) -> Result<ObjectHeader> {
    let (header, _) = ObjectHeader::decode(ciphertext)?;
    Ok(header)
}

fn decrypt_body(
    header: &ObjectHeader,
    mut body: &[u8],
    shared: &kem::SharedSecret,
) -> Result<Vec<u8>> {
    let aad = header.aad();
    let dek = unwrap_dek(shared, &header.wrap_nonce, &header.wrapped_dek, &aad)?;

    let mut plaintext = Vec::new();
    let mut counter = 0u32;
    loop {
        let Some(frame) = read_chunk_frame(&mut body)? else {
            return Err(Error::invalid_header("missing final stream chunk"));
        };
        let is_final = body.is_empty();
        let chunk = decrypt_chunk(
            &dek,
            &header.stream_nonce_prefix,
            counter,
            is_final,
            &frame,
            &aad,
        )?;
        plaintext.extend_from_slice(&chunk);
        if is_final {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::crypto("chunk counter overflow"))?;
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn seal_open_round_trip() {
        let (sk, pk) = generate_keypair();
        let id = KeyId::new("k1").unwrap();
        let ct = seal(b"payload", &pk, &id).unwrap();
        assert_eq!(&ct[..4], b"PQOS");
        assert_eq!(open(&ct, &sk).unwrap(), b"payload");
        assert_eq!(peek_header(&ct).unwrap().key_id, id);
    }

    #[test]
    fn seal_empty_and_chunk_boundary() {
        let (sk, pk) = generate_keypair();
        let id = KeyId::new("k1").unwrap();
        assert!(open(&seal(b"", &pk, &id).unwrap(), &sk).unwrap().is_empty());

        let mut big = vec![9u8; CHUNK_PLAINTEXT_SIZE + 3];
        for (i, b) in big.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        assert_eq!(open(&seal(&big, &pk, &id).unwrap(), &sk).unwrap(), big);
    }

    #[test]
    fn wrong_key_fails() {
        let (_, pk) = generate_keypair();
        let (sk2, _) = generate_keypair();
        let id = KeyId::new("k1").unwrap();
        let ct = seal(b"x", &pk, &id).unwrap();
        assert!(matches!(open(&ct, &sk2), Err(Error::AuthenticationFailed)));
    }
}
