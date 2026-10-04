//! Binary object header encoding and decoding.
//!
//! # Format version 1
//!
//! ```text
//! magic[4] = b"PQOS"
//! version:   u16 BE
//! suite:     u16 BE
//! key_id_len:u16 BE
//! key_id:    [u8; key_id_len]
//! kem_ct_len:u16 BE
//! kem_ct:    [u8; kem_ct_len]
//! wrap_nonce:[u8; 12]
//! wrapped_dek:[u8; 48]
//! stream_nonce_prefix:[u8; 8]
//! ```
//!
//! Each encrypted chunk is then framed as:
//!
//! ```text
//! chunk_len: u32 BE   // ciphertext length including 16-byte tag
//! chunk_ct:  [u8; chunk_len]
//! ```
//!
//! The final STREAM chunk is indicated by the high bit of the AES-GCM nonce
//! counter (see [`crate::crypto::stream`]).

use std::io::{Read, Write};

use crate::crypto::CipherSuite;
use crate::crypto::cipher::{WRAP_NONCE_LEN, WRAPPED_DEK_LEN};
use crate::crypto::kem::CIPHERTEXT_LEN;
use crate::crypto::stream::STREAM_NONCE_PREFIX_LEN;
use crate::error::{Error, Result};
use crate::key::KeyId;

/// Object format magic bytes.
pub const MAGIC: &[u8; 4] = b"PQOS";

/// Current object format version written by this crate.
pub const FORMAT_VERSION: u16 = 1;

/// Maximum accepted key ID length on the wire.
pub const MAX_KEY_ID_LEN: usize = 256;

/// Parsed object header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectHeader {
    /// Format version.
    pub version: u16,
    /// Cipher suite identifier.
    pub suite: CipherSuite,
    /// Key ID used to protect the object DEK.
    pub key_id: KeyId,
    /// ML-KEM ciphertext protecting the wrap key.
    pub kem_ciphertext: Vec<u8>,
    /// Nonce used when wrapping the DEK.
    pub wrap_nonce: [u8; WRAP_NONCE_LEN],
    /// AES-GCM ciphertext+tag of the DEK.
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// 8-byte prefix for STREAM chunk nonces.
    pub stream_nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
}

impl ObjectHeader {
    /// Construct a v1 header for the default suite.
    #[must_use]
    pub fn new_v1(
        key_id: KeyId,
        kem_ciphertext: Vec<u8>,
        wrap_nonce: [u8; WRAP_NONCE_LEN],
        wrapped_dek: [u8; WRAPPED_DEK_LEN],
        stream_nonce_prefix: [u8; STREAM_NONCE_PREFIX_LEN],
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            suite: CipherSuite::MlKem768Aes256GcmV1,
            key_id,
            kem_ciphertext,
            wrap_nonce,
            wrapped_dek,
            stream_nonce_prefix,
        }
    }

    /// AAD bytes that bind the wrapped DEK and STREAM chunks to this header.
    ///
    /// Covers magic, version, suite, and key id (not the ciphertexts themselves).
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(4 + 2 + 2 + self.key_id.as_str().len());
        aad.extend_from_slice(MAGIC);
        aad.extend_from_slice(&self.version.to_be_bytes());
        aad.extend_from_slice(&self.suite.as_u16().to_be_bytes());
        aad.extend_from_slice(self.key_id.as_str().as_bytes());
        aad
    }

    /// Encode this header to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_header(&mut out, self).expect("writing to Vec cannot fail");
        out
    }

    /// Decode a header from `bytes`, returning the header and remaining slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidHeader`] or [`Error::UnsupportedVersion`] on
    /// malformed or unsupported input.
    pub fn decode(mut bytes: &[u8]) -> Result<(Self, &[u8])> {
        let header = read_header(&mut bytes)?;
        Ok((header, bytes))
    }
}

/// Write `header` to `writer`.
pub fn write_header<W: Write>(writer: &mut W, header: &ObjectHeader) -> Result<()> {
    if header.version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(header.version));
    }
    let key_id = header.key_id.as_str().as_bytes();
    if key_id.len() > MAX_KEY_ID_LEN {
        return Err(Error::invalid_header("key id too long"));
    }
    if header.kem_ciphertext.len() != CIPHERTEXT_LEN {
        return Err(Error::invalid_header("unexpected kem ciphertext length"));
    }
    if header.kem_ciphertext.len() > u16::MAX as usize {
        return Err(Error::invalid_header("kem ciphertext too long"));
    }

    writer.write_all(MAGIC)?;
    writer.write_all(&header.version.to_be_bytes())?;
    writer.write_all(&header.suite.as_u16().to_be_bytes())?;
    writer.write_all(&(key_id.len() as u16).to_be_bytes())?;
    writer.write_all(key_id)?;
    writer.write_all(&(header.kem_ciphertext.len() as u16).to_be_bytes())?;
    writer.write_all(&header.kem_ciphertext)?;
    writer.write_all(&header.wrap_nonce)?;
    writer.write_all(&header.wrapped_dek)?;
    writer.write_all(&header.stream_nonce_prefix)?;
    Ok(())
}

/// Read a header from `reader`.
pub fn read_header<R: Read>(reader: &mut R) -> Result<ObjectHeader> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(Error::invalid_header("missing PQOS magic"));
    }

    let version = read_u16(reader)?;
    if version != FORMAT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let suite = CipherSuite::from_u16(read_u16(reader)?)?;

    let key_id_len = read_u16(reader)? as usize;
    if key_id_len == 0 || key_id_len > MAX_KEY_ID_LEN {
        return Err(Error::invalid_header("invalid key id length"));
    }
    let mut key_id_bytes = vec![0u8; key_id_len];
    reader.read_exact(&mut key_id_bytes)?;
    let key_id = KeyId::new(
        std::str::from_utf8(&key_id_bytes)
            .map_err(|_| Error::invalid_header("key id not utf-8"))?,
    )?;

    let kem_len = read_u16(reader)? as usize;
    if kem_len != CIPHERTEXT_LEN {
        return Err(Error::invalid_header("unexpected kem ciphertext length"));
    }
    let mut kem_ciphertext = vec![0u8; kem_len];
    reader.read_exact(&mut kem_ciphertext)?;

    let mut wrap_nonce = [0u8; WRAP_NONCE_LEN];
    reader.read_exact(&mut wrap_nonce)?;
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    reader.read_exact(&mut wrapped_dek)?;
    let mut stream_nonce_prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
    reader.read_exact(&mut stream_nonce_prefix)?;

    Ok(ObjectHeader {
        version,
        suite,
        key_id,
        kem_ciphertext,
        wrap_nonce,
        wrapped_dek,
        stream_nonce_prefix,
    })
}

/// Write a length-prefixed ciphertext chunk frame.
pub fn encode_chunk_frame(ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() > u32::MAX as usize {
        return Err(Error::crypto("chunk too large"));
    }
    let mut out = Vec::with_capacity(4 + ciphertext.len());
    out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(ciphertext);
    Ok(out)
}

/// Read one length-prefixed ciphertext chunk from `reader`.
///
/// Returns `None` on clean EOF before any length bytes.
pub fn read_chunk_frame<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if !chunk_len_in_range(len) {
        return Err(Error::invalid_header("invalid chunk length"));
    }
    let mut ct = vec![0u8; len];
    reader.read_exact(&mut ct)?;
    Ok(Some(ct))
}

/// Whether `len` is a legal STREAM chunk ciphertext length (including the tag).
pub(crate) fn chunk_len_in_range(len: usize) -> bool {
    (16..=crate::crypto::CHUNK_PLAINTEXT_SIZE + 16).contains(&len)
}

fn read_u16<R: Read>(reader: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kem::CIPHERTEXT_LEN;

    fn sample_header() -> ObjectHeader {
        ObjectHeader::new_v1(
            KeyId::new("workspace-a-v1").unwrap(),
            vec![7u8; CIPHERTEXT_LEN],
            [1u8; WRAP_NONCE_LEN],
            [2u8; WRAPPED_DEK_LEN],
            [3u8; STREAM_NONCE_PREFIX_LEN],
        )
    }

    #[test]
    fn header_round_trip() {
        let header = sample_header();
        let encoded = header.encode();
        let (decoded, rest) = ObjectHeader::decode(&encoded).unwrap();
        assert!(rest.is_empty());
        assert_eq!(decoded, header);
    }

    #[test]
    fn rejects_bad_magic() {
        let mut encoded = sample_header().encode();
        encoded[0] = b'X';
        let err = ObjectHeader::decode(&encoded).unwrap_err();
        assert!(matches!(err, Error::InvalidHeader(_)));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut encoded = sample_header().encode();
        encoded[4] = 0;
        encoded[5] = 99;
        let err = ObjectHeader::decode(&encoded).unwrap_err();
        assert!(matches!(err, Error::UnsupportedVersion(99)));
    }
}
