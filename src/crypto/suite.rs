//! Cipher suite identifiers.

use crate::error::{Error, Result};

/// Reviewed cryptographic suite identifiers.
///
/// Suites are pinned at the protocol layer. Casual feature-flag combinations of
/// algorithms are intentionally not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherSuite {
    /// ML-KEM-768 key wrapping with AES-256-GCM STREAM payload encryption.
    MlKem768Aes256GcmV1,
}

impl CipherSuite {
    /// Wire encoding used in object headers.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::MlKem768Aes256GcmV1 => 1,
        }
    }

    /// Parse a wire suite identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedSuite`] when the identifier is unknown.
    pub fn from_u16(value: u16) -> Result<Self> {
        match value {
            1 => Ok(Self::MlKem768Aes256GcmV1),
            other => Err(Error::UnsupportedSuite(other)),
        }
    }
}
