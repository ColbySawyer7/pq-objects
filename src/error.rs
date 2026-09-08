//! Crate-owned error types for `pq-objectstore`.

use std::fmt;

/// Convenient result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by encrypted object storage operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying object store rejected or failed an operation.
    #[error("object backend error: {0}")]
    Backend(String),

    /// Cryptographic operation failed.
    #[error("cryptographic error: {0}")]
    Crypto(String),

    /// The object header could not be parsed.
    #[error("invalid object header: {0}")]
    InvalidHeader(String),

    /// The object format version is not supported by this build.
    #[error("unsupported object format version: {0}")]
    UnsupportedVersion(u16),

    /// The cipher suite is not supported by this build.
    #[error("unsupported cipher suite: {0}")]
    UnsupportedSuite(u16),

    /// The referenced key ID is unknown to the configured [`crate::KeyProvider`].
    #[error("unknown key id: {0}")]
    UnknownKey(String),

    /// Authenticated decryption failed (tampering or wrong key).
    #[error("authentication failed")]
    AuthenticationFailed,

    /// I/O failure while reading or writing object data.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration supplied to a builder.
    #[error("invalid configuration: {0}")]
    Config(String),
}

impl Error {
    #[cfg(feature = "store")]
    pub(crate) fn backend(err: impl fmt::Display) -> Self {
        Self::Backend(err.to_string())
    }

    pub(crate) fn crypto(err: impl fmt::Display) -> Self {
        Self::Crypto(err.to_string())
    }

    pub(crate) fn invalid_header(err: impl fmt::Display) -> Self {
        Self::InvalidHeader(err.to_string())
    }

    pub(crate) fn config(err: impl fmt::Display) -> Self {
        Self::Config(err.to_string())
    }
}
