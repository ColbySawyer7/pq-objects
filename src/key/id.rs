//! Cryptographic key identifiers.

use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::format::header::MAX_KEY_ID_LEN;

/// Identifier for a long-lived ML-KEM key.
///
/// Object headers record the key ID used at encryption time so readers can
/// select the correct private key during rotation.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(String);

impl KeyId {
    /// Create a key ID from a string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the ID is empty, too long, or contains
    /// non-printable characters.
    pub fn new(id: impl AsRef<str>) -> Result<Self> {
        let id = id.as_ref();
        if id.is_empty() {
            return Err(Error::config("key id must not be empty"));
        }
        if id.len() > MAX_KEY_ID_LEN {
            return Err(Error::config(format!(
                "key id exceeds {MAX_KEY_ID_LEN} bytes"
            )));
        }
        if !id.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            return Err(Error::config("key id must be printable ASCII"));
        }
        Ok(Self(id.to_string()))
    }

    /// Borrow the key ID string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyId").field(&self.0).finish()
    }
}

impl FromStr for KeyId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::new(s)
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ids() {
        let id = KeyId::new("workspace-123-v1").unwrap();
        assert_eq!(id.as_str(), "workspace-123-v1");
    }

    #[test]
    fn rejects_empty() {
        assert!(KeyId::new("").is_err());
    }
}
