use super::errors::KidErrors;

use super::constants::KID_MAX_LEN;

/// `kid` (RFC 7517 §4.5), compared byte by byte. Stricter than the RFC: printable ASCII only,
/// no space at an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Kid(String);

impl Kid {
    pub(in crate::jwk) fn read(kid: String) -> Result<Self, KidErrors> {
        if kid.is_empty() {
            return Err(KidErrors::Empty);
        }

        if kid.len() > KID_MAX_LEN {
            return Err(KidErrors::TooLong);
        }

        if !kid.bytes().all(|byte| matches!(byte, b' '..=b'~')) {
            return Err(KidErrors::NotPrintableAscii);
        }

        if kid.starts_with(' ') || kid.ends_with(' ') {
            return Err(KidErrors::SpaceAtEdge);
        }

        Ok(Self(kid))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
