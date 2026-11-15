use std::fmt;

/// Why an oct key was refused while `k` was being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OctErrors {
    /// A `k` that is not unpadded, canonical base64url (RFC 7515 §2).
    InvalidEncoding,

    /// A `k` of no bytes: no algorithm has a key of size 0.
    Empty,
}

impl fmt::Display for OctErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("k is empty"),

            Self::InvalidEncoding => f.write_str("k is not canonical base64url"),
        }
    }
}

impl std::error::Error for OctErrors {}
