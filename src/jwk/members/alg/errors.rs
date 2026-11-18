use std::fmt;

/// Why an `alg` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgErrors {
    /// A name that is not an algorithm this library knows, registered or not.
    Unsupported,
}

impl fmt::Display for AlgErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("alg is not an algorithm this library knows"),
        }
    }
}

impl std::error::Error for AlgErrors {}
