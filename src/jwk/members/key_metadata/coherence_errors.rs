use std::fmt;

/// Two members of one JWK that contradict each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoherenceErrors {
    UseAndAlg,

    /// RFC 7517 §4.3: when both are present, they MUST be consistent.
    UseAndKeyOps,

    /// An operation the key does not do under its `alg`.
    KeyOpsAndAlg,

    /// Without an `alg`, operations that are not one of the pairs RFC 7517 §4.3 permits.
    UnrelatedOps,
}

impl fmt::Display for CoherenceErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UseAndAlg => f.write_str("use and alg say different uses"),

            Self::UseAndKeyOps => f.write_str("use and key_ops say different uses"),

            Self::KeyOpsAndAlg => f.write_str("key_ops lists an operation alg does not do"),

            Self::UnrelatedOps => f.write_str("key_ops lists operations that are not one pair"),
        }
    }
}

impl std::error::Error for CoherenceErrors {}
