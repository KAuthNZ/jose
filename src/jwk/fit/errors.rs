use std::fmt;

/// Why the metadata of one JWK does not fit its key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FitErrors {
    /// No algorithm this library knows takes this key in this mode.
    NoAlgorithm,

    /// `alg` is an algorithm that does not take this key: another `kty`, another curve, a
    /// public key under an algorithm that has no public side, or a secret too short for it.
    AlgAndKey,

    /// No algorithm that takes this key is of the declared `use`.
    UseAndKey,

    /// No algorithm left lets this key, in its mode, do what `key_ops` says, and only that.
    KeyOpsAndKey,
}

impl fmt::Display for FitErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAlgorithm => f.write_str("no algorithm this library knows takes the key"),

            Self::AlgAndKey => f.write_str("alg does not take the key"),

            Self::UseAndKey => f.write_str("use is not what any algorithm of the key is for"),

            Self::KeyOpsAndKey => {
                f.write_str("key_ops is not what the key does under any of its algorithms")
            }
        }
    }
}

impl std::error::Error for FitErrors {}
