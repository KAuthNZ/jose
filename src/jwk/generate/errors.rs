use std::fmt;

use crate::jwk::members::KidErrors;

use crate::jwk::key_types::RsaErrors;

/// Why a key was not generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerateErrors {
    /// The operating system gave no randomness.
    Rng,

    /// The RSA backend generated no key.
    RsaBackend,

    /// The RSA backend generated a key the rules of a read one refuse. Refused rather than
    /// assumed to pass.
    Rsa(RsaErrors),

    /// The `kid` it was given is not one a JWK may have.
    Kid(KidErrors),
}

impl From<RsaErrors> for GenerateErrors {
    fn from(error: RsaErrors) -> Self {
        Self::Rsa(error)
    }
}

impl From<KidErrors> for GenerateErrors {
    fn from(error: KidErrors) -> Self {
        Self::Kid(error)
    }
}

impl fmt::Display for GenerateErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => f.write_str("the operating system gave no randomness"),

            Self::RsaBackend => f.write_str("the RSA backend generated no key"),

            Self::Rsa(error) => error.fmt(f),

            Self::Kid(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for GenerateErrors {}
