use std::fmt;

use super::super::alg::AlgErrors;

use super::super::key_ops::KeyOpsErrors;

use super::super::key_use::KeyUseErrors;

use super::coherence_errors::CoherenceErrors;

/// Why the metadata of one JWK was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyMetadataErrors {
    Alg(AlgErrors),

    Use(KeyUseErrors),

    KeyOps(KeyOpsErrors),

    Coherence(CoherenceErrors),
}

impl From<KeyUseErrors> for KeyMetadataErrors {
    fn from(error: KeyUseErrors) -> Self {
        Self::Use(error)
    }
}

impl From<KeyOpsErrors> for KeyMetadataErrors {
    fn from(error: KeyOpsErrors) -> Self {
        Self::KeyOps(error)
    }
}

impl From<AlgErrors> for KeyMetadataErrors {
    fn from(error: AlgErrors) -> Self {
        Self::Alg(error)
    }
}

impl From<CoherenceErrors> for KeyMetadataErrors {
    fn from(error: CoherenceErrors) -> Self {
        Self::Coherence(error)
    }
}

impl fmt::Display for KeyMetadataErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Alg(error) => error.fmt(f),

            Self::Use(error) => error.fmt(f),

            Self::KeyOps(error) => error.fmt(f),

            Self::Coherence(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for KeyMetadataErrors {}
