use std::fmt;

use crate::jwk::fit::FitErrors;

use crate::jwk::members::KidErrors;

use crate::jwk::raw::RawJwkErrors;

use crate::jwk::members::KeyMetadataErrors;

use crate::jwk::decoding::JwkDecodingErrors;

use crate::jwk::key_types::ClassificationErrors;

/// Why one JWK was not read, by the stage that refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkErrors {
    Decoding(JwkDecodingErrors),

    Raw(RawJwkErrors),

    Kid(KidErrors),

    Metadata(KeyMetadataErrors),

    Classification(ClassificationErrors),

    Fit(FitErrors),
}

impl From<JwkDecodingErrors> for JwkErrors {
    fn from(error: JwkDecodingErrors) -> Self {
        Self::Decoding(error)
    }
}

impl From<RawJwkErrors> for JwkErrors {
    fn from(error: RawJwkErrors) -> Self {
        Self::Raw(error)
    }
}

impl From<KidErrors> for JwkErrors {
    fn from(error: KidErrors) -> Self {
        Self::Kid(error)
    }
}

impl From<KeyMetadataErrors> for JwkErrors {
    fn from(error: KeyMetadataErrors) -> Self {
        Self::Metadata(error)
    }
}

impl From<ClassificationErrors> for JwkErrors {
    fn from(error: ClassificationErrors) -> Self {
        Self::Classification(error)
    }
}

impl From<FitErrors> for JwkErrors {
    fn from(error: FitErrors) -> Self {
        Self::Fit(error)
    }
}

impl fmt::Display for JwkErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decoding(error) => error.fmt(f),

            Self::Raw(error) => error.fmt(f),

            Self::Kid(error) => error.fmt(f),

            Self::Metadata(error) => error.fmt(f),

            Self::Classification(error) => error.fmt(f),

            Self::Fit(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for JwkErrors {}
