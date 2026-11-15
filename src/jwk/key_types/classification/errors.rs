use std::fmt;

use super::super::ec::EcErrors;

use super::super::okp::OkpErrors;

use super::super::oct::OctErrors;

use super::super::rsa::RsaErrors;

/// Why one JWK was refused while its `kty` and members were being matched to a family, or while
/// that family read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationErrors {
    /// A `kty` that is not registered.
    UnknownKty,

    /// A registered `kty` this library doesn't read, e.g. `AKP`.
    UnsupportedKty,

    /// A `kty` whose keys have no public side, e.g. `oct`, in a key read as public.
    NoPublicSide,

    /// `oct`, in a key read as private: it is a secret, read as one.
    SymmetricKty,

    /// A `kty` of an asymmetric key, in a key read as secret.
    AsymmetricKty,

    /// A member of the "Private" class in a key read as public (RFC 7517 §8.1.1).
    SecretMember(&'static str),

    /// A member the family requires and the JWK doesn't have.
    MissingMember(&'static str),

    /// A registered key member that is not one of this family's, e.g. `n` in `kty: EC`.
    ForeignMember(&'static str),

    Ec(EcErrors),

    Okp(OkpErrors),

    Oct(OctErrors),

    Rsa(RsaErrors),
}

impl From<EcErrors> for ClassificationErrors {
    fn from(error: EcErrors) -> Self {
        Self::Ec(error)
    }
}

impl From<OkpErrors> for ClassificationErrors {
    fn from(error: OkpErrors) -> Self {
        Self::Okp(error)
    }
}

impl From<OctErrors> for ClassificationErrors {
    fn from(error: OctErrors) -> Self {
        Self::Oct(error)
    }
}

impl From<RsaErrors> for ClassificationErrors {
    fn from(error: RsaErrors) -> Self {
        Self::Rsa(error)
    }
}

impl fmt::Display for ClassificationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKty => f.write_str("kty is not a registered key type"),

            Self::UnsupportedKty => f.write_str("kty is a key type this library doesn't read"),

            Self::NoPublicSide => f.write_str("kty has no public side, in a key read as public"),

            Self::SymmetricKty => f.write_str("kty is a symmetric key, in a key read as private"),

            Self::AsymmetricKty => f.write_str("kty is an asymmetric key, in a key read as secret"),

            Self::MissingMember(name) => write!(f, "{name} is missing"),

            Self::ForeignMember(name) => write!(f, "{name} is not a member of this key type"),

            Self::SecretMember(name) => write!(f, "{name} is secret, in a key read as public"),

            Self::Ec(error) => error.fmt(f),

            Self::Okp(error) => error.fmt(f),

            Self::Oct(error) => error.fmt(f),

            Self::Rsa(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ClassificationErrors {}
