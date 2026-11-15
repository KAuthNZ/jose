use crate::jwa::Curve;

use super::curve::okp_curve;

use super::errors::OkpErrors;

use super::super::duplicate::Duplicate;

use super::okp_public_key::OkpPublicKey;

use super::ed25519_private_key::Ed25519PrivateKey;

/// The private key of an OKP JWK (RFC 8037 §2), with its public key: each curve keeps both, so
/// they can't be of different curves.
///
/// Without `Debug` on purpose: `d` is never printed. Not `Clone` either: copied only by
/// `Duplicate`, each copy wiped on drop.
pub enum OkpPrivateKey {
    Ed25519(Ed25519PrivateKey),
}

impl OkpPrivateKey {
    /// `crv`, `x` and `d` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, d: &str) -> Result<Self, OkpErrors> {
        Ok(match okp_curve(crv)? {
            Curve::Ed25519 => Self::Ed25519(Ed25519PrivateKey::read(x, d)?),

            _ => return Err(OkpErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
        }
    }

    /// The same key without `d`.
    pub(crate) fn public(&self) -> OkpPublicKey {
        match self {
            Self::Ed25519(key) => OkpPublicKey::Ed25519(key.public()),
        }
    }
}

impl Duplicate for OkpPrivateKey {
    fn duplicate(&self) -> Self {
        match self {
            Self::Ed25519(key) => Self::Ed25519(key.duplicate()),
        }
    }
}
