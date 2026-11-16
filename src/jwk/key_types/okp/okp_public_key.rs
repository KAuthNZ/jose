use crate::jwa::Curve;

use super::curve::okp_curve;

use super::errors::OkpErrors;

use crate::jwk::key_types::Publishes;

use crate::jwk::key_types::PublicMembers;

use super::ed25519_public_key::Ed25519PublicKey;

/// The public key of an OKP JWK (RFC 8037 §2): one a real signer could have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OkpPublicKey {
    Ed25519(Ed25519PublicKey),
}

impl OkpPublicKey {
    /// `crv` and `x` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str) -> Result<Self, OkpErrors> {
        Ok(match okp_curve(crv)? {
            Curve::Ed25519 => Self::Ed25519(Ed25519PublicKey::read(x)?),

            _ => return Err(OkpErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
        }
    }
}

impl Publishes for OkpPublicKey {
    fn public_members(&self) -> PublicMembers {
        match self {
            Self::Ed25519(key) => key.public_members(),
        }
    }
}
