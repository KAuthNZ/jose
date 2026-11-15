use crate::base64url;

use crate::jwa::Curve;

use crate::jwa::KeyType;

use super::ed25519;

use super::curve::okp_curve;

use super::errors::OkpErrors;

use crate::jwk::key_types::PublicMembers;

/// The public key of an OKP JWK (RFC 8037 §2): one a real signer could have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OkpPublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl OkpPublicKey {
    /// `crv` and `x` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str) -> Result<Self, OkpErrors> {
        Ok(match okp_curve(crv)? {
            Curve::Ed25519 => Self::Ed25519(ed25519::public_key(x)?),

            _ => return Err(OkpErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::Ed25519(_) => Curve::Ed25519,
        }
    }

    /// `x` is the 32 bytes of the encoded point (RFC 8037 §2).
    pub(crate) fn public_members(&self) -> PublicMembers {
        match self {
            Self::Ed25519(key) => PublicMembers::new(KeyType::Okp)
                .with("crv", Curve::Ed25519.name().to_owned())
                .with("x", base64url::encode(key.as_bytes())),
        }
    }
}
