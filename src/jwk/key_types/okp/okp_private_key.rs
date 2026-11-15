use crate::jwa::Curve;

use super::ed25519;

use super::curve::okp_curve;

use super::errors::OkpErrors;

use super::okp_public_key::OkpPublicKey;

/// The private key of an OKP JWK (RFC 8037 §2), with its public key. Both are in one variant, so
/// they can't be of different curves, and `public` is checked to be the one of `d`.
///
/// Without `Debug` or `Clone` on purpose: `d` is wiped on drop and never printed.
pub(crate) enum OkpPrivateKey {
    Ed25519 {
        d: ed25519_dalek::SigningKey,

        public: ed25519_dalek::VerifyingKey,
    },
}

impl OkpPrivateKey {
    /// `crv`, `x` and `d` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, d: &str) -> Result<Self, OkpErrors> {
        Ok(match okp_curve(crv)? {
            Curve::Ed25519 => {
                let (d, public) = ed25519::key_pair(x, d)?;

                Self::Ed25519 { d, public }
            }

            _ => return Err(OkpErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::Ed25519 { .. } => Curve::Ed25519,
        }
    }

    /// The same key without `d`.
    pub(crate) fn public(&self) -> OkpPublicKey {
        match self {
            Self::Ed25519 { public, .. } => OkpPublicKey::Ed25519(*public),
        }
    }
}
