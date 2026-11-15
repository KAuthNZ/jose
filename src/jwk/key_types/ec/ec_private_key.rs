use crate::jwa::Curve;

use super::curve::ec_curve;

use super::errors::EcErrors;

use super::coordinates::key_pair;

use super::ec_public_key::EcPublicKey;

/// The private key of an EC JWK (RFC 7518 §6.2.2), with its public key. Both are in one variant,
/// so they can't be of different curves, and `public` is checked to be the one of `d`.
///
/// Without `Debug` or `Clone` on purpose: `d` is wiped on drop and never printed.
pub(crate) enum EcPrivateKey {
    P256 {
        d: p256::SecretKey,

        public: p256::PublicKey,
    },

    P384 {
        d: p384::SecretKey,

        public: p384::PublicKey,
    },

    P521 {
        d: p521::SecretKey,

        public: p521::PublicKey,
    },
}

impl EcPrivateKey {
    /// `crv`, `x`, `y` and `d` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, y: &str, d: &str) -> Result<Self, EcErrors> {
        Ok(match ec_curve(crv)? {
            Curve::P256 => {
                let (d, public) = key_pair(x, y, d)?;

                Self::P256 { d, public }
            }

            Curve::P384 => {
                let (d, public) = key_pair(x, y, d)?;

                Self::P384 { d, public }
            }

            Curve::P521 => {
                let (d, public) = key_pair(x, y, d)?;

                Self::P521 { d, public }
            }

            _ => return Err(EcErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::P256 { .. } => Curve::P256,

            Self::P384 { .. } => Curve::P384,

            Self::P521 { .. } => Curve::P521,
        }
    }

    /// The same key without `d`.
    pub(crate) fn public(&self) -> EcPublicKey {
        match self {
            Self::P256 { public, .. } => EcPublicKey::P256(*public),

            Self::P384 { public, .. } => EcPublicKey::P384(*public),

            Self::P521 { public, .. } => EcPublicKey::P521(*public),
        }
    }
}
