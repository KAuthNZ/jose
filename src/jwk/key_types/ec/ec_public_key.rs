use p256::NistP256;

use p384::NistP384;

use p521::NistP521;

use crate::jwa::Curve;

use super::curve::ec_curve;

use super::errors::EcErrors;

use crate::jwk::key_types::PublicMembers;

use super::ec_curve_public_key::EcCurvePublicKey;

/// The public key of an EC JWK (RFC 7518 §6.2.1): a point of the curve, checked to be on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcPublicKey {
    P256(EcCurvePublicKey<NistP256>),

    P384(EcCurvePublicKey<NistP384>),

    P521(EcCurvePublicKey<NistP521>),
}

impl EcPublicKey {
    /// `crv`, `x` and `y` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, y: &str) -> Result<Self, EcErrors> {
        Ok(match ec_curve(crv)? {
            Curve::P256 => Self::P256(EcCurvePublicKey::read(x, y)?),

            Curve::P384 => Self::P384(EcCurvePublicKey::read(x, y)?),

            Curve::P521 => Self::P521(EcCurvePublicKey::read(x, y)?),

            _ => return Err(EcErrors::UnsupportedCurve),
        })
    }

    pub(crate) fn curve(&self) -> Curve {
        match self {
            Self::P256(_) => Curve::P256,

            Self::P384(_) => Curve::P384,

            Self::P521(_) => Curve::P521,
        }
    }

    pub(crate) fn public_members(&self) -> PublicMembers {
        match self {
            Self::P256(key) => key.public_members(Curve::P256),

            Self::P384(key) => key.public_members(Curve::P384),

            Self::P521(key) => key.public_members(Curve::P521),
        }
    }
}
