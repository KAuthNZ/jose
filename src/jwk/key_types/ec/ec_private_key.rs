use p256::NistP256;

use p384::NistP384;

use p521::NistP521;

use crate::jwa::Curve;

use super::curve::ec_curve;

use super::errors::EcErrors;

use super::ec_public_key::EcPublicKey;

use super::super::duplicate::Duplicate;

use super::super::public_side::PublicSide;

use super::ec_curve_private_key::EcCurvePrivateKey;

/// The private key of an EC JWK (RFC 7518 §6.2.2), with its public key: each curve keeps both,
/// so they can't be of different curves.
///
/// Without `Debug` on purpose: `d` is never printed. Not `Clone` either: copied only by
/// `Duplicate`, each copy wiped on drop.
pub enum EcPrivateKey {
    P256(EcCurvePrivateKey<NistP256>),

    P384(EcCurvePrivateKey<NistP384>),

    P521(EcCurvePrivateKey<NistP521>),
}

impl EcPrivateKey {
    /// `crv`, `x`, `y` and `d` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, y: &str, d: &str) -> Result<Self, EcErrors> {
        Ok(match ec_curve(crv)? {
            Curve::P256 => Self::P256(EcCurvePrivateKey::read(x, y, d)?),

            Curve::P384 => Self::P384(EcCurvePrivateKey::read(x, y, d)?),

            Curve::P521 => Self::P521(EcCurvePrivateKey::read(x, y, d)?),

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

    /// The same key without `d`.
    pub(crate) fn public(&self) -> EcPublicKey {
        match self {
            Self::P256(key) => EcPublicKey::P256(key.public()),

            Self::P384(key) => EcPublicKey::P384(key.public()),

            Self::P521(key) => EcPublicKey::P521(key.public()),
        }
    }
}

impl Duplicate for EcPrivateKey {
    fn duplicate(&self) -> Self {
        match self {
            Self::P256(key) => Self::P256(key.duplicate()),

            Self::P384(key) => Self::P384(key.duplicate()),

            Self::P521(key) => Self::P521(key.duplicate()),
        }
    }
}
