use elliptic_curve::PublicKey;

use elliptic_curve::CurveArithmetic;

use elliptic_curve::point::AffineCoordinates;

use crate::base64url;

use crate::jwa::Curve;

use crate::jwa::KeyType;

use super::curve::ec_curve;

use super::errors::EcErrors;

use super::coordinates::public_key;

use crate::jwk::key_types::PublicMembers;

/// The public key of an EC JWK (RFC 7518 §6.2.1): a point of the curve, checked to be on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EcPublicKey {
    P256(p256::PublicKey),

    P384(p384::PublicKey),

    P521(p521::PublicKey),
}

impl EcPublicKey {
    /// `crv`, `x` and `y` as they came in the JWK.
    pub(in crate::jwk) fn read(crv: &str, x: &str, y: &str) -> Result<Self, EcErrors> {
        Ok(match ec_curve(crv)? {
            Curve::P256 => Self::P256(public_key(x, y)?),

            Curve::P384 => Self::P384(public_key(x, y)?),

            Curve::P521 => Self::P521(public_key(x, y)?),

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
            Self::P256(key) => members(Curve::P256, key),

            Self::P384(key) => members(Curve::P384, key),

            Self::P521(key) => members(Curve::P521, key),
        }
    }
}

/// `x` and `y` the full size of the field, leading zeros kept (RFC 7518 §6.2.1.2-3): the affine
/// coordinates come as field bytes, never as a trimmed integer.
fn members<C>(crv: Curve, key: &PublicKey<C>) -> PublicMembers
where
    C: CurveArithmetic,
{
    let point = key.as_affine();

    PublicMembers::new(KeyType::Ec)
        .with("crv", crv.name().to_owned())
        .with("x", base64url::encode(&point.x()))
        .with("y", base64url::encode(&point.y()))
}
