use elliptic_curve::PublicKey;

use elliptic_curve::CurveArithmetic;

use elliptic_curve::point::AffineCoordinates;

use crate::base64url;

use crate::jwa::KeyType;

use super::errors::EcErrors;

use super::coordinates::public_key;

use super::named_curve::NamedCurve;

use crate::jwk::key_types::Publishes;

use crate::jwk::key_types::PublicMembers;

/// A point of curve `C`, checked to be on it: what a key bound to the algorithm of `C` verifies
/// with. `C` is fixed by the type, so a key of one curve can't be held as another.
///
/// `pub` in a module that can't be named from outside the crate: a bound key holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcCurvePublicKey<C>(PublicKey<C>)
where
    C: CurveArithmetic;

impl<C> EcCurvePublicKey<C>
where
    C: CurveArithmetic,
{
    /// `x` and `y` as they came in the JWK.
    pub(super) fn read(x: &str, y: &str) -> Result<Self, EcErrors> {
        public_key::<C>(x, y).map(Self)
    }

    /// One the private key already holds, checked when it was read.
    pub(super) fn from_backend(key: PublicKey<C>) -> Self {
        Self(key)
    }
}

/// `x` and `y` the full size of the field, leading zeros kept (RFC 7518 §6.2.1.2-3): the
/// affine coordinates come as field bytes, never as a trimmed integer.
impl<C> Publishes for EcCurvePublicKey<C>
where
    C: NamedCurve,
{
    fn public_members(&self) -> PublicMembers {
        let point = self.0.as_affine();

        PublicMembers::new(KeyType::Ec)
            .with("crv", C::CURVE.name().to_owned())
            .with("x", base64url::encode(&point.x()))
            .with("y", base64url::encode(&point.y()))
    }
}
