use elliptic_curve::PublicKey;

use elliptic_curve::SecretKey;

use elliptic_curve::CurveArithmetic;

use super::errors::EcErrors;

use super::coordinates::key_pair;

use super::ec_curve_public_key::EcCurvePublicKey;

use super::super::duplicate::Duplicate;

use super::super::public_side::PublicSide;

/// A private key of curve `C` with its public key, `public` checked to be the one of `d`: what a
/// key bound to the algorithm of `C` signs with. Both share `C`, so they can't be of different
/// curves.
///
/// `pub` for the same reason as [`EcCurvePublicKey`]. Without `Debug` on purpose: `d` is never
/// printed. Not `Clone` either: copied only by `Duplicate`, each copy wiped on drop.
pub struct EcCurvePrivateKey<C>
where
    C: CurveArithmetic,
{
    d: SecretKey<C>,

    public: PublicKey<C>,
}

impl<C> EcCurvePrivateKey<C>
where
    C: CurveArithmetic,
{
    /// `x`, `y` and `d` as they came in the JWK.
    pub(super) fn read(x: &str, y: &str, d: &str) -> Result<Self, EcErrors> {
        let (d, public) = key_pair::<C>(x, y, d)?;

        Ok(Self { d, public })
    }
}

impl<C> Duplicate for EcCurvePrivateKey<C>
where
    C: CurveArithmetic,
{
    fn duplicate(&self) -> Self {
        Self {
            d: self.d.clone(),
            public: self.public,
        }
    }
}

/// The same key without `d`.
impl<C> PublicSide for EcCurvePrivateKey<C>
where
    C: CurveArithmetic,
{
    type Public = EcCurvePublicKey<C>;

    fn public(&self) -> EcCurvePublicKey<C> {
        EcCurvePublicKey::from_backend(self.public)
    }
}
