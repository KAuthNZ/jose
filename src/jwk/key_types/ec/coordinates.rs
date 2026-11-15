use zeroize::Zeroizing;

use elliptic_curve::PublicKey;

use elliptic_curve::SecretKey;

use elliptic_curve::FieldBytes;

use elliptic_curve::CurveArithmetic;

use elliptic_curve::point::AffineCoordinates;

use crate::base64url;

use super::errors::EcErrors;

/// The point `(x, y)` of curve `C`, each coordinate exactly the size of the field.
pub(super) fn public_key<C>(x: &str, y: &str) -> Result<PublicKey<C>, EcErrors>
where
    C: CurveArithmetic,
{
    let x = base64url::decode(x).map_err(|_| EcErrors::InvalidEncoding("x"))?;

    let y = base64url::decode(y).map_err(|_| EcErrors::InvalidEncoding("y"))?;

    let x = <&FieldBytes<C>>::try_from(x.as_slice()).map_err(|_| EcErrors::InvalidLength("x"))?;

    let y = <&FieldBytes<C>>::try_from(y.as_slice()).map_err(|_| EcErrors::InvalidLength("y"))?;

    // `from_coordinates` refuses a coordinate at or above the prime, and a point that doesn't
    // satisfy the equation of the curve. The identity has no `(x, y)`, so it can't be written.
    let point = C::AffinePoint::from_coordinates(x, y)
        .into_option()
        .ok_or(EcErrors::NotOnCurve)?;

    PublicKey::from_affine(point).map_err(|_| EcErrors::NotOnCurve)
}

/// `d` with the point `(x, y)`, refused unless the point is the public key of `d`.
pub(super) fn key_pair<C>(
    x: &str,
    y: &str,
    d: &str,
) -> Result<(SecretKey<C>, PublicKey<C>), EcErrors>
where
    C: CurveArithmetic,
{
    let public = public_key::<C>(x, y)?;

    let len = base64url::decoded_len(d.len()).map_err(|_| EcErrors::InvalidEncoding("d"))?;

    let mut bytes = Zeroizing::new(vec![0u8; len]);

    base64url::decode_into(d, &mut bytes).map_err(|_| EcErrors::InvalidEncoding("d"))?;

    let bytes =
        <&FieldBytes<C>>::try_from(bytes.as_slice()).map_err(|_| EcErrors::InvalidLength("d"))?;

    let secret = SecretKey::<C>::from_bytes(bytes).map_err(|_| EcErrors::InvalidSecret)?;

    if secret.public_key() != public {
        return Err(EcErrors::KeyMismatch);
    }

    Ok((secret, public))
}
