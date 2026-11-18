use crate::jwa::Curve;

use crate::jwa::KeyType;

use super::errors::EcErrors;

/// `crv` as a registered curve of `kty: EC`. Whether this library reads it is decided by each key.
pub(super) fn ec_curve(crv: &str) -> Result<Curve, EcErrors> {
    let curve = Curve::from_name(crv).ok_or(EcErrors::UnknownCurve)?;

    if curve.kty() != KeyType::Ec {
        return Err(EcErrors::ForeignCurve);
    }

    Ok(curve)
}
