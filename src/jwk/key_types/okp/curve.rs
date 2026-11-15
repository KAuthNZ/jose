use crate::jwa::Curve;

use crate::jwa::KeyType;

use super::errors::OkpErrors;

/// `crv` as a registered curve of `kty: OKP`. Whether this library reads it is decided by each
/// key.
pub(super) fn okp_curve(crv: &str) -> Result<Curve, OkpErrors> {
    let curve = Curve::from_name(crv).ok_or(OkpErrors::UnknownCurve)?;

    if curve.kty() != KeyType::Okp {
        return Err(OkpErrors::ForeignCurve);
    }

    Ok(curve)
}
