use p256::NistP256;

use p384::NistP384;

use p521::NistP521;

use elliptic_curve::CurveArithmetic;

use crate::jwa::Curve;

/// The registered name of a curve of the backend: what a key of it writes as `crv`.
///
/// `pub` in a module that can't be named from outside the crate, as the keys of curve `C`.
pub trait NamedCurve: CurveArithmetic {
    const CURVE: Curve;
}

impl NamedCurve for NistP256 {
    const CURVE: Curve = Curve::P256;
}

impl NamedCurve for NistP384 {
    const CURVE: Curve = Curve::P384;
}

impl NamedCurve for NistP521 {
    const CURVE: Curve = Curve::P521;
}
