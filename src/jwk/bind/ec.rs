use p256::NistP256;

use p384::NistP384;

use p521::NistP521;

use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwk::key::Holds;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

use crate::jwk::key_types::EcPublicKey;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::EcPrivateKey;

use crate::jwk::key_types::AnyPrivateKey;

use crate::jwk::key_types::EcCurvePublicKey;

use crate::jwk::key_types::EcCurvePrivateKey;

use super::bound::Bound;

impl Holds for Public<Es256> {
    type Held = EcCurvePublicKey<NistP256>;
}

impl Bound for Public<Es256> {
    type From = AnyPublicKey;

    fn take(material: AnyPublicKey) -> Option<EcCurvePublicKey<NistP256>> {
        match material {
            AnyPublicKey::Ec(EcPublicKey::P256(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Private<Es256> {
    type Held = EcCurvePrivateKey<NistP256>;
}

impl Bound for Private<Es256> {
    type From = AnyPrivateKey;

    fn take(material: AnyPrivateKey) -> Option<EcCurvePrivateKey<NistP256>> {
        match material {
            AnyPrivateKey::Ec(EcPrivateKey::P256(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Public<Es384> {
    type Held = EcCurvePublicKey<NistP384>;
}

impl Bound for Public<Es384> {
    type From = AnyPublicKey;

    fn take(material: AnyPublicKey) -> Option<EcCurvePublicKey<NistP384>> {
        match material {
            AnyPublicKey::Ec(EcPublicKey::P384(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Private<Es384> {
    type Held = EcCurvePrivateKey<NistP384>;
}

impl Bound for Private<Es384> {
    type From = AnyPrivateKey;

    fn take(material: AnyPrivateKey) -> Option<EcCurvePrivateKey<NistP384>> {
        match material {
            AnyPrivateKey::Ec(EcPrivateKey::P384(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Public<Es512> {
    type Held = EcCurvePublicKey<NistP521>;
}

impl Bound for Public<Es512> {
    type From = AnyPublicKey;

    fn take(material: AnyPublicKey) -> Option<EcCurvePublicKey<NistP521>> {
        match material {
            AnyPublicKey::Ec(EcPublicKey::P521(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Private<Es512> {
    type Held = EcCurvePrivateKey<NistP521>;
}

impl Bound for Private<Es512> {
    type From = AnyPrivateKey;

    fn take(material: AnyPrivateKey) -> Option<EcCurvePrivateKey<NistP521>> {
        match material {
            AnyPrivateKey::Ec(EcPrivateKey::P521(key)) => Some(key),

            _ => None,
        }
    }
}
