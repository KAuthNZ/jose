use crate::jwa::Ed25519;

use crate::jwk::key::Holds;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

use crate::jwk::key_types::OkpPublicKey;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::OkpPrivateKey;

use crate::jwk::key_types::AnyPrivateKey;

use crate::jwk::key_types::Ed25519PublicKey;

use crate::jwk::key_types::Ed25519PrivateKey;

use super::bound::Bound;

impl Holds for Public<Ed25519> {
    type Held = Ed25519PublicKey;
}

impl Bound for Public<Ed25519> {
    type From = AnyPublicKey;

    fn take(material: AnyPublicKey) -> Option<Ed25519PublicKey> {
        match material {
            AnyPublicKey::Okp(OkpPublicKey::Ed25519(key)) => Some(key),

            _ => None,
        }
    }
}

impl Holds for Private<Ed25519> {
    type Held = Ed25519PrivateKey;
}

impl Bound for Private<Ed25519> {
    type From = AnyPrivateKey;

    fn take(material: AnyPrivateKey) -> Option<Ed25519PrivateKey> {
        match material {
            AnyPrivateKey::Okp(OkpPrivateKey::Ed25519(key)) => Some(key),

            _ => None,
        }
    }
}
