use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwk::key::Holds;

use crate::jwk::mode::Secret;

use crate::jwk::key_types::OctSecretKey;

use crate::jwk::key_types::AnySecretKey;

use super::bound::Bound;

/// The whole secret, as for every HS: whether it is long enough was judged by its candidates.
impl Holds for Secret<Hs256> {
    type Held = OctSecretKey;
}

impl Bound for Secret<Hs256> {
    type From = AnySecretKey;

    fn take(material: AnySecretKey) -> Option<OctSecretKey> {
        let AnySecretKey::Oct(key) = material;

        Some(key)
    }
}

/// The whole secret, as for every HS: whether it is long enough was judged by its candidates.
impl Holds for Secret<Hs384> {
    type Held = OctSecretKey;
}

impl Bound for Secret<Hs384> {
    type From = AnySecretKey;

    fn take(material: AnySecretKey) -> Option<OctSecretKey> {
        let AnySecretKey::Oct(key) = material;

        Some(key)
    }
}

/// The whole secret, as for every HS: whether it is long enough was judged by its candidates.
impl Holds for Secret<Hs512> {
    type Held = OctSecretKey;
}

impl Bound for Secret<Hs512> {
    type From = AnySecretKey;

    fn take(material: AnySecretKey) -> Option<OctSecretKey> {
        let AnySecretKey::Oct(key) = material;

        Some(key)
    }
}
