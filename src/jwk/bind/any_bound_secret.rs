use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

/// A secret JWK bound to an algorithm chosen at run time, as [`AnyBoundPublic`].
///
/// [`AnyBoundPublic`]: super::AnyBoundPublic
pub enum AnyBoundSecret {
    Hs256(Jwk<Secret<Hs256>>),

    Hs384(Jwk<Secret<Hs384>>),

    Hs512(Jwk<Secret<Hs512>>),
}

impl AnyBoundSecret {
    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::Hs256(key) => key.kid(),

            Self::Hs384(key) => key.kid(),

            Self::Hs512(key) => key.kid(),
        }
    }
}
