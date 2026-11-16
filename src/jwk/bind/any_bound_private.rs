use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwa::Rs256;

use crate::jwa::Rs384;

use crate::jwa::Rs512;

use crate::jwa::Ps256;

use crate::jwa::Ps384;

use crate::jwa::Ps512;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Private;

use super::any_bound_public::AnyBoundPublic;

/// A private JWK bound to an algorithm chosen at run time, as [`AnyBoundPublic`].
///
/// [`AnyBoundPublic`]: super::AnyBoundPublic
pub enum AnyBoundPrivate {
    Es256(Jwk<Private<Es256>>),

    Es384(Jwk<Private<Es384>>),

    Es512(Jwk<Private<Es512>>),

    Rs256(Jwk<Private<Rs256>>),

    Rs384(Jwk<Private<Rs384>>),

    Rs512(Jwk<Private<Rs512>>),

    Ps256(Jwk<Private<Ps256>>),

    Ps384(Jwk<Private<Ps384>>),

    Ps512(Jwk<Private<Ps512>>),

    Ed25519(Jwk<Private<Ed25519>>),
}

impl AnyBoundPrivate {
    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::Es256(key) => key.kid(),

            Self::Es384(key) => key.kid(),

            Self::Es512(key) => key.kid(),

            Self::Rs256(key) => key.kid(),

            Self::Rs384(key) => key.kid(),

            Self::Rs512(key) => key.kid(),

            Self::Ps256(key) => key.kid(),

            Self::Ps384(key) => key.kid(),

            Self::Ps512(key) => key.kid(),

            Self::Ed25519(key) => key.kid(),
        }
    }

    /// The public key of this one, bound to the same algorithm.
    pub fn public(&self) -> AnyBoundPublic {
        match self {
            Self::Ed25519(key) => AnyBoundPublic::Ed25519(key.public()),

            Self::Es256(key) => AnyBoundPublic::Es256(key.public()),

            Self::Es384(key) => AnyBoundPublic::Es384(key.public()),

            Self::Es512(key) => AnyBoundPublic::Es512(key.public()),

            Self::Rs256(key) => AnyBoundPublic::Rs256(key.public()),

            Self::Rs384(key) => AnyBoundPublic::Rs384(key.public()),

            Self::Rs512(key) => AnyBoundPublic::Rs512(key.public()),

            Self::Ps256(key) => AnyBoundPublic::Ps256(key.public()),

            Self::Ps384(key) => AnyBoundPublic::Ps384(key.public()),

            Self::Ps512(key) => AnyBoundPublic::Ps512(key.public()),
        }
    }
}
