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

use crate::jwk::mode::Public;

/// A public JWK bound to an algorithm chosen at run time, from configuration. One variant per
/// algorithm, named as its marker: once bound, the algorithm is never given again.
///
/// Without `Debug`, as [`Jwk`].
#[derive(Clone)]
pub enum AnyBoundPublic {
    Es256(Jwk<Public<Es256>>),

    Es384(Jwk<Public<Es384>>),

    Es512(Jwk<Public<Es512>>),

    Rs256(Jwk<Public<Rs256>>),

    Rs384(Jwk<Public<Rs384>>),

    Rs512(Jwk<Public<Rs512>>),

    Ps256(Jwk<Public<Ps256>>),

    Ps384(Jwk<Public<Ps384>>),

    Ps512(Jwk<Public<Ps512>>),

    Ed25519(Jwk<Public<Ed25519>>),
}

impl AnyBoundPublic {
    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::Ed25519(key) => key.kid(),

            Self::Es256(key) => key.kid(),

            Self::Es384(key) => key.kid(),

            Self::Es512(key) => key.kid(),

            Self::Rs256(key) => key.kid(),

            Self::Rs384(key) => key.kid(),

            Self::Rs512(key) => key.kid(),

            Self::Ps256(key) => key.kid(),

            Self::Ps384(key) => key.kid(),

            Self::Ps512(key) => key.kid(),
        }
    }
}
