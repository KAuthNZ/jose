use crate::jwk::key::Holds;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnyPrivateKey;

use crate::jwk::key_types::RsaPublicKey;

use crate::jwk::key_types::RsaPrivateKey;

use super::bound::Bound;

/// The same key for every RSA algorithm: the algorithm only picks the hash and the padding, so a
/// key bound to one holds what it holds bound to any other.
macro_rules! rsa_bound {
    ($($alg:ident),+ $(,)?) => {$(
        impl Holds for Public<crate::jwa::$alg> {
            type Held = RsaPublicKey;
        }

        impl Bound for Public<crate::jwa::$alg> {
            type From = AnyPublicKey;

            fn take(material: AnyPublicKey) -> Option<RsaPublicKey> {
                match material {
                    AnyPublicKey::Rsa(key) => Some(key),

                    _ => None,
                }
            }
        }

        impl Holds for Private<crate::jwa::$alg> {
            type Held = RsaPrivateKey;
        }

        impl Bound for Private<crate::jwa::$alg> {
            type From = AnyPrivateKey;

            fn take(material: AnyPrivateKey) -> Option<RsaPrivateKey> {
                match material {
                    AnyPrivateKey::Rsa(key) => Some(key),

                    _ => None,
                }
            }
        }
    )+};
}

rsa_bound!(Rs256, Rs384, Rs512);

rsa_bound!(Ps256, Ps384, Ps512);
