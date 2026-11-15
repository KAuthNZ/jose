use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnySecretKey;

use crate::jwk::key_types::AnyPrivateKey;

use super::Holds;

fn holds<M, K>()
where
    M: Holds<Key = K>,
{
}

#[test]
fn an_unbound_mode_holds_what_classification_read() {
    holds::<Public, AnyPublicKey>();

    holds::<Private, AnyPrivateKey>();

    holds::<Secret, AnySecretKey>();
}
