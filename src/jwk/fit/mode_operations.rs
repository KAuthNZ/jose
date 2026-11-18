use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::mode::KeyMode;

use crate::jwk::members::KeyOp;

use crate::jwk::members::KeyAlg;

/// What a key of this mode does under an algorithm, `None` where the mode has no place under it.
/// Here and not in `mode/`, which knows no algorithm.
pub(super) trait ModeOperations: KeyMode {
    fn operations(alg: KeyAlg) -> Option<&'static [KeyOp]>;
}

impl ModeOperations for Public {
    fn operations(alg: KeyAlg) -> Option<&'static [KeyOp]> {
        alg.public_operations()
    }
}

/// A private key holds its public side too: it does both.
impl ModeOperations for Private {
    fn operations(alg: KeyAlg) -> Option<&'static [KeyOp]> {
        Some(alg.operations())
    }
}

/// One key for both sides.
impl ModeOperations for Secret {
    fn operations(alg: KeyAlg) -> Option<&'static [KeyOp]> {
        Some(alg.operations())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alg(name: &str) -> KeyAlg {
        KeyAlg::read(name).unwrap()
    }

    fn names(ops: Option<&'static [KeyOp]>) -> Option<Vec<&'static str>> {
        ops.map(|ops| ops.iter().map(|op| op.name()).collect())
    }

    #[test]
    fn a_public_key_does_only_what_the_public_side_does() {
        assert_eq!(
            names(Public::operations(alg("ES256"))),
            Some(vec!["verify"])
        );

        assert_eq!(
            names(Public::operations(alg("RSA-OAEP"))),
            Some(vec!["encrypt", "wrapKey"])
        );
    }

    #[test]
    fn a_public_key_has_no_place_under_a_symmetric_algorithm() {
        for name in ["HS256", "A256KW", "dir"] {
            assert_eq!(Public::operations(alg(name)), None, "{name}");
        }
    }

    #[test]
    fn a_key_agreement_public_key_does_nothing_of_its_own() {
        assert_eq!(names(Public::operations(alg("ECDH-ES"))), Some(vec![]));
    }

    #[test]
    fn a_private_and_a_secret_key_do_everything_the_algorithm_does() {
        assert_eq!(
            names(Private::operations(alg("ES256"))),
            Some(vec!["sign", "verify"])
        );

        assert_eq!(
            names(Secret::operations(alg("HS256"))),
            Some(vec!["sign", "verify"])
        );
    }
}
