use super::curve::Curve;

use super::key_type::KeyType;

use super::signing_algorithm::SigningAlgorithm;

use super::key_management_algorithm::KeyManagementAlgorithm;

/// A value of `alg` (RFC 7515 §4.1.1, RFC 7516 §4.1.1): of signature or of key management, the
/// two of one registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Signing(SigningAlgorithm),

    KeyManagement(KeyManagementAlgorithm),
}

impl Algorithm {
    /// Every value of `alg`: the signature algorithms, then the key management ones, each in the
    /// order of its own `ALL`.
    pub fn all() -> impl Iterator<Item = Self> {
        SigningAlgorithm::ALL.into_iter().map(Self::Signing).chain(
            KeyManagementAlgorithm::ALL
                .into_iter()
                .map(Self::KeyManagement),
        )
    }

    /// Exact and case-sensitive, `EdDSA` read as `Ed25519`. No name is in both.
    pub fn from_name(name: &str) -> Option<Self> {
        SigningAlgorithm::from_name(name)
            .map(Self::Signing)
            .or_else(|| KeyManagementAlgorithm::from_name(name).map(Self::KeyManagement))
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Signing(alg) => alg.name(),

            Self::KeyManagement(alg) => alg.name(),
        }
    }

    pub fn accepts(self, kty: KeyType, crv: Option<Curve>) -> bool {
        match self {
            Self::Signing(alg) => alg.accepts(kty, crv),

            Self::KeyManagement(alg) => alg.accepts(kty, crv),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::jwa::ContentEncryptionAlgorithm;

    #[test]
    fn every_algorithm_of_both_kinds_is_read_by_its_name() {
        for alg in SigningAlgorithm::ALL {
            assert_eq!(
                Algorithm::from_name(alg.name()),
                Some(Algorithm::Signing(alg))
            );
        }

        for alg in KeyManagementAlgorithm::ALL {
            assert_eq!(
                Algorithm::from_name(alg.name()),
                Some(Algorithm::KeyManagement(alg))
            );
        }
    }

    #[test]
    fn no_name_is_of_two_registries() {
        let signing = SigningAlgorithm::ALL.map(SigningAlgorithm::name);

        let key_management = KeyManagementAlgorithm::ALL.map(KeyManagementAlgorithm::name);

        let content = ContentEncryptionAlgorithm::ALL.map(ContentEncryptionAlgorithm::name);

        for name in signing {
            assert!(!key_management.contains(&name), "{name}");
            assert!(!content.contains(&name), "{name}");
        }

        for name in key_management {
            assert!(!content.contains(&name), "{name}");
        }
    }

    #[test]
    fn eddsa_is_read_as_ed25519() {
        assert_eq!(
            Algorithm::from_name("EdDSA"),
            Some(Algorithm::Signing(SigningAlgorithm::Ed25519))
        );
    }

    #[test]
    fn a_content_encryption_name_is_not_an_alg() {
        for enc in ContentEncryptionAlgorithm::ALL {
            assert_eq!(Algorithm::from_name(enc.name()), None, "{enc:?}");
        }
    }

    #[test]
    fn a_name_of_no_registry_is_refused() {
        for name in ["", "none", "RSA1_5", "HS1", "es256", "ECDH-ES "] {
            assert_eq!(Algorithm::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn the_name_and_the_key_are_the_ones_of_the_algorithm_inside() {
        let es256 = Algorithm::Signing(SigningAlgorithm::Es256);

        assert_eq!(es256.name(), "ES256");
        assert!(es256.accepts(KeyType::Ec, Some(Curve::P256)));
        assert!(!es256.accepts(KeyType::Okp, Some(Curve::X25519)));

        let ecdh = Algorithm::KeyManagement(KeyManagementAlgorithm::EcdhEs);

        assert_eq!(ecdh.name(), "ECDH-ES");
        assert!(ecdh.accepts(KeyType::Okp, Some(Curve::X25519)));
        assert!(!ecdh.accepts(KeyType::Okp, Some(Curve::Ed25519)));
    }

    #[test]
    fn all_holds_every_algorithm_of_both_kinds_once() {
        let all: Vec<Algorithm> = Algorithm::all().collect();

        assert_eq!(
            all.len(),
            SigningAlgorithm::ALL.len() + KeyManagementAlgorithm::ALL.len()
        );

        for alg in SigningAlgorithm::ALL {
            assert_eq!(
                all.iter()
                    .filter(|a| **a == Algorithm::Signing(alg))
                    .count(),
                1,
                "{alg:?}"
            );
        }

        for alg in KeyManagementAlgorithm::ALL {
            assert_eq!(
                all.iter()
                    .filter(|a| **a == Algorithm::KeyManagement(alg))
                    .count(),
                1,
                "{alg:?}"
            );
        }
    }

    #[test]
    fn every_algorithm_of_all_is_read_back_by_its_name() {
        for alg in Algorithm::all() {
            assert_eq!(Algorithm::from_name(alg.name()), Some(alg), "{alg:?}");
        }
    }
}
