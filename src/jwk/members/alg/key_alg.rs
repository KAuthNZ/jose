use crate::jwa::Algorithm;

use crate::jwa::SigningAlgorithm;

use crate::jwa::KeyManagementAlgorithm;

use super::errors::AlgErrors;

use super::constants::DIRECT_OPS;

use super::constants::RSA_OAEP_OPS;

use super::constants::SIGNATURE_OPS;

use super::constants::DERIVATION_OPS;

use super::constants::KEY_WRAPPING_OPS;

use super::constants::PUBLIC_RSA_OAEP_OPS;

use super::constants::PUBLIC_SIGNATURE_OPS;

use super::constants::PUBLIC_DERIVATION_OPS;

use super::super::key_ops::KeyOp;

use super::super::key_use::KeyUse;

/// `alg` of a JWK (RFC 7517 §4.4): a value of the registry, with what it means for a key. A name
/// this library doesn't know refuses the key, registered or not: one it can't check against the
/// key is a confusion waiting to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyAlg(Algorithm);

impl KeyAlg {
    /// By the same names as `alg` in a JOSE header, `EdDSA` read as `Ed25519` included.
    pub(in crate::jwk) fn read(name: &str) -> Result<Self, AlgErrors> {
        Algorithm::from_name(name)
            .map(Self)
            .ok_or(AlgErrors::Unsupported)
    }

    pub(crate) fn algorithm(self) -> Algorithm {
        self.0
    }

    pub(crate) const fn key_use(self) -> KeyUse {
        match self.0 {
            Algorithm::Signing(_) => KeyUse::Signature,

            Algorithm::KeyManagement(_) => KeyUse::Encryption,
        }
    }

    /// The `key_ops` a key does under this algorithm: listed together they are still one
    /// algorithm, which is what RFC 7517 §4.3 guards. Not what the algorithm does as a whole:
    /// under `ECDH-ES+A*KW` the wrap is done by the derived key, so this one only derives.
    pub(crate) const fn operations(self) -> &'static [KeyOp] {
        use KeyManagementAlgorithm as Km;

        match self.0 {
            Algorithm::Signing(_) => &SIGNATURE_OPS,

            Algorithm::KeyManagement(alg) => match alg {
                Km::RsaOaep | Km::RsaOaep256 | Km::RsaOaep384 | Km::RsaOaep512 => &RSA_OAEP_OPS,

                Km::A128Kw
                | Km::A192Kw
                | Km::A256Kw
                | Km::A128GcmKw
                | Km::A192GcmKw
                | Km::A256GcmKw => &KEY_WRAPPING_OPS,

                Km::Dir => &DIRECT_OPS,

                Km::EcdhEs
                | Km::EcdhEsA128Kw
                | Km::EcdhEsA192Kw
                | Km::EcdhEsA256Kw
                | Km::Pbes2Hs256A128Kw
                | Km::Pbes2Hs384A192Kw
                | Km::Pbes2Hs512A256Kw => &DERIVATION_OPS,
            },
        }
    }

    /// What the public side of a key does under this algorithm, of [`operations`], or `None`
    /// where there is no public side: a symmetric key is never public.
    ///
    /// [`operations`]: Self::operations
    pub(crate) const fn public_operations(self) -> Option<&'static [KeyOp]> {
        use KeyManagementAlgorithm as Km;

        use SigningAlgorithm as Sig;

        match self.0 {
            Algorithm::Signing(alg) => match alg {
                Sig::Hs256 | Sig::Hs384 | Sig::Hs512 => None,

                Sig::Rs256
                | Sig::Rs384
                | Sig::Rs512
                | Sig::Ps256
                | Sig::Ps384
                | Sig::Ps512
                | Sig::Es256
                | Sig::Es384
                | Sig::Es512
                | Sig::Es256k
                | Sig::Ed25519
                | Sig::Ed448
                | Sig::MlDsa44
                | Sig::MlDsa65
                | Sig::MlDsa87 => Some(&PUBLIC_SIGNATURE_OPS),
            },

            Algorithm::KeyManagement(alg) => match alg {
                Km::RsaOaep | Km::RsaOaep256 | Km::RsaOaep384 | Km::RsaOaep512 => {
                    Some(&PUBLIC_RSA_OAEP_OPS)
                }

                Km::EcdhEs | Km::EcdhEsA128Kw | Km::EcdhEsA192Kw | Km::EcdhEsA256Kw => {
                    Some(&PUBLIC_DERIVATION_OPS)
                }

                Km::A128Kw
                | Km::A192Kw
                | Km::A256Kw
                | Km::A128GcmKw
                | Km::A192GcmKw
                | Km::A256GcmKw
                | Km::Dir
                | Km::Pbes2Hs256A128Kw
                | Km::Pbes2Hs384A192Kw
                | Km::Pbes2Hs512A256Kw => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing(alg: SigningAlgorithm) -> KeyAlg {
        KeyAlg(Algorithm::Signing(alg))
    }

    fn key_management(alg: KeyManagementAlgorithm) -> KeyAlg {
        KeyAlg(Algorithm::KeyManagement(alg))
    }

    fn every_alg() -> impl Iterator<Item = KeyAlg> {
        SigningAlgorithm::ALL
            .into_iter()
            .map(signing)
            .chain(KeyManagementAlgorithm::ALL.into_iter().map(key_management))
    }

    #[test]
    fn every_algorithm_of_both_kinds_is_read_by_its_name() {
        for alg in every_alg() {
            assert_eq!(KeyAlg::read(alg.algorithm().name()), Ok(alg), "{alg:?}");
        }
    }

    #[test]
    fn eddsa_is_read_as_ed25519() {
        assert_eq!(
            KeyAlg::read("EdDSA"),
            Ok(signing(SigningAlgorithm::Ed25519))
        );
    }

    #[test]
    fn es256k_and_ed448_are_known_by_name_whether_a_key_takes_them_is_for_later() {
        assert_eq!(
            KeyAlg::read("ES256K"),
            Ok(signing(SigningAlgorithm::Es256k))
        );

        assert_eq!(KeyAlg::read("Ed448"), Ok(signing(SigningAlgorithm::Ed448)));
    }

    #[test]
    fn a_name_this_library_does_not_know_is_refused() {
        // RSA1_5 and none are registered; this library knows neither. A content encryption
        // name is not an alg.
        for name in [
            "",
            "none",
            "None",
            "RSA1_5",
            "es256",
            "ES256 ",
            "EDDSA",
            "eddsa",
            "HS1",
            "RSA-OAEP-1",
            "rsa-oaep-384",
            "A128GCM",
        ] {
            assert_eq!(KeyAlg::read(name), Err(AlgErrors::Unsupported), "{name:?}");
        }
    }

    #[test]
    fn each_alg_belongs_to_its_use() {
        assert_eq!(
            signing(SigningAlgorithm::Es256).key_use(),
            KeyUse::Signature
        );

        assert_eq!(
            key_management(KeyManagementAlgorithm::RsaOaep).key_use(),
            KeyUse::Encryption
        );
    }

    fn names(alg: KeyAlg) -> Vec<&'static str> {
        alg.operations().iter().map(|op| op.name()).collect()
    }

    #[test]
    fn a_signing_algorithm_signs_and_verifies() {
        for alg in SigningAlgorithm::ALL {
            assert_eq!(names(signing(alg)), ["sign", "verify"], "{alg:?}");
        }
    }

    #[test]
    fn each_key_management_algorithm_has_the_operations_of_its_key() {
        use KeyManagementAlgorithm as Km;

        // Written out by name on purpose, not taken from the constants.
        let oaep = &["encrypt", "decrypt", "wrapKey", "unwrapKey"][..];

        let wrap = &["wrapKey", "unwrapKey"][..];

        let derive = &["deriveKey", "deriveBits"][..];

        for (alg, expected) in [
            (Km::RsaOaep, oaep),
            (Km::RsaOaep256, oaep),
            (Km::RsaOaep384, oaep),
            (Km::RsaOaep512, oaep),
            (Km::A128Kw, wrap),
            (Km::A192Kw, wrap),
            (Km::A256Kw, wrap),
            (Km::A128GcmKw, wrap),
            (Km::A192GcmKw, wrap),
            (Km::A256GcmKw, wrap),
            (Km::Dir, &["encrypt", "decrypt"]),
            (Km::EcdhEs, derive),
            (Km::EcdhEsA128Kw, derive),
            (Km::EcdhEsA192Kw, derive),
            (Km::EcdhEsA256Kw, derive),
            (Km::Pbes2Hs256A128Kw, derive),
            (Km::Pbes2Hs384A192Kw, derive),
            (Km::Pbes2Hs512A256Kw, derive),
        ] {
            assert_eq!(names(key_management(alg)), expected, "{alg:?}");
        }
    }

    #[test]
    fn every_operation_of_an_alg_is_of_its_use() {
        for alg in every_alg() {
            for op in alg.operations() {
                assert_eq!(op.key_use(), alg.key_use(), "{alg:?} {op:?}");
            }
        }
    }

    #[test]
    fn the_public_side_does_part_of_what_the_key_does() {
        for alg in every_alg() {
            if let Some(public) = alg.public_operations() {
                for op in public {
                    assert!(alg.operations().contains(op), "{alg:?} {op:?}");
                }
            }
        }
    }

    fn public_names(alg: KeyAlg) -> Option<Vec<&'static str>> {
        alg.public_operations()
            .map(|ops| ops.iter().map(|op| op.name()).collect())
    }

    #[test]
    fn each_algorithm_has_the_public_side_of_its_key() {
        use KeyManagementAlgorithm as Km;

        use SigningAlgorithm as Sig;

        // Written out by name on purpose, not taken from the constants.
        for (alg, expected) in [
            (signing(Sig::Hs256), None),
            (signing(Sig::Hs512), None),
            (signing(Sig::Rs256), Some(vec!["verify"])),
            (signing(Sig::Ps256), Some(vec!["verify"])),
            (signing(Sig::Es256), Some(vec!["verify"])),
            (signing(Sig::Es256k), Some(vec!["verify"])),
            (signing(Sig::Ed25519), Some(vec!["verify"])),
            (signing(Sig::Ed448), Some(vec!["verify"])),
            (signing(Sig::MlDsa65), Some(vec!["verify"])),
            (
                key_management(Km::RsaOaep),
                Some(vec!["encrypt", "wrapKey"]),
            ),
            (
                key_management(Km::RsaOaep512),
                Some(vec!["encrypt", "wrapKey"]),
            ),
            (key_management(Km::EcdhEs), Some(vec![])),
            (key_management(Km::EcdhEsA256Kw), Some(vec![])),
            (key_management(Km::A256Kw), None),
            (key_management(Km::A256GcmKw), None),
            (key_management(Km::Dir), None),
            (key_management(Km::Pbes2Hs256A128Kw), None),
        ] {
            assert_eq!(public_names(alg), expected, "{alg:?}");
        }
    }
}
