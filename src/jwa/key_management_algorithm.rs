use super::curve::Curve;

use super::key_type::KeyType;

/// The key management algorithms of the JSON Web Signature and Encryption Algorithms registry
/// (RFC 7518 §7.1.2, RFC 8037 §3.2, W3C WebCrypto for RSA-OAEP-384 and RSA-OAEP-512).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyManagementAlgorithm {
    RsaOaep,

    RsaOaep256,

    RsaOaep384,

    RsaOaep512,

    A128Kw,

    A192Kw,

    A256Kw,

    Dir,

    EcdhEs,

    EcdhEsA128Kw,

    EcdhEsA192Kw,

    EcdhEsA256Kw,

    A128GcmKw,

    A192GcmKw,

    A256GcmKw,

    Pbes2Hs256A128Kw,

    Pbes2Hs384A192Kw,

    Pbes2Hs512A256Kw,
}

impl KeyManagementAlgorithm {
    pub const ALL: [Self; 18] = [
        Self::RsaOaep,
        Self::RsaOaep256,
        Self::RsaOaep384,
        Self::RsaOaep512,
        Self::A128Kw,
        Self::A192Kw,
        Self::A256Kw,
        Self::Dir,
        Self::EcdhEs,
        Self::EcdhEsA128Kw,
        Self::EcdhEsA192Kw,
        Self::EcdhEsA256Kw,
        Self::A128GcmKw,
        Self::A192GcmKw,
        Self::A256GcmKw,
        Self::Pbes2Hs256A128Kw,
        Self::Pbes2Hs384A192Kw,
        Self::Pbes2Hs512A256Kw,
    ];

    /// Exact and case-sensitive.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::RsaOaep => "RSA-OAEP",

            Self::RsaOaep256 => "RSA-OAEP-256",

            Self::RsaOaep384 => "RSA-OAEP-384",

            Self::RsaOaep512 => "RSA-OAEP-512",

            Self::A128Kw => "A128KW",

            Self::A192Kw => "A192KW",

            Self::A256Kw => "A256KW",

            Self::Dir => "dir",

            Self::EcdhEs => "ECDH-ES",

            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",

            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",

            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",

            Self::A128GcmKw => "A128GCMKW",

            Self::A192GcmKw => "A192GCMKW",

            Self::A256GcmKw => "A256GCMKW",

            Self::Pbes2Hs256A128Kw => "PBES2-HS256+A128KW",

            Self::Pbes2Hs384A192Kw => "PBES2-HS384+A192KW",

            Self::Pbes2Hs512A256Kw => "PBES2-HS512+A256KW",
        }
    }

    /// Pairs and not two lists, so that a combination that does not exist, such as EC with
    /// X25519, is never accepted.
    pub const fn keys(self) -> &'static [(KeyType, Option<Curve>)] {
        match self {
            Self::RsaOaep | Self::RsaOaep256 | Self::RsaOaep384 | Self::RsaOaep512 => {
                &[(KeyType::Rsa, None)]
            }

            Self::EcdhEs | Self::EcdhEsA128Kw | Self::EcdhEsA192Kw | Self::EcdhEsA256Kw => &[
                (KeyType::Ec, Some(Curve::P256)),
                (KeyType::Ec, Some(Curve::P384)),
                (KeyType::Ec, Some(Curve::P521)),
                (KeyType::Okp, Some(Curve::X25519)),
                (KeyType::Okp, Some(Curve::X448)),
            ],

            Self::Dir
            | Self::A128Kw
            | Self::A192Kw
            | Self::A256Kw
            | Self::A128GcmKw
            | Self::A192GcmKw
            | Self::A256GcmKw
            | Self::Pbes2Hs256A128Kw
            | Self::Pbes2Hs384A192Kw
            | Self::Pbes2Hs512A256Kw => &[(KeyType::Oct, None)],
        }
    }

    pub fn accepts(self, kty: KeyType, crv: Option<Curve>) -> bool {
        self.keys().contains(&(kty, crv))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(alg: KeyManagementAlgorithm) -> usize {
        match alg {
            KeyManagementAlgorithm::RsaOaep => 0,
            KeyManagementAlgorithm::RsaOaep256 => 1,
            KeyManagementAlgorithm::RsaOaep384 => 2,
            KeyManagementAlgorithm::RsaOaep512 => 3,
            KeyManagementAlgorithm::A128Kw => 4,
            KeyManagementAlgorithm::A192Kw => 5,
            KeyManagementAlgorithm::A256Kw => 6,
            KeyManagementAlgorithm::Dir => 7,
            KeyManagementAlgorithm::EcdhEs => 8,
            KeyManagementAlgorithm::EcdhEsA128Kw => 9,
            KeyManagementAlgorithm::EcdhEsA192Kw => 10,
            KeyManagementAlgorithm::EcdhEsA256Kw => 11,
            KeyManagementAlgorithm::A128GcmKw => 12,
            KeyManagementAlgorithm::A192GcmKw => 13,
            KeyManagementAlgorithm::A256GcmKw => 14,
            KeyManagementAlgorithm::Pbes2Hs256A128Kw => 15,
            KeyManagementAlgorithm::Pbes2Hs384A192Kw => 16,
            KeyManagementAlgorithm::Pbes2Hs512A256Kw => 17,
        }
    }

    #[test]
    fn all_lists_every_algorithm_once_and_in_order() {
        for (index, alg) in KeyManagementAlgorithm::ALL.into_iter().enumerate() {
            assert_eq!(position(alg), index, "{alg:?}");
        }
    }

    #[test]
    fn names_are_the_registered_ones() {
        let names: Vec<&str> = KeyManagementAlgorithm::ALL
            .into_iter()
            .map(KeyManagementAlgorithm::name)
            .collect();

        assert_eq!(
            names,
            [
                "RSA-OAEP",
                "RSA-OAEP-256",
                "RSA-OAEP-384",
                "RSA-OAEP-512",
                "A128KW",
                "A192KW",
                "A256KW",
                "dir",
                "ECDH-ES",
                "ECDH-ES+A128KW",
                "ECDH-ES+A192KW",
                "ECDH-ES+A256KW",
                "A128GCMKW",
                "A192GCMKW",
                "A256GCMKW",
                "PBES2-HS256+A128KW",
                "PBES2-HS384+A192KW",
                "PBES2-HS512+A256KW"
            ]
        );
    }

    #[test]
    fn an_algorithm_is_read_by_its_name() {
        for alg in KeyManagementAlgorithm::ALL {
            assert_eq!(KeyManagementAlgorithm::from_name(alg.name()), Some(alg));
        }
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "none",
            "DIR",
            "Dir",
            "dir ",
            "rsa-oaep",
            "RSA-OAEP ",
            "RSA_OAEP",
            "RSA1_5",
            "ECDH-ES ",
            "ECDH-ES+a128kw",
            "ECDH-ES A128KW",
            "a128kw",
            "PBES2-HS256-A128KW",
        ] {
            assert_eq!(KeyManagementAlgorithm::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn ecdh_es_takes_the_nist_curves_and_both_x_curves() {
        let alg = KeyManagementAlgorithm::EcdhEs;

        for crv in [Curve::P256, Curve::P384, Curve::P521] {
            assert!(alg.accepts(KeyType::Ec, Some(crv)), "{crv:?}");
        }

        for crv in [Curve::X25519, Curve::X448] {
            assert!(alg.accepts(KeyType::Okp, Some(crv)), "{crv:?}");
        }
    }

    #[test]
    fn ecdh_es_refuses_a_curve_of_another_key_type_or_one_made_for_signing() {
        let alg = KeyManagementAlgorithm::EcdhEs;

        for (kty, crv) in [
            (KeyType::Ec, Some(Curve::X25519)),
            (KeyType::Okp, Some(Curve::P256)),
            (KeyType::Okp, Some(Curve::Ed25519)),
            (KeyType::Okp, Some(Curve::Ed448)),
            (KeyType::Ec, Some(Curve::Secp256k1)),
            (KeyType::Ec, None),
        ] {
            assert!(!alg.accepts(kty, crv), "{kty:?} {crv:?}");
        }
    }

    #[test]
    fn rsa_oaep_and_the_symmetric_ones_take_only_their_key_type() {
        assert!(KeyManagementAlgorithm::RsaOaep256.accepts(KeyType::Rsa, None));
        assert!(!KeyManagementAlgorithm::RsaOaep256.accepts(KeyType::Oct, None));

        for alg in [
            KeyManagementAlgorithm::Dir,
            KeyManagementAlgorithm::A256Kw,
            KeyManagementAlgorithm::A256GcmKw,
            KeyManagementAlgorithm::Pbes2Hs512A256Kw,
        ] {
            assert!(alg.accepts(KeyType::Oct, None), "{alg:?}");
            assert!(!alg.accepts(KeyType::Rsa, None), "{alg:?}");
        }
    }
}
