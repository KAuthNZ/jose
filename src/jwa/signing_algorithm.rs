use serde::Serialize;

use serde::Serializer;

use serde::Deserialize;

use serde::Deserializer;

use serde::de::Error;

use super::curve::Curve;

use super::constants::EDDSA;

use super::key_type::KeyType;

/// The signature algorithms of the JSON Web Signature and Encryption Algorithms registry
/// (RFC 7518 §7.1.2, RFC 8812 §3.2, RFC 9864, draft-ietf-cose-dilithium), read by this library or
/// not. `EdDSA` is not one of them: it is read as `Ed25519`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    Hs256,

    Hs384,

    Hs512,

    Rs256,

    Rs384,

    Rs512,

    Ps256,

    Ps384,

    Ps512,

    Es256,

    Es384,

    Es512,

    Es256k,

    Ed25519,

    Ed448,

    MlDsa44,

    MlDsa65,

    MlDsa87,
}

impl SigningAlgorithm {
    pub const ALL: [Self; 18] = [
        Self::Hs256,
        Self::Hs384,
        Self::Hs512,
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
        Self::Es256,
        Self::Es384,
        Self::Es512,
        Self::Es256k,
        Self::Ed25519,
        Self::Ed448,
        Self::MlDsa44,
        Self::MlDsa65,
        Self::MlDsa87,
    ];

    /// Exact and case-sensitive. `EdDSA` is read as `Ed25519`: it also names Ed448, so whoever
    /// verifies must still require an OKP key with `crv` Ed25519.
    pub fn from_name(name: &str) -> Option<Self> {
        if name == EDDSA {
            return Some(Self::Ed25519);
        }

        Self::ALL.into_iter().find(|alg| alg.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",

            Self::Hs384 => "HS384",

            Self::Hs512 => "HS512",

            Self::Rs256 => "RS256",

            Self::Rs384 => "RS384",

            Self::Rs512 => "RS512",

            Self::Ps256 => "PS256",

            Self::Ps384 => "PS384",

            Self::Ps512 => "PS512",

            Self::Es256 => "ES256",

            Self::Es384 => "ES384",

            Self::Es512 => "ES512",

            Self::Es256k => "ES256K",

            Self::Ed25519 => "Ed25519",

            Self::Ed448 => "Ed448",

            Self::MlDsa44 => "ML-DSA-44",

            Self::MlDsa65 => "ML-DSA-65",

            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    pub const fn kty(self) -> KeyType {
        match self {
            Self::Hs256 | Self::Hs384 | Self::Hs512 => KeyType::Oct,

            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                KeyType::Rsa
            }

            Self::Es256 | Self::Es384 | Self::Es512 | Self::Es256k => KeyType::Ec,

            Self::Ed25519 | Self::Ed448 => KeyType::Okp,

            Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => KeyType::Akp,
        }
    }

    pub const fn crv(self) -> Option<Curve> {
        match self {
            Self::Es256 => Some(Curve::P256),

            Self::Es384 => Some(Curve::P384),

            Self::Es512 => Some(Curve::P521),

            Self::Es256k => Some(Curve::Secp256k1),

            Self::Ed25519 => Some(Curve::Ed25519),

            Self::Ed448 => Some(Curve::Ed448),

            Self::Hs256
            | Self::Hs384
            | Self::Hs512
            | Self::Rs256
            | Self::Rs384
            | Self::Rs512
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => None,
        }
    }

    /// The key the registry gives it, one `kty` and one `crv`: ES256 with P-384 is not ES256.
    pub fn accepts(self, kty: KeyType, crv: Option<Curve>) -> bool {
        self.kty() == kty && self.crv() == crv
    }

    /// In bytes. `None` for RS* and PS*: it is the length of the RSA modulus.
    pub const fn signature_len(self) -> Option<usize> {
        match self {
            Self::Hs256 => Some(32),

            Self::Hs384 => Some(48),

            Self::Hs512 => Some(64),

            // R || S (RFC 7518 §3.4).
            Self::Es256 => Some(64),

            Self::Es384 => Some(96),

            Self::Es512 => Some(132),

            Self::Es256k => Some(64),

            Self::Ed25519 => Some(64),

            Self::Ed448 => Some(114),

            Self::MlDsa44 => Some(2420),

            Self::MlDsa65 => Some(3309),

            Self::MlDsa87 => Some(4627),

            Self::Rs256 | Self::Rs384 | Self::Rs512 | Self::Ps256 | Self::Ps384 | Self::Ps512 => {
                None
            }
        }
    }

    /// In bytes, of `x` (OKP) or `pub` (AKP). `None` when the algorithm does not fix it.
    pub const fn public_key_len(self) -> Option<usize> {
        match self {
            Self::Ed25519 => Some(32),

            Self::Ed448 => Some(57),

            Self::MlDsa44 => Some(1312),

            Self::MlDsa65 => Some(1952),

            Self::MlDsa87 => Some(2592),

            Self::Hs256
            | Self::Hs384
            | Self::Hs512
            | Self::Rs256
            | Self::Rs384
            | Self::Rs512
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::Es256
            | Self::Es384
            | Self::Es512
            | Self::Es256k => None,
        }
    }

    /// In bytes, of `d` (OKP) or `priv` (AKP). For ML-DSA it is the seed, not the expanded key.
    pub const fn private_param_len(self) -> Option<usize> {
        match self {
            Self::Ed25519 | Self::MlDsa44 | Self::MlDsa65 | Self::MlDsa87 => Some(32),

            Self::Ed448 => Some(57),

            Self::Hs256
            | Self::Hs384
            | Self::Hs512
            | Self::Rs256
            | Self::Rs384
            | Self::Rs512
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::Es256
            | Self::Es384
            | Self::Es512
            | Self::Es256k => None,
        }
    }

    /// In bytes: the hash output (RFC 7518 §3.2). `None` where the key is not a secret.
    pub const fn min_secret_len(self) -> Option<usize> {
        match self {
            Self::Hs256 => Some(32),

            Self::Hs384 => Some(48),

            Self::Hs512 => Some(64),

            Self::Rs256
            | Self::Rs384
            | Self::Rs512
            | Self::Ps256
            | Self::Ps384
            | Self::Ps512
            | Self::Es256
            | Self::Es384
            | Self::Es512
            | Self::Es256k
            | Self::Ed25519
            | Self::Ed448
            | Self::MlDsa44
            | Self::MlDsa65
            | Self::MlDsa87 => None,
        }
    }
}

impl Serialize for SigningAlgorithm {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.name())
    }
}

/// The error never quotes what was read: it can come from a token.
impl<'de> Deserialize<'de> for SigningAlgorithm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let name = String::deserialize(deserializer)?;

        Self::from_name(&name).ok_or_else(|| D::Error::custom("unsupported signing algorithm"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(alg: SigningAlgorithm) -> usize {
        match alg {
            SigningAlgorithm::Hs256 => 0,
            SigningAlgorithm::Hs384 => 1,
            SigningAlgorithm::Hs512 => 2,
            SigningAlgorithm::Rs256 => 3,
            SigningAlgorithm::Rs384 => 4,
            SigningAlgorithm::Rs512 => 5,
            SigningAlgorithm::Ps256 => 6,
            SigningAlgorithm::Ps384 => 7,
            SigningAlgorithm::Ps512 => 8,
            SigningAlgorithm::Es256 => 9,
            SigningAlgorithm::Es384 => 10,
            SigningAlgorithm::Es512 => 11,
            SigningAlgorithm::Es256k => 12,
            SigningAlgorithm::Ed25519 => 13,
            SigningAlgorithm::Ed448 => 14,
            SigningAlgorithm::MlDsa44 => 15,
            SigningAlgorithm::MlDsa65 => 16,
            SigningAlgorithm::MlDsa87 => 17,
        }
    }

    #[test]
    fn all_lists_every_algorithm_once_and_in_order() {
        for (index, alg) in SigningAlgorithm::ALL.into_iter().enumerate() {
            assert_eq!(position(alg), index, "{alg:?}");
        }
    }

    #[test]
    fn names_are_the_registered_ones() {
        let names: Vec<&str> = SigningAlgorithm::ALL
            .into_iter()
            .map(SigningAlgorithm::name)
            .collect();

        assert_eq!(
            names,
            [
                "HS256",
                "HS384",
                "HS512",
                "RS256",
                "RS384",
                "RS512",
                "PS256",
                "PS384",
                "PS512",
                "ES256",
                "ES384",
                "ES512",
                "ES256K",
                "Ed25519",
                "Ed448",
                "ML-DSA-44",
                "ML-DSA-65",
                "ML-DSA-87"
            ]
        );
    }

    #[test]
    fn an_algorithm_is_read_by_its_name() {
        for alg in SigningAlgorithm::ALL {
            assert_eq!(SigningAlgorithm::from_name(alg.name()), Some(alg));
        }
    }

    #[test]
    fn eddsa_is_read_as_ed25519_and_written_as_ed25519() {
        let alg = SigningAlgorithm::from_name("EdDSA");

        assert_eq!(alg, Some(SigningAlgorithm::Ed25519));
        assert_eq!(alg.map(SigningAlgorithm::name), Some("Ed25519"));
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "none",
            "None",
            "NONE",
            "es256",
            "Es256",
            "ES256 ",
            " ES256",
            "ES256\0",
            "E\u{0405}256",
            "eddsa",
            "EDDSA",
            "EdDSA ",
            "ed25519",
            "ed448",
            "ED448",
            "es256k",
            "ES256k",
            "ES256K ",
            "ML-DSA44",
            "ml-dsa-44",
        ] {
            assert_eq!(SigningAlgorithm::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn serde_writes_and_reads_the_name() {
        for alg in SigningAlgorithm::ALL {
            let json = serde_json::to_string(&alg).unwrap();

            assert_eq!(json, format!("\"{}\"", alg.name()));
            assert_eq!(
                serde_json::from_str::<SigningAlgorithm>(&json).unwrap(),
                alg
            );
        }

        assert_eq!(
            serde_json::from_str::<SigningAlgorithm>("\"EdDSA\"").unwrap(),
            SigningAlgorithm::Ed25519
        );
    }

    #[test]
    fn serde_refuses_an_unknown_name_without_quoting_it() {
        let error = serde_json::from_str::<SigningAlgorithm>("\"<script>\"").unwrap_err();

        assert!(!error.to_string().contains("<script>"), "{error}");
    }

    #[test]
    fn each_algorithm_accepts_only_its_key() {
        let pairs = [
            (SigningAlgorithm::Hs256, KeyType::Oct, None),
            (SigningAlgorithm::Rs256, KeyType::Rsa, None),
            (SigningAlgorithm::Ps512, KeyType::Rsa, None),
            (SigningAlgorithm::Es256, KeyType::Ec, Some(Curve::P256)),
            (SigningAlgorithm::Es384, KeyType::Ec, Some(Curve::P384)),
            (SigningAlgorithm::Es512, KeyType::Ec, Some(Curve::P521)),
            (
                SigningAlgorithm::Es256k,
                KeyType::Ec,
                Some(Curve::Secp256k1),
            ),
            (
                SigningAlgorithm::Ed25519,
                KeyType::Okp,
                Some(Curve::Ed25519),
            ),
            (SigningAlgorithm::Ed448, KeyType::Okp, Some(Curve::Ed448)),
            (SigningAlgorithm::MlDsa65, KeyType::Akp, None),
        ];

        for (alg, kty, crv) in pairs {
            assert!(alg.accepts(kty, crv), "{alg:?}");
        }

        for (alg, kty, crv) in [
            (SigningAlgorithm::Es256, KeyType::Ec, Some(Curve::P384)),
            (SigningAlgorithm::Es256, KeyType::Ec, None),
            (SigningAlgorithm::Es256, KeyType::Okp, Some(Curve::P256)),
            (SigningAlgorithm::Ed25519, KeyType::Okp, Some(Curve::X25519)),
            (SigningAlgorithm::Ed25519, KeyType::Ec, Some(Curve::Ed25519)),
            (SigningAlgorithm::Ed25519, KeyType::Okp, Some(Curve::Ed448)),
            (SigningAlgorithm::Ed448, KeyType::Okp, Some(Curve::Ed25519)),
            (SigningAlgorithm::Es256k, KeyType::Ec, Some(Curve::P256)),
            (SigningAlgorithm::Es256, KeyType::Ec, Some(Curve::Secp256k1)),
            (SigningAlgorithm::Hs256, KeyType::Rsa, None),
            (SigningAlgorithm::Rs256, KeyType::Oct, None),
        ] {
            assert!(!alg.accepts(kty, crv), "{alg:?} {kty:?} {crv:?}");
        }
    }

    #[test]
    fn only_hs_has_a_minimum_secret_and_it_is_its_hash_output() {
        for alg in SigningAlgorithm::ALL {
            let expected = match alg.kty() {
                KeyType::Oct => alg.signature_len(),

                _ => None,
            };

            assert_eq!(alg.min_secret_len(), expected, "{alg:?}");
        }
    }

    #[test]
    fn an_ecdsa_signature_is_two_coordinates_of_its_curve() {
        for (alg, coordinate) in [
            (SigningAlgorithm::Es256, 32),
            (SigningAlgorithm::Es384, 48),
            (SigningAlgorithm::Es512, 66),
            (SigningAlgorithm::Es256k, 32),
        ] {
            assert_eq!(alg.signature_len(), Some(2 * coordinate), "{alg:?}");
        }
    }
}
