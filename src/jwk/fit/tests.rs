use serde_json::Map;

use serde_json::Value;

use serde_json::json;

use crate::jwa::Curve;

use crate::jwa::Algorithm;

use crate::jwa::SigningAlgorithm as Sig;

use crate::jwa::KeyManagementAlgorithm as Km;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

use crate::jwk::mode::Secret;

use crate::jwk::raw::RawJwk;

use crate::jwk::members::KeyAlg;

use crate::jwk::members::KeyMetadata;

use crate::jwk::members::KeyMetadataMembers;

use crate::jwk::key_types::KeyShape;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnyPrivateKey;

use super::FitErrors;

use super::Candidates;

fn sig(alg: Sig) -> KeyAlg {
    KeyAlg::from(Algorithm::Signing(alg))
}

fn km(alg: Km) -> KeyAlg {
    KeyAlg::from(Algorithm::KeyManagement(alg))
}

/// The members of one JWK, by name: what a case doesn't name is absent.
#[derive(Default)]
struct Given<'a> {
    alg: Option<&'a str>,

    key_use: Option<&'a str>,

    key_ops: Option<&'a [&'a str]>,
}

fn metadata(given: Given<'_>) -> KeyMetadata {
    let key_ops: Option<Vec<String>> = given
        .key_ops
        .map(|ops| ops.iter().map(|op| (*op).to_owned()).collect());

    match KeyMetadata::read(KeyMetadataMembers {
        alg: given.alg,
        key_use: given.key_use,
        key_ops: key_ops.as_deref(),
    }) {
        Ok(metadata) => metadata,

        Err(error) => panic!("members refused it: {error:?}"),
    }
}

fn public(shape: KeyShape, given: Given<'_>) -> Result<Vec<KeyAlg>, FitErrors> {
    Candidates::of::<Public>(shape, &metadata(given)).map(|found| found.algs().to_vec())
}

fn private(shape: KeyShape, given: Given<'_>) -> Result<Vec<KeyAlg>, FitErrors> {
    Candidates::of::<Private>(shape, &metadata(given)).map(|found| found.algs().to_vec())
}

fn secret(shape: KeyShape, given: Given<'_>) -> Result<Vec<KeyAlg>, FitErrors> {
    Candidates::of::<Secret>(shape, &metadata(given)).map(|found| found.algs().to_vec())
}

fn hs(algs: &[Sig]) -> Vec<KeyAlg> {
    algs.iter().copied().map(sig).collect()
}

const P256: KeyShape = KeyShape::Ec(Curve::P256);

const ED25519: KeyShape = KeyShape::Okp(Curve::Ed25519);

fn ecdh_es() -> Vec<KeyAlg> {
    [
        Km::EcdhEs,
        Km::EcdhEsA128Kw,
        Km::EcdhEsA192Kw,
        Km::EcdhEsA256Kw,
    ]
    .map(km)
    .to_vec()
}

#[test]
fn without_metadata_a_key_has_every_algorithm_that_takes_it() {
    let mut p256 = vec![sig(Sig::Es256)];

    p256.extend(ecdh_es());

    assert_eq!(public(P256, Given::default()), Ok(p256.clone()));

    assert_eq!(private(P256, Given::default()), Ok(p256));

    assert_eq!(
        public(ED25519, Given::default()),
        Ok(vec![sig(Sig::Ed25519)])
    );
}

#[test]
fn a_symmetric_algorithm_never_takes_a_public_key() {
    assert_eq!(
        public(KeyShape::Oct { len: 64 }, Given::default()),
        Err(FitErrors::NoAlgorithm)
    );

    assert_eq!(
        secret(KeyShape::Oct { len: 64 }, Given::default()),
        Ok(hs(&[Sig::Hs256, Sig::Hs384, Sig::Hs512]))
    );
}

#[test]
fn alg_narrows_to_itself_only_when_it_takes_the_key() {
    let es256 = || Given {
        alg: Some("ES256"),
        ..Given::default()
    };

    assert_eq!(public(P256, es256()), Ok(vec![sig(Sig::Es256)]));

    for (shape, given) in [
        (KeyShape::Ec(Curve::P384), es256()),
        (ED25519, es256()),
        (
            P256,
            Given {
                alg: Some("RSA-OAEP"),
                ..Given::default()
            },
        ),
        (
            ED25519,
            Given {
                alg: Some("ECDH-ES"),
                ..Given::default()
            },
        ),
    ] {
        assert_eq!(public(shape, given), Err(FitErrors::AlgAndKey), "{shape:?}");
    }
}

#[test]
fn a_public_key_under_an_algorithm_without_a_public_side_is_refused() {
    assert_eq!(
        public(
            KeyShape::Oct { len: 64 },
            Given {
                alg: Some("A256KW"),
                ..Given::default()
            }
        ),
        Err(FitErrors::NoAlgorithm)
    );
}

#[test]
fn use_narrows_to_its_algorithms() {
    let with_use = |key_use| Given {
        key_use: Some(key_use),
        ..Given::default()
    };

    assert_eq!(public(P256, with_use("sig")), Ok(vec![sig(Sig::Es256)]));

    assert_eq!(public(P256, with_use("enc")), Ok(ecdh_es()));

    // Nothing in the library says Ed25519 is for signatures: no algorithm of encryption takes it.
    assert_eq!(public(ED25519, with_use("enc")), Err(FitErrors::UseAndKey));
}

fn with_ops<'a>(key_ops: &'a [&'a str]) -> Given<'a> {
    Given {
        key_ops: Some(key_ops),
        ..Given::default()
    }
}

#[test]
fn an_empty_key_ops_is_a_key_agreement_public_key_and_nothing_else() {
    assert_eq!(public(P256, with_ops(&[])), Ok(ecdh_es()));

    assert_eq!(public(ED25519, with_ops(&[])), Err(FitErrors::KeyOpsAndKey));

    assert_eq!(private(P256, with_ops(&[])), Err(FitErrors::KeyOpsAndKey));
}

#[test]
fn a_public_key_declares_only_what_its_public_side_does() {
    for (shape, key_ops) in [
        (P256, &["sign"][..]),
        (P256, &["deriveKey"]),
        (P256, &["deriveKey", "deriveBits"]),
        (ED25519, &["sign", "verify"]),
    ] {
        assert_eq!(
            public(shape, with_ops(key_ops)),
            Err(FitErrors::KeyOpsAndKey),
            "{shape:?} {key_ops:?}"
        );
    }

    assert_eq!(
        public(P256, with_ops(&["verify"])),
        Ok(vec![sig(Sig::Es256)])
    );
}

#[test]
fn a_private_key_declares_anything_its_algorithm_does() {
    assert_eq!(
        private(P256, with_ops(&["deriveKey", "deriveBits"])),
        Ok(ecdh_es())
    );

    assert_eq!(
        private(P256, with_ops(&["verify"])),
        Ok(vec![sig(Sig::Es256)])
    );
}

// RFC 7517 A.1, the P-256 key.
const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

// RFC 8037 A.1.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn raw(value: Value) -> RawJwk {
    let members: Map<String, Value> = match value {
        Value::Object(members) => members,

        other => panic!("not an object: {other}"),
    };

    match RawJwk::try_from(members) {
        Ok(raw) => raw,

        Err(error) => panic!("raw refused it: {error:?}"),
    }
}

fn read_metadata(raw: &RawJwk) -> KeyMetadata {
    match KeyMetadata::read(KeyMetadataMembers {
        alg: raw.alg.as_deref(),
        key_use: raw.key_use.as_deref(),
        key_ops: raw.key_ops.as_deref(),
    }) {
        Ok(metadata) => metadata,

        Err(error) => panic!("members refused it: {error:?}"),
    }
}

fn fit_public(value: Value) -> Result<Vec<KeyAlg>, FitErrors> {
    let raw = raw(value);

    let metadata = read_metadata(&raw);

    let key = match AnyPublicKey::classify(&raw.kty, raw.material) {
        Ok(key) => key,

        Err(error) => panic!("not classified: {error:?}"),
    };

    Candidates::of_public(&key, &metadata).map(|found| found.algs().to_vec())
}

fn fit_private(value: Value) -> Result<Vec<KeyAlg>, FitErrors> {
    let raw = raw(value);

    let metadata = read_metadata(&raw);

    let key = match AnyPrivateKey::classify(&raw.kty, raw.material) {
        Ok(key) => key,

        Err(error) => panic!("not classified: {error:?}"),
    };

    Candidates::of_private(&key, &metadata).map(|found| found.algs().to_vec())
}

#[test]
fn an_ecdh_public_key_as_webcrypto_exports_it_is_one_of_key_agreement() {
    let exported = json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "key_ops": [], "ext": true,
    });

    assert_eq!(fit_public(exported), Ok(ecdh_es()));
}

#[test]
fn a_classified_key_is_fitted_by_its_own_kty_crv_and_mode() {
    assert_eq!(
        fit_public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "use": "enc" })),
        Err(FitErrors::UseAndKey)
    );

    assert_eq!(
        fit_public(json!({
            "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "key_ops": ["deriveKey"],
        })),
        Err(FitErrors::KeyOpsAndKey)
    );

    assert_eq!(
        fit_private(json!({
            "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "d": EC_D,
            "key_ops": ["deriveKey"],
        })),
        Ok(ecdh_es())
    );
}

#[test]
fn a_secret_takes_each_hs_algorithm_its_size_reaches() {
    let cases: [(usize, &[Sig]); 6] = [
        (32, &[Sig::Hs256]),
        (47, &[Sig::Hs256]),
        (48, &[Sig::Hs256, Sig::Hs384]),
        (63, &[Sig::Hs256, Sig::Hs384]),
        (64, &[Sig::Hs256, Sig::Hs384, Sig::Hs512]),
        (4096, &[Sig::Hs256, Sig::Hs384, Sig::Hs512]),
    ];

    for (len, algs) in cases {
        assert_eq!(
            secret(KeyShape::Oct { len }, Given::default()),
            Ok(hs(algs)),
            "{len}"
        );
    }
}

#[test]
fn a_secret_shorter_than_every_hash_output_has_no_algorithm() {
    for len in [1, 16, 31] {
        assert_eq!(
            secret(KeyShape::Oct { len }, Given::default()),
            Err(FitErrors::NoAlgorithm),
            "{len}"
        );
    }
}

#[test]
fn an_alg_the_secret_is_too_short_for_is_refused() {
    assert_eq!(
        secret(
            KeyShape::Oct { len: 32 },
            Given {
                alg: Some("HS512"),
                ..Given::default()
            }
        ),
        Err(FitErrors::AlgAndKey)
    );
}

#[test]
fn a_secret_takes_no_key_management_algorithm_until_jwe() {
    // RFC 7517 A.3 declares its 16-byte key for A128KW: too short for any HS, it has nothing.
    assert_eq!(
        secret(
            KeyShape::Oct { len: 16 },
            Given {
                alg: Some("A128KW"),
                ..Given::default()
            }
        ),
        Err(FitErrors::NoAlgorithm)
    );

    assert_eq!(
        secret(
            KeyShape::Oct { len: 64 },
            Given {
                alg: Some("A256KW"),
                ..Given::default()
            }
        ),
        Err(FitErrors::AlgAndKey)
    );

    assert_eq!(
        secret(
            KeyShape::Oct { len: 64 },
            Given {
                key_use: Some("enc"),
                ..Given::default()
            }
        ),
        Err(FitErrors::UseAndKey)
    );
}

mod rsa {
    use crate::jwa::SigningAlgorithm as Sig;

    use crate::jwa::KeyManagementAlgorithm as Km;

    use crate::jwk::members::KeyAlg;

    use crate::jwk::key_types::KeyShape;

    use super::Given;

    use super::public;

    use super::private;

    use super::with_ops;

    use super::km;

    use super::sig;

    use super::FitErrors;

    const RSA: KeyShape = KeyShape::Rsa;

    fn rsa_signing() -> Vec<KeyAlg> {
        [
            Sig::Rs256,
            Sig::Rs384,
            Sig::Rs512,
            Sig::Ps256,
            Sig::Ps384,
            Sig::Ps512,
        ]
        .map(sig)
        .to_vec()
    }

    fn rsa_oaep() -> Vec<KeyAlg> {
        [Km::RsaOaep, Km::RsaOaep256, Km::RsaOaep384, Km::RsaOaep512]
            .map(km)
            .to_vec()
    }

    #[test]
    fn without_metadata_an_rsa_key_has_every_rsa_algorithm() {
        let mut rsa = rsa_signing();

        rsa.extend(rsa_oaep());

        assert_eq!(public(RSA, Given::default()), Ok(rsa.clone()));

        assert_eq!(private(RSA, Given::default()), Ok(rsa));
    }

    #[test]
    fn an_alg_of_another_family_does_not_take_an_rsa_key() {
        let es256 = Given {
            alg: Some("ES256"),
            ..Given::default()
        };

        assert_eq!(public(RSA, es256), Err(FitErrors::AlgAndKey));
    }

    #[test]
    fn use_enc_narrows_an_rsa_key_to_rsa_oaep() {
        let enc = Given {
            key_use: Some("enc"),
            ..Given::default()
        };

        assert_eq!(public(RSA, enc), Ok(rsa_oaep()));
    }

    #[test]
    fn an_rsa_public_key_declares_only_what_its_public_side_does() {
        for key_ops in [&[][..], &["decrypt"], &["unwrapKey"]] {
            assert_eq!(
                public(RSA, with_ops(key_ops)),
                Err(FitErrors::KeyOpsAndKey),
                "{key_ops:?}"
            );
        }

        // As WebCrypto exports an RSA-OAEP public key: always with its alg (WebCrypto §22.4.5).
        assert_eq!(
            public(
                RSA,
                Given {
                    alg: Some("RSA-OAEP-256"),
                    key_ops: Some(&["encrypt", "wrapKey"]),
                    ..Given::default()
                }
            ),
            Ok(vec![km(Km::RsaOaep256)])
        );

        assert_eq!(public(RSA, with_ops(&["encrypt"])), Ok(rsa_oaep()));
    }

    #[test]
    fn an_rsa_private_key_declares_anything_its_algorithm_does() {
        assert_eq!(private(RSA, with_ops(&["sign"])), Ok(rsa_signing()));
    }

    #[test]
    fn three_operations_of_rsa_oaep_fit_a_private_key_only() {
        let given = || Given {
            alg: Some("RSA-OAEP"),
            key_ops: Some(&["encrypt", "decrypt", "unwrapKey"]),
            ..Given::default()
        };

        assert_eq!(private(RSA, given()), Ok(vec![km(Km::RsaOaep)]));

        assert_eq!(public(RSA, given()), Err(FitErrors::KeyOpsAndKey));
    }
}
