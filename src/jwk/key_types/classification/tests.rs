use serde_json::Map;

use serde_json::Value;

use serde_json::json;

use crate::jwa::KeyType;

use crate::jwk::raw::RawJwk;

use crate::jwk::constants::SECRET_MEMBERS;

use super::super::ec::EcErrors;

use super::super::okp::OkpErrors;

use super::super::oct::OctErrors;

use super::AnyPublicKey;

use super::AnyPrivateKey;

use super::AnySecretKey;

use super::ClassificationErrors;

// RFC 7517 A.1 and A.2, the P-256 key.
const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

// RFC 8037 A.1.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

const OKP_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

fn ec_public() -> Value {
    json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y })
}

fn ec_private() -> Value {
    with(ec_public(), "d", json!(EC_D))
}

fn okp_public() -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X })
}

fn okp_private() -> Value {
    with(okp_public(), "d", json!(OKP_D))
}

// RFC 7517 A.3, the HMAC key of RFC 7515 A.1.
fn oct_secret() -> Value {
    json!({
        "kty": "oct",
        "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
    })
}

fn with(mut key: Value, name: &str, value: Value) -> Value {
    if let Value::Object(members) = &mut key {
        members.insert(name.to_owned(), value);
    }

    key
}

fn without(mut key: Value, name: &str) -> Value {
    if let Value::Object(members) = &mut key {
        members.remove(name);
    }

    key
}

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

fn public(value: Value) -> Result<AnyPublicKey, ClassificationErrors> {
    let RawJwk { kty, material, .. } = raw(value);

    AnyPublicKey::classify(&kty, material)
}

fn private(value: Value) -> Result<AnyPrivateKey, ClassificationErrors> {
    let RawJwk { kty, material, .. } = raw(value);

    AnyPrivateKey::classify(&kty, material)
}

fn refused_public(value: Value) -> ClassificationErrors {
    match public(value) {
        Ok(_) => panic!("classified"),

        Err(error) => error,
    }
}

fn refused_private(value: Value) -> ClassificationErrors {
    match private(value) {
        Ok(_) => panic!("classified"),

        Err(error) => error,
    }
}

#[test]
fn an_ec_key_is_classified_as_ec() {
    assert!(matches!(public(ec_public()), Ok(AnyPublicKey::Ec(_))));

    assert!(matches!(private(ec_private()), Ok(AnyPrivateKey::Ec(_))));
}

#[test]
fn an_okp_key_is_classified_as_okp() {
    assert!(matches!(public(okp_public()), Ok(AnyPublicKey::Okp(_))));

    assert!(matches!(private(okp_private()), Ok(AnyPrivateKey::Okp(_))));
}

#[test]
fn the_public_part_of_a_private_key_is_the_key_read_as_public() {
    let (Ok(AnyPrivateKey::Ec(secret)), Ok(AnyPublicKey::Ec(read))) =
        (private(ec_private()), public(ec_public()))
    else {
        panic!("not classified as EC");
    };

    let AnyPublicKey::Ec(derived) = AnyPrivateKey::Ec(secret).public() else {
        panic!("public() changed the family");
    };

    assert_eq!(derived, read);

    let (Ok(AnyPrivateKey::Okp(secret)), Ok(AnyPublicKey::Okp(read))) =
        (private(okp_private()), public(okp_public()))
    else {
        panic!("not classified as OKP");
    };

    let AnyPublicKey::Okp(derived) = AnyPrivateKey::Okp(secret).public() else {
        panic!("public() changed the family");
    };

    assert_eq!(derived, read);
}

#[test]
fn a_kty_that_is_not_registered_is_unknown() {
    for kty in ["", "ec", "Ec", "EC ", "okp", "FOO", "none"] {
        let key = with(ec_public(), "kty", json!(kty));

        assert_eq!(
            refused_public(key.clone()),
            ClassificationErrors::UnknownKty,
            "{kty:?}"
        );

        assert_eq!(
            refused_private(with(key, "d", json!(EC_D))),
            ClassificationErrors::UnknownKty,
            "{kty:?}"
        );
    }
}

#[test]
fn a_registered_kty_this_library_does_not_read_is_unsupported() {
    assert_eq!(
        refused_public(json!({ "kty": "AKP", "alg": "ML-DSA-44", "pub": "AAAA" })),
        ClassificationErrors::UnsupportedKty
    );
}

fn secret(value: Value) -> Result<AnySecretKey, ClassificationErrors> {
    let RawJwk { kty, material, .. } = raw(value);

    AnySecretKey::classify(&kty, material)
}

fn refused_secret(key: Value) -> ClassificationErrors {
    match secret(key) {
        Ok(_) => panic!("classified"),

        Err(error) => error,
    }
}

#[test]
fn an_oct_key_is_classified_only_as_secret() {
    let Ok(AnySecretKey::Oct(oct)) = secret(oct_secret()) else {
        panic!("not classified as oct");
    };

    assert_eq!(oct.len(), 64);

    assert_eq!(AnySecretKey::Oct(oct).shape().kty(), KeyType::Oct);

    assert_eq!(
        refused_private(oct_secret()),
        ClassificationErrors::SymmetricKty
    );
}

#[test]
fn an_asymmetric_key_read_as_secret_is_refused() {
    for key in [ec_private(), okp_private(), ec_public()] {
        assert_eq!(refused_secret(key), ClassificationErrors::AsymmetricKty);
    }
}

#[test]
fn an_oct_key_has_k_and_nothing_else() {
    assert_eq!(
        refused_secret(json!({ "kty": "oct" })),
        ClassificationErrors::MissingMember("k")
    );

    for (name, value) in [("x", OKP_X), ("d", OKP_D), ("n", "AQAB")] {
        assert_eq!(
            refused_secret(with(oct_secret(), name, json!(value))),
            ClassificationErrors::ForeignMember(name),
            "{name}"
        );
    }

    assert_eq!(
        refused_secret(with(oct_secret(), "k", json!(""))),
        ClassificationErrors::Oct(OctErrors::Empty)
    );

    assert_eq!(
        refused_secret(with(oct_secret(), "k", json!("AQ=="))),
        ClassificationErrors::Oct(OctErrors::InvalidEncoding)
    );
}

#[test]
fn an_oct_key_read_as_public_is_refused() {
    // With `k`, for the secret it holds; without it, for the side it doesn't have.
    assert_eq!(
        refused_public(oct_secret()),
        ClassificationErrors::SecretMember("k")
    );

    assert_eq!(
        refused_public(json!({ "kty": "oct" })),
        ClassificationErrors::NoPublicSide
    );
}

#[test]
fn a_secret_member_refuses_a_key_read_as_public() {
    // `oth` never gets here: raw refuses it first.
    for name in SECRET_MEMBERS.into_iter().filter(|name| *name != "oth") {
        assert_eq!(
            refused_public(with(ec_public(), name, json!("AQAB"))),
            ClassificationErrors::SecretMember(name),
            "{name}"
        );
    }
}

#[test]
fn a_secret_member_is_refused_before_the_kty_is_read() {
    for kty in ["FOO", "oct", "AKP"] {
        assert_eq!(
            refused_public(json!({ "kty": kty, "k": "AQAB" })),
            ClassificationErrors::SecretMember("k"),
            "{kty}"
        );
    }

    assert_eq!(
        refused_public(json!({ "kty": "AKP", "pub": "AAAA", "priv": "AAAA" })),
        ClassificationErrors::SecretMember("priv")
    );
}

#[test]
fn a_member_the_family_requires_is_missing() {
    for name in ["crv", "x", "y"] {
        assert_eq!(
            refused_public(without(ec_public(), name)),
            ClassificationErrors::MissingMember(name),
            "{name}"
        );
    }

    for name in ["crv", "x"] {
        assert_eq!(
            refused_public(without(okp_public(), name)),
            ClassificationErrors::MissingMember(name),
            "{name}"
        );
    }

    assert_eq!(
        refused_private(ec_public()),
        ClassificationErrors::MissingMember("d")
    );

    assert_eq!(
        refused_private(okp_public()),
        ClassificationErrors::MissingMember("d")
    );
}

#[test]
fn a_member_of_another_family_refuses_the_key() {
    for (key, name) in [
        (ec_public(), "n"),
        (ec_public(), "e"),
        (ec_public(), "pub"),
        (okp_public(), "y"),
        (okp_public(), "n"),
    ] {
        assert_eq!(
            refused_public(with(key, name, json!("AQAB"))),
            ClassificationErrors::ForeignMember(name),
            "{name}"
        );
    }

    for (key, name) in [
        (ec_private(), "n"),
        (okp_private(), "y"),
        (okp_private(), "k"),
    ] {
        assert_eq!(
            refused_private(with(key, name, json!("AQAB"))),
            ClassificationErrors::ForeignMember(name),
            "{name}"
        );
    }
}

#[test]
fn members_that_are_not_registered_are_dropped_not_judged() {
    let key = with(ec_public(), "foo", json!({ "anything": [1, 2, 3] }));

    assert!(matches!(public(key), Ok(AnyPublicKey::Ec(_))));
}

#[test]
fn structure_is_judged_before_material() {
    let broken = with(ec_public(), "x", json!("!!!"));

    assert_eq!(
        refused_public(with(broken.clone(), "n", json!("AQAB"))),
        ClassificationErrors::ForeignMember("n")
    );

    assert_eq!(
        refused_public(without(broken, "y")),
        ClassificationErrors::MissingMember("y")
    );
}

#[test]
fn what_the_family_refuses_comes_through() {
    assert_eq!(
        refused_public(with(ec_public(), "crv", json!("Ed25519"))),
        ClassificationErrors::Ec(EcErrors::ForeignCurve)
    );

    assert_eq!(
        refused_public(with(okp_public(), "crv", json!("P-256"))),
        ClassificationErrors::Okp(OkpErrors::ForeignCurve)
    );

    assert_eq!(
        refused_private(with(okp_private(), "d", json!(EC_D))),
        ClassificationErrors::Okp(OkpErrors::KeyMismatch)
    );
}

#[test]
fn a_classified_key_says_its_kty_and_crv() {
    use crate::jwa::Curve;

    use crate::jwa::KeyType;

    let of = |key: &AnyPublicKey| (key.shape().kty(), key.shape().crv());

    let of_private = |key: &AnyPrivateKey| (key.shape().kty(), key.shape().crv());

    let ec = Some(Curve::P256);

    let okp = Some(Curve::Ed25519);

    assert_eq!(
        public(ec_public()).map(|key| of(&key)),
        Ok((KeyType::Ec, ec))
    );

    assert_eq!(
        public(okp_public()).map(|key| of(&key)),
        Ok((KeyType::Okp, okp))
    );

    assert_eq!(
        private(ec_private()).map(|key| of_private(&key)),
        Ok((KeyType::Ec, ec))
    );

    assert_eq!(
        private(okp_private()).map(|key| of_private(&key)),
        Ok((KeyType::Okp, okp))
    );
}

mod rsa {
    use serde_json::Value;

    use serde_json::json;

    use super::super::super::rsa::RsaErrors;

    use super::*;

    // RFC 7517 A.1 and A.2, the RSA key.
    const N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

    const E: &str = "AQAB";

    const D: &str = "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";

    const P: &str = "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";

    const Q: &str = "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";

    const DP: &str = "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";

    const DQ: &str = "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";

    const QI: &str = "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";

    fn rsa_public() -> Value {
        json!({ "kty": "RSA", "n": N, "e": E })
    }

    fn rsa_private() -> Value {
        json!({
            "kty": "RSA", "n": N, "e": E, "d": D, "p": P, "q": Q, "dp": DP, "dq": DQ, "qi": QI,
        })
    }

    #[test]
    fn an_rsa_key_is_classified_as_rsa() {
        assert!(matches!(public(rsa_public()), Ok(AnyPublicKey::Rsa(_))));

        let Ok(AnyPrivateKey::Rsa(secret)) = private(rsa_private()) else {
            panic!("not classified as RSA");
        };

        let (AnyPublicKey::Rsa(derived), Ok(AnyPublicKey::Rsa(read))) =
            (AnyPrivateKey::Rsa(secret).public(), public(rsa_public()))
        else {
            panic!("public() changed the family");
        };

        assert_eq!(derived, read);
    }

    #[test]
    fn every_private_member_is_required() {
        for name in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
            assert_eq!(
                refused_private(without(rsa_private(), name)),
                ClassificationErrors::MissingMember(name),
                "{name}"
            );
        }

        for name in ["n", "e"] {
            assert_eq!(
                refused_public(without(rsa_public(), name)),
                ClassificationErrors::MissingMember(name),
                "{name}"
            );
        }
    }

    #[test]
    fn a_member_of_another_family_refuses_an_rsa_key() {
        for name in ["crv", "x", "y", "pub"] {
            assert_eq!(
                refused_public(with(rsa_public(), name, json!("AQAB"))),
                ClassificationErrors::ForeignMember(name),
                "{name}"
            );
        }

        assert_eq!(
            refused_private(with(rsa_private(), "x", json!("AQAB"))),
            ClassificationErrors::ForeignMember("x")
        );
    }

    #[test]
    fn what_rsa_refuses_comes_through() {
        assert_eq!(
            refused_public(with(rsa_public(), "e", json!("Aw"))),
            ClassificationErrors::Rsa(RsaErrors::UnsupportedExponent)
        );
    }

    #[test]
    fn an_rsa_key_has_no_curve() {
        use crate::jwa::KeyType;

        assert_eq!(
            public(rsa_public()).map(|key| (key.shape().kty(), key.shape().crv())),
            Ok((KeyType::Rsa, None))
        );

        assert_eq!(
            private(rsa_private()).map(|key| (key.shape().kty(), key.shape().crv())),
            Ok((KeyType::Rsa, None))
        );
    }
}

#[test]
fn an_unbound_public_key_writes_the_members_of_its_family() {
    let Ok(key) = public(ec_public()) else {
        panic!("not classified");
    };

    assert_eq!(
        key.public_members().to_json(),
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{EC_X}","y":"{EC_Y}"}}"#)
    );
}

#[test]
fn an_oct_key_says_its_size_and_no_curve() {
    let Ok(key) = secret(oct_secret()) else {
        panic!("not classified");
    };

    assert_eq!(key.shape().secret_len(), Some(64));

    assert_eq!(key.shape().crv(), None);
}
