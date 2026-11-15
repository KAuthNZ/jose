use serde_json::Value;

use serde_json::json;

use crate::jwa::Rs256;

use crate::jwa::Rs384;

use crate::jwa::Rs512;

use crate::jwa::Ps256;

use crate::jwa::Ps384;

use crate::jwa::Ps512;

use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::key_types::PublicSide;

use crate::jwk::key_types::AnyPublicKey;

use super::BindErrors;

// RFC 8037 A.1.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

const OKP_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

// RFC 7517 A.1 and A.2, the P-256 key.
const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

fn public(value: Value) -> Jwk<Public> {
    Jwk::read_public(value.to_string().as_bytes()).unwrap()
}

fn private(value: Value) -> Jwk<Private> {
    Jwk::read_private(value.to_string().as_bytes()).unwrap()
}

#[test]
fn an_ed25519_public_key_is_bound_with_its_kid() {
    let jwk = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "kid": "1" }));

    let key = jwk.bind::<Ed25519>().unwrap();

    assert_eq!(key.kid(), Some("1"));

    assert_eq!(
        key.held.as_bytes(),
        &[
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ]
    );
}

#[test]
fn an_ed25519_private_key_is_bound_with_its_public_key() {
    let jwk = private(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "d": OKP_D }));

    let key = jwk.bind::<Ed25519>().unwrap();

    let public = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X }))
        .bind::<Ed25519>()
        .unwrap();

    assert_eq!(key.held.public(), public.held);
}

#[test]
fn an_algorithm_that_is_not_a_candidate_is_refused() {
    // The typestate lets any public key try Ed25519: only its candidates refuse it.
    let jwk = public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y }));

    assert_eq!(jwk.bind::<Ed25519>().err(), Some(BindErrors::NotACandidate));
}

#[test]
fn a_declared_alg_leaves_only_itself_to_bind() {
    // The algorithm the JWK declares is the one asked for.
    let jwk = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "alg": "Ed25519" }));

    assert!(jwk.bind::<Ed25519>().is_ok());
}

#[test]
fn a_private_key_kept_by_duplicating_it_binds_twice() {
    let jwk = private(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "d": OKP_D }));

    let first = jwk.duplicate().bind::<Ed25519>().unwrap();

    let second = jwk.bind::<Ed25519>().unwrap();

    assert_eq!(first.held.public(), second.held.public());
}

const EC_RFC_KEYS: &str = include_str!("../../../testdata/ec/rfc_keys.json");

fn ec_keys() -> Vec<Value> {
    match serde_json::from_str(EC_RFC_KEYS).unwrap() {
        Value::Array(keys) => keys,

        other => panic!("not an array: {other}"),
    }
}

/// The key of the RFCs as a JWK: `source` dropped, `kty` added.
fn ec_jwk(key: &Value) -> Value {
    let mut jwk = key.clone();

    let members = jwk.as_object_mut().unwrap();

    members.remove("source");

    members.insert("kty".to_owned(), json!("EC"));

    jwk
}

/// The public JWK of a key of the RFCs: `d` dropped.
fn ec_public_jwk(key: &Value) -> Value {
    let mut jwk = ec_jwk(key);

    jwk.as_object_mut().unwrap().remove("d");

    jwk
}

#[test]
fn every_ec_key_of_the_rfcs_is_bound_to_the_algorithm_of_its_curve() {
    let keys = ec_keys();

    assert_eq!(keys.len(), 15);

    for key in &keys {
        let source = key.get("source").and_then(Value::as_str).unwrap();

        let public = public(ec_public_jwk(key));

        let bound = match key.get("crv").and_then(Value::as_str).unwrap() {
            "P-256" => public.bind::<Es256>().map(|_| ()),

            "P-384" => public.bind::<Es384>().map(|_| ()),

            "P-521" => public.bind::<Es512>().map(|_| ()),

            other => panic!("{source}: {other}"),
        };

        assert_eq!(bound, Ok(()), "{source}");
    }
}

#[test]
fn every_ec_private_key_of_the_rfcs_is_bound_with_its_public_key() {
    let keys = ec_keys();

    let privates: Vec<&Value> = keys.iter().filter(|key| key.get("d").is_some()).collect();

    assert!(!privates.is_empty());

    for key in privates {
        let source = key.get("source").and_then(Value::as_str).unwrap();

        let private = private(ec_jwk(key));

        let public = public(ec_public_jwk(key));

        match key.get("crv").and_then(Value::as_str).unwrap() {
            "P-256" => assert_eq!(
                private.bind::<Es256>().unwrap().held.public(),
                public.bind::<Es256>().unwrap().held,
                "{source}"
            ),

            "P-384" => assert_eq!(
                private.bind::<Es384>().unwrap().held.public(),
                public.bind::<Es384>().unwrap().held,
                "{source}"
            ),

            "P-521" => assert_eq!(
                private.bind::<Es512>().unwrap().held.public(),
                public.bind::<Es512>().unwrap().held,
                "{source}"
            ),

            other => panic!("{source}: {other}"),
        }
    }
}

#[test]
fn an_ec_key_is_not_a_candidate_of_another_curve() {
    let p256 = || public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y }));

    assert_eq!(
        p256().bind::<Es384>().err(),
        Some(BindErrors::NotACandidate)
    );

    assert_eq!(
        p256().bind::<Es512>().err(),
        Some(BindErrors::NotACandidate)
    );
}

// RFC 7517 A.3, the HMAC key: 64 bytes, long enough for every HS.
const HMAC_K: &str =
    "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

// The bytes 0 to 31: long enough for HS256 only.
const K_32: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

fn secret(value: Value) -> Jwk<Secret> {
    Jwk::read_secret(value.to_string().as_bytes()).unwrap()
}

#[test]
fn a_secret_long_enough_for_every_hs_is_bound_to_each() {
    let jwk = secret(json!({ "kty": "oct", "k": HMAC_K, "kid": "hmac" }));

    let hs256 = jwk.duplicate().bind::<Hs256>().unwrap();

    let hs384 = jwk.duplicate().bind::<Hs384>().unwrap();

    let hs512 = jwk.bind::<Hs512>().unwrap();

    for key in [&hs256.held, &hs384.held, &hs512.held] {
        assert_eq!(key.len(), 64);
    }

    assert_eq!(hs256.kid(), Some("hmac"));
}

#[test]
fn a_secret_too_short_for_an_hs_is_not_its_candidate() {
    let jwk = || secret(json!({ "kty": "oct", "k": K_32 }));

    assert!(jwk().bind::<Hs256>().is_ok());

    assert_eq!(jwk().bind::<Hs384>().err(), Some(BindErrors::NotACandidate));

    assert_eq!(jwk().bind::<Hs512>().err(), Some(BindErrors::NotACandidate));
}

#[test]
fn a_secret_that_declares_its_alg_is_bound_to_that_one_only() {
    let jwk = || secret(json!({ "kty": "oct", "k": HMAC_K, "alg": "HS384" }));

    assert!(jwk().bind::<Hs384>().is_ok());

    assert_eq!(jwk().bind::<Hs256>().err(), Some(BindErrors::NotACandidate));

    assert_eq!(jwk().bind::<Hs512>().err(), Some(BindErrors::NotACandidate));
}

const RSA_RFC_KEYS: &str = include_str!("../../../testdata/rsa/rfc_private_keys.json");

const RSA_GENERATED_KEYS: &str = include_str!("../../../testdata/rsa/generated_private_keys.json");

/// The fourteen RSA keys of the testdata as private JWKs: `source` and `short` dropped.
fn rsa_keys() -> Vec<(String, Value)> {
    [RSA_RFC_KEYS, RSA_GENERATED_KEYS]
        .into_iter()
        .flat_map(|source| match serde_json::from_str(source).unwrap() {
            Value::Array(keys) => keys,

            other => panic!("not an array: {other}"),
        })
        .map(|mut key| {
            let members = key.as_object_mut().unwrap();

            let source = members
                .remove("source")
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();

            members.remove("short");

            members.insert("kty".to_owned(), json!("RSA"));

            (source, key)
        })
        .collect()
}

/// `n` and `e` alone.
fn rsa_public_jwk(key: &Value) -> Value {
    json!({ "kty": "RSA", "n": key.get("n").unwrap(), "e": key.get("e").unwrap() })
}

#[test]
fn every_rsa_key_of_the_testdata_is_bound_to_every_rsa_algorithm() {
    let keys = rsa_keys();

    assert_eq!(keys.len(), 14);

    for (source, key) in &keys {
        let private = private(key.clone());

        let public = public(rsa_public_jwk(key));

        let expected = match &public.held.material {
            AnyPublicKey::Rsa(key) => key.clone(),

            _ => panic!("{source}: not RSA"),
        };

        let bound = [
            private
                .duplicate()
                .bind::<Rs256>()
                .map(|key| key.held.public()),
            private
                .duplicate()
                .bind::<Rs384>()
                .map(|key| key.held.public()),
            private
                .duplicate()
                .bind::<Rs512>()
                .map(|key| key.held.public()),
            private
                .duplicate()
                .bind::<Ps256>()
                .map(|key| key.held.public()),
            private
                .duplicate()
                .bind::<Ps384>()
                .map(|key| key.held.public()),
            private.bind::<Ps512>().map(|key| key.held.public()),
        ];

        for public in bound {
            assert_eq!(public.as_ref(), Ok(&expected), "{source}");
        }

        let publics = [
            public.clone().bind::<Rs256>().map(|key| key.held),
            public.clone().bind::<Rs384>().map(|key| key.held),
            public.clone().bind::<Rs512>().map(|key| key.held),
            public.clone().bind::<Ps256>().map(|key| key.held),
            public.clone().bind::<Ps384>().map(|key| key.held),
            public.bind::<Ps512>().map(|key| key.held),
        ];

        for public in publics {
            assert_eq!(public.as_ref(), Ok(&expected), "{source}");
        }
    }
}

#[test]
fn an_rsa_key_that_declares_its_alg_or_use_is_bound_to_those_only() {
    let (_, key) = rsa_keys().remove(0);

    let mut rs256 = rsa_public_jwk(&key);

    rs256
        .as_object_mut()
        .unwrap()
        .insert("alg".to_owned(), json!("RS256"));

    assert!(public(rs256.clone()).bind::<Rs256>().is_ok());

    assert_eq!(
        public(rs256).bind::<Ps256>().err(),
        Some(BindErrors::NotACandidate)
    );

    // `use: enc` leaves RSA-OAEP only: no signature algorithm is a candidate.
    let mut enc = rsa_public_jwk(&key);

    enc.as_object_mut()
        .unwrap()
        .insert("use".to_owned(), json!("enc"));

    assert_eq!(
        public(enc).bind::<Rs256>().err(),
        Some(BindErrors::NotACandidate)
    );
}
