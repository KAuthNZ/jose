use serde_json::Value;

use serde_json::json;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

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
