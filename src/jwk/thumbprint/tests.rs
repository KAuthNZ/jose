use serde_json::Value;

use serde_json::json;

use crate::jwa::Es256;

use crate::jwa::Rs256;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

// RFC 8037 A.1 and A.3.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

const OKP_D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

const OKP_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

const OKP_THUMBPRINT_HEX: &str = "90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89";

// RFC 7517 A.1 and A.2, the P-256 key.
const EC_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const EC_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

const EC_D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

// RFC 7638 §3.1: the key of RFC 7517 A.1.
const RSA_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const RSA_THUMBPRINT: &str = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

fn public(value: Value) -> Jwk<Public> {
    Jwk::read_public(value.to_string().as_bytes()).unwrap()
}

fn private(value: Value) -> Jwk<Private> {
    Jwk::read_private(value.to_string().as_bytes()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn rfc_8037_a3_the_ed25519_thumbprint() {
    let jwk = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X }));

    assert_eq!(jwk.thumbprint().to_string(), OKP_THUMBPRINT);

    assert_eq!(hex(jwk.thumbprint().as_bytes()), OKP_THUMBPRINT_HEX);
}

#[test]
fn rfc_7638_section_3_1_the_rsa_thumbprint() {
    // With its alg and kid, which aren't hashed.
    let jwk = public(json!({
        "kty": "RSA", "n": RSA_N, "e": "AQAB", "alg": "RS256", "kid": "2011-04-29",
    }));

    assert_eq!(jwk.thumbprint().to_string(), RSA_THUMBPRINT);

    assert_eq!(
        jwk.thumbprint().as_bytes(),
        &[
            55, 54, 203, 177, 120, 124, 184, 48, 156, 119, 238, 140, 55, 5, 197, 225, 111, 251,
            158, 133, 151, 21, 144, 31, 30, 76, 89, 177, 17, 130, 245, 123
        ]
    );
}

#[test]
fn a_bound_key_has_the_thumbprint_it_had_unbound() {
    let unbound = public(json!({ "kty": "RSA", "n": RSA_N, "e": "AQAB" }));

    let thumbprint = unbound.thumbprint();

    assert_eq!(unbound.bind::<Rs256>().unwrap().thumbprint(), thumbprint);

    let okp = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X }));

    assert_eq!(
        okp.bind::<Ed25519>().unwrap().thumbprint().to_string(),
        OKP_THUMBPRINT
    );
}

#[test]
fn a_private_key_has_the_thumbprint_of_its_public_key() {
    let okp = private(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "d": OKP_D }));

    assert_eq!(okp.thumbprint().to_string(), OKP_THUMBPRINT);

    let bound = okp.bind::<Ed25519>().unwrap();

    assert_eq!(bound.thumbprint().to_string(), OKP_THUMBPRINT);

    assert_eq!(bound.public().thumbprint().to_string(), OKP_THUMBPRINT);

    let ec = private(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y, "d": EC_D }));

    let ec_public = public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y }));

    assert_eq!(
        ec.bind::<Es256>().unwrap().thumbprint(),
        ec_public.thumbprint()
    );
}

#[test]
fn kid_alg_and_use_dont_change_the_thumbprint() {
    let bare = public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y }));

    let named = public(json!({
        "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y,
        "kid": "1", "alg": "ES256", "use": "sig",
    }));

    assert_eq!(named.thumbprint(), bare.thumbprint());
}

#[test]
fn another_key_has_another_thumbprint() {
    let ec = public(json!({ "kty": "EC", "crv": "P-256", "x": EC_X, "y": EC_Y }));

    let okp = public(json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X }));

    assert_ne!(ec.thumbprint(), okp.thumbprint());
}
