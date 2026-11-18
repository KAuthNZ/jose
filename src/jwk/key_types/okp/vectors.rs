//! The five Ed25519 key pairs of RFC 8032 7.1, its hex written as `x` and `d`. Each was checked
//! apart with OpenSSL: the public key of the seed is the one the RFC prints. A refusal here is a
//! bug of the reading.

use serde_json::Value;

use super::super::duplicate::Duplicate;

use super::OkpPublicKey;

use super::OkpPrivateKey;

use super::super::public_members::Publishes;

const RFC8032_KEYS: &str = include_str!("../../../../testdata/okp/rfc8032_ed25519_keys.json");

fn member<'a>(key: &'a Value, name: &str) -> &'a str {
    key.get(name).and_then(Value::as_str).unwrap()
}

#[test]
fn every_ed25519_key_pair_of_rfc_8032_is_read_and_written_back_as_it_came() {
    let Value::Array(keys) = serde_json::from_str(RFC8032_KEYS).unwrap() else {
        panic!("not an array");
    };

    assert_eq!(keys.len(), 5);

    for key in &keys {
        let source = member(key, "source");

        let public = match OkpPublicKey::read("Ed25519", member(key, "x")) {
            Ok(public) => public,

            Err(error) => panic!("{source}: {error:?}"),
        };

        let private = match OkpPrivateKey::read("Ed25519", member(key, "x"), member(key, "d")) {
            Ok(private) => private,

            Err(error) => panic!("{source}: {error:?}"),
        };

        assert_eq!(private.public(), public, "{source}");

        assert_eq!(private.duplicate().public(), public, "{source}");

        let written: Value =
            serde_json::from_str(&public.public_members().thumbprint_json()).unwrap();

        assert_eq!(written.get("x"), key.get("x"), "{source}");
    }
}
