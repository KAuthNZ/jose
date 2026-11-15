//! Keys made by others: the private keys printed in the RFCs, and keys made by a generator that
//! is not this crate's backend. Each was checked apart, with plain arithmetic, to be a valid key
//! (`n = p·q`, `d·e ≡ 1`, and `dp`, `dq`, `qi` derived from them): a refusal here is a bug of the
//! reading, not of the key.

use serde_json::Value;

use super::super::duplicate::Duplicate;

use super::super::public_side::PublicSide;

use super::RsaPublicKey;

use super::RsaPrivateKey;

use super::RsaPrivateKeyMembers;

/// RFC 7515 A.2, RFC 7516 A.1.3 and A.2.3, RFC 7520 3.4, 5.1.1, 5.2.1 (4096 bits) and 6.1.
const RFC_KEYS: &str = include_str!("../../../../testdata/rsa/rfc_private_keys.json");

/// Made by an independent generator: 2048, 3072 and 4096 bits, and keys whose `dp`, `dq` or `qi`
/// is a byte shorter than their prime, which is where the comparison widens what it compares.
const GENERATED_KEYS: &str = include_str!("../../../../testdata/rsa/generated_private_keys.json");

fn member<'a>(key: &'a Value, name: &str) -> &'a str {
    key.get(name).and_then(Value::as_str).unwrap()
}

fn keys(source: &str) -> Vec<Value> {
    match serde_json::from_str(source).unwrap() {
        Value::Array(keys) => keys,

        other => panic!("not an array: {other}"),
    }
}

fn read(key: &Value) -> RsaPrivateKey {
    let read = RsaPrivateKey::read(RsaPrivateKeyMembers {
        n: member(key, "n"),
        e: member(key, "e"),
        d: member(key, "d"),
        p: member(key, "p"),
        q: member(key, "q"),
        dp: member(key, "dp"),
        dq: member(key, "dq"),
        qi: member(key, "qi"),
    });

    match read {
        Ok(private) => private,

        Err(error) => panic!("{}: {error:?}", key.get("source").unwrap_or(key)),
    }
}

fn every_key_is_read_with_its_public_key(source: &str) {
    for key in keys(source) {
        let private = read(&key);

        let public = RsaPublicKey::read(member(&key, "n"), member(&key, "e")).unwrap();

        assert_eq!(private.public(), public);

        assert_eq!(private.duplicate().public(), public);

        let written: Value = serde_json::from_str(&public.public_members().to_json()).unwrap();

        assert_eq!(written.get("n"), key.get("n"));

        assert_eq!(written.get("e"), key.get("e"));
    }
}

#[test]
fn every_private_key_of_the_rfcs_is_read() {
    every_key_is_read_with_its_public_key(RFC_KEYS);
}

#[test]
fn every_independently_generated_key_is_read() {
    every_key_is_read_with_its_public_key(GENERATED_KEYS);
}

#[test]
fn the_generated_keys_include_crt_members_shorter_than_their_prime() {
    let short = keys(GENERATED_KEYS)
        .iter()
        .filter(|key| key.get("short").is_some())
        .count();

    assert!(short >= 3, "{short}");
}
