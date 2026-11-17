use serde_json::Value;

use serde_json::json;

use super::JwkSet;

use super::DiscardedKey;

use super::constants::MAX_KEYS;

use super::entries::entries;

use super::errors::JwkSetErrors;

use crate::jwk::key::JwkErrors;

use super::constants::MAX_JWK_SET_LEN;

use super::secret_members::no_secret_members;

use crate::jwk::key_types::ClassificationErrors;

// RFC 8037 A.2.
const OKP_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

fn okp(kid: &str) -> Value {
    json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "kid": kid })
}

fn read(set: &Value) -> Result<usize, JwkSetErrors> {
    entries(set.to_string().as_bytes()).map(|entries| entries.len())
}

fn refused(source: &[u8]) -> JwkSetErrors {
    match entries(source) {
        Ok(_) => panic!("read"),

        Err(error) => error,
    }
}

/// A set of one key, padded with a member nobody reads to exactly `len` bytes.
fn set_of_len(len: usize) -> Vec<u8> {
    let empty = json!({ "keys": [okp("a")], "pad": "" }).to_string();

    json!({ "keys": [okp("a")], "pad": "x".repeat(len - empty.len()) })
        .to_string()
        .into_bytes()
}

#[test]
fn the_limits_are_the_ones_the_errors_say() {
    // Written out in the docs of `TooLarge` and `TooManyKeys`, which can't link to them.
    assert_eq!(MAX_JWK_SET_LEN, 128 * 1024);

    assert_eq!(MAX_KEYS, 32);
}

#[test]
fn each_entry_of_keys_is_given_unread() {
    let set = json!({ "keys": [okp("a"), { "kty": "nobody knows" }] });

    assert_eq!(read(&set), Ok(2));
}

#[test]
fn a_member_other_than_keys_is_ignored() {
    // RFC 7517 §5: not understood, so ignored.
    let set = json!({ "keys": [okp("a")], "issuer": "https://as.example", "n": 1 });

    assert_eq!(read(&set), Ok(1));
}

#[test]
fn the_longest_set_is_read_and_one_byte_more_is_not() {
    assert!(entries(&set_of_len(MAX_JWK_SET_LEN)).is_ok());

    assert_eq!(
        refused(&set_of_len(MAX_JWK_SET_LEN + 1)),
        JwkSetErrors::TooLarge
    );
}

#[test]
fn what_is_not_a_json_object_is_refused() {
    for source in [
        &b""[..],
        b"{",
        b"{\"keys\":}",
        b"{} {}",
        b"{\"keys\":\"\xff\"}",
    ] {
        assert_eq!(refused(source), JwkSetErrors::NotJson, "{source:?}");
    }

    for source in [&b"[]"[..], b"[{\"keys\":[]}]", b"\"keys\"", b"null", b"1"] {
        assert_eq!(refused(source), JwkSetErrors::NotAnObject, "{source:?}");
    }
}

#[test]
fn a_member_repeated_in_the_set_or_in_a_key_is_refused() {
    let x = OKP_X;

    for source in [
        r#"{"keys":[],"keys":[]}"#.to_owned(),
        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","x":"{x}"}}]}}"#),
        format!(r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","x":"{x}","x":"{x}"}}]}}"#),
    ] {
        assert_eq!(
            refused(source.as_bytes()),
            JwkSetErrors::DuplicateMembers,
            "{source}"
        );
    }
}

#[test]
fn a_set_without_keys_is_refused() {
    assert_eq!(read(&json!({})), Err(JwkSetErrors::MissingKeys));

    assert_eq!(
        read(&json!({ "key": [okp("a")] })),
        Err(JwkSetErrors::MissingKeys)
    );
}

#[test]
fn keys_that_are_not_an_array_are_refused() {
    for keys in [json!(okp("a")), json!(null), json!("a"), json!(1)] {
        assert_eq!(
            read(&json!({ "keys": keys })),
            Err(JwkSetErrors::KeysNotAnArray),
            "{keys}"
        );
    }
}

#[test]
fn an_empty_set_is_refused() {
    assert_eq!(read(&json!({ "keys": [] })), Err(JwkSetErrors::Empty));
}

#[test]
fn the_most_keys_are_read_and_one_more_is_not() {
    let keys = |count: usize| -> Vec<Value> { (0..count).map(|i| okp(&i.to_string())).collect() };

    assert_eq!(read(&json!({ "keys": keys(MAX_KEYS) })), Ok(MAX_KEYS));

    assert_eq!(
        read(&json!({ "keys": keys(MAX_KEYS + 1) })),
        Err(JwkSetErrors::TooManyKeys)
    );
}

#[test]
fn too_many_keys_is_known_before_any_entry_is_looked_at() {
    let keys: Vec<Value> = (0..=MAX_KEYS).map(|_| json!("not a key")).collect();

    assert_eq!(
        read(&json!({ "keys": keys })),
        Err(JwkSetErrors::TooManyKeys)
    );
}

#[test]
fn an_entry_that_is_not_an_object_is_refused_with_its_index() {
    for entry in [json!([]), json!("OKP"), json!(null), json!(1)] {
        assert_eq!(
            read(&json!({ "keys": [okp("a"), okp("b"), entry] })),
            Err(JwkSetErrors::NotAKey { index: 2 }),
            "{entry}"
        );
    }
}

fn judged(set: &Value) -> Result<(), JwkSetErrors> {
    no_secret_members(&entries(set.to_string().as_bytes())?)
}

#[test]
fn a_set_of_public_keys_has_no_secret_member() {
    let rsa = json!({ "kty": "RSA", "n": "AQAB", "e": "AQAB", "kid": "r" });

    assert_eq!(judged(&json!({ "keys": [okp("a"), rsa] })), Ok(()));
}

#[test]
fn a_private_key_refuses_the_whole_set_with_its_index_and_member() {
    let private = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "d": "AA", "kid": "b" });

    assert_eq!(
        judged(&json!({ "keys": [okp("a"), private] })),
        Err(JwkSetErrors::SecretMember {
            index: 1,
            name: "d"
        })
    );
}

#[test]
fn every_secret_member_refuses_the_set_whatever_its_kty() {
    let names = ["d", "dp", "dq", "k", "oth", "p", "priv", "q", "qi"];

    for name in names {
        let mut key = okp("b");

        key[name] = json!("AA");

        assert_eq!(
            judged(&json!({ "keys": [okp("a"), key] })),
            Err(JwkSetErrors::SecretMember { index: 1, name }),
            "{name}"
        );
    }
}

#[test]
fn a_symmetric_key_refuses_the_set() {
    let secret = json!({ "kty": "oct", "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr8" });

    assert_eq!(
        judged(&json!({ "keys": [secret, okp("a")] })),
        Err(JwkSetErrors::SecretMember {
            index: 0,
            name: "k"
        })
    );
}

#[test]
fn the_first_entry_with_a_secret_is_the_one_reported() {
    let first = json!({ "kty": "EC", "d": "AA" });

    let second = json!({ "kty": "oct", "k": "AA" });

    assert_eq!(
        judged(&json!({ "keys": [okp("a"), first, second] })),
        Err(JwkSetErrors::SecretMember {
            index: 1,
            name: "d"
        })
    );
}

#[test]
fn a_member_that_only_looks_secret_is_not_one() {
    // Names are case-sensitive (RFC 7517 §4): "D" is not registered, and a key drops it.
    let mut key = okp("b");

    key["D"] = json!("AA");

    assert_eq!(judged(&json!({ "keys": [okp("a"), key] })), Ok(()));
}

fn read_public(set: &Value) -> Result<JwkSet<crate::jwk::mode::Public>, JwkSetErrors> {
    JwkSet::read_public(set.to_string().as_bytes())
}

fn kids(set: &JwkSet<crate::jwk::mode::Public>) -> Vec<Option<&str>> {
    set.keys.iter().map(|key| key.kid()).collect()
}

#[test]
fn every_key_is_read_in_the_order_of_keys() {
    let set = read_public(&json!({ "keys": [okp("a"), okp("b"), okp("c")] })).unwrap();

    assert_eq!(kids(&set), [Some("a"), Some("b"), Some("c")]);

    assert!(set.discarded().is_empty());
}

#[test]
fn a_key_that_cant_be_read_is_left_out_with_its_index_and_reason() {
    let unknown = json!({ "kty": "nobody knows", "kid": "b" });

    let set = read_public(&json!({ "keys": [okp("a"), unknown, okp("c")] })).unwrap();

    assert_eq!(kids(&set), [Some("a"), Some("c")]);

    assert_eq!(
        set.discarded(),
        [DiscardedKey::new(
            1,
            JwkErrors::Classification(ClassificationErrors::UnknownKty)
        )]
    );
}

#[test]
fn a_set_with_no_key_left_is_refused_with_the_first_one_left_out() {
    let unknown = json!({ "kty": "nobody knows" });

    let without_kty = json!({ "crv": "Ed25519", "x": OKP_X });

    assert_eq!(
        read_public(&json!({ "keys": [unknown, without_kty] })).err(),
        Some(JwkSetErrors::NoUsableKey(DiscardedKey::new(
            0,
            JwkErrors::Classification(ClassificationErrors::UnknownKty)
        )))
    );
}

#[test]
fn a_secret_member_refuses_the_set_and_is_not_a_key_left_out() {
    let private = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "d": "AA", "kid": "b" });

    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), private] })).err(),
        Some(JwkSetErrors::SecretMember {
            index: 1,
            name: "d"
        })
    );
}

#[test]
fn the_shape_is_judged_before_any_key() {
    assert_eq!(
        read_public(&json!({ "keys": [] })).err(),
        Some(JwkSetErrors::Empty)
    );

    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), "not a key"] })).err(),
        Some(JwkSetErrors::NotAKey { index: 1 })
    );
}

#[test]
fn one_key_needs_no_kid() {
    let without_kid = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X });

    let set = read_public(&json!({ "keys": [without_kid] })).unwrap();

    assert_eq!(kids(&set), [None]);
}

#[test]
fn two_keys_of_the_same_alg_without_kid_refuse_the_set() {
    let ed25519 = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X, "alg": "Ed25519" });

    assert_eq!(
        read_public(&json!({ "keys": [ed25519.clone(), ed25519] })).err(),
        Some(JwkSetErrors::MissingKid { index: 0 })
    );
}

#[test]
fn with_more_than_one_key_each_needs_a_kid() {
    let without_kid = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X });

    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), without_kid] })).err(),
        Some(JwkSetErrors::MissingKid { index: 1 })
    );
}

#[test]
fn a_kid_repeated_refuses_the_set_at_the_second_key() {
    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), okp("b"), okp("a")] })).err(),
        Some(JwkSetErrors::DuplicateKid { index: 2 })
    );
}

#[test]
fn a_kid_repeated_on_keys_of_different_kty_refuses_the_set_too() {
    // RFC 7517 §4.5 allows it; `get` by kid could not tell them apart.
    let ec = json!({
        "kty": "EC", "crv": "P-256", "kid": "a",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    });

    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), ec] })).err(),
        Some(JwkSetErrors::DuplicateKid { index: 1 })
    );
}

#[test]
fn the_index_of_a_kid_error_is_its_place_in_keys() {
    let unknown = json!({ "kty": "nobody knows" });

    let without_kid = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X });

    assert_eq!(
        read_public(&json!({ "keys": [okp("a"), unknown, without_kid] })).err(),
        Some(JwkSetErrors::MissingKid { index: 2 })
    );
}

#[test]
fn a_key_left_out_is_not_counted_for_the_kid_rules() {
    let unknown = json!({ "kty": "nobody knows" });

    let without_kid = json!({ "kty": "OKP", "crv": "Ed25519", "x": OKP_X });

    let set = read_public(&json!({ "keys": [unknown, without_kid] })).unwrap();

    assert_eq!(kids(&set), [None]);

    assert_eq!(set.discarded().len(), 1);
}
