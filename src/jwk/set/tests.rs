use serde_json::Value;

use serde_json::json;

use super::constants::MAX_KEYS;

use super::entries::entries;

use super::errors::JwkSetErrors;

use super::constants::MAX_JWK_SET_LEN;

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
