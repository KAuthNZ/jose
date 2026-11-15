use serde_json::Map;

use serde_json::Value;

use serde_json::json;

use crate::jwk::constants::KEY_MEMBERS;

use super::RawJwk;

use super::RawJwkErrors;

fn members(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(members) => members,

        other => panic!("not an object: {other}"),
    }
}

fn read(value: Value) -> RawJwk {
    match RawJwk::try_from(members(value)) {
        Ok(raw) => raw,

        Err(error) => panic!("refused: {error:?}"),
    }
}

fn refused(value: Value) -> RawJwkErrors {
    match RawJwk::try_from(members(value)) {
        Ok(_) => panic!("read"),

        Err(error) => error,
    }
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

/// Every common member, with an EC key's material.
fn full() -> Value {
    json!({
        "kty": "EC",
        "kid": "1",
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"],
        "x5u": "https://example.com/chain.pem",
        "x5c": ["MIIB"],
        "x5t": "dGh1bWI",
        "x5t#S256": "dGh1bWIy",
        "crv": "P-256",
        "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
        "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
    })
}

const STRING_MEMBERS: [&str; 6] = ["kid", "alg", "use", "x5u", "x5t", "x5t#S256"];

const ARRAY_MEMBERS: [&str; 2] = ["key_ops", "x5c"];

#[test]
fn every_member_is_kept_as_it_came() {
    let mut raw = read(full());

    assert_eq!(raw.kty, "EC");

    assert_eq!(raw.kid.as_deref(), Some("1"));

    assert_eq!(raw.alg.as_deref(), Some("ES256"));

    assert_eq!(raw.key_use.as_deref(), Some("sig"));

    assert_eq!(raw.key_ops, Some(vec!["verify".to_owned()]));

    assert_eq!(raw.x5u.as_deref(), Some("https://example.com/chain.pem"));

    assert_eq!(raw.x5c, Some(vec!["MIIB".to_owned()]));

    assert_eq!(raw.x5t.as_deref(), Some("dGh1bWI"));

    assert_eq!(raw.x5t_s256.as_deref(), Some("dGh1bWIy"));

    assert_eq!(
        raw.material.take("crv").as_deref().map(String::as_str),
        Some("P-256")
    );

    assert!(raw.material.take("x").is_some());

    assert!(raw.material.take("y").is_some());

    assert!(raw.material.take("d").is_none());
}

#[test]
fn only_kty_is_required() {
    let raw = read(json!({"kty": "EC"}));

    assert!(raw.kid.is_none() && raw.alg.is_none() && raw.key_use.is_none());

    assert!(raw.key_ops.is_none() && raw.x5c.is_none());

    assert_eq!(raw.material.names().count(), 0);

    assert_eq!(refused(without(full(), "kty")), RawJwkErrors::MissingKty);
}

#[test]
fn kty_is_a_string() {
    for kty in [
        json!(null),
        json!(1),
        json!(true),
        json!(["EC"]),
        json!({"kty": "EC"}),
    ] {
        assert_eq!(
            refused(with(full(), "kty", kty.clone())),
            RawJwkErrors::InvalidMember("kty"),
            "{kty}"
        );
    }
}

#[test]
fn kty_is_not_judged_here() {
    for kty in ["EC", "RSA", "OKP", "oct", "AKP", "ec", "", "none"] {
        assert_eq!(read(with(full(), "kty", json!(kty))).kty, kty);
    }
}

#[test]
fn a_common_member_of_another_type_refuses_the_key() {
    for name in STRING_MEMBERS {
        for value in [json!(null), json!(1), json!(false), json!(["1"]), json!({})] {
            assert_eq!(
                refused(with(full(), name, value.clone())),
                RawJwkErrors::InvalidMember(name),
                "{name}: {value}"
            );
        }
    }
}

#[test]
fn key_ops_and_x5c_are_arrays_of_strings() {
    for name in ARRAY_MEMBERS {
        for value in [
            json!(null),
            json!("verify"),
            json!(1),
            json!({}),
            json!([1]),
            json!(["verify", null]),
            json!([["verify"]]),
        ] {
            assert_eq!(
                refused(with(full(), name, value.clone())),
                RawJwkErrors::InvalidMember(name),
                "{name}: {value}"
            );
        }
    }
}

#[test]
fn a_key_member_of_another_type_refuses_the_key() {
    for name in KEY_MEMBERS.into_iter().filter(|name| *name != "oth") {
        for value in [json!(null), json!(1), json!(true), json!(["x"]), json!({})] {
            assert_eq!(
                refused(with(full(), name, value.clone())),
                RawJwkErrors::InvalidMember(name),
                "{name}: {value}"
            );
        }
    }
}

#[test]
fn every_registered_key_member_is_kept_whatever_the_kty() {
    // Whether it belongs to the kty is decided when the key is classified.
    let mut key = json!({"kty": "EC"});

    for name in KEY_MEMBERS.into_iter().filter(|name| *name != "oth") {
        key = with(key, name, json!(name));
    }

    let mut raw = read(key);

    for name in KEY_MEMBERS.into_iter().filter(|name| *name != "oth") {
        assert_eq!(
            raw.material.take(name).as_deref().map(String::as_str),
            Some(name)
        );
    }
}

#[test]
fn oth_is_not_read() {
    // Keys of more than two primes (RFC 7518 §6.3.2.7), whatever its value.
    for value in [
        json!([{"r": "AQ", "d": "AQ", "t": "AQ"}]),
        json!([]),
        json!("x"),
        json!(null),
    ] {
        assert_eq!(
            refused(with(full(), "oth", value.clone())),
            RawJwkErrors::UnsupportedMember("oth"),
            "{value}"
        );
    }
}

#[test]
fn members_not_registered_are_dropped() {
    // RFC 7517 §4: ignored, whatever their type.
    let mut key = full();

    for name in ["ext", "foo", "x5t#S512", "KID", "Kty", "D"] {
        key = with(key, name, json!({"nested": [1, null]}));
    }

    let raw = read(key);

    assert!(
        raw.material
            .names()
            .all(|name| ["crv", "x", "y"].contains(&name))
    );
}

#[test]
fn values_are_not_judged_here() {
    let key = with(full(), "kid", json!(""));

    let key = with(key, "x5t", json!("not base64!"));

    let key = with(key, "key_ops", json!([]));

    let key = with(key, "x5c", json!(["", "!!"]));

    let key = with(key, "x", json!("!!!"));

    let mut raw = read(key);

    assert_eq!(raw.kid.as_deref(), Some(""));

    assert_eq!(raw.key_ops, Some(vec![]));

    assert_eq!(
        raw.material.take("x").as_deref().map(String::as_str),
        Some("!!!")
    );
}
