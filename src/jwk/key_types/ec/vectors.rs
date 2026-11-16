//! The EC keys printed in the RFCs: RFC 7515 A.3.1 and A.4.1, RFC 7518 C, RFC 7520 3.1, 3.2, 5.4,
//! 5.5 and 5.13. Each was checked apart with OpenSSL: a private one derives its own `x` and `y`
//! from `d`, a public one is a point of its curve. A refusal here is a bug of the reading.

use serde_json::Value;

use super::super::duplicate::Duplicate;

use super::EcPublicKey;

use super::EcPrivateKey;

use super::super::public_members::Publishes;

const RFC_KEYS: &str = include_str!("../../../../testdata/ec/rfc_keys.json");

fn member<'a>(key: &'a Value, name: &str) -> &'a str {
    key.get(name).and_then(Value::as_str).unwrap()
}

fn source(key: &Value) -> &str {
    member(key, "source")
}

fn keys() -> Vec<Value> {
    match serde_json::from_str(RFC_KEYS).unwrap() {
        Value::Array(keys) => keys,

        other => panic!("not an array: {other}"),
    }
}

fn public(key: &Value) -> EcPublicKey {
    match EcPublicKey::read(member(key, "crv"), member(key, "x"), member(key, "y")) {
        Ok(public) => public,

        Err(error) => panic!("{}: {error:?}", source(key)),
    }
}

#[test]
fn every_ec_key_of_the_rfcs_is_read_and_written_back_as_it_came() {
    let keys = keys();

    assert_eq!(keys.len(), 15);

    for key in &keys {
        let public = public(key);

        let written: Value = serde_json::from_str(&public.public_members().to_json()).unwrap();

        for name in ["crv", "x", "y"] {
            assert_eq!(written.get(name), key.get(name), "{}: {name}", source(key));
        }

        if key.get("d").is_some() {
            let private = EcPrivateKey::read(
                member(key, "crv"),
                member(key, "x"),
                member(key, "y"),
                member(key, "d"),
            );

            match private {
                Ok(private) => {
                    assert_eq!(private.public(), public, "{}", source(key));

                    assert_eq!(private.duplicate().public(), public, "{}", source(key));
                }

                Err(error) => panic!("{}: {error:?}", source(key)),
            }
        }
    }
}

#[test]
fn the_rfc_keys_cover_the_three_curves_public_and_private() {
    let keys = keys();

    for crv in ["P-256", "P-384", "P-521"] {
        let of_curve = keys.iter().filter(|key| member(key, "crv") == crv);

        assert!(
            of_curve.clone().any(|key| key.get("d").is_some()),
            "{crv} private"
        );

        assert!(
            of_curve.clone().any(|key| key.get("d").is_none()),
            "{crv} public"
        );
    }
}
