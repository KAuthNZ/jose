use ed25519_dalek::SigningKey;

use ed25519_dalek::VerifyingKey;

use crate::base64url;

use crate::jwa::Curve;

use super::OkpErrors;

use super::OkpPublicKey;

use super::OkpPrivateKey;

use super::super::public_members::Publishes;

// RFC 8037 §A.1.
const X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

const D: &str = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";

/// The identity, of order 1: `y = 1`.
const IDENTITY: [u8; 32] = {
    let mut bytes = [0u8; 32];

    bytes[0] = 1;

    bytes
};

/// `(0, -1)`, of order 2: `y = p - 1`, little endian.
const ORDER_2: [u8; 32] = {
    let mut bytes = [0xffu8; 32];

    bytes[0] = 0xec;

    bytes[31] = 0x7f;

    bytes
};

/// `y = p`, which the backend reduces to 0.
const Y_IS_P: [u8; 32] = {
    let mut bytes = [0xffu8; 32];

    bytes[0] = 0xed;

    bytes[31] = 0x7f;

    bytes
};

/// `y = p + 1`, which the backend reduces to 1: the identity, written another way.
const Y_IS_P_PLUS_1: [u8; 32] = {
    let mut bytes = [0xffu8; 32];

    bytes[0] = 0xee;

    bytes[31] = 0x7f;

    bytes
};

fn b64(bytes: &[u8]) -> String {
    base64url::encode(bytes)
}

fn decoded(member: &str) -> Vec<u8> {
    base64url::decode(member).unwrap()
}

fn public(crv: &str, x: &str) -> Result<OkpPublicKey, OkpErrors> {
    OkpPublicKey::read(crv, x)
}

fn private(crv: &str, x: &str, d: &str) -> Result<OkpPrivateKey, OkpErrors> {
    OkpPrivateKey::read(crv, x, d)
}

#[test]
fn reads_the_public_key_of_rfc_8037() {
    let okp = public("Ed25519", X).unwrap();

    assert!(matches!(okp, OkpPublicKey::Ed25519(_)));

    assert_eq!(okp.curve(), Curve::Ed25519);
}

#[test]
fn reads_the_private_key_of_rfc_8037() {
    let okp = private("Ed25519", X, D).unwrap();

    assert!(matches!(okp, OkpPrivateKey::Ed25519(_)));

    assert_eq!(okp.curve(), Curve::Ed25519);
}

#[test]
fn the_public_half_of_a_private_key_is_its_public_key() {
    let from_private = private("Ed25519", X, D).unwrap().public();

    assert_eq!(from_private, public("Ed25519", X).unwrap());
}

#[test]
fn a_crv_that_is_not_registered_is_unknown() {
    for crv in [
        "",
        "ed25519",
        "Ed25519 ",
        "ED25519",
        "Ed-25519",
        "EdDSA",
        "Curve25519",
    ] {
        assert_eq!(
            public(crv, X).err(),
            Some(OkpErrors::UnknownCurve),
            "{crv:?}"
        );

        assert_eq!(
            private(crv, X, D).err(),
            Some(OkpErrors::UnknownCurve),
            "{crv:?}"
        );
    }
}

#[test]
fn a_crv_of_ec_is_foreign() {
    for crv in ["P-256", "P-384", "P-521", "secp256k1"] {
        assert_eq!(public(crv, X).err(), Some(OkpErrors::ForeignCurve), "{crv}");

        assert_eq!(
            private(crv, X, D).err(),
            Some(OkpErrors::ForeignCurve),
            "{crv}"
        );
    }
}

#[test]
fn x25519_ed448_and_x448_are_not_read() {
    for crv in ["X25519", "Ed448", "X448"] {
        assert_eq!(
            public(crv, X).err(),
            Some(OkpErrors::UnsupportedCurve),
            "{crv}"
        );

        assert_eq!(
            private(crv, X, D).err(),
            Some(OkpErrors::UnsupportedCurve),
            "{crv}"
        );
    }
}

#[test]
fn x_and_d_are_canonical_base64url() {
    // `/` is the standard alphabet's `_`.
    assert!(X.contains('_') && D.contains('_'));

    for (name, value) in [("x", X), ("d", D)] {
        for bad in [
            format!("{value}="),
            format!(" {value}"),
            value.replacen('_', "/", 1),
        ] {
            let (x, d) = if name == "x" {
                (bad.as_str(), D)
            } else {
                (X, bad.as_str())
            };

            assert_eq!(
                private("Ed25519", x, d).err(),
                Some(OkpErrors::InvalidEncoding(name)),
                "{name}: {bad}"
            );
        }
    }

    assert_eq!(
        public("Ed25519", &format!("{X}=")).err(),
        Some(OkpErrors::InvalidEncoding("x"))
    );
}

#[test]
fn x_and_d_are_exactly_32_bytes() {
    // RFC 8032 §5.1.5: the public key and the seed are 32 bytes, neither shorter nor longer.
    for (name, value) in [("x", X), ("d", D)] {
        let bytes = decoded(value);

        let shorter = b64(bytes.get(1..).unwrap());

        let longer = b64(&[&bytes[..], &[0u8][..]].concat());

        for bad in [shorter.as_str(), longer.as_str(), ""] {
            let (x, d) = if name == "x" { (bad, D) } else { (X, bad) };

            assert_eq!(
                private("Ed25519", x, d).err(),
                Some(OkpErrors::InvalidLength(name)),
                "{name}: {bad}"
            );
        }
    }

    assert_eq!(
        public("Ed25519", "").err(),
        Some(OkpErrors::InvalidLength("x"))
    );
}

#[test]
fn x_that_is_not_a_point_is_refused() {
    // Some y has no x on the curve: the first of them, whatever it is, is refused as such.
    let off_curve = (2u8..=255)
        .map(|y| {
            let mut bytes = [0u8; 32];

            bytes[0] = y;

            bytes
        })
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .unwrap();

    assert_eq!(
        public("Ed25519", &b64(&off_curve)).err(),
        Some(OkpErrors::NotOnCurve)
    );
}

#[test]
fn x_of_small_order_is_refused() {
    // Anyone can sign for it: a signature of it verifies for almost any message.
    for point in [IDENTITY, ORDER_2, [0u8; 32]] {
        assert_eq!(
            public("Ed25519", &b64(&point)).err(),
            Some(OkpErrors::SmallOrder),
            "{point:?}"
        );
    }
}

#[test]
fn x_of_mixed_order_is_refused() {
    // The key of RFC 8037 plus a point of order 2: on the curve and of large order, but no real
    // signer has it, and verifiers disagree on its signatures.
    let key = VerifyingKey::from_bytes(&decoded(X).try_into().unwrap()).unwrap();

    let torsion = VerifyingKey::from_bytes(&ORDER_2).unwrap();

    let mixed = (key.to_edwards() + torsion.to_edwards())
        .compress()
        .to_bytes();

    assert_eq!(
        public("Ed25519", &b64(&mixed)).err(),
        Some(OkpErrors::MixedOrder)
    );
}

#[test]
fn x_not_canonically_encoded_is_refused() {
    // RFC 8032 §5.1.3: a y of p or above is refused, and the backend would reduce it. The sign
    // of x set on a point whose x is 0 is another encoding of the same point.
    let mut signed_identity = IDENTITY;

    signed_identity[31] |= 0x80;

    for point in [Y_IS_P, Y_IS_P_PLUS_1, signed_identity] {
        assert_eq!(
            public("Ed25519", &b64(&point)).err(),
            Some(OkpErrors::NonCanonical),
            "{point:?}"
        );
    }
}

#[test]
fn d_of_another_key_is_refused() {
    // Signing with one key and publishing another.
    let other = b64(&[7u8; 32]);

    assert_eq!(
        private("Ed25519", X, &other).err(),
        Some(OkpErrors::KeyMismatch)
    );

    // And the other way: the right d with the x of another key.
    let other_x = SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();

    assert_eq!(
        private("Ed25519", &b64(&other_x), D).err(),
        Some(OkpErrors::KeyMismatch)
    );
}

#[test]
fn the_public_rules_hold_for_a_private_key() {
    assert_eq!(
        private("Ed25519", &b64(&IDENTITY), D).err(),
        Some(OkpErrors::SmallOrder)
    );
}

#[test]
fn an_ed25519_key_writes_crv_kty_and_x() {
    assert_eq!(
        public("Ed25519", X)
            .unwrap()
            .public_members()
            .thumbprint_json(),
        format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{X}"}}"#)
    );
}

#[test]
fn a_private_key_writes_the_members_of_its_public_key() {
    assert_eq!(
        private("Ed25519", X, D).unwrap().public().public_members(),
        public("Ed25519", X).unwrap().public_members()
    );
}
