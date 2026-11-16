use p384::NistP384;

use p521::NistP521;

use elliptic_curve::SecretKey;

use elliptic_curve::CurveArithmetic;

use elliptic_curve::point::AffineCoordinates;

use elliptic_curve::array::typenum::Unsigned;

use crate::base64url;

use crate::jwa::Curve;

use super::EcErrors;

use super::EcPublicKey;

use super::EcPrivateKey;

use super::super::public_members::Publishes;

// RFC 7517 §A.1 and §A.2: the same P-256 key, public and private.
const X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";

const Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

const D: &str = "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE";

/// The prime of the field of P-256, big endian (SEC 2 §2.4.2).
const P256_P: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";

/// The order of the group of P-256, big endian (SEC 2 §2.4.2).
const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// `a - b` as big endian numbers of the same length, `a >= b`.
fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut borrow = 0i16;

    let mut out: Vec<u8> = a
        .iter()
        .rev()
        .zip(b.iter().rev())
        .map(|(x, y)| {
            let mut diff = *x as i16 - *y as i16 - borrow;

            borrow = (diff < 0) as i16;

            if diff < 0 {
                diff += 256;
            }

            diff as u8
        })
        .collect();

    out.reverse();
    out
}

fn b64(bytes: &[u8]) -> String {
    base64url::encode(bytes)
}

fn decoded(member: &str) -> Vec<u8> {
    base64url::decode(member).unwrap()
}

fn public(crv: &str, x: &str, y: &str) -> Result<EcPublicKey, EcErrors> {
    EcPublicKey::read(crv, x, y)
}

fn private(crv: &str, x: &str, y: &str, d: &str) -> Result<EcPrivateKey, EcErrors> {
    EcPrivateKey::read(crv, x, y, d)
}

/// `(x, y, d)` of a key of curve `C`, `d` filled with `fill`, for curves without a vector here.
fn key_of<C>(fill: u8) -> (String, String, String)
where
    C: CurveArithmetic,
{
    let d = vec![fill; C::FieldBytesSize::USIZE];

    let point = *SecretKey::<C>::from_slice(&d)
        .unwrap()
        .public_key()
        .as_affine();

    (b64(&point.x()), b64(&point.y()), b64(&d))
}

#[test]
fn reads_the_public_key_of_rfc_7517() {
    let ec = public("P-256", X, Y).unwrap();

    assert!(matches!(ec, EcPublicKey::P256(_)));

    assert_eq!(ec.curve(), Curve::P256);
}

#[test]
fn reads_the_private_key_of_rfc_7517() {
    let ec = private("P-256", X, Y, D).unwrap();

    assert!(matches!(ec, EcPrivateKey::P256(_)));

    assert_eq!(ec.curve(), Curve::P256);
}

#[test]
fn the_public_half_of_a_private_key_is_its_public_key() {
    let from_private = private("P-256", X, Y, D).unwrap().public();

    assert_eq!(from_private, public("P-256", X, Y).unwrap());
}

#[test]
fn reads_p384_and_p521() {
    let (x, y, d) = key_of::<NistP384>(0x11);

    assert_eq!(public("P-384", &x, &y).unwrap().curve(), Curve::P384);

    assert_eq!(private("P-384", &x, &y, &d).unwrap().curve(), Curve::P384);

    // The top byte of a P-521 scalar is 0 or 1.
    let (x, y, d) = key_of::<NistP521>(0x01);

    assert_eq!(decoded(&x).len(), 66);

    assert_eq!(public("P-521", &x, &y).unwrap().curve(), Curve::P521);

    assert_eq!(private("P-521", &x, &y, &d).unwrap().curve(), Curve::P521);
}

#[test]
fn a_crv_that_is_not_registered_is_unknown() {
    for crv in [
        "",
        "p-256",
        "P256",
        "P-256 ",
        "P-257",
        "secp256r1",
        "prime256v1",
    ] {
        assert_eq!(
            public(crv, X, Y).err(),
            Some(EcErrors::UnknownCurve),
            "{crv:?}"
        );

        assert_eq!(
            private(crv, X, Y, D).err(),
            Some(EcErrors::UnknownCurve),
            "{crv:?}"
        );
    }
}

#[test]
fn a_crv_of_okp_is_foreign() {
    for crv in ["Ed25519", "Ed448", "X25519", "X448"] {
        assert_eq!(
            public(crv, X, Y).err(),
            Some(EcErrors::ForeignCurve),
            "{crv}"
        );

        assert_eq!(
            private(crv, X, Y, D).err(),
            Some(EcErrors::ForeignCurve),
            "{crv}"
        );
    }
}

#[test]
fn secp256k1_is_not_read() {
    assert_eq!(
        public("secp256k1", X, Y).err(),
        Some(EcErrors::UnsupportedCurve)
    );

    assert_eq!(
        private("secp256k1", X, Y, D).err(),
        Some(EcErrors::UnsupportedCurve)
    );
}

#[test]
fn a_coordinate_is_canonical_base64url() {
    let padded = format!("{X}=");

    // `+` is of the standard alphabet, not of base64url.
    let standard = X.replacen('M', "+", 1);

    let spaced = format!(" {X}");

    for bad in [padded.as_str(), standard.as_str(), spaced.as_str(), "*"] {
        assert_eq!(
            public("P-256", bad, Y).err(),
            Some(EcErrors::InvalidEncoding("x")),
            "{bad}"
        );

        assert_eq!(
            public("P-256", X, bad).err(),
            Some(EcErrors::InvalidEncoding("y")),
            "{bad}"
        );
    }
}

#[test]
fn a_coordinate_has_exactly_the_size_of_the_field() {
    // RFC 7518 §6.2.1.2: leading zeros kept, so neither shorter nor longer is the same number.
    let x = decoded(X);

    let shorter = b64(x.get(1..).unwrap());

    let longer = b64(&[&[0u8][..], &x].concat());

    for bad in [shorter.as_str(), longer.as_str(), ""] {
        assert_eq!(
            public("P-256", bad, Y).err(),
            Some(EcErrors::InvalidLength("x")),
            "{bad}"
        );

        assert_eq!(
            public("P-256", X, bad).err(),
            Some(EcErrors::InvalidLength("y")),
            "{bad}"
        );
    }

    // A P-256 point is not a P-384 one: the size is the curve's, not the input's.
    assert_eq!(
        public("P-384", X, Y).err(),
        Some(EcErrors::InvalidLength("x"))
    );
}

#[test]
fn a_point_off_the_curve_is_refused() {
    // The start of the invalid curve attacks: a point of another curve, sent as one of this one.
    let mut y = decoded(Y);

    if let Some(last) = y.last_mut() {
        *last ^= 1;
    }

    assert_eq!(
        public("P-256", X, &b64(&y)).err(),
        Some(EcErrors::NotOnCurve)
    );

    assert_eq!(
        private("P-256", X, &b64(&y), D).err(),
        Some(EcErrors::NotOnCurve)
    );

    let zero = b64(&[0u8; 32]);

    assert_eq!(
        public("P-256", &zero, &zero).err(),
        Some(EcErrors::NotOnCurve)
    );
}

#[test]
fn a_coordinate_at_or_above_the_prime_is_refused() {
    // x + p would be the same x modulo p: two encodings of one point.
    let p = b64(&unhex(P256_P));

    let max = b64(&[0xffu8; 32]);

    for bad in [p.as_str(), max.as_str()] {
        assert_eq!(public("P-256", bad, Y).err(), Some(EcErrors::NotOnCurve));

        assert_eq!(public("P-256", X, bad).err(), Some(EcErrors::NotOnCurve));
    }
}

#[test]
fn d_is_canonical_base64url_of_the_size_of_the_curve() {
    let padded = format!("{D}=");

    assert_eq!(
        private("P-256", X, Y, &padded).err(),
        Some(EcErrors::InvalidEncoding("d"))
    );

    // RFC 7518 §6.2.2.1: the full size of the order, leading zeros kept.
    let d = decoded(D);

    let shorter = b64(d.get(1..).unwrap());

    let longer = b64(&[&[0u8][..], &d].concat());

    for bad in [shorter.as_str(), longer.as_str(), ""] {
        assert_eq!(
            private("P-256", X, Y, bad).err(),
            Some(EcErrors::InvalidLength("d")),
            "{bad}"
        );
    }
}

#[test]
fn d_is_from_1_to_the_order_minus_1() {
    let zero = b64(&[0u8; 32]);

    let n = b64(&unhex(P256_N));

    let max = b64(&[0xffu8; 32]);

    for bad in [zero.as_str(), n.as_str(), max.as_str()] {
        assert_eq!(
            private("P-256", X, Y, bad).err(),
            Some(EcErrors::InvalidSecret),
            "{bad}"
        );
    }
}

#[test]
fn d_of_another_key_is_refused() {
    // Signing with one key and publishing another.
    let (_, _, other) = key_of::<p256::NistP256>(0x22);

    assert_eq!(
        private("P-256", X, Y, &other).err(),
        Some(EcErrors::KeyMismatch)
    );
}

#[test]
fn the_other_point_of_the_same_x_is_not_the_key_of_d() {
    // (x, p - y) is on the curve too: only the check against d tells them apart.
    let minus_y = b64(&sub(&unhex(P256_P), &decoded(Y)));

    assert!(public("P-256", X, &minus_y).is_ok());

    assert_eq!(
        private("P-256", X, &minus_y, D).err(),
        Some(EcErrors::KeyMismatch)
    );
}

#[test]
fn a_p256_key_writes_crv_kty_x_and_y() {
    assert_eq!(
        public("P-256", X, Y).unwrap().public_members().to_json(),
        format!(r#"{{"crv":"P-256","kty":"EC","x":"{X}","y":"{Y}"}}"#)
    );
}

#[test]
fn a_private_key_writes_the_members_of_its_public_key() {
    assert_eq!(
        private("P-256", X, Y, D).unwrap().public().public_members(),
        public("P-256", X, Y).unwrap().public_members()
    );
}

#[test]
fn a_p521_coordinate_keeps_its_leading_zero_byte() {
    // 521 bits in 66 bytes: the first byte of x is 0 or 1, so a leading zero is common. Each `d`
    // starts with a zero byte to stay below the order of the group.
    let (x, y) = (1u8..=255)
        .map(|fill| {
            let mut d = [fill; 66];

            d[0] = 0;

            let point = *SecretKey::<NistP521>::from_slice(&d)
                .unwrap()
                .public_key()
                .as_affine();

            (b64(&point.x()), b64(&point.y()))
        })
        .find(|(x, _)| decoded(x).first() == Some(&0))
        .unwrap();

    let members = public("P-521", &x, &y).unwrap().public_members();

    for (name, value) in members.iter().filter(|(name, _)| ["x", "y"].contains(name)) {
        assert_eq!(decoded(value).len(), 66, "{name}");
    }

    assert!(
        members
            .iter()
            .any(|(name, value)| name == "x" && value == x)
    );
}
