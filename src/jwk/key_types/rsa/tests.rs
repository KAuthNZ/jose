use crypto_bigint::NonZero;

use crypto_bigint::BoxedUint;

use crate::base64url;

use super::RsaErrors;

use super::super::public_side::PublicSide;

use super::RsaPublicKey;

use super::RsaPrivateKey;

use super::RsaPrivateKeyMembers;

use super::super::public_members::Publishes;

// RFC 7517 §A.2, taken from the text of the RFC.
const N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

const E: &str = "AQAB";

const D: &str = "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";

const P: &str = "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";

const Q: &str = "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";

const DP: &str = "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";

const DQ: &str = "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";

const QI: &str = "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";

const SECRET_NAMES: [&str; 6] = ["d", "p", "q", "dp", "dq", "qi"];

/// The members of RFC 7517 §A.2 as owned strings, so a test can change one.
#[derive(Clone)]
struct Members {
    n: String,
    e: String,
    d: String,
    p: String,
    q: String,
    dp: String,
    dq: String,
    qi: String,
}

impl Members {
    fn rfc() -> Self {
        Self {
            n: N.to_owned(),
            e: E.to_owned(),
            d: D.to_owned(),
            p: P.to_owned(),
            q: Q.to_owned(),
            dp: DP.to_owned(),
            dq: DQ.to_owned(),
            qi: QI.to_owned(),
        }
    }

    fn with(mut self, name: &str, value: String) -> Self {
        match name {
            "n" => self.n = value,
            "e" => self.e = value,
            "d" => self.d = value,
            "p" => self.p = value,
            "q" => self.q = value,
            "dp" => self.dp = value,
            "dq" => self.dq = value,
            "qi" => self.qi = value,
            _ => panic!("{name}"),
        }

        self
    }

    fn get(&self, name: &str) -> &str {
        match name {
            "n" => &self.n,
            "e" => &self.e,
            "d" => &self.d,
            "p" => &self.p,
            "q" => &self.q,
            "dp" => &self.dp,
            "dq" => &self.dq,
            "qi" => &self.qi,
            _ => panic!("{name}"),
        }
    }

    fn private(&self) -> Result<RsaPrivateKey, RsaErrors> {
        RsaPrivateKey::read(RsaPrivateKeyMembers {
            n: &self.n,
            e: &self.e,
            d: &self.d,
            p: &self.p,
            q: &self.q,
            dp: &self.dp,
            dq: &self.dq,
            qi: &self.qi,
        })
    }
}

fn public(n: &str, e: &str) -> Result<RsaPublicKey, RsaErrors> {
    RsaPublicKey::read(n, e)
}

fn decoded(member: &str) -> Vec<u8> {
    base64url::decode(member).unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64url::encode(bytes)
}

/// `member` with the lowest bit of its last byte flipped.
fn flipped(member: &str) -> String {
    let mut bytes = decoded(member);

    if let Some(last) = bytes.last_mut() {
        *last ^= 1;
    }

    b64(&bytes)
}

/// `member` with a zero byte in front: the same number, another encoding.
fn zero_prefixed(member: &str) -> String {
    b64(&[&[0u8][..], &decoded(member)].concat())
}

fn int(member: &str) -> BoxedUint {
    BoxedUint::from_be_slice(&decoded(member), 4096).unwrap()
}

/// `value` as a Base64urlUInt: big endian, leading zeros stripped.
fn uint(value: &BoxedUint) -> String {
    let bytes = value.to_be_bytes();

    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());

    b64(bytes.get(start..).unwrap())
}

fn less_one(prime: &str) -> BoxedUint {
    int(prime).wrapping_sub(BoxedUint::one_with_precision(4096))
}

#[test]
fn reads_the_public_key_of_rfc_7517() {
    let rsa = public(N, E).unwrap();

    assert_eq!(
        rsa.public_members().to_json(),
        format!(r#"{{"e":"AQAB","kty":"RSA","n":"{N}"}}"#)
    );
}

#[test]
fn reads_the_private_key_of_rfc_7517() {
    let rsa = Members::rfc().private().unwrap();

    assert_eq!(rsa.public(), public(N, E).unwrap());
}

#[test]
fn a_member_is_canonical_base64url() {
    let members = Members::rfc();

    for name in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        let value = members.get(name);

        for bad in [
            format!("{value}="),
            format!(" {value}"),
            format!("{value}*"),
        ] {
            let refused = if name == "n" || name == "e" {
                let (n, e) = if name == "n" {
                    (bad.as_str(), E)
                } else {
                    (N, bad.as_str())
                };

                public(n, e).err()
            } else {
                members.clone().with(name, bad.clone()).private().err()
            };

            assert_eq!(
                refused,
                Some(RsaErrors::InvalidEncoding(name)),
                "{name}: {bad}"
            );
        }
    }
}

#[test]
fn a_member_is_a_positive_integer_without_leading_zeros() {
    // RFC 7518 §2: one number, one encoding.
    let members = Members::rfc();

    for name in ["n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        let value = members.get(name);

        for bad in [zero_prefixed(value), String::new(), b64(&[0])] {
            let refused = if name == "n" || name == "e" {
                let (n, e) = if name == "n" {
                    (bad.as_str(), E)
                } else {
                    (N, bad.as_str())
                };

                public(n, e).err()
            } else {
                members.clone().with(name, bad.clone()).private().err()
            };

            assert_eq!(
                refused,
                Some(RsaErrors::InvalidInteger(name)),
                "{name}: {bad}"
            );
        }
    }
}

#[test]
fn the_modulus_has_from_2048_to_4096_bits() {
    let n = decoded(N);

    // 2040 bits.
    let short = b64(n.get(1..).unwrap());

    assert_eq!(public(&short, E).err(), Some(RsaErrors::TooShort));

    // 2047 bits.
    let mut top_clear = n.clone();

    if let Some(first) = top_clear.first_mut() {
        *first &= 0x7f;
    }

    assert_eq!(public(&b64(&top_clear), E).err(), Some(RsaErrors::TooShort));

    // 4096 and 4097 bits, odd.
    let mut max = vec![0xffu8; 512];

    assert!(public(&b64(&max), E).is_ok());

    max.insert(0, 0x01);

    assert_eq!(public(&b64(&max), E).err(), Some(RsaErrors::TooLong));

    // Refused before its bits are counted.
    assert_eq!(
        public(&b64(&vec![0xffu8; 100_000]), E).err(),
        Some(RsaErrors::TooLong)
    );
}

#[test]
fn the_modulus_is_odd() {
    let mut n = decoded(N);

    if let Some(last) = n.last_mut() {
        *last &= 0xfe;
    }

    assert_eq!(public(&b64(&n), E).err(), Some(RsaErrors::EvenModulus));
}

#[test]
fn the_public_exponent_is_65537() {
    // e = 3 is the exponent of the forgeries of Bleichenbacher 2006.
    for e in ["Aw", "AQAA", "AQAC", "_w", "AQABAQ"] {
        assert_eq!(
            public(N, e).err(),
            Some(RsaErrors::UnsupportedExponent),
            "{e}"
        );
    }
}

#[test]
fn every_secret_member_belongs_to_the_key() {
    for name in SECRET_NAMES {
        let members = Members::rfc();

        let changed = flipped(members.get(name));

        assert_eq!(
            members.with(name, changed).private().err(),
            Some(RsaErrors::KeyMismatch),
            "{name}"
        );
    }
}

#[test]
fn p_and_q_in_each_others_place_are_not_the_key() {
    let members = Members::rfc()
        .with("p", Q.to_owned())
        .with("q", P.to_owned());

    assert_eq!(members.private().err(), Some(RsaErrors::KeyMismatch));
}

#[test]
fn d_is_below_the_modulus() {
    let members = Members::rfc().with("d", N.to_owned());

    assert_eq!(members.private().err(), Some(RsaErrors::KeyMismatch));
}

#[test]
fn the_private_members_are_of_this_modulus() {
    // Another modulus of the same size: the private members are of another key.
    let mut n = decoded(N);

    if let Some(byte) = n.get_mut(100) {
        *byte ^= 0x10;
    }

    let members = Members::rfc().with("n", b64(&n));

    assert_eq!(members.private().err(), Some(RsaErrors::KeyMismatch));
}

#[test]
fn the_public_rules_hold_for_a_private_key() {
    assert_eq!(
        Members::rfc().with("e", "Aw".to_owned()).private().err(),
        Some(RsaErrors::UnsupportedExponent)
    );
}

#[test]
fn d_agrees_with_dp_and_with_dq() {
    // Odd, below n and long enough, so the backend takes it: only the check of d refuses it.
    let off_p = int(D).wrapping_add(less_one(Q));

    assert_eq!(
        Members::rfc().with("d", uint(&off_p)).private().err(),
        Some(RsaErrors::KeyMismatch)
    );

    let off_q = int(D).wrapping_add(less_one(P));

    assert_eq!(
        Members::rfc().with("d", uint(&off_q)).private().err(),
        Some(RsaErrors::KeyMismatch)
    );
}

#[test]
fn d_dp_and_dq_that_agree_but_are_not_the_inverse_of_e_are_refused() {
    // Consistent with each other, so only a signature checked against n and e refuses them.
    let d = int(D).wrapping_add(BoxedUint::from_be_slice(&[2], 4096).unwrap());

    let dp = d.rem(&NonZero::new(less_one(P)).unwrap());

    let dq = d.rem(&NonZero::new(less_one(Q)).unwrap());

    let members = Members::rfc()
        .with("d", uint(&d))
        .with("dp", uint(&dp))
        .with("dq", uint(&dq));

    assert_eq!(members.private().err(), Some(RsaErrors::KeyMismatch));
}

#[test]
fn dp_dq_and_qi_are_compared_and_not_only_read() {
    // The backend computes them from d, p and q: one of the JWK that is off by one is still
    // refused.
    for name in ["dp", "dq", "qi"] {
        let members = Members::rfc();

        let off = uint(&int(members.get(name)).wrapping_add(BoxedUint::one_with_precision(4096)));

        assert_eq!(
            members.with(name, off).private().err(),
            Some(RsaErrors::KeyMismatch),
            "{name}"
        );
    }
}
