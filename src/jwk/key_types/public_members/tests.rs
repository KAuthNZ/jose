use crate::jwa::KeyType;

use super::PublicMembers;

/// RFC 7638 §3.1, the `n` of the RSA key of RFC 7517 A.1.
const RFC7638_N: &str = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";

#[test]
fn a_key_starts_with_its_kty_only() {
    let members = PublicMembers::new(KeyType::Okp);

    assert_eq!(members.iter().collect::<Vec<_>>(), [("kty", "OKP")]);
}

#[test]
fn rfc7638_section_3_1_is_written_as_the_rfc_writes_it() {
    let members = PublicMembers::new(KeyType::Rsa)
        .with("n", RFC7638_N.to_owned())
        .with("e", "AQAB".to_owned());

    assert_eq!(
        members.thumbprint_json(),
        format!(r#"{{"e":"AQAB","kty":"RSA","n":"{RFC7638_N}"}}"#)
    );
}

#[test]
fn the_order_of_the_names_is_theirs_and_not_the_order_they_were_given_in() {
    let members = PublicMembers::new(KeyType::Ec)
        .with("y", "4".to_owned())
        .with("x", "3".to_owned())
        .with("crv", "P-256".to_owned());

    let names: Vec<&str> = members.iter().map(|(name, _)| name).collect();

    assert_eq!(names, ["crv", "kty", "x", "y"]);

    assert_eq!(
        members.thumbprint_json(),
        r#"{"crv":"P-256","kty":"EC","x":"3","y":"4"}"#
    );
}
