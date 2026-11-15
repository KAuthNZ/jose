use serde_json::Map;

use serde_json::Value;

use crate::json::JsonErrors;

use crate::json::parse_object_deep;

use super::constants::MAX_JWK_LEN;

use super::errors::JwkDecodingErrors;

/// The members of one JWK. Deep: a name repeated inside a member, e.g. in `x5c`, is refused too.
pub(in crate::jwk) fn members(source: &[u8]) -> Result<Map<String, Value>, JwkDecodingErrors> {
    parse_object_deep(source, MAX_JWK_LEN).map_err(|error| match error {
        JsonErrors::TooLarge => JwkDecodingErrors::TooLarge,

        JsonErrors::Malformed => JwkDecodingErrors::NotJson,

        JsonErrors::NotAnObject => JwkDecodingErrors::NotAnObject,

        JsonErrors::DuplicateMembers => JwkDecodingErrors::DuplicateMembers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A JSON object of exactly `len` bytes.
    fn object_of_len(len: usize) -> Vec<u8> {
        let filler = len - r#"{"a":""}"#.len();

        format!(r#"{{"a":"{}"}}"#, "x".repeat(filler)).into_bytes()
    }

    #[test]
    fn the_members_of_a_jwk_are_read() {
        let members = members(br#"{"kty":"OKP","crv":"Ed25519","x":"abc"}"#).unwrap();

        assert_eq!(members.get("kty"), Some(&Value::from("OKP")));
        assert_eq!(members.len(), 3);
    }

    #[test]
    fn the_longest_jwk_is_read_and_one_byte_more_is_not() {
        assert!(members(&object_of_len(MAX_JWK_LEN)).is_ok());

        assert_eq!(
            members(&object_of_len(MAX_JWK_LEN + 1)),
            Err(JwkDecodingErrors::TooLarge)
        );
    }

    #[test]
    fn what_is_not_json_is_refused() {
        for source in [&b""[..], b"{", b"{\"kty\":}", b"{} {}", b"{\"a\":\"\xff\"}"] {
            assert_eq!(
                members(source),
                Err(JwkDecodingErrors::NotJson),
                "{source:?}"
            );
        }
    }

    #[test]
    fn json_that_is_not_an_object_is_refused() {
        for source in [&b"[]"[..], b"[{}]", b"\"OKP\"", b"null", b"1"] {
            assert_eq!(
                members(source),
                Err(JwkDecodingErrors::NotAnObject),
                "{source:?}"
            );
        }
    }

    #[test]
    fn a_member_repeated_at_any_depth_is_refused() {
        for source in [
            &br#"{"kty":"EC","kty":"OKP"}"#[..],
            br#"{"kty":"EC","\u006bty":"OKP"}"#,
            br#"{"kty":"EC","x5c":[{"a":1,"a":2}]}"#,
        ] {
            assert_eq!(
                members(source),
                Err(JwkDecodingErrors::DuplicateMembers),
                "{source:?}"
            );
        }
    }
}
