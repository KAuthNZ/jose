use serde_json::Map;

use serde_json::Value;

use serde::de::DeserializeSeed;

use serde_json::error::Category;

use super::errors::JsonErrors;

use super::strict_map::StrictMap;

use super::strict_object::StrictObject;

/// A JSON object with no member name repeated at its top level: every JOSE header and the claims
/// of a JWT. `max_len` is checked before anything is parsed, and a malformed input is refused as
/// malformed even when it also repeats a name.
pub(crate) fn parse_object(bytes: &[u8], max_len: usize) -> Result<Map<String, Value>, JsonErrors> {
    if bytes.len() > max_len {
        return Err(JsonErrors::TooLarge);
    }

    let mut repeated = false;

    let mut de = serde_json::Deserializer::from_slice(bytes);

    let parsed = StrictMap {
        repeated: &mut repeated,
    }
    .deserialize(&mut de)
    .and_then(|map| de.end().map(|()| map));

    classify(parsed, repeated)
}

/// Like `parse_object`, with no name repeated in any object nested inside either, arrays
/// included: a JWK Set, where each key is a nested object.
pub(crate) fn parse_object_deep(
    bytes: &[u8],
    max_len: usize,
) -> Result<Map<String, Value>, JsonErrors> {
    if bytes.len() > max_len {
        return Err(JsonErrors::TooLarge);
    }

    let mut repeated = false;

    let mut de = serde_json::Deserializer::from_slice(bytes);

    // `deserialize_map` makes serde_json refuse a top level that is not an object.
    let parsed = serde::Deserializer::deserialize_map(
        &mut de,
        StrictObject {
            repeated: &mut repeated,
        },
    )
    .and_then(|map| de.end().map(|()| map));

    classify(parsed, repeated)
}

fn classify<T>(parsed: Result<T, serde_json::Error>, repeated: bool) -> Result<T, JsonErrors> {
    match parsed {
        Ok(value) if !repeated => Ok(value),

        Ok(_) => Err(JsonErrors::DuplicateMembers),

        // The syntax is fine and the value is not an object: serde_json reports the type
        // mismatch as a data error.
        Err(e) if e.classify() == Category::Data => Err(JsonErrors::NotAnObject),

        Err(_) => Err(JsonErrors::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const CAP: usize = 8 * 1024;

    fn parse(input: &[u8]) -> Result<Map<String, Value>, JsonErrors> {
        parse_object(input, CAP)
    }

    #[test]
    fn a_plain_object_parses() {
        let map = parse(br#"{"alg":"HS256","n":{"a":[1,null]}}"#).unwrap();

        assert_eq!(map.get("alg"), Some(&json!("HS256")));
        assert_eq!(map.get("n"), Some(&json!({"a": [1, null]})));
    }

    #[test]
    fn empty_object_parses() {
        assert!(parse(b"{}").unwrap().is_empty());
    }

    #[test]
    fn a_repeated_name_is_refused() {
        assert_eq!(
            parse(br#"{"a":1,"a":2}"#),
            Err(JsonErrors::DuplicateMembers)
        );
        assert_eq!(
            parse(br#"{"a":1,"b":1,"b":2,"c":1}"#),
            Err(JsonErrors::DuplicateMembers)
        );
    }

    #[test]
    fn names_are_compared_once_decoded() {
        assert_eq!(
            parse(br#"{"a":1,"a":2}"#),
            Err(JsonErrors::DuplicateMembers)
        );
        assert_eq!(
            parse(br#"{"alg":"HS256","alg":"none"}"#),
            Err(JsonErrors::DuplicateMembers)
        );
    }

    #[test]
    fn names_are_case_sensitive() {
        assert!(parse(br#"{"a":1,"A":2}"#).is_ok());
    }

    #[test]
    fn repeats_in_nested_objects_are_not_checked() {
        assert!(parse(br#"{"a":{"b":1,"b":2}}"#).is_ok());
    }

    #[test]
    fn malformed_wins_over_duplicates() {
        assert_eq!(parse(br#"{"a":1,"a":2,"#), Err(JsonErrors::Malformed));
    }

    #[test]
    fn the_top_level_must_be_an_object() {
        for input in [&b"[]"[..], b"1", b"\"x\"", b"null", b"true"] {
            assert_eq!(parse(input), Err(JsonErrors::NotAnObject), "{input:?}");
        }
    }

    #[test]
    fn malformed_input() {
        for input in [
            &b""[..],
            b"{",
            b"{\"a\":}",
            // Bytes after the value.
            b"{} x",
            b"{}{}",
            // A raw control character inside a string, NUL included, has to be escaped.
            b"{\"a\":\"\0\"}",
            b"{\"a\":\"\n\"}",
            // Invalid UTF-8.
            b"{\"a\":\"\xff\"}",
            // Lone surrogates.
            br#"{"a":"\ud800"}"#,
            br#"{"\udc00":1}"#,
        ] {
            assert_eq!(parse(input), Err(JsonErrors::Malformed), "{input:?}");
        }
    }

    #[test]
    fn nesting_beyond_the_parser_limit_is_refused() {
        let deep = format!(r#"{{"a":{}{}}}"#, "[".repeat(200), "]".repeat(200));

        assert_eq!(parse(deep.as_bytes()), Err(JsonErrors::Malformed));

        let shallow = format!(r#"{{"a":{}{}}}"#, "[".repeat(10), "]".repeat(10));

        assert!(parse(shallow.as_bytes()).is_ok());
    }

    #[test]
    fn the_size_cap_is_checked_first() {
        let input = br#"{"a":1}"#;

        assert!(parse_object(input, input.len()).is_ok());
        assert_eq!(
            parse_object(input, input.len() - 1),
            Err(JsonErrors::TooLarge)
        );

        // Too large wins even when the input would not parse.
        assert_eq!(parse_object(b"not json", 3), Err(JsonErrors::TooLarge));
    }

    fn deep(input: &[u8]) -> Result<Map<String, Value>, JsonErrors> {
        parse_object_deep(input, CAP)
    }

    #[test]
    fn deep_parses_the_same_values() {
        let input = br#"{"keys":[{"kty":"EC","x":"a"},{"n":1.5,"e":-2,"b":true,"z":null}],"u":18446744073709551615}"#;

        assert_eq!(deep(input), parse(input));
    }

    #[test]
    fn deep_refuses_a_repeat_at_the_top_level() {
        assert_eq!(
            deep(br#"{"keys":[],"keys":[]}"#),
            Err(JsonErrors::DuplicateMembers)
        );
    }

    #[test]
    fn deep_refuses_a_repeat_inside_an_array() {
        assert_eq!(
            deep(br#"{"keys":[{"kty":"EC"},{"x":"a","x":"b"}]}"#),
            Err(JsonErrors::DuplicateMembers)
        );
    }

    #[test]
    fn deep_refuses_a_repeat_in_a_nested_object() {
        for input in [
            &br#"{"a":{"b":1,"b":2}}"#[..],
            br#"{"a":[[{"c":{"d":1,"d":1}}]]}"#,
            br#"{"a":{"b":[1,{"c":0,"e":1,"c":0}]}}"#,
        ] {
            assert_eq!(deep(input), Err(JsonErrors::DuplicateMembers), "{input:?}");
        }
    }

    #[test]
    fn deep_compares_names_once_decoded() {
        assert_eq!(
            deep(br#"{"keys":[{"x":1,"\u0078":2}]}"#),
            Err(JsonErrors::DuplicateMembers)
        );
        assert!(deep(br#"{"keys":[{"x":1,"X":2}]}"#).is_ok());
    }

    #[test]
    fn deep_allows_the_same_name_in_sibling_objects() {
        assert!(deep(br#"{"keys":[{"kid":"1"},{"kid":"1"}],"a":{"kid":"1"}}"#).is_ok());
    }

    #[test]
    fn deep_malformed_wins_over_duplicates() {
        assert_eq!(
            deep(br#"{"a":[{"b":1,"b":2}],"#),
            Err(JsonErrors::Malformed)
        );
    }

    #[test]
    fn deep_the_top_level_must_be_an_object() {
        for input in [&b"[]"[..], b"[{}]", b"1", b"\"x\"", b"null", b"true"] {
            assert_eq!(deep(input), Err(JsonErrors::NotAnObject), "{input:?}");
        }
    }

    #[test]
    fn deep_malformed_input() {
        for input in [
            &b""[..],
            b"{",
            b"{} x",
            b"{\"a\":[{\"b\":\"\0\"}]}",
            b"{\"a\":[\"\xff\"]}",
            br#"{"a":[{"\ud800":1}]}"#,
        ] {
            assert_eq!(deep(input), Err(JsonErrors::Malformed), "{input:?}");
        }
    }

    #[test]
    fn deep_nesting_beyond_the_parser_limit_is_refused() {
        for (open, close) in [("[", "]"), (r#"{"a":"#, "}")] {
            let too_deep = format!(r#"{{"a":{}0{}}}"#, open.repeat(200), close.repeat(200));

            assert_eq!(
                deep(too_deep.as_bytes()),
                Err(JsonErrors::Malformed),
                "{open}"
            );

            let shallow = format!(r#"{{"a":{}0{}}}"#, open.repeat(10), close.repeat(10));

            assert!(deep(shallow.as_bytes()).is_ok(), "{open}");
        }
    }

    #[test]
    fn deep_the_size_cap_is_checked_first() {
        let input = br#"{"a":1}"#;

        assert!(parse_object_deep(input, input.len()).is_ok());
        assert_eq!(
            parse_object_deep(input, input.len() - 1),
            Err(JsonErrors::TooLarge)
        );
        assert_eq!(parse_object_deep(b"not json", 3), Err(JsonErrors::TooLarge));
    }
}
