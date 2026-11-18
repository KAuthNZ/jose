use std::fmt;

/// Why the bytes of one JWK are not a JSON object to read a key from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkDecodingErrors {
    /// Longer than any key this library reads, checked before parsing.
    TooLarge,

    NotJson,

    NotAnObject,

    /// A member name more than once, at any depth (RFC 7517 §4, RFC 8259 §4).
    DuplicateMembers,
}

impl fmt::Display for JwkDecodingErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "JWK is too large",

            Self::NotJson => "JWK is not JSON",

            Self::NotAnObject => "JWK is not a JSON object",

            Self::DuplicateMembers => "JWK repeats a member name",
        })
    }
}

impl std::error::Error for JwkDecodingErrors {}
