use std::fmt;

/// Why a JWK Set is refused whole. A key that can't be read is not one of these: it is left out
/// of the set, with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwkSetErrors {
    /// Longer than 128 KiB, checked before parsing.
    TooLarge,

    NotJson,

    NotAnObject,

    /// A member name more than once, at any depth: in the set or in one of its keys (RFC 7517
    /// §5, RFC 8259 §4).
    DuplicateMembers,

    /// No `keys` member (RFC 7517 §5).
    MissingKeys,

    KeysNotAnArray,

    /// A `keys` array with nothing in it: a set to verify with has at least one key.
    Empty,

    /// More than 32 keys, counted before any of them is read.
    TooManyKeys,

    /// The entry at `index` of `keys` is not a JSON object.
    NotAKey {
        index: usize,
    },

    /// The entry at `index` has `name`, a member of the "Private" class (RFC 7517 §8.1.1): a
    /// published set has no private or symmetric key (OpenID Connect Discovery §3).
    SecretMember {
        index: usize,

        name: &'static str,
    },
}

impl fmt::Display for JwkSetErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("JWK Set is too large"),

            Self::NotJson => f.write_str("JWK Set is not JSON"),

            Self::NotAnObject => f.write_str("JWK Set is not a JSON object"),

            Self::DuplicateMembers => f.write_str("JWK Set repeats a member name"),

            Self::MissingKeys => f.write_str("JWK Set has no keys member"),

            Self::KeysNotAnArray => f.write_str("JWK Set keys member is not an array"),

            Self::Empty => f.write_str("JWK Set has no keys"),

            Self::TooManyKeys => f.write_str("JWK Set has too many keys"),

            Self::NotAKey { index } => write!(f, "JWK Set entry {index} is not a JSON object"),

            Self::SecretMember { index, name } => {
                write!(f, "JWK Set entry {index} has the secret member {name}")
            }
        }
    }
}

impl std::error::Error for JwkSetErrors {}
