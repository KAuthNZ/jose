use std::fmt;

/// Why one JWK was refused while its members were being read, before anything they say is
/// judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawJwkErrors {
    /// No `kty` (RFC 7517 §4.1).
    MissingKty,

    /// A registered member with the wrong JSON type, `null` included.
    InvalidMember(&'static str),

    /// A registered member this library refuses to read, e.g. `oth`.
    UnsupportedMember(&'static str),
}

impl fmt::Display for RawJwkErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKty => f.write_str("kty is missing"),

            Self::InvalidMember(name) => write!(f, "{name} is not of its JSON type"),

            Self::UnsupportedMember(name) => write!(f, "{name} is not read by this library"),
        }
    }
}

impl std::error::Error for RawJwkErrors {}
