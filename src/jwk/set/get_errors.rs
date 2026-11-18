use std::fmt;

/// Why no key was taken out of a JWK Set that was read. Not of reading it: of using it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetErrors {
    /// No key has this `kid`. Compared exactly, case included (RFC 7517 §4.5).
    UnknownKid,

    /// No `kid` was given and the set has more than one key: no key is tried.
    KidRequired,
}

impl fmt::Display for GetErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownKid => "no key of the JWK Set has this kid",

            Self::KidRequired => "a kid is required to take a key out of this JWK Set",
        })
    }
}

impl std::error::Error for GetErrors {}
