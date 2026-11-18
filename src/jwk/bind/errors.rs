use std::fmt;

/// Why a JWK was not bound to an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindErrors {
    /// The algorithm is not one of the key: what it is or what it declared does not let it.
    NotACandidate,

    /// The algorithm is one of the key, but its material is not of that algorithm. Refused
    /// rather than assumed impossible.
    MaterialAndCandidates,

    /// The algorithm is in the registry, but this library does not implement it yet.
    Unsupported,
}

impl fmt::Display for BindErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACandidate => f.write_str("the key does not take the algorithm"),

            Self::MaterialAndCandidates => {
                f.write_str("the key takes the algorithm but its material is not of it")
            }

            Self::Unsupported => f.write_str("this library does not implement the algorithm yet"),
        }
    }
}

impl std::error::Error for BindErrors {}
