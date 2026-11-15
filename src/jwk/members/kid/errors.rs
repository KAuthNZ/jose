use std::fmt;

/// Why a `kid` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KidErrors {
    Empty,

    /// Longer than 256 bytes.
    TooLong,

    /// A space at the start or the end.
    SpaceAtEdge,

    /// A byte outside space to `~`.
    NotPrintableAscii,
}

impl fmt::Display for KidErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("kid is empty"),

            Self::TooLong => f.write_str("kid is longer than 256 bytes"),

            Self::SpaceAtEdge => f.write_str("kid starts or ends with a space"),

            Self::NotPrintableAscii => f.write_str("kid has a byte outside printable ASCII"),
        }
    }
}

impl std::error::Error for KidErrors {}
