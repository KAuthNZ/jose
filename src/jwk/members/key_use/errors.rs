use std::fmt;

/// Why a `use` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyUseErrors {
    /// A value that is not in the "JSON Web Key Use" registry.
    Unregistered,
}

impl fmt::Display for KeyUseErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unregistered => f.write_str("use is not a registered key use"),
        }
    }
}

impl std::error::Error for KeyUseErrors {}
