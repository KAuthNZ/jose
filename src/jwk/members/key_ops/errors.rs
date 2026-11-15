use std::fmt;

use super::key_op::KeyOp;

/// Why a `key_ops` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOpsErrors {
    /// A value that is not in the "JSON Web Key Operations" registry.
    Unregistered,

    /// An operation listed twice (RFC 7517 §4.3).
    Duplicate(KeyOp),
}

impl fmt::Display for KeyOpsErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unregistered => f.write_str("key_ops has an operation that is not registered"),

            Self::Duplicate(op) => write!(f, "key_ops lists {} twice", op.name()),
        }
    }
}

impl std::error::Error for KeyOpsErrors {}
