use super::super::key_use::KeyUse;

/// One value of `key_ops` (RFC 7517 §4.3), only from the "JSON Web Key Operations" registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyOp {
    Sign,

    Verify,

    Encrypt,

    Decrypt,

    WrapKey,

    UnwrapKey,

    DeriveKey,

    DeriveBits,
}

impl KeyOp {
    pub(crate) const ALL: [Self; 8] = [
        Self::Sign,
        Self::Verify,
        Self::Encrypt,
        Self::Decrypt,
        Self::WrapKey,
        Self::UnwrapKey,
        Self::DeriveKey,
        Self::DeriveBits,
    ];

    /// Case-sensitive, nothing trimmed (RFC 7517 §4.3).
    pub(super) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Sign => "sign",

            Self::Verify => "verify",

            Self::Encrypt => "encrypt",

            Self::Decrypt => "decrypt",

            Self::WrapKey => "wrapKey",

            Self::UnwrapKey => "unwrapKey",

            Self::DeriveKey => "deriveKey",

            Self::DeriveBits => "deriveBits",
        }
    }

    /// The `use` this operation belongs to, so that `use` and `key_ops` can be compared
    /// (RFC 7517 §4.3).
    pub(crate) const fn key_use(self) -> KeyUse {
        match self {
            Self::Sign | Self::Verify => KeyUse::Signature,

            Self::Encrypt
            | Self::Decrypt
            | Self::WrapKey
            | Self::UnwrapKey
            | Self::DeriveKey
            | Self::DeriveBits => KeyUse::Encryption,
        }
    }

    /// The other face of the same operation, the only one it may be listed with
    /// (RFC 7517 §4.3). `deriveKey` and `deriveBits` have none.
    pub(crate) const fn counterpart(self) -> Option<Self> {
        match self {
            Self::Sign => Some(Self::Verify),

            Self::Verify => Some(Self::Sign),

            Self::Encrypt => Some(Self::Decrypt),

            Self::Decrypt => Some(Self::Encrypt),

            Self::WrapKey => Some(Self::UnwrapKey),

            Self::UnwrapKey => Some(Self::WrapKey),

            Self::DeriveKey | Self::DeriveBits => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(op: KeyOp) -> usize {
        match op {
            KeyOp::Sign => 0,
            KeyOp::Verify => 1,
            KeyOp::Encrypt => 2,
            KeyOp::Decrypt => 3,
            KeyOp::WrapKey => 4,
            KeyOp::UnwrapKey => 5,
            KeyOp::DeriveKey => 6,
            KeyOp::DeriveBits => 7,
        }
    }

    #[test]
    fn all_lists_every_operation_once_and_in_order() {
        for (index, op) in KeyOp::ALL.into_iter().enumerate() {
            assert_eq!(position(op), index, "{op:?}");
        }
    }

    #[test]
    fn an_operation_is_read_by_its_registered_name() {
        for op in KeyOp::ALL {
            assert_eq!(KeyOp::from_name(op.name()), Some(op));
        }
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "Sign",
            "SIGN",
            "wrapkey",
            "unwrap_key",
            "verify ",
            "derive",
            "none",
        ] {
            assert_eq!(KeyOp::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn each_operation_belongs_to_its_use() {
        for (op, key_use) in [
            (KeyOp::Sign, KeyUse::Signature),
            (KeyOp::Verify, KeyUse::Signature),
            (KeyOp::Encrypt, KeyUse::Encryption),
            (KeyOp::Decrypt, KeyUse::Encryption),
            (KeyOp::WrapKey, KeyUse::Encryption),
            (KeyOp::UnwrapKey, KeyUse::Encryption),
            (KeyOp::DeriveKey, KeyUse::Encryption),
            (KeyOp::DeriveBits, KeyUse::Encryption),
        ] {
            assert_eq!(op.key_use(), key_use, "{op:?}");
        }
    }

    #[test]
    fn each_operation_has_its_counterpart_only() {
        for (op, counterpart) in [
            (KeyOp::Sign, Some(KeyOp::Verify)),
            (KeyOp::Verify, Some(KeyOp::Sign)),
            (KeyOp::Encrypt, Some(KeyOp::Decrypt)),
            (KeyOp::Decrypt, Some(KeyOp::Encrypt)),
            (KeyOp::WrapKey, Some(KeyOp::UnwrapKey)),
            (KeyOp::UnwrapKey, Some(KeyOp::WrapKey)),
            (KeyOp::DeriveKey, None),
            (KeyOp::DeriveBits, None),
        ] {
            assert_eq!(op.counterpart(), counterpart, "{op:?}");
        }
    }
}
