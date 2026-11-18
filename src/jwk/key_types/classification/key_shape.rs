use crate::jwa::Curve;

use crate::jwa::KeyType;

/// What a key read from a JWK is, as far as choosing its algorithms goes: the family, with its
/// curve or, for a symmetric key, its size. Given by the key, so each family says only what it
/// has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyShape {
    /// `len` in bytes.
    Oct {
        len: usize,
    },

    Rsa,

    Ec(Curve),

    Okp(Curve),
}

impl KeyShape {
    pub(crate) fn kty(self) -> KeyType {
        match self {
            Self::Ec(_) => KeyType::Ec,

            Self::Okp(_) => KeyType::Okp,

            Self::Oct { .. } => KeyType::Oct,

            Self::Rsa => KeyType::Rsa,
        }
    }

    /// `None` for a family without curves.
    pub(crate) fn crv(self) -> Option<Curve> {
        match self {
            Self::Ec(crv) | Self::Okp(crv) => Some(crv),

            Self::Oct { .. } => None,

            Self::Rsa => None,
        }
    }

    /// `None` for a family whose key is not a bare secret.
    pub(crate) fn secret_len(self) -> Option<usize> {
        match self {
            Self::Oct { len } => Some(len),

            Self::Ec(_) | Self::Okp(_) => None,

            Self::Rsa => None,
        }
    }
}
