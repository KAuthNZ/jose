use super::key_type::KeyType;

/// The JSON Web Key Elliptic Curve registry (RFC 7518 §7.6.2, RFC 8037 §5, RFC 8812 §3.2), read
/// by this library or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    P256,

    P384,

    P521,

    Secp256k1,

    Ed25519,

    Ed448,

    X25519,

    X448,
}

impl Curve {
    pub const ALL: [Self; 8] = [
        Self::P256,
        Self::P384,
        Self::P521,
        Self::Secp256k1,
        Self::Ed25519,
        Self::Ed448,
        Self::X25519,
        Self::X448,
    ];

    /// Exact and case-sensitive.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|curve| curve.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",

            Self::P384 => "P-384",

            Self::P521 => "P-521",

            Self::Secp256k1 => "secp256k1",

            Self::Ed448 => "Ed448",

            Self::Ed25519 => "Ed25519",

            Self::X448 => "X448",

            Self::X25519 => "X25519",
        }
    }

    /// The `kty` the registry gives it: in a key of another type, the curve is foreign.
    pub const fn kty(self) -> KeyType {
        match self {
            Self::P256 | Self::P384 | Self::P521 | Self::Secp256k1 => KeyType::Ec,

            Self::Ed25519 | Self::Ed448 | Self::X25519 | Self::X448 => KeyType::Okp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(curve: Curve) -> usize {
        match curve {
            Curve::P256 => 0,
            Curve::P384 => 1,
            Curve::P521 => 2,
            Curve::Secp256k1 => 3,
            Curve::Ed25519 => 4,
            Curve::Ed448 => 5,
            Curve::X25519 => 6,
            Curve::X448 => 7,
        }
    }

    #[test]
    fn all_lists_every_curve_once_and_in_order() {
        for (index, curve) in Curve::ALL.into_iter().enumerate() {
            assert_eq!(position(curve), index, "{curve:?}");
        }
    }

    #[test]
    fn names_are_the_registered_ones() {
        let names: Vec<&str> = Curve::ALL.into_iter().map(Curve::name).collect();

        assert_eq!(
            names,
            [
                "P-256",
                "P-384",
                "P-521",
                "secp256k1",
                "Ed25519",
                "Ed448",
                "X25519",
                "X448"
            ]
        );
    }

    #[test]
    fn a_curve_is_read_by_its_name() {
        for curve in Curve::ALL {
            assert_eq!(Curve::from_name(curve.name()), Some(curve));
        }
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "p-256",
            "P256",
            "P-256 ",
            " P-256",
            "P-256\0",
            "ed25519",
            "Ed25519\n",
            "P\u{2010}256",
            "SECP256K1",
            "secp256r1",
            "prime256v1",
            "none",
        ] {
            assert_eq!(Curve::from_name(name), None, "{name:?}");
        }
    }

    #[test]
    fn each_curve_belongs_to_its_kty() {
        for (curve, kty) in [
            (Curve::P256, KeyType::Ec),
            (Curve::P384, KeyType::Ec),
            (Curve::P521, KeyType::Ec),
            (Curve::Secp256k1, KeyType::Ec),
            (Curve::Ed25519, KeyType::Okp),
            (Curve::Ed448, KeyType::Okp),
            (Curve::X25519, KeyType::Okp),
            (Curve::X448, KeyType::Okp),
        ] {
            assert_eq!(curve.kty(), kty, "{curve:?}");
        }
    }
}
