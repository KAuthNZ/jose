/// The JSON Web Key Types registry (RFC 7518 §7.4.2, RFC 8037 §5, draft-ietf-cose-dilithium),
/// read by this library or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyType {
    Rsa,

    Ec,

    Oct,

    Okp,

    Akp,
}

impl KeyType {
    pub const ALL: [Self; 5] = [Self::Rsa, Self::Ec, Self::Oct, Self::Okp, Self::Akp];

    /// Exact and case-sensitive (RFC 7517 §4.1).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kty| kty.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Ec => "EC",

            Self::Akp => "AKP",

            Self::Oct => "oct",

            Self::Okp => "OKP",

            Self::Rsa => "RSA",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(kty: KeyType) -> usize {
        match kty {
            KeyType::Rsa => 0,
            KeyType::Ec => 1,
            KeyType::Oct => 2,
            KeyType::Okp => 3,
            KeyType::Akp => 4,
        }
    }

    #[test]
    fn all_lists_every_kty_once_and_in_order() {
        for (index, kty) in KeyType::ALL.into_iter().enumerate() {
            assert_eq!(position(kty), index, "{kty:?}");
        }
    }

    #[test]
    fn names_are_the_registered_ones() {
        let names: Vec<&str> = KeyType::ALL.into_iter().map(KeyType::name).collect();

        assert_eq!(names, ["RSA", "EC", "oct", "OKP", "AKP"]);
    }

    #[test]
    fn a_kty_is_read_by_its_name() {
        for kty in KeyType::ALL {
            assert_eq!(KeyType::from_name(kty.name()), Some(kty));
        }
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "ec",
            "Ec",
            "EC ",
            " EC",
            "EC\0",
            "EC\n",
            "E\u{0421}",
            "rsa",
            "Rsa",
            "OCT",
            "okp",
            "Okp",
            "akp",
            "none",
        ] {
            assert_eq!(KeyType::from_name(name), None, "{name:?}");
        }
    }
}
