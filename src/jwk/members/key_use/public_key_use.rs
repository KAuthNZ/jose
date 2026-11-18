use super::errors::KeyUseErrors;

/// `use` (RFC 7517 §4.2): only the values of the "JSON Web Key Use" registry. The RFC lets
/// others be used; this library doesn't, since a use it doesn't know can't say what the key is
/// for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyUse {
    Signature,

    Encryption,
}

impl KeyUse {
    pub(crate) const ALL: [Self; 2] = [Self::Signature, Self::Encryption];

    /// Case-sensitive, nothing trimmed (RFC 7517 §4.2).
    pub(in crate::jwk) fn read(name: &str) -> Result<Self, KeyUseErrors> {
        Self::ALL
            .into_iter()
            .find(|key_use| key_use.name() == name)
            .ok_or(KeyUseErrors::Unregistered)
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Signature => "sig",

            Self::Encryption => "enc",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(key_use: KeyUse) -> usize {
        match key_use {
            KeyUse::Signature => 0,
            KeyUse::Encryption => 1,
        }
    }

    #[test]
    fn all_lists_every_use_once_and_in_order() {
        for (index, key_use) in KeyUse::ALL.into_iter().enumerate() {
            assert_eq!(position(key_use), index, "{key_use:?}");
        }
    }

    #[test]
    fn a_use_is_read_by_its_registered_name() {
        assert_eq!(KeyUse::read("sig"), Ok(KeyUse::Signature));

        assert_eq!(KeyUse::read("enc"), Ok(KeyUse::Encryption));
    }

    #[test]
    fn a_name_out_of_the_registry_is_refused() {
        for name in [
            "",
            "SIG",
            "Sig",
            "sig ",
            " enc",
            "enc\0",
            "signature",
            "verify",
            "both",
        ] {
            assert_eq!(
                KeyUse::read(name),
                Err(KeyUseErrors::Unregistered),
                "{name:?}"
            );
        }
    }
}
