/// The content encryption algorithms of the JSON Web Signature and Encryption Algorithms registry
/// (RFC 7518 §7.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentEncryptionAlgorithm {
    A128Gcm,

    A192Gcm,

    A256Gcm,

    A128CbcHs256,

    A192CbcHs384,

    A256CbcHs512,
}

impl ContentEncryptionAlgorithm {
    pub const ALL: [Self; 6] = [
        Self::A128Gcm,
        Self::A192Gcm,
        Self::A256Gcm,
        Self::A128CbcHs256,
        Self::A192CbcHs384,
        Self::A256CbcHs512,
    ];

    /// Exact and case-sensitive.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|enc| enc.name() == name)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::A128Gcm => "A128GCM",

            Self::A192Gcm => "A192GCM",

            Self::A256Gcm => "A256GCM",

            Self::A128CbcHs256 => "A128CBC-HS256",

            Self::A192CbcHs384 => "A192CBC-HS384",

            Self::A256CbcHs512 => "A256CBC-HS512",
        }
    }

    /// In bytes. For AES-CBC-HMAC it is MAC_KEY || ENC_KEY (RFC 7518 §5.2.2.1).
    pub const fn key_len(self) -> usize {
        match self {
            Self::A128Gcm => 16,

            Self::A192Gcm => 24,

            Self::A256Gcm => 32,

            Self::A128CbcHs256 => 32,

            Self::A192CbcHs384 => 48,

            Self::A256CbcHs512 => 64,
        }
    }

    /// In bytes.
    pub const fn iv_len(self) -> usize {
        match self {
            Self::A128Gcm | Self::A192Gcm | Self::A256Gcm => 12,

            Self::A128CbcHs256 | Self::A192CbcHs384 | Self::A256CbcHs512 => 16,
        }
    }

    /// In bytes.
    pub const fn tag_len(self) -> usize {
        match self {
            Self::A128CbcHs256 => 16,

            Self::A192CbcHs384 => 24,

            Self::A256CbcHs512 => 32,

            Self::A128Gcm | Self::A192Gcm | Self::A256Gcm => 16,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // No wildcard on purpose.
    fn position(enc: ContentEncryptionAlgorithm) -> usize {
        match enc {
            ContentEncryptionAlgorithm::A128Gcm => 0,
            ContentEncryptionAlgorithm::A192Gcm => 1,
            ContentEncryptionAlgorithm::A256Gcm => 2,
            ContentEncryptionAlgorithm::A128CbcHs256 => 3,
            ContentEncryptionAlgorithm::A192CbcHs384 => 4,
            ContentEncryptionAlgorithm::A256CbcHs512 => 5,
        }
    }

    #[test]
    fn all_lists_every_algorithm_once_and_in_order() {
        for (index, enc) in ContentEncryptionAlgorithm::ALL.into_iter().enumerate() {
            assert_eq!(position(enc), index, "{enc:?}");
        }
    }

    #[test]
    fn names_are_the_registered_ones() {
        let names: Vec<&str> = ContentEncryptionAlgorithm::ALL
            .into_iter()
            .map(ContentEncryptionAlgorithm::name)
            .collect();

        assert_eq!(
            names,
            [
                "A128GCM",
                "A192GCM",
                "A256GCM",
                "A128CBC-HS256",
                "A192CBC-HS384",
                "A256CBC-HS512",
            ]
        );
    }

    #[test]
    fn an_algorithm_is_read_by_its_name() {
        for enc in ContentEncryptionAlgorithm::ALL {
            assert_eq!(ContentEncryptionAlgorithm::from_name(enc.name()), Some(enc));
        }
    }

    #[test]
    fn names_are_exact() {
        for name in [
            "",
            "none",
            "a128gcm",
            "A128Gcm",
            "A128GCM ",
            "A128-GCM",
            "A128CBC-HS256 ",
            "A128CBC_HS256",
            "a128cbc-hs256",
            "A128CBC",
            "A128CBC+HS256",
        ] {
            assert_eq!(
                ContentEncryptionAlgorithm::from_name(name),
                None,
                "{name:?}"
            );
        }
    }

    #[test]
    fn a_cbc_hmac_key_is_a_mac_key_and_an_encryption_key_each_as_long_as_the_tag() {
        for enc in [
            ContentEncryptionAlgorithm::A128CbcHs256,
            ContentEncryptionAlgorithm::A192CbcHs384,
            ContentEncryptionAlgorithm::A256CbcHs512,
        ] {
            assert_eq!(enc.key_len(), 2 * enc.tag_len(), "{enc:?}");
            assert_eq!(enc.iv_len(), 16, "{enc:?}");
        }
    }

    #[test]
    fn gcm_takes_an_aes_key_a_96_bit_iv_and_a_128_bit_tag() {
        for (enc, key_len) in [
            (ContentEncryptionAlgorithm::A128Gcm, 16),
            (ContentEncryptionAlgorithm::A192Gcm, 24),
            (ContentEncryptionAlgorithm::A256Gcm, 32),
        ] {
            assert_eq!(enc.key_len(), key_len, "{enc:?}");
            assert_eq!(enc.iv_len(), 12, "{enc:?}");
            assert_eq!(enc.tag_len(), 16, "{enc:?}");
        }
    }
}
