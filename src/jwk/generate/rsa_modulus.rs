/// The size of a generated RSA key: only one a key read from a JWK may have (2048 to 4096 bits),
/// so this library never generates a key it would then refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaModulus {
    Bits2048,

    Bits3072,

    Bits4096,
}

impl RsaModulus {
    pub const fn bits(self) -> usize {
        match self {
            Self::Bits2048 => 2048,

            Self::Bits3072 => 3072,

            Self::Bits4096 => 4096,
        }
    }
}
