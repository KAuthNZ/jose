use std::fmt;

/// Why an RSA key was refused while its material was being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaErrors {
    /// A member that is not unpadded, canonical base64url (RFC 7515 §2).
    InvalidEncoding(&'static str),

    /// A member that is empty, zero, or has a leading zero byte: not a Base64urlUInt of a
    /// positive number (RFC 7518 §2).
    InvalidInteger(&'static str),

    /// A modulus of less than 2048 bits.
    TooShort,

    /// A modulus of more than 4096 bits.
    TooLong,

    /// An even modulus, which no RSA key has.
    EvenModulus,

    /// A public exponent other than 65537.
    UnsupportedExponent,

    /// Private members that are not one key with `n` and `e`.
    KeyMismatch,

    /// The backend refused a public key these rules took: refused rather than assumed to pass.
    BackendRefused,
}

impl fmt::Display for RsaErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEncoding(name) => write!(f, "{name} is not canonical base64url"),

            Self::InvalidInteger(name) => write!(f, "{name} is not a positive Base64urlUInt"),

            Self::TooShort => f.write_str("modulus shorter than 2048 bits"),

            Self::TooLong => f.write_str("modulus longer than 4096 bits"),

            Self::EvenModulus => f.write_str("modulus is even"),

            Self::UnsupportedExponent => f.write_str("public exponent other than 65537"),

            Self::KeyMismatch => f.write_str("private members are not the key of n and e"),

            Self::BackendRefused => f.write_str("the RSA backend refused the public key"),
        }
    }
}

impl std::error::Error for RsaErrors {}
