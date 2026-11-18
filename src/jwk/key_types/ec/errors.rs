use std::fmt;

/// Why an EC key was refused while its material was being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcErrors {
    /// A `crv` that is not registered.
    UnknownCurve,

    /// A `crv` registered for another `kty`, e.g. `Ed25519`.
    ForeignCurve,

    /// A `crv` registered for EC that this library doesn't read, e.g. `secp256k1`.
    UnsupportedCurve,

    /// A member that is not unpadded, canonical base64url (RFC 7515 §2).
    InvalidEncoding(&'static str),

    /// A coordinate or `d` not of the exact size of the curve (RFC 7518 §6.2.1.2, §6.2.2.1).
    InvalidLength(&'static str),

    /// A coordinate at or above the prime of the field, or a point that is not on the curve.
    NotOnCurve,

    /// A `d` that is 0 or not below the order of the group.
    InvalidSecret,

    /// A `d` whose public key is not the `x` and `y` of the JWK.
    KeyMismatch,
}

impl fmt::Display for EcErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCurve => f.write_str("crv is not a registered curve"),

            Self::ForeignCurve => f.write_str("crv is a curve of another key type"),

            Self::UnsupportedCurve => f.write_str("crv is a curve this library doesn't read"),

            Self::InvalidEncoding(name) => write!(f, "{name} is not canonical base64url"),

            Self::InvalidLength(name) => write!(f, "{name} is not of the size of the curve"),

            Self::NotOnCurve => f.write_str("x and y are not a point of the curve"),

            Self::InvalidSecret => f.write_str("d is not a valid scalar of the curve"),

            Self::KeyMismatch => f.write_str("d is not the private key of x and y"),
        }
    }
}

impl std::error::Error for EcErrors {}
