use std::fmt;

/// Why an OKP key was refused while its material was being read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OkpErrors {
    /// A `crv` that is not registered.
    UnknownCurve,

    /// A `crv` registered for another `kty`, e.g. `P-256`.
    ForeignCurve,

    /// A `crv` registered for OKP that this library doesn't read, e.g. `X25519`.
    UnsupportedCurve,

    /// A member that is not unpadded, canonical base64url (RFC 7515 §2).
    InvalidEncoding(&'static str),

    /// `x` or `d` not of the exact size of the curve (RFC 8032 §5.1.5).
    InvalidLength(&'static str),

    /// An `x` that is not the encoding of a point of the curve.
    NotOnCurve,

    /// An `x` that is not the one encoding of its point (RFC 8032 §5.1.3).
    NonCanonical,

    /// An `x` of small order: a signature of it verifies for almost any message.
    SmallOrder,

    /// An `x` of mixed order: no real signer has it, and verifiers disagree on its signatures.
    MixedOrder,

    /// A `d` whose public key is not `x`.
    KeyMismatch,
}

impl fmt::Display for OkpErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCurve => f.write_str("crv is not a registered curve"),

            Self::ForeignCurve => f.write_str("crv is a curve of another key type"),

            Self::UnsupportedCurve => f.write_str("crv is a curve this library doesn't read"),

            Self::InvalidEncoding(name) => write!(f, "{name} is not canonical base64url"),

            Self::InvalidLength(name) => write!(f, "{name} is not of the size of the curve"),

            Self::NotOnCurve => f.write_str("x is not a point of the curve"),

            Self::NonCanonical => f.write_str("x is not the canonical encoding of its point"),

            Self::SmallOrder => f.write_str("x is a point of small order"),

            Self::MixedOrder => f.write_str("x is a point of mixed order"),

            Self::KeyMismatch => f.write_str("d is not the private key of x"),
        }
    }
}

impl std::error::Error for OkpErrors {}
