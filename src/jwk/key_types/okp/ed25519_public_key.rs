use ed25519_dalek::VerifyingKey;

use super::ed25519;

use super::errors::OkpErrors;

/// An Ed25519 public key, one a real signer could have: what a key bound to Ed25519 verifies with.
///
/// `pub` in a module that can't be named from outside the crate: a bound key holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519PublicKey(VerifyingKey);

impl Ed25519PublicKey {
    /// `x` as it came in the JWK.
    pub(super) fn read(x: &str) -> Result<Self, OkpErrors> {
        ed25519::public_key(x).map(Self)
    }

    /// One the private key already holds, checked when it was read.
    pub(super) fn from_backend(key: VerifyingKey) -> Self {
        Self(key)
    }

    /// The 32 bytes of the encoded point (RFC 8037 §2).
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}
