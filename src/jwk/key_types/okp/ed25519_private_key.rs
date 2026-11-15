use ed25519_dalek::SigningKey;

use ed25519_dalek::VerifyingKey;

use super::ed25519;

use super::errors::OkpErrors;

use super::super::duplicate::Duplicate;

use super::super::public_side::PublicSide;

use super::ed25519_public_key::Ed25519PublicKey;

/// An Ed25519 private key with its public key, `public` checked to be the one of `d`: what a key
/// bound to Ed25519 signs with.
///
/// `pub` for the same reason as [`Ed25519PublicKey`]. Without `Debug` on purpose: `d` is never
/// printed. Not `Clone` either: copied only by `Duplicate`, each copy wiped on drop.
pub struct Ed25519PrivateKey {
    d: SigningKey,

    public: VerifyingKey,
}

impl Ed25519PrivateKey {
    /// `x` and `d` as they came in the JWK.
    pub(super) fn read(x: &str, d: &str) -> Result<Self, OkpErrors> {
        let (d, public) = ed25519::key_pair(x, d)?;

        Ok(Self { d, public })
    }
}

impl Duplicate for Ed25519PrivateKey {
    fn duplicate(&self) -> Self {
        Self {
            d: self.d.clone(),
            public: self.public,
        }
    }
}

/// The same key without `d`.
impl PublicSide for Ed25519PrivateKey {
    type Public = Ed25519PublicKey;

    fn public(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from_backend(self.public)
    }
}
