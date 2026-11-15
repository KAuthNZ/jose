use rsa::BoxedUint;

use rsa::PublicKey;

use rsa::traits::PublicKeyParts;

use crate::base64url;

use crate::jwa::KeyType;

use super::key_rules;

use super::decoding;

use super::errors::RsaErrors;

use crate::jwk::key_types::PublicMembers;

/// The public key of an RSA JWK (RFC 7518 §6.3.1): `n` from 2048 to 4096 bits and odd, `e` of
/// 65537, each a Base64urlUInt without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey(PublicKey);

impl RsaPublicKey {
    /// `n` and `e` as they came in the JWK. These rules first, stricter than the backend's.
    pub(in crate::jwk) fn read(n: &str, e: &str) -> Result<Self, RsaErrors> {
        let n = decoding::public("n", n)?;

        let e = decoding::public("e", e)?;

        key_rules::modulus(&n)?;

        key_rules::public_exponent(&e)?;

        PublicKey::new(
            BoxedUint::from_be_slice_vartime(&n),
            BoxedUint::from_be_slice_vartime(&e),
        )
        .map(Self)
        .map_err(|_| RsaErrors::BackendRefused)
    }

    pub(super) fn from_backend(key: PublicKey) -> Self {
        Self(key)
    }

    pub(super) fn backend(&self) -> &PublicKey {
        &self.0
    }

    /// The precision every integer of this key is read with: the width of `n`, which is public,
    /// so that it never depends on the length of a secret.
    pub(super) fn precision(&self) -> Result<u32, RsaErrors> {
        self.0
            .n_bytes()
            .len()
            .checked_mul(8)
            .and_then(|bits| u32::try_from(bits).ok())
            .ok_or(RsaErrors::TooLong)
    }

    /// `n` and `e` as the Base64urlUInt they were read as (RFC 7518 §6.3.1), leading zeros
    /// trimmed. Variable time, on public values only.
    pub(crate) fn public_members(&self) -> PublicMembers {
        PublicMembers::new(KeyType::Rsa)
            .with("n", base64url::encode(&self.0.n_bytes()))
            .with("e", base64url::encode(&self.0.e_bytes()))
    }
}
