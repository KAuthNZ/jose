use zeroize::Zeroizing;

use crate::jwa::Ed25519;

use crate::jwk::mode::Private;

use crate::jwk::thumbprint::Thumbprint;

use crate::jwk::key_types::Ed25519PrivateKey;

use super::generates::Generates;

use super::errors::GenerateErrors;

impl Generates for Private<Ed25519> {
    /// A seed of 32 random bytes: any is one (RFC 8032 §5.1.5). Filled here and not by the
    /// backend, whose `generate` takes an RNG that may not fail.
    fn material() -> Result<Ed25519PrivateKey, GenerateErrors> {
        let mut seed = Zeroizing::new([0u8; 32]);

        getrandom::fill(seed.as_mut()).map_err(|_| GenerateErrors::Rng)?;

        Ok(Ed25519PrivateKey::from_seed(&seed))
    }

    fn kid(held: &Ed25519PrivateKey) -> Result<String, GenerateErrors> {
        Ok(Thumbprint::of(held).to_string())
    }
}
