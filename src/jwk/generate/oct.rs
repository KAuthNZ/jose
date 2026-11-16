use zeroize::Zeroizing;

use crate::base64url;

use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwk::mode::Secret;

use crate::jwk::key_types::OctSecretKey;

use super::generates::Generates;

use super::errors::GenerateErrors;

use super::constants::RANDOM_KID_LEN;

/// 32 bytes: the output of its hash, the least RFC 7518 §3.2 lets it take.
impl Generates for Secret<Hs256> {
    fn material() -> Result<OctSecretKey, GenerateErrors> {
        random_secret(32)
    }

    fn kid(_: &OctSecretKey) -> Result<String, GenerateErrors> {
        random_kid()
    }
}

/// 48 bytes, as for HS256.
impl Generates for Secret<Hs384> {
    fn material() -> Result<OctSecretKey, GenerateErrors> {
        random_secret(48)
    }

    fn kid(_: &OctSecretKey) -> Result<String, GenerateErrors> {
        random_kid()
    }
}

/// 64 bytes, as for HS256.
impl Generates for Secret<Hs512> {
    fn material() -> Result<OctSecretKey, GenerateErrors> {
        random_secret(64)
    }

    fn kid(_: &OctSecretKey) -> Result<String, GenerateErrors> {
        random_kid()
    }
}

/// The `kid` of a secret: random, since its thumbprint would be the hash of the secret. Only to
/// find the key; it says nothing of it.
fn random_kid() -> Result<String, GenerateErrors> {
    let mut bytes = [0u8; RANDOM_KID_LEN];

    getrandom::fill(&mut bytes).map_err(|_| GenerateErrors::Rng)?;

    Ok(base64url::encode(&bytes))
}

fn random_secret(len: usize) -> Result<OctSecretKey, GenerateErrors> {
    let mut k = Zeroizing::new(vec![0u8; len]);

    getrandom::fill(&mut k).map_err(|_| GenerateErrors::Rng)?;

    Ok(OctSecretKey::generated(k))
}
