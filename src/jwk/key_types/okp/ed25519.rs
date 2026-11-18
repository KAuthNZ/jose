use zeroize::Zeroizing;

use ed25519_dalek::SigningKey;

use ed25519_dalek::VerifyingKey;

use crate::base64url;

use super::errors::OkpErrors;

/// The Ed25519 public key in `x`, refused unless a real signer could have it.
pub(super) fn public_key(x: &str) -> Result<VerifyingKey, OkpErrors> {
    let bytes = base64url::decode(x).map_err(|_| OkpErrors::InvalidEncoding("x"))?;

    let bytes =
        <&[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| OkpErrors::InvalidLength("x"))?;

    let key = VerifyingKey::from_bytes(bytes).map_err(|_| OkpErrors::NotOnCurve)?;

    // First, since every non-canonical encoding is of a point of small or mixed order: the
    // backend reduces a `y` of p or above.
    if key.to_edwards().compress().to_bytes() != *bytes {
        return Err(OkpErrors::NonCanonical);
    }

    if key.is_weak() {
        return Err(OkpErrors::SmallOrder);
    }

    if !key.to_edwards().is_torsion_free() {
        return Err(OkpErrors::MixedOrder);
    }

    Ok(key)
}

/// The seed `d` with the public key `x`, refused unless `x` is the key of `d`. Any 32 bytes are
/// a seed (RFC 8032 §5.1.5): there is no invalid one.
pub(super) fn key_pair(x: &str, d: &str) -> Result<(SigningKey, VerifyingKey), OkpErrors> {
    let public = public_key(x)?;

    let len = base64url::decoded_len(d.len()).map_err(|_| OkpErrors::InvalidEncoding("d"))?;

    let mut bytes = Zeroizing::new(vec![0u8; len]);

    base64url::decode_into(d, &mut bytes).map_err(|_| OkpErrors::InvalidEncoding("d"))?;

    let seed =
        <&[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| OkpErrors::InvalidLength("d"))?;

    let secret = SigningKey::from_bytes(seed);

    if secret.verifying_key() != public {
        return Err(OkpErrors::KeyMismatch);
    }

    Ok((secret, public))
}
