use zeroize::Zeroizing;

use crate::base64url;

use super::errors::RsaErrors;

pub(super) fn public(name: &'static str, encoded: &str) -> Result<Vec<u8>, RsaErrors> {
    base64url::decode(encoded).map_err(|_| RsaErrors::InvalidEncoding(name))
}

/// Into a buffer wiped on drop, also when the decoding fails halfway.
pub(super) fn secret(name: &'static str, encoded: &str) -> Result<Zeroizing<Vec<u8>>, RsaErrors> {
    let len =
        base64url::decoded_len(encoded.len()).map_err(|_| RsaErrors::InvalidEncoding(name))?;

    let mut bytes = Zeroizing::new(vec![0u8; len]);

    base64url::decode_into(encoded, &mut bytes).map_err(|_| RsaErrors::InvalidEncoding(name))?;

    Ok(bytes)
}
