use zeroize::Zeroizing;

use crate::base64url;

use super::errors::OctErrors;

/// The secret of an oct JWK (RFC 7518 §6.4): `k`, decoded. Any bytes but none are a key; whether
/// they are enough for an algorithm is judged with the algorithm.
///
/// Without `Debug` or `Clone` on purpose: `k` is wiped on drop and never printed.
pub struct OctSecretKey {
    k: Zeroizing<Vec<u8>>,
}

impl OctSecretKey {
    /// `k` as it came in the JWK.
    pub(in crate::jwk) fn read(k: &str) -> Result<Self, OctErrors> {
        let len = base64url::decoded_len(k.len()).map_err(|_| OctErrors::InvalidEncoding)?;

        if len == 0 {
            return Err(OctErrors::Empty);
        }

        let mut bytes = Zeroizing::new(vec![0u8; len]);

        base64url::decode_into(k, &mut bytes).map_err(|_| OctErrors::InvalidEncoding)?;

        Ok(Self { k: bytes })
    }

    /// For the MAC it keys; the bytes stay in this buffer, wiped on drop.
    pub(crate) fn secret(&self) -> &[u8] {
        &self.k
    }

    /// In bytes.
    pub(crate) fn len(&self) -> usize {
        self.k.len()
    }
}
