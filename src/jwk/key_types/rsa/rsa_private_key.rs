use rsa::BoxedUint;

use rsa::PrivateKey;

use zeroize::Zeroizing;

use crypto_bigint::CtEq;

use crypto_bigint::Resize;

use rsa::traits::PublicKeyParts;

use rsa::traits::PrivateKeyParts;

use super::key_rules;

use super::decoding;

use super::errors::RsaErrors;

use super::rsa_public_key::RsaPublicKey;

use super::rsa_private_key_members::RsaPrivateKeyMembers;

/// The private key of an RSA JWK (RFC 7518 §6.3.2), every CRT member required, each checked to
/// be of this key. Kept as the key of the backend, which wipes it on drop.
///
/// Without `Debug` or `Clone` on purpose.
pub struct RsaPrivateKey(PrivateKey);

impl RsaPrivateKey {
    /// The backend checks `d < n`, `n = p·q` with distinct primes and `d·e ≡ 1` modulo `p − 1`
    /// and `q − 1`, but computes `dp`, `dq` and `qi` itself instead of reading them: those of the
    /// JWK are compared with its own, in constant time.
    pub(in crate::jwk) fn read(members: RsaPrivateKeyMembers<'_>) -> Result<Self, RsaErrors> {
        let public = RsaPublicKey::read(members.n, members.e)?;

        let d = decoding::secret("d", members.d)?;

        let p = decoding::secret("p", members.p)?;

        let q = decoding::secret("q", members.q)?;

        let dp = decoding::secret("dp", members.dp)?;

        let dq = decoding::secret("dq", members.dq)?;

        let qi = decoding::secret("qi", members.qi)?;

        for (name, value) in [
            ("d", &d),
            ("p", &p),
            ("q", &q),
            ("dp", &dp),
            ("dq", &dq),
            ("qi", &qi),
        ] {
            key_rules::unsigned(name, value)?;
        }

        let bits = public.precision()?;

        let int = |bytes: &[u8]| {
            BoxedUint::from_be_slice(bytes, bits)
                .map(Zeroizing::new)
                .map_err(|_| RsaErrors::KeyMismatch)
        };

        let backend = public.backend();

        let key = PrivateKey::from_components(
            backend.n().as_ref().clone(),
            backend.e().clone(),
            (*int(&d)?).clone(),
            vec![(*int(&p)?).clone(), (*int(&q)?).clone()],
        )
        .map_err(|_| RsaErrors::KeyMismatch)?;

        // `try_resize` and not `widen`, which panics on a precision below the current one.
        let to_bits = |value: Option<&BoxedUint>| {
            value
                .and_then(|value| value.try_resize(bits))
                .map(Zeroizing::new)
                .ok_or(RsaErrors::KeyMismatch)
        };

        let expected_dp = to_bits(key.dp())?;

        let expected_dq = to_bits(key.dq())?;

        let expected_qi = to_bits(key.crt_coefficient().as_ref())?;

        let matches = int(&dp)?.ct_eq(&*expected_dp)
            & int(&dq)?.ct_eq(&*expected_dq)
            & int(&qi)?.ct_eq(&*expected_qi);

        if matches.to_bool() {
            Ok(Self(key))
        } else {
            Err(RsaErrors::KeyMismatch)
        }
    }

    /// The same key without its private members.
    pub(crate) fn public(&self) -> RsaPublicKey {
        RsaPublicKey::from_backend(self.0.to_public_key())
    }
}
