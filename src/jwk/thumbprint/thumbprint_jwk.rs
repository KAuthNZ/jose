use crate::jwk::key::Jwk;

use crate::jwk::key::Holds;

use crate::jwk::key_types::Publishes;

use super::jwk_thumbprint::JwkThumbprint;

impl<M> Jwk<M>
where
    M: Holds,
    M::Held: Publishes,
{
    /// Its JWK Thumbprint (RFC 7638): of its public members only, so a private key has the one of
    /// its public key, and `kid`, `alg` or `use` don't change it. Not of a secret: it would be
    /// the hash of the secret itself.
    ///
    /// ```
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2 and A.3.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    ///
    /// assert_eq!(jwk.thumbprint().to_string(), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
    /// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
    /// ```
    ///
    /// ```compile_fail,E0599
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// let secret = Jwk::read_secret(br#"{"kty": "oct",
    ///     "k": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#)?;
    ///
    /// let thumbprint = secret.thumbprint();
    /// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
    /// ```
    pub fn thumbprint(&self) -> JwkThumbprint {
        JwkThumbprint::of(&self.held.public_members())
    }
}
