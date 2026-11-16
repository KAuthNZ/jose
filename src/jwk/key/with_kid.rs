use crate::jwk::members::Kid;

use crate::jwk::members::KidErrors;

use super::jwk::Jwk;

use super::holds::Holds;

impl<M> Jwk<M>
where
    M: Holds,
{
    /// The same key with another `kid`, held to the rules of a read one. In the key and not in
    /// a token, so that the JWKS it is published in and the header of a token never differ.
    ///
    /// ```
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2, read without a kid.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?
    ///     .with_kid("2026-11-tenant-a")?;
    ///
    /// assert_eq!(jwk.kid(), Some("2026-11-tenant-a"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_kid<K>(self, kid: K) -> Result<Self, KidErrors>
    where
        K: Into<String>,
    {
        Ok(Self {
            kid: Some(Kid::read(kid.into())?),
            held: self.held,
        })
    }
}
