use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnyPublicKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

impl Jwk<Public> {
    /// The key for `A`, if `A` is one of its candidates. Consumes it: whoever keeps it clones it.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Ed25519;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519", "kid": "2026-11",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    ///
    /// let key = jwk.bind::<Ed25519>()?;
    ///
    /// assert_eq!(key.kid(), Some("2026-11"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Only to an algorithm a public key of some family can have: never a symmetric one.
    ///
    /// ```compile_fail,E0277
    /// use kauthnz_jose::jwa::Hs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    ///
    /// let key = jwk.bind::<Hs256>()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind<A>(self) -> Result<Jwk<Public<A>>, BindErrors>
    where
        A: TypedSigningAlgorithm,
        Public<A>: Bound<From = AnyPublicKey>,
    {
        let UnboundMaterial {
            material,
            candidates,
        } = self.held;

        admits::<A>(&candidates)?;

        let held = Public::<A>::take(material).ok_or(BindErrors::MaterialAndCandidates)?;

        Ok(Jwk {
            kid: self.kid,
            held,
        })
    }
}
