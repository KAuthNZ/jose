use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnySecretKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

impl Jwk<Secret> {
    /// The key for `A`, as [`Jwk::<Public>::bind`](Jwk::bind). Consumes it: whoever keeps it
    /// duplicates it.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Hs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// let jwk = Jwk::read_secret(br#"{"kty": "oct",
    ///     "k": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#)?;
    ///
    /// let key = jwk.bind::<Hs256>()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Only to a symmetric algorithm: a secret has no curve.
    ///
    /// ```compile_fail,E0277
    /// use kauthnz_jose::jwa::Es256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// let jwk = Jwk::read_secret(br#"{"kty": "oct",
    ///     "k": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#)?;
    ///
    /// let key = jwk.bind::<Es256>()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind<A>(self) -> Result<Jwk<Secret<A>>, BindErrors>
    where
        A: TypedSigningAlgorithm,
        Secret<A>: Bound<From = AnySecretKey>,
    {
        let UnboundMaterial {
            material,
            candidates,
        } = self.held;

        admits::<A>(&candidates)?;

        let held = Secret::<A>::take(material).ok_or(BindErrors::MaterialAndCandidates)?;

        Ok(Jwk {
            kid: self.kid,
            held,
        })
    }
}
