use crate::jwk::mode::Public;

use crate::jwk::mode::Private;

use crate::jwk::key_types::PublicSide;

use super::jwk::Jwk;

use super::holds::Holds;

impl<A> Jwk<Private<A>>
where
    Private<A>: Holds,
    Public<A>: Holds,
    <Private<A> as Holds>::Held: PublicSide<Public = <Public<A> as Holds>::Held>,
{
    /// The public key of this one, bound to the same algorithm, with the same `kid`. Its own: the
    /// private one is kept, and what is copied is public material, never a secret.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Ed25519;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.1.
    /// let signer = Jwk::read_private(br#"{"kty": "OKP", "crv": "Ed25519", "kid": "2026-11",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    ///     "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#)?
    ///     .bind::<Ed25519>()?;
    ///
    /// let verifier = signer.public();
    ///
    /// assert_eq!(verifier.kid(), Some("2026-11"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Not of a secret: it has no public side.
    ///
    /// ```compile_fail,E0599
    /// use kauthnz_jose::jwa::Hs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// let secret = Jwk::read_secret(br#"{"kty": "oct",
    ///     "k": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"}"#)?
    ///     .bind::<Hs256>()?;
    ///
    /// let public = secret.public();
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn public(&self) -> Jwk<Public<A>> {
        Jwk {
            kid: self.kid.clone(),
            held: self.held.public(),
        }
    }
}
