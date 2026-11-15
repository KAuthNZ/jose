use crate::jwk::members::Kid;

use crate::jwk::key_types::Duplicate;

use super::holds::Holds;

/// One JWK in a mode. `Jwk<Public>`, `Jwk<Private>` and `Jwk<Secret>` are read and judged, and
/// bound to no algorithm.
///
/// ```
/// use kauthnz_jose::jwk::Jwk;
///
/// // RFC 8037 A.2.
/// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519", "kid": "2026-11",
///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
///
/// assert_eq!(jwk.kid(), Some("2026-11"));
/// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
/// ```
///
/// Without `Debug` on purpose: a private or secret one holds a secret.
pub struct Jwk<M>
where
    M: Holds,
{
    pub(in crate::jwk) kid: Option<Kid>,

    pub(in crate::jwk) held: M::Held,
}

impl<M> Jwk<M>
where
    M: Holds,
{
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_ref().map(Kid::as_str)
    }
}

/// Only where what it holds is public: a secret is copied by [`Jwk::duplicate`].
impl<M> Clone for Jwk<M>
where
    M: Holds,
    M::Held: Clone,
{
    fn clone(&self) -> Self {
        Self {
            kid: self.kid.clone(),
            held: self.held.clone(),
        }
    }
}

impl<M> Jwk<M>
where
    M: Holds,
    M::Held: Duplicate,
{
    /// A copy of a private or secret key, asked for by name: nothing copies one without saying
    /// so. Each copy is wiped on drop, as the original is.
    ///
    /// ```
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.1.
    /// let private = Jwk::read_private(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    ///     "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#)?;
    ///
    /// let copy = private.duplicate();
    /// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
    /// ```
    ///
    /// Not `Clone`:
    ///
    /// ```compile_fail,E0599
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.1.
    /// let private = Jwk::read_private(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
    ///     "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#)?;
    ///
    /// let copy = private.clone();
    /// # Ok::<(), kauthnz_jose::jwk::JwkErrors>(())
    /// ```
    pub fn duplicate(&self) -> Self {
        Self {
            kid: self.kid.clone(),
            held: self.held.duplicate(),
        }
    }
}
