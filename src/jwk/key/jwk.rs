use crate::jwk::members::Kid;

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
    pub(super) kid: Option<Kid>,

    pub(super) held: M::Held,
}

impl<M> Jwk<M>
where
    M: Holds,
{
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_ref().map(Kid::as_str)
    }
}
