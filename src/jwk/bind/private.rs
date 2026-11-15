use crate::jwk::key::Jwk;

use crate::jwk::mode::Private;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnyPrivateKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

impl Jwk<Private> {
    /// The key for `A`, as [`Jwk::<Public>::bind`](Jwk::bind). Consumes it: whoever keeps it
    /// duplicates it.
    pub fn bind<A>(self) -> Result<Jwk<Private<A>>, BindErrors>
    where
        A: TypedSigningAlgorithm,
        Private<A>: Bound<From = AnyPrivateKey>,
    {
        let UnboundMaterial {
            material,
            candidates,
        } = self.held;

        admits::<A>(&candidates)?;

        let held = Private::<A>::take(material).ok_or(BindErrors::MaterialAndCandidates)?;

        Ok(Jwk {
            kid: self.kid,
            held,
        })
    }
}
