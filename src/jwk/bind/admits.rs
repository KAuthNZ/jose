use crate::jwa::Algorithm;

use crate::jwk::members::KeyAlg;

use crate::jwk::fit::Candidates;

use crate::jwa::TypedSigningAlgorithm;

use super::errors::BindErrors;

/// The one check of whether the key takes `A`: fit already judged its `kty`, curve, mode, `alg`,
/// `use` and `key_ops`.
pub(super) fn admits<A>(candidates: &Candidates) -> Result<(), BindErrors>
where
    A: TypedSigningAlgorithm,
{
    if candidates.contains(KeyAlg::from(Algorithm::Signing(A::ALG))) {
        Ok(())
    } else {
        Err(BindErrors::NotACandidate)
    }
}
