use crate::jwa::SigningAlgorithm;

use super::closed_set::ClosedSet;

/// A signing algorithm as a type, to fix it when the code is written instead of when it runs.
///
/// ```
/// use kauthnz_jose::jwa::Es256;
///
/// use kauthnz_jose::jwa::SigningAlgorithm;
///
/// use kauthnz_jose::jwa::TypedSigningAlgorithm;
///
/// assert_eq!(Es256::ALG, SigningAlgorithm::Es256);
/// ```
///
/// ```compile_fail
/// use kauthnz_jose::jwa::SigningAlgorithm;
///
/// use kauthnz_jose::jwa::TypedSigningAlgorithm;
///
/// enum Mine {}
///
/// impl TypedSigningAlgorithm for Mine {
///     const ALG: SigningAlgorithm = SigningAlgorithm::Hs256;
/// }
/// ```
pub trait TypedSigningAlgorithm: ClosedSet {
    const ALG: SigningAlgorithm;
}
