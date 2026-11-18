use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

use crate::jwa::SigningAlgorithm;

use crate::jwk::bind::AnyBoundSecret;

use super::errors::GenerateErrors;

impl Jwk<Secret> {
    /// A new secret for the algorithm the caller expects, chosen at run time from its
    /// configuration, as [`generate`](Jwk::generate) for a type.
    ///
    /// ```
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// use kauthnz_jose::jwk::Secret;
    ///
    /// use kauthnz_jose::jwa::SigningAlgorithm;
    ///
    /// let secret = Jwk::<Secret>::generate_expected(SigningAlgorithm::Hs256)?;
    /// # Ok::<(), kauthnz_jose::jwk::GenerateErrors>(())
    /// ```
    pub fn generate_expected(alg: SigningAlgorithm) -> Result<AnyBoundSecret, GenerateErrors> {
        match alg {
            SigningAlgorithm::Hs256 => Jwk::<Secret<Hs256>>::generate().map(AnyBoundSecret::Hs256),

            SigningAlgorithm::Hs384 => Jwk::<Secret<Hs384>>::generate().map(AnyBoundSecret::Hs384),

            SigningAlgorithm::Hs512 => Jwk::<Secret<Hs512>>::generate().map(AnyBoundSecret::Hs512),

            SigningAlgorithm::Ed25519
            | SigningAlgorithm::Es256
            | SigningAlgorithm::Es384
            | SigningAlgorithm::Es512
            | SigningAlgorithm::Es256k
            | SigningAlgorithm::Ed448
            | SigningAlgorithm::Rs256
            | SigningAlgorithm::Rs384
            | SigningAlgorithm::Rs512
            | SigningAlgorithm::Ps256
            | SigningAlgorithm::Ps384
            | SigningAlgorithm::Ps512
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87 => Err(GenerateErrors::NotForThisMode),
        }
    }
}
