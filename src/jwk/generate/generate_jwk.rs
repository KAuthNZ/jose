use crate::jwk::key::Jwk;

use crate::jwk::members::Kid;

use super::generates::Generates;

use super::errors::GenerateErrors;

impl<M> Jwk<M>
where
    M: Generates,
{
    /// A new key for the algorithm of `M`, from the randomness of the operating system. Its
    /// `kid` is its thumbprint, or random for a secret, which has none; `with_kid` gives another.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Es256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// use kauthnz_jose::jwk::Private;
    ///
    /// let signer = Jwk::<Private<Es256>>::generate()?;
    ///
    /// assert_eq!(signer.kid(), Some(signer.thumbprint().to_string().as_str()));
    /// # Ok::<(), kauthnz_jose::jwk::GenerateErrors>(())
    /// ```
    ///
    /// Not RSA, whose size is chosen: [`generate_rsa`](Jwk::generate_rsa).
    ///
    /// ```compile_fail,E0599
    /// use kauthnz_jose::jwa::Rs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// use kauthnz_jose::jwk::Private;
    ///
    /// let signer = Jwk::<Private<Rs256>>::generate()?;
    /// # Ok::<(), kauthnz_jose::jwk::GenerateErrors>(())
    /// ```
    pub fn generate() -> Result<Self, GenerateErrors> {
        let held = M::material()?;

        let kid = Kid::read(M::kid(&held)?)?;

        Ok(Self {
            kid: Some(kid),
            held,
        })
    }
}
