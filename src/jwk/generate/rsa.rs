use rsa::PrivateKey;

use getrandom::SysRng;

use crate::jwk::key::Jwk;

use crate::jwk::key::Holds;

use crate::jwk::members::Kid;

use crate::jwk::mode::Private;

use crate::jwk::thumbprint::Thumbprint;

use crate::jwk::key_types::RsaPrivateKey;

use super::errors::GenerateErrors;

use super::rsa_modulus::RsaModulus;

impl<A> Jwk<Private<A>>
where
    Private<A>: Holds<Held = RsaPrivateKey>,
{
    /// A new RSA key of `modulus` bits, `e` 65537, its `kid` its thumbprint. The size is chosen,
    /// so not through `generate`, which takes nothing.
    ///
    /// ```no_run
    /// use kauthnz_jose::jwa::Rs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// use kauthnz_jose::jwk::Private;
    ///
    /// use kauthnz_jose::jwk::RsaModulus;
    ///
    /// let signer = Jwk::<Private<Rs256>>::generate_rsa(RsaModulus::Bits3072)?;
    /// # Ok::<(), kauthnz_jose::jwk::GenerateErrors>(())
    /// ```
    pub fn generate_rsa(modulus: RsaModulus) -> Result<Self, GenerateErrors> {
        let key =
            PrivateKey::new(&mut SysRng, modulus.bits()).map_err(|_| GenerateErrors::RsaBackend)?;

        let held = RsaPrivateKey::generated(key)?;

        let kid = Kid::read(Thumbprint::of(&held).to_string())?;

        Ok(Self {
            kid: Some(kid),
            held,
        })
    }
}
