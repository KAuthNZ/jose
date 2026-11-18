use crate::jwa::Hs256;

use crate::jwa::Hs384;

use crate::jwa::Hs512;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Secret;

use crate::jwa::SigningAlgorithm;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnySecretKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

use super::any_bound_secret::AnyBoundSecret;

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

    /// The key for the algorithm the caller expects, chosen at run time: from its configuration,
    /// or from an allowlist it checked, as for the `alg` of a DPoP proof. Never one a token picks
    /// for a key the caller trusts (RFC 8725 §3.1). The one place the value becomes a type; once
    /// bound, it is never given again. A secret only takes a symmetric one.
    pub fn bind_expected(self, alg: SigningAlgorithm) -> Result<AnyBoundSecret, BindErrors> {
        match alg {
            SigningAlgorithm::Hs256 => self.bind::<Hs256>().map(AnyBoundSecret::Hs256),

            SigningAlgorithm::Hs384 => self.bind::<Hs384>().map(AnyBoundSecret::Hs384),

            SigningAlgorithm::Hs512 => self.bind::<Hs512>().map(AnyBoundSecret::Hs512),

            SigningAlgorithm::Ed25519
            | SigningAlgorithm::Es256
            | SigningAlgorithm::Es384
            | SigningAlgorithm::Es512
            | SigningAlgorithm::Rs256
            | SigningAlgorithm::Rs384
            | SigningAlgorithm::Rs512
            | SigningAlgorithm::Ps256
            | SigningAlgorithm::Ps384
            | SigningAlgorithm::Ps512 => Err(BindErrors::NotACandidate),

            SigningAlgorithm::Es256k
            | SigningAlgorithm::Ed448
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87 => Err(BindErrors::Unsupported),
        }
    }
}
