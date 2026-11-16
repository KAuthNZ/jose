use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwa::Rs256;

use crate::jwa::Rs384;

use crate::jwa::Rs512;

use crate::jwa::Ps256;

use crate::jwa::Ps384;

use crate::jwa::Ps512;

use crate::jwa::Ed25519;

use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use crate::jwa::SigningAlgorithm;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnyPublicKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

use super::any_bound_public::AnyBoundPublic;

impl Jwk<Public> {
    /// The key for `A`, if `A` is one of its candidates. Consumes it: whoever keeps it clones it.
    ///
    /// ```
    /// use kauthnz_jose::jwa::Ed25519;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519", "kid": "2026-11",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    ///
    /// let key = jwk.bind::<Ed25519>()?;
    ///
    /// assert_eq!(key.kid(), Some("2026-11"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// Only to an algorithm a public key of some family can have: never a symmetric one.
    ///
    /// ```compile_fail,E0277
    /// use kauthnz_jose::jwa::Hs256;
    ///
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// // RFC 8037 A.2.
    /// let jwk = Jwk::read_public(br#"{"kty": "OKP", "crv": "Ed25519",
    ///     "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#)?;
    ///
    /// let key = jwk.bind::<Hs256>()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn bind<A>(self) -> Result<Jwk<Public<A>>, BindErrors>
    where
        A: TypedSigningAlgorithm,
        Public<A>: Bound<From = AnyPublicKey>,
    {
        let UnboundMaterial {
            material,
            candidates,
        } = self.held;

        admits::<A>(&candidates)?;

        let held = Public::<A>::take(material).ok_or(BindErrors::MaterialAndCandidates)?;

        Ok(Jwk {
            kid: self.kid,
            held,
        })
    }

    /// The key for the algorithm the caller expects, chosen at run time: from its configuration,
    /// or from an allowlist it checked, as for the `alg` of a DPoP proof. Never one a token picks
    /// for a key the caller trusts (RFC 8725 §3.1). The one place the value becomes a type; once
    /// bound, it is never given again. A public key never takes a symmetric one.
    pub fn bind_expected(self, alg: SigningAlgorithm) -> Result<AnyBoundPublic, BindErrors> {
        match alg {
            SigningAlgorithm::Es256 => self.bind::<Es256>().map(AnyBoundPublic::Es256),

            SigningAlgorithm::Es384 => self.bind::<Es384>().map(AnyBoundPublic::Es384),

            SigningAlgorithm::Es512 => self.bind::<Es512>().map(AnyBoundPublic::Es512),

            SigningAlgorithm::Rs256 => self.bind::<Rs256>().map(AnyBoundPublic::Rs256),

            SigningAlgorithm::Rs384 => self.bind::<Rs384>().map(AnyBoundPublic::Rs384),

            SigningAlgorithm::Rs512 => self.bind::<Rs512>().map(AnyBoundPublic::Rs512),

            SigningAlgorithm::Ps256 => self.bind::<Ps256>().map(AnyBoundPublic::Ps256),

            SigningAlgorithm::Ps384 => self.bind::<Ps384>().map(AnyBoundPublic::Ps384),

            SigningAlgorithm::Ps512 => self.bind::<Ps512>().map(AnyBoundPublic::Ps512),

            SigningAlgorithm::Ed25519 => self.bind::<Ed25519>().map(AnyBoundPublic::Ed25519),

            SigningAlgorithm::Hs256 | SigningAlgorithm::Hs384 | SigningAlgorithm::Hs512 => {
                Err(BindErrors::NotACandidate)
            }

            SigningAlgorithm::Es256k
            | SigningAlgorithm::Ed448
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87 => Err(BindErrors::Unsupported),
        }
    }
}
