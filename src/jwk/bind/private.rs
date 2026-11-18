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

use crate::jwk::mode::Private;

use crate::jwa::SigningAlgorithm;

use crate::jwk::key::UnboundMaterial;

use crate::jwa::TypedSigningAlgorithm;

use crate::jwk::key_types::AnyPrivateKey;

use super::bound::Bound;

use super::admits::admits;

use super::errors::BindErrors;

use super::any_bound_private::AnyBoundPrivate;

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

    /// The key for the algorithm the caller expects, chosen at run time: from its configuration,
    /// or from an allowlist it checked, as for the `alg` of a DPoP proof. Never one a token picks
    /// for a key the caller trusts (RFC 8725 §3.1). The one place the value becomes a type; once
    /// bound, it is never given again. A private key never takes a symmetric one.
    pub fn bind_expected(self, alg: SigningAlgorithm) -> Result<AnyBoundPrivate, BindErrors> {
        match alg {
            SigningAlgorithm::Ed25519 => self.bind::<Ed25519>().map(AnyBoundPrivate::Ed25519),

            SigningAlgorithm::Es256 => self.bind::<Es256>().map(AnyBoundPrivate::Es256),

            SigningAlgorithm::Es384 => self.bind::<Es384>().map(AnyBoundPrivate::Es384),

            SigningAlgorithm::Es512 => self.bind::<Es512>().map(AnyBoundPrivate::Es512),

            SigningAlgorithm::Rs256 => self.bind::<Rs256>().map(AnyBoundPrivate::Rs256),

            SigningAlgorithm::Rs384 => self.bind::<Rs384>().map(AnyBoundPrivate::Rs384),

            SigningAlgorithm::Rs512 => self.bind::<Rs512>().map(AnyBoundPrivate::Rs512),

            SigningAlgorithm::Ps256 => self.bind::<Ps256>().map(AnyBoundPrivate::Ps256),

            SigningAlgorithm::Ps384 => self.bind::<Ps384>().map(AnyBoundPrivate::Ps384),

            SigningAlgorithm::Ps512 => self.bind::<Ps512>().map(AnyBoundPrivate::Ps512),

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
