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

use crate::jwk::bind::AnyBoundPrivate;

use super::errors::GenerateErrors;

use super::rsa_modulus::RsaModulus;

impl Jwk<Private> {
    /// A new key for the algorithm the caller expects, chosen at run time from its configuration,
    /// as [`generate`](Jwk::generate) for a type. Not RSA, whose size is chosen too:
    /// [`generate_rsa_expected`](Jwk::generate_rsa_expected).
    ///
    /// ```
    /// use kauthnz_jose::jwk::Jwk;
    ///
    /// use kauthnz_jose::jwk::Private;
    ///
    /// use kauthnz_jose::jwa::SigningAlgorithm;
    ///
    /// let signer = Jwk::<Private>::generate_expected(SigningAlgorithm::Es256)?;
    /// # Ok::<(), kauthnz_jose::jwk::GenerateErrors>(())
    /// ```
    pub fn generate_expected(alg: SigningAlgorithm) -> Result<AnyBoundPrivate, GenerateErrors> {
        match alg {
            SigningAlgorithm::Ed25519 => {
                Jwk::<Private<Ed25519>>::generate().map(AnyBoundPrivate::Ed25519)
            }

            SigningAlgorithm::Es256 => {
                Jwk::<Private<Es256>>::generate().map(AnyBoundPrivate::Es256)
            }

            SigningAlgorithm::Es384 => {
                Jwk::<Private<Es384>>::generate().map(AnyBoundPrivate::Es384)
            }

            SigningAlgorithm::Es512 => {
                Jwk::<Private<Es512>>::generate().map(AnyBoundPrivate::Es512)
            }

            SigningAlgorithm::Rs256
            | SigningAlgorithm::Rs384
            | SigningAlgorithm::Rs512
            | SigningAlgorithm::Ps256
            | SigningAlgorithm::Ps384
            | SigningAlgorithm::Ps512 => Err(GenerateErrors::RsaSizeRequired),

            SigningAlgorithm::Hs256 | SigningAlgorithm::Hs384 | SigningAlgorithm::Hs512 => {
                Err(GenerateErrors::NotForThisMode)
            }

            SigningAlgorithm::Es256k
            | SigningAlgorithm::Ed448
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87 => Err(GenerateErrors::Unsupported),
        }
    }

    /// A new RSA key of `modulus` bits for the algorithm the caller expects, chosen at run time,
    /// as [`generate_rsa`](Jwk::generate_rsa) for a type. The algorithm names the hash and the
    /// padding, never the size: any RS or PS algorithm takes 2048 bits or more (RFC 7518 §3.3,
    /// §3.5).
    pub fn generate_rsa_expected(
        alg: SigningAlgorithm,
        modulus: RsaModulus,
    ) -> Result<AnyBoundPrivate, GenerateErrors> {
        match alg {
            SigningAlgorithm::Rs256 => {
                Jwk::<Private<Rs256>>::generate_rsa(modulus).map(AnyBoundPrivate::Rs256)
            }

            SigningAlgorithm::Rs384 => {
                Jwk::<Private<Rs384>>::generate_rsa(modulus).map(AnyBoundPrivate::Rs384)
            }

            SigningAlgorithm::Rs512 => {
                Jwk::<Private<Rs512>>::generate_rsa(modulus).map(AnyBoundPrivate::Rs512)
            }

            SigningAlgorithm::Ps256 => {
                Jwk::<Private<Ps256>>::generate_rsa(modulus).map(AnyBoundPrivate::Ps256)
            }

            SigningAlgorithm::Ps384 => {
                Jwk::<Private<Ps384>>::generate_rsa(modulus).map(AnyBoundPrivate::Ps384)
            }

            SigningAlgorithm::Ps512 => {
                Jwk::<Private<Ps512>>::generate_rsa(modulus).map(AnyBoundPrivate::Ps512)
            }

            SigningAlgorithm::Ed25519
            | SigningAlgorithm::Es256
            | SigningAlgorithm::Es384
            | SigningAlgorithm::Es512
            | SigningAlgorithm::Es256k
            | SigningAlgorithm::Ed448
            | SigningAlgorithm::MlDsa44
            | SigningAlgorithm::MlDsa65
            | SigningAlgorithm::MlDsa87
            | SigningAlgorithm::Hs256
            | SigningAlgorithm::Hs384
            | SigningAlgorithm::Hs512 => Err(GenerateErrors::NotRsa),
        }
    }
}
