use crate::jwa::Algorithm;

use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::members::KeyOp;

use crate::jwk::members::KeyAlg;

use crate::jwk::members::KeyMetadata;

use crate::jwk::key_types::KeyShape;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnySecretKey;

use crate::jwk::key_types::AnyPrivateKey;

use super::errors::FitErrors;

use super::mode_operations::ModeOperations;

/// The algorithms one key may be used with, after its metadata: never empty. `alg`, `use` and
/// `key_ops` only narrow what the key itself allows, taken from the JWA registry, so a new
/// algorithm needs no rule here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Candidates(Vec<KeyAlg>);

impl Candidates {
    pub(in crate::jwk) fn of_public(
        key: &AnyPublicKey,
        metadata: &KeyMetadata,
    ) -> Result<Self, FitErrors> {
        Self::of::<Public>(key.shape(), metadata)
    }

    pub(in crate::jwk) fn of_private(
        key: &AnyPrivateKey,
        metadata: &KeyMetadata,
    ) -> Result<Self, FitErrors> {
        Self::of::<Private>(key.shape(), metadata)
    }

    pub(in crate::jwk) fn of_secret(
        key: &AnySecretKey,
        metadata: &KeyMetadata,
    ) -> Result<Self, FitErrors> {
        Self::of::<Secret>(key.shape(), metadata)
    }

    /// What the key allows first: every algorithm that takes its `kty` and curve, that has a
    /// place in its mode and, for a secret, that its size reaches. Then `alg`, `use` and
    /// `key_ops` narrow it, each with its own error.
    pub(super) fn of<M>(shape: KeyShape, metadata: &KeyMetadata) -> Result<Self, FitErrors>
    where
        M: ModeOperations,
    {
        let (kty, crv) = (shape.kty(), shape.crv());

        let mut algs: Vec<KeyAlg> = Algorithm::all()
            .filter(|alg| alg.accepts(kty, crv))
            .map(KeyAlg::from)
            .filter(|alg| M::operations(*alg).is_some())
            .filter(|alg| {
                shape
                    .secret_len()
                    .is_none_or(|len| Self::secret_fits(*alg, len))
            })
            .collect();

        if algs.is_empty() {
            return Err(FitErrors::NoAlgorithm);
        }

        if let Some(alg) = metadata.alg() {
            if !algs.contains(&alg) {
                return Err(FitErrors::AlgAndKey);
            }

            algs.retain(|candidate| *candidate == alg);
        }

        if let Some(key_use) = metadata.key_use() {
            algs.retain(|candidate| candidate.key_use() == key_use);

            if algs.is_empty() {
                return Err(FitErrors::UseAndKey);
            }
        }

        if let Some(key_ops) = metadata.key_ops() {
            algs.retain(|candidate| {
                M::operations(*candidate).is_some_and(|done| Self::declares(key_ops.ops(), done))
            });

            if algs.is_empty() {
                return Err(FitErrors::KeyOpsAndKey);
            }
        }

        Ok(Self(algs))
    }

    /// Whether a symmetric key of `len` bytes is long enough for `alg` (RFC 7518 §3.2).
    fn secret_fits(alg: KeyAlg, len: usize) -> bool {
        match alg.algorithm() {
            Algorithm::Signing(alg) => alg.min_secret_len().is_some_and(|min| len >= min),

            // No JWE yet: the sizes A*KW, A*GCMKW, dir and PBES2 take are written with it.
            Algorithm::KeyManagement(_) => false,
        }
    }

    /// Nothing the key doesn't do, and nothing at all only where it does nothing of its own: an
    /// ES256 public key with an empty `key_ops` says it verifies nothing, an ECDH-ES one says
    /// what it is.
    fn declares(key_ops: &[KeyOp], done: &[KeyOp]) -> bool {
        key_ops.iter().all(|op| done.contains(op)) && key_ops.is_empty() == done.is_empty()
    }

    pub(crate) fn contains(&self, alg: KeyAlg) -> bool {
        self.0.contains(&alg)
    }

    #[cfg(test)]
    pub(super) fn algs(&self) -> &[KeyAlg] {
        &self.0
    }
}
