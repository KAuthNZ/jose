use super::super::alg::KeyAlg;

use super::super::key_ops::KeyOp;

use super::super::key_ops::KeyOps;

use super::super::key_use::KeyUse;

use super::errors::KeyMetadataErrors;

use super::coherence_errors::CoherenceErrors;

use super::key_metadata_members::KeyMetadataMembers;

/// `use`, `key_ops` and `alg` of one JWK, each read by its own rules and none contradicting
/// another: every one that is present says the same use. Whether they fit the key itself is
/// judged with the key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyMetadata {
    alg: Option<KeyAlg>,

    key_use: Option<KeyUse>,

    key_ops: Option<KeyOps>,
}

impl KeyMetadata {
    /// The members as they came in the JWK.
    pub(in crate::jwk) fn read(members: KeyMetadataMembers<'_>) -> Result<Self, KeyMetadataErrors> {
        let alg = members.alg.map(KeyAlg::read).transpose()?;

        let key_use = members.key_use.map(KeyUse::read).transpose()?;

        let key_ops = members.key_ops.map(KeyOps::read).transpose()?;

        if let (Some(declared), Some(ops)) = (key_use, &key_ops)
            && ops.ops().iter().any(|op| op.key_use() != declared)
        {
            return Err(CoherenceErrors::UseAndKeyOps.into());
        }

        if let (Some(declared), Some(alg)) = (key_use, alg)
            && declared != alg.key_use()
        {
            return Err(CoherenceErrors::UseAndAlg.into());
        }

        if let Some(ops) = &key_ops {
            match alg {
                Some(alg) => {
                    if !ops.ops().iter().all(|op| alg.operations().contains(op)) {
                        return Err(CoherenceErrors::KeyOpsAndAlg.into());
                    }
                }

                None => {
                    if !Self::one_pair(ops) {
                        return Err(CoherenceErrors::UnrelatedOps.into());
                    }
                }
            }
        }

        Ok(Self {
            alg,
            key_use,
            key_ops,
        })
    }

    /// Without an `alg` to tell whether they are one algorithm: none, one operation, or one of
    /// the pairs `sign`/`verify`, `encrypt`/`decrypt`, `wrapKey`/`unwrapKey` (RFC 7517 §4.3), or
    /// `deriveKey`/`deriveBits`. Any other combination is refused, though the RFC only says it
    /// SHOULD NOT be used.
    fn one_pair(ops: &KeyOps) -> bool {
        match ops.ops() {
            [] | [_] => true,

            // Not in RFC 7517 §4.3, but one derivation: WebCrypto exports ECDH keys with both
            // and never with an `alg` (WebCrypto §24.4.4).
            [KeyOp::DeriveKey, KeyOp::DeriveBits] | [KeyOp::DeriveBits, KeyOp::DeriveKey] => true,

            [one, other] => one.counterpart() == Some(*other),

            _ => false,
        }
    }

    pub(crate) fn key_use(&self) -> Option<KeyUse> {
        self.key_use
    }

    pub(crate) fn key_ops(&self) -> Option<&KeyOps> {
        self.key_ops.as_ref()
    }

    pub(crate) fn alg(&self) -> Option<KeyAlg> {
        self.alg
    }
}
