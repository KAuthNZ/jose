use super::key_op::KeyOp;

use super::errors::KeyOpsErrors;

/// `key_ops` (RFC 7517 §4.3): registered operations, none twice. Nothing more: which of them
/// may come together depends on `alg`, and is judged by `KeyMetadata`.
///
/// Empty is a key that does no operation of its own, not an absent `key_ops`: WebCrypto exports
/// every ECDH and X25519 public key so (WebCrypto §24.4.1 step 11, §24.4.4 step 4), and that is
/// what such a key is, an input to the derivation of the other side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyOps(Vec<KeyOp>);

impl KeyOps {
    pub(in crate::jwk) fn read(names: &[String]) -> Result<Self, KeyOpsErrors> {
        let mut ops: Vec<KeyOp> = Vec::with_capacity(KeyOp::ALL.len());

        for name in names {
            let op = KeyOp::from_name(name).ok_or(KeyOpsErrors::Unregistered)?;

            if ops.contains(&op) {
                return Err(KeyOpsErrors::Duplicate(op));
            }

            ops.push(op);
        }

        Ok(Self(ops))
    }

    pub(crate) fn ops(&self) -> &[KeyOp] {
        &self.0
    }
}
