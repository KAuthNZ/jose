use super::super::key_ops::KeyOp;

pub(super) const SIGNATURE_OPS: [KeyOp; 2] = [KeyOp::Sign, KeyOp::Verify];

pub(super) const KEY_WRAPPING_OPS: [KeyOp; 2] = [KeyOp::WrapKey, KeyOp::UnwrapKey];

/// OAEP encrypts a key and content alike: one algorithm, as WebCrypto exports it.
pub(super) const RSA_OAEP_OPS: [KeyOp; 4] = [
    KeyOp::Encrypt,
    KeyOp::Decrypt,
    KeyOp::WrapKey,
    KeyOp::UnwrapKey,
];

pub(super) const DIRECT_OPS: [KeyOp; 2] = [KeyOp::Encrypt, KeyOp::Decrypt];

pub(super) const DERIVATION_OPS: [KeyOp; 2] = [KeyOp::DeriveKey, KeyOp::DeriveBits];

pub(super) const PUBLIC_SIGNATURE_OPS: [KeyOp; 1] = [KeyOp::Verify];

pub(super) const PUBLIC_RSA_OAEP_OPS: [KeyOp; 2] = [KeyOp::Encrypt, KeyOp::WrapKey];

/// The public key of a key agreement does nothing of its own: it is an input to the derivation
/// of the other side (WebCrypto §24.4.1 gives it no usage).
pub(super) const PUBLIC_DERIVATION_OPS: [KeyOp; 0] = [];
