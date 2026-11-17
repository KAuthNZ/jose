use std::fmt;

use sha2::Digest;

use sha2::Sha256;

use crate::base64url;

use crate::jwk::key_types::Publishes;

/// The SHA-256 JWK Thumbprint of a key (RFC 7638): the hash of its required public members, in
/// lexicographic order, without whitespace. Written as base64url, as a `kid` built from it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thumbprint([u8; 32]);

impl Thumbprint {
    /// The thumbprint of `key`: of what it publishes, nothing else.
    pub(in crate::jwk) fn of<K>(key: &K) -> Self
    where
        K: Publishes,
    {
        Self(Sha256::digest(key.public_members().thumbprint_json().as_bytes()).into())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64url::encode(&self.0))
    }
}
