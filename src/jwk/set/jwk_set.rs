use crate::jwk::key::Jwk;

use crate::jwk::key::Holds;

use super::discarded_key::DiscardedKey;

/// The keys of a JWK Set, read and bound to no algorithm: the algorithm is chosen for one key,
/// when it is taken out by its `kid`. With the keys that were left out, and why.
///
/// Without `Debug`, as [`Jwk`].
pub struct JwkSet<M>
where
    M: Holds,
{
    pub(super) keys: Vec<Jwk<M>>,

    pub(super) discarded: Vec<DiscardedKey>,
}

impl<M> JwkSet<M>
where
    M: Holds,
{
    /// The keys that were not read, in the order of `keys`.
    pub fn discarded(&self) -> &[DiscardedKey] {
        &self.discarded
    }
}
