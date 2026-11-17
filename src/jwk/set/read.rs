use crate::jwk::key::Jwk;

use crate::jwk::mode::Public;

use super::kids::kids;

use super::jwk_set::JwkSet;

use super::entries::entries;

use super::errors::JwkSetErrors;

use super::discarded_key::DiscardedKey;

use super::secret_members::no_secret_members;

impl JwkSet<Public> {
    /// A published JWK Set, as from a `jwks_uri`: its shape, then no secret in any entry, then
    /// each key, then their `kid`s. A key that can't be read is left out with its reason; the set
    /// is refused if none is left, or if what is left can't be told apart by `kid`.
    pub fn read_public(source: &[u8]) -> Result<Self, JwkSetErrors> {
        let entries = entries(source)?;

        no_secret_members(&entries)?;

        let mut keys = Vec::with_capacity(entries.len());

        let mut discarded = Vec::with_capacity(entries.len());

        for (index, entry) in entries.into_iter().enumerate() {
            match Jwk::<Public>::from_members(entry) {
                Ok(jwk) => keys.push((index, jwk)),

                Err(error) => discarded.push(DiscardedKey::new(index, error)),
            }
        }

        if keys.is_empty() {
            return Err(match discarded.first() {
                Some(&first) => JwkSetErrors::NoUsableKey(first),

                None => JwkSetErrors::Empty,
            });
        }

        kids(&keys)?;

        Ok(Self {
            keys: keys.into_iter().map(|(_, jwk)| jwk).collect(),
            discarded,
        })
    }
}
