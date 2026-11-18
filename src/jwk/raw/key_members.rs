use std::collections::BTreeMap;

use zeroize::Zeroizing;

use crate::jwk::constants::KEY_MEMBERS;

use super::take::take_string;

use super::errors::RawJwkErrors;

use super::scrubbed_members::ScrubbedMembers;

/// The registered key members of one JWK, each a string as it came, of any `kty`: which ones
/// belong to the key, and what they say, is decided when the key is classified. Every value is
/// wiped on drop, the public ones too, since this doesn't know which are secret.
pub(in crate::jwk) struct KeyMembers(BTreeMap<&'static str, Zeroizing<String>>);

impl KeyMembers {
    pub(super) fn take_from(members: &mut ScrubbedMembers) -> Result<Self, RawJwkErrors> {
        // Keys of more than two primes are not read (RFC 7518 §6.3.2.7).
        if members.contains_key("oth") {
            return Err(RawJwkErrors::UnsupportedMember("oth"));
        }

        let mut taken = BTreeMap::new();

        for name in KEY_MEMBERS {
            if let Some(value) = take_string(members, name)? {
                taken.insert(name, Zeroizing::new(value));
            }
        }

        Ok(Self(taken))
    }

    pub(in crate::jwk) fn take(&mut self, name: &str) -> Option<Zeroizing<String>> {
        self.0.remove(name)
    }

    /// The names still here.
    pub(in crate::jwk) fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.keys().copied()
    }
}
