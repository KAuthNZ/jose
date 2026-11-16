use std::collections::BTreeMap;

use serde_json::Value;

use crate::jwa::KeyType;

/// The members a public key is made of and nothing else (RFC 7638 §3.2): `kty` and the ones of
/// its family, never `kid`, `alg` or `use`. Written from the key, not copied from what was read,
/// so one key has one writing.
///
/// A `BTreeMap`, because `&str` orders by bytes, which in UTF-8 is the order of the code points
/// RFC 7638 §3.3 sorts the names in. Not left to `serde_json`, whose `preserve_order` feature
/// another crate of the build could turn on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicMembers {
    members: BTreeMap<&'static str, String>,
}

impl PublicMembers {
    pub(in crate::jwk) fn new(kty: KeyType) -> Self {
        Self {
            members: BTreeMap::from([("kty", kty.name().to_owned())]),
        }
    }

    /// Only names written in this crate, one per member of the family.
    pub(in crate::jwk) fn with(mut self, name: &'static str, value: String) -> Self {
        self.members.insert(name, value);

        self
    }

    /// In the order of their names.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &str)> {
        self.members
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
    }

    /// The JSON RFC 7638 §3 hashes: the members in order, no whitespace, each name and value a
    /// JSON string. Written by hand so nothing in between can reorder or space it.
    pub(crate) fn to_json(&self) -> String {
        let mut json = String::from("{");

        for (position, (name, value)) in self.iter().enumerate() {
            if position > 0 {
                json.push(',');
            }

            json.push_str(&Value::from(name).to_string());

            json.push(':');

            json.push_str(&Value::from(value).to_string());
        }

        json.push('}');

        json
    }
}
