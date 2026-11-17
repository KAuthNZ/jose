use serde_json::Value;

use crate::json::JsonErrors;

use crate::jwk::raw::ScrubbedMembers;

use crate::json::parse_object_deep;

use super::constants::MAX_KEYS;

use super::errors::JwkSetErrors;

use super::constants::MAX_JWK_SET_LEN;

/// The entries of `keys`, each a JSON object, before any key is read. Each one is wiped on drop:
/// a public set may still carry a secret member, and is refused for it later, not freed as it
/// came. Members other than `keys` are ignored (RFC 7517 §5).
pub(in crate::jwk) fn entries(source: &[u8]) -> Result<Vec<ScrubbedMembers>, JwkSetErrors> {
    let mut set = ScrubbedMembers::new(parse_object_deep(source, MAX_JWK_SET_LEN).map_err(
        |error| match error {
            JsonErrors::TooLarge => JwkSetErrors::TooLarge,

            JsonErrors::Malformed => JwkSetErrors::NotJson,

            JsonErrors::NotAnObject => JwkSetErrors::NotAnObject,

            JsonErrors::DuplicateMembers => JwkSetErrors::DuplicateMembers,
        },
    )?);

    shape(set.get("keys"))?;

    let Some(Value::Array(keys)) = set.remove("keys") else {
        return Err(JwkSetErrors::MissingKeys);
    };

    let mut entries = Vec::with_capacity(keys.len());

    for (index, entry) in keys.into_iter().enumerate() {
        let Value::Object(members) = entry else {
            return Err(JwkSetErrors::NotAKey { index });
        };

        entries.push(ScrubbedMembers::new(members));
    }

    Ok(entries)
}

/// Judged in place, while the set is still wiped on drop: nothing is moved out of it until every
/// entry is known to be an object.
fn shape(keys: Option<&Value>) -> Result<(), JwkSetErrors> {
    let keys = match keys {
        Some(Value::Array(keys)) => keys,

        Some(_) => return Err(JwkSetErrors::KeysNotAnArray),

        None => return Err(JwkSetErrors::MissingKeys),
    };

    if keys.is_empty() {
        return Err(JwkSetErrors::Empty);
    }

    if keys.len() > MAX_KEYS {
        return Err(JwkSetErrors::TooManyKeys);
    }

    match keys.iter().position(|entry| !entry.is_object()) {
        Some(index) => Err(JwkSetErrors::NotAKey { index }),

        None => Ok(()),
    }
}
