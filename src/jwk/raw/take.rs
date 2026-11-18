use serde_json::Value;

use super::errors::RawJwkErrors;

use super::scrubbed_members::ScrubbedMembers;

/// The type is checked before the member is taken out: a value of the wrong type stays in
/// `members`, which wipes it on drop.
pub(super) fn take_string(
    members: &mut ScrubbedMembers,
    name: &'static str,
) -> Result<Option<String>, RawJwkErrors> {
    match members.get(name) {
        None => return Ok(None),

        Some(Value::String(_)) => {}

        Some(_) => return Err(RawJwkErrors::InvalidMember(name)),
    }

    match members.remove(name) {
        Some(Value::String(value)) => Ok(Some(value)),

        _ => Err(RawJwkErrors::InvalidMember(name)),
    }
}

/// An array of strings, as it came, checked as `take_string`: whether it may be empty or repeat
/// is not decided here.
pub(super) fn take_strings(
    members: &mut ScrubbedMembers,
    name: &'static str,
) -> Result<Option<Vec<String>>, RawJwkErrors> {
    match members.get(name) {
        None => return Ok(None),

        Some(Value::Array(items)) if items.iter().all(Value::is_string) => {}

        Some(_) => return Err(RawJwkErrors::InvalidMember(name)),
    }

    let Some(Value::Array(items)) = members.remove(name) else {
        return Err(RawJwkErrors::InvalidMember(name));
    };

    Ok(Some(
        items
            .into_iter()
            .filter_map(|item| match item {
                Value::String(text) => Some(text),

                _ => None,
            })
            .collect(),
    ))
}
