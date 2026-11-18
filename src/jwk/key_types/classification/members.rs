use zeroize::Zeroizing;

use crate::jwk::raw::KeyMembers;

use crate::jwk::constants::SECRET_MEMBERS;

use super::errors::ClassificationErrors;

pub(super) fn required(
    material: &mut KeyMembers,
    name: &'static str,
) -> Result<Zeroizing<String>, ClassificationErrors> {
    material
        .take(name)
        .ok_or(ClassificationErrors::MissingMember(name))
}

/// By name, before `kty` is read: a secret is refused in a public key of any type, one this
/// library reads or not.
pub(super) fn no_secret(material: &KeyMembers) -> Result<(), ClassificationErrors> {
    match material.names().find(|name| SECRET_MEMBERS.contains(name)) {
        Some(name) => Err(ClassificationErrors::SecretMember(name)),

        None => Ok(()),
    }
}

/// Run after the family took its members: whatever is left belongs to another one.
pub(super) fn nothing_left(material: &KeyMembers) -> Result<(), ClassificationErrors> {
    match material.names().next() {
        Some(name) => Err(ClassificationErrors::ForeignMember(name)),

        None => Ok(()),
    }
}
