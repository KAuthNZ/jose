use crate::jwk::raw::ScrubbedMembers;

use crate::jwk::constants::SECRET_MEMBERS;

use super::errors::JwkSetErrors;

/// No entry has a member of the "Private" class, of any `kty`: a published set "MUST NOT contain
/// private or symmetric key values" (OpenID Connect Discovery §3).
///
/// Before any key is read and for the whole set: reading the key alone would refuse it and leave
/// it out, and the set would load as if a private key had not just been published.
pub(in crate::jwk) fn no_secret_members(entries: &[ScrubbedMembers]) -> Result<(), JwkSetErrors> {
    for (index, entry) in entries.iter().enumerate() {
        if let Some(&name) = SECRET_MEMBERS
            .iter()
            .find(|name| entry.contains_key(**name))
        {
            return Err(JwkSetErrors::SecretMember { index, name });
        }
    }

    Ok(())
}
