use crate::jwk::key::Jwk;

use crate::jwk::key::Holds;

use super::errors::JwkSetErrors;

/// With more than one key read, each has a `kid` and no two the same: a key is taken out by its
/// `kid` alone, never tried, so one `kid` names one key. OpenID Connect Core §10.1 asks a token
/// for a `kid` when the set has more than one key; RFC 7517 §4.5 lets two keys of different
/// `kty` share one, and this set does not, for the same reason.
///
/// `index` is each key's place in `keys`, kept from before the keys left out were removed.
pub(super) fn kids<M>(keys: &[(usize, Jwk<M>)]) -> Result<(), JwkSetErrors>
where
    M: Holds,
{
    if keys.len() < 2 {
        return Ok(());
    }

    for (position, (index, jwk)) in keys.iter().enumerate() {
        let Some(kid) = jwk.kid() else {
            return Err(JwkSetErrors::MissingKid { index: *index });
        };

        if keys
            .iter()
            .take(position)
            .any(|(_, earlier)| earlier.kid() == Some(kid))
        {
            return Err(JwkSetErrors::DuplicateKid { index: *index });
        }
    }

    Ok(())
}
