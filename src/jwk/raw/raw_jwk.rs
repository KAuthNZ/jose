use super::take::take_string;

use super::take::take_strings;

use super::errors::RawJwkErrors;

use super::key_members::KeyMembers;

use super::scrubbed_members::ScrubbedMembers;

/// One JWK as it came: every registered member checked in its JSON type, and nothing more, `kty`
/// included. Members that are not registered are dropped (RFC 7517 §4).
///
/// Without `Debug` on purpose: `material` may hold secret members.
pub(in crate::jwk) struct RawJwk {
    pub(in crate::jwk) kty: String,

    pub(in crate::jwk) kid: Option<String>,

    pub(in crate::jwk) alg: Option<String>,

    pub(in crate::jwk) key_use: Option<String>,

    pub(in crate::jwk) key_ops: Option<Vec<String>>,

    pub(in crate::jwk) x5u: Option<String>,

    pub(in crate::jwk) x5c: Option<Vec<String>>,

    pub(in crate::jwk) x5t: Option<String>,

    pub(in crate::jwk) x5t_s256: Option<String>,

    pub(in crate::jwk) material: KeyMembers,
}

/// From members already wiped on drop: whoever parsed them wrapped them first, so nothing is
/// freed unwiped on the way here.
impl TryFrom<ScrubbedMembers> for RawJwk {
    type Error = RawJwkErrors;

    fn try_from(mut members: ScrubbedMembers) -> Result<Self, Self::Error> {
        let kty = take_string(&mut members, "kty")?.ok_or(RawJwkErrors::MissingKty)?;

        Ok(Self {
            kty,
            kid: take_string(&mut members, "kid")?,
            alg: take_string(&mut members, "alg")?,
            key_use: take_string(&mut members, "use")?,
            key_ops: take_strings(&mut members, "key_ops")?,
            x5u: take_string(&mut members, "x5u")?,
            x5c: take_strings(&mut members, "x5c")?,
            x5t: take_string(&mut members, "x5t")?,
            x5t_s256: take_string(&mut members, "x5t#S256")?,
            material: KeyMembers::take_from(&mut members)?,
        })
    }
}
