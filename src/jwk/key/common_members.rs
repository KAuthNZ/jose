use crate::jwk::raw::RawJwk;

use crate::jwk::members::Kid;

use crate::jwk::raw::ScrubbedMembers;

use crate::jwk::raw::KeyMembers;

use crate::jwk::decoding::members;

use crate::jwk::members::KeyMetadata;

use crate::jwk::members::KeyMetadataMembers;

use super::errors::JwkErrors;

/// What every mode reads the same way, before its material is judged in its mode.
pub(super) struct CommonMembers {
    pub(super) kty: String,

    pub(super) kid: Option<Kid>,

    pub(super) metadata: KeyMetadata,

    pub(super) material: KeyMembers,
}

impl CommonMembers {
    /// From the bytes of one JWK, wrapped as soon as they are parsed.
    pub(super) fn read(source: &[u8]) -> Result<Self, JwkErrors> {
        Self::from_members(ScrubbedMembers::new(members(source)?))
    }

    /// From members already parsed, as each key of a JWK Set is. The cheap judgement first: the
    /// metadata are strings, the material is decoded later and checked on its curve or modulus.
    ///
    /// `x5u`, `x5c`, `x5t` and `x5t#S256` are dropped unread: nothing here checks a certificate
    /// against the key, so nothing here may let one vouch for it.
    pub(super) fn from_members(members: ScrubbedMembers) -> Result<Self, JwkErrors> {
        let RawJwk {
            kty,
            kid,
            alg,
            key_use,
            key_ops,
            material,
            ..
        } = RawJwk::try_from(members)?;

        let kid = kid.map(Kid::read).transpose()?;

        let metadata = KeyMetadata::read(KeyMetadataMembers {
            alg: alg.as_deref(),
            key_use: key_use.as_deref(),
            key_ops: key_ops.as_deref(),
        })?;

        Ok(Self {
            kty,
            kid,
            metadata,
            material,
        })
    }
}
