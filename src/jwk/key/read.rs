use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::fit::Candidates;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnySecretKey;

use crate::jwk::key_types::AnyPrivateKey;

use super::jwk::Jwk;

use super::errors::JwkErrors;

use super::common_members::CommonMembers;

use super::unbound_material::UnboundMaterial;

impl Jwk<Public> {
    /// A JWK with its public members only: one with a secret member is refused, not trimmed.
    pub fn read_public(source: &[u8]) -> Result<Self, JwkErrors> {
        let common = CommonMembers::read(source)?;

        let public_material = AnyPublicKey::classify(&common.kty, common.material)?;

        let candidates = Candidates::of_public(&public_material, &common.metadata)?;

        Ok(Self {
            kid: common.kid,
            held: UnboundMaterial {
                material: public_material,
                candidates,
            },
        })
    }
}

impl Jwk<Private> {
    /// A JWK with every secret member its family requires.
    pub fn read_private(source: &[u8]) -> Result<Self, JwkErrors> {
        let common = CommonMembers::read(source)?;

        let private_material = AnyPrivateKey::classify(&common.kty, common.material)?;

        let candidates = Candidates::of_private(&private_material, &common.metadata)?;

        Ok(Self {
            kid: common.kid,
            held: UnboundMaterial {
                material: private_material,
                candidates,
            },
        })
    }
}

impl Jwk<Secret> {
    /// A symmetric JWK: `oct`.
    pub fn read_secret(source: &[u8]) -> Result<Self, JwkErrors> {
        let common = CommonMembers::read(source)?;

        let secret_material = AnySecretKey::classify(&common.kty, common.material)?;

        let candidates = Candidates::of_secret(&secret_material, &common.metadata)?;

        Ok(Self {
            kid: common.kid,
            held: UnboundMaterial {
                material: secret_material,
                candidates,
            },
        })
    }
}
