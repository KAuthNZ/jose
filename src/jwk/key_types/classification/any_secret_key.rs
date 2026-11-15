use crate::jwa::KeyType;

use crate::jwk::raw::KeyMembers;

use super::super::oct::OctSecretKey;

use super::members::required;

use super::key_shape::KeyShape;

use super::members::nothing_left;

use super::errors::ClassificationErrors;

/// A key read as secret: a symmetric one, the whole key in one member. Only `oct` in JOSE.
pub(crate) enum AnySecretKey {
    Oct(OctSecretKey),
}

impl AnySecretKey {
    /// Structure before material, as in [`AnyPublicKey::classify`](super::AnyPublicKey).
    pub(in crate::jwk) fn classify(
        kty: &str,
        mut material: KeyMembers,
    ) -> Result<Self, ClassificationErrors> {
        match KeyType::from_name(kty).ok_or(ClassificationErrors::UnknownKty)? {
            KeyType::Oct => {
                let k = required(&mut material, "k")?;

                nothing_left(&material)?;

                Ok(Self::Oct(OctSecretKey::read(&k)?))
            }

            KeyType::Akp => Err(ClassificationErrors::UnsupportedKty),

            KeyType::Ec | KeyType::Okp | KeyType::Rsa => Err(ClassificationErrors::AsymmetricKty),
        }
    }

    pub(crate) fn shape(&self) -> KeyShape {
        match self {
            Self::Oct(key) => KeyShape::Oct { len: key.len() },
        }
    }
}
