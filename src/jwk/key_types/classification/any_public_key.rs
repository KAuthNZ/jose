use crate::jwa::KeyType;

use crate::jwk::raw::KeyMembers;

use super::super::ec::EcPublicKey;

use super::super::okp::OkpPublicKey;

use super::super::rsa::RsaPublicKey;

use super::members::required;

use super::members::no_secret;

use super::key_shape::KeyShape;

use super::members::nothing_left;

use super::errors::ClassificationErrors;

use super::super::public_members::Publishes;

use super::super::public_members::PublicMembers;

/// A key read as public, of any family this library reads. With [`AnyPrivateKey`], the one
/// place that matches `kty` to a family: a new family is a variant here and nothing else changes.
///
/// [`AnyPrivateKey`]: super::AnyPrivateKey
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyPublicKey {
    Ec(EcPublicKey),

    Okp(OkpPublicKey),

    Rsa(RsaPublicKey),
}

impl AnyPublicKey {
    /// Structure before material: a secret, an unknown `kty`, a missing or foreign member each
    /// refuse the key before any of its values is decoded.
    pub(in crate::jwk) fn classify(
        kty: &str,
        mut material: KeyMembers,
    ) -> Result<Self, ClassificationErrors> {
        no_secret(&material)?;

        match KeyType::from_name(kty).ok_or(ClassificationErrors::UnknownKty)? {
            KeyType::Ec => {
                let crv = required(&mut material, "crv")?;

                let x = required(&mut material, "x")?;

                let y = required(&mut material, "y")?;

                nothing_left(&material)?;

                Ok(Self::Ec(EcPublicKey::read(&crv, &x, &y)?))
            }

            KeyType::Okp => {
                let crv = required(&mut material, "crv")?;

                let x = required(&mut material, "x")?;

                nothing_left(&material)?;

                Ok(Self::Okp(OkpPublicKey::read(&crv, &x)?))
            }

            KeyType::Rsa => {
                let n = required(&mut material, "n")?;

                let e = required(&mut material, "e")?;

                nothing_left(&material)?;

                Ok(Self::Rsa(RsaPublicKey::read(&n, &e)?))
            }

            KeyType::Oct => Err(ClassificationErrors::NoPublicSide),

            KeyType::Akp => Err(ClassificationErrors::UnsupportedKty),
        }
    }

    pub(crate) fn shape(&self) -> KeyShape {
        match self {
            Self::Ec(key) => KeyShape::Ec(key.curve()),

            Self::Okp(key) => KeyShape::Okp(key.curve()),

            Self::Rsa(_) => KeyShape::Rsa,
        }
    }
}

/// What an unbound public JWK writes: the members of whichever family it is.
impl Publishes for AnyPublicKey {
    fn public_members(&self) -> PublicMembers {
        match self {
            Self::Ec(key) => key.public_members(),

            Self::Okp(key) => key.public_members(),

            Self::Rsa(key) => key.public_members(),
        }
    }
}
