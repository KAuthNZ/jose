use crate::jwa::KeyType;

use crate::jwk::raw::KeyMembers;

use super::super::ec::EcPrivateKey;

use super::super::okp::OkpPrivateKey;

#[cfg(feature = "rsa")]
use super::super::rsa::RsaPrivateKey;

#[cfg(feature = "rsa")]
use super::super::rsa::RsaPrivateKeyMembers;

use super::members::required;

use super::key_shape::KeyShape;

use super::members::nothing_left;

use super::errors::ClassificationErrors;

use super::any_public_key::AnyPublicKey;

/// A key read as private, of any family this library reads: every secret member its family
/// requires, checked to be the private key of its public members.
pub(crate) enum AnyPrivateKey {
    Ec(EcPrivateKey),

    Okp(OkpPrivateKey),

    #[cfg(feature = "rsa")]
    Rsa(RsaPrivateKey),
}

impl AnyPrivateKey {
    /// Structure before material, as in [`AnyPublicKey::classify`].
    pub(in crate::jwk) fn classify(
        kty: &str,
        mut material: KeyMembers,
    ) -> Result<Self, ClassificationErrors> {
        match KeyType::from_name(kty).ok_or(ClassificationErrors::UnknownKty)? {
            KeyType::Ec => {
                let crv = required(&mut material, "crv")?;

                let x = required(&mut material, "x")?;

                let y = required(&mut material, "y")?;

                let d = required(&mut material, "d")?;

                nothing_left(&material)?;

                Ok(Self::Ec(EcPrivateKey::read(&crv, &x, &y, &d)?))
            }

            KeyType::Okp => {
                let crv = required(&mut material, "crv")?;

                let x = required(&mut material, "x")?;

                let d = required(&mut material, "d")?;

                nothing_left(&material)?;

                Ok(Self::Okp(OkpPrivateKey::read(&crv, &x, &d)?))
            }

            #[cfg(feature = "rsa")]
            KeyType::Rsa => {
                let n = required(&mut material, "n")?;

                let e = required(&mut material, "e")?;

                let d = required(&mut material, "d")?;

                let p = required(&mut material, "p")?;

                let q = required(&mut material, "q")?;

                let dp = required(&mut material, "dp")?;

                let dq = required(&mut material, "dq")?;

                let qi = required(&mut material, "qi")?;

                nothing_left(&material)?;

                Ok(Self::Rsa(RsaPrivateKey::read(RsaPrivateKeyMembers {
                    n: &n,
                    e: &e,
                    d: &d,
                    p: &p,
                    q: &q,
                    dp: &dp,
                    dq: &dq,
                    qi: &qi,
                })?))
            }

            KeyType::Oct => Err(ClassificationErrors::SymmetricKty),

            #[cfg(not(feature = "rsa"))]
            KeyType::Rsa => Err(ClassificationErrors::UnsupportedKty),

            KeyType::Akp => Err(ClassificationErrors::UnsupportedKty),
        }
    }

    pub(crate) fn shape(&self) -> KeyShape {
        match self {
            Self::Ec(key) => KeyShape::Ec(key.curve()),

            Self::Okp(key) => KeyShape::Okp(key.curve()),

            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyShape::Rsa,
        }
    }

    /// The same key without its secret members, e.g. to publish it in a JWKS.
    pub(crate) fn public(&self) -> AnyPublicKey {
        match self {
            Self::Ec(key) => AnyPublicKey::Ec(key.public()),

            Self::Okp(key) => AnyPublicKey::Okp(key.public()),

            #[cfg(feature = "rsa")]
            Self::Rsa(key) => AnyPublicKey::Rsa(key.public()),
        }
    }
}
