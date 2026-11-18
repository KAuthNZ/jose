use p256::NistP256;

use p384::NistP384;

use p521::NistP521;

use getrandom::SysRng;

use elliptic_curve::Generate;

use elliptic_curve::SecretKey;

use elliptic_curve::CurveArithmetic;

use crate::jwa::Es256;

use crate::jwa::Es384;

use crate::jwa::Es512;

use crate::jwk::mode::Private;

use crate::jwk::thumbprint::Thumbprint;

use crate::jwk::key_types::EcCurvePrivateKey;

use super::generates::Generates;

use super::errors::GenerateErrors;

impl Generates for Private<Es256> {
    fn material() -> Result<EcCurvePrivateKey<NistP256>, GenerateErrors> {
        on_curve::<NistP256>()
    }

    fn kid(held: &EcCurvePrivateKey<NistP256>) -> Result<String, GenerateErrors> {
        Ok(Thumbprint::of(held).to_string())
    }
}

impl Generates for Private<Es384> {
    fn material() -> Result<EcCurvePrivateKey<NistP384>, GenerateErrors> {
        on_curve::<NistP384>()
    }

    fn kid(held: &EcCurvePrivateKey<NistP384>) -> Result<String, GenerateErrors> {
        Ok(Thumbprint::of(held).to_string())
    }
}

impl Generates for Private<Es512> {
    fn material() -> Result<EcCurvePrivateKey<NistP521>, GenerateErrors> {
        on_curve::<NistP521>()
    }

    fn kid(held: &EcCurvePrivateKey<NistP521>) -> Result<String, GenerateErrors> {
        Ok(Thumbprint::of(held).to_string())
    }
}

/// A scalar the backend draws below the order of `C`, from the randomness of the system.
fn on_curve<C>() -> Result<EcCurvePrivateKey<C>, GenerateErrors>
where
    C: CurveArithmetic,
{
    let d = SecretKey::<C>::try_generate_from_rng(&mut SysRng).map_err(|_| GenerateErrors::Rng)?;

    Ok(EcCurvePrivateKey::from_secret(d))
}
