use super::errors::RsaErrors;

use super::constants::PUBLIC_EXPONENT;

use super::constants::MAX_MODULUS_BITS;

use super::constants::MIN_MODULUS_BITS;

/// A Base64urlUInt (RFC 7518 §2) that is not zero, since no member of an RSA key is, and with no
/// leading zero byte, so that one number has one encoding.
pub(super) fn unsigned(name: &'static str, bytes: &[u8]) -> Result<(), RsaErrors> {
    match bytes.first() {
        Some(0) | None => Err(RsaErrors::InvalidInteger(name)),

        Some(_) => Ok(()),
    }
}

/// `n` from 2048 to 4096 bits and odd, as every RSA modulus is.
pub(super) fn modulus(n: &[u8]) -> Result<(), RsaErrors> {
    unsigned("n", n)?;

    // Refused before counting, whatever the length.
    if n.len() > MAX_MODULUS_BITS / 8 + 1 {
        return Err(RsaErrors::TooLong);
    }

    let (Some((first, rest)), Some(last)) = (n.split_first(), n.last()) else {
        return Err(RsaErrors::InvalidInteger("n"));
    };

    // Checked: with a 32-bit usize the count could wrap into the range.
    let bits = rest
        .len()
        .checked_mul(8)
        .and_then(|bits| bits.checked_add(8 - first.leading_zeros() as usize))
        .ok_or(RsaErrors::TooLong)?;

    if bits < MIN_MODULUS_BITS {
        return Err(RsaErrors::TooShort);
    }

    if bits > MAX_MODULUS_BITS {
        return Err(RsaErrors::TooLong);
    }

    if last % 2 == 0 {
        return Err(RsaErrors::EvenModulus);
    }

    Ok(())
}

/// `e` is 65537.
pub(super) fn public_exponent(e: &[u8]) -> Result<(), RsaErrors> {
    unsigned("e", e)?;

    if e == PUBLIC_EXPONENT {
        Ok(())
    } else {
        Err(RsaErrors::UnsupportedExponent)
    }
}
