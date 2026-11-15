use base64ct::Encoding;

use base64ct::Base64UrlUnpadded;

use super::decoding_errors::Base64DecodingErrors;

/// Exact length of the decoding of `input_len` unpadded base64url chars. `1 (mod 4)` can't come
/// out of any encoder, so it is refused.
pub(crate) const fn decoded_len(input_len: usize) -> Result<usize, Base64DecodingErrors> {
    match input_len % 4 {
        1 => Err(Base64DecodingErrors::InvalidLength),

        remainder => Ok(input_len / 4 * 3 + remainder.saturating_sub(1)),
    }
}

/// For a secret (`d`, `k`, ...) use [`decode_into`] with a buffer you zeroize: on error this
/// `Vec` may hold part of the decoding and is freed without being wiped.
pub(crate) fn decode(b64_str: &str) -> Result<Vec<u8>, Base64DecodingErrors> {
    let mut out = vec![0u8; decoded_len(b64_str.len())?];

    decode_into(b64_str, &mut out)?;

    Ok(out)
}

/// Constant time with respect to the contents: it only branches on the length and on the error.
/// On error `out` may hold part of the decoding.
pub(crate) fn decode_into<'o>(
    b64_str: &str,
    out: &'o mut [u8],
) -> Result<&'o [u8], Base64DecodingErrors> {
    let src = b64_str.as_bytes();

    if src.last() == Some(&b'=') {
        return Err(Base64DecodingErrors::DisallowedPadding);
    }

    let len = decoded_len(src.len())?;

    let out = out
        .get_mut(..len)
        .ok_or(Base64DecodingErrors::InvalidOutputLength)?;

    Base64UrlUnpadded::decode(src, out).map_err(|err| match err {
        base64ct::Error::InvalidLength => Base64DecodingErrors::InvalidOutputLength,

        // base64ct reports a byte outside the alphabet and non-zero unused bits the same way.
        _ => classify_invalid_encoding(src),
    })
}

/// Tells `NonCanonical` from `InvalidCharacter`, reading only the last byte.
fn classify_invalid_encoding(src: &[u8]) -> Base64DecodingErrors {
    let unused_bits: i16 = match src.len() % 4 {
        2 => 0b1111,

        3 => 0b0011,

        _ => return Base64DecodingErrors::InvalidCharacter,
    };

    let Some(&last) = src.last() else {
        return Base64DecodingErrors::InvalidCharacter;
    };

    let sextet = decode_sextet(last);

    // `&` and not `&&`: no early exit on whether the character is valid.
    if (sextet >= 0) & ((sextet & unused_bits) != 0) {
        Base64DecodingErrors::NonCanonical
    } else {
        Base64DecodingErrors::InvalidCharacter
    }
}

/// Value (0..=63) of a base64url character, or -1, without branches or tables: `(lo - c) &
/// (c - hi)` is negative only inside the range, and `>> 8` turns that sign into a mask. Same
/// trick as base64ct.
fn decode_sextet(c: u8) -> i16 {
    let c = i16::from(c);

    let mut v: i16 = -1;

    v += (((0x40 - c) & (c - 0x5b)) >> 8) & (c - 64); // 'A'..='Z' -> 0..=25
    v += (((0x60 - c) & (c - 0x7b)) >> 8) & (c - 70); // 'a'..='z' -> 26..=51
    v += (((0x2f - c) & (c - 0x3a)) >> 8) & (c + 5); // '0'..='9' -> 52..=61
    v += (((0x2c - c) & (c - 0x2e)) >> 8) & 63; // '-' -> 62
    v += (((0x5e - c) & (c - 0x60)) >> 8) & 64; // '_' -> 63

    v
}
