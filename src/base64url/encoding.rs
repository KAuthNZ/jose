use base64ct::Encoding;

use base64ct::Base64UrlUnpadded;

/// Exact length of the unpadded base64url encoding of `input_len` bytes. `const` so it can size
/// a stack buffer.
pub(crate) const fn encoded_len(input_len: usize) -> usize {
    input_len / 3 * 4 + (input_len % 3 * 4).div_ceil(3)
}

/// Constant time with respect to the contents. The `String` is not wiped when dropped: for a
/// secret, encode into a buffer you zeroize.
pub(crate) fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}
