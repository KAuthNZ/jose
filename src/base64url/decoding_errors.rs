#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Base64DecodingErrors {
    /// `1 (mod 4)`, which no encoder produces.
    InvalidLength,

    /// A byte outside `A-Z a-z 0-9 - _`.
    InvalidCharacter,

    /// `out` is shorter than `decoded_len(input.len())`.
    InvalidOutputLength,

    /// A trailing `=`: JOSE omits the padding (RFC 7515 §2).
    DisallowedPadding,

    /// Non-zero unused bits in the last character, e.g. `"Zh"` for `b"f"` (RFC 4648 §3.5). One
    /// encoding per byte string, so a signature can't be rewritten into a second token that
    /// still verifies.
    NonCanonical,
}
