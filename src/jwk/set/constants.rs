/// The most keys a set may have, counted before any of them is read: each one is decoded and
/// judged when the set is loaded. A set with more is refused, not trimmed.
pub(super) const MAX_KEYS: usize = 32;

/// The longest JWK Set read. A public RSA-4096 JWK is under 1 KiB, its `n` 683 characters: 32 of
/// them are about 25 KiB, and the rest is room for `x5c`.
pub(super) const MAX_JWK_SET_LEN: usize = 128 * 1024;
