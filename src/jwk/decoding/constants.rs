/// The longest JSON one key is read from. An RSA-4096 private JWK is about 3.3 KiB; the rest is
/// room for `x5c`, whose certificates are parsed before anything else is read.
pub(super) const MAX_JWK_LEN: usize = 16 * 1024;
