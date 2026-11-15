/// Every member of an RSA private key (RFC 7518 §6.3.2), `n` and `e` included, each as it came.
/// Named fields, so that no two of them can be swapped by position.
pub(in crate::jwk) struct RsaPrivateKeyMembers<'a> {
    pub(in crate::jwk) n: &'a str,

    pub(in crate::jwk) e: &'a str,

    pub(in crate::jwk) d: &'a str,

    pub(in crate::jwk) p: &'a str,

    pub(in crate::jwk) q: &'a str,

    pub(in crate::jwk) dp: &'a str,

    pub(in crate::jwk) dq: &'a str,

    pub(in crate::jwk) qi: &'a str,
}
