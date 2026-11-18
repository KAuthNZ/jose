/// The smallest modulus, in bits (RFC 7518 §3.3, §3.5).
pub(super) const MIN_MODULUS_BITS: usize = 2048;

/// The largest modulus, in bits: above it, verifying is a denial of service (CVE-2023-29409).
pub(super) const MAX_MODULUS_BITS: usize = 4096;

/// The only public exponent taken, 65537 (`AQAB`): no `e = 3`, the exponent of the forgeries
/// of Bleichenbacher 2006 against verifiers that parse the padding.
pub(super) const PUBLIC_EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];
