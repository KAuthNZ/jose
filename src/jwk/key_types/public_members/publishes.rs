use super::ordered_members::PublicMembers;

/// What a key publishes in its JWK: `kty` and the public members its family requires, in the
/// order of RFC 7638. Only where it has a public side: a secret publishes nothing.
///
/// `pub` in a module that can't be named from outside the crate, as `Holds`.
pub trait Publishes {
    fn public_members(&self) -> PublicMembers;
}
