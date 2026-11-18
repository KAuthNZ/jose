use crate::jwk::key::Holds;

/// A mode bound to an algorithm: what it takes from the material read unbound. Only the pairs
/// that exist implement it, so `bind` to any other does not compile.
///
/// `pub` in a module that can't be named from outside the crate, as `Holds`.
pub trait Bound: Holds {
    type From;

    /// `None` where the material is not of the algorithm: never, once `Candidates` took it.
    fn take(material: Self::From) -> Option<Self::Held>;
}
