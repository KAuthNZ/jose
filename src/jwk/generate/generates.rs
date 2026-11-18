use crate::jwk::key::Holds;

use super::errors::GenerateErrors;

/// A mode bound to an algorithm whose key is made of randomness alone: how its material is
/// made, and the `kid` it is given. Not RSA, whose size is chosen.
///
/// `pub` in a module that can't be named from outside the crate, as `Holds`.
pub trait Generates: Holds {
    fn material() -> Result<Self::Held, GenerateErrors>;

    /// Its thumbprint where it has a public side, random where it doesn't.
    fn kid(held: &Self::Held) -> Result<String, GenerateErrors>;
}
