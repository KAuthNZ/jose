use crate::jwk::mode::Public;

use crate::jwk::mode::Secret;

use crate::jwk::mode::Private;

use crate::jwk::mode::ClosedSet;

use crate::jwk::key_types::AnyPublicKey;

use crate::jwk::key_types::AnySecretKey;

use crate::jwk::key_types::AnyPrivateKey;

use super::unbound_material::UnboundMaterial;

/// What a key of this mode keeps. Here and not in `mode/`, which knows no family.
///
/// `pub` in a module that can't be named from outside the crate, as `ClosedSet`: a public
/// `Jwk<M>` can be bound by it, and nobody else says what a mode holds.
pub trait Holds: ClosedSet {
    type Held;
}

impl Holds for Public {
    type Held = UnboundMaterial<AnyPublicKey>;
}

impl Holds for Private {
    type Held = UnboundMaterial<AnyPrivateKey>;
}

impl Holds for Secret {
    type Held = UnboundMaterial<AnySecretKey>;
}
