use crate::jwa::SigningAlgorithm;

use crate::jwa::TypedSigningAlgorithm;

use super::public::Public;

use super::unbound::Unbound;

use super::private::Private;

use super::closed_set::ClosedSet;

/// The algorithm a key of this mode is bound to, `None` while it is [`Unbound`]. Apart from
/// [`Holds`](crate::jwk::key::Holds), which says what material it keeps.
///
/// `pub` in a module that can't be named from outside the crate, as `ClosedSet`: a public
/// `Jwk<M>` can be bound by it, and nobody else says what a mode is bound to.
pub trait HoldsAlg: ClosedSet {
    const ALG: Option<SigningAlgorithm>;
}

impl HoldsAlg for Public<Unbound> {
    const ALG: Option<SigningAlgorithm> = None;
}

impl<A> HoldsAlg for Public<A>
where
    A: TypedSigningAlgorithm,
{
    const ALG: Option<SigningAlgorithm> = Some(A::ALG);
}

impl HoldsAlg for Private<Unbound> {
    const ALG: Option<SigningAlgorithm> = None;
}

impl<A> HoldsAlg for Private<A>
where
    A: TypedSigningAlgorithm,
{
    const ALG: Option<SigningAlgorithm> = Some(A::ALG);
}
