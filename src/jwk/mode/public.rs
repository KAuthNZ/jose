use core::marker::PhantomData;

use core::convert::Infallible;

use super::unbound::Unbound;

use super::key_mode::KeyMode;

use super::closed_set::ClosedSet;

/// A key read with its public members only: it has nowhere to keep a secret one. `A` is the
/// algorithm it is bound to, [`Unbound`] until it is.
///
/// `Infallible` has no value, so neither has this: a mode is only ever a type.
pub struct Public<A = Unbound>(PhantomData<A>, Infallible);

impl<A> ClosedSet for Public<A> {}

/// Only unbound: a family reads material, not an algorithm.
impl KeyMode for Public<Unbound> {}
