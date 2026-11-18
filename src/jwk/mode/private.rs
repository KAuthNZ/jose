use core::marker::PhantomData;

use core::convert::Infallible;

use super::unbound::Unbound;

use super::key_mode::KeyMode;

use super::closed_set::ClosedSet;

/// A key read with its public members and every secret one its family requires. `A` is the
/// algorithm it is bound to, [`Unbound`] until it is.
///
/// `Infallible` has no value, so neither has this: a mode is only ever a type.
pub struct Private<A = Unbound>(PhantomData<A>, Infallible);

impl<A> ClosedSet for Private<A> {}

/// Only unbound, as for [`Public`](super::Public).
impl KeyMode for Private<Unbound> {}
