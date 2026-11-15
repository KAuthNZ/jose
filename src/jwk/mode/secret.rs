use core::marker::PhantomData;

use core::convert::Infallible;

use super::unbound::Unbound;

use super::key_mode::KeyMode;

use super::closed_set::ClosedSet;

/// A symmetric key: one secret that signs and verifies, with no public side to split from it.
/// Not a [`Private`](super::Private) one, which has a public side and only signs. `A` is the
/// algorithm it is bound to, [`Unbound`] until it is.
///
/// `Infallible` has no value, so neither has this: a mode is only ever a type.
pub struct Secret<A = Unbound>(PhantomData<A>, Infallible);

impl<A> ClosedSet for Secret<A> {}

/// Only unbound, as for [`Public`](super::Public).
impl KeyMode for Secret<Unbound> {}
