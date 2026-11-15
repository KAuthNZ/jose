/// The public side of a private key: what verifies what it signs. Only where there is one: a
/// secret has none.
///
/// `pub` in a module that can't be named from outside the crate, as `Duplicate`.
pub trait PublicSide {
    type Public;

    fn public(&self) -> Self::Public;
}
