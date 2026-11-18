/// A copy of secret material, asked for by name. Not `Clone`, so that no `derive(Clone)`,
/// `Vec::clone` or `Arc::make_mut` copies a secret without saying so: every copy is a call to
/// this, and each one is wiped on drop as the original is.
///
/// `pub` in a module that can't be named from outside the crate, as `Holds`.
pub trait Duplicate {
    fn duplicate(&self) -> Self;
}
