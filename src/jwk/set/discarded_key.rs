use crate::jwk::key::JwkErrors;

/// A key of the set that was not read, left out with its reason (RFC 7517 §5: a key that is not
/// understood SHOULD be ignored). `index` is its place in `keys`, counted from 0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscardedKey {
    index: usize,

    error: JwkErrors,
}

impl DiscardedKey {
    pub(super) fn new(index: usize, error: JwkErrors) -> Self {
        Self { index, error }
    }

    pub fn index(&self) -> usize {
        self.index
    }

    pub fn error(&self) -> JwkErrors {
        self.error
    }
}
