use crate::jwk::fit::Candidates;

/// A key read and judged, bound to no algorithm yet: its material and the algorithms that may
/// still take it. What it declared is not kept: it said all it had to when it narrowed them.
///
/// `pub` for the same reason as [`Holds`](super::Holds). Without `Debug` on purpose: `K` may
/// hold a secret.
pub struct UnboundMaterial<K> {
    pub(super) material: K,

    pub(super) candidates: Candidates,
}
