use crate::jwk::fit::Candidates;

use crate::jwk::key_types::Duplicate;

/// A key read and judged, bound to no algorithm yet: its material and the algorithms that may
/// still take it. What it declared is not kept: it said all it had to when it narrowed them.
///
/// `pub` for the same reason as [`Holds`](super::Holds). Without `Debug` on purpose: `K` may
/// hold a secret. `Clone` only where the material is, `Duplicate` where it is a secret.
#[derive(Clone)]
pub struct UnboundMaterial<K> {
    pub(in crate::jwk) material: K,

    pub(in crate::jwk) candidates: Candidates,
}

impl<K> Duplicate for UnboundMaterial<K>
where
    K: Duplicate,
{
    fn duplicate(&self) -> Self {
        Self {
            material: self.material.duplicate(),
            candidates: self.candidates.clone(),
        }
    }
}
