use super::closed_set::ClosedSet;

/// How a key was read: [`Public`](super::Public), [`Private`](super::Private) or
/// [`Secret`](super::Secret). Each family says what a mode adds to its material; this module
/// knows none of them.
pub trait KeyMode: ClosedSet {}
