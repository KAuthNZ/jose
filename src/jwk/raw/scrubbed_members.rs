use std::ops::Deref;

use std::ops::DerefMut;

use zeroize::Zeroize;

use serde_json::Map;

use serde_json::Value;

/// The members of one JWK, with every string left in them wiped on drop: a secret member that
/// was never taken out, because the key was refused first, is not freed as it came.
pub(in crate::jwk) struct ScrubbedMembers(Map<String, Value>);

impl ScrubbedMembers {
    pub(in crate::jwk) fn new(members: Map<String, Value>) -> Self {
        Self(members)
    }
}

impl Deref for ScrubbedMembers {
    type Target = Map<String, Value>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ScrubbedMembers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for ScrubbedMembers {
    fn drop(&mut self) {
        let mut pending: Vec<&mut Value> = self.0.values_mut().collect();

        // A stack and not recursion, so the depth of the input can't grow the call stack.
        while let Some(value) = pending.pop() {
            match value {
                Value::String(text) => text.zeroize(),

                Value::Array(items) => pending.extend(items.iter_mut()),

                Value::Object(members) => pending.extend(members.values_mut()),

                _ => {}
            }
        }
    }
}
