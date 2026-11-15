use std::fmt;

use serde_json::Map;

use serde_json::Value;

use serde::de::Visitor;

use serde::de::MapAccess;

use super::strict_value::StrictValue;

/// A JSON object whose values are read by `StrictValue`, so a repeated name is recorded at any
/// depth.
pub(super) struct StrictObject<'a> {
    pub(super) repeated: &'a mut bool,
}

impl<'de> Visitor<'de> for StrictObject<'_> {
    type Value = Map<String, Value>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut map = Map::new();

        // Reading goes on after a repeated name, so a later syntax error still wins.
        while let Some(name) = access.next_key::<String>()? {
            let value = access.next_value_seed(StrictValue {
                repeated: &mut *self.repeated,
            })?;

            if map.insert(name, value).is_some() {
                *self.repeated = true;
            }
        }

        Ok(map)
    }
}
