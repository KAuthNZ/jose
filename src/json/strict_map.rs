use std::fmt;

use serde_json::Map;

use serde::de::Visitor;

use serde_json::Value;

use serde::de::MapAccess;

use serde::de::Deserializer;

use serde::de::DeserializeSeed;

/// Reads a JSON object into a `Map` and records whether a member name repeats: `serde_json::Map`
/// keeps the last value of a repeated name without saying so. A seed and not a `Deserialize`,
/// because serde errors can't carry what it found. Names are compared once decoded and
/// case-sensitive.
///
/// Only the top level is checked, not the objects nested inside the values.
pub(super) struct StrictMap<'a> {
    pub(super) repeated: &'a mut bool,
}

impl<'de> Visitor<'de> for StrictMap<'_> {
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
        while let Some((name, value)) = access.next_entry::<String, Value>()? {
            if map.insert(name, value).is_some() {
                *self.repeated = true;
            }
        }

        Ok(map)
    }
}

impl<'de> DeserializeSeed<'de> for StrictMap<'_> {
    type Value = Map<String, Value>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(self)
    }
}
