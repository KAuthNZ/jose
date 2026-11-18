use std::fmt;

use serde_json::Value;

use serde::de::Visitor;

use serde::de::SeqAccess;

use serde::de::MapAccess;

use serde::de::Deserializer;

use serde::de::DeserializeSeed;

use super::strict_object::StrictObject;

/// Reads any JSON value and records whether a member name repeats in any object, at any depth.
/// Depth is bounded by the recursion limit of serde_json: every level goes through the same
/// deserializer.
pub(super) struct StrictValue<'a> {
    pub(super) repeated: &'a mut bool,
}

impl<'de> Visitor<'de> for StrictValue<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut items = Vec::new();

        while let Some(item) = access.next_element_seed(StrictValue {
            repeated: &mut *self.repeated,
        })? {
            items.push(item);
        }

        Ok(Value::Array(items))
    }

    fn visit_map<A>(self, access: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        StrictObject {
            repeated: self.repeated,
        }
        .visit_map(access)
        .map(Value::Object)
    }
}

impl<'de> DeserializeSeed<'de> for StrictValue<'_> {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}
