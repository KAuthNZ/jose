use std::collections::BTreeMap;

use serde_json::Value;

/// A JSON object of string members, in the order of the map, without whitespace. Each name and
/// value is escaped as a JSON string here and nowhere else.
///
/// A `BTreeMap` so the order is the map's and not the caller's: `&str` orders by bytes, which in
/// UTF-8 is the order of the code points. Written by hand so nothing in between can reorder or
/// space it.
pub(crate) fn write_object<V>(members: &BTreeMap<&str, V>) -> String
where
    V: AsRef<str>,
{
    let mut json = String::from("{");

    for (position, (name, value)) in members.iter().enumerate() {
        if position > 0 {
            json.push(',');
        }

        json.push_str(&Value::from(*name).to_string());

        json.push(':');

        json.push_str(&Value::from(value.as_ref()).to_string());
    }

    json.push('}');

    json
}
