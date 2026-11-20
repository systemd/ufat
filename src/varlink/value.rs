// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading the JSON text of a message into a [`Value`].

use std::fmt;

use serde_core::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::{Object, Value};

/// Reads a JSON value into a [`Value`], and refuses an object that has a
/// key twice, at any depth. RFC 8259 leaves open what such an object
/// means, and serde_json's own reader keeps the last of the two values.
/// The server and the client read every message this way.
pub struct UniqueKeys;

impl UniqueKeys {
    /// Reads `text`, which has to be one JSON value and nothing more.
    pub fn parse(text: &str) -> Result<Value, serde_json::Error> {
        let mut json = serde_json::Deserializer::from_str(text);
        let value = UniqueKeys.deserialize(&mut json)?;
        json.end()?;
        Ok(value)
    }
}

impl<'de> DeserializeSeed<'de> for UniqueKeys {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for UniqueKeys {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::from(value))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut elements = Vec::new();
        while let Some(element) = seq.next_element_seed(UniqueKeys)? {
            elements.push(element);
        }
        Ok(Value::Array(elements))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut object = Object::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate key"));
            }
            let value = map.next_value_seed(UniqueKeys)?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_a_key_twice() {
        for text in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"\u0061":1}"#,
            r#"{"x":{"b":[],"b":null}}"#,
            r#"[{"a":1},{"b":1,"b":1}]"#,
            // What follows the second key is not read.
            r#"{"a":1,"a":[}"#,
            r#"{"a":1,"a" 2}"#,
        ] {
            let e = UniqueKeys::parse(text).unwrap_err();
            assert!(e.to_string().starts_with("duplicate key at line 1"), "{}: {}", text, e);
        }
        // Each object has keys of its own, and keeps them in their order.
        let value = UniqueKeys::parse(r#"{"b":{"a":1},"a":[{"a":1},{"a":1.5}],"c":"\u0063"}"#).unwrap();
        let keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(keys, ["b", "a", "c"]);
        assert_eq!(value["a"][1]["a"], Value::from(1.5));
        assert_eq!(value["c"], Value::from("c"));
    }

    #[test]
    fn reads_what_serde_json_reads() {
        for text in [
            "null",
            "true",
            "-1",
            "18446744073709551615",
            "-0",
            "1e300",
            "0.1",
            r#""a\u00e9\ud83d\ude00""#,
            r#"[1,[2,[3]],{}]"#,
            r#" {"k" : [ true , false ] } "#,
        ] {
            assert_eq!(
                UniqueKeys::parse(text).unwrap(),
                serde_json::from_str::<Value>(text).unwrap(),
                "{}",
                text
            );
        }
        for text in ["", "{", "1 2", "[1,]", "1E400", "\"\\ud800\""] {
            assert!(UniqueKeys::parse(text).is_err(), "{}", text);
        }
        // Nesting is limited, and refused without overflowing the stack.
        let deep = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(UniqueKeys::parse(&deep).is_err());
    }
}
