// SPDX-License-Identifier: LGPL-2.1-or-later
//! A small, strict JSON implementation: a value type, an RFC 8259 parser and
//! a compact serializer.
//!
//! Numbers keep their nature: anything written without a fraction or an
//! exponent that fits into 128 bits stays an integer, so 64-bit sizes and
//! offsets survive a round trip exactly. Objects keep their insertion order
//! and refuse duplicate keys.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;
use std::str::FromStr;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A number without fraction or exponent.
    Int(i128),
    /// Any other number.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Object),
}

/// A JSON object: key/value pairs in insertion order with unique keys.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    /// An empty object.
    pub fn new() -> Object {
        Object::default()
    }

    /// The value stored under `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Whether `key` is present, even with a null value.
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|(k, _)| k == key)
    }

    /// Stores `value` under `key`, replacing an existing value.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<Value>) -> &mut Object {
        let key = key.into();
        let value = value.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some(slot) => slot.1 = value,
            None => self.entries.push((key, value)),
        }
        self
    }

    /// Removes `key` and returns its value.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let i = self.entries.iter().position(|(k, _)| k == key)?;
        Some(self.entries.remove(i).1)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the object has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.into_iter()
    }

    /// The keys in insertion order.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|(k, _)| k.as_str())
    }

    /// Sorts the entries by key, recursively.
    pub fn sort(&mut self) {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, v) in &mut self.entries {
            v.sort_objects();
        }
    }
}

impl Value {
    /// Whether the value is `null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// The boolean, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The integer as i64, if this is an integer in range.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => i64::try_from(*i).ok(),
            _ => None,
        }
    }

    /// The integer as u64, if this is a non-negative integer in range.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Int(i) => u64::try_from(*i).ok(),
            _ => None,
        }
    }

    /// The number as f64, integers included.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Int(i) => Some(*i as f64),
            Value::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// The string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    /// The array, if this is one.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    /// The object, if this is one.
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// The object, mutably, if this is one.
    pub fn as_object_mut(&mut self) -> Option<&mut Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }

    /// Sorts all objects inside the value by key.
    pub fn sort_objects(&mut self) {
        match self {
            Value::Object(o) => o.sort(),
            Value::Array(a) => a.iter_mut().for_each(Value::sort_objects),
            _ => {}
        }
    }
}

/// The entries of an object.
type Entries<'a> =
    std::iter::Map<std::slice::Iter<'a, (String, Value)>, fn(&'a (String, Value)) -> (&'a str, &'a Value)>;

impl<'a> IntoIterator for &'a Object {
    type Item = (&'a str, &'a Value);
    type IntoIter = Entries<'a>;

    /// The entries in insertion order.
    fn into_iter(self) -> Entries<'a> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl FromStr for Value {
    type Err = ParseError;

    /// Parses a complete JSON text, see [`parse`].
    fn from_str(text: &str) -> Result<Value, ParseError> {
        parse(text)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}

impl From<i64> for Value {
    fn from(i: i64) -> Value {
        Value::Int(i128::from(i))
    }
}

impl From<u64> for Value {
    fn from(i: u64) -> Value {
        Value::Int(i128::from(i))
    }
}

impl From<u32> for Value {
    fn from(i: u32) -> Value {
        Value::Int(i128::from(i))
    }
}

impl From<i32> for Value {
    fn from(i: i32) -> Value {
        Value::Int(i128::from(i))
    }
}

impl From<usize> for Value {
    fn from(i: usize) -> Value {
        // No usize is wider than 64 bits.
        Value::Int(i as i128)
    }
}

impl From<f64> for Value {
    fn from(f: f64) -> Value {
        Value::Float(f)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}

impl From<Object> for Value {
    fn from(o: Object) -> Value {
        Value::Object(o)
    }
}

impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Value {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Value {
        match v {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}

/// Where and why parsing failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset into the text.
    pub offset: usize,
    /// What went wrong.
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Nesting deeper than this is refused, to bound stack use.
const MAX_DEPTH: usize = 128;

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn error(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.pos,
            message,
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(&b) = self.bytes.get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.peek() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error("unexpected character"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > MAX_DEPTH {
            return Err(self.error("nesting too deep"));
        }
        self.skip_whitespace();
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, ParseError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.error("invalid literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        let mut object = Object::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(object));
        }
        // Duplicate keys are refused. The object itself is a list, which is
        // right for the small objects this crate builds and receives, and
        // those are checked by looking through the keys so far. Past a few
        // dozen keys a set takes over, so that a parser fed a large hostile
        // object does not go quadratic over it.
        const SCAN_UP_TO: usize = 32;
        let mut seen: Option<std::collections::HashSet<String>> = None;
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a string key"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            self.expect(b':')?;
            let value = self.value(depth + 1)?;
            let duplicate = match seen.as_mut() {
                Some(set) => !set.insert(key.clone()),
                None => object.entries.iter().any(|(k, _)| *k == key),
            };
            if duplicate {
                return Err(self.error("duplicate key"));
            }
            object.entries.push((key, value));
            if seen.is_none() && object.entries.len() >= SCAN_UP_TO {
                seen = Some(object.entries.iter().map(|(k, _)| k.clone()).collect());
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(object));
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error("expected ',' or ']'")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let s = self
            .bytes
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| self.error("truncated unicode escape"))?;
        // from_str_radix would also take a sign; only hex digits are JSON.
        if !s.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.error("invalid unicode escape"));
        }
        let text = std::str::from_utf8(s).map_err(|_| self.error("invalid unicode escape"))?;
        let v = u32::from_str_radix(text, 16).map_err(|_| self.error("invalid unicode escape"))?;
        self.pos += 4;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = Vec::new();
        loop {
            let start = self.pos;
            while let Some(&b) = self.bytes.get(self.pos) {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            out.extend_from_slice(&self.bytes[start..self.pos]);
            match self.peek() {
                None => return Err(self.error("unterminated string")),
                Some(b'"') => {
                    self.pos += 1;
                    break;
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let esc = self.peek().ok_or_else(|| self.error("unterminated string"))?;
                    self.pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code) {
                                // A high surrogate must be followed by a low one.
                                if self.bytes.get(self.pos..self.pos + 2) != Some(b"\\u") {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                self.pos += 2;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            } else if (0xDC00..0xE000).contains(&code) {
                                return Err(self.error("unpaired surrogate"));
                            }
                            let c = char::from_u32(code).ok_or_else(|| self.error("invalid unicode escape"))?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                Some(_) => return Err(self.error("control character in string")),
            }
        }
        String::from_utf8(out).map_err(|_| self.error("invalid UTF-8 in string"))
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.error("invalid number")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("invalid number"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).expect("ASCII digits");
        if !is_float {
            if let Ok(i) = text.parse::<i128>() {
                return Ok(Value::Int(i));
            }
        }
        let f: f64 = text.parse().map_err(|_| self.error("invalid number"))?;
        if !f.is_finite() {
            return Err(self.error("number out of range"));
        }
        Ok(Value::Float(f))
    }
}

/// Parses a complete JSON text. Leading and trailing whitespace is allowed,
/// anything else after the value is an error.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut p = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    let v = p.value(0)?;
    p.skip_whitespace();
    if p.pos != p.bytes.len() {
        return Err(p.error("trailing characters"));
    }
    Ok(v)
}

/// Writes `s` as a JSON string. The runs between escapes go out as they
/// are.
fn write_string<W: fmt::Write + ?Sized>(out: &mut W, s: &str) -> fmt::Result {
    out.write_char('"')?;
    let mut plain = 0;
    for (i, c) in s.char_indices() {
        let escape = match c {
            '"' => Some("\\\""),
            '\\' => Some("\\\\"),
            '\n' => Some("\\n"),
            '\r' => Some("\\r"),
            '\t' => Some("\\t"),
            '\u{08}' => Some("\\b"),
            '\u{0c}' => Some("\\f"),
            c if u32::from(c) < 0x20 => None,
            _ => continue,
        };
        out.write_str(&s[plain..i])?;
        match escape {
            Some(escape) => out.write_str(escape)?,
            None => write!(out, "\\u{:04x}", u32::from(c))?,
        }
        plain = i + c.len_utf8();
    }
    out.write_str(&s[plain..])?;
    out.write_char('"')
}

fn write_value<W: fmt::Write + ?Sized>(out: &mut W, v: &Value) -> fmt::Result {
    match v {
        Value::Null => out.write_str("null"),
        Value::Bool(b) => out.write_str(if *b { "true" } else { "false" }),
        Value::Int(i) => write!(out, "{}", i),
        // A float that is a whole number keeps a fraction, so that it reads
        // back as a float.
        Value::Float(f) if f.is_finite() && f.fract() == 0.0 => write!(out, "{}.0", f),
        Value::Float(f) if f.is_finite() => write!(out, "{}", f),
        Value::Float(_) => out.write_str("null"),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            out.write_char('[')?;
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.write_char(',')?;
                }
                write_value(out, item)?;
            }
            out.write_char(']')
        }
        Value::Object(o) => write_object(out, o),
    }
}

fn write_object<W: fmt::Write + ?Sized>(out: &mut W, o: &Object) -> fmt::Result {
    out.write_char('{')?;
    for (i, (k, item)) in o.iter().enumerate() {
        if i > 0 {
            out.write_char(',')?;
        }
        write_string(out, k)?;
        out.write_char(':')?;
        write_value(out, item)?;
    }
    out.write_char('}')
}

impl fmt::Display for Value {
    /// Compact serialization without any whitespace.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_value(f, self)
    }
}

impl fmt::Display for Object {
    /// Compact serialization without any whitespace.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_object(f, self)
    }
}

/// Builds an object from key/value pairs.
#[macro_export]
macro_rules! object {
    ($($key:expr => $value:expr),* $(,)?) => {{
        let mut o = $crate::Object::new();
        $( o.insert($key, $value); )*
        o
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_escapes_and_floats() {
        let text = Value::String("a\u{1}b\"c\\\n\u{7f}\u{e9}".into()).to_string();
        assert_eq!(text, "\"a\\u0001b\\\"c\\\\\\n\u{7f}\u{e9}\"");
        assert_eq!(
            text.parse::<Value>(),
            Ok(Value::String("a\u{1}b\"c\\\n\u{7f}\u{e9}".into()))
        );
        for (f, text) in [
            (1.0, "1.0"),
            (-0.0, "-0.0"),
            (1.5, "1.5"),
            (1e21, "1000000000000000000000.0"),
            (f64::NAN, "null"),
            (f64::INFINITY, "null"),
        ] {
            assert_eq!(Value::Float(f).to_string(), text);
        }
        let o = object! { "a" => 1u32, "b" => "x" };
        assert_eq!(o.to_string(), r#"{"a":1,"b":"x"}"#);
        assert_eq!((&o).into_iter().map(|(k, _)| k).collect::<Vec<_>>(), ["a", "b"]);
    }

    #[test]
    fn round_trips() {
        for text in [
            r#"{"a":1,"b":[true,false,null],"c":"x\"y\\z\n","d":{"e":-12,"f":1.5}}"#,
            r#"[]"#,
            r#"{}"#,
            r#""\u00e9\ud83d\ude00""#,
            r#"18446744073709551615"#,
            r#"-170141183460469231731687303715884105728"#,
            r#"1e300"#,
        ] {
            let v = parse(text).unwrap();
            let again = parse(&v.to_string()).unwrap();
            assert_eq!(v, again, "{}", text);
        }
        assert_eq!(parse("\"\\u00e9\"").unwrap().as_str(), Some("é"));
        assert_eq!(parse("\"\\ud83d\\ude00\"").unwrap().as_str(), Some("\u{1F600}"));
        assert_eq!(parse("18446744073709551615").unwrap().as_u64(), Some(u64::MAX));
        assert_eq!(parse("-1").unwrap().as_u64(), None);
        assert_eq!(parse("1.0").unwrap(), Value::Float(1.0));
        assert_eq!(Value::Float(1.0).to_string(), "1.0");
        assert_eq!(Value::Float(f64::NAN).to_string(), "null");
        assert_eq!(
            parse(" \t\n{ \"a\" : [ 1 , 2 ] } \r\n").unwrap().to_string(),
            r#"{"a":[1,2]}"#
        );
    }

    #[test]
    fn rejects_garbage() {
        for text in [
            "",
            " ",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{a:1}",
            "01",
            "1.",
            ".5",
            "+1",
            "1e",
            "tru",
            "nul",
            "\"abc",
            "\"a\u{01}b\"",
            "\"\\x\"",
            "\"\\ud83d\"",
            "\"\\ude00\"",
            "{\"a\":1,\"a\":2}",
            "[1] x",
            "NaN",
            "Infinity",
            "\"\\u12\"",
            "\"\\u+041\"",
            "\"\\u-041\"",
        ] {
            assert!(parse(text).is_err(), "{:?} accepted", text);
        }
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(parse(&deep).is_err());
        // Many keys stay cheap to check for duplicates; one duplicate among
        // them is still found.
        let keys: Vec<String> = (0..20_000).map(|i| format!("\"k{}\":{}", i, i)).collect();
        let wide = format!("{{{}}}", keys.join(","));
        assert_eq!(parse(&wide).unwrap().as_object().unwrap().len(), 20_000);
        let dup = format!("{{{},\"k1\":0}}", keys.join(","));
        assert!(parse(&dup).is_err());
        // A duplicate is found on both sides of the point where the check
        // switches from scanning the keys to a set, and right at it.
        for n in [5, 31, 32, 33, 40] {
            let keys: Vec<String> = (0..n).map(|i| format!("\"k{}\":{}", i, i)).collect();
            assert_eq!(
                parse(&format!("{{{}}}", keys.join(",")))
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .len(),
                n
            );
            for at in [0, n / 2, n - 1] {
                let dup = format!("{{{},\"k{}\":0}}", keys.join(","), at);
                assert!(parse(&dup).is_err(), "{} keys, duplicate of {}", n, at);
            }
        }
    }

    #[test]
    fn objects() {
        let mut o = object! { "b" => 1i64, "a" => "x" };
        assert_eq!(o.keys().collect::<Vec<_>>(), vec!["b", "a"]);
        o.insert("b", 2i64);
        assert_eq!(o.get("b").unwrap().as_i64(), Some(2));
        assert_eq!(o.len(), 2);
        o.sort();
        assert_eq!(o.keys().collect::<Vec<_>>(), vec!["a", "b"]);
        assert_eq!(o.remove("a"), Some(Value::from("x")));
        assert!(!o.contains_key("a"));
        let v: Value = object! { "n" => Value::Null, "list" => vec![1u32, 2] }.into();
        assert_eq!(v.to_string(), r#"{"n":null,"list":[1,2]}"#);
        assert_eq!(v.get("list").unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn escapes() {
        let v = Value::from("a\"b\\c\n\t\u{01}é");
        assert_eq!(v.to_string(), "\"a\\\"b\\\\c\\n\\t\\u0001é\"");
        assert_eq!(parse(&v.to_string()).unwrap(), v);
    }
}
