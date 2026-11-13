// SPDX-License-Identifier: LGPL-2.1-or-later
//! A small, strict JSON implementation: a value type, an RFC 8259 parser and
//! a compact serializer.
//!
//! [`parse`] reads a text into a [`Value`], and a `Value` prints itself as
//! compact text. [`Parser`] reads a text value by value, for a caller that
//! has types of its own and does not want a `Value` in between.
//!
//! Numbers keep their nature: anything written without a fraction or an
//! exponent that fits into 128 bits stays an integer, so 64-bit sizes and
//! offsets survive a round trip exactly. Objects keep their insertion order
//! and refuse duplicate keys.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::borrow::Cow;
use std::collections::HashSet;
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

/// The most arrays and objects a parser is inside of at once: the value at
/// the top and one at every level of nesting below it.
const MAX_OPEN: usize = MAX_DEPTH + 1;

/// The keys of an object are checked for duplicates by looking through
/// them, which is right for the small objects this crate builds and
/// receives. The parser keeps this many keys at hand for that. An object
/// that needs more gets a set, so that a parser fed a large hostile object
/// does not go quadratic over it.
const SCAN_UP_TO: usize = 32;

/// Eight bytes of a text in one integer, the first of them in its lowest
/// bits. A string is searched for its end a word at a time.
#[derive(Clone, Copy)]
struct Word(u64);

impl Word {
    /// How many bytes a word holds.
    const SIZE: usize = size_of::<u64>();
    /// The lowest bit of every byte, and the highest.
    const LOW_BITS: u64 = u64::from_ne_bytes([0x01; Word::SIZE]);
    const HIGH_BITS: u64 = u64::from_ne_bytes([0x80; Word::SIZE]);

    fn new(bytes: [u8; Word::SIZE]) -> Word {
        Word(u64::from_le_bytes(bytes))
    }

    /// The high bit of every byte that is below `limit`, which is no more
    /// than 0x80. Only the lowest bit set is to be relied on: a byte after
    /// the first one below the limit can be marked wrongly.
    const fn below(self, limit: u8) -> u64 {
        self.0.wrapping_sub(Word::LOW_BITS * limit as u64) & !self.0 & Word::HIGH_BITS
    }

    /// The high bit of every byte that is `byte`, to be relied on like
    /// that of [`Word::below`].
    const fn equal(self, byte: u8) -> u64 {
        Word(self.0 ^ (Word::LOW_BITS * byte as u64)).below(1)
    }

    /// Where the first byte is that does not stand for itself in a
    /// string, if the word has one.
    fn first_special(self) -> Option<usize> {
        let special = self.equal(QUOTE) | self.equal(ESCAPE) | self.below(FIRST_PRINTABLE);
        (special != 0).then(|| (special.trailing_zeros() / u8::BITS) as usize)
    }

    /// How many bytes at the start of `bytes` stand for themselves in a
    /// string: all up to the first quote, backslash or control character.
    fn plain_run(bytes: &[u8]) -> usize {
        let mut rest = bytes;
        while let Some((word, behind)) = rest.split_first_chunk() {
            if let Some(at) = Word::new(*word).first_special() {
                return bytes.len() - rest.len() + at;
            }
            rest = behind;
        }
        let plain = |b: &&u8| **b != QUOTE && **b != ESCAPE && **b >= FIRST_PRINTABLE;
        bytes.len() - rest.len() + rest.iter().take_while(plain).count()
    }
}

/// The first byte of a string and its last.
const QUOTE: u8 = b'"';
/// The byte that starts an escape inside a string.
const ESCAPE: u8 = b'\\';
/// The bytes below this one are control characters. A string has to
/// escape them.
const FIRST_PRINTABLE: u8 = 0x20;
/// What a `\u` escape starts with, and how many hex digits follow.
const UNICODE_ESCAPE: &[u8] = b"\\u";
const UNICODE_ESCAPE_DIGITS: usize = 4;
/// The base of those digits.
const HEX: u32 = 16;
/// The base a number is written in, and how many digits the largest u64
/// has in it. A number of fewer digits fits into a u64.
const DECIMAL: u64 = 10;
const U64_DIGITS: usize = 20;
/// The UTF-16 units that are one half of a pair: the high surrogates, which
/// come first, and the low ones.
const HIGH_SURROGATES: std::ops::Range<u32> = 0xD800..0xDC00;
const LOW_SURROGATES: std::ops::Range<u32> = 0xDC00..0xE000;
/// The first character a surrogate pair stands for.
const FIRST_SUPPLEMENTARY: u32 = 0x10000;
/// The bits of a character one surrogate carries.
const SURROGATE_BITS: u32 = 10;

/// The kind of a JSON value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `null`
    Null,
    /// `true` or `false`
    Bool,
    /// A number.
    Number,
    /// A string.
    String,
    /// An array.
    Array,
    /// An object.
    Object,
}

/// A JSON number. One written without a fraction or an exponent that fits
/// into 128 bits is an integer.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Number {
    /// A number without fraction or exponent.
    Int(i128),
    /// Any other number.
    Float(f64),
}

impl Number {
    /// The number as u64, if it is a non-negative integer in range.
    pub fn as_u64(self) -> Option<u64> {
        match self {
            Number::Int(i) => u64::try_from(i).ok(),
            Number::Float(_) => None,
        }
    }

    /// The number as i64, if it is an integer in range.
    pub fn as_i64(self) -> Option<i64> {
        match self {
            Number::Int(i) => i64::try_from(i).ok(),
            Number::Float(_) => None,
        }
    }

    /// The number as f64, integers included.
    pub fn as_f64(self) -> f64 {
        match self {
            Number::Int(i) => i as f64,
            Number::Float(f) => f,
        }
    }
}

impl From<Number> for Value {
    fn from(n: Number) -> Value {
        match n {
            Number::Int(i) => Value::Int(i),
            Number::Float(f) => Value::Float(f),
        }
    }
}

/// What the parser is inside of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Open {
    /// An array.
    Array,
    /// An object. Its keys are among the ones the parser keeps at hand.
    Object,
    /// An object with more keys than the parser keeps at hand. They are in
    /// a set.
    Wide,
}

/// One array or object the parser is inside of.
#[derive(Clone, Copy)]
struct Level {
    open: Open,
    /// How many keys the parser had at hand when it went in. Those of an
    /// object come after them.
    first_key: u8,
}

/// Reads a JSON text value by value, without building a [`Value`].
///
/// The parser stands in front of a value. [`Parser::peek`] says what kind
/// it is. The methods named after a kind read the value if it is of that
/// kind, and leave it alone if it is not. [`Parser::skip`] reads a value of
/// any kind. An array is entered with [`Parser::array`], and then
/// [`Parser::element`] says before every element whether there is one. An
/// object is entered with [`Parser::object`], and then [`Parser::key`]
/// returns the key of every member, whose value is read next.
///
/// A text the parser reads to its end without an error is one [`parse`]
/// takes, and the other way around.
///
/// ```
/// let mut parser = json::Parser::new(r#"{"name":"a","size":3,"more":[1,2]}"#);
/// let mut size = None;
/// assert!(parser.object()?);
/// while let Some(key) = parser.key()? {
///     match key.as_ref() {
///         "size" => size = parser.number()?.and_then(json::Number::as_u64),
///         _ => parser.skip()?,
///     }
/// }
/// parser.end()?;
/// assert_eq!(size, Some(3));
/// # Ok::<(), json::ParseError>(())
/// ```
pub struct Parser<'a> {
    text: &'a str,
    pos: usize,
    /// The arrays and objects the parser is inside of, outermost first.
    levels: [Level; MAX_OPEN],
    depth: usize,
    /// Whether the innermost of them has no member so far.
    empty: bool,
    /// The keys of the objects in `open` that are looked through. They
    /// are parts of the text.
    keys: [&'a str; SCAN_UP_TO],
    key_count: usize,
    /// The keys of the objects in `open` that have a set, outermost first.
    sets: Vec<HashSet<Cow<'a, str>>>,
    /// How deep the object is whose last key it had before. That is an
    /// error once the value of the key was read.
    duplicate: Option<usize>,
}

impl<'a> Parser<'a> {
    /// A parser in front of the value `text` holds.
    pub fn new(text: &'a str) -> Parser<'a> {
        Parser {
            text,
            pos: 0,
            levels: [Level {
                open: Open::Array,
                first_key: 0,
            }; MAX_OPEN],
            depth: 0,
            empty: false,
            keys: [""; SCAN_UP_TO],
            key_count: 0,
            sets: Vec::new(),
            duplicate: None,
        }
    }

    /// How many bytes of the text the parser has read.
    pub fn offset(&self) -> usize {
        self.pos
    }

    fn error(&self, message: &'static str) -> ParseError {
        ParseError {
            offset: self.pos,
            message,
        }
    }

    fn bytes(&self) -> &'a [u8] {
        self.text.as_bytes()
    }

    fn skip_whitespace(&mut self) {
        while let Some(&b) = self.bytes().get(self.pos) {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn byte(&self) -> Option<u8> {
        self.bytes().get(self.pos).copied()
    }

    fn expect(&mut self, b: u8) -> Result<(), ParseError> {
        if self.byte() == Some(b) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.error("unexpected character"))
        }
    }

    /// The kind of the value the parser stands in front of. It is an
    /// error when there is no value.
    pub fn peek(&mut self) -> Result<Kind, ParseError> {
        if self.depth > MAX_DEPTH {
            return Err(self.error("nesting too deep"));
        }
        self.skip_whitespace();
        match self.byte() {
            None => Err(self.error("unexpected end of input")),
            Some(b'{') => Ok(Kind::Object),
            Some(b'[') => Ok(Kind::Array),
            Some(QUOTE) => Ok(Kind::String),
            Some(b't' | b'f') => Ok(Kind::Bool),
            Some(b'n') => Ok(Kind::Null),
            Some(b'-' | b'0'..=b'9') => Ok(Kind::Number),
            Some(_) => Err(self.error("unexpected character")),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), ParseError> {
        if self.bytes()[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(self.error("invalid literal"))
        }
    }

    /// Reads the value if it is `null`, and says whether it was.
    pub fn null(&mut self) -> Result<bool, ParseError> {
        if self.peek()? != Kind::Null {
            return Ok(false);
        }
        self.literal("null")?;
        Ok(true)
    }

    /// Reads the boolean the parser stands in front of.
    fn bool_token(&mut self) -> Result<bool, ParseError> {
        let value = self.byte() == Some(b't');
        self.literal(if value { "true" } else { "false" })?;
        Ok(value)
    }

    /// Reads the value if it is a boolean.
    pub fn bool(&mut self) -> Result<Option<bool>, ParseError> {
        if self.peek()? != Kind::Bool {
            return Ok(None);
        }
        self.bool_token().map(Some)
    }

    /// Reads the value if it is a number.
    pub fn number(&mut self) -> Result<Option<Number>, ParseError> {
        if self.peek()? != Kind::Number {
            return Ok(None);
        }
        self.number_token().map(Some)
    }

    /// Moves over a run of digits and says whether there was one.
    fn digits(&mut self) -> bool {
        let run = self.bytes()[self.pos..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
        self.pos += run;
        run > 0
    }

    /// Reads the number the parser stands in front of.
    fn number_token(&mut self) -> Result<Number, ParseError> {
        let start = self.pos;
        let negative = self.byte() == Some(b'-');
        if negative {
            self.pos += 1;
        }
        // The digits in front of a fraction, and their value if they are
        // few enough to fit into a u64 whatever they are.
        let mut magnitude = Some(0u64);
        match self.byte() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                let digits = self.bytes()[self.pos..].iter().map(|b| b.wrapping_sub(b'0'));
                // With too many digits the value wraps around. It is not
                // used then.
                let (value, run) = digits
                    .take_while(|&digit| u64::from(digit) < DECIMAL)
                    .fold((0u64, 0), |(value, run), digit| {
                        (value.wrapping_mul(DECIMAL).wrapping_add(u64::from(digit)), run + 1)
                    });
                self.pos += run;
                magnitude = (run < U64_DIGITS).then_some(value);
            }
            _ => return Err(self.error("invalid number")),
        }
        let mut is_float = false;
        if self.byte() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            if !self.digits() {
                return Err(self.error("invalid number"));
            }
        }
        if matches!(self.byte(), Some(b'e' | b'E')) {
            is_float = true;
            self.pos += 1;
            if matches!(self.byte(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.digits() {
                return Err(self.error("invalid number"));
            }
        }
        let text = &self.text[start..self.pos];
        if !is_float {
            if let Some(magnitude) = magnitude {
                let magnitude = i128::from(magnitude);
                return Ok(Number::Int(if negative { -magnitude } else { magnitude }));
            }
            if let Ok(i) = text.parse::<i128>() {
                return Ok(Number::Int(i));
            }
        }
        let f: f64 = text.parse().map_err(|_| self.error("invalid number"))?;
        if !f.is_finite() {
            return Err(self.error("number out of range"));
        }
        Ok(Number::Float(f))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let s = self
            .bytes()
            .get(self.pos..self.pos + UNICODE_ESCAPE_DIGITS)
            .ok_or_else(|| self.error("truncated unicode escape"))?;
        // from_str_radix would also take a sign; only hex digits are JSON.
        if !s.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.error("invalid unicode escape"));
        }
        let text = std::str::from_utf8(s).map_err(|_| self.error("invalid unicode escape"))?;
        let v = u32::from_str_radix(text, HEX).map_err(|_| self.error("invalid unicode escape"))?;
        self.pos += UNICODE_ESCAPE_DIGITS;
        Ok(v)
    }

    /// Moves over the bytes of a string that stand for themselves.
    fn plain_run(&mut self) {
        self.pos += Word::plain_run(&self.bytes()[self.pos..]);
    }

    /// Reads the string the parser stands in front of. A string without
    /// an escape is a part of the text.
    fn string_token(&mut self) -> Result<Cow<'a, str>, ParseError> {
        self.expect(QUOTE)?;
        let start = self.pos;
        self.plain_run();
        if self.byte() == Some(QUOTE) {
            let plain = &self.text[start..self.pos];
            self.pos += 1;
            return Ok(Cow::Borrowed(plain));
        }
        let mut out = String::from(&self.text[start..self.pos]);
        loop {
            match self.byte() {
                None => return Err(self.error("unterminated string")),
                Some(QUOTE) => {
                    self.pos += 1;
                    break;
                }
                Some(ESCAPE) => {
                    self.pos += 1;
                    let esc = self.byte().ok_or_else(|| self.error("unterminated string"))?;
                    self.pos += 1;
                    match esc {
                        QUOTE => out.push('"'),
                        ESCAPE => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if HIGH_SURROGATES.contains(&code) {
                                // A high surrogate must be followed by a low one.
                                if !self.bytes()[self.pos..].starts_with(UNICODE_ESCAPE) {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                self.pos += UNICODE_ESCAPE.len();
                                let low = self.hex4()?;
                                if !LOW_SURROGATES.contains(&low) {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                code = FIRST_SUPPLEMENTARY
                                    + ((code - HIGH_SURROGATES.start) << SURROGATE_BITS)
                                    + (low - LOW_SURROGATES.start);
                            } else if LOW_SURROGATES.contains(&code) {
                                return Err(self.error("unpaired surrogate"));
                            }
                            out.push(char::from_u32(code).ok_or_else(|| self.error("invalid unicode escape"))?);
                        }
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                Some(_) => return Err(self.error("control character in string")),
            }
            let start = self.pos;
            self.plain_run();
            out.push_str(&self.text[start..self.pos]);
        }
        Ok(Cow::Owned(out))
    }

    /// Reads the value if it is a string. A string without an escape is
    /// returned as the part of the text it is.
    pub fn string(&mut self) -> Result<Option<Cow<'a, str>>, ParseError> {
        if self.peek()? != Kind::String {
            return Ok(None);
        }
        self.string_token().map(Some)
    }

    /// Goes into the array or object the parser stands in front of.
    fn enter(&mut self, open: Open) {
        self.pos += 1;
        self.levels[self.depth] = Level {
            open,
            // Never more than SCAN_UP_TO keys are at hand, so the count fits.
            first_key: self.key_count as u8,
        };
        self.depth += 1;
        self.empty = true;
    }

    /// Leaves the innermost array or object at its closing bracket.
    fn leave(&mut self) {
        self.pos += 1;
        self.depth -= 1;
        let level = self.levels[self.depth];
        match level.open {
            Open::Array => {}
            Open::Object => self.key_count = usize::from(level.first_key),
            Open::Wide => {
                self.sets.pop();
            }
        }
        self.empty = false;
    }

    /// Goes into the value if it is an array, and says whether it is one.
    /// [`Parser::element`] is to be asked before every element then.
    pub fn array(&mut self) -> Result<bool, ParseError> {
        if self.peek()? != Kind::Array {
            return Ok(false);
        }
        self.enter(Open::Array);
        Ok(true)
    }

    /// Whether the array the parser is in has another element. The parser
    /// stands in front of it then. Otherwise it has left the array.
    pub fn element(&mut self) -> Result<bool, ParseError> {
        debug_assert!(self.depth > 0 && self.levels[self.depth - 1].open == Open::Array);
        self.skip_whitespace();
        if self.empty {
            if self.byte() == Some(b']') {
                self.leave();
                return Ok(false);
            }
            self.empty = false;
            return Ok(true);
        }
        match self.byte() {
            Some(b',') => {
                self.pos += 1;
                Ok(true)
            }
            Some(b']') => {
                self.leave();
                Ok(false)
            }
            _ => Err(self.error("expected ',' or ']'")),
        }
    }

    /// Goes into the value if it is an object, and says whether it is
    /// one. [`Parser::key`] returns the key of every member then.
    pub fn object(&mut self) -> Result<bool, ParseError> {
        if self.peek()? != Kind::Object {
            return Ok(false);
        }
        self.enter(Open::Object);
        Ok(true)
    }

    /// The key of the next member of the object the parser is in. The
    /// parser stands in front of the member's value then. Without another
    /// member it has left the object. A key the object had before is an
    /// error, which is reported after the value of that key.
    pub fn key(&mut self) -> Result<Option<Cow<'a, str>>, ParseError> {
        debug_assert!(self.depth > 0 && self.levels[self.depth - 1].open != Open::Array);
        if self.empty {
            self.skip_whitespace();
            if self.byte() == Some(b'}') {
                self.leave();
                return Ok(None);
            }
        } else {
            if self.duplicate == Some(self.depth) {
                return Err(self.error("duplicate key"));
            }
            self.skip_whitespace();
            match self.byte() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.leave();
                    return Ok(None);
                }
                _ => return Err(self.error("expected ',' or '}'")),
            }
        }
        self.skip_whitespace();
        if self.byte() != Some(QUOTE) {
            return Err(self.error("expected a string key"));
        }
        let key = self.string_token()?;
        self.skip_whitespace();
        self.expect(b':')?;
        let new = match key {
            Cow::Borrowed(plain) => self.remember(plain),
            Cow::Owned(ref escaped) => self.remember_escaped(escaped),
        };
        if !new {
            self.duplicate = Some(self.depth);
        }
        self.empty = false;
        Ok(Some(key))
    }

    /// Notes `key`, a part of the text, as a key of the innermost object.
    /// Returns false when the object had the key before.
    fn remember(&mut self, key: &'a str) -> bool {
        let level = self.levels[self.depth - 1];
        match level.open {
            Open::Array => return true,
            Open::Wide => {}
            Open::Object => {
                if self.keys[usize::from(level.first_key)..self.key_count].contains(&key) {
                    return false;
                }
                if self.key_count < SCAN_UP_TO {
                    self.keys[self.key_count] = key;
                    self.key_count += 1;
                    return true;
                }
                // No room at hand.
                self.widen();
            }
        }
        self.sets.last_mut().is_some_and(|set| set.insert(Cow::Borrowed(key)))
    }

    /// Notes a key that was written with an escape as a key of the
    /// innermost object. Such a key is no part of the text, so the object
    /// gets a set. Returns false when the object had the key before.
    fn remember_escaped(&mut self, key: &str) -> bool {
        match self.levels[self.depth - 1].open {
            Open::Array => return true,
            Open::Wide => {}
            Open::Object => self.widen(),
        }
        self.sets
            .last_mut()
            .is_some_and(|set| set.insert(Cow::Owned(key.into())))
    }

    /// Moves the keys of the innermost object from those at hand into a
    /// set.
    fn widen(&mut self) {
        let level = &mut self.levels[self.depth - 1];
        let first = usize::from(level.first_key);
        level.open = Open::Wide;
        let keys = &self.keys[first..self.key_count];
        self.sets.push(keys.iter().map(|&key| Cow::Borrowed(key)).collect());
        self.key_count = first;
    }

    /// Reads the value, whatever kind it is.
    pub fn skip(&mut self) -> Result<(), ParseError> {
        match self.peek()? {
            Kind::Null => self.literal("null"),
            Kind::Bool => self.bool_token().map(drop),
            Kind::Number => self.number_token().map(drop),
            Kind::String => self.string_token().map(drop),
            Kind::Array => {
                self.enter(Open::Array);
                while self.element()? {
                    self.skip()?;
                }
                Ok(())
            }
            Kind::Object => {
                self.enter(Open::Object);
                while self.key()?.is_some() {
                    self.skip()?;
                }
                Ok(())
            }
        }
    }

    /// Reads the value into a [`Value`].
    pub fn value(&mut self) -> Result<Value, ParseError> {
        Ok(match self.peek()? {
            Kind::Null => {
                self.literal("null")?;
                Value::Null
            }
            Kind::Bool => Value::Bool(self.bool_token()?),
            Kind::Number => self.number_token()?.into(),
            Kind::String => Value::String(self.string_token()?.into_owned()),
            Kind::Array => {
                self.enter(Open::Array);
                let mut items = Vec::new();
                while self.element()? {
                    items.push(self.value()?);
                }
                Value::Array(items)
            }
            Kind::Object => {
                self.enter(Open::Object);
                let mut object = Object::new();
                while let Some(key) = self.key()? {
                    let value = self.value()?;
                    object.entries.push((key.into_owned(), value));
                }
                Value::Object(object)
            }
        })
    }

    /// Checks that the value at the top was read whole and that nothing
    /// but whitespace is left of the text.
    pub fn end(&mut self) -> Result<(), ParseError> {
        self.skip_whitespace();
        if self.depth != 0 {
            return Err(self.error("unexpected end of input"));
        }
        if self.pos != self.text.len() {
            return Err(self.error("trailing characters"));
        }
        Ok(())
    }
}

/// Parses a complete JSON text. Leading and trailing whitespace is allowed,
/// anything else after the value is an error.
pub fn parse(text: &str) -> Result<Value, ParseError> {
    let mut parser = Parser::new(text);
    let value = parser.value()?;
    parser.end()?;
    Ok(value)
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

    /// Reads `text` with the methods named after the kinds and writes what
    /// they return back out.
    fn walk(p: &mut Parser<'_>, out: &mut String) -> Result<(), ParseError> {
        match p.peek()? {
            Kind::Null => {
                assert!(p.null()?);
                out.push_str("null");
            }
            Kind::Bool => out.push_str(if p.bool()?.unwrap() { "true" } else { "false" }),
            Kind::Number => out.push_str(&Value::from(p.number()?.unwrap()).to_string()),
            Kind::String => out.push_str(&Value::from(p.string()?.unwrap().as_ref()).to_string()),
            Kind::Array => {
                assert!(p.array()?);
                out.push('[');
                let mut elements = 0;
                while p.element()? {
                    if elements > 0 {
                        out.push(',');
                    }
                    elements += 1;
                    walk(p, out)?;
                }
                out.push(']');
            }
            Kind::Object => {
                assert!(p.object()?);
                out.push('{');
                let mut members = 0;
                while let Some(key) = p.key()? {
                    if members > 0 {
                        out.push(',');
                    }
                    members += 1;
                    out.push_str(&Value::from(key.as_ref()).to_string());
                    out.push(':');
                    walk(p, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    /// What [`parse`] says about `text`, what skipping over it says and what
    /// reading it value by value says: the same value or the same error.
    fn three_ways(text: &str) -> Result<String, ParseError> {
        let parsed = parse(text).map(|v| v.to_string());
        let mut p = Parser::new(text);
        let skipped = p.skip().and_then(|()| p.end());
        assert_eq!(skipped, parsed.clone().map(drop), "{:?}", text);
        let mut p = Parser::new(text);
        let mut out = String::new();
        let walked = walk(&mut p, &mut out).and_then(|()| p.end()).map(|()| out);
        assert_eq!(walked, parsed, "{:?}", text);
        parsed
    }

    #[test]
    fn parser_reads_value_by_value() {
        let text = r#" {"name" : "a/b", "esc":"x\ny", "size":18446744073709551615, "neg":-1, "f":1.5,
            "list":[1,[],{}, null ,true,false], "o":{"k":"v"}, "n":null} "#;
        let mut p = Parser::new(text);
        assert_eq!(p.peek(), Ok(Kind::Object));
        // A method of another kind reads nothing.
        assert_eq!(p.string(), Ok(None));
        assert_eq!(p.number(), Ok(None));
        assert_eq!(p.bool(), Ok(None));
        assert_eq!(p.null(), Ok(false));
        assert_eq!(p.array(), Ok(false));
        assert_eq!(p.offset(), 1);
        assert_eq!(p.object(), Ok(true));
        assert_eq!(p.key().unwrap().as_deref(), Some("name"));
        assert_eq!(p.object(), Ok(false));
        // A string without an escape is a part of the text, one with an
        // escape is not.
        assert!(matches!(p.string(), Ok(Some(Cow::Borrowed("a/b")))));
        assert_eq!(p.key().unwrap().as_deref(), Some("esc"));
        assert!(matches!(p.string(), Ok(Some(Cow::Owned(s))) if s == "x\ny"));
        assert_eq!(p.key().unwrap().as_deref(), Some("size"));
        assert_eq!(p.number().unwrap().and_then(Number::as_u64), Some(u64::MAX));
        assert_eq!(p.key().unwrap().as_deref(), Some("neg"));
        let neg = p.number().unwrap().unwrap();
        assert_eq!((neg.as_u64(), neg.as_i64(), neg.as_f64()), (None, Some(-1), -1.0));
        assert_eq!(p.key().unwrap().as_deref(), Some("f"));
        let f = p.number().unwrap().unwrap();
        assert_eq!(
            (f, f.as_u64(), f.as_i64(), f.as_f64()),
            (Number::Float(1.5), None, None, 1.5)
        );
        assert_eq!(p.key().unwrap().as_deref(), Some("list"));
        assert_eq!(p.array(), Ok(true));
        let mut kinds = Vec::new();
        while p.element().unwrap() {
            kinds.push(p.peek().unwrap());
            p.skip().unwrap();
        }
        assert_eq!(
            kinds,
            [
                Kind::Number,
                Kind::Array,
                Kind::Object,
                Kind::Null,
                Kind::Bool,
                Kind::Bool
            ]
        );
        assert_eq!(p.key().unwrap().as_deref(), Some("o"));
        assert_eq!(p.value().unwrap().to_string(), r#"{"k":"v"}"#);
        assert_eq!(p.key().unwrap().as_deref(), Some("n"));
        assert_eq!(p.null(), Ok(true));
        assert_eq!(p.key(), Ok(None));
        assert_eq!(p.end(), Ok(()));
        assert_eq!(p.offset(), text.len());
        assert_eq!(
            three_ways(text).unwrap(),
            r#"{"name":"a/b","esc":"x\ny","size":18446744073709551615,"neg":-1,"f":1.5,"list":[1,[],{},null,true,false],"o":{"k":"v"},"n":null}"#
        );
        // An array or an object that was not read to its end is not the
        // end of the text.
        let mut p = Parser::new("[1]");
        assert_eq!(p.array(), Ok(true));
        assert_eq!(p.element(), Ok(true));
        assert_eq!(p.skip(), Ok(()));
        assert!(p.end().is_err());
        assert_eq!(p.element(), Ok(false));
        assert_eq!(p.end(), Ok(()));
    }

    #[test]
    fn parser_agrees_with_parse() {
        for text in [
            "null",
            " true ",
            "false",
            "0",
            "-0",
            "1e5",
            "\"\"",
            "\"a\\u00e9\\ud83d\\ude00\"",
            "[]",
            "[ ]",
            "{}",
            "{ }",
            "[[[]],{\"a\":{\"a\":[{}]}}]",
            "{\"a\":1,\"b\":{\"a\":1},\"c\":[{\"a\":1},{\"a\":2}]}",
        ] {
            assert!(three_ways(text).is_ok(), "{:?}", text);
        }
        // The errors, with where they are found.
        for (text, offset, message) in [
            ("", 0, "unexpected end of input"),
            ("  ", 2, "unexpected end of input"),
            ("x", 0, "unexpected character"),
            ("tru", 0, "invalid literal"),
            ("nul", 0, "invalid literal"),
            ("-", 1, "invalid number"),
            ("1.", 2, "invalid number"),
            ("1e", 2, "invalid number"),
            ("1e999", 5, "number out of range"),
            ("01", 1, "trailing characters"),
            ("\"abc", 4, "unterminated string"),
            ("\"a\\", 3, "unterminated string"),
            ("\"a\u{1}\"", 2, "control character in string"),
            ("\"\\x\"", 3, "invalid escape"),
            ("\"\\u12\"", 3, "truncated unicode escape"),
            ("\"\\u12x4\"", 3, "invalid unicode escape"),
            ("\"\\ud83d\"", 7, "unpaired surrogate"),
            ("\"\\ud83d\\u0041\"", 13, "unpaired surrogate"),
            ("\"\\ude00\"", 7, "unpaired surrogate"),
            ("[1,]", 3, "unexpected character"),
            ("[1 2]", 3, "expected ',' or ']'"),
            ("[1", 2, "expected ',' or ']'"),
            ("{\"a\":1,}", 7, "expected a string key"),
            ("{a:1}", 1, "expected a string key"),
            ("{\"a\" 1}", 5, "unexpected character"),
            ("{\"a\":1 \"b\":2}", 7, "expected ',' or '}'"),
            ("{\"a\":}", 5, "unexpected character"),
            ("[1] x", 4, "trailing characters"),
            ("{\"a\":1,\"a\":2}", 12, "duplicate key"),
            ("{\"a\":1,\"\\u0061\":[1, 2] ,\"b\":3}", 22, "duplicate key"),
            // What is wrong inside the value of a repeated key comes first.
            ("{\"a\":1,\"a\":[}", 12, "unexpected character"),
            ("{\"a\":1,\"a\":{\"b\":1,\"b\":2},\"c\":}", 23, "duplicate key"),
            // The same key in another object is no duplicate.
            ("{\"a\":{\"a\":1},\"b\":[{\"a\":1}],\"a\":2}", 32, "duplicate key"),
        ] {
            assert_eq!(three_ways(text), Err(ParseError { offset, message }), "{:?}", text);
        }
    }

    #[test]
    fn parser_limits_nesting() {
        // A value has at most MAX_DEPTH arrays and objects around it.
        for (open, close) in [("[", "]"), ("{\"k\":", "}")] {
            let nested = |n: usize, inner: &str| format!("{}{}{}", open.repeat(n), inner, close.repeat(n));
            assert!(three_ways(&nested(MAX_DEPTH, "1")).is_ok());
            assert!(three_ways(&nested(MAX_DEPTH, "[]")).is_ok());
            assert!(three_ways(&nested(MAX_DEPTH, "{}")).is_ok());
            for inner in ["1", "[]", "{}"] {
                let e = three_ways(&nested(MAX_DEPTH + 1, inner)).unwrap_err();
                assert_eq!(e.message, "nesting too deep", "{}", inner);
                assert_eq!(e.offset, open.len() * (MAX_DEPTH + 1));
            }
        }
    }

    #[test]
    fn parser_finds_duplicates_in_wide_and_nested_objects() {
        // Objects inside each other share the keys the parser has at hand.
        // An object that finds no room there, or has more keys than are
        // looked through, is checked all the same.
        let members = |prefix: &str, n: usize| -> String {
            (0..n)
                .map(|i| format!("\"{}{}\":{}", prefix, i, i))
                .collect::<Vec<_>>()
                .join(",")
        };
        for outer in [0, 1, SCAN_UP_TO - 1, SCAN_UP_TO, SCAN_UP_TO + 1, 3 * SCAN_UP_TO] {
            for inner in [1, 2, SCAN_UP_TO - 1, SCAN_UP_TO, SCAN_UP_TO + 1, 3 * SCAN_UP_TO] {
                let comma = if outer > 0 { "," } else { "" };
                let unique = format!(
                    "{{{}{}\"in\":{{{}}},\"last\":[{{{}}}]}}",
                    members("o", outer),
                    comma,
                    members("i", inner),
                    members("i", inner)
                );
                let value = three_ways(&unique).unwrap();
                assert_eq!(parse(&value).unwrap().as_object().unwrap().len(), outer + 2);
                for at in [0, inner / 2, inner - 1] {
                    let repeated = format!(
                        "{{{}{}\"in\":{{{},\"i{}\":0}}}}",
                        members("o", outer),
                        comma,
                        members("i", inner),
                        at
                    );
                    assert_eq!(three_ways(&repeated).unwrap_err().message, "duplicate key");
                }
                if outer > 0 {
                    // The outer object still knows its keys after the inner one.
                    let repeated = format!(
                        "{{{},\"in\":{{{}}},\"o{}\":0}}",
                        members("o", outer),
                        members("i", inner),
                        outer - 1
                    );
                    assert_eq!(three_ways(&repeated).unwrap_err().message, "duplicate key");
                }
            }
        }
    }

    #[test]
    fn parser_knows_keys_written_with_an_escape() {
        // A key with an escape is the key it stands for.
        for text in [
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"a":1,"a":2}"#,
            r#"{"a\n":1,"b":2,"a\u000a":3}"#,
            r#"{"x":{"a":1,"b":2,"a":3}}"#,
            r#"{"a":1,"x":{"b":1},"a":2}"#,
            r#"{"a":1,"x":{"b":1,"c":{}},"a":2}"#,
        ] {
            assert_eq!(three_ways(text).unwrap_err().message, "duplicate key", "{}", text);
        }
        for text in [
            r#"{"a":1,"b":2}"#,
            r#"{"a":1,"b":2,"c":3}"#,
            r#"{"a":{"a":{"a":1}},"b":{"a":1,"b":2},"c":[{"a":1,"b":2}]}"#,
        ] {
            assert!(three_ways(text).is_ok(), "{}", text);
        }
        // With many keys around it, before the object has a set and after.
        for plain in [0, 1, SCAN_UP_TO - 1, SCAN_UP_TO, SCAN_UP_TO + 1, 3 * SCAN_UP_TO] {
            let keys: Vec<String> = (0..plain).map(|i| format!("\"k{}\":{}", i, i)).collect();
            for at in [0, plain / 2, plain] {
                let mut members = keys.clone();
                members.insert(at, r#""k":0"#.to_string());
                assert!(three_ways(&format!("{{{}}}", members.join(","))).is_ok());
                for repeated in [r#""k":1"#, r#""k":1"#] {
                    for again in [0, members.len() / 2, members.len()] {
                        let mut members = members.clone();
                        members.insert(again, repeated.to_string());
                        let text = format!("{{{}}}", members.join(","));
                        assert_eq!(three_ways(&text).unwrap_err().message, "duplicate key", "{}", text);
                    }
                }
            }
        }
    }

    #[test]
    fn parser_finds_the_end_of_a_string() {
        // What a string can hold, some of it one bit away from what ends
        // it: 0xa2 and 0xdc are a quote and a backslash with the high bit
        // set, and 0x9f is a control character with it.
        let fillers = [
            "a",
            " ",
            "!",
            "#",
            "[",
            "]",
            "\x7f",
            "\u{e9}",
            "\u{a2}",
            "\u{9f}",
            "\u{70c}",
            "\u{20ac}",
            "\u{1f600}",
        ];
        for filler in fillers {
            for before in 0..(3 * Word::SIZE + 2) {
                let plain = filler.repeat(before);
                for behind in ["", "x", "tail of the text"] {
                    // The string ends at its quote, whatever follows.
                    let text = format!("[\"{}\",\"{}\"]", plain, behind);
                    let expected = Value::Array(vec![Value::from(plain.as_str()), Value::from(behind)]);
                    assert_eq!(three_ways(&text), Ok(expected.to_string()), "{:?}", text);
                    let mut p = Parser::new(&text);
                    assert_eq!(p.array(), Ok(true));
                    assert_eq!(p.element(), Ok(true));
                    assert!(matches!(p.string(), Ok(Some(Cow::Borrowed(s))) if s == plain));
                    // An escape, anywhere.
                    let text = format!("\"{}\\n{}\\\"{}\\\\\"", plain, behind, plain);
                    let expected = format!("{}\n{}\"{}\\", plain, behind, plain);
                    assert_eq!(
                        three_ways(&text),
                        Ok(Value::from(expected.as_str()).to_string()),
                        "{:?}",
                        text
                    );
                    // A control character, anywhere.
                    for control in ["\0", "\x01", "\n", "\x1f"] {
                        let text = format!("\"{}{}{}\"", plain, control, behind);
                        let e = ParseError {
                            offset: 1 + plain.len(),
                            message: "control character in string",
                        };
                        assert_eq!(three_ways(&text), Err(e), "{:?}", text);
                    }
                    // No end at all.
                    let text = format!("\"{}{}", plain, behind);
                    let e = ParseError {
                        offset: text.len(),
                        message: "unterminated string",
                    };
                    assert_eq!(three_ways(&text), Err(e), "{:?}", text);
                }
            }
        }
        // Every byte a word can have in every place of it.
        for byte in 0..=u8::MAX {
            for at in 0..Word::SIZE {
                let mut bytes = [b'a'; Word::SIZE];
                bytes[at] = byte;
                let special = byte == QUOTE || byte == ESCAPE || byte < FIRST_PRINTABLE;
                assert_eq!(
                    Word::new(bytes).first_special(),
                    special.then_some(at),
                    "{:#x} at {}",
                    byte,
                    at
                );
                // The first of two is the one that is found.
                for second in [QUOTE, ESCAPE, 0, FIRST_PRINTABLE - 1, FIRST_PRINTABLE, 0x80, u8::MAX] {
                    for behind in at + 1..Word::SIZE {
                        let mut bytes = bytes;
                        bytes[behind] = second;
                        let first = if special {
                            Some(at)
                        } else {
                            (second == QUOTE || second == ESCAPE || second < FIRST_PRINTABLE).then_some(behind)
                        };
                        assert_eq!(Word::new(bytes).first_special(), first);
                    }
                }
            }
        }
    }

    #[test]
    fn parser_reads_numbers_of_any_length() {
        let mut texts: Vec<String> = Vec::new();
        for digits in 1..=45 {
            texts.push("9".repeat(digits));
            texts.push(format!("1{}", "0".repeat(digits - 1)));
            texts.push(format!("1{}7", "0".repeat(digits - 1)));
        }
        for near in [u128::from(u64::MAX), i128::MAX as u128, i128::MAX as u128 + 1] {
            for value in [near - 1, near, near + 1, near + 2] {
                texts.push(value.to_string());
            }
        }
        for text in texts {
            for text in [text.clone(), format!("-{}", text)] {
                // An integer that fits into 128 bits is exact. A larger one
                // is the nearest float.
                let expected = match text.parse::<i128>() {
                    Ok(i) => Value::Int(i),
                    Err(_) => Value::Float(text.parse().unwrap()),
                };
                assert_eq!(parse(&text), Ok(expected.clone()), "{}", text);
                assert_eq!(three_ways(&text), Ok(expected.to_string()), "{}", text);
                let mut p = Parser::new(&text);
                let number = p.number().unwrap().unwrap();
                assert_eq!(number.as_u64(), text.parse::<u64>().ok(), "{}", text);
                assert_eq!(number.as_i64(), text.parse::<i64>().ok(), "{}", text);
                // With a fraction or an exponent it is a float.
                for float in [format!("{}.0", text), format!("{}e0", text), format!("{}.5E+1", text)] {
                    let expected = Value::Float(float.parse().unwrap());
                    assert_eq!(parse(&float), Ok(expected), "{}", float);
                    assert!(three_ways(&float).is_ok(), "{}", float);
                }
            }
        }
    }
}
