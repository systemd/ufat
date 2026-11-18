// SPDX-License-Identifier: LGPL-2.1-or-later
//! A small, strict JSON implementation: a value type, an RFC 8259 parser and
//! a compact serializer.
//!
//! [`parse`] reads a text into a [`Value`], and a `Value` prints itself as
//! compact text. [`Parser`] reads a text value by value, and
//! [`ObjectWriter`] and [`ArrayWriter`] write one member by member, for a
//! caller that has types of its own and does not want a `Value` in between.
//!
//! Numbers keep their nature: anything written without a fraction or an
//! exponent that fits into 128 bits stays an integer, so 64-bit sizes and
//! offsets survive a round trip exactly. -0 is a float, since an integer has
//! no negative zero. Objects keep their insertion order and refuse duplicate
//! keys.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt::{self, Write as _};
use std::str::FromStr;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// A number without fraction or exponent, other than -0.
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
    /// Whether the text is not JSON, has a key twice in an object, or
    /// breaks a rule of the parser.
    pub kind: ParseErrorKind,
}

/// What kind of error a [`ParseError`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ParseErrorKind {
    /// The text is not JSON.
    Syntax,
    /// An object has a key twice. RFC 8259 leaves open what such an object
    /// means, and the parser refuses it.
    DuplicateKey,
    /// A string breaks one of the [`StringRules`] the parser was made with.
    StringRule,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// Nesting deeper than this is refused, to bound stack use. A value that
/// [`Parser::skip`] passes over can be nested deeper.
const MAX_DEPTH: usize = 128;

/// The most arrays and objects a parser is inside of at once: the value at
/// the top and one at every level of nesting below it.
const MAX_OPEN: usize = MAX_DEPTH + 1;

/// How many keys the set of an object has room for from the start, about
/// as many as an object of a manifest has. A set that grows hashes all its
/// keys again.
const OBJECT_KEYS: usize = 8;

/// Eight bytes of a text in one integer, the first of them in its lowest
/// bits. A string is searched for its end a word at a time: std has no
/// search for any of several bytes, and looking at one byte after the
/// other takes four times as long on a long string.
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

    /// How many bytes at the start of `bytes` are what RFC 8259 calls
    /// unescaped, bytes that stand for themselves in a string: all up to
    /// the first quote, backslash or control character.
    fn unescaped_len(bytes: &[u8]) -> usize {
        let mut rest = bytes;
        while let Some((word, behind)) = rest.split_first_chunk() {
            if let Some(at) = Word::new(*word).first_special() {
                return bytes.len() - rest.len() + at;
            }
            rest = behind;
        }
        let unescaped = |b: &&u8| **b != QUOTE && **b != ESCAPE && **b >= FIRST_PRINTABLE;
        bytes.len() - rest.len() + rest.iter().take_while(unescaped).count()
    }
}

/// The first byte of a string and its last.
const QUOTE: u8 = b'"';
/// The byte that starts an escape inside a string.
const ESCAPE: u8 = b'\\';
/// The bytes below this one are control characters. A string has to
/// escape them.
const FIRST_PRINTABLE: u8 = 0x20;
/// What a `\u` escape starts with, and how many hex digits follow: one
/// UTF-16 unit.
const UNICODE_ESCAPE: &str = "\\u";
const UNICODE_ESCAPE_DIGITS: usize = 4;
/// The control characters with an escape of a letter of their own, besides
/// newline, carriage return and tab.
const BACKSPACE: u8 = 0x08;
const FORM_FEED: u8 = 0x0c;
/// The base of those digits, and the bits of one of them.
const HEX: u32 = 16;
const HEX_DIGIT_BITS: u32 = 4;
/// The UTF-16 units that are the first half of a pair, the high
/// surrogates. A `\u` escape of one has to be followed by one of the low
/// surrogate that completes it.
const HIGH_SURROGATES: std::ops::Range<u16> = 0xD800..0xDC00;
/// The structural characters, as RFC 8259 names them: what begins and ends
/// an array and an object, and what follows the name of a member and a
/// value.
const BEGIN_ARRAY: u8 = b'[';
const END_ARRAY: u8 = b']';
const BEGIN_OBJECT: u8 = b'{';
const END_OBJECT: u8 = b'}';
const NAME_SEPARATOR: u8 = b':';
const VALUE_SEPARATOR: u8 = b',';

/// Whether `b` is what RFC 8259 calls whitespace: space, tab, newline
/// and carriage return. Form feed is not, unlike for
/// `u8::is_ascii_whitespace`.
pub const fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

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
/// into 128 bits is an integer, other than -0, which only a float can hold.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Number {
    /// A number without fraction or exponent, other than -0.
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

/// What the strings of a text may not hold beyond what JSON forbids.
///
/// JSON lets a string hold any Unicode scalar value. Formats built on JSON
/// often rule out more, and a [`Parser`] made with
/// [`Parser::with_rules`] refuses those strings, keys included, however
/// they are written: as they are or with escapes.
///
/// ```
/// use json::{Parser, StringRules};
///
/// let mut parser = Parser::with_rules(r#""a\u0000b""#, StringRules::NO_NUL);
/// assert_eq!(parser.string().unwrap_err().message, "NUL in string");
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct StringRules(u8);

impl StringRules {
    /// No noncharacter, as I-JSON (RFC 7493) asks: U+FDD0 to U+FDEF and
    /// the last two code points of every plane, U+FFFE and U+FFFF, U+1FFFE
    /// and U+1FFFF and so on.
    pub const NO_NONCHARACTERS: StringRules = StringRules(1 << 0);
    /// No NUL character, which JSON only lets a string have as `\u0000`.
    pub const NO_NUL: StringRules = StringRules(1 << 1);
    /// No rule beyond those of JSON.
    pub const NONE: StringRules = StringRules(0);

    /// Whether every rule of `rules` is among these.
    pub const fn contains(self, rules: StringRules) -> bool {
        self.0 & rules.0 == rules.0
    }

    /// These rules and those of `rules`.
    pub const fn union(self, rules: StringRules) -> StringRules {
        StringRules(self.0 | rules.0)
    }

    /// These rules but those of `rules`.
    pub const fn without(self, rules: StringRules) -> StringRules {
        StringRules(self.0 & !rules.0)
    }

    /// Whether the string `s` keeps to these rules.
    pub fn admits(self, s: &str) -> bool {
        self.broken_in(s).is_none()
    }

    /// Which of these rules the string `s` breaks first, if one.
    fn broken_in(self, s: &str) -> Option<&'static str> {
        if self == StringRules::NONE {
            return None;
        }
        // A string without a byte as high as NONCHARACTER_LEAD has no
        // noncharacter, so only a NUL can break a rule. Such bytes are
        // looked for many at a time: by is_ascii, the cheapest look for
        // ASCII strings, which most are, and by a fold without an early
        // end, which the compiler turns into vector instructions. A look at
        // every character takes about fifteen instructions for each.
        let lead = !s.is_ascii() && s.bytes().fold(false, |lead, b| lead | (b >= NONCHARACTER_LEAD));
        if lead {
            s.chars().find_map(|c| self.broken_by(c))
        } else {
            (self.contains(StringRules::NO_NUL) && s.contains(NUL)).then_some(NUL_IN_STRING)
        }
    }

    /// Whether a string holding `c` breaks one of these rules, and which.
    fn broken_by(self, c: char) -> Option<&'static str> {
        if c == NUL && self.contains(StringRules::NO_NUL) {
            Some(NUL_IN_STRING)
        } else if self.contains(StringRules::NO_NONCHARACTERS) && is_noncharacter(c) {
            Some("noncharacter in string")
        } else {
            None
        }
    }
}

/// The character [`StringRules::NO_NUL`] rules out, and what a string that
/// holds it is told.
const NUL: char = '\0';
const NUL_IN_STRING: &str = "NUL in string";

impl std::ops::BitOr for StringRules {
    type Output = StringRules;

    fn bitor(self, rules: StringRules) -> StringRules {
        self.union(rules)
    }
}

/// The noncharacters that are not at the end of a plane.
const NONCHARACTER_BLOCK: std::ops::RangeInclusive<u32> = 0xFDD0..=0xFDEF;
/// The bits that are set in the last two code points of every plane, and
/// only in them.
const PLANE_END: u32 = 0xFFFE;
/// The first byte of the lowest noncharacter in UTF-8. Higher characters
/// start with the same byte or a higher one, and no byte after the first
/// one of a character is as high, so a string without it has none.
const NONCHARACTER_LEAD: u8 = match char::from_u32(*NONCHARACTER_BLOCK.start()) {
    Some(lowest) => lowest.encode_utf8(&mut [0; 4]).as_bytes()[0],
    None => panic!("the lowest noncharacter is a character"),
};

/// Whether `c` is a noncharacter, a code point Unicode keeps for use
/// inside a program.
fn is_noncharacter(c: char) -> bool {
    let code = u32::from(c);
    NONCHARACTER_BLOCK.contains(&code) || code & PLANE_END == PLANE_END
}

/// An array or an object the parser is inside of.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Container {
    /// An array.
    Array,
    /// An object.
    Object,
}

/// The keys of the objects a parser is inside of, a set for each of them.
/// The set of an object the parser left is emptied and taken again for the
/// next object that is inside of as many objects. So a text needs as many
/// sets as the most objects the parser is inside of at once, and not one
/// for every object. The set of the outermost object is kept apart, so that
/// a text whose objects are not nested needs that set and nothing more.
///
/// Emptying a set that has keys takes time in proportion to its capacity,
/// and an emptied set keeps its capacity. So a set that grew past the
/// capacity for [`OBJECT_KEYS`] keys is shrunk back to it when it is
/// emptied. Otherwise every object that takes the set after a large one
/// would pay for the capacity of the large one.
#[derive(Default)]
struct Keys<'a> {
    /// How many objects the parser is inside of.
    objects: usize,
    /// The keys of the outermost object the parser is inside of.
    outermost: HashSet<Cow<'a, str>>,
    /// The keys of the objects inside of that one, outermost first, and
    /// behind them emptied sets kept for later objects.
    inner: Vec<HashSet<Cow<'a, str>>>,
}

impl<'a> Keys<'a> {
    /// The set of the innermost object the parser is inside of.
    fn innermost(&mut self) -> Option<&mut HashSet<Cow<'a, str>>> {
        match self.objects {
            0 => None,
            1 => Some(&mut self.outermost),
            objects => self.inner.get_mut(objects - 2),
        }
    }

    /// Takes a set for the keys of an object the parser goes into.
    fn open(&mut self) {
        if self.objects > self.inner.len() {
            self.inner.push(HashSet::new());
        }
        self.objects += 1;
        if let Some(keys) = self.innermost() {
            keys.reserve(OBJECT_KEYS);
        }
    }

    /// Empties the set of the innermost object, which the parser left.
    fn close(&mut self) {
        if let Some(keys) = self.innermost() {
            keys.clear();
            keys.shrink_to(OBJECT_KEYS);
        }
        self.objects -= 1;
    }

    /// Notes `key` as a key of the innermost object. Returns false when
    /// that object had the key before.
    fn insert(&mut self, key: Cow<'a, str>) -> bool {
        self.innermost().is_some_and(|keys| keys.insert(key))
    }
}

/// An array or an object that [`Parser::skip`] is inside of.
#[derive(Clone, Copy)]
enum SkippedContainer {
    /// An array.
    Array,
    /// An object, with where it starts in the text. That tells it apart
    /// from the other objects.
    Object(usize),
}

/// What [`Parser::skip`] keeps of the value it reads. The value can be
/// nested to any depth, so the keys of all of its objects go into one set,
/// each with where its object starts, and not into a set for each object.
/// The parser keeps it from one value to the next and empties it in
/// between, the way [`Keys`] empties its sets.
#[derive(Default)]
struct SkippedValue<'a> {
    /// The arrays and objects the parser is inside of, outermost first.
    containers: Vec<SkippedContainer>,
    /// The keys of the objects so far, each with where its object starts.
    keys: HashSet<(usize, Cow<'a, str>)>,
}

impl SkippedValue<'_> {
    /// Goes into the object that starts at `start`, with room for as many
    /// more keys as an object of a manifest has.
    fn open_object(&mut self, start: usize) {
        self.keys.reserve(OBJECT_KEYS);
        self.containers.push(SkippedContainer::Object(start));
    }

    /// Forgets the value it was kept for. A set of keys that grew past the
    /// capacity for [`OBJECT_KEYS`] keys is shrunk back to it.
    fn clear(&mut self) {
        self.containers.clear();
        self.keys.clear();
        self.keys.shrink_to(OBJECT_KEYS);
    }
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
/// takes, and the other way around. Only what [`Parser::skip`] passes over
/// can be more: numbers too large for a float and arrays and objects nested
/// deeper than [`parse`] takes them.
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
    levels: [Container; MAX_OPEN],
    depth: usize,
    /// Whether the innermost of them has no member so far.
    empty: bool,
    /// The keys of the objects the parser is inside of.
    keys: Keys<'a>,
    /// What [`Parser::skip`] keeps of the value it reads.
    skipped: SkippedValue<'a>,
    /// What strings may not hold beyond what JSON forbids.
    rules: StringRules,
}

impl<'a> Parser<'a> {
    /// A parser in front of the value `text` holds.
    pub fn new(text: &'a str) -> Parser<'a> {
        Parser::with_rules(text, StringRules::NONE)
    }

    /// A parser in front of the value `text` holds that refuses strings
    /// which break `rules`.
    pub fn with_rules(text: &'a str, rules: StringRules) -> Parser<'a> {
        Parser {
            text,
            pos: 0,
            levels: [Container::Array; MAX_OPEN],
            depth: 0,
            empty: false,
            keys: Keys::default(),
            skipped: SkippedValue::default(),
            rules,
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
            kind: ParseErrorKind::Syntax,
        }
    }

    fn bytes(&self) -> &'a [u8] {
        self.text.as_bytes()
    }

    fn skip_whitespace(&mut self) {
        while self.byte().is_some_and(is_whitespace) {
            self.pos += 1;
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
            Some(BEGIN_OBJECT) => Ok(Kind::Object),
            Some(BEGIN_ARRAY) => Ok(Kind::Array),
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

    /// Moves over the number the parser stands in front of, which has to
    /// keep to JSON's grammar, and returns its text and whether it has a
    /// fraction or an exponent.
    // Inlined into number_token(), which every number goes through.
    #[inline(always)]
    fn number_text(&mut self) -> Result<(&'a str, bool), ParseError> {
        let start = self.pos;
        if self.byte() == Some(b'-') {
            self.pos += 1;
        }
        // JSON's grammar is checked here: std's parsers would also take a
        // plus sign, leading zeros, "inf" and "NaN".
        match self.byte() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
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
        Ok((&self.text[start..self.pos], is_float))
    }

    /// Reads the number the parser stands in front of.
    fn number_token(&mut self) -> Result<Number, ParseError> {
        let (text, is_float) = self.number_text()?;
        // What is too large for an integer is a float, and so is -0,
        // which an integer would turn into 0.
        if !is_float {
            match text.parse::<i128>() {
                Ok(0) if text.starts_with('-') => {}
                Ok(i) => return Ok(Number::Int(i)),
                Err(_) => {}
            }
        }
        let f: f64 = text.parse().map_err(|_| self.error("invalid number"))?;
        if !f.is_finite() {
            return Err(self.error("number out of range"));
        }
        Ok(Number::Float(f))
    }

    /// Reads the hex digits of a `\u` escape, the UTF-16 unit they spell.
    fn hex4(&mut self) -> Result<u16, ParseError> {
        let digits = self
            .bytes()
            .get(self.pos..self.pos + UNICODE_ESCAPE_DIGITS)
            .ok_or_else(|| self.error("truncated unicode escape"))?;
        // Four hex digits always fit into a unit.
        let unit = digits
            .iter()
            .try_fold(0, |unit, &digit| {
                Some((unit << HEX_DIGIT_BITS) | char::from(digit).to_digit(HEX)?)
            })
            .and_then(|unit| u16::try_from(unit).ok())
            .ok_or_else(|| self.error("invalid unicode escape"))?;
        self.pos += UNICODE_ESCAPE_DIGITS;
        Ok(unit)
    }

    /// Moves over the unescaped bytes of a string, those that stand for
    /// themselves, up to the next quote, backslash or control character.
    fn skip_unescaped(&mut self) {
        self.pos += Word::unescaped_len(&self.bytes()[self.pos..]);
    }

    /// Reads the string the parser stands in front of. A string without
    /// an escape is a part of the text.
    fn string_token(&mut self) -> Result<Cow<'a, str>, ParseError> {
        self.expect(QUOTE)?;
        let start = self.pos;
        self.skip_unescaped();
        if self.byte() == Some(QUOTE) {
            let unescaped = &self.text[start..self.pos];
            self.pos += 1;
            // The unescaped run ends at every control character, so only an
            // escape can put a NUL into a string.
            self.check_rules(unescaped, self.rules.without(StringRules::NO_NUL))?;
            return Ok(Cow::Borrowed(unescaped));
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
                        b'b' => out.push(char::from(BACKSPACE)),
                        b'f' => out.push(char::from(FORM_FEED)),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let unit = self.hex4()?;
                            // A high surrogate and the low one that follows it are
                            // one character. No other surrogate is one.
                            let c = if HIGH_SURROGATES.contains(&unit) {
                                if !self.bytes()[self.pos..].starts_with(UNICODE_ESCAPE.as_bytes()) {
                                    return Err(self.error("unpaired surrogate"));
                                }
                                self.pos += UNICODE_ESCAPE.len();
                                char::decode_utf16([unit, self.hex4()?]).next().and_then(Result::ok)
                            } else {
                                char::from_u32(u32::from(unit))
                            };
                            out.push(c.ok_or_else(|| self.error("unpaired surrogate"))?);
                        }
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                Some(_) => return Err(self.error("control character in string")),
            }
            let start = self.pos;
            self.skip_unescaped();
            out.push_str(&self.text[start..self.pos]);
        }
        self.check_rules(&out, self.rules)?;
        Ok(Cow::Owned(out))
    }

    /// Fails if the string `s` breaks one of `rules`, rules of the parser.
    fn check_rules(&self, s: &str, rules: StringRules) -> Result<(), ParseError> {
        match rules.broken_in(s) {
            Some(message) => Err(ParseError {
                kind: ParseErrorKind::StringRule,
                ..self.error(message)
            }),
            None => Ok(()),
        }
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
    fn enter(&mut self, container: Container) {
        self.pos += 1;
        self.levels[self.depth] = container;
        if container == Container::Object {
            self.keys.open();
        }
        self.depth += 1;
        self.empty = true;
    }

    /// Leaves the innermost array or object, whose end was read.
    fn leave(&mut self) {
        self.depth -= 1;
        if self.levels[self.depth] == Container::Object {
            self.keys.close();
        }
        self.empty = false;
    }

    /// Goes into the value if it is an array, and says whether it is one.
    /// [`Parser::element`] is to be asked before every element then.
    pub fn array(&mut self) -> Result<bool, ParseError> {
        if self.peek()? != Kind::Array {
            return Ok(false);
        }
        self.enter(Container::Array);
        Ok(true)
    }

    /// Whether the array the parser is in has another element. The parser
    /// stands in front of it then. Otherwise it has left the array.
    pub fn element(&mut self) -> Result<bool, ParseError> {
        debug_assert!(self.depth > 0 && self.levels[self.depth - 1] == Container::Array);
        let first = std::mem::replace(&mut self.empty, false);
        let more = self.next_element(first)?;
        if !more {
            self.leave();
        }
        Ok(more)
    }

    /// Moves on in an array, at its start if `first`: over the comma in
    /// front of the next element, or over the bracket that ends the array.
    /// Says whether an element follows.
    fn next_element(&mut self, first: bool) -> Result<bool, ParseError> {
        self.skip_whitespace();
        match self.byte() {
            Some(END_ARRAY) => {
                self.pos += 1;
                Ok(false)
            }
            _ if first => Ok(true),
            Some(VALUE_SEPARATOR) => {
                self.pos += 1;
                Ok(true)
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
        self.enter(Container::Object);
        Ok(true)
    }

    /// The key of the next member of the object the parser is in. The
    /// parser stands in front of the member's value then. Without another
    /// member it has left the object. A key the object had before is an
    /// error of the kind [`ParseErrorKind::DuplicateKey`], which is
    /// reported right behind the key.
    pub fn key(&mut self) -> Result<Option<Cow<'a, str>>, ParseError> {
        debug_assert!(self.depth > 0 && self.levels[self.depth - 1] == Container::Object);
        let first = std::mem::replace(&mut self.empty, false);
        let Some(key) = self.member(first)? else {
            self.leave();
            return Ok(None);
        };
        if !self.keys.insert(key.clone()) {
            return Err(self.duplicate_key());
        }
        self.name_separator()?;
        Ok(Some(key))
    }

    /// The error for a key that the object it is in had before, found
    /// right behind the key.
    fn duplicate_key(&self) -> ParseError {
        ParseError {
            kind: ParseErrorKind::DuplicateKey,
            ..self.error("duplicate key")
        }
    }

    /// Moves on in an object, at its start if `first`: over the comma in
    /// front of the next member and over its key, which it returns, or over
    /// the brace that ends the object.
    // Inlined into key(), which every member of every object goes through.
    #[inline(always)]
    fn member(&mut self, first: bool) -> Result<Option<Cow<'a, str>>, ParseError> {
        self.skip_whitespace();
        match self.byte() {
            Some(END_OBJECT) => {
                self.pos += 1;
                return Ok(None);
            }
            _ if first => {}
            Some(VALUE_SEPARATOR) => {
                self.pos += 1;
                self.skip_whitespace();
            }
            _ => return Err(self.error("expected ',' or '}'")),
        }
        if self.byte() != Some(QUOTE) {
            return Err(self.error("expected a string key"));
        }
        self.string_token().map(Some)
    }

    /// Moves over the colon between the key of a member and its value.
    fn name_separator(&mut self) -> Result<(), ParseError> {
        self.skip_whitespace();
        self.expect(NAME_SEPARATOR)
    }

    /// Reads the value, whatever kind it is. What it reads is held to
    /// JSON's grammar and nothing more: a number is not converted, so it can
    /// be of any size, and arrays and objects can be nested to any depth.
    /// Strings, keys among them, are read as everywhere else, and a key
    /// twice in an object is an error.
    pub fn skip(&mut self) -> Result<(), ParseError> {
        let skipped = self.skip_value();
        self.skipped.clear();
        skipped
    }

    /// Reads the value for [`Parser::skip`], with what that keeps.
    fn skip_value(&mut self) -> Result<(), ParseError> {
        // The arrays and objects of the value are not recursed into, so
        // their depth is not limited.
        loop {
            let kind = self.peek()?;
            match kind {
                Kind::Null => self.literal("null")?,
                Kind::Bool => self.bool_token().map(drop)?,
                Kind::Number => self.number_text().map(drop)?,
                Kind::String => self.string_token().map(drop)?,
                Kind::Array => self.skipped.containers.push(SkippedContainer::Array),
                Kind::Object => self.skipped.open_object(self.pos),
            }
            // Into the array or object that starts here, or out of what
            // ends here, up to the next value.
            let mut first = matches!(kind, Kind::Array | Kind::Object);
            if first {
                self.pos += 1;
            }
            loop {
                let Some(&innermost) = self.skipped.containers.last() else {
                    return Ok(());
                };
                if self.next_skipped(innermost, first)? {
                    break;
                }
                self.skipped.containers.pop();
                first = false;
            }
        }
    }

    /// Moves on in `innermost`, the innermost of the arrays and objects
    /// [`Parser::skip`] is inside of, at its start if `first`: over what
    /// comes in front of its next value, or over its end. Says whether a
    /// value follows.
    fn next_skipped(&mut self, innermost: SkippedContainer, first: bool) -> Result<bool, ParseError> {
        let SkippedContainer::Object(object) = innermost else {
            return self.next_element(first);
        };
        let Some(key) = self.member(first)? else {
            return Ok(false);
        };
        if !self.skipped.keys.insert((object, key)) {
            return Err(self.duplicate_key());
        }
        self.name_separator()?;
        Ok(true)
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
                self.enter(Container::Array);
                let mut items = Vec::new();
                while self.element()? {
                    items.push(self.value()?);
                }
                Value::Array(items)
            }
            Kind::Object => {
                self.enter(Container::Object);
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

/// Writes the inside of the JSON string for `s`: the runs between escapes
/// as they are, and an escape for every character that needs one.
fn escape<W: fmt::Write + ?Sized>(out: &mut W, s: &str) -> fmt::Result {
    let bytes = s.as_bytes();
    // Where the current unescaped run starts.
    let mut unescaped = 0;
    loop {
        let at = unescaped + Word::unescaped_len(&bytes[unescaped..]);
        let Some(&b) = bytes.get(at) else {
            return out.write_str(&s[unescaped..]);
        };
        out.write_str(&s[unescaped..at])?;
        match b {
            QUOTE => out.write_str("\\\"")?,
            ESCAPE => out.write_str("\\\\")?,
            b'\n' => out.write_str("\\n")?,
            b'\r' => out.write_str("\\r")?,
            b'\t' => out.write_str("\\t")?,
            BACKSPACE => out.write_str("\\b")?,
            FORM_FEED => out.write_str("\\f")?,
            _ => write!(out, "{}{:0digits$x}", UNICODE_ESCAPE, b, digits = UNICODE_ESCAPE_DIGITS)?,
        }
        unescaped = at + 1;
    }
}

/// Writes `s` as a JSON string.
fn write_string<W: fmt::Write + ?Sized>(out: &mut W, s: &str) -> fmt::Result {
    out.write_char('"')?;
    escape(out, s)?;
    out.write_char('"')
}

/// Appends `s` to `out` as a JSON string.
fn push_string(out: &mut String, s: &str) {
    write_string(out, s).expect("a String takes any write");
}

impl fmt::Display for Value {
    /// Compact serialization without any whitespace.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => f.write_str("null"),
            Value::Bool(b) => f.write_str(if *b { "true" } else { "false" }),
            Value::Int(i) => write!(f, "{}", i),
            // Debug writes the shortest text that reads back as the same
            // float, and always one that reads back as a float.
            Value::Float(x) if x.is_finite() => write!(f, "{:?}", x),
            Value::Float(_) => f.write_str("null"),
            Value::String(s) => write_string(f, s),
            Value::Array(a) => {
                f.write_char('[')?;
                for (i, item) in a.iter().enumerate() {
                    if i > 0 {
                        f.write_char(',')?;
                    }
                    item.fmt(f)?;
                }
                f.write_char(']')
            }
            Value::Object(o) => o.fmt(f),
        }
    }
}

impl fmt::Display for Object {
    /// Compact serialization without any whitespace.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char('{')?;
        for (i, (k, item)) in self.iter().enumerate() {
            if i > 0 {
                f.write_char(',')?;
            }
            write_string(f, k)?;
            f.write_char(':')?;
            item.fmt(f)?;
        }
        f.write_char('}')
    }
}

/// Writes a JSON object into a string member by member, without a
/// [`Value`] in between. The object is closed when the writer is dropped.
///
/// A member is written together with its value, so a member whose value
/// is never written is left out:
///
/// ```
/// let mut text = String::new();
/// let mut object = json::ObjectWriter::new(&mut text);
/// object.key("name").string("a\"b");
/// object.key("sizes").array().element().unsigned(3);
/// let label: Option<&str> = None;
/// let value = object.key("label");
/// if let Some(label) = label {
///     value.string(label);
/// }
/// drop(object);
/// assert_eq!(text, r#"{"name":"a\"b","sizes":[3]}"#);
/// ```
#[derive(Debug)]
pub struct ObjectWriter<'a> {
    out: &'a mut String,
    /// Whether a member was written, so the next one needs a comma.
    members: bool,
}

impl<'a> ObjectWriter<'a> {
    /// Opens an object at the end of `out`.
    pub fn new(out: &'a mut String) -> ObjectWriter<'a> {
        out.push('{');
        ObjectWriter { out, members: false }
    }

    /// Starts the member `key`. What is returned writes the member when it
    /// writes the value, and nothing if it is dropped without one. The
    /// caller keeps the keys of an object distinct.
    pub fn key<'k>(&'k mut self, key: &'k str) -> ValueWriter<'k> {
        ValueWriter {
            out: self.out,
            key: Some(key),
            follows: &mut self.members,
        }
    }
}

impl Drop for ObjectWriter<'_> {
    fn drop(&mut self) {
        self.out.push('}');
    }
}

/// Writes a JSON array into a string element by element, without a
/// [`Value`] in between. The array is closed when the writer is dropped.
#[derive(Debug)]
pub struct ArrayWriter<'a> {
    out: &'a mut String,
    /// Whether an element was written, so the next one needs a comma.
    elements: bool,
}

impl<'a> ArrayWriter<'a> {
    /// Opens an array at the end of `out`.
    pub fn new(out: &'a mut String) -> ArrayWriter<'a> {
        out.push('[');
        ArrayWriter { out, elements: false }
    }

    /// Starts an element. What is returned writes the element when it
    /// writes the value, and nothing if it is dropped without one.
    pub fn element(&mut self) -> ValueWriter<'_> {
        ValueWriter {
            out: self.out,
            key: None,
            follows: &mut self.elements,
        }
    }
}

impl Drop for ArrayWriter<'_> {
    fn drop(&mut self) {
        self.out.push(']');
    }
}

/// The place of one value in the text an [`ObjectWriter`] or an
/// [`ArrayWriter`] writes. Every method writes the value, and with it the
/// comma in front of it and the key of a member. A `ValueWriter` that is
/// dropped without a value writes nothing.
#[derive(Debug)]
#[must_use = "a member or an element is only written with its value"]
pub struct ValueWriter<'a> {
    out: &'a mut String,
    /// The key of a member, none for an element.
    key: Option<&'a str>,
    /// Whether the object or the array has a value already, so this one
    /// needs a comma in front. Set when this one is written.
    follows: &'a mut bool,
}

impl<'a> ValueWriter<'a> {
    /// Writes what goes in front of the value: the comma after the value
    /// before it and the key of a member. Returns where the value goes.
    fn begin(self) -> &'a mut String {
        if *self.follows {
            self.out.push(',');
        }
        *self.follows = true;
        if let Some(key) = self.key {
            push_string(self.out, key);
            self.out.push(':');
        }
        self.out
    }

    /// Writes `null`.
    pub fn null(self) {
        self.begin().push_str("null");
    }

    /// Writes `true` or `false`.
    pub fn bool(self, value: bool) {
        self.begin().push_str(if value { "true" } else { "false" });
    }

    /// Writes an integer.
    pub fn unsigned(self, value: u64) {
        write!(self.begin(), "{}", value).expect("a String takes any write");
    }

    /// Writes a string.
    pub fn string(self, value: &str) {
        push_string(self.begin(), value);
    }

    /// Writes what `value` prints as a string.
    pub fn display(self, value: impl fmt::Display) {
        /// Escapes what is written to it.
        struct Escaper<'a>(&'a mut String);

        impl fmt::Write for Escaper<'_> {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                escape(self.0, s)
            }
        }

        let out = self.begin();
        out.push('"');
        write!(Escaper(out), "{}", value).expect("a Display implementation returned an error");
        out.push('"');
    }

    /// Opens an object as the value. The member or the element is written
    /// with it, even if the object stays empty.
    pub fn object(self) -> ObjectWriter<'a> {
        ObjectWriter::new(self.begin())
    }

    /// Opens an array as the value. The member or the element is written
    /// with it, even if the array stays empty.
    pub fn array(self) -> ArrayWriter<'a> {
        ArrayWriter::new(self.begin())
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
            (1e15, "1000000000000000.0"),
            (1e21, "1e21"),
            (-2.5e-8, "-2.5e-8"),
            (5e-324, "5e-324"),
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
        // -0 is a float, which keeps its sign, and no integer.
        let zero = parse("-0").unwrap();
        assert!(matches!(zero, Value::Float(f) if f.is_sign_negative()), "{:?}", zero);
        assert_eq!(
            (zero.as_u64(), zero.as_i64(), zero.to_string()),
            (None, None, "-0.0".into())
        );
        assert!(matches!(Parser::new("-0").number(), Ok(Some(Number::Float(f))) if f.is_sign_negative()));
        assert_eq!(parse("0"), Ok(Value::Int(0)));
        assert_eq!(
            parse(" \t\n{ \"a\" : [ 1 , 2 ] } \r\n").unwrap().to_string(),
            r#"{"a":[1,2]}"#
        );
    }

    #[test]
    fn whitespace_is_four_bytes() {
        let whitespace: Vec<u8> = (0..=u8::MAX).filter(|&b| is_whitespace(b)).collect();
        assert_eq!(whitespace, b"\t\n\r ");
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
            // Form feed and vertical tab are no whitespace in JSON.
            "\u{c}1",
            "[1,\u{c}2]",
            "{\"a\":1}\u{b}",
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
        // A duplicate of the first, a middle or the last key is found, in
        // small objects and in larger ones.
        for n in [1, 5, 40] {
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
        // Every control character has an escape, the ones with a letter
        // of their own use it.
        let all: String = (0u8..0x20).map(char::from).collect();
        let text = Value::from(all.as_str()).to_string();
        assert!(text.starts_with("\"\\u0000\\u0001") && text.contains("\\b\\t\\n\\u000b\\f\\r\\u000e"));
        assert!(text.ends_with("\\u001f\""), "{}", text);
        assert_eq!(parse(&text).unwrap().as_str(), Some(all.as_str()));
        // What needs an escape gets it wherever it is in the string, and
        // nothing else does.
        let escape_of = |c: char| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\u{1}' => "\\u0001".to_string(),
            c => c.to_string(),
        };
        for filler in [
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
            "\u{1f600}",
        ] {
            for before in 0..(2 * Word::SIZE + 2) {
                for special in ['"', '\\', '\n', '\u{1}', 'x'] {
                    for behind in ["", "y", "the rest of the string"] {
                        let string = format!("{}{}{}{}", filler.repeat(before), special, behind, special);
                        let escaped: String = string.chars().map(escape_of).collect();
                        let text = Value::from(string.as_str()).to_string();
                        assert_eq!(text, format!("\"{}\"", escaped), "{:?}", string);
                        assert_eq!(parse(&text).unwrap().as_str(), Some(string.as_str()));
                        let mut written = String::new();
                        ObjectWriter::new(&mut written).key(&string).display(&string);
                        assert_eq!(written, format!("{{\"{}\":\"{}\"}}", escaped, escaped), "{:?}", string);
                    }
                }
            }
        }
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

    /// What [`parse`] refuses of a text that is JSON, and skipping over the
    /// text does not.
    const LIMITS: [&str; 2] = ["number out of range", "nesting too deep"];

    /// What [`parse`] says about `text`, what skipping over it says and what
    /// reading it value by value says: the same value or the same error.
    /// Skipping goes on where a number is too large or the nesting too
    /// deep for the others.
    fn three_ways(text: &str) -> Result<String, ParseError> {
        let parsed = parse(text).map(|v| v.to_string());
        let mut p = Parser::new(text);
        let skipped = p.skip().and_then(|()| p.end());
        match &parsed {
            Err(e) if LIMITS.contains(&e.message) => {}
            _ => assert_eq!(skipped, parsed.clone().map(drop), "{:?}", text),
        }
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
        ] {
            let kind = ParseErrorKind::Syntax;
            assert_eq!(
                three_ways(text),
                Err(ParseError { offset, message, kind }),
                "{:?}",
                text
            );
        }
        // A key twice in an object is an error of its own kind, found right
        // behind the key.
        for (text, offset) in [
            ("{\"a\":1,\"a\":2}", 10),
            ("{\"a\":1,\"\\u0061\":[1, 2] ,\"b\":3}", 15),
            ("{\"a\":1,\"b\":{\"c\":1,\"c\":2},\"d\":}", 21),
            // The same key in another object is no duplicate.
            ("{\"a\":{\"a\":1},\"b\":[{\"a\":1}],\"a\":2}", 30),
            // What follows the key is not read.
            ("{\"a\":1,\"a\":[}", 10),
            ("{\"a\":1,\"a\" 2}", 10),
        ] {
            let e = ParseError {
                offset,
                message: "duplicate key",
                kind: ParseErrorKind::DuplicateKey,
            };
            assert_eq!(three_ways(text), Err(e), "{:?}", text);
        }
    }

    /// Reads `text` with the parser that is inside of an object, at the
    /// value of its key `k`, by skipping over the value.
    fn skipped(text: &str) -> Result<(), ParseError> {
        let text = format!("{{\"k\":{}}}", text);
        let mut p = Parser::new(&text);
        assert_eq!(p.object(), Ok(true));
        assert_eq!(p.key().unwrap().as_deref(), Some("k"));
        p.skip()?;
        assert_eq!(p.key()?, None);
        p.end()
    }

    #[test]
    fn skipping_holds_values_to_the_grammar() {
        // Numbers of any size, which parse() and number() refuse or turn
        // into floats.
        let digits = "9".repeat(400);
        for number in ["1e400", "-1e400", "1E+400", "1e-400", digits.as_str(), "-0.5e999999"] {
            assert_eq!(skipped(number), Ok(()), "{}", number);
            assert_eq!(skipped(&format!("[{0},{{\"x\":{0}}}]", number)), Ok(()), "{}", number);
        }
        // Nesting of any depth, which a skip that recursed would run out
        // of stack for.
        let deep = 100_000;
        for (open, close) in [("[", "]"), ("{\"k\":", "}"), ("[{\"a\":[1],\"k\":", "}]")] {
            let nested = format!("{}null{}", open.repeat(deep), close.repeat(deep));
            assert_eq!(skipped(&nested), Ok(()), "{}", open);
            assert_eq!(parse(&nested).unwrap_err().message, "nesting too deep");
        }
        // The grammar of what is skipped is checked all the same.
        for (text, offset, message) in [
            ("1.", 7, "invalid number"),
            ("-", 6, "invalid number"),
            ("01", 6, "expected ',' or '}'"),
            ("[1 2]", 8, "expected ',' or ']'"),
            ("[1,]", 8, "unexpected character"),
            ("{\"a\":1,}", 12, "expected a string key"),
            ("{\"a\" 1}", 10, "unexpected character"),
            ("[[[[", 9, "unexpected character"),
            ("[[[]]", 10, "expected ',' or ']'"),
            ("\"\\x\"", 8, "invalid escape"),
            ("nul", 5, "invalid literal"),
        ] {
            let e = skipped(text).unwrap_err();
            assert_eq!((e.offset, e.message), (offset, message), "{}", text);
        }
        // A key twice in an object, at any depth, found right behind the
        // key.
        let repeated = format!("{}{{\"a\":1,\"a\":2}}{}", "[".repeat(deep), "]".repeat(deep));
        let e = skipped(&repeated).unwrap_err();
        assert_eq!(
            (e.kind, e.offset),
            (
                ParseErrorKind::DuplicateKey,
                "{\"k\":".len() + deep + "{\"a\":1,\"a\"".len()
            )
        );
        let e = skipped("{\"a\":{\"b\":1},\"a\":[{\"a\":1}]}").unwrap_err();
        assert_eq!((e.kind, e.offset), (ParseErrorKind::DuplicateKey, 21));
        assert_eq!(skipped("{\"a\":{\"a\":{\"a\":1}},\"b\":[{\"a\":1},{\"a\":1}]}"), Ok(()));
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
    fn parser_applies_string_rules() {
        let strict = StringRules::NO_NONCHARACTERS | StringRules::NO_NUL;
        // Reads `text` the way a reader of a format with these rules does:
        // every key and every value, also those it passes over.
        let read = |text: &str, rules: StringRules| -> Result<(), ParseError> {
            let mut parser = Parser::with_rules(text, rules);
            parser.skip()?;
            parser.end()
        };
        let refused = [
            ("\"\u{fdd0}\"", "noncharacter in string"),
            ("\"\u{fdef}\"", "noncharacter in string"),
            ("\"a\u{fffe}\"", "noncharacter in string"),
            ("\"\u{ffff}\"", "noncharacter in string"),
            ("\"\u{1fffe}\"", "noncharacter in string"),
            ("\"\u{10ffff}\"", "noncharacter in string"),
            (r#""﷐""#, "noncharacter in string"),
            (r#""￿""#, "noncharacter in string"),
            (r#""🿾""#, "noncharacter in string"),
            (r#""􏿿""#, "noncharacter in string"),
            (r#""a\u0000b""#, "NUL in string"),
            (r#"{"a\u0000":1}"#, "NUL in string"),
            ("{\"\u{ffff}\":1}", "noncharacter in string"),
            (r#"{"x":["￿"]}"#, "noncharacter in string"),
        ];
        for (text, message) in refused {
            assert!(read(text, StringRules::NONE).is_ok(), "{}", text);
            assert_eq!(read(text, strict).unwrap_err().message, message, "{}", text);
        }
        // Each rule on its own.
        assert!(read(r#""\u0000""#, StringRules::NO_NONCHARACTERS).is_ok());
        assert!(read(r#""￿""#, StringRules::NO_NUL).is_ok());
        // Their neighbours and the replacement character are fine.
        for text in [
            "\"\u{fdcf}\u{fdf0}\u{fffd}\u{e000}\u{1fffd}\u{10fffd}\"",
            r#""﷏ﷰ�🿽\u0001""#,
            r#"{"a":"b","c":[1,"d"]}"#,
        ] {
            assert!(read(text, strict).is_ok(), "{}", text);
        }
    }

    /// How many code points a plane has.
    const PLANE_SIZE: u32 = 1 << 16;

    /// Every noncharacter: those of the block and the last two code points
    /// of each of the 17 planes.
    fn noncharacters() -> Vec<char> {
        let planes = 0..=u32::from(char::MAX) / PLANE_SIZE;
        let ends = planes.flat_map(|plane| [plane * PLANE_SIZE + PLANE_END, plane * PLANE_SIZE + PLANE_END + 1]);
        NONCHARACTER_BLOCK.chain(ends).filter_map(char::from_u32).collect()
    }

    /// `c` written with `\u` escapes, two of them for a surrogate pair.
    fn escaped(c: char) -> String {
        c.encode_utf16(&mut [0; 2]).iter().fold(String::new(), |mut out, unit| {
            write!(out, "\\u{:04x}", unit).expect("a String takes any write");
            out
        })
    }

    /// The rules are checked character by character only in strings
    /// beyond ASCII, and a NUL is only looked for in strings with an
    /// escape: what they find is the same for every kind of string.
    #[test]
    fn string_rules_in_every_kind_of_string() {
        let strict = StringRules::NO_NONCHARACTERS | StringRules::NO_NUL;
        let read = |text: &str, rules: StringRules| -> Result<(), ParseError> {
            let mut parser = Parser::with_rules(text, rules);
            parser.skip()?;
            parser.end()
        };
        // A string as a value and as a key, with nothing else in the text.
        let texts = |string: &str| [format!("\"{}\"", string), format!("{{\"{}\":[1]}}", string)];
        // The strings with `c` written into them: alone, behind ASCII,
        // ahead of it, behind more than a word of it, with an escape
        // before it, and next to characters beyond ASCII that start with
        // a lower byte than any noncharacter and with the same byte.
        let strings = |c: &str| {
            let long = "x".repeat(70);
            [
                c.to_string(),
                format!("abc{}", c),
                format!("{}abc", c),
                format!("{}{}", long, c),
                format!("{}{}{}", long, c, long),
                format!("a\\n{}", c),
                format!("\u{e9}{}", c),
                format!("{}\u{efff}{}", long, c),
                format!("{}\u{f000}", c),
            ]
        };
        // Unicode has 66 of them.
        let noncharacters = noncharacters();
        assert_eq!(noncharacters.len(), 66);
        for &c in &noncharacters {
            for written in [c.to_string(), escaped(c)] {
                for string in strings(&written) {
                    let [value, key] = texts(&string);
                    for rules in [strict, StringRules::NO_NONCHARACTERS] {
                        // Reported right behind the string.
                        let e = read(&value, rules).unwrap_err();
                        assert_eq!(
                            (e.message, e.offset),
                            ("noncharacter in string", value.len()),
                            "{:?}",
                            value
                        );
                        assert_eq!(e.kind, ParseErrorKind::StringRule);
                        let e = read(&key, rules).unwrap_err();
                        let behind = string.len() + "{\"\"".len();
                        assert_eq!((e.message, e.offset), ("noncharacter in string", behind), "{:?}", key);
                    }
                }
                for text in strings(&written).iter().flat_map(|string| texts(string)) {
                    assert!(read(&text, StringRules::NO_NUL).is_ok(), "{:?}", text);
                    assert!(read(&text, StringRules::NONE).is_ok(), "{:?}", text);
                }
            }
            for string in strings(&c.to_string()) {
                assert!(!strict.admits(&string), "{:?}", string);
                assert!(StringRules::NO_NUL.admits(&string), "{:?}", string);
            }
        }
        // The code points next to them are none.
        let neighbours = (0..=u32::from(char::MAX) / PLANE_SIZE)
            .map(|plane| plane * PLANE_SIZE + PLANE_END - 1)
            .chain([*NONCHARACTER_BLOCK.start() - 1, *NONCHARACTER_BLOCK.end() + 1]);
        for c in neighbours.filter_map(char::from_u32) {
            for written in [c.to_string(), escaped(c)] {
                for text in strings(&written).iter().flat_map(|string| texts(string)) {
                    assert!(read(&text, strict).is_ok(), "{:?}", text);
                }
            }
            assert!(strings(&c.to_string()).iter().all(|string| strict.admits(string)));
        }
        // A NUL can only be written as an escape: as it is, it is a control
        // character, which no string may have.
        for string in strings("\0") {
            let e = read(&format!("\"{}\"", string), StringRules::NONE).unwrap_err();
            assert_eq!(e.message, "control character in string");
        }
        for string in strings(r"\u0000") {
            let [value, key] = texts(&string);
            for rules in [strict, StringRules::NO_NUL] {
                let e = read(&value, rules).unwrap_err();
                assert_eq!((e.message, e.offset), ("NUL in string", value.len()), "{:?}", value);
                assert_eq!(e.kind, ParseErrorKind::StringRule);
                let e = read(&key, rules).unwrap_err();
                let behind = string.len() + "{\"\"".len();
                assert_eq!((e.message, e.offset), ("NUL in string", behind), "{:?}", key);
            }
            for text in [value, key] {
                assert!(read(&text, StringRules::NO_NONCHARACTERS).is_ok(), "{:?}", text);
            }
        }
        for string in strings("\0") {
            assert!(
                !strict.admits(&string) && !StringRules::NO_NUL.admits(&string),
                "{:?}",
                string
            );
            assert!(StringRules::NO_NONCHARACTERS.admits(&string), "{:?}", string);
        }
        // What breaks a rule first is what is reported.
        for (text, message) in [
            (r#""\u0000\ufdd0""#, "NUL in string"),
            (r#""\ufdd0\u0000""#, "noncharacter in string"),
            ("\"\u{fdd0}\\u0000\"", "noncharacter in string"),
            ("\"\\u0000\u{fdd0}\"", "NUL in string"),
        ] {
            assert_eq!(read(text, strict).unwrap_err().message, message, "{}", text);
        }
        assert_eq!(strict.without(StringRules::NO_NUL), StringRules::NO_NONCHARACTERS);
        assert_eq!(strict.without(strict), StringRules::NONE);
        assert_eq!(
            StringRules::NO_NUL.without(StringRules::NO_NONCHARACTERS),
            StringRules::NO_NUL
        );
    }

    /// What looking for a noncharacter by the bytes of a string relies on,
    /// for every character there is.
    #[test]
    fn noncharacters_start_with_a_high_byte() {
        let mut utf8 = [0; 4];
        let lowest = char::from_u32(*NONCHARACTER_BLOCK.start()).unwrap();
        assert_eq!(lowest.encode_utf8(&mut utf8).as_bytes()[0], NONCHARACTER_LEAD);
        let mut first = 0;
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let (&lead, rest) = c.encode_utf8(&mut utf8).as_bytes().split_first().unwrap();
            assert!(rest.iter().all(|&b| b < NONCHARACTER_LEAD), "{:?}", c);
            assert!(lead >= first, "{:?}", c);
            first = lead;
            if is_noncharacter(c) {
                assert!(lead >= NONCHARACTER_LEAD, "{:?}", c);
            }
        }
    }

    /// How many members the objects of the tests below have at most.
    const MANY_MEMBERS: usize = 100;

    #[test]
    fn parser_finds_duplicates_in_large_and_nested_objects() {
        // Every object has its own keys, also inside another one.
        let members = |prefix: &str, n: usize| -> String {
            (0..n)
                .map(|i| format!("\"{}{}\":{}", prefix, i, i))
                .collect::<Vec<_>>()
                .join(",")
        };
        for outer in [0, 1, 2, MANY_MEMBERS] {
            for inner in [1, 2, MANY_MEMBERS] {
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
    fn parser_starts_every_object_without_keys() {
        // An object starts without the keys of the objects that were as
        // deep before it, also behind a large one, and still finds a key
        // twice.
        let large = (0..MANY_MEMBERS)
            .map(|i| format!("\"k{}\":{}", i, i))
            .collect::<Vec<_>>()
            .join(",");
        for (text, duplicate) in [
            (format!("[{{{0}}},{{{0}}},{{\"k1\":1}},{{}}]", large), None),
            (
                format!("[{{{0}}},{{\"k1\":1,\"k1\":2}}]", large),
                Some("{\"k1\":1,\"k1\""),
            ),
            (
                format!("{{\"a\":{{\"b\":{{{0}}}}},\"b\":{{{0}}},\"c\":[[{{{0}}}]]}}", large),
                None,
            ),
            (
                format!("{{\"a\":{{\"b\":{{{0}}}}},\"b\":{{\"c\":1,\"c\":2}}}}", large),
                Some("{\"c\":1,\"c\""),
            ),
        ] {
            let result = three_ways(&text).map(drop);
            let e = duplicate.map(|key| ParseError {
                offset: text.find(key).unwrap() + key.len(),
                message: "duplicate key",
                kind: ParseErrorKind::DuplicateKey,
            });
            assert_eq!(result, e.map_or(Ok(()), Err), "{}", text);
        }
        // So does every value that is skipped.
        let text = format!("{{\"a\":{{{0}}},\"b\":[{{{0}}}],\"c\":{{\"k1\":1,\"k1\":2}}}}", large);
        let mut p = Parser::new(&text);
        assert_eq!(p.object(), Ok(true));
        for key in ["a", "b"] {
            assert_eq!(p.key().unwrap().as_deref(), Some(key));
            assert_eq!(p.skip(), Ok(()));
        }
        assert_eq!(p.key().unwrap().as_deref(), Some("c"));
        let e = p.skip().unwrap_err();
        assert_eq!(
            (e.kind, e.offset),
            (ParseErrorKind::DuplicateKey, text.len() - ":2}}".len())
        );
    }

    #[test]
    fn parser_knows_keys_written_with_an_escape() {
        // A key with an escape is the key it stands for.
        for text in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"\u0061":1,"a":2}"#,
            r#"{"\u0061":1,"\u0061":2}"#,
            r#"{"a\n":1,"b":2,"a\u000a":3}"#,
            r#"{"x":{"a":1,"b":2,"\u0061":3}}"#,
            r#"{"\u0061":1,"x":{"b":1},"a":2}"#,
            r#"{"a":1,"x":{"b":1,"c":{}},"\u0061":2}"#,
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
        // With few and with many keys around it.
        for around in [0, 1, 2, MANY_MEMBERS] {
            let keys: Vec<String> = (0..around).map(|i| format!("\"k{}\":{}", i, i)).collect();
            for at in [0, around / 2, around] {
                let mut members = keys.clone();
                members.insert(at, r#""k":0"#.to_string());
                assert!(three_ways(&format!("{{{}}}", members.join(","))).is_ok());
                for repeated in [r#""k":1"#, r#""\u006b":1"#] {
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
                let unescaped = filler.repeat(before);
                for behind in ["", "x", "tail of the text"] {
                    // The string ends at its quote, whatever follows.
                    let text = format!("[\"{}\",\"{}\"]", unescaped, behind);
                    let expected = Value::Array(vec![Value::from(unescaped.as_str()), Value::from(behind)]);
                    assert_eq!(three_ways(&text), Ok(expected.to_string()), "{:?}", text);
                    let mut p = Parser::new(&text);
                    assert_eq!(p.array(), Ok(true));
                    assert_eq!(p.element(), Ok(true));
                    assert!(matches!(p.string(), Ok(Some(Cow::Borrowed(s))) if s == unescaped));
                    // An escape, anywhere.
                    let text = format!("\"{}\\n{}\\\"{}\\\\\"", unescaped, behind, unescaped);
                    let expected = format!("{}\n{}\"{}\\", unescaped, behind, unescaped);
                    assert_eq!(
                        three_ways(&text),
                        Ok(Value::from(expected.as_str()).to_string()),
                        "{:?}",
                        text
                    );
                    // A control character, anywhere.
                    for control in ["\0", "\x01", "\n", "\x1f"] {
                        let text = format!("\"{}{}{}\"", unescaped, control, behind);
                        let e = ParseError {
                            offset: 1 + unescaped.len(),
                            message: "control character in string",
                            kind: ParseErrorKind::Syntax,
                        };
                        assert_eq!(three_ways(&text), Err(e), "{:?}", text);
                    }
                    // No end at all.
                    let text = format!("\"{}{}", unescaped, behind);
                    let e = ParseError {
                        offset: text.len(),
                        message: "unterminated string",
                        kind: ParseErrorKind::Syntax,
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

    #[test]
    fn writers() {
        let mut text = String::new();
        {
            let mut object = ObjectWriter::new(&mut text);
            object.key("s").string("a\"b\\c\n\u{1}é");
            object.key("key \"quoted\"").null();
            object.key("t").bool(true);
            object.key("f").bool(false);
            object.key("zero").unsigned(0);
            object.key("ten").unsigned(10);
            object.key("max").unsigned(u64::MAX);
            object.key("shown").display(format_args!("{}:{:?}", 5, "x\ty"));
            object.key("empty object").object();
            object.key("empty array").array();
            let mut array = object.key("array").array();
            array.element().unsigned(1);
            array.element().string("two");
            array.element().array().element().null();
            let mut inner = array.element().object();
            inner.key("k").unsigned(3);
            drop(inner);
            drop(array);
            object.key("last").string("");
        }
        assert_eq!(
            text,
            concat!(
                r#"{"s":"a\"b\\c\n\u0001é","key \"quoted\"":null,"t":true,"f":false,"zero":0,"ten":10,"#,
                r#""max":18446744073709551615,"shown":"5:\"x\\ty\"","empty object":{},"empty array":[],"#,
                r#""array":[1,"two",[null],{"k":3}],"last":""}"#
            )
        );
        // What the writers write is what the value prints.
        let value = parse(&text).unwrap();
        assert_eq!(value.to_string(), text);
        assert_eq!(value.get("s").unwrap().as_str(), Some("a\"b\\c\n\u{1}é"));
        assert_eq!(value.get("shown").unwrap().as_str(), Some("5:\"x\\ty\""));
        assert_eq!(value.get("max").unwrap().as_u64(), Some(u64::MAX));
        // A writer appends to what the string holds.
        let mut text = String::from("\u{1e}");
        ArrayWriter::new(&mut text).element().unsigned(7);
        text.push('\n');
        assert_eq!(text, "\u{1e}[7]\n");
    }

    #[test]
    fn dropped_value_writers_write_nothing() {
        // A member or an element whose value is never written is left
        // out, in the first, a middle and the last place.
        let values = [("a", 1), ("b", 2), ("c", 3)];
        for (left_out, object_text, array_text) in [
            (0, r#"{"b":2,"c":3}"#, "[2,3]"),
            (1, r#"{"a":1,"c":3}"#, "[1,3]"),
            (2, r#"{"a":1,"b":2}"#, "[1,2]"),
        ] {
            let mut object_written = String::new();
            let mut array_written = String::new();
            {
                let mut object = ObjectWriter::new(&mut object_written);
                let mut array = ArrayWriter::new(&mut array_written);
                for (place, (key, value)) in values.into_iter().enumerate() {
                    let member = object.key(key);
                    let element = array.element();
                    if place != left_out {
                        member.unsigned(value);
                        element.unsigned(value);
                    }
                }
            }
            assert_eq!(object_written, object_text);
            assert_eq!(array_written, array_text);
        }
        // Nor does a writer dropped with let _ write anything, nor the
        // only one of an object or an array.
        let mut text = String::new();
        {
            let mut object = ObjectWriter::new(&mut text);
            let _ = object.key("a");
            let mut inner = object.key("b").object();
            let _ = inner.key("c");
            drop(inner);
            let mut inner = object.key("d").array();
            let _ = inner.element();
            drop(inner);
            let _ = object.key("e");
        }
        assert_eq!(text, r#"{"b":{},"d":[]}"#);
        assert_eq!(parse(&text).unwrap().to_string(), text);
    }
}
