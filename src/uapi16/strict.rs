// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the JSON of a manifest keeps to beyond what serde_json checks, and
//! how a record that breaks it is reported.
//!
//! serde_json refuses what is not JSON. A manifest asks for more: no object
//! has a key twice, and no string has a noncharacter or the NUL character,
//! keys among them, however they are written. Both hold for the values a
//! reader passes over too. serde_json hands every key and every string it
//! reads to the visitor of the value it is in, and the visitors that read
//! a record see to the rules with what this module has: [`StringRules`]
//! for the strings, [`Members`] for the keys of an object, and [`Skip`]
//! for a value the reader does not take. [`Strict`] holds what they need.
//! A key that names a field of its object is told apart from the keys
//! before it by a bit, see [`FieldTable`]. Only other keys are hashed.
//!
//! A visitor that finds a rule broken fails the read. serde_json reports
//! that like any other error, at a line and a column of the record.
//! [`Strict::error`] tells a broken rule from what serde_json found itself,
//! and says which byte of the record the error is at.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;

use serde_core::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::error::Field;
use crate::STRING_RULES;

/// What the strings of a manifest may not hold beyond what JSON forbids.
///
/// JSON lets a string hold any Unicode scalar value. A manifest rules out
/// more, see [`STRING_RULES`], however a string is written: as it is or
/// with escapes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StringRules(u8);

impl StringRules {
    /// No noncharacter, as I-JSON (RFC 7493) asks: U+FDD0 to U+FDEF and
    /// the last two code points of every plane, U+FFFE and U+FFFF, U+1FFFE
    /// and U+1FFFF and so on.
    pub(crate) const NO_NONCHARACTERS: StringRules = StringRules(1 << 0);
    /// No NUL character, which JSON only lets a string have as `\u0000`.
    pub(crate) const NO_NUL: StringRules = StringRules(1 << 1);
    /// No rule beyond those of JSON.
    const NONE: StringRules = StringRules(0);

    /// Whether every rule of `rules` is among these.
    const fn contains(self, rules: StringRules) -> bool {
        self.0 & rules.0 == rules.0
    }

    /// These rules and those of `rules`.
    pub(crate) const fn union(self, rules: StringRules) -> StringRules {
        StringRules(self.0 | rules.0)
    }

    /// These rules but those of `rules`.
    pub(crate) const fn without(self, rules: StringRules) -> StringRules {
        StringRules(self.0 & !rules.0)
    }

    /// Whether the string `s` keeps to these rules.
    pub(crate) fn admits(self, s: &str) -> bool {
        self.broken_in(s).is_none()
    }

    /// Which of these rules the string `s` breaks first, if one, as a
    /// reader tells it.
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
            Some(NONCHARACTER_IN_STRING)
        } else {
            None
        }
    }
}

/// The character [`StringRules::NO_NUL`] rules out, and what a string that
/// holds it is told.
const NUL: char = '\0';
const NUL_IN_STRING: &str = "NUL in string";
/// What a string that holds a noncharacter is told.
const NONCHARACTER_IN_STRING: &str = "noncharacter in string";
/// What an object that has a key twice is told.
const DUPLICATE_KEY: &str = "duplicate key";

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

/// Whether `b` is what RFC 8259 calls whitespace: space, tab, newline
/// and carriage return. Form feed is not, unlike for
/// `u8::is_ascii_whitespace`.
pub(crate) const fn is_whitespace(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// Where and why a record is not JSON as a manifest has it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ParseError {
    /// The byte of the record the error is at.
    pub(crate) offset: usize,
    /// What is wrong.
    pub(crate) message: Cow<'static, str>,
    /// Whether the record is not JSON, has a key twice in an object, or
    /// has a string a manifest may not have.
    pub(crate) kind: ParseErrorKind,
}

/// What kind of error a [`ParseError`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseErrorKind {
    /// The record is not JSON.
    Syntax,
    /// An object has a key twice. RFC 8259 leaves open what such an object
    /// means, and a manifest may not have one.
    DuplicateKey,
    /// A string breaks one of the [`StringRules`] of a manifest.
    StringRule,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for ParseError {}

/// How many keys the set of an object has room for once it takes its first
/// key. A set that grows hashes all its keys again.
const OBJECT_KEYS: usize = 8;

/// The keys of the objects a reader is inside of that name none of their
/// fields, a set for each of the objects. The set of an object the reader
/// left is emptied and taken again for the next object that is inside of
/// as many objects. So a text needs as many sets as the most objects the
/// reader is inside of at once, and not one for every object. The set of
/// the outermost object is kept apart, so that a text whose objects are not
/// nested needs that set and nothing more. A set takes room for keys only
/// once it takes one, so an object that has nothing but fields needs none.
///
/// Emptying a set that has keys takes time in proportion to its capacity,
/// and an emptied set keeps its capacity. So a set that grew past the
/// capacity for [`OBJECT_KEYS`] keys is shrunk back to it when it is
/// emptied. Otherwise every object that takes the set after a large one
/// would pay for the capacity of the large one.
#[derive(Default)]
struct Keys<'de> {
    /// How many objects the reader is inside of.
    objects: usize,
    /// The keys of the outermost object the reader is inside of.
    outermost: HashSet<Cow<'de, str>>,
    /// The keys of the objects inside of that one, outermost first, and
    /// behind them emptied sets kept for later objects.
    inner: Vec<HashSet<Cow<'de, str>>>,
}

impl<'de> Keys<'de> {
    /// The set of the innermost object the reader is inside of.
    fn innermost(&mut self) -> Option<&mut HashSet<Cow<'de, str>>> {
        match self.objects {
            0 => None,
            1 => Some(&mut self.outermost),
            objects => self.inner.get_mut(objects - 2),
        }
    }

    /// Takes a set for the keys of an object the reader goes into.
    fn open(&mut self) {
        if self.objects > self.inner.len() {
            self.inner.push(HashSet::new());
        }
        self.objects += 1;
    }

    /// Empties the set of the innermost object, which the reader left.
    fn close(&mut self) {
        if let Some(keys) = self.innermost() {
            keys.clear();
            keys.shrink_to(OBJECT_KEYS);
        }
        self.objects -= 1;
    }

    /// Notes `key` as a key of the innermost object. Returns false when
    /// that object had the key before.
    fn insert(&mut self, key: Cow<'de, str>) -> bool {
        self.innermost().is_some_and(|keys| {
            if keys.is_empty() {
                keys.reserve(OBJECT_KEYS);
            }
            keys.insert(key)
        })
    }
}

/// A rule of a manifest that a key or a string broke.
#[derive(Clone, Copy)]
struct Broken {
    kind: ParseErrorKind,
    message: &'static str,
}

/// What the read of one JSON text keeps to hold it to the rules of a
/// manifest: the keys of the objects the reader is inside of, and the rule
/// a key or a string broke, which ended the read.
#[derive(Default)]
pub(crate) struct Strict<'de> {
    keys: Keys<'de>,
    broken: Option<Broken>,
}

impl Strict<'_> {
    /// Checks the string or the key `s` against the [`StringRules`] of a
    /// manifest.
    pub(crate) fn check_string<E: de::Error>(&mut self, s: &str) -> Result<(), E> {
        self.check(s, STRING_RULES)
    }

    /// Checks `s`, a string or a key the text has as it is, without an
    /// escape, against the [`StringRules`] of a manifest. serde_json
    /// refuses a control character in a string, so only an escape can put
    /// a NUL into one.
    pub(crate) fn check_unescaped<E: de::Error>(&mut self, s: &str) -> Result<(), E> {
        self.check(s, STRING_RULES.without(StringRules::NO_NUL))
    }

    /// Checks `s` against `rules`.
    fn check<E: de::Error>(&mut self, s: &str, rules: StringRules) -> Result<(), E> {
        match rules.broken_in(s) {
            Some(message) => Err(self.break_rule(ParseErrorKind::StringRule, message)),
            None => Ok(()),
        }
    }

    /// Notes that a rule of the kind `kind` was broken, which `message`
    /// tells, and returns the error that ends the read.
    fn break_rule<E: de::Error>(&mut self, kind: ParseErrorKind, message: &'static str) -> E {
        self.broken = Some(Broken { kind, message });
        E::custom(message)
    }

    /// What `error`, which serde_json returned for the text `text`, is, and
    /// at which byte of the text.
    ///
    /// serde_json tells where it found an error by line and column, both
    /// counted from 1, and a column counts bytes. A syntax error is at the
    /// byte the column names, and one where the text ends too early at the
    /// end of the text. A rule is found broken once the key or the string
    /// that breaks it was read, and the error is right behind its closing
    /// quote. For a string, that is the byte the column names. For a key,
    /// serde_json may have read on over whitespace and the brace that ends
    /// the object before it said where it was. So the error is behind the
    /// last quote serde_json read. What serde_json says about an error ends
    /// with where it is, which the message leaves out.
    pub(crate) fn error(&self, text: &str, error: &serde_json::Error) -> ParseError {
        let line: usize = text
            .split_inclusive('\n')
            .take(error.line().saturating_sub(1))
            .map(str::len)
            .sum();
        // The byte behind the one the column names.
        let behind = line + error.column();
        if let Some(Broken { kind, message }) = self.broken {
            let read = &text.as_bytes()[..behind];
            return ParseError {
                offset: read.iter().rposition(|&b| b == b'"').map_or(0, |quote| quote + 1),
                message: message.into(),
                kind,
            };
        }
        let said = error.to_string();
        let place = format!(" at line {} column {}", error.line(), error.column());
        let message = said.strip_suffix(&place).unwrap_or(&said).to_owned();
        ParseError {
            offset: if error.is_eof() {
                text.len()
            } else {
                behind.saturating_sub(1)
            },
            message: message.into(),
            kind: ParseErrorKind::Syntax,
        }
    }
}

/// The fields of a kind of object of a manifest, those its keys can name.
/// A field has the bit of its place in the table in a [`FieldSet`], so a
/// table has no more fields than a set has bits. A table with more does
/// not build.
pub(crate) struct FieldTable(&'static [Field]);

impl FieldTable {
    /// The table of an object whose keys are names and none of them a
    /// field, such as the names of extended attributes and of HTTP header
    /// fields.
    pub(crate) const NONE: FieldTable = FieldTable::new(&[]);

    /// The table of `fields`.
    pub(crate) const fn new(fields: &'static [Field]) -> FieldTable {
        assert!(
            fields.len() <= FieldSet::CAPACITY,
            "a field set has a bit for every field of a table"
        );
        FieldTable(fields)
    }

    /// The field the key `name` names, with its place in the table.
    pub(crate) fn find(&self, name: &str) -> Option<(usize, Field)> {
        self.iter()
            .copied()
            .enumerate()
            .find(|(_, field)| field.as_str() == name)
    }
}

impl Deref for FieldTable {
    type Target = [Field];

    fn deref(&self) -> &[Field] {
        self.0
    }
}

/// The fields an object had so far, each the bit of its place in the
/// [`FieldTable`] of the object.
#[derive(Clone, Copy, Default)]
struct FieldSet(u64);

impl FieldSet {
    /// How many fields a set can hold, as many as it has bits.
    const CAPACITY: usize = u64::BITS as usize;

    /// Notes the field at `place` in the table. Returns false when the set
    /// had it before.
    fn insert(&mut self, place: usize) -> bool {
        let bit = 1 << place;
        let first = self.0 & bit == 0;
        self.0 |= bit;
        first
    }
}

/// A key of an object as a reader takes it: one of the fields of the
/// object, or any other key, as the text has it.
pub(crate) enum Key<'de> {
    Field(Field),
    Other(Cow<'de, str>),
}

impl<'de> Key<'de> {
    /// The key as the text has it.
    fn into_name(self) -> Cow<'de, str> {
        match self {
            Key::Field(field) => Cow::Borrowed(field.as_str()),
            Key::Other(name) => name,
        }
    }
}

/// The members of an object a visitor reads, key by key. Every key is held
/// to the string rules, and a key the object had before is an error,
/// reported right behind the key. A key that names a field of the object
/// is told apart from the keys before it by the bit of the field in a
/// [`FieldSet`]. Any other key goes into the set of keys of the object, see
/// [`Keys`].
pub(crate) struct Members<A> {
    map: A,
    /// The fields the keys of the object can name.
    table: &'static FieldTable,
    /// The fields the object had so far.
    fields: FieldSet,
}

impl<'de, A: MapAccess<'de>> Members<A> {
    /// The members `map` hands out, of an object whose keys can name the
    /// fields of `table`, in the text `strict` holds to the rules.
    pub(crate) fn new(map: A, table: &'static FieldTable, strict: &mut Strict<'de>) -> Members<A> {
        strict.keys.open();
        Members {
            map,
            table,
            fields: FieldSet::default(),
        }
    }

    /// The key of the next member, whose value is read next. None at the
    /// end of the object.
    pub(crate) fn next_key(&mut self, strict: &mut Strict<'de>) -> Result<Option<Key<'de>>, A::Error> {
        let Some(name) = self.map.next_key_seed(KeySeed(strict))? else {
            strict.keys.close();
            return Ok(None);
        };
        // A field of the object goes into its set of fields, any other key
        // into its set of keys.
        let (key, first) = match self.table.find(&name) {
            Some((place, field)) => (Key::Field(field), self.fields.insert(place)),
            None => (Key::Other(name.clone()), strict.keys.insert(name)),
        };
        if !first {
            return Err(strict.break_rule(ParseErrorKind::DuplicateKey, DUPLICATE_KEY));
        }
        Ok(Some(key))
    }

    /// The key of the next member as the text has it, of an object whose
    /// keys are names. None at the end of the object.
    pub(crate) fn next_name(&mut self, strict: &mut Strict<'de>) -> Result<Option<Cow<'de, str>>, A::Error> {
        Ok(self.next_key(strict)?.map(Key::into_name))
    }

    /// Reads the value of the member with `seed`.
    pub(crate) fn value<S: DeserializeSeed<'de>>(&mut self, seed: S) -> Result<S::Value, A::Error> {
        self.map.next_value_seed(seed)
    }

    /// Reads through the value of the member, see [`Skip`].
    pub(crate) fn skip(&mut self, strict: &mut Strict<'de>) -> Result<(), A::Error> {
        self.map.next_value_seed(Skip(strict))
    }
}

/// Reads a key, which is borrowed from the text unless it has an escape.
struct KeySeed<'s, 'de>(&'s mut Strict<'de>);

impl<'de> DeserializeSeed<'de> for KeySeed<'_, 'de> {
    type Value = Cow<'de, str>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Cow<'de, str>, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for KeySeed<'_, 'de> {
    type Value = Cow<'de, str>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a key")
    }

    fn visit_borrowed_str<E: de::Error>(self, key: &'de str) -> Result<Cow<'de, str>, E> {
        self.0.check_unescaped(key)?;
        Ok(Cow::Borrowed(key))
    }

    fn visit_str<E: de::Error>(self, key: &str) -> Result<Cow<'de, str>, E> {
        self.0.check_string(key)?;
        Ok(Cow::Owned(key.to_owned()))
    }
}

/// Reads through a value of any type and keeps nothing of it, but holds
/// its keys and strings to the rules: what serde's `IgnoredAny` does not
/// do.
pub(crate) struct Skip<'s, 'de>(pub(crate) &'s mut Strict<'de>);

impl<'de> DeserializeSeed<'de> for Skip<'_, 'de> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Skip<'_, 'de> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_borrowed_str<E: de::Error>(self, s: &'de str) -> Result<(), E> {
        self.0.check_unescaped(s)
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<(), E> {
        self.0.check_string(s)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Skip(&mut *self.0))?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        let mut members = Members::new(map, &FieldTable::NONE, self.0);
        while members.next_key(self.0)?.is_some() {
            members.skip(self.0)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::testing::{read_json, MAX_NESTING};

    #[test]
    fn whitespace_is_four_bytes() {
        let whitespace: Vec<u8> = (0..=u8::MAX).filter(|&b| is_whitespace(b)).collect();
        assert_eq!(whitespace, b"\t\n\r ");
    }

    #[test]
    fn rules_hold_for_every_string() {
        let refused = [
            ("\"\u{fdd0}\"", NONCHARACTER_IN_STRING),
            ("\"\u{fdef}\"", NONCHARACTER_IN_STRING),
            ("\"a\u{fffe}\"", NONCHARACTER_IN_STRING),
            ("\"\u{ffff}\"", NONCHARACTER_IN_STRING),
            ("\"\u{1fffe}\"", NONCHARACTER_IN_STRING),
            ("\"\u{10ffff}\"", NONCHARACTER_IN_STRING),
            (r#""\ufdd0""#, NONCHARACTER_IN_STRING),
            (r#""\uffff""#, NONCHARACTER_IN_STRING),
            (r#""\ud83f\udffe""#, NONCHARACTER_IN_STRING),
            (r#""\udbff\udfff""#, NONCHARACTER_IN_STRING),
            (r#""a\u0000b""#, NUL_IN_STRING),
            (r#"{"a\u0000":1}"#, NUL_IN_STRING),
            ("{\"\u{ffff}\":1}", NONCHARACTER_IN_STRING),
            (r#"{"x":["\uffff"]}"#, NONCHARACTER_IN_STRING),
        ];
        for (text, message) in refused {
            let e = read_json(text).unwrap_err();
            assert_eq!(
                (e.kind, e.message.as_ref()),
                (ParseErrorKind::StringRule, message),
                "{}",
                text
            );
            assert!(serde_json::from_str::<serde_json::Value>(text).is_ok(), "{}", text);
        }
        // Their neighbours and the replacement character are fine.
        for text in [
            "\"\u{fdcf}\u{fdf0}\u{fffd}\u{e000}\u{1fffd}\u{10fffd}\"",
            r#""\ufdcf\ufdf0\ufffd\ud83f\udffd\u0001""#,
            r#"{"a":"b","c":[1,"d"]}"#,
        ] {
            assert_eq!(read_json(text), Ok(()), "{}", text);
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
    /// beyond ASCII: what they find is the same for every kind of string,
    /// a value or a key, with an escape or without.
    #[test]
    fn string_rules_in_every_kind_of_string() {
        let strict = StringRules::NO_NONCHARACTERS.union(StringRules::NO_NUL);
        assert_eq!(strict, STRING_RULES);
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
                    // Reported right behind the string.
                    let [value, key] = texts(&string);
                    let e = read_json(&value).unwrap_err();
                    assert_eq!(
                        (e.kind, e.message.as_ref(), e.offset),
                        (ParseErrorKind::StringRule, NONCHARACTER_IN_STRING, value.len()),
                        "{:?}",
                        value
                    );
                    let e = read_json(&key).unwrap_err();
                    let behind = string.len() + "{\"\"".len();
                    assert_eq!(
                        (e.message.as_ref(), e.offset),
                        (NONCHARACTER_IN_STRING, behind),
                        "{:?}",
                        key
                    );
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
                    assert_eq!(read_json(&text), Ok(()), "{:?}", text);
                }
            }
            assert!(strings(&c.to_string()).iter().all(|string| strict.admits(string)));
        }
        // A NUL can only be written as an escape: as it is, it is a control
        // character, which no string may have.
        for string in strings("\0") {
            let e = read_json(&format!("\"{}\"", string)).unwrap_err();
            assert_eq!(e.kind, ParseErrorKind::Syntax, "{:?}", string);
        }
        for string in strings(r"\u0000") {
            let [value, key] = texts(&string);
            let e = read_json(&value).unwrap_err();
            assert_eq!(
                (e.kind, e.message.as_ref(), e.offset),
                (ParseErrorKind::StringRule, NUL_IN_STRING, value.len()),
                "{:?}",
                value
            );
            let e = read_json(&key).unwrap_err();
            let behind = string.len() + "{\"\"".len();
            assert_eq!((e.message.as_ref(), e.offset), (NUL_IN_STRING, behind), "{:?}", key);
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
            (r#""\u0000\ufdd0""#, NUL_IN_STRING),
            (r#""\ufdd0\u0000""#, NONCHARACTER_IN_STRING),
            ("\"\u{fdd0}\\u0000\"", NONCHARACTER_IN_STRING),
            ("\"\\u0000\u{fdd0}\"", NUL_IN_STRING),
        ] {
            assert_eq!(read_json(text).unwrap_err().message, message, "{}", text);
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

    /// The members `"<prefix>0":0` to `"<prefix><n - 1>":<n - 1>`.
    fn members(prefix: &str, n: usize) -> String {
        (0..n)
            .map(|i| format!("\"{}{}\":{}", prefix, i, i))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// The error of a key twice, right behind the `n`th time `key` is in
    /// `text`, counted from 1.
    fn duplicate(text: &str, key: &str, n: usize) -> ParseError {
        let (at, _) = text.match_indices(key).nth(n - 1).unwrap();
        ParseError {
            offset: at + key.len(),
            message: DUPLICATE_KEY.into(),
            kind: ParseErrorKind::DuplicateKey,
        }
    }

    #[test]
    fn finds_duplicates_in_large_and_nested_objects() {
        // Every object has its own keys, also inside another one.
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
                assert_eq!(read_json(&unique), Ok(()), "{}", unique);
                for at in [0, inner / 2, inner - 1] {
                    let repeated = format!(
                        "{{{}{}\"in\":{{{},\"i{}\":0}}}}",
                        members("o", outer),
                        comma,
                        members("i", inner),
                        at
                    );
                    let key = format!("\"i{}\"", at);
                    assert_eq!(read_json(&repeated), Err(duplicate(&repeated, &key, 2)), "{}", repeated);
                }
                if outer > 0 {
                    // The outer object still knows its keys after the inner one.
                    let repeated = format!(
                        "{{{},\"in\":{{{}}},\"o{}\":0}}",
                        members("o", outer),
                        members("i", inner),
                        outer - 1
                    );
                    let key = format!("\"o{}\"", outer - 1);
                    assert_eq!(read_json(&repeated), Err(duplicate(&repeated, &key, 2)), "{}", repeated);
                }
            }
        }
    }

    /// A key twice in an object is found right behind the key, before
    /// what follows it is read: whitespace, the colon and the value, a
    /// comma or the end of the object. So is a key that breaks a rule for
    /// strings.
    #[test]
    fn finds_a_key_twice_right_behind_it() {
        for text in [
            "{\"a\":1,\"a\":2}",
            "{\"a\":1,\"a\":[}",
            "{\"a\":1,\"a\" 2}",
            "{\"a\":1,\"a\" :2}",
            "{\"a\":1,\"a\"\r\n\t:2}",
            "{\"a\":1,\"a\",\"b\":2}",
            "{\"a\":1,\"a\"}",
            "{\"a\":1,\"a\" \n }",
            "{\"a\":1,\"a\"",
            "{\"a\":1,\"a\"  ",
            "[{\"a\":1,\"a\"}]",
            "[{\"k\":{\"a\":1,\"a\" :2}}]",
            "[{\"k\":{\"a\":1,\"a\"} }]",
        ] {
            assert_eq!(read_json(text), Err(duplicate(text, "\"a\"", 2)), "{:?}", text);
        }
        // A key with a noncharacter or NUL in it, whatever follows it.
        let object = "{";
        for (key, message) in [("\"\\uFFFF\"", NONCHARACTER_IN_STRING), ("\"a\\u0000\"", NUL_IN_STRING)] {
            for follower in [":1}", " :1}", ",\"b\":1}", "}", " \n }", "\n"] {
                let text = format!("{}{}{}", object, key, follower);
                let e = ParseError {
                    offset: object.len() + key.len(),
                    message: message.into(),
                    kind: ParseErrorKind::StringRule,
                };
                assert_eq!(read_json(&text), Err(e), "{:?}", text);
            }
        }
    }

    #[test]
    fn starts_every_object_without_keys() {
        // An object starts without the keys of the objects that were as
        // deep before it, also behind a large one, and still finds a key
        // twice.
        let large = members("k", MANY_MEMBERS);
        for (text, duplicate_at) in [
            (format!("[{{{0}}},{{{0}}},{{\"k1\":1}},{{}}]", large), None),
            (format!("[{{{0}}},{{\"k1\":1,\"k1\":2}}]", large), Some(3)),
            (
                format!("{{\"a\":{{\"b\":{{{0}}}}},\"b\":{{{0}}},\"c\":[[{{{0}}}]]}}", large),
                None,
            ),
            (
                format!("{{\"a\":{{\"b\":{{{0}}}}},\"b\":{{\"k1\":1,\"k1\":2}}}}", large),
                Some(3),
            ),
        ] {
            let e = duplicate_at.map(|n| duplicate(&text, "\"k1\"", n));
            assert_eq!(read_json(&text), e.map_or(Ok(()), Err), "{}", text);
        }
    }

    #[test]
    fn knows_keys_written_with_an_escape() {
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
            let e = read_json(text).unwrap_err();
            assert_eq!(e.kind, ParseErrorKind::DuplicateKey, "{}", text);
            // Right behind the second key, which ends the text but for
            // its value and the braces behind it.
            let value = text.rfind(':').unwrap();
            assert_eq!(e.offset, value, "{}", text);
        }
        for text in [r#"{"a":1,"\u0062":2}"#, r#"{"a":{"a":{"a":1}},"\u0062":[{"a":1}]}"#] {
            assert_eq!(read_json(text), Ok(()), "{}", text);
        }
    }

    /// serde_json's errors are at the byte the column names, a text that
    /// ends too early at its end, on any line. What serde_json says leaves
    /// out where.
    #[test]
    fn says_where_serde_json_finds_an_error() {
        for (text, message, offset) in [
            ("", "EOF while parsing a value", 0),
            ("{", "EOF while parsing an object", 1),
            ("{\"a\":1\n", "EOF while parsing an object", 7),
            ("[1,]", "trailing comma", 3),
            ("{\"a\":1,}", "trailing comma", 7),
            ("{1:2}", "key must be a string", 1),
            ("1 2", "trailing characters", 2),
            ("{\"a\":1}\n\nx", "trailing characters", 9),
            ("{\n\"a\":1,\n\"b\":}", "expected value", 13),
            (
                "\"a\tb\"",
                "control character (\\u0000-\\u001F) found while parsing a string",
                2,
            ),
            (
                "\"a\nb\"",
                "control character (\\u0000-\\u001F) found while parsing a string",
                2,
            ),
            ("[01]", "invalid number", 2),
            ("1E400", "number out of range", 4),
            ("[\"\\x\"]", "invalid escape", 3),
        ] {
            let e = read_json(text).unwrap_err();
            assert_eq!(
                (e.kind, e.message.as_ref(), e.offset),
                (ParseErrorKind::Syntax, message, offset),
                "{:?}",
                text
            );
        }
        // A rule broken on a later line, behind the key.
        let text = "{\n  \"a\": 1,\n  \"a\": 2\n}";
        assert_eq!(read_json(text), Err(duplicate(text, "\"a\"", 2)));
    }

    /// Nesting is as deep as serde_json reads it, and refused beyond that,
    /// without overflowing the stack.
    #[test]
    fn limits_nesting() {
        for (open, close) in [("[", "]"), ("{\"k\":", "}")] {
            let nested = |n: usize| format!("{}1{}", open.repeat(n), close.repeat(n));
            assert_eq!(read_json(&nested(MAX_NESTING)), Ok(()));
            for depth in [MAX_NESTING + 1, 1_000, 1_000_000] {
                let e = read_json(&nested(depth)).unwrap_err();
                assert_eq!(
                    (e.kind, e.message.as_ref()),
                    (ParseErrorKind::Syntax, "recursion limit exceeded")
                );
            }
        }
    }
}
