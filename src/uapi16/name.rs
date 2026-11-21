// SPDX-License-Identifier: LGPL-2.1-or-later
//! The names of file objects.

use std::cmp::Ordering;
use std::fmt;
use std::iter;
use std::ops::Deref;
use std::str::FromStr;

use json::StringRules;

use crate::{InodeType, FILENAME, STRING_RULES};

/// What separates the components of a name.
const SEPARATOR: char = '/';
/// The separator as the one byte it is in UTF-8. Being ASCII, that byte is
/// in no other character, so the components of a name are found by
/// looking at its bytes.
const SEPARATOR_BYTE: u8 = SEPARATOR as u8;
/// The components that stand for a directory itself and for the one above
/// it. A name has neither.
const CURRENT: &str = ".";
const PARENT: &str = "..";
/// What follows [`FILENAME`] in the name of a file that belongs to the
/// manifest, such as its signature or a compressed copy.
const SUFFIX_SEPARATOR: char = '.';
/// The control characters a name may not have are the bytes below the
/// space, ASCII 0 to 31, and delete, ASCII 127.
const SPACE: u8 = b' ';
const DELETE: u8 = 0x7f;
/// What the text of a name may not hold besides control characters: what
/// the strings of a manifest may not hold, except for the NUL character,
/// which is a control character. That leaves the noncharacters.
const RULES: StringRules = STRING_RULES.without(StringRules::NO_NUL);

/// The name of a file object: the path of the file below the root of the
/// tree the manifest describes.
///
/// A name is a normalized relative path. Its components are separated by
/// single slashes, and none of them is empty, `.` or `..`. It has no
/// control characters and no noncharacters, and it is at most
/// [`Name::MAX_LEN`] bytes long. Its components are not limited on their
/// own. It is not `Uapi16Manifest` and does not begin with
/// `Uapi16Manifest.`, the names the manifest itself and what belongs to it
/// have inside the tree.
///
/// Names are ordered the way the specification orders the file objects of
/// a manifest in code point order: component by component, each compared
/// by its bytes, so that the name of a directory comes right before the
/// names below it. That is not the order of the names as strings: `a/x`
/// comes before `a-b`.
///
/// The root file object has no name. Its name here is the empty one,
/// [`Name::ROOT`], which no file has, and which comes before every other
/// name.
///
/// ```
/// use uapi16::{InvalidName, Name};
///
/// let name = Name::new("EFI/BOOT")?;
/// assert_eq!(name.join("BOOTX64.EFI")?, "EFI/BOOT/BOOTX64.EFI");
/// assert_eq!("EFI//BOOT".parse::<Name>(), Err(InvalidName::EmptyComponent));
/// assert_eq!(Name::new("../etc/passwd"), Err(InvalidName::ContainsDotComponent));
/// assert!(Name::new("a/x")? < Name::new("a-b")?);
/// # Ok::<(), InvalidName>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Name(String);

/// Why a string is not the name of a file object, see [`Name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InvalidName {
    /// The string is empty. No file object has that name: [`Name::ROOT`]
    /// only stands in for the root file object, which has no name.
    Empty,
    /// It is longer than [`Name::MAX_LEN`] bytes.
    TooLong,
    /// It is `Uapi16Manifest` or begins with `Uapi16Manifest.`, which the
    /// specification reserves for the manifest and what belongs to it.
    Reserved,
    /// It contains a control character: ASCII 0 to 31 or 127.
    ContainsControlCharacter,
    /// It contains a noncharacter, which no string of a manifest may have.
    ContainsNoncharacter,
    /// One of its components is empty: it begins or ends with a slash, or
    /// it has two slashes in a row.
    EmptyComponent,
    /// It contains a component that is `.` or `..`.
    ContainsDotComponent,
    /// The component given to [`Name::join`] contains a slash, so it is
    /// more than one component.
    ContainsSeparator,
}

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvalidName::Empty => f.write_str("name is empty"),
            InvalidName::TooLong => write!(f, "name is longer than {} bytes", Name::MAX_LEN),
            InvalidName::Reserved => f.write_str("name is reserved for the manifest"),
            InvalidName::ContainsControlCharacter => f.write_str("name contains a control character"),
            InvalidName::ContainsNoncharacter => f.write_str("name contains a noncharacter"),
            InvalidName::EmptyComponent => f.write_str("name has an empty component"),
            InvalidName::ContainsDotComponent => write!(f, "name contains a '{}' or '{}' component", CURRENT, PARENT),
            InvalidName::ContainsSeparator => write!(f, "name component contains '{}'", SEPARATOR),
        }
    }
}

impl std::error::Error for InvalidName {}

impl Name {
    /// The name of the root file object: the empty one.
    pub const ROOT: Name = Name(String::new());

    /// The most bytes a name has, as the specification says.
    pub const MAX_LEN: usize = 4095;

    /// Takes `name` as the name of a file object, if it is one. If it is
    /// not, the error says why.
    pub fn new(name: impl Into<String>) -> Result<Name, InvalidName> {
        let name = name.into();
        if name.is_empty() {
            return Err(InvalidName::Empty);
        }
        if name.len() > Name::MAX_LEN {
            return Err(InvalidName::TooLong);
        }
        if Name::is_reserved(&name) {
            return Err(InvalidName::Reserved);
        }
        // The separator is neither a control character nor a noncharacter,
        // so the text of the components is checked all at once.
        Name::check_text(&name)?;
        for component in name.as_bytes().split(|&b| b == SEPARATOR_BYTE) {
            Name::check_component(component)?;
        }
        Ok(Name(name))
    }

    /// The name of the entry `component` of the directory this name is
    /// the name of. Only the new component is looked at, so the names of
    /// a deep tree are cheap to make on the way down.
    pub fn join(&self, component: &str) -> Result<Name, InvalidName> {
        if component.contains(SEPARATOR) {
            return Err(InvalidName::ContainsSeparator);
        }
        if self.is_root() {
            return Name::new(component);
        }
        let len = self.0.len() + SEPARATOR.len_utf8() + component.len();
        if len > Name::MAX_LEN {
            return Err(InvalidName::TooLong);
        }
        // In the order of Name::new(), so that a component is refused for
        // the reason the whole name would be refused for.
        Name::check_text(component)?;
        Name::check_component(component.as_bytes())?;
        let mut name = String::with_capacity(len);
        name.push_str(&self.0);
        name.push(SEPARATOR);
        name.push_str(component);
        Ok(Name(name))
    }

    /// Checks that `text` can be in a name: it has no control characters,
    /// and nothing that the strings of a manifest may not hold.
    fn check_text(text: &str) -> Result<(), InvalidName> {
        // Every byte is looked at, not only those up to the first control
        // character, and with two comparisons instead of is_ascii_control(),
        // which the compiler turns into a branch. Without an early end and
        // without a branch the compiler looks at many bytes at a time.
        let control = text
            .bytes()
            .fold(false, |control, b| control | (b < SPACE) | (b == DELETE));
        if control {
            return Err(InvalidName::ContainsControlCharacter);
        }
        if !RULES.admits(text) {
            return Err(InvalidName::ContainsNoncharacter);
        }
        Ok(())
    }

    /// Checks the bytes `component` between two separators as a component
    /// as far as its shape goes: it is not empty, and it does not stand
    /// for a directory itself or for the one above it.
    fn check_component(component: &[u8]) -> Result<(), InvalidName> {
        if component.is_empty() {
            return Err(InvalidName::EmptyComponent);
        }
        if component == CURRENT.as_bytes() || component == PARENT.as_bytes() {
            return Err(InvalidName::ContainsDotComponent);
        }
        Ok(())
    }

    /// The components of the name, the first one first. The root has none.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        // The root's empty name would make one empty component.
        self.0.split(SEPARATOR).filter(|component| !component.is_empty())
    }

    /// The name of the directory the file is in, which is the empty name
    /// of the root for a file at the top. The root has none.
    pub fn parent(&self) -> Option<&str> {
        if self.is_root() {
            return None;
        }
        Some(self.0.rsplit_once(SEPARATOR).map_or("", |(parent, _)| parent))
    }

    /// The name of the file in its directory, its last component. The
    /// root has none.
    pub fn file_name(&self) -> Option<&str> {
        self.components().next_back()
    }

    /// Whether `name` is one the specification reserves for the manifest
    /// and what belongs to it: `Uapi16Manifest`, or a name that begins
    /// with `Uapi16Manifest.`. A file of such a name is not listed in a
    /// manifest.
    pub fn is_reserved(name: &str) -> bool {
        name.strip_prefix(FILENAME)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(SUFFIX_SEPARATOR))
    }

    /// Whether this is the name of the root file object.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Name) -> Ordering {
        NamePair::new(&self.0, &other.0).ordering()
    }
}

/// Two names, looked at from the first byte in which they differ. If one
/// name is the first part of the other, that is where it ends.
///
/// The names are the same in all bytes before that one, so the bytes from
/// there on settle both how the names are ordered and whether the second
/// one may follow the first in a manifest. That is why one pass over the
/// bytes the names share answers all the questions
/// [`SequenceCheck`](crate::sequence::SequenceCheck) asks of a file object
/// and the one before it. The root's empty name is a name here, too.
pub(crate) struct NamePair<'a> {
    /// The bytes of the first name from the first byte in which the names
    /// differ on, and those of the second one.
    first: &'a [u8],
    second: &'a [u8],
}

impl<'a> NamePair<'a> {
    /// The pair of the names `first` and `second`.
    pub(crate) fn new(first: &'a str, second: &'a str) -> NamePair<'a> {
        let (first, second) = (first.as_bytes(), second.as_bytes());
        let common = iter::zip(first, second).take_while(|(a, b)| a == b).count();
        NamePair {
            first: &first[common..],
            second: &second[common..],
        }
    }

    /// How the names are ordered, see [`Name`]: component by component,
    /// each compared by its bytes.
    ///
    /// That is the order of the bytes of the whole names with the separator
    /// taken as lower than any other byte, so the first bytes in which the
    /// names differ decide it. All components that end before those bytes
    /// are the same in both names, and the one they are in starts at the
    /// same byte in both:
    /// - If one name ends there, its component there is the first part of
    ///   the other's, or the other name goes on with a separator to a
    ///   component it does not have at all. Either way it comes first.
    /// - If one name has the separator there, its component ends there and
    ///   is the first part of the other's, which goes on. It comes first,
    ///   as the separator is lowest.
    /// - Otherwise both components go on, and the bytes there are the first
    ///   ones in which they differ.
    pub(crate) fn ordering(&self) -> Ordering {
        let rank = |rest: &[u8]| rest.first().map(|&b| (b != SEPARATOR_BYTE, b));
        rank(self.first).cmp(&rank(self.second))
    }

    /// Whether the second name is that of a file in a directory that can
    /// still have entries after the first file, the last one so far: the
    /// root, a directory the first file is in, or the first file itself if
    /// its type, `first_type`, is a directory.
    ///
    /// The directory of the second file is the root or one the first file
    /// is in if every separator of the second name comes before the first
    /// byte in which the names differ, where the first name has the same
    /// separators. It is the first file itself if the first name ends there
    /// and the second name has its last separator right there.
    pub(crate) fn second_is_in_open_directory(&self, first_type: InodeType) -> bool {
        let first_is_directory = first_type == InodeType::Directory;
        let rest = match self.second.split_first() {
            Some((&SEPARATOR_BYTE, inside)) if first_is_directory && self.first.is_empty() => inside,
            _ => self.second,
        };
        !rest.contains(&SEPARATOR_BYTE)
    }

    /// Whether the second name is the first one, or that of a directory
    /// the first file is in.
    pub(crate) fn second_is_first_or_above(&self) -> bool {
        self.second.is_empty() && self.first.first().is_none_or(|&b| b == SEPARATOR_BYTE)
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Name {
    type Err = InvalidName;

    fn from_str(name: &str) -> Result<Name, InvalidName> {
        Name::new(name)
    }
}

impl TryFrom<String> for Name {
    type Error = InvalidName;

    fn try_from(name: String) -> Result<Name, InvalidName> {
        Name::new(name)
    }
}

impl TryFrom<&str> for Name {
    type Error = InvalidName;

    fn try_from(name: &str) -> Result<Name, InvalidName> {
        Name::new(name)
    }
}

impl From<Name> for String {
    fn from(name: Name) -> String {
        name.0
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::full_tree_names;

    #[test]
    fn names() {
        for name in [
            "a",
            "a/b",
            "EFI/BOOT/BOOTX64.EFI",
            "with space",
            "\u{fc}mlaut \u{221e}.txt",
            "...",
            "a/...",
            ".hidden",
            "a.",
            "Uapi16Manifest2",
            "Uapi16Manifes",
            "uapi16manifest",
            "sub/Uapi16Manifest",
            "sub/Uapi16Manifest.sig",
            "xUapi16Manifest.sig",
        ] {
            let parsed = Name::new(name).unwrap_or_else(|_| panic!("{:?}", name));
            assert_eq!(parsed, name);
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.to_string(), name);
            assert!(!parsed.is_root());
            assert_eq!(name.parse::<Name>(), Ok(parsed.clone()));
            assert_eq!(Name::try_from(name), Ok(parsed.clone()));
            assert_eq!(Name::try_from(name.to_string()), Ok(parsed.clone()));
            assert_eq!(String::from(parsed), name);
        }
        for (name, reason) in [
            ("", InvalidName::Empty),
            ("/", InvalidName::EmptyComponent),
            ("/abs", InvalidName::EmptyComponent),
            ("a/", InvalidName::EmptyComponent),
            ("a//b", InvalidName::EmptyComponent),
            (".", InvalidName::ContainsDotComponent),
            ("..", InvalidName::ContainsDotComponent),
            ("a/.", InvalidName::ContainsDotComponent),
            ("a/..", InvalidName::ContainsDotComponent),
            ("./a", InvalidName::ContainsDotComponent),
            ("../a", InvalidName::ContainsDotComponent),
            ("a/./b", InvalidName::ContainsDotComponent),
            ("a/../b", InvalidName::ContainsDotComponent),
            ("a\nb", InvalidName::ContainsControlCharacter),
            ("a\0b", InvalidName::ContainsControlCharacter),
            ("a/\u{1}", InvalidName::ContainsControlCharacter),
            ("a\u{7f}", InvalidName::ContainsControlCharacter),
            ("\u{fdd0}", InvalidName::ContainsNoncharacter),
            ("a\u{fffe}", InvalidName::ContainsNoncharacter),
            ("a/\u{10ffff}", InvalidName::ContainsNoncharacter),
            ("Uapi16Manifest", InvalidName::Reserved),
            ("Uapi16Manifest.", InvalidName::Reserved),
            ("Uapi16Manifest.sig", InvalidName::Reserved),
            ("Uapi16Manifest.gz", InvalidName::Reserved),
            ("Uapi16Manifest.d/inside", InvalidName::Reserved),
        ] {
            assert_eq!(Name::new(name), Err(reason), "{:?}", name);
            assert_eq!(name.parse::<Name>(), Err(reason), "{:?}", name);
        }
        // The control characters of Latin-1 are not ASCII control
        // characters.
        assert!(Name::new("a\u{85}b").is_ok());
    }

    /// The error says what is wrong with the name.
    #[test]
    fn messages() {
        for (reason, text) in [
            (InvalidName::Empty, "name is empty"),
            (InvalidName::TooLong, "name is longer than 4095 bytes"),
            (InvalidName::Reserved, "name is reserved for the manifest"),
            (
                InvalidName::ContainsControlCharacter,
                "name contains a control character",
            ),
            (InvalidName::ContainsNoncharacter, "name contains a noncharacter"),
            (InvalidName::EmptyComponent, "name has an empty component"),
            (
                InvalidName::ContainsDotComponent,
                "name contains a '.' or '..' component",
            ),
            (InvalidName::ContainsSeparator, "name component contains '/'"),
        ] {
            assert_eq!(reason.to_string(), text);
        }
    }

    #[test]
    fn lengths() {
        // The whole name is limited, its components are not on their own.
        let longest = "x".repeat(Name::MAX_LEN);
        assert!(Name::new(longest.as_str()).is_ok());
        assert_eq!(Name::new(format!("{}x", longest)), Err(InvalidName::TooLong));
        let component = "y".repeat(1000);
        let deep = [component.as_str(); 4].join("/");
        assert!(Name::new(deep.as_str()).is_ok());
        let fits = format!("{}/{}", deep, "z".repeat(Name::MAX_LEN - deep.len() - 1));
        assert_eq!(fits.len(), Name::MAX_LEN);
        assert!(Name::new(fits.as_str()).is_ok());
        assert_eq!(Name::new(format!("{}z", fits)), Err(InvalidName::TooLong));
        // The limit counts bytes, not characters.
        let euro = '\u{20ac}';
        assert_eq!(euro.len_utf8(), 3);
        assert!(Name::new(euro.to_string().repeat(Name::MAX_LEN / 3)).is_ok());
        assert_eq!(
            Name::new(euro.to_string().repeat(Name::MAX_LEN / 3 + 1)),
            Err(InvalidName::TooLong)
        );
    }

    #[test]
    fn order() {
        // In the order the specification sorts the names of a manifest in.
        let names: Vec<Name> = [
            "",
            "a",
            "a/b",
            "a/b/c",
            "a/x",
            "a-b",
            "a.b",
            "a0",
            "b",
            "\u{e9}",
            "\u{ff61}",
            "\u{1f600}",
        ]
        .into_iter()
        .map(|name| {
            if name.is_empty() {
                Name::ROOT
            } else {
                Name::new(name).unwrap()
            }
        })
        .collect();
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                assert_eq!(a.cmp(b), i.cmp(&j), "{:?} {:?}", a, b);
                assert_eq!(a.partial_cmp(b), Some(i.cmp(&j)));
            }
        }
        // As strings they are not in that order.
        assert!(names[5].as_str() < names[4].as_str());
    }

    /// The components the names of the tests below are made of: one that
    /// is the first part of others, bytes below the separator and above
    /// it, and characters beyond ASCII.
    const PIECES: [&str; 8] = ["a", "ab", "a b", "a-b", "a.b", "a0", "\u{e9}", "\u{1f600}"];

    /// Names are in the order of their components, whatever order the
    /// bytes of the whole names are in.
    #[test]
    fn order_of_components() {
        let names = full_tree_names(&PIECES, 3);
        for a in &names {
            for b in &names {
                assert_eq!(a.cmp(b), a.components().cmp(b.components()), "{:?} {:?}", a, b);
            }
        }
        // The separator comes before any other byte, also before those
        // that are lower as bytes: the space to the full stop.
        for byte in b' '..SEPARATOR_BYTE {
            let other = Name::new(format!("a{}b", char::from(byte))).unwrap();
            for name in ["a/b", "a/x", "a/b/c", "a/\u{e9}"] {
                assert!(Name::new(name).unwrap() < other, "{:?} {:?}", name, other);
            }
            let other = Name::new(format!("a{}", char::from(byte))).unwrap();
            assert!(Name::new("a/b").unwrap() < other, "{:?}", other);
        }
        // A name comes before the names it is the first part of.
        for (first, second) in [
            ("a", "a/b"),
            ("a", "ab"),
            ("a", "a b"),
            ("a/b", "a/bc"),
            ("a/b", "a/b/c"),
            ("a/b/c", "a/bc"),
            ("a/b", "ab"),
            ("\u{e9}", "\u{e9}/a"),
        ] {
            let (first, second) = (Name::new(first).unwrap(), Name::new(second).unwrap());
            assert_eq!(first.cmp(&second), Ordering::Less, "{:?} {:?}", first, second);
            assert_eq!(second.cmp(&first), Ordering::Greater, "{:?} {:?}", first, second);
        }
    }

    /// Everything that makes `name` not a name by the definition of
    /// [`Name`], with every component and every character of it looked at
    /// on its own. Nothing if it is a name.
    fn reasons(name: &str) -> Vec<InvalidName> {
        let mut reasons = Vec::new();
        if name.is_empty() {
            reasons.push(InvalidName::Empty);
        }
        if name.len() > Name::MAX_LEN {
            reasons.push(InvalidName::TooLong);
        }
        if Name::is_reserved(name) {
            reasons.push(InvalidName::Reserved);
        }
        if name.chars().any(|c| c.is_ascii_control()) {
            reasons.push(InvalidName::ContainsControlCharacter);
        }
        // The NUL character, which the strings of a manifest may not hold
        // either, is a control character.
        let noncharacter = |c: char| !c.is_ascii_control() && !STRING_RULES.admits(c.encode_utf8(&mut [0; 4]));
        if name.chars().any(noncharacter) {
            reasons.push(InvalidName::ContainsNoncharacter);
        }
        for component in name.split(SEPARATOR) {
            if component.is_empty() {
                reasons.push(InvalidName::EmptyComponent);
            }
            if component == CURRENT || component == PARENT {
                reasons.push(InvalidName::ContainsDotComponent);
            }
        }
        reasons
    }

    /// Every string of a few of the characters below is a name if the
    /// definition says so, and only then: on its own and in long names,
    /// whose bytes are looked at many at a time. If it is not one, the
    /// reason given is one of the reasons it is not.
    #[test]
    fn names_by_the_definition() {
        let characters = [
            'a',
            '.',
            SEPARATOR,
            ' ',
            '\0',
            '\u{1f}',
            '\u{7f}',
            '\u{85}',
            '\u{e9}',
            '\u{fdd0}',
            '\u{fffe}',
            '\u{10ffff}',
        ];
        let mut strings = vec![String::new()];
        let mut level = vec![String::new()];
        for _ in 0..4 {
            level = level
                .iter()
                .flat_map(|string| characters.iter().map(move |c| format!("{}{}", string, c)))
                .collect();
            strings.extend(level.iter().cloned());
        }
        let head = "abcdefgh/".repeat(8);
        let tail = "/abcdefgh".repeat(8);
        let mut valid = [0; 2];
        for string in &strings {
            for name in [
                string.clone(),
                format!("{}{}", head, string),
                format!("{}{}", string, tail),
                format!("{}{}{}", head, string, tail),
            ] {
                let reasons = reasons(&name);
                match Name::new(name.as_str()) {
                    Ok(_) => assert!(reasons.is_empty(), "{:?} {:?}", name, reasons),
                    Err(reason) => assert!(reasons.contains(&reason), "{:?} {:?} {:?}", name, reason, reasons),
                }
                valid[usize::from(reasons.is_empty())] += 1;
            }
        }
        // Both kinds come up.
        assert!(valid.iter().all(|&count| count > 0), "{:?}", valid);
        // A character a name may not have is found wherever it is.
        let name = format!("{}end", head);
        for at in 0..=name.len() {
            for (c, reason) in [
                ('\0', Some(InvalidName::ContainsControlCharacter)),
                ('\u{1f}', Some(InvalidName::ContainsControlCharacter)),
                ('\u{7f}', Some(InvalidName::ContainsControlCharacter)),
                ('\u{fdd0}', Some(InvalidName::ContainsNoncharacter)),
                ('\u{10ffff}', Some(InvalidName::ContainsNoncharacter)),
                (' ', None),
                ('\u{85}', None),
                ('\u{e9}', None),
            ] {
                let mut with = name.clone();
                with.insert(at, c);
                assert_eq!(Name::new(with.as_str()).err(), reason, "{:?}", with);
            }
        }
    }

    #[test]
    fn components_and_parents() {
        let name = Name::new("a/b/c").unwrap();
        assert_eq!(name.components().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(name.components().next_back(), Some("c"));
        assert_eq!(name.parent(), Some("a/b"));
        assert_eq!(name.file_name(), Some("c"));
        let top = Name::new("a").unwrap();
        assert_eq!(top.parent(), Some(""));
        assert_eq!(top.file_name(), Some("a"));
        assert_eq!(Name::ROOT.components().count(), 0);
        assert_eq!(Name::ROOT.parent(), None);
        assert_eq!(Name::ROOT.file_name(), None);
    }

    #[test]
    fn the_root() {
        assert!(Name::ROOT.is_root());
        assert_eq!(Name::ROOT, "");
        assert_eq!(Name::default(), Name::ROOT);
        assert_eq!(Name::new(""), Err(InvalidName::Empty));
    }

    #[test]
    fn reserved() {
        for name in [
            "Uapi16Manifest",
            "Uapi16Manifest.",
            "Uapi16Manifest.sig",
            "Uapi16Manifest.d/x",
        ] {
            assert!(Name::is_reserved(name), "{:?}", name);
        }
        for name in [
            "",
            "Uapi16Manifest2",
            "Uapi16Manifes",
            "sub/Uapi16Manifest",
            "x.Uapi16Manifest",
        ] {
            assert!(!Name::is_reserved(name), "{:?}", name);
        }
    }

    /// Joining gives the name the whole path gives, and refuses what the
    /// whole path is refused for, for the same reason. A component with a
    /// separator is more than one and refused.
    #[test]
    fn joining() {
        let long = "x".repeat(1000);
        let parents = [
            Name::ROOT,
            Name::new("a").unwrap(),
            Name::new("a/b c").unwrap(),
            Name::new("Uapi16Manifest2").unwrap(),
        ];
        for parent in &parents {
            for component in [
                "c",
                "c d",
                ".x",
                "...",
                long.as_str(),
                "",
                ".",
                "..",
                "a/b",
                "/",
                "a/..",
                "a\tb",
                "a\u{fffe}",
                "Uapi16Manifest",
                "Uapi16Manifest.sig",
                "Uapi16Manifest2",
            ] {
                let whole = if parent.is_root() {
                    component.to_string()
                } else {
                    format!("{}/{}", parent, component)
                };
                let expected = if component.contains(SEPARATOR) {
                    Err(InvalidName::ContainsSeparator)
                } else {
                    Name::new(whole)
                };
                assert_eq!(parent.join(component), expected, "{:?} {:?}", parent, component);
            }
        }
        assert_eq!(Name::ROOT.join("a").unwrap().join("b").unwrap(), "a/b");
        // The length of the whole name counts.
        let mut deep = Name::ROOT;
        while deep.len() + 2 * (long.len() + 1) <= Name::MAX_LEN {
            deep = deep.join(&long).unwrap();
        }
        let room = Name::MAX_LEN - (deep.len() + 1);
        assert!(room > 0);
        assert_eq!(deep.join(&"y".repeat(room)).unwrap().len(), Name::MAX_LEN);
        assert_eq!(deep.join(&"y".repeat(room + 1)), Err(InvalidName::TooLong));
        // A component that is too long, and wrong in another way too, is
        // refused for its length, as the whole name is.
        let wrong = format!("{}\n", "y".repeat(room));
        assert_eq!(deep.join(&wrong), Err(InvalidName::TooLong));
        assert_eq!(Name::new(format!("{}/{}", deep, wrong)), Err(InvalidName::TooLong));
    }
}
