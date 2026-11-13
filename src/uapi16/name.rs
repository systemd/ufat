// SPDX-License-Identifier: LGPL-2.1-or-later
//! The names of file objects.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use crate::FILENAME;

/// The longest component of a name, Linux's NAME_MAX.
const NAME_MAX: usize = libc::NAME_MAX as usize;
/// The length a name stays below, Linux's PATH_MAX.
const PATH_MAX: usize = libc::PATH_MAX as usize;
/// What separates the components of a name.
const SEPARATOR: u8 = b'/';
/// The components that stand for a directory itself and for the one above
/// it. A name has neither.
const CURRENT: &[u8] = b".";
const PARENT: &[u8] = b"..";
/// What follows [`FILENAME`] in the name of a file that belongs to the
/// manifest, such as its signature or a compressed copy.
const SUFFIX_SEPARATOR: char = '.';

/// The name of a file object: the path of the file below the root of the
/// tree the manifest describes.
///
/// A name is a normalized relative path. Its components are separated by
/// single slashes, and none of them is empty, `.` or `..`. It has no
/// control characters, a component is at most 255 bytes long and the whole
/// name is shorter than 4096 bytes, as a path on Linux. It is not
/// `Uapi16Manifest` and does not begin with `Uapi16Manifest.`, the names
/// the manifest itself and what belongs to it have inside the tree.
///
/// The root file object has no name. Its name here is the empty one,
/// [`Name::ROOT`], which no file has.
///
/// ```
/// use uapi16::Name;
///
/// let name = Name::new("EFI/BOOT")?;
/// assert_eq!(name.join("BOOTX64.EFI")?, "EFI/BOOT/BOOTX64.EFI");
/// assert!("EFI//BOOT".parse::<Name>().is_err());
/// assert!(Name::new("../etc/passwd").is_err());
/// # Ok::<(), uapi16::InvalidName>(())
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// A string that is not the name of a file object, see [`Name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidName(());

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a valid relative path")
    }
}

impl std::error::Error for InvalidName {}

impl Name {
    /// The name of the root file object: the empty one.
    pub const ROOT: Name = Name(String::new());

    /// Takes `name` as the name of a file object, if it is one.
    pub fn new(name: impl Into<String>) -> Result<Name, InvalidName> {
        let name = name.into();
        if name.len() >= PATH_MAX || Name::is_reserved(&name) {
            return Err(InvalidName(()));
        }
        // A slash in UTF-8 is a byte of its own, so the bytes can be split
        // where the name can.
        for component in name.as_bytes().split(|&b| b == SEPARATOR) {
            Name::check_component(component)?;
        }
        Ok(Name(name))
    }

    /// The name of the entry `component` of the directory this name is
    /// the name of. Only the new component is looked at, so the names of
    /// a deep tree are cheap to make on the way down.
    pub fn join(&self, component: &str) -> Result<Name, InvalidName> {
        Name::check_component(component.as_bytes())?;
        if component.as_bytes().contains(&SEPARATOR) {
            return Err(InvalidName(()));
        }
        if self.is_root() {
            return Name::new(component);
        }
        let len = self.0.len() + size_of_val(&SEPARATOR) + component.len();
        if len >= PATH_MAX {
            return Err(InvalidName(()));
        }
        let mut name = String::with_capacity(len);
        name.push_str(&self.0);
        name.push(char::from(SEPARATOR));
        name.push_str(component);
        Ok(Name(name))
    }

    /// Checks one component of a name: what is between two separators.
    fn check_component(component: &[u8]) -> Result<(), InvalidName> {
        if component.is_empty()
            || component == CURRENT
            || component == PARENT
            || component.len() > NAME_MAX
            || component.iter().any(u8::is_ascii_control)
        {
            return Err(InvalidName(()));
        }
        Ok(())
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
        for name in [
            "",
            "/",
            "/abs",
            "a/",
            "a//b",
            ".",
            "..",
            "a/.",
            "a/..",
            "./a",
            "../a",
            "a/./b",
            "a/../b",
            "a\nb",
            "a\0b",
            "a/\u{1}",
            "a\u{7f}",
            "Uapi16Manifest",
            "Uapi16Manifest.",
            "Uapi16Manifest.sig",
            "Uapi16Manifest.gz",
            "Uapi16Manifest.d/inside",
        ] {
            assert!(Name::new(name).is_err(), "{:?}", name);
        }
        // The control characters of Latin-1 are not ASCII control
        // characters.
        assert!(Name::new("a\u{85}b").is_ok());
    }

    #[test]
    fn lengths() {
        let longest = "x".repeat(NAME_MAX);
        assert!(Name::new(longest.as_str()).is_ok());
        assert!(Name::new(format!("{}x", longest)).is_err());
        assert!(Name::new(format!("a/{}/b", longest)).is_ok());
        assert!(Name::new(format!("a/{}x/b", longest)).is_err());
        // A name of 100 three-byte characters is longer than a component
        // may be.
        assert!(Name::new("\u{20ac}".repeat(100)).is_err());
        // Components of 255 bytes and separators up to one below PATH_MAX.
        let mut name = String::new();
        while name.len() + NAME_MAX + 1 < PATH_MAX {
            name.push_str(&longest);
            name.push('/');
        }
        let fits = format!("{}{}", name, "y".repeat(PATH_MAX - 1 - name.len()));
        assert_eq!(fits.len(), PATH_MAX - 1);
        assert!(Name::new(fits.as_str()).is_ok());
        assert!(Name::new(format!("{}y", fits)).is_err());
    }

    #[test]
    fn the_root() {
        assert!(Name::ROOT.is_root());
        assert_eq!(Name::ROOT, "");
        assert_eq!(Name::default(), Name::ROOT);
        assert!(Name::new("").is_err());
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
    /// whole path is refused for.
    #[test]
    fn joining() {
        let longest = "x".repeat(NAME_MAX);
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
                longest.as_str(),
                "",
                ".",
                "..",
                "a/b",
                "/",
                "a\tb",
                "Uapi16Manifest",
                "Uapi16Manifest.sig",
                "Uapi16Manifest2",
            ] {
                let whole = if parent.is_root() {
                    component.to_string()
                } else {
                    format!("{}/{}", parent, component)
                };
                let expected = if component.contains('/') {
                    Err(InvalidName(()))
                } else {
                    Name::new(whole)
                };
                assert_eq!(parent.join(component), expected, "{:?} {:?}", parent, component);
            }
        }
        assert_eq!(Name::ROOT.join("a").unwrap().join("b").unwrap(), "a/b");
        // The length of the whole name counts: the longest one is one
        // byte short of PATH_MAX.
        let mut deep = Name::ROOT;
        while deep.len() + 2 * (NAME_MAX + 1) < PATH_MAX {
            deep = deep.join(&longest).unwrap();
        }
        let room = PATH_MAX - 1 - (deep.len() + 1);
        assert!(room > 0 && room <= NAME_MAX);
        assert_eq!(deep.join(&"y".repeat(room)).unwrap().len(), PATH_MAX - 1);
        assert!(deep.join(&"y".repeat(room + 1)).is_err());
    }
}
