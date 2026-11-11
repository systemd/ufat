// SPDX-License-Identifier: LGPL-2.1-or-later
//! The names of entries.
//!
//! The kernel hands the name of an entry to its path lookup as it is,
//! starting at the root of the file system it unpacks into. So `a/b`,
//! `./a/b` and `/a/b` all name the same file, and an entry called `.`
//! is the root directory itself.
//!
//! This crate writes names in one form only, see [`Name`]: relative,
//! without a leading `./`, the root as `.`. That is the form GNU cpio and
//! the kernel's own gen_init_cpio write, and the only one the kernel's
//! early lookup of microcode and ACPI tables finds, which compares names
//! byte for byte. Archives made by other tools are read in every form the
//! kernel takes, see [`Normalized`].

use std::fmt;

use crate::errno::*;
use crate::header::{MAX_NAME_LEN, TRAILER};
use crate::{sys, Detail, NameProblem, Result};

/// The longest component of a name, Linux's NAME_MAX. The file systems an
/// initramfs is unpacked into take no longer one.
pub const MAX_COMPONENT_LEN: usize = sys::NAME_MAX;
/// How much of a name that is too long an error shows.
const SHOWN_LEN: usize = 64;

/// The name of an entry in the one form this crate writes: `.` for the
/// root, else components separated by single slashes, none of them empty,
/// `.` or `..` and none longer than [`MAX_COMPONENT_LEN`], without a NUL
/// byte and at most [`MAX_NAME_LEN`] bytes long. `TRAILER!!!` is no name:
/// an entry called that ends the archive.
///
/// It is shown as text, with what is not UTF-8 replaced.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Name<'a>(&'a [u8]);

impl<'a> Name<'a> {
    /// The root directory.
    pub const ROOT: Name<'static> = Name(b".");

    /// The name `bytes` are, if they are one.
    pub fn new(bytes: &'a [u8]) -> Result<Name<'a>> {
        let shown = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        let bad = |problem: NameProblem| Detail::Name {
            name: shown(bytes),
            problem,
        };
        if bytes.is_empty() {
            bail!(EINVAL, bad(NameProblem::Empty), "the name of an entry is empty");
        }
        if bytes.len() > MAX_NAME_LEN {
            bail!(
                ENAMETOOLONG,
                bad(NameProblem::TooLong),
                "'{}...' is longer than {} bytes",
                shown(&bytes[..SHOWN_LEN]),
                MAX_NAME_LEN
            );
        }
        if bytes.contains(&0) {
            bail!(
                EINVAL,
                bad(NameProblem::InvalidCharacter),
                "'{}' contains a NUL byte",
                shown(bytes)
            );
        }
        if bytes == Name::ROOT.0 {
            return Ok(Name(bytes));
        }
        if bytes == TRAILER {
            bail!(
                EINVAL,
                bad(NameProblem::Reserved),
                "an entry named '{}' ends the archive",
                shown(bytes)
            );
        }
        for component in bytes.split(|&b| b == b'/') {
            if component.is_empty() {
                bail!(
                    EINVAL,
                    bad(NameProblem::Empty),
                    "'{}' has an empty component",
                    shown(bytes)
                );
            }
            if component == b"." || component == b".." {
                bail!(
                    EINVAL,
                    bad(NameProblem::DotComponent),
                    "'{}' has a '{}' component",
                    shown(bytes),
                    shown(component)
                );
            }
            if component.len() > MAX_COMPONENT_LEN {
                bail!(
                    ENAMETOOLONG,
                    bad(NameProblem::TooLong),
                    "a component of '{}' is longer than {} bytes",
                    shown(bytes),
                    MAX_COMPONENT_LEN
                );
            }
        }
        Ok(Name(bytes))
    }

    /// The bytes of the name.
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Whether this is the root directory.
    pub fn is_root(self) -> bool {
        self == Name::ROOT
    }

    /// The directory the name is in: None for the root, the root for a
    /// name of one component.
    pub fn parent(self) -> Option<Name<'a>> {
        if self.is_root() {
            return None;
        }
        Some(match self.0.iter().rposition(|&b| b == b'/') {
            Some(at) => Name(&self.0[..at]),
            None => Name::ROOT,
        })
    }

    /// The directories the name is below, from the one it is in upwards.
    /// The root is not among them.
    pub fn ancestors(self) -> impl Iterator<Item = Name<'a>> {
        std::iter::successors(self.parent(), |directory| directory.parent())
            .take_while(|directory| !directory.is_root())
    }

    /// The last component of the name.
    pub fn file_name(self) -> &'a [u8] {
        match self.0.iter().rposition(|&b| b == b'/') {
            Some(at) => &self.0[at + 1..],
            None => self.0,
        }
    }

    /// The name `below` has in this directory, if that is one: `below` is
    /// one or more components.
    pub fn join(self, below: &[u8]) -> Result<NameBuf> {
        if self.is_root() {
            return NameBuf::new(below.to_vec());
        }
        let mut joined = Vec::with_capacity(self.0.len() + 1 + below.len());
        joined.extend_from_slice(self.0);
        joined.push(b'/');
        joined.extend_from_slice(below);
        NameBuf::new(joined)
    }
}

impl<'a> TryFrom<&'a [u8]> for Name<'a> {
    type Error = crate::Error;

    fn try_from(bytes: &'a [u8]) -> Result<Name<'a>> {
        Name::new(bytes)
    }
}

impl fmt::Display for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        String::from_utf8_lossy(self.0).fmt(f)
    }
}

impl fmt::Debug for Name<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({:?})", String::from_utf8_lossy(self.0))
    }
}

/// A [`Name`] that is held.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NameBuf(Vec<u8>);

impl NameBuf {
    /// The name `bytes` are, if they are one.
    pub fn new(bytes: Vec<u8>) -> Result<NameBuf> {
        Name::new(&bytes)?;
        Ok(NameBuf(bytes))
    }

    /// The name.
    pub fn as_name(&self) -> Name<'_> {
        Name(&self.0)
    }

    /// The bytes of the name.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Name<'_>> for NameBuf {
    fn from(name: Name<'_>) -> NameBuf {
        NameBuf(name.0.to_vec())
    }
}

impl TryFrom<Vec<u8>> for NameBuf {
    type Error = crate::Error;

    fn try_from(bytes: Vec<u8>) -> Result<NameBuf> {
        NameBuf::new(bytes)
    }
}

impl fmt::Display for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_name().fmt(f)
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_name().fmt(f)
    }
}

/// What form a stored name is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The one this crate writes.
    Written,
    /// Another one that starts with `./`.
    LeadingDotSlash,
    /// One that starts with a slash.
    Absolute,
    /// Any other: with repeated or trailing slashes, or with `.`
    /// components.
    Unnormalized,
}

/// How a stored name ends, which decides what a lookup takes it for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// With a component of its own. Such a name leads to anything.
    Plain,
    /// With a slash. A lookup takes such a name for a directory only.
    Slash,
    /// With a `.` component, or the name is the root. Such a name stands
    /// for a directory that is there: no directory is made under it, and
    /// the one it leads to is not removed under it.
    Dot,
}

/// A name of an archive another tool wrote, read the way a path lookup
/// reads it. What it leads to need not be a [`Name`]: `./TRAILER!!!` is a
/// file called `TRAILER!!!` to the kernel, which this crate cannot write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Normalized<'a> {
    stored: &'a [u8],
    /// The form the stored name is in.
    pub form: Form,
    /// How the stored name ends.
    pub ending: Ending,
}

/// Why a stored name names nothing this crate can follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unusable {
    /// The name is empty, which no lookup accepts. It is not the root.
    Empty,
    /// A `..` component. Where it leads depends on what the path before it
    /// resolves to when the archive is unpacked.
    DotDot,
    /// A component longer than [`MAX_COMPONENT_LEN`], which no lookup
    /// accepts.
    ComponentTooLong,
}

impl<'a> Normalized<'a> {
    /// Reads a stored name the way the kernel's path lookup does, as far as
    /// that can be told from the name alone: leading, repeated and trailing
    /// slashes and `.` components carry no meaning, and what is left of the
    /// root is `.`. `stored` is the name up to its first NUL.
    pub fn new(stored: &'a [u8]) -> std::result::Result<Normalized<'a>, Unusable> {
        if stored.is_empty() {
            return Err(Unusable::Empty);
        }
        // A last component that is empty is what follows a slash at the end.
        let no_name = |path: &[u8]| matches!(path.rsplit(|&b| b == b'/').next(), Some(b"" | b"."));
        // The slashes at the end aside, what is the last component?
        let ends = stored.len() - stored.iter().rev().take_while(|&&b| b == b'/').count();
        let ending = if no_name(&stored[..ends]) {
            Ending::Dot
        } else if no_name(stored) {
            Ending::Slash
        } else {
            Ending::Plain
        };
        // Whether every component counts: none is empty or `.`.
        let mut plain = true;
        for component in stored.split(|&b| b == b'/') {
            if component.is_empty() || component == b"." {
                plain = false;
                continue;
            }
            if component == b".." {
                return Err(Unusable::DotDot);
            }
            if component.len() > MAX_COMPONENT_LEN {
                return Err(Unusable::ComponentTooLong);
            }
        }
        // The root is the one name this crate writes with a `.` in it.
        let form = if plain || stored == Name::ROOT.as_bytes() {
            Form::Written
        } else if stored.starts_with(b"./") {
            Form::LeadingDotSlash
        } else if stored.starts_with(b"/") {
            Form::Absolute
        } else {
            Form::Unnormalized
        };
        Ok(Normalized { stored, form, ending })
    }

    /// The components of the path the stored name leads to. The root has
    /// none.
    pub fn components(&self) -> impl Iterator<Item = &'a [u8]> {
        self.stored
            .split(|&b| b == b'/')
            .filter(|component| !component.is_empty() && *component != b".")
    }

    /// The path the stored name leads to: its components separated by
    /// single slashes, `.` for the root.
    pub fn name(&self) -> Vec<u8> {
        if self.form == Form::Written {
            return self.stored.to_vec();
        }
        let mut name = Vec::with_capacity(self.stored.len());
        for component in self.components() {
            if !name.is_empty() {
                name.push(b'/');
            }
            name.extend_from_slice(component);
        }
        if name.is_empty() {
            name.extend_from_slice(Name::ROOT.as_bytes());
        }
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(name: &[u8]) -> Option<NameProblem> {
        match Name::new(name).unwrap_err().detail() {
            Some(Detail::Name { problem, .. }) => Some(*problem),
            _ => None,
        }
    }

    #[test]
    fn names_this_crate_writes() {
        for name in [
            &b"."[..],
            b"a",
            b"a/b",
            b"usr/lib/modules/6.1",
            b"..a",
            b"a..",
            b"...",
            b" ",
            b"\xff\x01",
        ] {
            Name::new(name).unwrap();
        }
        assert_eq!(problem(b""), Some(NameProblem::Empty));
        for name in [&b"/"[..], b"/a", b"a/", b"a//b"] {
            assert_eq!(problem(name), Some(NameProblem::Empty), "{:?}", name);
        }
        for name in [&b"./a"[..], b"a/./b", b"a/.", b"..", b"../a", b"a/..", b"a/../b"] {
            assert_eq!(problem(name), Some(NameProblem::DotComponent), "{:?}", name);
        }
        assert_eq!(problem(b"a\0b"), Some(NameProblem::InvalidCharacter));
        assert_eq!(problem(b"TRAILER!!!"), Some(NameProblem::Reserved));
        // Only the whole name ends an archive.
        Name::new(b"a/TRAILER!!!").unwrap();
        Name::new(b"TRAILER!!!/a").unwrap();
    }

    #[test]
    fn lengths() {
        let component = vec![b'c'; MAX_COMPONENT_LEN];
        Name::new(&component).unwrap();
        let mut too_long = component.clone();
        too_long.push(b'c');
        assert_eq!(problem(&too_long), Some(NameProblem::TooLong));
        assert_eq!(Name::new(&too_long).unwrap_err().errno(), ENAMETOOLONG);
        // 4095 bytes fit, 4096 do not.
        let mut name = Vec::new();
        while name.len() + 256 <= MAX_NAME_LEN {
            name.extend_from_slice(&component);
            name.push(b'/');
        }
        name.extend(std::iter::repeat_n(b'f', MAX_NAME_LEN - name.len()));
        assert_eq!(name.len(), MAX_NAME_LEN);
        Name::new(&name).unwrap();
        name.push(b'f');
        assert_eq!(problem(&name), Some(NameProblem::TooLong));
    }

    #[test]
    fn parents_and_joins() {
        let name = |bytes| Name::new(bytes).unwrap();
        assert_eq!(Name::ROOT.parent(), None);
        assert!(Name::ROOT.is_root() && !name(b"a").is_root());
        assert_eq!(name(b"a").parent(), Some(Name::ROOT));
        assert_eq!(name(b"a/b/c").parent(), Some(name(b"a/b")));
        assert_eq!(name(b"a/b/c").file_name(), b"c");
        assert_eq!(name(b"a").file_name(), b"a");
        assert_eq!(Name::ROOT.join(b"a").unwrap().as_name(), name(b"a"));
        assert_eq!(name(b"a/b").join(b"c").unwrap().as_name(), name(b"a/b/c"));
        assert_eq!(name(b"a").join(b"b/c").unwrap().as_name(), name(b"a/b/c"));
        // What is joined is checked.
        for below in [&b""[..], b"/b", b"b/", b"..", b"b//c"] {
            assert!(name(b"a").join(below).is_err(), "{:?}", below);
            assert!(Name::ROOT.join(below).is_err(), "{:?}", below);
        }
        assert_eq!(Name::ROOT.join(b"TRAILER!!!").unwrap_err().errno(), EINVAL);
        name(b"a").join(b"TRAILER!!!").unwrap();
        // The directories a name is below, the root aside.
        let above = |bytes| name(bytes).ancestors().collect::<Vec<_>>();
        assert_eq!(above(b"."), []);
        assert_eq!(above(b"a"), []);
        assert_eq!(above(b"a/b/c"), [name(b"a/b"), name(b"a")]);
    }

    #[test]
    fn names_are_held_and_shown() {
        let held = NameBuf::new(b"etc/\xff".to_vec()).unwrap();
        assert_eq!(held.as_name().as_bytes(), b"etc/\xff");
        assert_eq!(held.to_string(), "etc/\u{fffd}");
        assert_eq!(NameBuf::from(Name::ROOT), NameBuf::new(b".".to_vec()).unwrap());
        assert_eq!(NameBuf::try_from(b"a//b".to_vec()).unwrap_err().errno(), EINVAL);
        assert_eq!(Name::try_from(&b"a/b"[..]).unwrap().to_string(), "a/b");
        assert_eq!(format!("{:?}", Name::ROOT), "Name(\".\")");
        assert_eq!(held.into_bytes(), b"etc/\xff");
    }

    #[test]
    fn stored_names_are_read_like_a_lookup_reads_them() {
        let read = |stored| {
            let normalized = Normalized::new(stored).unwrap();
            (normalized.name(), normalized.form, normalized.ending)
        };
        for (stored, ending) in [
            (&b"."[..], Ending::Dot),
            (b"a", Ending::Plain),
            (b"a/b", Ending::Plain),
            (b"a/.b", Ending::Plain),
            (b"a/b./c", Ending::Plain),
        ] {
            assert_eq!(read(stored), (stored.to_vec(), Form::Written, ending));
        }
        for (stored, name, form, ending) in [
            (&b"./a/b"[..], &b"a/b"[..], Form::LeadingDotSlash, Ending::Plain),
            (b"/a/b", b"a/b", Form::Absolute, Ending::Plain),
            (b"a//b", b"a/b", Form::Unnormalized, Ending::Plain),
            (b"a/b/", b"a/b", Form::Unnormalized, Ending::Slash),
            (b"a/b//", b"a/b", Form::Unnormalized, Ending::Slash),
            (b"a/b/.", b"a/b", Form::Unnormalized, Ending::Dot),
            (b"a/b/./", b"a/b", Form::Unnormalized, Ending::Dot),
            (b"a/./b", b"a/b", Form::Unnormalized, Ending::Plain),
            (b"./a/", b"a", Form::LeadingDotSlash, Ending::Slash),
            (b"./", b".", Form::LeadingDotSlash, Ending::Dot),
            (b"/", b".", Form::Absolute, Ending::Dot),
            (b"//", b".", Form::Absolute, Ending::Dot),
            (b"./.", b".", Form::LeadingDotSlash, Ending::Dot),
            (b"././a", b"a", Form::LeadingDotSlash, Ending::Plain),
        ] {
            assert_eq!(read(stored), (name.to_vec(), form, ending), "{:?}", stored);
            Name::new(name).unwrap();
            // The components are the ones of the path.
            let components: Vec<&[u8]> = Normalized::new(stored).unwrap().components().collect();
            let path: Vec<&[u8]> = name.split(|&b| b == b'/').filter(|c| *c != b".").collect();
            assert_eq!(components, path, "{:?}", stored);
        }
        // What a name leads to need not be a name this crate writes.
        assert_eq!(read(b"./TRAILER!!!").0, b"TRAILER!!!");
        assert!(Name::new(b"TRAILER!!!").is_err());
        assert_eq!(Normalized::new(b""), Err(Unusable::Empty));
        assert_eq!(Normalized::new(b"a/../b"), Err(Unusable::DotDot));
        assert_eq!(Normalized::new(b".."), Err(Unusable::DotDot));
        assert_eq!(Normalized::new(&vec![b'c'; 256]), Err(Unusable::ComponentTooLong));
    }
}
