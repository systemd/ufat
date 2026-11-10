// SPDX-License-Identifier: LGPL-2.1-or-later
//! The crate's error type: an errno, a message for people, and a detail
//! that says in a form a program can act on what the error is about.
//!
//! The message is English prose for the command line. The detail is what
//! the Varlink service reports, and the only thing it reports: an error
//! name with typed fields that a client renders in its own language. A
//! site that raises an error a client can do something about sets the
//! detail; an error without one is a plain errno to the service.

use std::fmt;

use crate::errno::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOMEM, ENOTDIR, ENOTEMPTY};

/// What is wrong with a name inside a volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameProblem {
    /// The name is empty.
    Empty,
    /// "." or "..", as a name or as a path component.
    DotComponent,
    /// A control character, U+FFFF or one of `" * / : < > ? \ |`.
    InvalidCharacter,
    /// The name starts with a space.
    LeadingSpace,
    /// The name ends with a space or a dot.
    TrailingSpaceOrDot,
    /// More than 255 UTF-16 units, or a path longer than PATH_MAX.
    TooLong,
}

impl NameProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            NameProblem::Empty => "empty",
            NameProblem::DotComponent => "dotComponent",
            NameProblem::InvalidCharacter => "invalidCharacter",
            NameProblem::LeadingSpace => "leadingSpace",
            NameProblem::TrailingSpaceOrDot => "trailingSpaceOrDot",
            NameProblem::TooLong => "tooLong",
        }
    }
}

/// What is wrong with a volume label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelProblem {
    /// Longer than the 11 characters FAT stores.
    TooLong,
    /// A character a FAT label cannot hold: a non-printable or non-ASCII
    /// one, one of `* ? . , ; : / \ | + = < > [ ] "`, or a leading space.
    InvalidCharacter,
    /// The file system has no label at all; unused on FAT.
    NotSupported,
}

impl LabelProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            LabelProblem::TooLong => "tooLong",
            LabelProblem::InvalidCharacter => "invalidCharacter",
            LabelProblem::NotSupported => "notSupported",
        }
    }
}

/// What is wrong with a file system identifier, the volume serial number
/// on FAT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierProblem {
    /// Not `XXXX-XXXX` or eight hex digits.
    Malformed,
    /// An identifier of another kind than the one the file system
    /// carries, a UUID where FAT has a 32 bit serial.
    WrongKind,
    /// The file system carries no identifier; unused on FAT.
    NotSupported,
    /// A value the file system reserves; unused on FAT.
    Reserved,
}

impl IdentifierProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            IdentifierProblem::Malformed => "malformed",
            IdentifierProblem::WrongKind => "wrongKind",
            IdentifierProblem::NotSupported => "notSupported",
            IdentifierProblem::Reserved => "reserved",
        }
    }
}

/// What a volume ran out of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoSpaceReason {
    /// No free cluster is left.
    Clusters,
    /// The volume is too small for a FAT32 file system of the geometry asked for.
    Volume,
    /// A directory has all the entry slots FAT32 allows.
    DirectoryEntries,
    /// Every numeric tail for the short name is taken.
    ShortNames,
}

impl NoSpaceReason {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            NoSpaceReason::Clusters => "clusters",
            NoSpaceReason::Volume => "volume",
            NoSpaceReason::DirectoryEntries => "directoryEntries",
            NoSpaceReason::ShortNames => "shortNames",
        }
    }
}

/// Why an image holds no FAT32 file system we can work with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotFat32Reason {
    /// The boot sector is all zeros.
    Blank,
    /// A FAT12 or FAT16 volume, or no FAT at all.
    NotFat32,
    /// A sector size this crate does not support.
    SectorSize,
    /// The image is too small to hold a file system.
    TooSmall,
}

impl NotFat32Reason {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            NotFat32Reason::Blank => "blank",
            NotFat32Reason::NotFat32 => "notFat32",
            NotFat32Reason::SectorSize => "sectorSize",
            NotFat32Reason::TooSmall => "tooSmall",
        }
    }
}

/// Which structure of a volume is damaged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptPlace {
    /// A field of the boot sector, named by `field`.
    BootSector,
    /// The FAT itself.
    Fat,
    /// A cluster chain: it loops, or runs into a free, bad or invalid entry.
    Chain,
    /// A directory's contents.
    Directory,
}

impl CorruptPlace {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            CorruptPlace::BootSector => "bootSector",
            CorruptPlace::Fat => "fat",
            CorruptPlace::Chain => "chain",
            CorruptPlace::Directory => "directory",
        }
    }
}

/// What an error is about, for a program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Detail {
    /// The path inside the volume the error is about: it does not exist,
    /// exists already, is or is not a directory, is not empty.
    Path(String),
    /// A name inside the volume is not valid.
    Name {
        /// The name, or the path when the problem is with a path.
        name: String,
        /// What is wrong with it.
        problem: NameProblem,
    },
    /// A volume label is not valid.
    Label {
        /// The label as it was given.
        label: String,
        /// What is wrong with it.
        problem: LabelProblem,
    },
    /// A file system identifier, the volume serial number, is not valid.
    Identifier {
        /// The identifier as it was given.
        identifier: String,
        /// What is wrong with it.
        problem: IdentifierProblem,
    },
    /// A file or a volume is larger than FAT32 allows.
    TooLarge {
        /// The path inside the volume, for a file.
        path: Option<String>,
        /// The size in bytes.
        size: u64,
        /// The largest size FAT32 allows, in bytes.
        maximum: u64,
    },
    /// The volume has no room.
    NoSpace {
        /// What ran out.
        reason: NoSpaceReason,
        /// The path inside the volume of what did not fit.
        path: Option<String>,
    },
    /// The image holds no FAT32 file system.
    NotFat32 {
        /// Why not.
        reason: NotFat32Reason,
        /// The sector size found, when that is the reason.
        sector_size: Option<u32>,
    },
    /// The file system is damaged.
    Corrupt {
        /// Which structure.
        place: CorruptPlace,
        /// The boot sector field, for the boot sector.
        field: Option<&'static str>,
        /// The path inside the volume of the entry affected.
        path: Option<String>,
        /// The cluster where the damage was found.
        cluster: Option<u32>,
    },
    /// An option the caller gave is not valid, named as the Varlink
    /// interface spells it.
    InvalidOption(&'static str),
}

/// An error with an errno value, a description of what went wrong and the
/// detail a program acts on.
///
/// The parts live behind one allocation, like those of [`std::io::Error`],
/// so that a [`Result`] stays as small as its value.
#[derive(Clone, PartialEq, Eq)]
pub struct Error(Box<Inner>);

#[derive(Clone, PartialEq, Eq)]
struct Inner {
    errno: i32,
    message: String,
    detail: Option<Detail>,
}

impl Error {
    /// Creates an error from a positive errno value and a message.
    pub fn new(errno: i32, message: impl Into<String>) -> Self {
        Error(Box::new(Inner {
            errno: i32::try_from(errno.unsigned_abs()).unwrap_or(i32::MAX),
            message: message.into(),
            detail: None,
        }))
    }

    /// The positive errno value describing this error.
    pub fn errno(&self) -> i32 {
        self.0.errno
    }

    /// What the error is about, for a program, if anything beyond the
    /// errno.
    pub fn detail(&self) -> Option<&Detail> {
        self.0.detail.as_ref()
    }

    /// Attaches the detail.
    #[must_use]
    pub fn with(mut self, detail: Detail) -> Self {
        self.0.detail = Some(detail);
        self
    }

    /// Names the path inside the volume the error is about, where the
    /// detail has room for one and none is set yet: the file that did not
    /// fit, the entry that is too large, the directory found damaged, or
    /// the path of an error that is about nothing but a path so far.
    #[must_use]
    pub fn at_path(mut self, path: &str) -> Self {
        let inner = &mut *self.0;
        match &mut inner.detail {
            Some(
                Detail::NoSpace { path: p, .. } | Detail::TooLarge { path: p, .. } | Detail::Corrupt { path: p, .. },
            ) if p.is_none() => {
                *p = Some(path.to_string());
            }
            None if matches!(inner.errno, ENOENT | EEXIST | ENOTDIR | EISDIR | ENOTEMPTY) => {
                inner.detail = Some(Detail::Path(path.to_string()));
            }
            _ => {}
        }
        self
    }

    /// The message describing this error.
    pub fn message(&self) -> &str {
        &self.0.message
    }

    /// Prefixes the message with additional context.
    #[must_use]
    pub fn context(mut self, context: impl fmt::Display) -> Self {
        self.0.message = format!("{}: {}", context, self.0.message);
        self
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Error")
            .field("errno", &self.0.errno)
            .field("message", &self.0.message)
            .field("detail", &self.0.detail)
            .finish()
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        // An io::Error wrapping one of our own errors comes back unchanged.
        if let Some(inner) = e.get_ref().and_then(|i| i.downcast_ref::<Error>()) {
            return inner.clone();
        }
        let errno = match e.raw_os_error() {
            Some(n) => n,
            None => match e.kind() {
                std::io::ErrorKind::InvalidInput => EINVAL,
                std::io::ErrorKind::OutOfMemory => ENOMEM,
                _ => EIO,
            },
        };
        Error::new(errno, e.to_string())
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        let kind = std::io::Error::from_raw_os_error(e.errno()).kind();
        std::io::Error::new(kind, e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.message)
    }
}

impl std::error::Error for Error {}

/// The result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Adds context to a failure while turning it into an [`Error`].
pub trait Context<T> {
    /// Turns the error into an [`Error`] and prefixes its message with
    /// what `context` returns, which is only called on failure.
    fn with_context<D: fmt::Display>(self, context: impl FnOnce() -> D) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn with_context<D: fmt::Display>(self, context: impl FnOnce() -> D) -> Result<T> {
        self.map_err(|e| e.into().context(context()))
    }
}

/// Builds an [`Error`] from an errno constant and a format string, with
/// a [`Detail`] before the format string when there is one:
/// `err!(ENOENT, Detail::Path(p), "'{}' does not exist", p)`.
#[macro_export]
macro_rules! err {
    ($errno:expr, $fmt:literal $($arg:tt)*) => {
        $crate::Error::new($errno, ::std::format!($fmt $($arg)*))
    };
    ($errno:expr, $detail:expr, $fmt:literal $($arg:tt)*) => {
        $crate::Error::new($errno, ::std::format!($fmt $($arg)*)).with($detail)
    };
}

/// Returns early with an [`Error`] built like [`err!`].
#[macro_export]
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::err!($($arg)*))
    };
}
