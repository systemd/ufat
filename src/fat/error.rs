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

use uapi16::Problem;

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
    /// The directory has an entry whose name FAT does not tell apart from
    /// this one, as it does not tell `A` from `a`.
    CaseCollision,
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
            NameProblem::CaseCollision => "caseCollision",
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
    /// Nothing is there. [`crate::boot::BootSector::parse`] says so for a
    /// boot sector of zeros. Opening or checking a volume says so only
    /// when the first 256 KiB of the image are zeros, which is where file
    /// systems and partition tables keep their signatures.
    Blank,
    /// The boot sector is not that of a FAT32 volume. Opening or checking
    /// a volume says so only when libblkid finds another file system or a
    /// partition table, a FAT12 or FAT16 volume included, and names it in
    /// `found`.
    NotFat32,
    /// A FAT boot sector with a sector size this crate does not support.
    SectorSize,
    /// The image is too small to hold a file system.
    TooSmall,
    /// The image is not blank, and holds nothing this crate recognizes.
    Unknown,
}

impl NotFat32Reason {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            NotFat32Reason::Blank => "blank",
            NotFat32Reason::NotFat32 => "notFat32",
            NotFat32Reason::SectorSize => "sectorSize",
            NotFat32Reason::TooSmall => "tooSmall",
            NotFat32Reason::Unknown => "unknown",
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

/// Why a descriptor another process handed over cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorProblem {
    /// Opened with O_PATH: nothing can be read through it.
    OPath,
    /// Status flags set that the service cannot work with; `flags` says which.
    Flags,
    /// Open for writing only.
    WriteOnly,
    /// Open for writing where it has to be read-only.
    NotReadOnly,
    /// Not open for reading and writing where it has to be.
    NotReadWrite,
    /// Not open for writing where it has to be written to.
    NotWritable,
    /// Not of the type the parameter needs.
    WrongType,
}

impl DescriptorProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            DescriptorProblem::OPath => "oPath",
            DescriptorProblem::Flags => "flags",
            DescriptorProblem::WriteOnly => "writeOnly",
            DescriptorProblem::NotReadOnly => "notReadOnly",
            DescriptorProblem::NotReadWrite => "notReadWrite",
            DescriptorProblem::NotWritable => "notWritable",
            DescriptorProblem::WrongType => "wrongType",
        }
    }
}

/// What is wrong with a UAPI.16 manifest, the reason of an
/// `InvalidManifest` error of the Varlink interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestProblem {
    /// What the specification does not permit in a manifest, named by the
    /// problem the [`uapi16`] crate has for it.
    Malformed(Problem),
    /// A regular file without a size, where the size has to be known: to
    /// plan the size of a volume, or to take the contents from a stream.
    NoSize,
}

impl ManifestProblem {
    /// The value as the Varlink interface spells it, which is
    /// [`Problem::as_str`] for a problem of the [`uapi16`] crate.
    pub fn as_str(self) -> &'static str {
        match self {
            ManifestProblem::Malformed(problem) => problem.as_str(),
            ManifestProblem::NoSize => "noSize",
        }
    }
}

/// How a file below the source directory fails to be what the manifest
/// describes, found when it is opened to be copied. A file too short for
/// the contents the manifest says it holds, or not of the size the manifest
/// gives for it, is found while it is copied, see [`ContentProblem::Size`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceProblem {
    /// The file is not there.
    Missing,
    /// It is not a regular file.
    NotRegular,
}

impl SourceProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceProblem::Missing => "missing",
            SourceProblem::NotRegular => "notRegular",
        }
    }
}

/// How file contents fail to match the manifest while being copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentProblem {
    /// Not as many bytes as the manifest says, or in a file of the source
    /// that is too short for them or not of the size the manifest gives for
    /// it.
    Size,
    /// Not the SHA-256 hash the manifest says.
    Hash,
    /// The stream ended before the file was complete.
    StreamEnded,
    /// The file of the source they are in changed while it was read.
    SourceChanged,
}

impl ContentProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ContentProblem::Size => "size",
            ContentProblem::Hash => "hash",
            ContentProblem::StreamEnded => "streamEnded",
            ContentProblem::SourceChanged => "sourceChanged",
        }
    }
}

/// What a manifest asks for that cannot be done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedKind {
    /// Contents at an offset into a streamed source.
    Offset,
    /// Contents only available through a transport, named by `value`.
    Transport,
    /// A directory that refers to a sub-manifest.
    SubManifest,
    /// An inode type FAT cannot store, named by `value`.
    InodeType,
}

impl UnsupportedKind {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            UnsupportedKind::Offset => "offset",
            UnsupportedKind::Transport => "transport",
            UnsupportedKind::SubManifest => "subManifest",
            UnsupportedKind::InodeType => "inodeType",
        }
    }
}

/// Why a manifest entry is not valid now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidityProblem {
    /// Marked revoked.
    Revoked,
    /// Its validity has not begun.
    NotYetValid,
    /// Its validity has ended.
    Expired,
}

impl ValidityProblem {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ValidityProblem::Revoked => "revoked",
            ValidityProblem::NotYetValid => "notYetValid",
            ValidityProblem::Expired => "expired",
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
        /// What the image holds instead, named the way libblkid names it,
        /// such as `ext4`, `crypto_LUKS` or `gpt`. FAT12 and FAT16 volumes
        /// are `fat12` and `fat16`.
        found: Option<String>,
        /// The sector size found, when that is the reason.
        sector_size: Option<u32>,
    },
    /// The image holds something that formatting would destroy.
    NotEmpty {
        /// What it holds, named the way libblkid names it, such as
        /// `vfat`, `ext4`, `crypto_LUKS` or `gpt`. FAT12 and FAT16 volumes
        /// are `fat12` and `fat16`. `unknown` when libblkid is not
        /// available and the image is not blank.
        found: String,
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
    /// A descriptor handed over by another process is not usable.
    Descriptor {
        /// Why not.
        problem: DescriptorProblem,
        /// The offending status flags, when that is the problem.
        flags: Option<i32>,
        /// The parameter the descriptor was passed as, where its vetting or
        /// a read or write of it knows that name, as host::passed_stream()
        /// and the stream it returns do.
        parameter: Option<&'static str>,
    },
    /// The manifest is malformed.
    Manifest {
        /// What is wrong.
        problem: ManifestProblem,
        /// The index of the record, counting from 0, when known.
        record: Option<u64>,
        /// The object's name, when known.
        name: Option<String>,
        /// The field, when the problem is with one.
        field: Option<String>,
    },
    /// A file the manifest names is not below the source directory as the
    /// manifest describes it: missing, or not a regular file.
    Source {
        /// The entry's name, exactly as its record in the manifest has it.
        name: String,
        /// What is wrong.
        problem: SourceProblem,
    },
    /// File contents do not match the manifest, found while they are
    /// copied: a file below the source directory that is too short for
    /// them among them, or one that changed while it was read.
    Content {
        /// The entry's name, exactly as its record in the manifest has it.
        name: String,
        /// What is wrong.
        problem: ContentProblem,
        /// The size found, when sizes are the problem.
        size: Option<u64>,
        /// The size the manifest says, when sizes are the problem: for a
        /// part of a file, the size the file needs to hold it.
        expected: Option<u64>,
    },
    /// The manifest asks for something that cannot be done.
    Unsupported {
        /// The entry's path as the manifest names it, when about one.
        name: Option<String>,
        /// What cannot be done.
        what: UnsupportedKind,
        /// The encoding, transport or inode type asked for.
        value: Option<String>,
    },
    /// A manifest entry is revoked or outside its validity window.
    Validity {
        /// The entry's path as the manifest names it.
        name: String,
        /// Why it is not valid.
        problem: ValidityProblem,
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
    /// The error for the path `path` when its directory holds the entry
    /// at the path `existing`, whose name FAT does not tell apart from the
    /// last name of `path`, as it does not tell `A` from `a`.
    pub(crate) fn case_collision(path: &str, existing: &str) -> Error {
        let message = format!("'{}' and '{}' are names FAT cannot tell apart", path, existing);
        Error::new(EEXIST, message).with(Detail::Name {
            name: path.to_string(),
            problem: NameProblem::CaseCollision,
        })
    }

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

    /// Whether the error is about the manifest itself rather than about
    /// contents that do not match it.
    pub fn is_manifest(&self) -> bool {
        matches!(self.0.detail, Some(Detail::Manifest { .. }))
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

/// The errno of an [`std::io::Error`], and an error of ours it carries.
pub(crate) trait IoErrorExt {
    /// The error of ours the error carries, such as the one a passed
    /// stream fails with when it was made non-blocking during the call
    /// (host::PassedStream).
    fn own_error(&self) -> Option<&Error>;

    /// The errno the error stands for: that of an error of ours it
    /// carries, the one the system gave, or the one that fits its kind.
    fn errno(&self) -> i32;
}

impl IoErrorExt for std::io::Error {
    fn own_error(&self) -> Option<&Error> {
        self.get_ref().and_then(|inner| inner.downcast_ref::<Error>())
    }

    fn errno(&self) -> i32 {
        if let Some(own) = self.own_error() {
            return own.errno();
        }
        match self.raw_os_error() {
            Some(n) => n,
            None => match self.kind() {
                std::io::ErrorKind::InvalidInput => EINVAL,
                std::io::ErrorKind::OutOfMemory => ENOMEM,
                _ => EIO,
            },
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        // An io::Error wrapping one of our own errors comes back unchanged.
        if let Some(inner) = e.own_error() {
            return inner.clone();
        }
        Error::new(e.errno(), e.to_string())
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
