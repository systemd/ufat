// SPDX-License-Identifier: LGPL-2.1-or-later
//! The error of this crate.

use std::fmt;
use std::io;

use crate::decode::Subject;
use crate::object::FileObject;
use crate::{MAX_CONTENTS, MAX_RECORD_SIZE};

/// What is wrong with a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Problem {
    /// A record is not valid JSON.
    NotJson,
    /// An object of a record has a key twice, which the specification does
    /// not permit.
    DuplicateKey,
    /// A string holds what the specification does not permit in strings: a
    /// noncharacter or the NUL character, written as it is or with an
    /// escape.
    InvalidString,
    /// A record is not a JSON object.
    NotObject,
    /// A record is not UTF-8.
    NotUtf8,
    /// A record contains a NUL byte.
    ContainsNulByte,
    /// A record does not start with the record separator.
    NoRecordSeparator,
    /// A record is larger than [`MAX_RECORD_SIZE`], its record separator
    /// counted.
    RecordTooLarge,
    /// The manifest holds no object at all.
    NoObjects,
    /// The trailer object is missing.
    NoTrailer,
    /// Data follows the trailer object.
    DataAfterTrailer,
    /// A file object follows a signature object.
    FileAfterSignature,
    /// The media type is missing on the first object, is not a string, or
    /// is not the one of a manifest where it has to be.
    InvalidMediaType,
    /// The root file object has a name.
    RootHasName,
    /// The root file object is not a directory.
    RootNotDirectory,
    /// The root file object does not declare the order a consumer requires
    /// in `order`, see
    /// [`RootObject::require_order`](crate::RootObject::require_order).
    NoOrder,
    /// An object after the first has no name.
    NoName,
    /// A name is not one a file object can have, for one of the reasons of
    /// [`InvalidName`](crate::InvalidName).
    InvalidName,
    /// Two objects carry the same name.
    DuplicateName,
    /// A file object does not come right after the file object of its
    /// directory: the directory is not listed, or its entries ended.
    Misplaced,
    /// A file object comes after one it sorts before, in the order the
    /// manifest declares.
    OutOfOrder,
    /// A file object has a field of a feature the manifest does not list in
    /// `features`.
    UnlistedFeature,
    /// A symbolic link has no target in a manifest that records the targets
    /// of symbolic links.
    NoTarget,
    /// An inode type the specification does not have.
    UnknownType,
    /// A field is of the wrong JSON type or shape.
    WrongFieldType,
    /// The value of a field is out of range.
    FieldOutOfRange,
    /// A field the object cannot have: one its inode type does not permit,
    /// one only the root file object has on another object, or one only the
    /// other file objects have on the root file object.
    FieldNotPermitted,
    /// Two fields contradict each other.
    Contradiction,
    /// A contents object is malformed, or there are more than
    /// [`MAX_CONTENTS`] of them.
    InvalidContents,
    /// A signature object is malformed.
    InvalidSignature,
    /// The `extendedAttributes` field is malformed.
    InvalidExtendedAttributes,
}

impl Problem {
    /// Every problem, in the order of the variants. A problem added to the
    /// enum is added here too, which a test of this crate checks.
    pub const ALL: &'static [Problem] = &[
        Problem::NotJson,
        Problem::DuplicateKey,
        Problem::InvalidString,
        Problem::NotObject,
        Problem::NotUtf8,
        Problem::ContainsNulByte,
        Problem::NoRecordSeparator,
        Problem::RecordTooLarge,
        Problem::NoObjects,
        Problem::NoTrailer,
        Problem::DataAfterTrailer,
        Problem::FileAfterSignature,
        Problem::InvalidMediaType,
        Problem::RootHasName,
        Problem::RootNotDirectory,
        Problem::NoOrder,
        Problem::NoName,
        Problem::InvalidName,
        Problem::DuplicateName,
        Problem::Misplaced,
        Problem::OutOfOrder,
        Problem::UnlistedFeature,
        Problem::NoTarget,
        Problem::UnknownType,
        Problem::WrongFieldType,
        Problem::FieldOutOfRange,
        Problem::FieldNotPermitted,
        Problem::Contradiction,
        Problem::InvalidContents,
        Problem::InvalidSignature,
        Problem::InvalidExtendedAttributes,
    ];

    /// The name of the problem, such as `noTrailer`, for a caller that
    /// passes it on, in the errors of an interface for example. The names
    /// are stable and do not follow the names of the variants:
    /// [`Problem::RootHasName`] is `firstHasName`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Problem::NotJson => "notJson",
            Problem::DuplicateKey => "duplicateKey",
            Problem::InvalidString => "invalidString",
            Problem::NotObject => "notObject",
            Problem::NotUtf8 => "notUtf8",
            Problem::ContainsNulByte => "nulByte",
            Problem::NoRecordSeparator => "recordSeparator",
            Problem::RecordTooLarge => "recordTooLarge",
            Problem::NoObjects => "empty",
            Problem::NoTrailer => "noTrailer",
            Problem::DataAfterTrailer => "dataAfterTrailer",
            Problem::FileAfterSignature => "fileAfterSignature",
            Problem::InvalidMediaType => "mediaType",
            Problem::RootHasName => "firstHasName",
            Problem::RootNotDirectory => "firstNotDirectory",
            Problem::NoOrder => "noOrder",
            Problem::NoName => "noName",
            Problem::InvalidName => "invalidName",
            Problem::DuplicateName => "duplicateName",
            Problem::Misplaced => "misplaced",
            Problem::OutOfOrder => "outOfOrder",
            Problem::UnlistedFeature => "unlistedFeature",
            Problem::NoTarget => "noTarget",
            Problem::UnknownType => "unknownType",
            Problem::WrongFieldType => "fieldType",
            Problem::FieldOutOfRange => "fieldRange",
            Problem::FieldNotPermitted => "fieldNotPermitted",
            Problem::Contradiction => "contradiction",
            Problem::InvalidContents => "contents",
            Problem::InvalidSignature => "signature",
            Problem::InvalidExtendedAttributes => "extendedAttributes",
        }
    }
}

/// Why a file object must not be used now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Invalid {
    /// Its `validity` is `revoked`.
    Revoked,
    /// The time is before its `validSinceUSec`.
    NotYetValid,
    /// The time is not before its `validUntilUSec`.
    Expired,
}

/// What kind of error an [`Error`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The manifest is malformed.
    Manifest(Problem),
    /// A file object is revoked or outside its validity window.
    NotValid(Invalid),
    /// Reading or writing failed.
    Io,
}

/// A field of an object of a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Field {
    /// `name` of a file object.
    Name,
    /// `mediaType` of any object.
    MediaType,
    /// `type` of a file object.
    Type,
    /// `size` of a file object.
    Size,
    /// `mode` of a file object.
    Mode,
    /// `uid` of a file object.
    Uid,
    /// `gid` of a file object.
    Gid,
    /// `userName` of a file object.
    UserName,
    /// `groupName` of a file object.
    GroupName,
    /// `major` of a file object.
    Major,
    /// `minor` of a file object.
    Minor,
    /// `mTimeNSec` of a file object.
    MTimeNSec,
    /// `inodeToken` of a file object.
    InodeToken,
    /// `extendedAttributes` of a file object.
    ExtendedAttributes,
    /// `gptLabel` of a file object.
    GptLabel,
    /// `gptUuid` of a file object.
    GptUuid,
    /// `gptTypeUuid` of a file object.
    GptTypeUuid,
    /// `gptDiskUuid` of the root file object.
    GptDiskUuid,
    /// `gptFlags` of a file object.
    GptFlags,
    /// `gptFlagNoAuto` of a file object.
    GptFlagNoAuto,
    /// `gptFlagGrowFileSystem` of a file object.
    GptFlagGrowFileSystem,
    /// `readOnly` of a file object.
    ReadOnly,
    /// `flagHidden` of a file object.
    FlagHidden,
    /// `flagSystem` of a file object.
    FlagSystem,
    /// `flagArchive` of a file object.
    FlagArchive,
    /// `flagAppendOnly` of a file object.
    FlagAppendOnly,
    /// `flagImmutable` of a file object.
    FlagImmutable,
    /// `flagNoAtime` of a file object.
    FlagNoAtime,
    /// `flagNoCow` of a file object.
    FlagNoCow,
    /// `flagNoDump` of a file object.
    FlagNoDump,
    /// `fatSerial` of the root file object.
    FatSerial,
    /// `fsUUID` of the root file object.
    FsUuid,
    /// `fsLabel` of the root file object.
    FsLabel,
    /// `order` of the root file object.
    Order,
    /// `features` of the root file object.
    Features,
    /// `contents` of a file object.
    Contents,
    /// `sha256` of a file object.
    Sha256,
    /// `validSinceUSec` of a file object.
    ValidSinceUSec,
    /// `validUntilUSec` of a file object.
    ValidUntilUSec,
    /// `validity` of a file object.
    Validity,
    /// `file` of a contents object.
    File,
    /// `url` of a contents object.
    Url,
    /// `literal` of a contents object.
    Literal,
    /// `encoding` of a contents object.
    Encoding,
    /// `encodedSize` of a contents object.
    EncodedSize,
    /// `encodedSha256` of a contents object.
    EncodedSha256,
    /// `originalSize` of a contents object.
    OriginalSize,
    /// `originalSha256` of a contents object.
    OriginalSha256,
    /// `offset` of a contents object.
    Offset,
    /// `httpHeaders` of a contents object.
    HttpHeaders,
    /// `text` of the value of an extended attribute.
    Text,
    /// `base64` of the value of an extended attribute.
    Base64,
    /// `mechanism` of a signature object.
    Mechanism,
    /// `key` of a signature object.
    Key,
    /// `data` of a signature object.
    Data,
}

impl Field {
    /// The field as its object spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Field::Name => "name",
            Field::MediaType => "mediaType",
            Field::Type => "type",
            Field::Size => "size",
            Field::Mode => "mode",
            Field::Uid => "uid",
            Field::Gid => "gid",
            Field::UserName => "userName",
            Field::GroupName => "groupName",
            Field::Major => "major",
            Field::Minor => "minor",
            Field::MTimeNSec => "mTimeNSec",
            Field::InodeToken => "inodeToken",
            Field::ExtendedAttributes => "extendedAttributes",
            Field::GptLabel => "gptLabel",
            Field::GptUuid => "gptUuid",
            Field::GptTypeUuid => "gptTypeUuid",
            Field::GptDiskUuid => "gptDiskUuid",
            Field::GptFlags => "gptFlags",
            Field::GptFlagNoAuto => "gptFlagNoAuto",
            Field::GptFlagGrowFileSystem => "gptFlagGrowFileSystem",
            Field::ReadOnly => "readOnly",
            Field::FlagHidden => "flagHidden",
            Field::FlagSystem => "flagSystem",
            Field::FlagArchive => "flagArchive",
            Field::FlagAppendOnly => "flagAppendOnly",
            Field::FlagImmutable => "flagImmutable",
            Field::FlagNoAtime => "flagNoAtime",
            Field::FlagNoCow => "flagNoCow",
            Field::FlagNoDump => "flagNoDump",
            Field::FatSerial => "fatSerial",
            Field::FsUuid => "fsUUID",
            Field::FsLabel => "fsLabel",
            Field::Order => "order",
            Field::Features => "features",
            Field::Contents => "contents",
            Field::Sha256 => "sha256",
            Field::ValidSinceUSec => "validSinceUSec",
            Field::ValidUntilUSec => "validUntilUSec",
            Field::Validity => "validity",
            Field::File => "file",
            Field::Url => "url",
            Field::Literal => "literal",
            Field::Encoding => "encoding",
            Field::EncodedSize => "encodedSize",
            Field::EncodedSha256 => "encodedSha256",
            Field::OriginalSize => "originalSize",
            Field::OriginalSha256 => "originalSha256",
            Field::Offset => "offset",
            Field::HttpHeaders => "httpHeaders",
            Field::Text => "text",
            Field::Base64 => "base64",
            Field::Mechanism => "mechanism",
            Field::Key => "key",
            Field::Data => "data",
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What an error was caused by.
#[derive(Debug)]
enum Cause {
    Io(io::Error),
    Json(json::ParseError),
}

/// What went wrong reading a manifest, or using one.
///
/// [`Error::kind`] says what kind of error it is. The other methods say
/// what it is about, as far as that is known: the record of the manifest,
/// the name of the file object, the field. The error prints as a sentence
/// for a person.
///
/// The parts live behind one allocation, like those of [`io::Error`], so
/// that a `Result` stays small.
#[derive(Debug)]
pub struct Error(Box<Inner>);

#[derive(Debug)]
struct Inner {
    kind: ErrorKind,
    message: String,
    record_number: Option<u64>,
    name: Option<String>,
    field: Option<Field>,
    cause: Option<Cause>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: String) -> Error {
        Error(Box::new(Inner {
            kind,
            message,
            record_number: None,
            name: None,
            field: None,
            cause: None,
        }))
    }

    /// A manifest that is malformed.
    pub(crate) fn manifest(problem: Problem, message: String) -> Error {
        Error::new(ErrorKind::Manifest(problem), message)
    }

    /// Names the record the error is about, unless one is named.
    #[must_use]
    pub(crate) fn in_record(mut self, record_number: u64) -> Error {
        self.0.record_number.get_or_insert(record_number);
        self
    }

    /// Names the file object the error is about.
    #[must_use]
    pub(crate) fn named(mut self, name: impl Into<String>) -> Error {
        self.0.name = Some(name.into());
        self
    }

    /// Names the field the error is about.
    #[must_use]
    pub(crate) fn at(mut self, field: Field) -> Error {
        self.0.field = Some(field);
        self
    }

    /// Notes the I/O error behind this one.
    #[must_use]
    pub(crate) fn caused_by(mut self, error: io::Error) -> Error {
        self.0.cause = Some(Cause::Io(error));
        self
    }

    /// A record that is not JSON, that has a key twice in an object, or
    /// that has a string the specification does not permit.
    pub(crate) fn not_json(record_number: u64, error: json::ParseError) -> Error {
        let (problem, message) = match error.kind {
            json::ParseErrorKind::Syntax => (
                Problem::NotJson,
                format!("manifest record {} is not valid JSON: {}", record_number, error),
            ),
            json::ParseErrorKind::DuplicateKey => (
                Problem::DuplicateKey,
                format!(
                    "manifest record {} has a key twice in an object: {}",
                    record_number, error
                ),
            ),
            json::ParseErrorKind::StringRule => (
                Problem::InvalidString,
                format!("manifest record {} has an invalid string: {}", record_number, error),
            ),
        };
        let mut e = Error::manifest(problem, message).in_record(record_number);
        e.0.cause = Some(Cause::Json(error));
        e
    }

    /// The root file object, which has a name.
    pub(crate) fn root_has_name() -> Error {
        Error::manifest(Problem::RootHasName, "the root file object has a name".into()).at(Field::Name)
    }

    /// The root file object, which is not a directory.
    pub(crate) fn root_not_directory() -> Error {
        Error::manifest(
            Problem::RootNotDirectory,
            "the root file object is not a directory".into(),
        )
        .at(Field::Type)
    }

    /// A file object after the root file object, in the record with the
    /// number `record_number`, that has no name.
    pub(crate) fn no_name(record_number: u64) -> Error {
        Error::manifest(
            Problem::NoName,
            format!("manifest object {} has no name", record_number),
        )
        .at(Field::Name)
        .in_record(record_number)
    }

    /// A file object in the record with the number `record_number`, behind
    /// a signature object.
    pub(crate) fn file_after_signature(record_number: u64) -> Error {
        Error::manifest(
            Problem::FileAfterSignature,
            "manifest contains a file object after a signature object".into(),
        )
        .in_record(record_number)
    }

    /// Data in the record with the number `record_number`, behind the
    /// trailer object.
    pub(crate) fn data_after_trailer(record_number: u64) -> Error {
        Error::manifest(
            Problem::DataAfterTrailer,
            "manifest contains data after the trailer object".into(),
        )
        .in_record(record_number)
    }

    /// A record larger than [`MAX_RECORD_SIZE`], its record separator
    /// counted.
    pub(crate) fn record_too_large() -> Error {
        Error::manifest(
            Problem::RecordTooLarge,
            format!("manifest record exceeds {} bytes", MAX_RECORD_SIZE),
        )
    }

    /// A file object, which `subject` names, with more than
    /// [`MAX_CONTENTS`] contents objects.
    pub(crate) fn too_many_contents(subject: Subject<'_>) -> Error {
        Error::manifest(
            Problem::InvalidContents,
            format!("{}: more than {} contents entries", subject, MAX_CONTENTS),
        )
        .at(Field::Contents)
    }

    /// `object`, which `subject` names, states the flag of the field
    /// `field`, which it cannot have, see [`FileObject::unpermitted_flag`].
    pub(crate) fn unpermitted_flag(object: &FileObject, field: Field, subject: Subject<'_>) -> Error {
        Error::manifest(
            Problem::FieldNotPermitted,
            format!("{}: '{}' is not permitted on a {}", subject, field, object.inode_type),
        )
        .at(field)
    }
}

impl Error {
    /// What kind of error this is.
    pub fn kind(&self) -> ErrorKind {
        self.0.kind
    }

    /// The number of the record the error is about, counting from 0.
    pub fn record_number(&self) -> Option<u64> {
        self.0.record_number
    }

    /// The name of the file object the error is about, as its record has
    /// it. The name can be the very thing that is wrong.
    pub fn name(&self) -> Option<&str> {
        self.0.name.as_deref()
    }

    /// The field the error is about.
    pub fn field(&self) -> Option<Field> {
        self.0.field
    }

    /// The I/O error behind this one, if there is one.
    pub fn io_error(&self) -> Option<&io::Error> {
        match &self.0.cause {
            Some(Cause::Io(e)) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.0.kind, &self.0.cause) {
            (ErrorKind::Io, Some(Cause::Io(e))) => e.fmt(f),
            _ => f.write_str(&self.0.message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0.cause {
            Some(Cause::Io(e)) => Some(e),
            Some(Cause::Json(e)) => Some(e),
            None => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::new(ErrorKind::Io, String::new()).caused_by(e)
    }
}

impl From<Error> for io::Error {
    /// An I/O error comes back as it went in. Any other error becomes
    /// the payload of an I/O error of the kind `InvalidData`.
    fn from(e: Error) -> io::Error {
        match *e.0 {
            Inner {
                kind: ErrorKind::Io,
                cause: Some(Cause::Io(e)),
                ..
            } => e,
            inner => io::Error::new(io::ErrorKind::InvalidData, Error(Box::new(inner))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_io_error_passes_through() {
        let e = Error::from(io::Error::from_raw_os_error(libc::ENOSPC));
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::ENOSPC));
        assert_eq!(e.to_string(), io::Error::from_raw_os_error(libc::ENOSPC).to_string());
        assert!(std::error::Error::source(&e).is_some());
        assert_eq!(io::Error::from(e).raw_os_error(), Some(libc::ENOSPC));
        // Any other error is carried by an I/O error.
        let e = Error::manifest(Problem::NoTrailer, "incomplete".to_string());
        let io = io::Error::from(e);
        assert_eq!(io.kind(), io::ErrorKind::InvalidData);
        let inner = io.get_ref().and_then(|e| e.downcast_ref::<Error>()).unwrap();
        assert_eq!(inner.kind(), ErrorKind::Manifest(Problem::NoTrailer));
        assert_eq!(io.to_string(), "incomplete");
    }

    /// The names of the problems the vectors of refused.jsonl do not hold:
    /// those of the bytes of a manifest that are not UTF-8, that do not
    /// start with a record separator or that are too large, and the one of
    /// the order a consumer requires.
    #[test]
    fn problem_names() {
        for (problem, name) in [
            (Problem::NotUtf8, "notUtf8"),
            (Problem::NoRecordSeparator, "recordSeparator"),
            (Problem::RecordTooLarge, "recordTooLarge"),
            (Problem::NoOrder, "noOrder"),
        ] {
            assert_eq!(problem.as_str(), name);
        }
    }

    /// Where `problem` is in [`Problem::ALL`]. As a constant it does not
    /// build for a problem that ALL lacks.
    const fn position_in_all(problem: Problem) -> usize {
        let mut position = 0;
        while position < Problem::ALL.len() {
            if Problem::ALL[position] as usize == problem as usize {
                return position;
            }
            position += 1;
        }
        panic!("Problem::ALL lacks a problem");
    }

    /// ALL holds every problem once, in the order of the variants, and no
    /// two problems have the same name. The match names every problem, so
    /// a problem added to the enum does not build without an arm here, and
    /// its arm, a constant, does not build until ALL has the problem.
    #[test]
    fn all_problems() {
        let position = |problem: Problem| match problem {
            Problem::NotJson => const { position_in_all(Problem::NotJson) },
            Problem::DuplicateKey => const { position_in_all(Problem::DuplicateKey) },
            Problem::InvalidString => const { position_in_all(Problem::InvalidString) },
            Problem::NotObject => const { position_in_all(Problem::NotObject) },
            Problem::NotUtf8 => const { position_in_all(Problem::NotUtf8) },
            Problem::ContainsNulByte => const { position_in_all(Problem::ContainsNulByte) },
            Problem::NoRecordSeparator => const { position_in_all(Problem::NoRecordSeparator) },
            Problem::RecordTooLarge => const { position_in_all(Problem::RecordTooLarge) },
            Problem::NoObjects => const { position_in_all(Problem::NoObjects) },
            Problem::NoTrailer => const { position_in_all(Problem::NoTrailer) },
            Problem::DataAfterTrailer => const { position_in_all(Problem::DataAfterTrailer) },
            Problem::FileAfterSignature => const { position_in_all(Problem::FileAfterSignature) },
            Problem::InvalidMediaType => const { position_in_all(Problem::InvalidMediaType) },
            Problem::RootHasName => const { position_in_all(Problem::RootHasName) },
            Problem::RootNotDirectory => const { position_in_all(Problem::RootNotDirectory) },
            Problem::NoOrder => const { position_in_all(Problem::NoOrder) },
            Problem::NoName => const { position_in_all(Problem::NoName) },
            Problem::InvalidName => const { position_in_all(Problem::InvalidName) },
            Problem::DuplicateName => const { position_in_all(Problem::DuplicateName) },
            Problem::Misplaced => const { position_in_all(Problem::Misplaced) },
            Problem::OutOfOrder => const { position_in_all(Problem::OutOfOrder) },
            Problem::UnlistedFeature => const { position_in_all(Problem::UnlistedFeature) },
            Problem::NoTarget => const { position_in_all(Problem::NoTarget) },
            Problem::UnknownType => const { position_in_all(Problem::UnknownType) },
            Problem::WrongFieldType => const { position_in_all(Problem::WrongFieldType) },
            Problem::FieldOutOfRange => const { position_in_all(Problem::FieldOutOfRange) },
            Problem::FieldNotPermitted => const { position_in_all(Problem::FieldNotPermitted) },
            Problem::Contradiction => const { position_in_all(Problem::Contradiction) },
            Problem::InvalidContents => const { position_in_all(Problem::InvalidContents) },
            Problem::InvalidSignature => const { position_in_all(Problem::InvalidSignature) },
            Problem::InvalidExtendedAttributes => const { position_in_all(Problem::InvalidExtendedAttributes) },
        };
        for (i, &problem) in Problem::ALL.iter().enumerate() {
            assert_eq!((position(problem), problem as usize), (i, i), "{:?}", problem);
        }
        let names: std::collections::HashSet<&str> = Problem::ALL.iter().map(|problem| problem.as_str()).collect();
        assert_eq!(names.len(), Problem::ALL.len());
    }
}
