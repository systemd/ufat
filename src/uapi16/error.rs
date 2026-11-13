// SPDX-License-Identifier: LGPL-2.1-or-later
//! The error of this crate.

use std::fmt;
use std::io;

/// What is wrong with a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Problem {
    /// A record is not valid JSON.
    NotJson,
    /// A record is not a JSON object.
    NotObject,
    /// A record is not UTF-8.
    NotUtf8,
    /// A record contains a NUL byte.
    NulByte,
    /// A record does not start with the record separator.
    RecordSeparator,
    /// A record is larger than [`MAX_RECORD_SIZE`](crate::MAX_RECORD_SIZE).
    RecordTooLarge,
    /// The manifest holds no object at all.
    Empty,
    /// The trailer object is missing.
    NoTrailer,
    /// Data follows the trailer object.
    DataAfterTrailer,
    /// A file object follows a signature object.
    FileAfterSignature,
    /// The media type is missing on the first object, is not a string, or
    /// is not the one of a manifest where it has to be.
    MediaType,
    /// The first object has a name.
    FirstHasName,
    /// The first object is not a directory.
    FirstNotDirectory,
    /// An object after the first has no name.
    NoName,
    /// A name is not a normalized relative path, see [`Name`](crate::Name).
    InvalidName,
    /// Two objects carry the same name.
    DuplicateName,
    /// An inode type the specification does not have.
    UnknownType,
    /// A field is of the wrong JSON type or shape.
    FieldType,
    /// The value of a field is out of range.
    FieldRange,
    /// A field that the inode type of the object does not permit.
    FieldNotPermitted,
    /// Two fields contradict each other.
    Contradiction,
    /// A contents object is malformed, or there are more than
    /// [`MAX_CONTENTS`](crate::MAX_CONTENTS) of them.
    Contents,
    /// A signature object is malformed.
    Signature,
    /// The `extendedAttributes` field is malformed.
    ExtendedAttributes,
    /// A regular file has no size where its contents need one, as they do
    /// when they come from a stream.
    NoSize,
}

/// How a file that a manifest refers to fails to be what the manifest
/// describes, found without reading it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SourceProblem {
    /// The file is not there.
    Missing,
    /// It is not a regular file.
    NotRegular,
    /// Its size is not what the manifest says, or too small for the offset
    /// and the size the manifest gives.
    Size,
    /// It could not be opened, for the reason [`Error::io_error`] gives.
    Unreadable,
}

/// How contents fail to be what the manifest describes, found while they
/// are copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentProblem {
    /// They are not as many bytes as the manifest says.
    Size,
    /// They do not have the hash the manifest says.
    Hash,
    /// The stream they come from ended before they were complete.
    StreamEnded,
}

/// A way a manifest gives contents in that this crate cannot follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Unsupported {
    /// They start at an offset, in a source that cannot be read from one.
    Offset,
    /// Every contents object of the file has them in an encoding or at a
    /// URL, and they would have to be decoded or fetched.
    Transport,
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
pub enum ErrorKind {
    /// The manifest is malformed.
    Manifest(Problem),
    /// A file the manifest refers to is not there as the manifest
    /// describes it.
    Source(SourceProblem),
    /// Contents are not what the manifest describes.
    Content(ContentProblem),
    /// The manifest gives contents in a way this crate cannot follow.
    Unsupported(Unsupported),
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
    record: Option<u64>,
    name: Option<String>,
    field: Option<Field>,
    size: Option<u64>,
    expected: Option<u64>,
    value: Option<String>,
    cause: Option<Cause>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: String) -> Error {
        Error(Box::new(Inner {
            kind,
            message,
            record: None,
            name: None,
            field: None,
            size: None,
            expected: None,
            value: None,
            cause: None,
        }))
    }

    /// A manifest that is malformed.
    pub(crate) fn manifest(problem: Problem, message: String) -> Error {
        Error::new(ErrorKind::Manifest(problem), message)
    }

    /// Names the record the error is about, unless one is named.
    #[must_use]
    pub(crate) fn in_record(mut self, record: u64) -> Error {
        self.0.record.get_or_insert(record);
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

    /// Notes the size that was found and the one that was expected.
    #[must_use]
    pub(crate) fn sizes(mut self, size: Option<u64>, expected: Option<u64>) -> Error {
        self.0.size = size;
        self.0.expected = expected;
        self
    }

    /// Notes what is not supported: the encoding, or the ways the contents
    /// are available in.
    #[must_use]
    pub(crate) fn valued(mut self, value: impl Into<String>) -> Error {
        self.0.value = Some(value.into());
        self
    }

    /// Notes the I/O error behind this one.
    #[must_use]
    pub(crate) fn caused_by(mut self, error: io::Error) -> Error {
        self.0.cause = Some(Cause::Io(error));
        self
    }

    /// A record that is not JSON.
    pub(crate) fn not_json(record: u64, error: json::ParseError) -> Error {
        let message = format!("manifest record {} is not valid JSON: {}", record, error);
        let mut e = Error::manifest(Problem::NotJson, message).in_record(record);
        e.0.cause = Some(Cause::Json(error));
        e
    }
}

impl Error {
    /// What kind of error this is.
    pub fn kind(&self) -> ErrorKind {
        self.0.kind
    }

    /// The number of the record the error is about, counting from 0.
    pub fn record(&self) -> Option<u64> {
        self.0.record
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

    /// The size that was found, when the error is about a size.
    pub fn size(&self) -> Option<u64> {
        self.0.size
    }

    /// The size the manifest says, when the error is about a size.
    pub fn expected_size(&self) -> Option<u64> {
        self.0.expected
    }

    /// What is not supported, for [`ErrorKind::Unsupported`]: the encoding,
    /// or the ways the contents are available in.
    pub fn value(&self) -> Option<&str> {
        self.0.value.as_deref()
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

    #[test]
    fn what_an_error_is_about() {
        let e = Error::manifest(Problem::FieldType, "message".to_string())
            .at(Field::MTimeNSec)
            .in_record(3)
            .in_record(4)
            .named("a/b");
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::FieldType));
        assert_eq!(
            (e.record(), e.name(), e.field()),
            (Some(3), Some("a/b"), Some(Field::MTimeNSec))
        );
        assert_eq!(e.field().unwrap().to_string(), "mTimeNSec");
        assert_eq!(e.to_string(), "message");
        assert_eq!((e.size(), e.expected_size(), e.value()), (None, None, None));
        assert!(e.io_error().is_none() && std::error::Error::source(&e).is_none());
        let e = Error::new(ErrorKind::Content(ContentProblem::Size), String::new())
            .sizes(Some(1), Some(2))
            .valued("gzip");
        assert_eq!(
            (e.size(), e.expected_size(), e.value()),
            (Some(1), Some(2), Some("gzip"))
        );
        let e = Error::not_json(7, json::parse("{").unwrap_err());
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NotJson));
        assert_eq!(e.record(), Some(7));
        assert_eq!(
            e.to_string(),
            "manifest record 7 is not valid JSON: expected a string key at byte 1"
        );
        assert!(std::error::Error::source(&e).is_some());
    }
}
