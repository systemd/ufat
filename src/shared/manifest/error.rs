// SPDX-License-Identifier: LGPL-2.1-or-later
//! The errors of the `uapi16` crate as errors of this one: with the errno
//! and the detail a client of the Varlink interface is told.

use uapi16::{ErrorKind, Invalid, Problem, Unsupported};

use crate::errno::*;
use crate::{ContentProblem, Detail, Error, ManifestProblem, SourceProblem, UnsupportedKind, ValidityProblem};

impl From<Problem> for ManifestProblem {
    fn from(problem: Problem) -> ManifestProblem {
        match problem {
            Problem::NotJson => ManifestProblem::NotJson,
            Problem::NotObject => ManifestProblem::NotObject,
            Problem::NotUtf8 => ManifestProblem::NotUtf8,
            Problem::NulByte => ManifestProblem::NulByte,
            Problem::RecordSeparator => ManifestProblem::RecordSeparator,
            Problem::RecordTooLarge => ManifestProblem::RecordTooLarge,
            Problem::Empty => ManifestProblem::Empty,
            Problem::NoTrailer => ManifestProblem::NoTrailer,
            Problem::DataAfterTrailer => ManifestProblem::DataAfterTrailer,
            Problem::FileAfterSignature => ManifestProblem::FileAfterSignature,
            Problem::MediaType => ManifestProblem::MediaType,
            Problem::FirstHasName => ManifestProblem::FirstHasName,
            Problem::FirstNotDirectory => ManifestProblem::FirstNotDirectory,
            Problem::NoName => ManifestProblem::NoName,
            Problem::InvalidName => ManifestProblem::InvalidName,
            Problem::DuplicateName => ManifestProblem::DuplicateName,
            Problem::UnknownType => ManifestProblem::UnknownType,
            Problem::FieldType => ManifestProblem::FieldType,
            Problem::FieldRange => ManifestProblem::FieldRange,
            Problem::FieldNotPermitted => ManifestProblem::FieldNotPermitted,
            Problem::Contradiction => ManifestProblem::Contradiction,
            Problem::Contents => ManifestProblem::Contents,
            Problem::Signature => ManifestProblem::Signature,
            Problem::ExtendedAttributes => ManifestProblem::ExtendedAttributes,
            Problem::NoSize => ManifestProblem::NoSize,
        }
    }
}

impl From<uapi16::Error> for Error {
    fn from(e: uapi16::Error) -> Error {
        // A file is named by its path inside the volume where the error is
        // about what the volume is to hold, and by its name in the
        // manifest where it is about the manifest or its files.
        let name = e.name().unwrap_or_default();
        let path = crate::path::join("/", name);
        match e.kind() {
            // What the volume said when it was written to comes back as it
            // was.
            ErrorKind::Io => Error::from(std::io::Error::from(e)),
            ErrorKind::Manifest(Problem::NoSize) => {
                Error::new(EINVAL, format!("{}: streamed contents need a known size", path)).with(Detail::Manifest {
                    problem: ManifestProblem::NoSize,
                    record: None,
                    name: Some(path),
                    field: e.field().map(|field| field.to_string()),
                })
            }
            ErrorKind::Manifest(problem) => {
                let errno = match problem {
                    Problem::RecordTooLarge => E2BIG,
                    _ => EBADMSG,
                };
                // These are about the manifest as a whole more than about
                // one record of it, and name none.
                let record = match problem {
                    Problem::NotObject
                    | Problem::MediaType
                    | Problem::DataAfterTrailer
                    | Problem::FileAfterSignature => None,
                    _ => e.record(),
                };
                Error::new(errno, e.to_string()).with(Detail::Manifest {
                    problem: problem.into(),
                    record,
                    name: e.name().map(str::to_string),
                    field: e.field().map(|field| field.to_string()),
                })
            }
            ErrorKind::Source(problem) => {
                let cause = e.io_error().map(Error::errno_of);
                let (errno, problem) = match problem {
                    uapi16::SourceProblem::Missing => (cause.unwrap_or(ENOENT), SourceProblem::Missing),
                    uapi16::SourceProblem::NotRegular => (EINVAL, SourceProblem::NotRegular),
                    uapi16::SourceProblem::Size => (EBADMSG, SourceProblem::Size),
                    // A file that cannot be read for a reason of the host
                    // is no mismatch between the manifest and its files.
                    uapi16::SourceProblem::Unreadable => return Error::new(cause.unwrap_or(EIO), e.to_string()),
                };
                Error::new(errno, e.to_string()).with(Detail::Source {
                    name: name.to_string(),
                    problem,
                    size: e.size(),
                    expected: e.expected_size(),
                })
            }
            ErrorKind::Content(problem) => Error::new(EBADMSG, e.to_string()).with(Detail::Content {
                name: name.to_string(),
                problem: match problem {
                    uapi16::ContentProblem::Size => ContentProblem::Size,
                    uapi16::ContentProblem::Hash => ContentProblem::Hash,
                    uapi16::ContentProblem::StreamEnded => ContentProblem::StreamEnded,
                },
                size: e.size(),
                expected: e.expected_size(),
            }),
            ErrorKind::Unsupported(what) => {
                let (what, message) = match what {
                    Unsupported::Offset => (
                        UnsupportedKind::Offset,
                        format!("{}: encodings and offsets cannot be used with streamed contents", path),
                    ),
                    Unsupported::Transport => (
                        UnsupportedKind::Transport,
                        format!(
                            "'{}' is only available through {}, which is not supported",
                            path,
                            e.value().unwrap_or_default()
                        ),
                    ),
                };
                Error::new(EOPNOTSUPP, message).with(Detail::Unsupported {
                    name: Some(path),
                    what,
                    value: e.value().map(str::to_string),
                })
            }
            ErrorKind::NotValid(reason) => {
                let (errno, problem) = match reason {
                    Invalid::Revoked => (EKEYREVOKED, ValidityProblem::Revoked),
                    Invalid::NotYetValid => (EKEYEXPIRED, ValidityProblem::NotYetValid),
                    Invalid::Expired => (EKEYEXPIRED, ValidityProblem::Expired),
                };
                Error::new(errno, e.to_string()).with(Detail::Validity { name: path, problem })
            }
        }
    }
}
