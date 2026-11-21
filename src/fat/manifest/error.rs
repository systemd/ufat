// SPDX-License-Identifier: LGPL-2.1-or-later
//! The errors of the `uapi16` crate as errors of this one: with the errno
//! and the detail a client of the Varlink interface is told.

use uapi16::{ErrorKind, Field, Problem, UnsupportedContent};

use super::path_in_volume;
use crate::errno::*;
use crate::error::IoErrorExt;
use crate::{ContentProblem, Detail, Error, ManifestProblem, SourceProblem, UnsupportedKind, ValidityProblem};

/// What the size of a regular file of a manifest is needed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SizePurpose {
    /// Planning the size of a volume for the file.
    Planning,
    /// Taking its contents from a stream, which has the contents of every
    /// file back to back.
    Streaming,
}

impl SizePurpose {
    /// The word messages use for it, as in "cannot be planned".
    fn as_str(self) -> &'static str {
        match self {
            SizePurpose::Planning => "planned",
            SizePurpose::Streaming => "streamed",
        }
    }
}

impl Error {
    /// The error for the regular file `name` of a manifest, in the record
    /// `record` when that is known, that has no size although `purpose`
    /// needs one.
    pub(crate) fn no_size(name: &str, record: Option<u64>, purpose: SizePurpose) -> Error {
        let what = match record {
            Some(record) => format!("manifest object {} ({})", record, name),
            None => format!("'{}'", name),
        };
        Error::new(
            EINVAL,
            format!("{}: a file without a size cannot be {}", what, purpose.as_str()),
        )
        .with(Detail::Manifest {
            problem: ManifestProblem::NoSize,
            record,
            name: Some(name.to_string()),
            field: Some(Field::Size.as_str().to_string()),
        })
    }
}

impl From<uapi16::Error> for Error {
    fn from(e: uapi16::Error) -> Error {
        // A file is named by its path inside the volume where the error is
        // about what the volume is to hold, and by its name in the
        // manifest where it is about the manifest or its files.
        let name = e.name().unwrap_or_default();
        let path = path_in_volume(name);
        match e.kind() {
            // What the volume said when it was written to, and what the
            // output said when a manifest was written to it, comes back as
            // it was.
            ErrorKind::Io => Error::from(std::io::Error::from(e)),
            ErrorKind::Manifest(problem) => {
                let errno = match problem {
                    Problem::RecordTooLarge => E2BIG,
                    _ => EBADMSG,
                };
                // These are about the manifest as a whole more than about
                // one record of it, and name none.
                let record = match problem {
                    Problem::NotObject
                    | Problem::InvalidMediaType
                    | Problem::DataAfterTrailer
                    | Problem::FileAfterSignature => None,
                    _ => e.record_number(),
                };
                Error::new(errno, e.to_string()).with(Detail::Manifest {
                    problem: ManifestProblem::Malformed(problem),
                    record,
                    name: e.name().map(str::to_string),
                    field: e.field().map(|field| field.to_string()),
                })
            }
            ErrorKind::Source(problem) => {
                let cause = e.io_error().map(IoErrorExt::errno);
                let (errno, problem) = match problem {
                    uapi16::SourceProblem::Missing => (cause.unwrap_or(ENOENT), SourceProblem::Missing),
                    uapi16::SourceProblem::NotRegular => (EINVAL, SourceProblem::NotRegular),
                    // A file that cannot be read for a reason of the host,
                    // SourceProblem::Unreadable, is no mismatch between the
                    // manifest and its files. An error of ours behind it
                    // keeps its detail, such as that of a passed stream made
                    // non-blocking during the call.
                    _ => {
                        let error = Error::new(cause.unwrap_or(EIO), e.to_string());
                        return match e.io_error().and_then(IoErrorExt::own_error).and_then(Error::detail) {
                            Some(detail) => error.with(detail.clone()),
                            None => error,
                        };
                    }
                };
                Error::new(errno, e.to_string()).with(Detail::Source {
                    name: name.to_string(),
                    problem,
                })
            }
            ErrorKind::Content(problem) => {
                let problem = match problem {
                    uapi16::ContentProblem::SizeMismatch => ContentProblem::Size,
                    uapi16::ContentProblem::HashMismatch => ContentProblem::Hash,
                    uapi16::ContentProblem::StreamEnded => ContentProblem::StreamEnded,
                    uapi16::ContentProblem::SourceChanged => ContentProblem::SourceChanged,
                    _ => return Error::new(EBADMSG, e.to_string()),
                };
                Error::new(EBADMSG, e.to_string()).with(Detail::Content {
                    name: name.to_string(),
                    problem,
                    size: e.found_size(),
                    expected: e.expected_size(),
                })
            }
            ErrorKind::Unsupported(what) => {
                let (what, message) = match what {
                    UnsupportedContent::OffsetInStream => (
                        UnsupportedKind::Offset,
                        format!("{}: an offset cannot be used with streamed contents", path),
                    ),
                    UnsupportedContent::UrlOrEncoding => (
                        UnsupportedKind::Transport,
                        format!(
                            "'{}' is only available through {}, which is not supported",
                            path,
                            e.value().unwrap_or_default()
                        ),
                    ),
                    UnsupportedContent::NoSize => {
                        return Error::no_size(name, e.record_number(), SizePurpose::Streaming)
                    }
                    // An object without data, UnsupportedContent::Absent:
                    // only the data of regular files is copied, and they
                    // always have some.
                    _ => return Error::new(EOPNOTSUPP, e.to_string()),
                };
                Error::new(EOPNOTSUPP, message).with(Detail::Unsupported {
                    name: Some(path),
                    what,
                    value: e.value().map(str::to_string),
                })
            }
            ErrorKind::NotValid(reason) => {
                let (errno, problem) = match reason {
                    uapi16::ValidityProblem::Revoked => (EKEYREVOKED, ValidityProblem::Revoked),
                    uapi16::ValidityProblem::NotYetValid => (EKEYEXPIRED, ValidityProblem::NotYetValid),
                    uapi16::ValidityProblem::Expired => (EKEYEXPIRED, ValidityProblem::Expired),
                    // A reason this crate does not know of. The entry is not
                    // to be used now all the same.
                    _ => return Error::new(EKEYEXPIRED, e.to_string()),
                };
                Error::new(errno, e.to_string()).with(Detail::Validity { name: path, problem })
            }
            // A kind of error this crate does not know of.
            _ => Error::new(EIO, e.to_string()),
        }
    }
}
