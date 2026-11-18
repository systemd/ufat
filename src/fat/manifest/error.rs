// SPDX-License-Identifier: LGPL-2.1-or-later
//! The errors of the `uapi16` crate as errors of this one: with the errno
//! and the detail a client of the Varlink interface is told.

use uapi16::{ErrorKind, Problem};

use crate::errno::*;
use crate::{Detail, Error, ManifestProblem};

impl From<uapi16::Error> for Error {
    fn from(e: uapi16::Error) -> Error {
        match e.kind() {
            // What the output said when it was written to comes back as it
            // was.
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
            // Writing a manifest fails for the reasons above only.
            _ => Error::new(EIO, e.to_string()),
        }
    }
}
