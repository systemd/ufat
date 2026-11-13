// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: reading, checking and writing them.
//!
//! A [UAPI.16 file manifest] describes a tree of files. It is an RFC 7464
//! JSON text sequence: one JSON object per record, each record after an
//! ASCII record separator. The first object describes the root of the
//! tree. One object for every file follows, with its name, its type and
//! what else is known of it: size, hash, owner, mode, time. Signature
//! objects can come after the file objects, and a trailer object ends the
//! manifest.
//!
//! - [`FileObject`], [`Contents`] and [`Signature`] are the objects, and
//!   [`Name`], [`InodeType`], [`Mode`], [`Sha256`] and [`Uuid`] what their
//!   fields hold.
//! - [`Sha256Hasher`] computes the hash of a file while it is read.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod digest;
mod error;
mod hex;
mod name;
mod object;

pub use digest::{Digest, InvalidDigest, Sha256, Sha256Hasher};
pub use error::{ContentProblem, Error, ErrorKind, Field, Invalid, Problem, SourceProblem, Unsupported};
pub use name::{InvalidName, Name};
pub use object::{
    Contents, FileObject, Gpt, InodeType, InvalidUuid, Location, Mode, Signature, UnknownInodeType, Uuid, Validity,
};

/// The name of a manifest that is stored in the tree it describes.
pub const FILENAME: &str = "Uapi16Manifest";
/// What the name of a manifest ends in that is stored next to what it
/// describes.
pub const SUFFIX: &str = ".Uapi16Manifest";
