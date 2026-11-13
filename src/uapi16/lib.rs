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
//! - [`Reader`] reads a manifest record by record and checks every object
//!   against the rules of the specification. [`Manifest`] is a whole
//!   manifest in memory.
//! - [`FileObject`], [`Contents`] and [`Signature`] are the objects, and
//!   [`Name`], [`InodeType`], [`Mode`], [`Sha256`] and [`Uuid`] what their
//!   fields hold.
//! - [`Sha256Hasher`] computes the hash of a file while it is read.
//!
//! A manifest is input from outside. Reading one takes time in proportion
//! to its size and keeps one record in memory, which is at most
//! [`MAX_RECORD_SIZE`] long.
//!
//! Signature objects are read and not verified: that takes an OpenPGP or
//! an X.509 implementation. [`Reader::signed_len`] says how much of the
//! manifest they sign.
//!
//! The reader takes the fields systemd's reader takes. A field it does
//! not know is passed over, whatever its value is. That goes for the
//! fields the specification has beyond those as well: the DOS attributes
//! and the inode flags (`flagHidden` and the other `flag` fields),
//! `fatSerial`, `fsUUID`, `fsLabel`, and the `httpHeaders` of a contents
//! object.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod base64;
mod decode;
mod digest;
mod error;
mod hex;
mod manifest;
mod name;
mod object;
mod reader;

pub use digest::{Digest, InvalidDigest, Sha256, Sha256Hasher};
pub use error::{ContentProblem, Error, ErrorKind, Field, Invalid, Problem, SourceProblem, Unsupported};
pub use manifest::Manifest;
pub use name::{InvalidName, Name};
pub use object::{
    Contents, FileObject, Gpt, InodeType, InvalidUuid, Location, Mode, Signature, UnknownInodeType, Uuid, Validity,
};
pub use reader::{Reader, Record};

/// The media type of a manifest, which its first object carries.
pub const MEDIA_TYPE: &str = "application/vnd.uapi.16.manifest";
/// The media type of a signature object.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.uapi.16.signature";
/// The media type of the trailer object.
pub const TRAILER_MEDIA_TYPE: &str = "application/vnd.uapi.16.trailer";
/// The name of a manifest that is stored in the tree it describes.
pub const FILENAME: &str = "Uapi16Manifest";
/// What the name of a manifest ends in that is stored next to what it
/// describes.
pub const SUFFIX: &str = ".Uapi16Manifest";
/// The byte every record starts with, the ASCII record separator.
pub const RECORD_SEPARATOR: u8 = 0x1E;
/// The largest record a reader takes, the same as systemd's.
pub const MAX_RECORD_SIZE: usize = 4 * 1024 * 1024;
/// The most contents objects a file object can have, the same as for
/// systemd.
pub const MAX_CONTENTS: usize = 256;

/// What the tests of this crate build manifests from.
#[cfg(test)]
pub(crate) mod testing {
    use super::RECORD_SEPARATOR;

    /// The root file object that says nothing but that this is a manifest.
    pub(crate) const ROOT: &str = r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#;
    /// The trailer object.
    pub(crate) const TRAILER: &str = r#"{"mediaType":"application/vnd.uapi.16.trailer"}"#;
    /// A signature object.
    pub(crate) const SIGNATURE: &str =
        r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AAAA"}"#;
    /// The hash of "hello", in hex.
    pub(crate) const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    /// The hash of "world", in hex.
    pub(crate) const WORLD: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
    /// The hash of no data, in hex.
    pub(crate) const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The JSON text sequence of `records`.
    pub(crate) fn sequence(records: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            out.push(RECORD_SEPARATOR);
            out.extend_from_slice(record.as_bytes());
            out.push(b'\n');
        }
        out
    }

    /// The manifest with the file objects `records` between the root file
    /// object and the trailer.
    pub(crate) fn manifest(records: &[&str]) -> Vec<u8> {
        sequence(&[&[ROOT][..], records, &[TRAILER]].concat())
    }
}
