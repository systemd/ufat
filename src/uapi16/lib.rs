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
//! - [`Reader`] reads a manifest record by record from a [`Read`]. It
//!   checks every object against the rules of the specification, and
//!   where it comes: right after the object of its directory, in the order
//!   the manifest declares, and with the fields of the [`Features`] the
//!   manifest records.
//! - [`Decoder`] does the same with the bytes it is fed, and does no I/O.
//! - [`Writer`] writes a manifest record by record to a [`Write`], and
//!   checks it the way the reader does. [`Encoder`] does the same into a
//!   string, and does no I/O. [`Sha256Context`] computes the hash of a file
//!   while it is read, and [`Finalize::finalize`] returns it.
//! - [`RootObject`], [`FileObject`], [`Contents`] and [`Signature`] are the
//!   objects, and [`Name`], [`InodeType`], [`Mode`], [`DosFlags`],
//!   [`InodeFlags`], [`Sha256`] and [`Uuid`] what their fields hold. What
//!   the root file object and a file object both have is in
//!   [`InodeAttributes`] and [`ValidityWindow`].
//!
//! A manifest that does not come through a [`Read`], such as one from an
//! async runtime, goes to a [`Decoder`] as it comes. [`Decoder::step`] says
//! what comes next. When it asks for more of the manifest with
//! [`Step::Input`], [`Decoder::feed`] takes the bytes that came, up to the
//! end of the record it reads, and returns how many it took. The others go
//! in with a later call. [`Decoder::end`] says that there are no more. The
//! other steps hand out the root file object, the objects after it, and
//! the end of the manifest. A record ends where the next one starts, so an
//! object comes once the separator of the record after it was fed, or the
//! input ended, and the end of the manifest once the input ended. A step
//! reads a whole record, of up to [`MAX_RECORD_SIZE`] bytes with its record
//! separator, at once.
//!
//! A manifest that does not go to a [`Write`] is put together by an
//! [`Encoder`]: [`Encoder::begin`], [`Encoder::file`],
//! [`Encoder::signature`] and [`Encoder::finish`] append its records to a
//! string, and the caller sends them on.
//!
//! A manifest is input from outside and can be very large. Reading one
//! takes time in proportion to its size, and keeps one record without its
//! separator and the name of the file object before it in memory: less
//! than [`MAX_RECORD_SIZE`] and at most [`Name::MAX_LEN`] bytes. Nothing
//! grows with the manifest. Writing one keeps the record it puts together,
//! its separator included, and the name of the file object before it.
//!
//! Signature objects are read and not verified: that takes an OpenPGP or
//! an X.509 implementation. [`Reader::signed_len`] says how much of the
//! manifest they sign.
//!
//! The reader takes every field the specification has. A field it does
//! not know is passed over, whatever its value is, as the specification
//! asks.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/
//! [`Read`]: std::io::Read
//! [`Write`]: std::io::Write

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod base64;
mod decode;
mod digest;
mod error;
mod features;
mod hex;
mod name;
mod object;
mod reader;
mod sequence;
mod writer;

pub use digest::{Digest, Finalize, InvalidDigest, Sha256, Sha256Context};
pub use error::{Error, ErrorKind, Field, Invalid, Problem};
pub use features::{Features, Order, UnknownFeature};
pub use name::{InvalidName, Name};
pub use object::{
    Contents, DosFlags, FatSerial, FileObject, FileSystemIdentity, FilledIn, FlagStates, GptPartition, InodeAttributes,
    InodeFlags, InodeType, InvalidFatSerial, InvalidUuid, Location, Mode, RootObject, Signature, UnknownInodeType,
    Uuid, Validity, ValidityWindow,
};
pub use reader::{Decoder, Object, Reader, Step};
pub use writer::{Encoder, Writer};

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
/// The byte that ends a record behind its JSON text, a newline.
pub(crate) const RECORD_END: u8 = b'\n';
/// The namespace of the extended attributes of a file object, the one the
/// specification defines.
pub(crate) const USER_NAMESPACE: &str = "user";
/// The largest record a reader takes and a writer writes, from its record
/// separator up to the next one as the specification counts it, the same
/// as systemd's.
pub const MAX_RECORD_SIZE: usize = 4 * 1024 * 1024;
/// The most contents objects a file object can have, the same as for
/// systemd.
pub const MAX_CONTENTS: usize = 256;

/// What the strings of a manifest may not hold beyond what JSON forbids:
/// noncharacters and the NUL character, escaped or not.
pub(crate) const STRING_RULES: json::StringRules = json::StringRules::NO_NONCHARACTERS.union(json::StringRules::NO_NUL);

/// What the tests of this crate build manifests from.
#[cfg(test)]
pub(crate) mod testing {
    use super::{Error, FileObject, Name, Object, Reader, RootObject, Signature, Writer, RECORD_END, RECORD_SEPARATOR};

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
            out.push(RECORD_END);
        }
        out
    }

    /// The manifest with the file objects `records` between the root file
    /// object and the trailer.
    pub(crate) fn manifest(records: &[&str]) -> Vec<u8> {
        sequence(&[&[ROOT][..], records, &[TRAILER]].concat())
    }

    /// A manifest read to its end: what the tests look at.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Whole {
        pub(crate) root: RootObject,
        pub(crate) objects: Vec<FileObject>,
        pub(crate) signatures: Vec<Signature>,
    }

    /// Reads the manifest `bytes` to its end.
    pub(crate) fn read_whole(bytes: &[u8]) -> Result<Whole, Error> {
        read_whole_from(bytes)
    }

    /// Reads the manifest that `input` holds to its end.
    pub(crate) fn read_whole_from(input: impl std::io::Read) -> Result<Whole, Error> {
        let mut reader = Reader::open(input)?;
        let mut whole = Whole {
            root: reader.root().clone(),
            objects: Vec::new(),
            signatures: Vec::new(),
        };
        for object in &mut reader {
            match object? {
                Object::File(object) => whole.objects.push(*object),
                Object::Signature(signature) => whole.signatures.push(signature),
            }
        }
        Ok(whole)
    }

    /// The names of the full tree in which every directory has an entry
    /// for each of `pieces`, down to `depth` components: every name of at
    /// most `depth` components made of `pieces`, the root among them.
    pub(crate) fn full_tree_names(pieces: &[&str], depth: usize) -> Vec<Name> {
        let mut names = vec![Name::ROOT];
        let mut level = vec![Name::ROOT];
        for _ in 0..depth {
            level = level
                .iter()
                .flat_map(|parent| pieces.iter().map(move |piece| parent.join(piece).unwrap()))
                .collect();
            names.extend(level.iter().cloned());
        }
        names
    }

    /// Writes the manifest `whole`.
    pub(crate) fn write_whole(whole: &Whole) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::begin(Vec::new(), &whole.root)?;
        for object in &whole.objects {
            writer.file(object)?;
        }
        for signature in &whole.signatures {
            writer.signature(signature)?;
        }
        writer.finish()
    }
}
