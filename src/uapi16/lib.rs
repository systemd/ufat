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
//! - [`ContentSource`] is where the contents of the files come from when a
//!   manifest is applied: [`DirectorySource`] for the files next to the
//!   manifest and [`StreamSource`] for one stream with all of them.
//!   [`FileObject::copy_contents`] copies the contents of a file and checks
//!   them against the manifest with a [`ContentCheck`].
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
//! Contents that do not go through a [`Write`] are checked with a
//! [`ContentCheck`]: [`ContentCheck::update`] takes them as they come, and
//! [`ContentCheck::finish`] says whether they have the size and the hash
//! the manifest gives.
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
//! manifest they sign. Contents that are stored in an encoding or that
//! have to be fetched from a URL are not taken.
//!
//! The reader takes every field the specification has. A field it does
//! not know is passed over, as the specification asks, unless it holds a
//! number too large for a double, such as 1E400, or more arrays and
//! objects inside each other than serde_json reads. serde_json reads 127,
//! the object of the record included.
//!
//! The reader reads JSON with serde_json. The features of serde_json are
//! the same for every crate of a build, and uapi16 cannot turn one off that
//! another crate turns on. With arbitrary_precision, serde_json hands every
//! number with a fraction or an exponent, -0 and every integer that does
//! not fit into 64 bits to the reader as an object. Then a field the reader
//! does not know may hold a number too large for a double. A field it knows
//! that holds such a number has a value of the wrong type instead of not
//! being JSON. A record that is one of these numbers, such as 1.5 or -0, is
//! read as an object without a name.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/
//! [`Read`]: std::io::Read
//! [`Write`]: std::io::Write

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod base64;
mod blocking;
mod content;
mod decode;
mod digest;
mod error;
mod features;
mod hex;
mod name;
mod object;
mod reader;
mod sequence;
mod strict;
mod writer;

pub use blocking::{Reader, Writer};
pub use content::{ContentCheck, ContentSource, Data, Directory, DirectorySource, OpenError, Reference, StreamSource};
pub use digest::{Digest, Finalize, InvalidDigest, Sha256, Sha256Context};
pub use error::{ContentProblem, Error, ErrorKind, Field, Invalid, Problem, SourceProblem, UnsupportedContent};
pub use features::{Features, Order, UnknownFeature};
pub use name::{InvalidName, Name};
pub use object::{
    Contents, DosFlags, FatSerial, FileObject, FileSystemIdentity, FilledIn, FlagStates, GptPartition, InodeAttributes,
    InodeFlags, InodeType, InvalidFatSerial, InvalidUuid, Location, Mode, RootObject, Signature, UnknownInodeType,
    Uuid, Validity, ValidityWindow,
};
pub use reader::{Decoder, Object, Step};
pub use writer::Encoder;

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
pub(crate) const STRING_RULES: strict::StringRules =
    strict::StringRules::NO_NONCHARACTERS.union(strict::StringRules::NO_NUL);

/// What the tests of this crate build manifests from.
#[cfg(test)]
pub(crate) mod testing {
    use super::blocking::READ_SIZE;
    use super::{
        Contents, DosFlags, Error, Features, FileObject, GptPartition, InodeFlags, InodeType, Location, Mode, Name,
        Object, Reader, RootObject, Sha256, Signature, Uuid, Validity, Writer, RECORD_END, RECORD_SEPARATOR,
    };
    use crate::strict::{ParseError, Skip, Strict};
    use serde_core::de::DeserializeSeed;
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

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
    /// How many bytes the tests feed a decoder at a time. The pieces end
    /// anywhere: inside a record, inside a character, right in front of a
    /// separator, and around the size a reader reads at a time.
    pub(crate) const PIECES: [usize; 8] = [1, 2, 3, 7, 4096, READ_SIZE - 1, READ_SIZE, READ_SIZE + 1];

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

    /// How many arrays and objects serde_json reads inside each other.
    pub(crate) const MAX_NESTING: usize = 127;

    /// Reads the JSON text `text` the way a reader reads a value it passes
    /// over: every key and every string held to the rules of a manifest.
    pub(crate) fn read_json(text: &str) -> Result<(), ParseError> {
        let mut strict = Strict::default();
        let mut json = serde_json::Deserializer::from_str(text);
        let read = Skip(&mut strict).deserialize(&mut json).and_then(|()| json.end());
        read.map_err(|e| strict.error(text, &e))
    }

    /// The JSON value of `text`, none for a text a reader refuses, see
    /// [`read_json`]: one with a key twice in an object too, which
    /// serde_json's own Value takes.
    pub(crate) fn json(text: &str) -> Option<serde_json::Value> {
        read_json(text).ok()?;
        serde_json::from_str(text).ok()
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

    pub(crate) fn name(name: &str) -> Name {
        Name::new(name).unwrap()
    }

    /// The records `writer` wrote after `root`, without the frame of
    /// each: the separator in front and the newline behind.
    pub(crate) fn written(root: &RootObject, write: impl FnOnce(&mut Writer<Vec<u8>>)) -> Vec<String> {
        let mut writer = Writer::begin(Vec::new(), root).unwrap();
        write(&mut writer);
        let text = String::from_utf8(writer.finish().unwrap()).unwrap();
        let separator = char::from(RECORD_SEPARATOR);
        assert!(text.starts_with(separator));
        text.split(separator)
            .skip(1)
            .map(|record| record.strip_suffix(char::from(RECORD_END)).unwrap().to_string())
            .collect()
    }

    /// The root file object of a manifest that records every feature, and
    /// its record.
    pub(crate) fn recording_all() -> (RootObject, String) {
        let root = RootObject {
            features: Some(Features::ALL),
            ..RootObject::default()
        };
        let names: Vec<String> = Features::ALL.names().map(|name| format!("\"{}\"", name)).collect();
        let text = format!(
            r#"{{"features":[{}],"mediaType":"application/vnd.uapi.16.manifest"}}"#,
            names.join(",")
        );
        (root, text)
    }

    /// A directory that says nothing else about itself.
    pub(crate) fn directory(name_of: &str) -> FileObject {
        let mut directory = FileObject::new(name(name_of));
        directory.inode_type = InodeType::Directory;
        directory
    }

    /// The record the writer writes for `object`, in a manifest that
    /// records every feature, after the objects of the directories it is
    /// in.
    pub(crate) fn record(object: &FileObject) -> String {
        let (root, root_text) = recording_all();
        let directories: Vec<FileObject> = object
            .name
            .match_indices('/')
            .map(|(end, _)| directory(&object.name[..end]))
            .collect();
        let mut records = written(&root, |writer| {
            for directory in &directories {
                writer.file(directory).unwrap();
            }
            writer.file(object).unwrap();
        });
        assert_eq!(records.len(), directories.len() + 3);
        assert_eq!(records[0], root_text);
        assert_eq!(records.pop().as_deref(), Some(TRAILER));
        records.pop().unwrap()
    }

    /// An object with every field there is, and one of its contents
    /// objects with every field.
    pub(crate) fn everything() -> FileObject {
        let uuid = |last: u8| {
            let mut bytes = [0x11; Uuid::SIZE];
            bytes[Uuid::SIZE - 1] = last;
            Uuid::new(bytes)
        };
        let mut encoded = Contents::new(Location::File(name("blob.gz")));
        encoded.encoding = Some("gzip".into());
        encoded.encoded_size = Some(3);
        encoded.encoded_sha256 = Some(Sha256::digest(b"gz"));
        encoded.original_size = Some(9);
        encoded.original_sha256 = Some(Sha256::digest(b"original"));
        encoded.offset = 4;
        let mut object = FileObject::new(name("a/\u{e9} \"quoted\"\\"));
        object.size = Some(5);
        object.inode.mode = Mode::new(0o440);
        object.inode.uid = Some(1);
        object.inode.gid = Some(2);
        object.inode.user_name = Some("user".into());
        object.inode.group_name = Some("group".into());
        object.inode.mtime_nsec = Some(u64::MAX);
        object.inode_token = NonZeroU64::new(3);
        object.inode.user_xattrs = Some(Box::new(BTreeMap::from([
            ("text".to_string(), b"value".to_vec()),
            ("empty".to_string(), Vec::new()),
            ("binary".to_string(), vec![0xff, 0x00]),
            ("nul".to_string(), b"a\0b".to_vec()),
            ("noncharacter".to_string(), "a\u{fffe}".as_bytes().to_vec()),
        ])));
        // Flags of both kinds, which mix in the order of their names.
        object.inode.flags.put(InodeFlags::APPEND_ONLY, Some(true));
        object.dos_flags.put(DosFlags::ARCHIVE, Some(false));
        object.dos_flags.put(DosFlags::HIDDEN, Some(true));
        object.inode.flags.put(InodeFlags::IMMUTABLE, Some(true));
        object.inode.flags.put(InodeFlags::NO_COW, Some(false));
        object.dos_flags.put(DosFlags::SYSTEM, Some(true));
        // The partition is read-only, which gptFlags says as well where the
        // manifest records both.
        object.gpt = Some(Box::new(GptPartition {
            label: Some("label".into()),
            uuid: Some(uuid(1)),
            type_uuid: Some(uuid(2)),
            flags: Some(
                GptPartition::FLAG_NO_AUTO | GptPartition::FLAG_GROW_FILE_SYSTEM | GptPartition::FLAG_READ_ONLY,
            ),
            no_auto: Some(true),
            grow_file_system: Some(true),
        }));
        object.inode.read_only = Some(true);
        object.contents = vec![
            encoded,
            Contents {
                http_headers: vec![
                    ("X-Foo".into(), "bar".into()),
                    ("Authorization".into(), "Bearer x".into()),
                ],
                ..Contents::new(Location::Url("https://example.com/blob".into()))
            },
            Contents::new(Location::Literal(b"hello".to_vec())),
            Contents::default(),
        ];
        object.sha256 = HELLO.parse().ok();
        object.validity.since_usec = 6;
        object.validity.until_usec = Some(7);
        object.validity.state = Validity::Revoked;
        object
    }
}
