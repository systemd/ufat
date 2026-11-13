// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing a manifest record by record.

use std::fmt;
use std::io::Write;
use std::ops::{BitOr, BitOrAssign};
use std::str::FromStr;

use json::{ObjectWriter, ValueWriter};

use crate::base64::Base64;
use crate::decode::ROOT_RECORD;
use crate::error::{Error, Field, Problem};
use crate::hex::Hex;
use crate::manifest::Manifest;
use crate::object::{Contents, FileObject, InodeType, Location, Signature, Validity};
use crate::{MEDIA_TYPE, RECORD_SEPARATOR, SIGNATURE_MEDIA_TYPE, TRAILER_MEDIA_TYPE};

/// What ends a record.
const RECORD_END: char = '\n';
/// The namespace the extended attributes of a file object are in.
const USER_NAMESPACE: &str = "user";
/// The `validity` of a file that is not to be used.
const REVOKED: &str = "revoked";

/// The fields the file objects of a written manifest carry, beside their
/// names and their inode types, which every manifest has.
///
/// These are the fields `systemd-manifest` takes with `--field=`, by its
/// names for them. A field stands for what a writer records, which can be
/// more than one field of a file object: [`Fields::HASH`] is `sha256`,
/// [`Fields::DEVICE`] is `major` and `minor`. A writer leaves out what the
/// tree it describes has no notion of.
///
/// ```
/// use uapi16::Fields;
///
/// let fields = Fields::SIZE | Fields::HASH;
/// assert!(fields.contains(Fields::SIZE) && !fields.contains(Fields::MTIME));
/// assert_eq!(Fields::from_names(["size", "hash"]), Ok(fields));
/// assert!(Fields::default().contains(Fields::MODE | Fields::HASH));
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fields(u16);

/// A name that is not the name of a field of [`Fields`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownField(());

impl fmt::Display for UnknownField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a field of a manifest")
    }
}

impl std::error::Error for UnknownField {}

impl Fields {
    /// `mode`: the access mode.
    pub const MODE: Fields = Fields(1 << 0);
    /// `uid`: the owning user.
    pub const UID: Fields = Fields(1 << 1);
    /// `gid`: the owning group.
    pub const GID: Fields = Fields(1 << 2);
    /// `size`: the size of regular files and symbolic links.
    pub const SIZE: Fields = Fields(1 << 3);
    /// `hash`: the SHA-256 of regular files.
    pub const HASH: Fields = Fields(1 << 4);
    /// `symlink`: the target of symbolic links.
    pub const SYMLINK: Fields = Fields(1 << 5);
    /// `device`: the major and the minor number of device nodes.
    pub const DEVICE: Fields = Fields(1 << 6);
    /// `hardlink`: the token the names of one file share.
    pub const HARDLINK: Fields = Fields(1 << 7);
    /// `mtime`: the modification time.
    pub const MTIME: Fields = Fields(1 << 8);
    /// `userXattr`: the extended attributes of the user namespace.
    pub const USER_XATTR: Fields = Fields(1 << 9);
    /// `userName`: the name of the owning user.
    pub const USER_NAME: Fields = Fields(1 << 10);
    /// `groupName`: the name of the owning group.
    pub const GROUP_NAME: Fields = Fields(1 << 11);

    /// No field: the manifest carries names and inode types.
    pub const NONE: Fields = Fields(0);
    /// The fields `systemd-manifest` writes when it is told none: every
    /// one but `mtime`, `userName` and `groupName`.
    pub const DEFAULT: Fields = Fields(
        Fields::MODE.0
            | Fields::UID.0
            | Fields::GID.0
            | Fields::SIZE.0
            | Fields::HASH.0
            | Fields::SYMLINK.0
            | Fields::DEVICE.0
            | Fields::HARDLINK.0
            | Fields::USER_XATTR.0,
    );
    /// Every field.
    pub const ALL: Fields = Fields(Fields::DEFAULT.0 | Fields::MTIME.0 | Fields::USER_NAME.0 | Fields::GROUP_NAME.0);

    /// Every single field with its name.
    const NAMES: [(Fields, &'static str); 12] = [
        (Fields::MODE, "mode"),
        (Fields::UID, "uid"),
        (Fields::GID, "gid"),
        (Fields::SIZE, "size"),
        (Fields::HASH, "hash"),
        (Fields::SYMLINK, "symlink"),
        (Fields::DEVICE, "device"),
        (Fields::HARDLINK, "hardlink"),
        (Fields::MTIME, "mtime"),
        (Fields::USER_XATTR, "userXattr"),
        (Fields::USER_NAME, "userName"),
        (Fields::GROUP_NAME, "groupName"),
    ];

    /// Whether every field of `fields` is among these.
    pub const fn contains(self, fields: Fields) -> bool {
        self.0 & fields.0 == fields.0
    }

    /// The fields with the names `names`.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Fields, UnknownField> {
        names
            .into_iter()
            .try_fold(Fields::NONE, |fields, name| Ok(fields | name.parse()?))
    }

    /// The names of the fields.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Fields::NAMES
            .into_iter()
            .filter(move |(field, _)| self.contains(*field))
            .map(|(_, name)| name)
    }
}

impl Default for Fields {
    /// [`Fields::DEFAULT`].
    fn default() -> Fields {
        Fields::DEFAULT
    }
}

impl BitOr for Fields {
    type Output = Fields;

    fn bitor(self, other: Fields) -> Fields {
        Fields(self.0 | other.0)
    }
}

impl BitOrAssign for Fields {
    fn bitor_assign(&mut self, other: Fields) {
        self.0 |= other.0;
    }
}

impl FromStr for Fields {
    type Err = UnknownField;

    /// The one field with the name `name`.
    fn from_str(name: &str) -> Result<Fields, UnknownField> {
        Fields::NAMES
            .into_iter()
            .find(|(_, field)| *field == name)
            .map(|(field, _)| field)
            .ok_or(UnknownField(()))
    }
}

impl fmt::Debug for Fields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Fields(")?;
        for (i, name) in self.names().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

/// Writes the fields of an object of a manifest.
trait WriteField {
    /// Starts the member of the object that is the field `field`.
    fn field(&mut self, field: Field) -> ValueWriter<'_>;
}

impl WriteField for ObjectWriter<'_> {
    fn field(&mut self, field: Field) -> ValueWriter<'_> {
        self.key(field.as_str())
    }
}

/// How far a writer has got in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// File objects can follow.
    Files,
    /// A signature object was written. File objects cannot follow.
    Signatures,
}

/// Writes a manifest record by record.
///
/// [`Writer::begin`] writes the root file object, [`Writer::file`] the
/// file objects, [`Writer::signature`] the signature objects after them
/// and [`Writer::finish`] the trailer object. A manifest without its
/// trailer is one a reader takes as incomplete, so a writer that is
/// dropped before it finished leaves nothing that passes for a manifest.
///
/// Every object is one record of the JSON text sequence: a record
/// separator, the object with its keys sorted and without whitespace, and
/// a newline, the way `systemd-manifest` writes it. A field that says
/// nothing is left out. So is the inode type where the specification
/// implies it, on the root file object and on regular files. Each record
/// goes out in one write, so a file wants a `BufWriter` around it.
///
/// The writer checks that the root file object is one and that the other
/// objects have names. It does not check the fields of an object against
/// each other.
///
/// ```
/// use uapi16::{FileObject, Manifest, Name, Writer};
///
/// let mut file = FileObject::new(Name::new("a")?);
/// file.size = Some(3);
/// let mut writer = Writer::begin(Vec::new(), &FileObject::root())?;
/// writer.file(&file)?;
/// let bytes = writer.finish()?;
/// assert_eq!(
///     String::from_utf8_lossy(&bytes),
///     concat!(
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
///         "\x1e{\"name\":\"a\",\"size\":3}\n",
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
///     )
/// );
/// assert_eq!(Manifest::parse(&bytes)?.objects, [file]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct Writer<W: Write> {
    out: W,
    /// The text of one record, kept from one record to the next.
    record: String,
    /// The number of the next record.
    next: u64,
    stage: Stage,
}

impl<W: Write> Writer<W> {
    /// Starts a manifest in `out` with the root file object `root`.
    pub fn begin(out: W, root: &FileObject) -> Result<Writer<W>, Error> {
        if !root.name.is_root() {
            return Err(
                Error::manifest(Problem::FirstHasName, "the first manifest object has a name".into())
                    .at(Field::Name)
                    .named(root.name.as_str()),
            );
        }
        if root.inode_type != InodeType::Directory {
            return Err(Error::manifest(
                Problem::FirstNotDirectory,
                "the first manifest object is not a directory".into(),
            )
            .at(Field::Type));
        }
        let mut writer = Writer {
            out,
            record: String::new(),
            next: ROOT_RECORD,
            stage: Stage::Files,
        };
        writer.record(|object| root.write(Some(MEDIA_TYPE), object))?;
        Ok(writer)
    }

    /// Writes a file object.
    pub fn file(&mut self, object: &FileObject) -> Result<(), Error> {
        if object.name.is_root() {
            return Err(
                Error::manifest(Problem::NoName, format!("manifest object {} has no name", self.next))
                    .at(Field::Name)
                    .in_record(self.next),
            );
        }
        if self.stage == Stage::Signatures {
            return Err(Error::manifest(
                Problem::FileAfterSignature,
                "manifest contains a file object after a signature object".into(),
            )
            .in_record(self.next));
        }
        self.record(|record| object.write(None, record))
    }

    /// Writes a signature object. No file object can follow it: it would
    /// be one the signature does not cover.
    pub fn signature(&mut self, signature: &Signature) -> Result<(), Error> {
        self.stage = Stage::Signatures;
        self.record(|record| signature.write(record))
    }

    /// What the manifest is written to. What is written there directly
    /// goes between the records as it is.
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.out
    }

    /// Ends the manifest with the trailer object, flushes what it was
    /// written to and returns it.
    pub fn finish(mut self) -> Result<W, Error> {
        self.record(|record| record.field(Field::MediaType).string(TRAILER_MEDIA_TYPE))?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// Writes one record, the members of whose object `members` writes.
    fn record(&mut self, members: impl FnOnce(&mut ObjectWriter<'_>)) -> Result<(), Error> {
        self.record.clear();
        self.record.push(char::from(RECORD_SEPARATOR));
        members(&mut ObjectWriter::new(&mut self.record));
        self.record.push(RECORD_END);
        self.out.write_all(self.record.as_bytes())?;
        self.next += 1;
        Ok(())
    }
}

impl FileObject {
    /// Writes the fields of the object in the order of their names. The
    /// root file object has `media_type` and no name.
    fn write(&self, media_type: Option<&str>, object: &mut ObjectWriter<'_>) {
        if !self.contents.is_empty() {
            let mut array = object.field(Field::Contents).array();
            for contents in &self.contents {
                contents.write(array.element());
            }
        }
        if let Some(attributes) = &self.user_xattrs {
            let mut namespaces = object.field(Field::ExtendedAttributes).object();
            let mut user = namespaces.key(USER_NAMESPACE).object();
            for (name, value) in attributes.iter() {
                // The value goes out as text when it is text, and as
                // Base64 otherwise.
                let mut value_object = user.key(name).object();
                match std::str::from_utf8(value) {
                    Ok(text) if !text.contains('\0') => value_object.field(Field::Text).string(text),
                    _ => value_object.field(Field::Base64).display(Base64(value)),
                }
            }
        }
        if let Some(gid) = self.gid {
            object.field(Field::Gid).unsigned(u64::from(gid));
        }
        let gpt = self.gpt.as_deref();
        if let Some(uuid) = gpt.and_then(|gpt| gpt.disk_uuid) {
            object.field(Field::GptDiskUuid).display(uuid);
        }
        if let Some(grow) = gpt.and_then(|gpt| gpt.grow_file_system) {
            object.field(Field::GptFlagGrowFileSystem).bool(grow);
        }
        if let Some(no_auto) = gpt.and_then(|gpt| gpt.no_auto) {
            object.field(Field::GptFlagNoAuto).bool(no_auto);
        }
        if let Some(flags) = gpt.and_then(|gpt| gpt.flags) {
            object.field(Field::GptFlags).unsigned(flags);
        }
        if let Some(label) = gpt.and_then(|gpt| gpt.label.as_deref()) {
            object.field(Field::GptLabel).string(label);
        }
        if let Some(uuid) = gpt.and_then(|gpt| gpt.type_uuid) {
            object.field(Field::GptTypeUuid).display(uuid);
        }
        if let Some(uuid) = gpt.and_then(|gpt| gpt.uuid) {
            object.field(Field::GptUuid).display(uuid);
        }
        if let Some(name) = &self.group_name {
            object.field(Field::GroupName).string(name);
        }
        if let Some(token) = self.inode_token {
            object.field(Field::InodeToken).unsigned(token.get());
        }
        if let Some(nsec) = self.mtime_nsec {
            object.field(Field::MTimeNSec).unsigned(nsec);
        }
        if let Some(major) = self.major {
            object.field(Field::Major).unsigned(major);
        }
        if let Some(media_type) = media_type {
            object.field(Field::MediaType).string(media_type);
        }
        if let Some(minor) = self.minor {
            object.field(Field::Minor).unsigned(minor);
        }
        if let Some(mode) = self.mode {
            object.field(Field::Mode).unsigned(u64::from(mode.bits()));
        }
        if !self.name.is_root() {
            object.field(Field::Name).string(&self.name);
        }
        if let Some(read_only) = self.read_only {
            object.field(Field::ReadOnly).bool(read_only);
        }
        if let Some(sha256) = self.sha256 {
            object.field(Field::Sha256).display(sha256);
        }
        if let Some(size) = self.size {
            object.field(Field::Size).unsigned(size);
        }
        // The specification implies the type of the root file object and
        // of a regular file.
        if !self.name.is_root() && self.inode_type != InodeType::Regular {
            object.field(Field::Type).string(self.inode_type.as_str());
        }
        if let Some(uid) = self.uid {
            object.field(Field::Uid).unsigned(u64::from(uid));
        }
        if let Some(name) = &self.user_name {
            object.field(Field::UserName).string(name);
        }
        if self.valid_since_usec != 0 {
            object.field(Field::ValidSinceUSec).unsigned(self.valid_since_usec);
        }
        if let Some(until) = self.valid_until_usec {
            object.field(Field::ValidUntilUSec).unsigned(until);
        }
        if self.validity == Validity::Revoked {
            object.field(Field::Validity).string(REVOKED);
        }
    }
}

impl Contents {
    /// Writes the contents object, its fields in the order of their names.
    fn write(&self, value: ValueWriter<'_>) {
        let mut object = value.object();
        if let Some(sha256) = self.encoded_sha256 {
            object.field(Field::EncodedSha256).display(sha256);
        }
        if let Some(size) = self.encoded_size {
            object.field(Field::EncodedSize).unsigned(size);
        }
        if let Some(encoding) = &self.encoding {
            object.field(Field::Encoding).string(encoding);
        }
        if let Location::File(file) = &self.location {
            object.field(Field::File).string(file);
        }
        if let Location::Literal(literal) = &self.location {
            object.field(Field::Literal).display(Base64(literal));
        }
        if self.offset != 0 {
            object.field(Field::Offset).unsigned(self.offset);
        }
        if let Some(sha256) = self.original_sha256 {
            object.field(Field::OriginalSha256).display(sha256);
        }
        if let Some(size) = self.original_size {
            object.field(Field::OriginalSize).unsigned(size);
        }
        if let Location::Url(url) = &self.location {
            object.field(Field::Url).string(url);
        }
    }
}

impl Signature {
    /// Writes the fields of the signature object in the order of their
    /// names.
    fn write(&self, object: &mut ObjectWriter<'_>) {
        if let Some(data) = &self.data {
            object.field(Field::Data).display(Base64(data));
        }
        if let Some(key) = &self.key {
            object.field(Field::Key).display(Hex(key));
        }
        object.field(Field::Mechanism).string(&self.mechanism);
        object.field(Field::MediaType).string(SIGNATURE_MEDIA_TYPE);
    }
}

impl Manifest {
    /// Writes the manifest to `out`, see [`Writer`].
    pub fn write(&self, out: impl Write) -> Result<(), Error> {
        let mut writer = Writer::begin(out, &self.root)?;
        for object in &self.objects {
            writer.file(object)?;
        }
        for signature in &self.signatures {
            writer.signature(signature)?;
        }
        writer.finish()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::object::{Gpt, Mode, Uuid};
    use crate::testing::{sequence, EMPTY, HELLO, ROOT, TRAILER};
    use crate::{Name, Sha256};
    use std::collections::BTreeMap;
    use std::num::NonZeroU64;

    #[test]
    fn fields() {
        let names = [
            "mode",
            "uid",
            "gid",
            "size",
            "hash",
            "symlink",
            "device",
            "hardlink",
            "mtime",
            "userXattr",
            "userName",
            "groupName",
        ];
        assert_eq!(Fields::from_names(names), Ok(Fields::ALL));
        assert_eq!(Fields::ALL.names().collect::<Vec<_>>(), names);
        assert_eq!(Fields::from_names([]), Ok(Fields::NONE));
        assert_eq!(Fields::NONE.names().count(), 0);
        // systemd's default set: everything but mtime, userName and
        // groupName.
        let default = [
            "mode",
            "uid",
            "gid",
            "size",
            "hash",
            "symlink",
            "device",
            "hardlink",
            "userXattr",
        ];
        assert_eq!(Fields::from_names(default), Ok(Fields::DEFAULT));
        assert_eq!(Fields::default(), Fields::DEFAULT);
        assert_eq!(Fields::DEFAULT.names().collect::<Vec<_>>(), default);
        // A name twice is the field once.
        let some = Fields::from_names(["size", "hash", "mtime", "size"]).unwrap();
        assert_eq!(some, Fields::SIZE | Fields::HASH | Fields::MTIME);
        assert!(some.contains(Fields::SIZE) && some.contains(Fields::SIZE | Fields::MTIME));
        assert!(!some.contains(Fields::MODE) && !some.contains(Fields::SIZE | Fields::MODE));
        assert!(some.contains(Fields::NONE) && Fields::NONE.contains(Fields::NONE));
        assert!(!Fields::NONE.contains(Fields::SIZE));
        let mut grown = Fields::NONE;
        grown |= Fields::HASH;
        grown |= Fields::SIZE | Fields::MTIME;
        assert_eq!(grown, some);
        assert_eq!("userXattr".parse(), Ok(Fields::USER_XATTR));
        for name in ["sha256", "user_xattr", "Mode", "", "type", "size,hash"] {
            assert!(name.parse::<Fields>().is_err(), "{:?}", name);
            assert!(Fields::from_names(["size", name]).is_err(), "{:?}", name);
        }
        assert_eq!(format!("{:?}", some), "Fields(size | hash | mtime)");
        assert_eq!(format!("{:?}", Fields::NONE), "Fields()");
    }

    fn name(name: &str) -> Name {
        Name::new(name).unwrap()
    }

    /// The records `writer` wrote after `root`, without the frame of
    /// each: the separator in front and the newline behind.
    fn written(root: &FileObject, write: impl FnOnce(&mut Writer<Vec<u8>>)) -> Vec<String> {
        let mut writer = Writer::begin(Vec::new(), root).unwrap();
        write(&mut writer);
        let text = String::from_utf8(writer.finish().unwrap()).unwrap();
        let separator = char::from(RECORD_SEPARATOR);
        assert!(text.starts_with(separator));
        text.split(separator)
            .skip(1)
            .map(|record| record.strip_suffix(RECORD_END).unwrap().to_string())
            .collect()
    }

    /// The one record the writer writes for `object`.
    fn record(object: &FileObject) -> String {
        let mut records = written(&FileObject::root(), |writer| writer.file(object).unwrap());
        assert_eq!(records.len(), 3);
        assert_eq!((records[0].as_str(), records[2].as_str()), (ROOT, TRAILER));
        records.remove(1)
    }

    /// What `systemd-manifest` writes, see the manifests in tests/fixtures:
    /// the same objects give the same records.
    #[test]
    fn writes_what_systemd_writes() {
        let mut root = FileObject::root();
        root.user_xattrs = Some(Box::default());
        root.gid = Some(1000);
        root.mtime_nsec = Some(1_699_999_000_000_000_000);
        root.mode = Mode::new(0o775);
        root.uid = Some(1000);
        let mut directory = FileObject::new(name("EFI"));
        directory.inode_type = InodeType::Directory;
        directory.user_xattrs = Some(Box::default());
        directory.gid = Some(1000);
        directory.mtime_nsec = Some(1_699_999_000_000_000_000);
        directory.mode = Mode::new(0o775);
        directory.uid = Some(1000);
        let mut file = FileObject::new(name("EFI/BOOT/BOOTX64.EFI"));
        file.user_xattrs = Some(Box::default());
        file.gid = Some(1000);
        file.mtime_nsec = Some(1_700_000_000_000_000_000);
        file.mode = Mode::new(0o664);
        file.sha256 = "608047e995ccddf55441b8ed783ac49c780b9a911aa655f47d3a4c174748f86b"
            .parse()
            .ok();
        file.size = Some(4096);
        file.uid = Some(1000);
        let records = written(&root, |writer| {
            writer.file(&directory).unwrap();
            writer.file(&file).unwrap();
        });
        assert_eq!(
            records,
            [
                concat!(
                    r#"{"extendedAttributes":{"user":{}},"gid":1000,"mTimeNSec":1699999000000000000,"#,
                    r#""mediaType":"application/vnd.uapi.16.manifest","mode":509,"uid":1000}"#
                ),
                concat!(
                    r#"{"extendedAttributes":{"user":{}},"gid":1000,"mTimeNSec":1699999000000000000,"#,
                    r#""mode":509,"name":"EFI","type":"dir","uid":1000}"#
                ),
                concat!(
                    r#"{"extendedAttributes":{"user":{}},"gid":1000,"mTimeNSec":1700000000000000000,"#,
                    r#""mode":436,"name":"EFI/BOOT/BOOTX64.EFI","#,
                    r#""sha256":"608047e995ccddf55441b8ed783ac49c780b9a911aa655f47d3a4c174748f86b","#,
                    r#""size":4096,"uid":1000}"#
                ),
                TRAILER,
            ]
        );
        // A symbolic link with its target, a file with an attribute, the
        // names of one hard-linked file.
        let mut link = FileObject::new(name("link"));
        link.inode_type = InodeType::Symlink;
        link.contents = vec![Contents::new(Location::Literal(b"a.txt".to_vec()))];
        link.gid = Some(1000);
        link.group_name = Some("brauner".into());
        link.size = Some(5);
        link.user_name = Some("brauner".into());
        assert_eq!(
            record(&link),
            concat!(
                r#"{"contents":[{"literal":"YS50eHQ="}],"gid":1000,"groupName":"brauner","name":"link","#,
                r#""size":5,"type":"lnk","userName":"brauner"}"#
            )
        );
        let mut noted = FileObject::new(name("a.txt"));
        noted.user_xattrs = Some(Box::new(BTreeMap::from([(
            "comment".to_string(),
            b"set by make-fixtures".to_vec(),
        )])));
        assert_eq!(
            record(&noted),
            r#"{"extendedAttributes":{"user":{"comment":{"text":"set by make-fixtures"}}},"name":"a.txt"}"#
        );
        let mut linked = FileObject::new(name("sub/hl_a"));
        linked.inode_token = NonZeroU64::new(1);
        linked.size = Some(11);
        assert_eq!(record(&linked), r#"{"inodeToken":1,"name":"sub/hl_a","size":11}"#);
        let mut fifo = FileObject::new(name("sub/fifo"));
        fifo.inode_type = InodeType::Fifo;
        assert_eq!(record(&fifo), r#"{"name":"sub/fifo","type":"fifo"}"#);
        // The least a manifest and an object are.
        assert_eq!(record(&FileObject::new(name("x"))), r#"{"name":"x"}"#);
        let empty = Writer::begin(Vec::new(), &FileObject::root())
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(empty, sequence(&[ROOT, TRAILER]));
    }

    /// An object with every field there is, and one of its contents
    /// objects with every field.
    fn everything() -> FileObject {
        let uuid = |last: u8| {
            let mut bytes = [0x11; Uuid::SIZE];
            bytes[Uuid::SIZE - 1] = last;
            Uuid::new(bytes)
        };
        let mut encoded = Contents::new(Location::File(name("blob.gz")));
        encoded.encoding = Some("gzip".into());
        encoded.encoded_size = Some(3);
        encoded.encoded_sha256 = Some(Sha256::of(b"gz"));
        encoded.original_size = Some(9);
        encoded.original_sha256 = Some(Sha256::of(b"original"));
        encoded.offset = 4;
        let mut object = FileObject::new(name("a/\u{e9} \"quoted\"\\"));
        object.size = Some(5);
        object.mode = Mode::new(0o640);
        object.uid = Some(1);
        object.gid = Some(2);
        object.user_name = Some("user".into());
        object.group_name = Some("group".into());
        object.mtime_nsec = Some(u64::MAX);
        object.inode_token = NonZeroU64::new(3);
        object.user_xattrs = Some(Box::new(BTreeMap::from([
            ("text".to_string(), b"value".to_vec()),
            ("empty".to_string(), Vec::new()),
            ("binary".to_string(), vec![0xff, 0x00]),
            ("nul".to_string(), b"a\0b".to_vec()),
        ])));
        object.gpt = Some(Box::new(Gpt {
            disk_uuid: None,
            label: Some("label".into()),
            uuid: Some(uuid(1)),
            type_uuid: Some(uuid(2)),
            flags: Some(Gpt::FLAG_GROW_FILE_SYSTEM),
            no_auto: Some(false),
            grow_file_system: Some(true),
        }));
        object.read_only = Some(false);
        object.contents = vec![
            encoded,
            Contents::new(Location::Url("https://example.com/blob".into())),
            Contents::new(Location::Literal(b"hello".to_vec())),
            Contents::default(),
        ];
        object.sha256 = HELLO.parse().ok();
        object.valid_since_usec = 6;
        object.valid_until_usec = Some(7);
        object.validity = Validity::Revoked;
        object
    }

    /// Checks that the keys of every object in `value` are in the order of
    /// their bytes.
    fn sorted(value: &json::Value) {
        match value {
            json::Value::Object(object) => {
                let keys: Vec<&str> = object.keys().collect();
                assert!(
                    keys.windows(2).all(|pair| pair[0].as_bytes() < pair[1].as_bytes()),
                    "{:?}",
                    keys
                );
                object.iter().for_each(|(_, value)| sorted(value));
            }
            json::Value::Array(items) => items.iter().for_each(sorted),
            _ => {}
        }
    }

    #[test]
    fn keys_are_sorted_and_nothing_is_lost() {
        let object = everything();
        let mut device = FileObject::new(name("dev/null"));
        device.inode_type = InodeType::CharDevice;
        device.major = Some(1);
        device.minor = Some(3);
        let mut root = FileObject::root();
        root.gpt = Some(Box::new(Gpt {
            disk_uuid: Some(Uuid::new([0xab; Uuid::SIZE])),
            ..Gpt::default()
        }));
        root.mtime_nsec = Some(0);
        let mut signature = Signature::new("pkcs7");
        signature.key = Some(vec![0xde, 0xad]);
        signature.data = Some(vec![1, 2, 3, 4]);
        let records = written(&root, |writer| {
            writer.file(&object).unwrap();
            writer.file(&device).unwrap();
            writer.signature(&signature).unwrap();
            writer.signature(&Signature::new("openpgp")).unwrap();
        });
        // No whitespace but the one in the name, and every key in its place.
        for record in &records {
            assert!(
                !record.replace("a/\u{e9} \\\"quoted", "").contains(char::is_whitespace),
                "{}",
                record
            );
            sorted(&json::parse(record).unwrap());
        }
        let whole = json::parse(&records[1]).unwrap();
        let keys: Vec<&str> = whole.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "contents",
                "extendedAttributes",
                "gid",
                "gptFlagGrowFileSystem",
                "gptFlagNoAuto",
                "gptFlags",
                "gptLabel",
                "gptTypeUuid",
                "gptUuid",
                "groupName",
                "inodeToken",
                "mTimeNSec",
                "mode",
                "name",
                "readOnly",
                "sha256",
                "size",
                "uid",
                "userName",
                "validSinceUSec",
                "validUntilUSec",
                "validity",
            ]
        );
        let contents = whole.get("contents").unwrap().as_array().unwrap();
        let keys: Vec<&str> = contents[0].as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "encodedSha256",
                "encodedSize",
                "encoding",
                "file",
                "offset",
                "originalSha256",
                "originalSize"
            ]
        );
        assert_eq!(contents[1].to_string(), r#"{"url":"https://example.com/blob"}"#);
        assert_eq!(contents[2].to_string(), r#"{"literal":"aGVsbG8="}"#);
        assert_eq!(contents[3].to_string(), "{}");
        assert_eq!(
            records[0],
            r#"{"gptDiskUuid":"abababab-abab-abab-abab-abababababab","mTimeNSec":0,"mediaType":"application/vnd.uapi.16.manifest"}"#
        );
        assert_eq!(records[2], r#"{"major":1,"minor":3,"name":"dev/null","type":"chr"}"#);
        assert_eq!(
            records[3],
            r#"{"data":"AQIDBA==","key":"dead","mechanism":"pkcs7","mediaType":"application/vnd.uapi.16.signature"}"#
        );
        assert_eq!(
            records[4],
            r#"{"mechanism":"openpgp","mediaType":"application/vnd.uapi.16.signature"}"#
        );
        // A value that is text goes out as text, any other as Base64.
        assert!(records[1].contains(concat!(
            r#""extendedAttributes":{"user":{"binary":{"base64":"/wA="},"empty":{"text":""},"#,
            r#""nul":{"base64":"YQBi"},"text":{"text":"value"}}}"#
        )));
        // What was written reads back as what was there.
        let text: Vec<&str> = records.iter().map(String::as_str).collect();
        let m = Manifest::parse(&sequence(&text)).unwrap();
        assert_eq!(m.root, root);
        assert_eq!(m.objects.len(), 2);
        assert_eq!(m.objects[1], device);
        assert_eq!(m.signatures, [signature, Signature::new("openpgp")]);
        // The reader adds what follows from a literal: how long it is.
        let mut expected = object.clone();
        expected.contents[2].encoded_size = Some(5);
        expected.contents[2].original_size = Some(5);
        assert_eq!(m.objects[0], expected);
        let mut again = Vec::new();
        m.write(&mut again).unwrap();
        assert_eq!(Manifest::parse(&again).unwrap(), m);
    }

    #[test]
    fn the_order_of_the_objects() {
        let kind = |e: Error| match e.kind() {
            ErrorKind::Manifest(problem) => (problem, e.record(), e.field()),
            other => panic!("{:?}", other),
        };
        // The first object is the root file object: no name, a directory.
        let e = Writer::begin(Vec::new(), &FileObject::new(name("x"))).unwrap_err();
        assert_eq!(e.name(), Some("x"));
        assert_eq!(kind(e), (Problem::FirstHasName, None, Some(Field::Name)));
        let mut root = FileObject::root();
        root.inode_type = InodeType::Regular;
        let e = Writer::begin(Vec::new(), &root).unwrap_err();
        assert_eq!(kind(e), (Problem::FirstNotDirectory, None, Some(Field::Type)));
        // Every other file object has a name, and comes before the
        // signatures.
        let mut writer = Writer::begin(Vec::new(), &FileObject::root()).unwrap();
        let e = writer.file(&FileObject::root()).unwrap_err();
        assert_eq!(kind(e), (Problem::NoName, Some(1), Some(Field::Name)));
        writer.file(&FileObject::new(name("a"))).unwrap();
        writer.signature(&Signature::new("pkcs7")).unwrap();
        let e = writer.file(&FileObject::new(name("b"))).unwrap_err();
        assert_eq!(kind(e), (Problem::FileAfterSignature, Some(3), None));
        writer.signature(&Signature::new("openpgp")).unwrap();
        let bytes = writer.finish().unwrap();
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!((m.objects.len(), m.signatures.len()), (1, 2));
        // What a writer leaves that did not finish is no manifest.
        let mut unfinished = Vec::new();
        let mut writer = Writer::begin(&mut unfinished, &FileObject::root()).unwrap();
        writer.file(&FileObject::new(name("a"))).unwrap();
        drop(writer);
        let e = Manifest::parse(&unfinished).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoTrailer));
    }

    /// Notes every write and every flush.
    #[derive(Debug, Default)]
    struct Calls {
        writes: Vec<usize>,
        flushes: usize,
        fail: bool,
    }

    impl Write for Calls {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            if self.fail {
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.writes.push(data.len());
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn a_record_is_one_write() {
        let mut calls = Calls::default();
        let mut writer = Writer::begin(&mut calls, &FileObject::root()).unwrap();
        let mut empty = FileObject::new(name("empty"));
        empty.sha256 = EMPTY.parse().ok();
        writer.file(&empty).unwrap();
        writer.file(&everything()).unwrap();
        writer.finish().unwrap();
        assert_eq!(calls.writes.len(), 4);
        assert_eq!(calls.writes[0], sequence(&[ROOT]).len());
        assert_eq!(calls.writes[3], sequence(&[TRAILER]).len());
        assert_eq!(calls.flushes, 1);
        // An error of what is written to is the writer's.
        let mut calls = Calls {
            fail: true,
            ..Calls::default()
        };
        let e = Writer::begin(&mut calls, &FileObject::root()).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.io_error().and_then(std::io::Error::raw_os_error), Some(libc::ENOSPC));
    }
}
