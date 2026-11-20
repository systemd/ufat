// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading one record of a manifest into the object it holds, and the
//! rules for the fields of the objects, which the writer checks what it
//! writes against as well.
//!
//! A record is read once, member by member: serde_json reads it, and the
//! visitors here take its values as they come. Whether it is JSON at all
//! is only known at its end, and so is its media type, which says what
//! kind of object it is. So the first error in a field is noted and
//! reported when the record is known to be a file object. The rules are
//! those of the specification, and where it leaves something open those
//! of systemd's reader, src/shared/uapi16-manifest.c.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::num::NonZeroU64;

use serde_core::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::base64::Base64;
use crate::digest::Digest;
use crate::error::{Error, Field, Problem};
use crate::hex::Hex;
use crate::object::{
    Contents, DosFlags, FatSerial, FileObject, FileSystemIdentity, FlagSet, GptPartition, InodeAttributes, InodeFlags,
    InodeType, Location, Mode, RootObject, Signature, Uuid, Validity,
};
use crate::strict::{FieldTable, Key, Members, Skip, Strict};
use crate::{
    Features, Name, Order, Sha256, MAX_CONTENTS, MEDIA_TYPE, SIGNATURE_MEDIA_TYPE, TRAILER_MEDIA_TYPE, USER_NAMESPACE,
};

/// The user and group ID that is -1 as an unsigned 32-bit integer,
/// `(uid_t) -1`, which stands for no ID.
const INVALID_ID: u32 = u32::MAX;
/// The user and group ID that is -1 as an unsigned 16-bit integer, which
/// the legacy 16-bit system calls take for no ID.
const INVALID_ID_16: u32 = u16::MAX as u32;
/// The schemes a URL can have.
const URL_SCHEMES: [&str; 2] = ["http://", "https://"];
/// The symbols an HTTP field name may have besides letters and digits,
/// RFC 9110's tchar.
const TOKEN_SYMBOLS: &[u8] = b"!#$%&'*+-.^_`|~";
/// What the value of an HTTP header field cannot have.
const LINE_BREAKS: [char; 2] = ['\r', '\n'];
/// The encoding that stands for none in HTTP, which a manifest does not
/// take.
const IDENTITY_ENCODING: &str = "identity";

/// What a record holds.
pub(crate) enum DecodedObject {
    /// A file object, or what is wrong with it.
    File(Result<Box<FileObject>, Error>),
    /// A signature object.
    Signature(Signature),
    /// The trailer object.
    Trailer,
    /// An object of a media type this crate does not know.
    Other,
}

/// What the `mediaType` of a record says it is.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MediaType {
    /// None was given, or null: the record holds a file object.
    Absent,
    /// The one of a manifest, which the first object of a manifest has to
    /// have.
    Manifest,
    Signature,
    Trailer,
    Other,
}

/// A member that has to be a string, as it was found.
enum StringMember<'a> {
    /// Not there, or null.
    Absent,
    String(Cow<'a, str>),
    /// There, and not a string.
    NotString,
}

/// What is wrong with a hash and the size of the data it is the hash of:
/// data of size 0 has the hash of no data, and only it has.
enum SizeHashConflict {
    /// The hash of no data, with a size that is not 0.
    EmptyHashWithSize,
    /// The size 0, with a hash that is not the one of no data.
    ZeroSizeWithHash,
}

/// The object a message is about: `manifest object 5`, and with its name
/// `manifest object 5 (EFI/BOOT)`.
#[derive(Clone, Copy)]
pub(crate) struct Subject<'a> {
    /// The number of the record the object is in.
    record_number: u64,
    name: Option<&'a str>,
}

/// The size of some data and its hash, as far as they are known.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SizeAndHash {
    pub(crate) size: Option<u64>,
    pub(crate) sha256: Option<Sha256>,
}

/// What a contents object says of its data, as it is stored and as it is
/// once decoded, with what follows from its fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ContentsData {
    /// The data as it is stored, in its encoding.
    pub(crate) encoded: SizeAndHash,
    /// The data once it is decoded.
    pub(crate) original: SizeAndHash,
}

impl<'a> Subject<'a> {
    /// The file object `object` of the record with the number
    /// `record_number`.
    pub(crate) fn new(object: &'a FileObject, record_number: u64) -> Subject<'a> {
        Subject {
            record_number,
            name: (!object.name.is_root()).then_some(object.name.as_str()),
        }
    }

    /// The root file object, which the first record holds.
    pub(crate) fn root() -> Subject<'static> {
        Subject {
            record_number: ROOT_RECORD,
            name: Some(ROOT_NAME),
        }
    }
}

impl fmt::Display for Subject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest object {}", self.record_number)?;
        match self.name {
            Some(name) => write!(f, " ({})", name.escape_debug()),
            None => Ok(()),
        }
    }
}

impl SizeAndHash {
    /// Reconciles the size and the hash: the size 0 gives the hash of no
    /// data and the hash of no data the size 0, and the two must not
    /// contradict each other.
    fn reconcile(&mut self) -> Result<(), SizeHashConflict> {
        match (self.sha256, self.size) {
            (Some(hash), Some(size)) if hash == Sha256::EMPTY && size != 0 => {
                return Err(SizeHashConflict::EmptyHashWithSize)
            }
            (Some(hash), Some(0)) if hash != Sha256::EMPTY => return Err(SizeHashConflict::ZeroSizeWithHash),
            (Some(hash), None) if hash == Sha256::EMPTY => self.size = Some(0),
            (None, Some(0)) => self.sha256 = Some(Sha256::EMPTY),
            _ => {}
        }
        Ok(())
    }
}

impl SizeHashConflict {
    /// The error about the object `subject` names, or about a contents
    /// object of it, whose hash is the field `hash` and whose size the field
    /// `size`.
    fn into_error(self, subject: Subject<'_>, hash: Field, size: Field) -> Error {
        match self {
            SizeHashConflict::EmptyHashWithSize => Error::manifest(
                Problem::Contradiction,
                format!(
                    "{}: '{}' is the hash of no data, but '{}' is not 0",
                    subject, hash, size
                ),
            )
            .at(hash),
            SizeHashConflict::ZeroSizeWithHash => Error::manifest(
                Problem::Contradiction,
                format!(
                    "{}: '{}' is 0, but '{}' is not the hash of no data",
                    subject, size, hash
                ),
            )
            .at(size),
        }
    }
}

impl Field {
    /// The fields of a file object this crate reads, the most common
    /// first.
    const FILE_OBJECT: FieldTable = FieldTable::new(&[
        Field::Name,
        Field::Size,
        Field::Sha256,
        Field::MTimeNSec,
        Field::Mode,
        Field::Type,
        Field::Uid,
        Field::Gid,
        Field::Contents,
        Field::MediaType,
        Field::UserName,
        Field::GroupName,
        Field::Major,
        Field::Minor,
        Field::InodeToken,
        Field::ExtendedAttributes,
        Field::ReadOnly,
        Field::FlagHidden,
        Field::FlagSystem,
        Field::FlagArchive,
        Field::FlagAppendOnly,
        Field::FlagImmutable,
        Field::FlagNoAtime,
        Field::FlagNoCow,
        Field::FlagNoDump,
        Field::GptLabel,
        Field::GptUuid,
        Field::GptTypeUuid,
        Field::GptDiskUuid,
        Field::GptFlags,
        Field::GptFlagNoAuto,
        Field::GptFlagGrowFileSystem,
        Field::FatSerial,
        Field::FsUuid,
        Field::FsLabel,
        Field::Order,
        Field::Features,
        Field::ValidSinceUSec,
        Field::ValidUntilUSec,
        Field::Validity,
    ]);
    /// The fields of a contents object.
    const CONTENTS: FieldTable = FieldTable::new(&[
        Field::File,
        Field::Url,
        Field::Literal,
        Field::Encoding,
        Field::EncodedSize,
        Field::EncodedSha256,
        Field::OriginalSize,
        Field::OriginalSha256,
        Field::Offset,
        Field::HttpHeaders,
    ]);
    /// The fields of the value of an extended attribute.
    const EXTENDED_ATTRIBUTE: FieldTable = FieldTable::new(&[Field::Text, Field::Base64]);
    /// The fields of a signature object.
    const SIGNATURE: FieldTable = FieldTable::new(&[Field::Mechanism, Field::Key, Field::Data]);
}

/// An object as far as its record was read: what does not go into a
/// [`FileObject`] as it is. The fields only the root file object has are
/// kept apart, so that the first record makes a [`RootObject`] of the
/// draft and every other record a [`FileObject`].
struct Draft {
    object: Box<FileObject>,
    name: Option<Name>,
    /// The name as the record has it, when it is not a valid one.
    invalid_name: Option<String>,
    inode_type: Option<InodeType>,
    /// `fsUUID`, `fsLabel` and `fatSerial`.
    file_system: FileSystemIdentity,
    /// `gptDiskUuid`.
    gpt_disk_uuid: Option<Uuid>,
    /// `order`.
    order: Option<Order>,
    /// `features`.
    features: Option<Features>,
    /// The first field the record has that only the root file object may
    /// have.
    root_only: Option<Field>,
}

impl Draft {
    /// The draft of a record no member of which was read yet.
    fn new() -> Draft {
        Draft {
            object: Box::new(FileObject::new(Name::ROOT)),
            name: None,
            invalid_name: None,
            inode_type: None,
            file_system: FileSystemIdentity::default(),
            gpt_disk_uuid: None,
            order: None,
            features: None,
            root_only: None,
        }
    }

    /// The name the record gives, valid or not.
    fn stated_name(&self) -> Option<&str> {
        if !self.object.name.is_root() {
            return Some(&self.object.name);
        }
        self.name.as_deref().or(self.invalid_name.as_deref())
    }

    /// The fields of a partition, which are made when the first of them is
    /// read.
    fn gpt(&mut self) -> &mut GptPartition {
        self.object.gpt.get_or_insert_with(Box::default)
    }

    /// The first field the draft has that only the file objects after the
    /// root file object have: the contents, the size and the hash of a
    /// file, its inode token and device numbers, the fields of a partition
    /// and the DOS attributes.
    fn file_only_field(&self) -> Option<Field> {
        let object = &*self.object;
        [
            (Field::Size, object.size.is_some()),
            (Field::Sha256, object.sha256.is_some()),
            (Field::Contents, !object.contents.is_empty()),
            (Field::InodeToken, object.inode_token.is_some()),
            (Field::Major, object.major.is_some()),
            (Field::Minor, object.minor.is_some()),
        ]
        .into_iter()
        .find_map(|(field, has)| has.then_some(field))
        .or_else(|| object.gpt.as_deref().and_then(GptPartition::first_field))
        .or_else(|| object.dos_flags.feature_fields().map(|(field, _)| field).next())
    }

    /// Checks the draft of the first record as the root file object: it
    /// has no name, is a directory and has none of the fields only the
    /// other file objects have. [`RootObject::check_consistency`] checks
    /// its fields against each other.
    fn check_root(&self) -> Result<(), Error> {
        if self.name.is_some() {
            return Err(Error::root_has_name());
        }
        if !matches!(self.inode_type, None | Some(InodeType::Directory)) {
            return Err(Error::root_not_directory());
        }
        match self.file_only_field() {
            Some(field) => Err(Error::manifest(
                Problem::FieldNotPermitted,
                format!(
                    "{}: '{}' is not permitted on the root file object",
                    Subject::root(),
                    field
                ),
            )
            .at(field)),
            None => Ok(()),
        }
    }

    /// The root file object the draft of the first record holds, once
    /// [`Draft::check_root`] found nothing wrong with it.
    fn into_root(self) -> RootObject {
        let object = *self.object;
        RootObject {
            inode: object.inode,
            file_system: self.file_system,
            gpt_disk_uuid: self.gpt_disk_uuid,
            order: self.order,
            features: self.features,
            validity: object.validity,
        }
    }

    /// Makes the draft the file object of the record with the number
    /// `record_number`, one after the root file object: checks its fields
    /// against its inode type and against each other, and fills in what
    /// follows from them.
    fn finish(&mut self, record_number: u64) -> Result<(), Error> {
        let Some(name) = self.name.take() else {
            return Err(Error::no_name(record_number));
        };
        let object = &mut *self.object;
        object.name = name;
        object.inode_type = self.inode_type.unwrap_or(InodeType::Regular);
        let subject = Subject::new(object, record_number);
        object.check_permitted_fields(subject)?;
        if let Some(field) = self.root_only {
            return Err(Error::manifest(
                Problem::FieldNotPermitted,
                format!("{}: '{}' is only permitted on the root file object", subject, field),
            )
            .at(field));
        }
        // The contents objects were checked when they were read, and hold
        // what follows from their fields.
        let data = object.check_consistency(subject, |contents| Ok(contents.data()))?;
        // What the record does not give was filled in.
        for (field, given, known) in [
            (Field::Size, object.size.is_some(), data.size.is_some()),
            (Field::Sha256, object.sha256.is_some(), data.sha256.is_some()),
        ] {
            if known && !given {
                object.filled_in.insert(field);
            }
        }
        (object.size, object.sha256) = (data.size, data.sha256);
        Ok(())
    }
}

// The rules for the fields of the objects, which the reader holds what it
// reads to and the writer what it writes. Each check names the object in
// its error with `subject`.

impl FileObject {
    /// Checks that the object has no field its inode type does not permit:
    /// a size, contents objects or a hash on anything but a regular file, a
    /// symbolic link or a directory, device numbers on anything but a
    /// device, an access mode on a symbolic link, an inode token on a
    /// directory, the fields of a partition on anything but a regular file,
    /// and flags on anything but a regular file or a directory.
    pub(crate) fn check_permitted_fields(&self, subject: Subject<'_>) -> Result<(), Error> {
        let inode_type = self.inode_type;
        let not_permitted = |message: String| Error::manifest(Problem::FieldNotPermitted, message);
        if self.size.is_some() && !inode_type.has_contents() {
            return Err(
                not_permitted(format!("{}: 'size' is not permitted on a {}", subject, inode_type)).at(Field::Size),
            );
        }
        if (self.major.is_some() || self.minor.is_some()) && !inode_type.is_device() {
            return Err(not_permitted(format!(
                "{}: 'major' and 'minor' are not permitted on a {}",
                subject, inode_type
            ))
            .at(Field::Major));
        }
        if self.inode.mode.is_some() && inode_type == InodeType::Symlink {
            return Err(not_permitted(format!("{}: 'mode' is not permitted on a symlink", subject)).at(Field::Mode));
        }
        if self.inode_token.is_some() && inode_type == InodeType::Directory {
            return Err(
                not_permitted(format!("{}: 'inodeToken' is not permitted on a directory", subject))
                    .at(Field::InodeToken),
            );
        }
        if (!self.contents.is_empty() || self.sha256.is_some()) && !inode_type.has_contents() {
            return Err(not_permitted(format!(
                "{}: 'contents' and 'sha256' are not permitted on a {}",
                subject, inode_type
            ))
            .at(Field::Contents));
        }
        if inode_type != InodeType::Regular {
            if let Some(field) = self.gpt.as_deref().and_then(GptPartition::first_field) {
                return Err(
                    not_permitted(format!("{}: '{}' is not permitted on a {}", subject, field, inode_type)).at(field),
                );
            }
        }
        match self.unpermitted_flag() {
            Some(field) => Err(Error::unpermitted_flag(self, field, subject)),
            None => Ok(()),
        }
    }

    /// Checks that the fields of the object agree with each other, as the
    /// specification requires: `readOnly` and `mode`, and the size and the
    /// hash of the object and those of its contents objects. `contents_data`
    /// gives what each contents object says of its data: what
    /// [`Contents::check_consistency`] returns for it, or what its fields
    /// hold once a reader checked and filled it in. Returns the size and the
    /// hash of the data of the object: those it gives, and those that follow
    /// from its contents objects and from each other. Whether `gptFlags`
    /// agrees with the fields that give its flags one by one depends on what
    /// the manifest records, see [`FileObject::check_partition_flags`].
    pub(crate) fn check_consistency(
        &self,
        subject: Subject<'_>,
        contents_data: impl Fn(&Contents) -> Result<ContentsData, Error>,
    ) -> Result<SizeAndHash, Error> {
        self.inode.check_read_only(subject)?;
        // The size and the hash of the object and those of its contents
        // objects have to agree where they are about the same data. A part
        // of the data of a contents object, of the size the object gives,
        // has to fit into it. Without a size of the object, a contents
        // object gives it: the rest of its data from the offset on, and
        // every contents object that gives one has to give the same. A
        // contents object that is all of the data gives its hash.
        let mut data = SizeAndHash {
            size: self.size,
            sha256: self.sha256,
        };
        for contents in &self.contents {
            let original = contents_data(contents)?.original;
            let Some(total) = original.size else {
                continue;
            };
            // Contents::check_consistency found the offset inside the data.
            let rest = total - contents.offset;
            match (self.size, data.size) {
                (Some(stated), _) => {
                    if contents.offset.checked_add(stated).is_none_or(|end| end > total) {
                        return Err(Error::manifest(
                            Problem::Contradiction,
                            format!(
                                "{}: offset {} plus size {} exceeds the contents size {}",
                                subject, contents.offset, stated, total
                            ),
                        )
                        .at(Field::Offset));
                    }
                }
                (None, None) => data.size = Some(rest),
                (None, Some(given)) => {
                    if given != rest {
                        return Err(Error::manifest(
                            Problem::Contradiction,
                            format!("{}: contents objects give the sizes {} and {}", subject, given, rest),
                        )
                        .at(Field::Contents));
                    }
                }
            }
            // The size of the object is known from here on.
            let whole = contents.offset == 0 && original.size == data.size;
            match (original.sha256.filter(|_| whole), data.sha256) {
                (Some(hash), Some(known)) if hash != known => {
                    return Err(Error::manifest(
                        Problem::Contradiction,
                        format!("{}: object and contents hashes differ", subject),
                    )
                    .at(Field::Sha256));
                }
                (Some(hash), None) => data.sha256 = Some(hash),
                _ => {}
            }
        }
        // What the size and the hash were given or follow from has to agree.
        data.reconcile()
            .map_err(|conflict| conflict.into_error(subject, Field::Sha256, Field::Size))?;
        Ok(data)
    }

    /// Checks that the attribute flags of the partition the object
    /// describes agree where they are given twice: all of them in
    /// `gptFlags`, and one each in `gptFlagNoAuto`, `gptFlagGrowFileSystem`
    /// and `readOnly`. Where `features`, which the manifest records, has
    /// the feature of one of these fields, an object without the field
    /// counts as having it cleared, and `gptFlags` as 0. Only a regular
    /// file has `gptFlags`.
    pub(crate) fn check_partition_flags(&self, features: Features, subject: Subject<'_>) -> Result<(), Error> {
        let gpt = self.gpt.as_deref();
        let given = gpt.and_then(|gpt| gpt.flags);
        let implied = (self.inode_type == InodeType::Regular && features.contains(Features::GPT_FLAGS)).then_some(0);
        let Some(flags) = given.or(implied) else {
            return Ok(());
        };
        let one_each = [
            (
                Field::GptFlagNoAuto,
                gpt.and_then(|gpt| gpt.no_auto),
                Features::GPT_FLAG_NO_AUTO,
                GptPartition::FLAG_NO_AUTO,
            ),
            (
                Field::GptFlagGrowFileSystem,
                gpt.and_then(|gpt| gpt.grow_file_system),
                Features::GPT_FLAG_GROW_FILE_SYSTEM,
                GptPartition::FLAG_GROW_FILE_SYSTEM,
            ),
            (
                Field::ReadOnly,
                self.inode.stated_read_only(),
                Features::READ_ONLY,
                GptPartition::FLAG_READ_ONLY,
            ),
        ];
        for (field, stated, feature, flag) in one_each {
            let set = stated.or(features.contains(feature).then_some(false));
            if set.is_none_or(|set| set == (flags & flag != 0)) {
                continue;
            }
            // The error is about a field the object has. Where the other
            // one is missing, the message says what that stands for.
            let (at, missing) = match (given, stated) {
                (Some(_), Some(_)) => (Field::GptFlags, None),
                (Some(_), None) => (Field::GptFlags, Some((field, feature, "false"))),
                (None, _) => (field, Some((Field::GptFlags, Features::GPT_FLAGS, "0"))),
            };
            let mut message = format!(
                "{}: '{}' and '{}' contradict each other",
                subject,
                Field::GptFlags,
                field
            );
            if let Some((missing, feature, value)) = missing {
                message = format!(
                    "{} ('{}' is not there, which means {} as the manifest lists '{}')",
                    message,
                    missing,
                    value,
                    feature.names().next().unwrap_or_default()
                );
            }
            return Err(Error::manifest(Problem::Contradiction, message).at(at));
        }
        Ok(())
    }

    /// The user or group ID `id`, the value of `field`, if it is one. The
    /// two IDs that stand for no ID are none.
    pub(crate) fn check_id(field: Field, id: u64, subject: Subject<'_>) -> Result<u32, Error> {
        match u32::try_from(id) {
            Ok(id) if id != INVALID_ID && id != INVALID_ID_16 => Ok(id),
            _ => Err(Error::manifest(
                Problem::FieldOutOfRange,
                format!("{}: {} {} is out of range", subject, field, id),
            )
            .at(field)),
        }
    }

    /// Checks `name`, the value of `field`, as the name of a user or of a
    /// group. systemd's relaxed rules take anything that is not obviously
    /// broken or a number in disguise.
    pub(crate) fn check_owner_name(field: Field, name: &str, subject: Subject<'_>) -> Result<(), Error> {
        let digits = name.strip_prefix('-').unwrap_or(name);
        if name.is_empty()
            || name.starts_with(' ')
            || name.ends_with(' ')
            || name == "."
            || name == ".."
            || name.chars().any(|c| c.is_ascii_control() || c == ':' || c == '/')
            || digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::manifest(
                Problem::WrongFieldType,
                format!("{}: {} '{}' is not a valid name", subject, field, name.escape_debug()),
            )
            .at(field));
        }
        Ok(())
    }

    /// Checks `name` as the name of an extended attribute: it is not empty
    /// and has no control character.
    pub(crate) fn check_xattr_name(name: &str, subject: Subject<'_>) -> Result<(), Error> {
        if name.is_empty() || name.chars().any(|c| c.is_ascii_control()) {
            return Err(Error::manifest(
                Problem::InvalidExtendedAttributes,
                format!("{}: invalid extended attribute name '{}'", subject, name.escape_debug()),
            )
            .at(Field::ExtendedAttributes));
        }
        Ok(())
    }
}

impl RootObject {
    /// Checks that the fields of the root file object agree with each
    /// other, as the specification requires: `readOnly` and `mode`.
    pub(crate) fn check_consistency(&self) -> Result<(), Error> {
        self.inode.check_read_only(Subject::root())
    }
}

impl InodeAttributes {
    /// Checks that `readOnly` and `mode` agree where the attributes have
    /// both: the file is read-only if nobody has write permission. A
    /// `readOnly` a reader filled in is not one the attributes have, see
    /// [`FilledIn`](crate::FilledIn).
    fn check_read_only(&self, subject: Subject<'_>) -> Result<(), Error> {
        match (self.stated_read_only(), self.mode) {
            (Some(read_only), Some(mode)) if read_only == mode.is_writable() => Err(Error::manifest(
                Problem::Contradiction,
                format!("{}: 'readOnly' and 'mode' contradict each other", subject),
            )
            .at(Field::ReadOnly)),
            _ => Ok(()),
        }
    }
}

impl Contents {
    /// Checks that the fields of the contents object agree with each
    /// other, as the specification requires, and returns what they say of
    /// its data with what follows from them: a literal gives the size of
    /// the stored data, and without an encoding the stored data is the
    /// data. A size of 0 and the hash of no data go together. `httpHeaders`
    /// come with a URL only, and the offset is inside the data. `subject`
    /// names the file object the contents object belongs to.
    pub(crate) fn check_consistency(&self, subject: Subject<'_>) -> Result<ContentsData, Error> {
        if !self.http_headers.is_empty() && self.url().is_none() {
            return Err(Error::manifest(
                Problem::InvalidContents,
                format!("{}: 'httpHeaders' is only permitted with 'url'", subject),
            )
            .at(Field::HttpHeaders));
        }
        let mut data = self.data();
        // A literal is as large as the data as it is stored, and without
        // an encoding that is the data.
        if let Location::Literal(literal) = &self.location {
            let len = literal.len() as u64;
            let original = data.original.size.filter(|_| self.encoding.is_none());
            if let Some(size) = [data.encoded.size, original]
                .into_iter()
                .flatten()
                .find(|&size| size != len)
            {
                return Err(Error::manifest(
                    Problem::Contradiction,
                    format!("{}: literal contents are {} bytes, not {}", subject, len, size),
                )
                .at(Field::Literal));
            }
            data.encoded.size = Some(len);
            if self.encoding.is_none() {
                data.original.size = Some(len);
            }
        }
        data.encoded
            .reconcile()
            .map_err(|conflict| conflict.into_error(subject, Field::EncodedSha256, Field::EncodedSize))?;
        data.original
            .reconcile()
            .map_err(|conflict| conflict.into_error(subject, Field::OriginalSha256, Field::OriginalSize))?;
        if self.encoding.is_none() {
            // Without an encoding the encoded and the original data are the same.
            let ContentsData { encoded, original } = &mut data;
            match (encoded.size, original.size) {
                (Some(a), Some(b)) if a != b => {
                    return Err(Error::manifest(
                        Problem::Contradiction,
                        format!("{}: encoded and original size differ without an encoding", subject),
                    )
                    .at(Field::EncodedSize));
                }
                (Some(a), None) => original.size = Some(a),
                (None, Some(b)) => encoded.size = Some(b),
                _ => {}
            }
            match (encoded.sha256, original.sha256) {
                (Some(a), Some(b)) if a != b => {
                    return Err(Error::manifest(
                        Problem::Contradiction,
                        format!("{}: encoded and original hash differ without an encoding", subject),
                    )
                    .at(Field::EncodedSha256));
                }
                (Some(a), None) => original.sha256 = Some(a),
                (None, Some(b)) => encoded.sha256 = Some(b),
                _ => {}
            }
        }
        if let Some(total) = data.original.size {
            if self.offset > total {
                return Err(Error::manifest(
                    Problem::InvalidContents,
                    format!(
                        "{}: contents offset {} is beyond the data size {}",
                        subject, self.offset, total
                    ),
                )
                .at(Field::Offset));
            }
        }
        Ok(data)
    }

    /// What the contents object says of its data, as its fields hold it.
    fn data(&self) -> ContentsData {
        ContentsData {
            encoded: SizeAndHash {
                size: self.encoded_size,
                sha256: self.encoded_sha256,
            },
            original: SizeAndHash {
                size: self.original_size,
                sha256: self.original_sha256,
            },
        }
    }

    /// Fills in what follows from the fields of the contents object, `data`
    /// from [`Contents::check_consistency`], and notes what it filled in.
    fn fill_in(&mut self, data: ContentsData) {
        let given = [
            self.encoded_size.is_some(),
            self.encoded_sha256.is_some(),
            self.original_size.is_some(),
            self.original_sha256.is_some(),
        ];
        let known = [
            (Field::EncodedSize, data.encoded.size.is_some()),
            (Field::EncodedSha256, data.encoded.sha256.is_some()),
            (Field::OriginalSize, data.original.size.is_some()),
            (Field::OriginalSha256, data.original.sha256.is_some()),
        ];
        for ((field, known), given) in known.into_iter().zip(given) {
            if known && !given {
                self.filled_in.insert(field);
            }
        }
        (self.encoded_size, self.encoded_sha256) = (data.encoded.size, data.encoded.sha256);
        (self.original_size, self.original_sha256) = (data.original.size, data.original.sha256);
    }

    /// Checks `url` as the URL of the data: an http or an https one.
    pub(crate) fn check_url(url: &str, subject: Subject<'_>) -> Result<(), Error> {
        if !URL_SCHEMES.iter().any(|scheme| url.starts_with(scheme)) {
            return Err(Error::manifest(
                Problem::InvalidContents,
                format!(
                    "{}: contents URL '{}' is not http or https",
                    subject,
                    url.escape_debug()
                ),
            )
            .at(Field::Url));
        }
        Ok(())
    }

    /// Checks `encoding` as the encoding of the data: a content coding of
    /// HTTP other than the one that stands for none, in lower case. HTTP
    /// does not tell upper case from lower case, so a reader lowers the case
    /// of what it reads first.
    pub(crate) fn check_encoding(encoding: &str, subject: Subject<'_>) -> Result<(), Error> {
        let wrong = if encoding.is_empty() || encoding.eq_ignore_ascii_case(IDENTITY_ENCODING) {
            "is not permitted"
        } else if encoding.bytes().any(|b| b.is_ascii_uppercase()) {
            "is not in lower case"
        } else {
            return Ok(());
        };
        Err(Error::manifest(
            Problem::InvalidContents,
            format!("{}: encoding '{}' {}", subject, encoding.escape_debug(), wrong),
        )
        .at(Field::Encoding))
    }

    /// Checks `headers` as the header fields of the requests for the data
    /// at a URL: a name is a token as RFC 9110 has it, and none comes twice
    /// in any case. A value has no line break.
    pub(crate) fn check_headers<'h>(
        headers: impl IntoIterator<Item = &'h (String, String)>,
        subject: Subject<'_>,
    ) -> Result<(), Error> {
        let mut names = HashSet::new();
        for (name, value) in headers {
            let token = !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || TOKEN_SYMBOLS.contains(&b));
            let problem = if !token {
                format!("'{}' is not the name of an HTTP header field", name.escape_debug())
            } else if value.contains(LINE_BREAKS) {
                format!(
                    "the value of HTTP header field '{}' has a line break",
                    name.escape_debug()
                )
            } else if !names.insert(name.to_ascii_lowercase()) {
                format!("HTTP header field '{}' is given twice", name.escape_debug())
            } else {
                continue;
            };
            return Err(
                Error::manifest(Problem::InvalidContents, format!("{}: {}", subject, problem)).at(Field::HttpHeaders),
            );
        }
        Ok(())
    }
}

impl GptPartition {
    /// The first field of the partition that is set, of `gptLabel`,
    /// `gptUuid`, `gptTypeUuid`, `gptFlags`, `gptFlagNoAuto` and
    /// `gptFlagGrowFileSystem`.
    pub(crate) fn first_field(&self) -> Option<Field> {
        [
            (Field::GptLabel, self.label.is_some()),
            (Field::GptUuid, self.uuid.is_some()),
            (Field::GptTypeUuid, self.type_uuid.is_some()),
            (Field::GptFlags, self.flags.is_some()),
            (Field::GptFlagNoAuto, self.no_auto.is_some()),
            (Field::GptFlagGrowFileSystem, self.grow_file_system.is_some()),
        ]
        .into_iter()
        .find_map(|(field, set)| set.then_some(field))
    }

    /// Checks `label` as a partition label: it has no control characters
    /// and no more UTF-16 units than the partition table has room for.
    pub(crate) fn check_label(label: &str, subject: Subject<'_>) -> Result<(), Error> {
        if label.chars().any(char::is_control) || label.encode_utf16().nth(GptPartition::LABEL_MAX).is_some() {
            return Err(Error::manifest(
                Problem::WrongFieldType,
                format!(
                    "{}: '{}' is not a valid GPT partition label",
                    subject,
                    label.escape_debug()
                ),
            )
            .at(Field::GptLabel));
        }
        Ok(())
    }
}

impl FileSystemIdentity {
    /// Checks `label` as the label of a file system, see
    /// [`FileSystemIdentity::is_valid_label`].
    pub(crate) fn check_label(label: &str, subject: Subject<'_>) -> Result<(), Error> {
        if !FileSystemIdentity::is_valid_label(label) {
            return Err(Error::manifest(
                Problem::WrongFieldType,
                format!(
                    "{}: '{}' is not a valid file system label",
                    subject,
                    label.escape_debug()
                ),
            )
            .at(Field::FsLabel));
        }
        Ok(())
    }
}

/// The number of the first record of a manifest, the one that holds the
/// root file object.
pub(crate) const ROOT_RECORD: u64 = 0;
/// What a message calls the root file object, which has no name.
const ROOT_NAME: &str = "root";

/// Reads one record, member by member, into the object it holds.
pub(crate) struct RecordDecoder<'a> {
    /// What holds the JSON of the record to the rules of a manifest.
    json: Strict<'a>,
    /// The number of the record, for what is said about it.
    record_number: u64,
    /// The first error found in a field.
    first_error: Option<Error>,
}

/// A record that was read as a file object, before its media type said
/// whether it is one.
struct Candidate {
    draft: Draft,
    record_number: u64,
    first_error: Option<Error>,
}

impl Candidate {
    /// The root file object the first record holds, or what is wrong with
    /// it.
    fn into_root_object(mut self) -> Result<RootObject, Error> {
        let checked = match self.first_error.take() {
            Some(e) => Err(e),
            None => self.draft.check_root(),
        };
        checked.map_err(|e| self.annotate(e))?;
        let root = self.draft.into_root();
        root.check_consistency().map_err(|e| e.in_record(self.record_number))?;
        Ok(root)
    }

    /// The file object the record holds, or what is wrong with it.
    fn into_file_object(mut self) -> Result<Box<FileObject>, Error> {
        let finished = match self.first_error.take() {
            Some(e) => Err(e),
            None => self.draft.finish(self.record_number),
        };
        finished.map_err(|e| self.annotate(e))?;
        Ok(self.draft.object)
    }

    /// Annotates `e` as an error about the record: with its number, and
    /// with the name of the object as the record states it.
    fn annotate(&self, e: Error) -> Error {
        let e = e.in_record(self.record_number);
        match self.draft.stated_name() {
            Some(name) => e.named(name),
            None => e,
        }
    }
}

/// A value of a record as a field takes it: its type, and what it holds
/// where a field can take that. What a [`Part`] made of an array or an
/// object is a `T`.
enum Value<'a, T> {
    /// `null`. A field that is null is not there.
    Null,
    Bool(bool),
    /// A number without sign, fraction and exponent that fits into 64
    /// bits.
    Unsigned(u64),
    String(Cow<'a, str>),
    /// What a part made of an array or an object.
    Part(T),
    /// Any other number, and an array or an object the part read through.
    Other,
}

/// What a [`Part`] parsed: the value it read, or the error that ended the
/// read.
type Parsed<'a, T, E> = Result<Value<'a, T>, E>;

impl<'a, T> From<Value<'a, T>> for StringMember<'a> {
    fn from(value: Value<'a, T>) -> StringMember<'a> {
        match value {
            Value::Null => StringMember::Absent,
            Value::String(text) => StringMember::String(text),
            _ => StringMember::NotString,
        }
    }
}

impl MediaType {
    /// What the `mediaType` `value` says the record is. None is a media
    /// type that is not a string.
    fn of<T>(value: Value<'_, T>) -> Option<MediaType> {
        let Value::String(media_type) = value else {
            return None;
        };
        Some(match media_type.as_ref() {
            MEDIA_TYPE => MediaType::Manifest,
            SIGNATURE_MEDIA_TYPE => MediaType::Signature,
            TRAILER_MEDIA_TYPE => MediaType::Trailer,
            _ => MediaType::Other,
        })
    }
}

/// A part of a record that is an array or an object: the record itself,
/// and the fields that have elements or members. A [`RecordDecoder`] reads
/// a value with a part, and the part reads the array or the object. An
/// array or an object the part does not read is read through, and so is a
/// member or an element the part passes over. Their keys and strings are
/// held to the rules of a manifest all the same.
trait Part<'a>: Sized {
    /// What the part makes of what it reads.
    type Value;

    /// Reads the array `seq` hands out.
    fn array<A: SeqAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, seq: A) -> Parsed<'a, Self::Value, A::Error> {
        Skip(&mut decoder.json).visit_seq(seq).map(|()| Value::Other)
    }

    /// Reads the object `map` hands out.
    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        Skip(&mut decoder.json).visit_map(map).map(|()| Value::Other)
    }
}

/// Reads a value of a record, whatever its type is, and an array or an
/// object with `part`.
struct ValueSeed<'r, 'a, P> {
    decoder: &'r mut RecordDecoder<'a>,
    part: P,
}

impl<'a, P: Part<'a>> DeserializeSeed<'a> for ValueSeed<'_, 'a, P> {
    type Value = Value<'a, P::Value>;

    fn deserialize<D: Deserializer<'a>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'a, P: Part<'a>> Visitor<'a> for ValueSeed<'_, 'a, P> {
    type Value = Value<'a, P::Value>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    // serde_json hands out a number without sign, fraction and exponent
    // that fits into 64 bits as a u64, and any other number as an i64 or
    // an f64.
    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Unsigned(value))
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(Value::Other)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(Value::Other)
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'a str) -> Result<Self::Value, E> {
        self.decoder.json.check_unescaped(value)?;
        Ok(Value::String(Cow::Borrowed(value)))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        self.decoder.json.check_string(value)?;
        Ok(Value::String(Cow::Owned(value.to_owned())))
    }

    fn visit_seq<A: SeqAccess<'a>>(self, seq: A) -> Result<Self::Value, A::Error> {
        self.part.array(self.decoder, seq)
    }

    fn visit_map<A: MapAccess<'a>>(self, map: A) -> Result<Self::Value, A::Error> {
        self.part.object(self.decoder, map)
    }
}

impl<'a> RecordDecoder<'a> {
    /// The decoder of the record with the number `record_number`.
    fn new(record_number: u64) -> RecordDecoder<'a> {
        RecordDecoder {
            json: Strict::default(),
            record_number,
            first_error: None,
        }
    }

    /// What reads a value of the record with `part`.
    fn seed<P: Part<'a>>(&mut self, part: P) -> ValueSeed<'_, 'a, P> {
        ValueSeed { decoder: self, part }
    }

    /// Reads `text`, the whole record, as an object with `part`. A record
    /// that is JSON but no object is an error too.
    fn object<P: Part<'a>>(&mut self, text: &'a str, part: P) -> Result<P::Value, Error> {
        let mut json = serde_json::Deserializer::from_str(text);
        let read = self
            .seed(part)
            .deserialize(&mut json)
            .and_then(|value| json.end().map(|()| value));
        let record_number = self.record_number;
        match read {
            Ok(Value::Part(object)) => Ok(object),
            Ok(_) => Err(Error::manifest(
                Problem::NotObject,
                format!("manifest record {} is not a JSON object", record_number),
            )
            .in_record(record_number)),
            Err(e) => Err(Error::not_json(record_number, self.json.error(text, &e))),
        }
    }

    /// Reads the record `text`, the one with the number `record_number`, as
    /// far as a file object goes, and says what its media type makes it.
    fn read(text: &'a str, record_number: u64) -> Result<(MediaType, Candidate), Error> {
        let mut decoder = RecordDecoder::new(record_number);
        let (media_type, draft) = decoder.object(text, FileObjectRecord)?;
        let Some(media_type) = media_type else {
            return Err(Error::manifest(
                Problem::InvalidMediaType,
                format!("manifest object {} has a mediaType that is not a string", record_number),
            )
            .in_record(record_number));
        };
        let candidate = Candidate {
            draft,
            record_number,
            first_error: decoder.first_error,
        };
        Ok((media_type, candidate))
    }

    /// Reads the first record of a manifest, which holds the root file
    /// object and says with its media type that this is a manifest.
    pub(crate) fn root(text: &'a str) -> Result<RootObject, Error> {
        let (media_type, candidate) = RecordDecoder::read(text, ROOT_RECORD)?;
        if media_type != MediaType::Manifest {
            return Err(Error::manifest(
                Problem::InvalidMediaType,
                "the first object of the manifest is not of the manifest media type".into(),
            )
            .in_record(ROOT_RECORD));
        }
        candidate.into_root_object()
    }

    /// Reads the record `text`, the one with the number `record_number`,
    /// which is not the first.
    pub(crate) fn record(text: &'a str, record_number: u64) -> Result<DecodedObject, Error> {
        let (media_type, candidate) = RecordDecoder::read(text, record_number)?;
        Ok(match media_type {
            MediaType::Trailer => DecodedObject::Trailer,
            MediaType::Signature => DecodedObject::Signature(Signature::decode(text, record_number)?),
            MediaType::Other => DecodedObject::Other,
            MediaType::Absent | MediaType::Manifest => DecodedObject::File(candidate.into_file_object()),
        })
    }

    /// Notes the error `problem` in `field`, which `message` describes,
    /// unless an error was noted before.
    fn note_error(&mut self, problem: Problem, field: Field, message: impl FnOnce() -> String) {
        if self.first_error.is_none() {
            self.first_error = Some(Error::manifest(problem, message()).at(field));
        }
    }

    /// The value `checked` holds, or None after noting its error, unless an
    /// error was noted before.
    fn note_err<T>(&mut self, checked: Result<T, Error>) -> Option<T> {
        checked
            .map_err(|e| {
                self.first_error.get_or_insert(e);
            })
            .ok()
    }

    /// The object the record is about, for a message. The first record
    /// holds the root file object.
    fn subject(&self) -> Subject<'static> {
        if self.record_number == ROOT_RECORD {
            return Subject::root();
        }
        Subject {
            record_number: self.record_number,
            name: None,
        }
    }

    /// What the part made of `value`, which is none for null. A value of
    /// another type is the error `problem` in `field`, which `message`
    /// describes, and is noted.
    fn part<T>(
        &mut self,
        value: Value<'a, T>,
        problem: Problem,
        field: Field,
        message: impl FnOnce() -> String,
    ) -> Option<T> {
        match value {
            Value::Part(part) => Some(part),
            Value::Null => None,
            _ => {
                self.note_error(problem, field, message);
                None
            }
        }
    }

    /// The string `value` is. Any other value is an error, which is noted.
    fn string<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Cow<'a, str>> {
        let Value::String(value) = value else {
            self.note_error(Problem::WrongFieldType, field, || {
                format!("manifest field '{}' is not a string", field)
            });
            return None;
        };
        Some(value)
    }

    /// The boolean `value` is. Any other value is an error, which is noted.
    fn bool<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<bool> {
        let Value::Bool(value) = value else {
            self.note_error(Problem::WrongFieldType, field, || {
                format!("manifest field '{}' is not a boolean", field)
            });
            return None;
        };
        Some(value)
    }

    /// The unsigned integer of 64 bits `value` is: a number written as
    /// decimal digits without sign, fraction or exponent, as the
    /// specification has it. Any other value is an error, which is noted, a
    /// string of digits too.
    fn unsigned<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<u64> {
        let Value::Unsigned(value) = value else {
            self.note_error(Problem::WrongFieldType, field, || {
                format!("manifest field '{}' is not an unsigned integer", field)
            });
            return None;
        };
        Some(value)
    }

    /// The hash `value` is. Anything but the hex digits of one is an error,
    /// which is noted.
    fn digest<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Sha256> {
        let text = self.string(field, value)?;
        let digest = text.parse().ok();
        if digest.is_none() {
            self.note_error(Problem::WrongFieldType, field, || {
                format!("manifest field '{}' is not a SHA-256 hash", field)
            });
        }
        digest
    }

    /// The access mode `value` is, an unsigned integer like every other
    /// one.
    fn mode<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Mode> {
        let bits = self.unsigned(field, value)?;
        let mode = u32::try_from(bits).ok().and_then(Mode::new);
        if mode.is_none() {
            self.note_error(Problem::FieldOutOfRange, field, || {
                format!("manifest field '{}' is out of range: {}", field, bits)
            });
        }
        mode
    }

    /// The user or group ID `value` is.
    fn id<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<u32> {
        let id = self.unsigned(field, value)?;
        self.note_err(FileObject::check_id(field, id, self.subject()))
    }

    /// The name of a user or of a group `value` is.
    fn user_or_group_name<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Box<str>> {
        let name = self.string(field, value)?;
        let checked = FileObject::check_owner_name(field, &name, self.subject());
        self.note_err(checked).map(|()| name.into())
    }

    /// The UUID `value` is.
    fn uuid<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Uuid> {
        let text = self.string(field, value)?;
        let uuid = text.parse().ok();
        if uuid.is_none() {
            let subject = self.subject();
            self.note_error(Problem::WrongFieldType, field, || {
                format!("{}: {} '{}' is not a UUID", subject, field, text.escape_debug())
            });
        }
        uuid
    }

    /// The GPT partition label `value` is.
    fn gpt_label<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<String> {
        let label = self.string(field, value)?;
        let checked = GptPartition::check_label(&label, self.subject());
        self.note_err(checked).map(|()| label.into_owned())
    }

    /// The FAT volume serial number `value` is, `1234-ABCD`.
    fn fat_serial<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<FatSerial> {
        let text = self.string(field, value)?;
        let serial = text.parse().ok();
        if serial.is_none() {
            let subject = self.subject();
            self.note_error(Problem::WrongFieldType, field, || {
                format!(
                    "{}: {} '{}' is not a FAT volume serial number",
                    subject,
                    field,
                    text.escape_debug()
                )
            });
        }
        serial
    }

    /// The file system label `value` is.
    fn fs_label<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<String> {
        let label = self.string(field, value)?;
        let checked = FileSystemIdentity::check_label(&label, self.subject());
        self.note_err(checked).map(|()| label.into_owned())
    }

    /// The order `value`, the value of `order`, declares. A value the
    /// specification does not have declares no order, as it asks.
    fn order<T>(&mut self, field: Field, value: Value<'a, T>) -> Option<Order> {
        self.string(field, value).and_then(|value| Order::declared(&value))
    }

    /// Takes `value`, which is not null, as the value of `field` into
    /// `draft`: one of the fields of a file object or of the root file
    /// object that hold no array and no object.
    fn file_field(&mut self, field: Field, value: Value<'a, Infallible>, draft: &mut Draft) {
        let object = &mut *draft.object;
        match field {
            Field::Name => {
                if let Some(name) = self.string(field, value) {
                    match Name::new(name.as_ref()) {
                        Ok(name) => draft.name = Some(name),
                        Err(reason) => {
                            let subject = self.subject();
                            self.note_error(Problem::InvalidName, field, || {
                                format!("{}: {}: '{}'", subject, reason, name.escape_debug())
                            });
                            draft.invalid_name = Some(name.into_owned());
                        }
                    }
                }
            }
            Field::Type => {
                if let Some(name) = self.string(field, value) {
                    draft.inode_type = name.parse().ok();
                    if draft.inode_type.is_none() {
                        let subject = self.subject();
                        self.note_error(Problem::UnknownType, field, || {
                            format!("{}: unknown inode type '{}'", subject, name.escape_debug())
                        });
                    }
                }
            }
            Field::Size => object.size = self.unsigned(field, value),
            Field::Mode => object.inode.mode = self.mode(field, value),
            Field::Uid => object.inode.uid = self.id(field, value),
            Field::Gid => object.inode.gid = self.id(field, value),
            Field::UserName => object.inode.user_name = self.user_or_group_name(field, value),
            Field::GroupName => object.inode.group_name = self.user_or_group_name(field, value),
            Field::Major => object.major = self.unsigned(field, value),
            Field::Minor => object.minor = self.unsigned(field, value),
            Field::MTimeNSec => object.inode.mtime_nsec = self.unsigned(field, value),
            // The token 0 is that of a file with one name.
            Field::InodeToken => object.inode_token = self.unsigned(field, value).and_then(NonZeroU64::new),
            Field::GptLabel => draft.gpt().label = self.gpt_label(field, value),
            Field::GptUuid => draft.gpt().uuid = self.uuid(field, value),
            Field::GptTypeUuid => draft.gpt().type_uuid = self.uuid(field, value),
            Field::GptFlags => draft.gpt().flags = self.unsigned(field, value),
            Field::GptFlagNoAuto => draft.gpt().no_auto = self.bool(field, value),
            Field::GptFlagGrowFileSystem => draft.gpt().grow_file_system = self.bool(field, value),
            Field::ReadOnly => object.inode.read_only = self.bool(field, value),
            Field::FlagHidden | Field::FlagSystem | Field::FlagArchive => {
                if let (Some(flag), Some(set)) = (DosFlags::from_field(field), self.bool(field, value)) {
                    object.dos_flags.put(flag, Some(set));
                }
            }
            Field::FlagAppendOnly
            | Field::FlagImmutable
            | Field::FlagNoAtime
            | Field::FlagNoCow
            | Field::FlagNoDump => {
                if let (Some(flag), Some(set)) = (InodeFlags::from_field(field), self.bool(field, value)) {
                    object.inode.flags.put(flag, Some(set));
                }
            }
            Field::FatSerial => {
                draft.root_only.get_or_insert(field);
                draft.file_system.fat_serial = self.fat_serial(field, value);
            }
            Field::FsUuid => {
                draft.root_only.get_or_insert(field);
                draft.file_system.uuid = self.uuid(field, value);
            }
            Field::FsLabel => {
                draft.root_only.get_or_insert(field);
                draft.file_system.label = self.fs_label(field, value);
            }
            Field::GptDiskUuid => {
                draft.root_only.get_or_insert(field);
                draft.gpt_disk_uuid = self.uuid(field, value);
            }
            Field::Order => {
                draft.root_only.get_or_insert(field);
                draft.order = self.order(field, value);
            }
            Field::Sha256 => object.sha256 = self.digest(field, value),
            Field::ValidSinceUSec => object.validity.since_usec = self.unsigned(field, value).unwrap_or_default(),
            Field::ValidUntilUSec => object.validity.until_usec = self.unsigned(field, value),
            // A value the specification does not have yet is good.
            Field::Validity => {
                let validity = self.string(field, value);
                if validity.is_some_and(|validity| validity == Validity::Revoked.as_str()) {
                    object.validity.state = Validity::Revoked;
                }
            }
            _ => {}
        }
    }
}

/// The part of a member that is to be a string, a number or a boolean: it
/// reads no array and no object.
struct Scalar;

impl Part<'_> for Scalar {
    type Value = Infallible;
}

/// The record as a file object or as the root file object: the draft of
/// the object, and the media type the record gives. None is a media type
/// that is not a string.
struct FileObjectRecord;

impl<'a> Part<'a> for FileObjectRecord {
    type Value = (Option<MediaType>, Draft);

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let subject = decoder.subject();
        let mut media_type = Some(MediaType::Absent);
        let mut draft = Draft::new();
        let mut members = Members::new(map, &Field::FILE_OBJECT, &mut decoder.json);
        while let Some(key) = members.next_key(&mut decoder.json)? {
            let Key::Field(field) = key else {
                members.skip(&mut decoder.json)?;
                continue;
            };
            // A field that is null is a field that is not there. The fields
            // that hold an array or an object are read with their parts.
            match field {
                Field::ExtendedAttributes => {
                    let value = members.value(decoder.seed(XattrNamespaces))?;
                    let user = decoder.part(value, Problem::InvalidExtendedAttributes, field, || {
                        format!("{}: 'extendedAttributes' is not an object", subject)
                    });
                    draft.object.inode.user_xattrs = user.flatten().map(Box::new);
                }
                Field::Contents => {
                    let value = members.value(decoder.seed(ContentsArray))?;
                    let contents = decoder.part(value, Problem::WrongFieldType, field, || {
                        format!("manifest field '{}' is not an array", field)
                    });
                    draft.object.contents = contents.unwrap_or_default();
                }
                Field::Features => {
                    let value = members.value(decoder.seed(FeatureNames))?;
                    if !matches!(value, Value::Null) {
                        draft.root_only.get_or_insert(field);
                    }
                    draft.features = decoder.part(value, Problem::WrongFieldType, field, || {
                        format!("{}: '{}' is not an array of strings", subject, field)
                    });
                }
                _ => match members.value(decoder.seed(Scalar))? {
                    Value::Null => {}
                    value if field == Field::MediaType => media_type = MediaType::of(value),
                    value => decoder.file_field(field, value, &mut draft),
                },
            }
        }
        Ok(Value::Part((media_type, draft)))
    }
}

/// `features`: the names of the features the manifest records, strings
/// and none of them twice. Names the specification does not have are
/// passed over, as it asks.
struct FeatureNames;

impl<'a> Part<'a> for FeatureNames {
    type Value = Features;

    fn array<A: SeqAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, mut seq: A) -> Parsed<'a, Self::Value, A::Error> {
        let field = Field::Features;
        let subject = decoder.subject();
        let mut features = Features::NONE;
        let mut names = HashSet::new();
        while let Some(value) = seq.next_element_seed(decoder.seed(Scalar))? {
            let Value::String(name) = value else {
                decoder.note_error(Problem::WrongFieldType, field, || {
                    format!("{}: '{}' is not an array of strings", subject, field)
                });
                continue;
            };
            if let Some(feature) = Features::listed(&name) {
                features |= feature;
            }
            if names.contains(&name) {
                decoder.note_error(Problem::FieldOutOfRange, field, || {
                    format!("{}: '{}' lists '{}' twice", subject, field, name.escape_debug())
                });
            }
            names.insert(name);
        }
        Ok(Value::Part(features))
    }
}

/// `extendedAttributes`: namespaces that map the names of extended
/// attributes to their values. Only the `user` namespace is defined, and
/// what the part makes of it. Others are passed over, as systemd passes
/// over them.
struct XattrNamespaces;

impl<'a> Part<'a> for XattrNamespaces {
    type Value = Option<BTreeMap<String, Vec<u8>>>;

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let field = Field::ExtendedAttributes;
        let subject = decoder.subject();
        let mut user = None;
        let mut members = Members::new(map, &FieldTable::NONE, &mut decoder.json);
        while let Some(namespace) = members.next_name(&mut decoder.json)? {
            if namespace != USER_NAMESPACE {
                members.skip(&mut decoder.json)?;
                continue;
            }
            // A namespace that is null says nothing about its attributes.
            let value = members.value(decoder.seed(UserXattrs))?;
            user = decoder.part(value, Problem::InvalidExtendedAttributes, field, || {
                format!(
                    "{}: extended attribute namespace '{}' is not an object",
                    subject, namespace
                )
            });
        }
        Ok(Value::Part(user))
    }
}

/// The extended attributes of the `user` namespace: their names and
/// their values.
struct UserXattrs;

impl<'a> Part<'a> for UserXattrs {
    type Value = BTreeMap<String, Vec<u8>>;

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let field = Field::ExtendedAttributes;
        let subject = decoder.subject();
        let mut attributes = BTreeMap::new();
        let mut members = Members::new(map, &FieldTable::NONE, &mut decoder.json);
        while let Some(name) = members.next_name(&mut decoder.json)? {
            let value = members.value(decoder.seed(XattrValue))?;
            // An attribute that is null is not there.
            if matches!(value, Value::Null) || decoder.note_err(FileObject::check_xattr_name(&name, subject)).is_none()
            {
                continue;
            }
            let Some((text, base64)) = decoder.part(value, Problem::InvalidExtendedAttributes, field, || {
                format!(
                    "{}: value of extended attribute '{}' is not an object",
                    subject,
                    name.escape_debug()
                )
            }) else {
                continue;
            };
            let value = match (text, base64) {
                (StringMember::String(text), StringMember::Absent) => Some(text.into_owned().into_bytes()),
                (StringMember::NotString, StringMember::Absent) => {
                    decoder.note_error(Problem::WrongFieldType, Field::Text, || {
                        format!("manifest field '{}' is not a string", Field::Text)
                    });
                    None
                }
                (StringMember::Absent, StringMember::String(base64)) => {
                    let value = Base64::decode(&base64);
                    if value.is_none() {
                        decoder.note_error(Problem::InvalidExtendedAttributes, field, || {
                            format!(
                                "{}: extended attribute '{}' is not valid Base64",
                                subject,
                                name.escape_debug()
                            )
                        });
                    }
                    value
                }
                (StringMember::Absent, StringMember::NotString) => {
                    decoder.note_error(Problem::WrongFieldType, Field::Base64, || {
                        format!("manifest field '{}' is not a string", Field::Base64)
                    });
                    None
                }
                _ => {
                    decoder.note_error(Problem::InvalidExtendedAttributes, field, || {
                        format!(
                            "{}: extended attribute '{}' needs exactly one of 'text' and 'base64'",
                            subject,
                            name.escape_debug()
                        )
                    });
                    None
                }
            };
            if let Some(value) = value {
                attributes.insert(name.into_owned(), value);
            }
        }
        Ok(Value::Part(attributes))
    }
}

/// The value of an extended attribute, an object that is to have exactly
/// one of `text` and `base64`: the two as they were found.
struct XattrValue;

impl<'a> Part<'a> for XattrValue {
    type Value = (StringMember<'a>, StringMember<'a>);

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let (mut text, mut base64) = (StringMember::Absent, StringMember::Absent);
        let mut members = Members::new(map, &Field::EXTENDED_ATTRIBUTE, &mut decoder.json);
        while let Some(key) = members.next_key(&mut decoder.json)? {
            match key {
                Key::Field(Field::Text) => text = members.value(decoder.seed(Scalar))?.into(),
                Key::Field(Field::Base64) => base64 = members.value(decoder.seed(Scalar))?.into(),
                _ => members.skip(&mut decoder.json)?,
            }
        }
        Ok(Value::Part((text, base64)))
    }
}

/// `contents`: the contents objects of a file object.
struct ContentsArray;

impl<'a> Part<'a> for ContentsArray {
    type Value = Vec<Contents>;

    fn array<A: SeqAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, mut seq: A) -> Parsed<'a, Self::Value, A::Error> {
        let subject = decoder.subject();
        let mut list = Vec::new();
        let error_before = decoder.first_error.is_some();
        let mut count = 0usize;
        while let Some(value) = seq.next_element_seed(decoder.seed(ContentsObject))? {
            let contents = match value {
                Value::Part(contents) => contents,
                _ => {
                    decoder.note_error(Problem::InvalidContents, Field::Contents, || {
                        format!("{}: contents entry is not an object", subject)
                    });
                    Contents::default()
                }
            };
            count += 1;
            if count <= MAX_CONTENTS {
                list.push(contents);
            }
        }
        // Too many of them is what is wrong with the field, whatever is
        // wrong with one of them.
        if count > MAX_CONTENTS && !error_before {
            decoder.first_error = Some(Error::too_many_contents(subject));
        }
        Ok(Value::Part(list))
    }
}

/// A contents object.
struct ContentsObject;

impl<'a> Part<'a> for ContentsObject {
    type Value = Contents;

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let subject = decoder.subject();
        let mut contents = Contents::default();
        // How many of file, url and literal the object has.
        let mut places = 0;
        let mut members = Members::new(map, &Field::CONTENTS, &mut decoder.json);
        while let Some(key) = members.next_key(&mut decoder.json)? {
            let Key::Field(field) = key else {
                members.skip(&mut decoder.json)?;
                continue;
            };
            // A field that is null is a field that is not there.
            if field == Field::HttpHeaders {
                let value = members.value(decoder.seed(HeaderFields))?;
                let headers = decoder.part(value, Problem::InvalidContents, field, || {
                    format!("{}: '{}' is not an object", subject, field)
                });
                contents.http_headers = headers.unwrap_or_default();
                continue;
            }
            let value = members.value(decoder.seed(Scalar))?;
            if matches!(value, Value::Null) {
                continue;
            }
            match field {
                Field::File => {
                    if let Some(file) = decoder.string(field, value) {
                        match Name::new(file.as_ref()) {
                            Ok(file) => {
                                contents.location = Location::File(file);
                                places += 1;
                            }
                            Err(reason) => decoder.note_error(Problem::InvalidContents, field, || {
                                format!(
                                    "{}: contents file reference: {}: '{}'",
                                    subject,
                                    reason,
                                    file.escape_debug()
                                )
                            }),
                        }
                    }
                }
                Field::Url => {
                    if let Some(url) = decoder.string(field, value) {
                        if decoder.note_err(Contents::check_url(&url, subject)).is_some() {
                            contents.location = Location::Url(url.into_owned());
                            places += 1;
                        }
                    }
                }
                Field::Literal => {
                    if let Some(literal) = decoder.string(field, value) {
                        match Base64::decode(&literal) {
                            Some(literal) => {
                                contents.location = Location::Literal(literal);
                                places += 1;
                            }
                            None => decoder.note_error(Problem::InvalidContents, field, || {
                                format!("{}: literal contents are not Base64", subject)
                            }),
                        }
                    }
                }
                Field::Encoding => {
                    if let Some(encoding) = decoder.string(field, value) {
                        let encoding = encoding.to_ascii_lowercase();
                        if decoder.note_err(Contents::check_encoding(&encoding, subject)).is_some() {
                            contents.encoding = Some(encoding);
                        }
                    }
                }
                Field::EncodedSize => contents.encoded_size = decoder.unsigned(field, value),
                Field::EncodedSha256 => contents.encoded_sha256 = decoder.digest(field, value),
                Field::OriginalSize => contents.original_size = decoder.unsigned(field, value),
                Field::OriginalSha256 => contents.original_sha256 = decoder.digest(field, value),
                Field::Offset => contents.offset = decoder.unsigned(field, value).unwrap_or_default(),
                _ => {}
            }
        }
        // What is wrong with the contents object as a whole counts unless an
        // error was noted before.
        if decoder.first_error.is_none() {
            let checked = if places > 1 {
                Err(Error::manifest(
                    Problem::InvalidContents,
                    format!("{}: only one of file, url and literal may be set", subject),
                ))
            } else {
                contents.check_consistency(subject)
            };
            match checked {
                Ok(data) => contents.fill_in(data),
                Err(e) => decoder.first_error = Some(e),
            }
        }
        Ok(Value::Part(contents))
    }
}

/// `httpHeaders`: an object that maps the names of HTTP header fields to
/// their values, see [`Contents::check_headers`].
struct HeaderFields;

impl<'a> Part<'a> for HeaderFields {
    type Value = Vec<(String, String)>;

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let field = Field::HttpHeaders;
        let subject = decoder.subject();
        let mut headers = Vec::new();
        let mut members = Members::new(map, &FieldTable::NONE, &mut decoder.json);
        while let Some(name) = members.next_name(&mut decoder.json)? {
            match members.value(decoder.seed(Scalar))? {
                // A header field that is null is not there.
                Value::Null => {}
                Value::String(value) => headers.push((name.into_owned(), value.into_owned())),
                _ => decoder.note_error(Problem::InvalidContents, field, || {
                    format!(
                        "{}: the value of HTTP header field '{}' is not a string",
                        subject,
                        name.escape_debug()
                    )
                }),
            }
        }
        decoder.note_err(Contents::check_headers(&headers, subject));
        Ok(Value::Part(headers))
    }
}

/// The record as a signature object: its `mechanism`, `key` and `data`
/// as they were found.
struct SignatureRecord;

/// The members of a signature object, as they were found.
struct SignatureMembers<'a> {
    mechanism: StringMember<'a>,
    key: StringMember<'a>,
    data: StringMember<'a>,
}

impl<'a> Part<'a> for SignatureRecord {
    type Value = SignatureMembers<'a>;

    fn object<A: MapAccess<'a>>(self, decoder: &mut RecordDecoder<'a>, map: A) -> Parsed<'a, Self::Value, A::Error> {
        let mut signature = SignatureMembers {
            mechanism: StringMember::Absent,
            key: StringMember::Absent,
            data: StringMember::Absent,
        };
        let mut members = Members::new(map, &Field::SIGNATURE, &mut decoder.json);
        while let Some(key) = members.next_key(&mut decoder.json)? {
            let found = match key {
                Key::Field(Field::Mechanism) => &mut signature.mechanism,
                Key::Field(Field::Key) => &mut signature.key,
                Key::Field(Field::Data) => &mut signature.data,
                _ => {
                    members.skip(&mut decoder.json)?;
                    continue;
                }
            };
            *found = members.value(decoder.seed(Scalar))?.into();
        }
        Ok(Value::Part(signature))
    }
}

impl Signature {
    /// Reads the signature object the record `text` holds, the one with the
    /// number `record_number`, which is known to be a JSON object. The
    /// signature is not verified, but a manifest whose signature objects
    /// are malformed is refused like systemd refuses it.
    fn decode(text: &str, record_number: u64) -> Result<Signature, Error> {
        RecordDecoder::new(record_number)
            .object(text, SignatureRecord)?
            .into_signature(record_number)
            .map_err(|e| e.in_record(record_number))
    }
}

impl SignatureMembers<'_> {
    /// The signature object of the record with the number `record_number`
    /// that has these members.
    fn into_signature(self, record_number: u64) -> Result<Signature, Error> {
        let not_a_string = |field: Field| {
            Error::manifest(
                Problem::WrongFieldType,
                format!("manifest field '{}' is not a string", field),
            )
            .at(field)
        };
        let StringMember::String(mechanism) = self.mechanism else {
            return Err(Error::manifest(
                Problem::InvalidSignature,
                format!("manifest signature object {} has no 'mechanism' string", record_number),
            )
            .at(Field::Mechanism));
        };
        let key = match self.key {
            StringMember::Absent => None,
            StringMember::NotString => return Err(not_a_string(Field::Key)),
            StringMember::String(key) => match Hex::decode(&key) {
                Some(key) => Some(key),
                None => {
                    return Err(Error::manifest(
                        Problem::InvalidSignature,
                        format!("manifest signature object {}: 'key' is not hex", record_number),
                    )
                    .at(Field::Key));
                }
            },
        };
        let data = match self.data {
            StringMember::Absent => None,
            StringMember::NotString => return Err(not_a_string(Field::Data)),
            StringMember::String(data) => match Base64::decode(&data) {
                Some(data) => Some(data),
                None => {
                    return Err(Error::manifest(
                        Problem::InvalidSignature,
                        format!("manifest signature object {}: 'data' is not Base64", record_number),
                    )
                    .at(Field::Data));
                }
            },
        };
        let mut signature = Signature::new(mechanism);
        signature.key = key;
        signature.data = data;
        Ok(signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::testing::{read_whole, sequence, EMPTY, HELLO, MAX_NESTING, ROOT, SIGNATURE, TRAILER, WORLD};

    /// The file object of `record`, the record after the root file object.
    fn object(record: &str) -> FileObject {
        match RecordDecoder::record(record, ROOT_RECORD + 1) {
            Ok(DecodedObject::File(Ok(object))) => *object,
            Ok(DecodedObject::File(Err(e))) | Err(e) => panic!("{}: {}", record, e),
            Ok(_) => panic!("{}: not a file object", record),
        }
    }

    /// What is wrong with `record`, the record after the root file object.
    fn refused(record: &str) -> Error {
        match RecordDecoder::record(record, ROOT_RECORD + 1) {
            Ok(DecodedObject::File(Err(e))) | Err(e) => e,
            Ok(_) => panic!("{} was taken", record),
        }
    }

    #[test]
    fn reads_every_field() {
        let o = object(&format!(
            concat!(
                r#"{{"name":"dir/file","type":"reg","size":5,"mode":420,"uid":1000,"gid":100,"#,
                r#""userName":"Domain Users","groupName":"users","mTimeNSec":1700000000000000005,"#,
                r#""inodeToken":7,"extendedAttributes":{{"user":{{"b":{{"base64":"AP8="}},"a":{{"text":"x"}}}}}},"#,
                r#""gptLabel":"root","gptUuid":"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709","#,
                r#""gptTypeUuid":"urn:uuid:4f68bce3e8cd4db196e7fbcaf984b709","gptFlags":9223372036854775808,"#,
                r#""gptFlagNoAuto":true,"gptFlagGrowFileSystem":false,"readOnly":false,"sha256":"{}","#,
                r#""contents":[{{"url":"https://example.com/x"}},{{"file":"blob","offset":2,"originalSize":7,"#,
                r#""originalSha256":"{}"}}],"validSinceUSec":10,"validUntilUSec":20,"validity":"revoked","#,
                r#""xVendorField":{{"anything":[1,2,3]}}}}"#
            ),
            HELLO, WORLD
        ));
        assert_eq!(o.name, "dir/file");
        assert_eq!(o.inode_type, InodeType::Regular);
        assert_eq!(o.size, Some(5));
        assert_eq!(o.inode.mode, Mode::new(0o644));
        assert_eq!((o.inode.uid, o.inode.gid), (Some(1000), Some(100)));
        assert_eq!(o.inode.user_name.as_deref(), Some("Domain Users"));
        assert_eq!(o.inode.group_name.as_deref(), Some("users"));
        assert_eq!((o.major, o.minor), (None, None));
        assert_eq!(o.inode.mtime_nsec, Some(1_700_000_000_000_000_005));
        assert_eq!(o.inode_token, NonZeroU64::new(7));
        let attributes = o.inode.user_xattrs.as_ref().unwrap();
        let listed: Vec<(&str, &[u8])> = attributes.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
        assert_eq!(listed, [("a", &b"x"[..]), ("b", &[0, 0xff])]);
        let gpt = o.gpt.as_deref().unwrap();
        let uuid: Uuid = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709".parse().unwrap();
        assert_eq!(gpt.label.as_deref(), Some("root"));
        assert_eq!((gpt.uuid, gpt.type_uuid), (Some(uuid), Some(uuid)));
        assert_eq!(gpt.flags, Some(GptPartition::FLAG_NO_AUTO));
        assert_eq!((gpt.no_auto, gpt.grow_file_system), (Some(true), Some(false)));
        assert_eq!(o.inode.read_only, Some(false));
        assert_eq!(o.sha256, HELLO.parse().ok());
        assert_eq!(o.contents.len(), 2);
        assert_eq!(o.contents[0].url(), Some("https://example.com/x"));
        assert_eq!(o.contents[1].file().map(Name::as_str), Some("blob"));
        assert_eq!((o.contents[1].offset, o.contents[1].original_size), (2, Some(7)));
        assert_eq!(o.contents[1].original_sha256, WORLD.parse().ok());
        assert_eq!((o.validity.since_usec, o.validity.until_usec), (10, Some(20)));
        assert_eq!(o.validity.state, Validity::Revoked);

        // The fields of the other inode types.
        let o = object(r#"{"name":"null","type":"chr","major":1,"minor":3,"mode":438}"#);
        assert_eq!(
            (o.inode_type, o.major, o.minor),
            (InodeType::CharDevice, Some(1), Some(3))
        );
        let o = object(r#"{"name":"sda","type":"blk","major":18446744073709551615}"#);
        assert_eq!(
            (o.inode_type, o.major, o.minor),
            (InodeType::BlockDevice, Some(u64::MAX), None)
        );
        let o = object(r#"{"contents":[{"literal":"YS50eHQ="}],"name":"link","size":5,"type":"lnk"}"#);
        assert_eq!(o.inode_type, InodeType::Symlink);
        assert_eq!(o.contents[0].literal(), Some(&b"a.txt"[..]));
        for (name, inode_type) in [
            ("fifo", InodeType::Fifo),
            ("sock", InodeType::Socket),
            ("dir", InodeType::Directory),
        ] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","type":"{}"}}"#, name)).inode_type,
                inode_type
            );
        }

        // The root file object: a directory, and the one object that can
        // have a disk UUID.
        let root = RecordDecoder::root(concat!(
            r#"{"extendedAttributes":{"user":{}},"gid":1000,"mTimeNSec":1699999000000000000,"#,
            r#""mediaType":"application/vnd.uapi.16.manifest","mode":509,"uid":1000,"readOnly":false,"#,
            r#""gptDiskUuid":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709","validUntilUSec":20}"#
        ))
        .unwrap();
        assert_eq!(
            root.stated_features(),
            Features::USER_XATTR
                | Features::GID
                | Features::MTIME
                | Features::MODE
                | Features::UID
                | Features::READ_ONLY
                | Features::GPT_DISK_UUID
        );
        assert_eq!(root.inode.user_xattrs.as_deref().map(BTreeMap::len), Some(0));
        assert_eq!(
            (root.inode.uid, root.inode.gid, root.inode.mode),
            (Some(1000), Some(1000), Mode::new(0o775))
        );
        assert_eq!(root.inode.read_only, Some(false));
        assert_eq!(root.gpt_disk_uuid, Some(uuid));
        assert_eq!(root.validity.until_usec, Some(20));
        // Saying that it has no name, that it is a directory or that it is
        // no hard link says nothing.
        let root = r#"{"mediaType":"application/vnd.uapi.16.manifest","type":"dir","name":null,"inodeToken":0}"#;
        assert_eq!(RecordDecoder::root(root).unwrap(), RootObject::default());
    }

    /// The root file object has none of the fields only the other file
    /// objects have. Those of a sub-manifest in its directory, size,
    /// contents and hash, are the fields of the object of that directory
    /// in the manifest above.
    #[test]
    fn what_the_root_cannot_have() {
        let root = |field: &str| format!(r#"{{"mediaType":"application/vnd.uapi.16.manifest",{}}}"#, field);
        let sha256 = format!(r#""sha256":"{}""#, EMPTY);
        for (member, field) in [
            (r#""size":5"#, Field::Size),
            (r#""size":0"#, Field::Size),
            (sha256.as_str(), Field::Sha256),
            (r#""contents":[{"file":"sub"}]"#, Field::Contents),
            (r#""inodeToken":3"#, Field::InodeToken),
            (r#""major":1"#, Field::Major),
            (r#""minor":1"#, Field::Minor),
            (r#""gptLabel":"l""#, Field::GptLabel),
            (r#""gptUuid":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709""#, Field::GptUuid),
            (
                r#""gptTypeUuid":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709""#,
                Field::GptTypeUuid,
            ),
            (r#""gptFlags":0"#, Field::GptFlags),
            (r#""gptFlagNoAuto":false"#, Field::GptFlagNoAuto),
            (r#""gptFlagGrowFileSystem":true"#, Field::GptFlagGrowFileSystem),
            (r#""flagHidden":false"#, Field::FlagHidden),
            (r#""flagSystem":true"#, Field::FlagSystem),
            (r#""flagArchive":true"#, Field::FlagArchive),
            // The first of them is named.
            (r#""flagHidden":true,"size":1"#, Field::Size),
        ] {
            let e = RecordDecoder::root(&root(member)).unwrap_err();
            assert_eq!(
                (e.kind(), e.record_number(), e.name(), e.field()),
                (
                    ErrorKind::Manifest(Problem::FieldNotPermitted),
                    Some(ROOT_RECORD),
                    None,
                    Some(field)
                ),
                "{}",
                member
            );
            assert_eq!(
                e.to_string(),
                format!(
                    "manifest object 0 (root): '{}' is not permitted on the root file object",
                    field
                )
            );
        }
        // An empty list of contents objects is none, and null is no value.
        for member in [r#""contents":[]"#, r#""size":null,"flagHidden":null,"gptLabel":null"#] {
            assert_eq!(
                RecordDecoder::root(&root(member)).unwrap(),
                RootObject::default(),
                "{}",
                member
            );
        }
        // A name and a type that is not a directory have errors of their
        // own, and readOnly has to agree with mode on the root too.
        for (member, problem) in [
            (r#""name":"x""#, Problem::RootHasName),
            (r#""type":"reg""#, Problem::RootNotDirectory),
            (r#""mode":420,"readOnly":true"#, Problem::Contradiction),
        ] {
            let e = RecordDecoder::root(&root(member)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(problem), "{}", member);
        }
    }

    #[test]
    fn what_a_field_can_look_like() {
        // An object says as little as its name.
        let o = object(r#"{"name":"x"}"#);
        assert_eq!(o, FileObject::new(Name::new("x").unwrap()));
        // A field that is null is not there. Fields this crate does not
        // know are passed over, whatever they hold.
        let nulls = concat!(
            r#"{"name":"x","type":null,"size":null,"mode":null,"uid":null,"userName":null,"major":null,"#,
            r#""mTimeNSec":null,"inodeToken":null,"extendedAttributes":null,"gptLabel":null,"gptFlags":null,"#,
            r#""gptDiskUuid":null,"readOnly":null,"contents":null,"sha256":null,"validSinceUSec":null,"#,
            r#""validUntilUSec":null,"validity":null,"xUnknown":null,"xFlagHidden":"x","other":{"a":[{}]}}"#
        );
        assert_eq!(object(nulls), o);
        assert_eq!(
            object(r#"{"name":"x","mediaType":"application/vnd.uapi.16.manifest"}"#),
            o
        );
        assert_eq!(object(r#"{"name":"x","mediaType":null}"#), o);
        // Also large numbers and nesting. What JSON takes nowhere else in
        // a record it does not take in such a field either: a number too
        // large for a double, and more arrays and objects inside each other
        // than serde_json reads, the object of the record among them.
        // 1.7976931348623158e308 rounds to the largest double, and only
        // float_roundtrip reads it as that.
        let largest = "1.7976931348623158e308";
        let deep = |depth: usize| format!("{}1{}", r#"[{"a":"#.repeat(depth), "}]".repeat(depth));
        let nested = |depth: usize| format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
        for value in [
            "1e300",
            "-1e300",
            &"9".repeat(300),
            largest,
            &deep(50),
            &nested(MAX_NESTING - 1),
        ] {
            assert_eq!(object(&format!(r#"{{"name":"x","xUnknown":{}}}"#, value)), o);
        }
        for value in ["1e400", "-1e400", &"9".repeat(400), &deep(500), &nested(MAX_NESTING)] {
            let e = refused(&format!(r#"{{"name":"x","xUnknown":{}}}"#, value));
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NotJson), "{}", value);
        }
        let e = refused(&format!(r#"{{"name":"x","size":{}}}"#, largest));
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::WrongFieldType), Some(Field::Size))
        );
        // Integers are numbers of up to 64 bits.
        for (text, size) in [("5", 5), ("0", 0), ("18446744073709551615", u64::MAX)] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","size":{}}}"#, text)).size,
                Some(size),
                "{}",
                text
            );
        }
        // An integer has no sign, not even -0, and is no string of digits.
        for text in [
            "-0",
            "-1",
            r#""-0""#,
            r#""5""#,
            r#""0005""#,
            r#""0""#,
            r#""18446744073709551615""#,
        ] {
            let e = refused(&format!(r#"{{"name":"x","size":{}}}"#, text));
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::WrongFieldType), Some(Field::Size)),
                "{}",
                text
            );
        }
        // Access modes are numbers in decimal like every other integer, and
        // no strings of octal digits.
        for (text, mode) in [("420", 0o644), ("4095", 0o7777), ("0", 0)] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","mode":{}}}"#, text)).inode.mode,
                Mode::new(mode),
                "{}",
                text
            );
        }
        for text in [r#""644""#, r#""0644""#, r#""7777""#] {
            let e = refused(&format!(r#"{{"name":"x","mode":{}}}"#, text));
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::WrongFieldType), Some(Field::Mode)),
                "{}",
                text
            );
        }
        // The largest ID, and the token of a file with one name. An ID is
        // any below (uid_t) -1 but the one that is -1 in 16 bits.
        assert_eq!(
            object(r#"{"name":"x","uid":4294967294,"gid":65534}"#).inode.uid,
            Some(u32::MAX - 1)
        );
        assert_eq!(object(r#"{"name":"x","uid":65536,"gid":65534}"#).inode.gid, Some(65534));
        for (record, field) in [
            (r#"{"name":"x","uid":65535}"#, Field::Uid),
            (r#"{"name":"x","gid":65535}"#, Field::Gid),
            (r#"{"name":"x","uid":4294967295}"#, Field::Uid),
            (r#"{"name":"x","gid":4294967295}"#, Field::Gid),
        ] {
            let e = refused(record);
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::FieldOutOfRange), Some(field)),
                "{}",
                record
            );
        }
        assert_eq!(object(r#"{"name":"x","inodeToken":0}"#).inode_token, None);
        assert_eq!(object(r#"{"name":"x","type":"dir","inodeToken":0}"#).inode_token, None);
        // Any validity but revoked is good.
        for (text, validity) in [
            ("good", Validity::Good),
            ("revoked", Validity::Revoked),
            ("REVOKED", Validity::Good),
            ("", Validity::Good),
            ("later", Validity::Good),
        ] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","validity":"{}"}}"#, text))
                    .validity
                    .state,
                validity,
                "{:?}",
                text
            );
        }
        // Names of users and groups are taken liberally.
        for name in ["root", "Domain Users", "1a", "-a", "\u{e9}", "a\u{85}"] {
            let o = object(&format!(
                r#"{{"name":"x","userName":"{}","groupName":"{}"}}"#,
                name, name
            ));
            assert_eq!(
                (o.inode.user_name.as_deref(), o.inode.group_name.as_deref()),
                (Some(name), Some(name))
            );
        }
        // A partition label has room for 36 UTF-16 units.
        let label = "x".repeat(GptPartition::LABEL_MAX);
        let o = object(&format!(r#"{{"name":"x","gptLabel":"{}"}}"#, label));
        assert_eq!(o.gpt.unwrap().label, Some(label));
        let pairs = "\u{1f600}".repeat(GptPartition::LABEL_MAX / 2);
        assert!(object(&format!(r#"{{"name":"x","gptLabel":"{}"}}"#, pairs))
            .gpt
            .is_some());
        for label in [
            format!("{}x", pairs),
            "x".repeat(GptPartition::LABEL_MAX + 1),
            "a\tb".into(),
            "a\u{85}b".into(),
        ] {
            let e = refused(&format!(
                r#"{{"name":"x","gptLabel":{}}}"#,
                serde_json::Value::from(label.as_str())
            ));
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::WrongFieldType), "{:?}", label);
        }
        // The longest name, and one byte more. A component is not limited
        // on its own.
        let name = "x".repeat(Name::MAX_LEN);
        assert_eq!(object(&format!(r#"{{"name":"{}"}}"#, name)).name, name.as_str());
        let e = refused(&format!(r#"{{"name":"{}x"}}"#, name));
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::InvalidName));
        assert_eq!(
            e.to_string(),
            format!("manifest object 1: name is longer than 4095 bytes: '{}x'", name)
        );
    }

    /// A `readOnly` the reader filled in is not one the object has: the
    /// checks of the object, which a writer runs as well, take it for one
    /// that is not there.
    #[test]
    fn filled_in_read_only() {
        let root = r#"{"mediaType":"application/vnd.uapi.16.manifest","features":["mode","read-only"],"mode":365}"#;
        let m = read_whole(&sequence(&[root, r#"{"name":"x","mode":292}"#, TRAILER])).unwrap();
        let (root, object) = (&m.root, &m.objects[0]);
        for inode in [&root.inode, &object.inode] {
            assert_eq!(inode.read_only, Some(false));
            assert!(inode.filled_in.contains(Field::ReadOnly));
            assert!(!inode.is_read_only());
        }
        assert!(root.check_consistency().is_ok());
        let subject = Subject::new(object, 1);
        assert_eq!(
            object
                .check_consistency(subject, |contents| contents.check_consistency(subject))
                .unwrap(),
            SizeAndHash::default()
        );
        assert_eq!(
            (root.stated_features(), object.stated_features()),
            (Features::MODE, Features::MODE)
        );
        // A readOnly the object has is held against its mode.
        let mut given = object.clone();
        given.inode.filled_in.remove(Field::ReadOnly);
        let e = given
            .check_consistency(Subject::new(&given, 1), |contents| Ok(contents.data()))
            .unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::Contradiction), Some(Field::ReadOnly))
        );
    }

    /// The checks a writer runs on an object it is handed, whose contents
    /// objects no reader checked or filled in, find what a reader finds in
    /// the record of that object.
    #[test]
    fn consistency_of_objects_not_read() {
        let check = |object: &FileObject| {
            let subject = Subject::new(object, 1);
            object.check_consistency(subject, |contents| contents.check_consistency(subject))
        };
        let file = |size: Option<u64>, contents: Contents| {
            let mut object = FileObject::new(Name::new("x").unwrap());
            object.size = size;
            object.contents = vec![contents];
            object
        };
        let hello = || Contents::new(Location::Literal(b"hello".to_vec()));
        assert_eq!(
            check(&file(None, hello())).unwrap(),
            SizeAndHash {
                size: Some(5),
                sha256: None
            }
        );
        let mut beyond = hello();
        beyond.offset = 7;
        let mut headers = Contents::new(Location::File(Name::new("a").unwrap()));
        headers.http_headers = vec![("A".to_string(), "b".to_string())];
        let mut empty = file(Some(3), hello());
        empty.contents.clear();
        empty.sha256 = EMPTY.parse().ok();
        let mut read_only = file(None, hello());
        read_only.inode.mode = Mode::new(0o644);
        read_only.inode.read_only = Some(true);
        for (object, record) in [
            (
                file(None, beyond),
                r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":7}]}"#.to_string(),
            ),
            (
                file(Some(10), hello()),
                r#"{"name":"x","size":10,"contents":[{"literal":"aGVsbG8="}]}"#.to_string(),
            ),
            (
                file(None, headers),
                r#"{"name":"x","contents":[{"file":"a","httpHeaders":{"A":"b"}}]}"#.to_string(),
            ),
            (empty, format!(r#"{{"name":"x","size":3,"sha256":"{}"}}"#, EMPTY)),
            (
                read_only,
                r#"{"name":"x","mode":420,"readOnly":true,"contents":[{"literal":"aGVsbG8="}]}"#.to_string(),
            ),
        ] {
            let e = check(&object).unwrap_err();
            let read = refused(&record);
            assert_eq!((e.kind(), e.field()), (read.kind(), read.field()), "{}", record);
        }
    }

    /// `gptFlags` holds the flags that `gptFlagNoAuto`,
    /// `gptFlagGrowFileSystem` and `readOnly` give one each, and the two
    /// agree. Where the manifest lists the feature of a field, an object
    /// without the field has its flags cleared.
    #[test]
    fn partition_flags() {
        let (no_auto, grow) = (GptPartition::FLAG_NO_AUTO, GptPartition::FLAG_GROW_FILE_SYSTEM);
        let read_only = GptPartition::FLAG_READ_ONLY;
        let listed = Features::GPT_FLAGS
            | Features::GPT_FLAG_NO_AUTO
            | Features::GPT_FLAG_GROW_FILE_SYSTEM
            | Features::READ_ONLY;
        let check = |features: Features, record: &str| {
            let o = object(record);
            o.check_partition_flags(features, Subject::new(&o, 1))
        };
        for (features, record) in [
            (
                Features::NONE,
                format!(r#"{{"name":"x","gptFlags":{},"gptFlagNoAuto":true}}"#, no_auto),
            ),
            (
                Features::NONE,
                format!(
                    r#"{{"name":"x","gptFlags":{},"gptFlagGrowFileSystem":true,"gptFlagNoAuto":false}}"#,
                    grow
                ),
            ),
            (
                Features::NONE,
                format!(r#"{{"name":"x","gptFlags":{},"readOnly":true}}"#, read_only),
            ),
            (Features::NONE, r#"{"name":"x","gptFlags":0,"readOnly":false}"#.into()),
            // Without the features nothing is known of a field that is not
            // there.
            (
                Features::NONE,
                format!(r#"{{"name":"x","gptFlags":{}}}"#, no_auto | grow | read_only),
            ),
            (
                Features::NONE,
                r#"{"name":"x","readOnly":true,"gptFlagNoAuto":true}"#.into(),
            ),
            // With them, it is cleared.
            (listed, r#"{"name":"x"}"#.into()),
            (listed, r#"{"name":"x","gptFlags":0}"#.into()),
            (listed, r#"{"name":"x","readOnly":false,"gptFlagNoAuto":false}"#.into()),
            (
                listed,
                format!(
                    r#"{{"name":"x","gptFlags":{},"gptFlagNoAuto":true,"readOnly":true}}"#,
                    no_auto | read_only
                ),
            ),
            // Only a regular file has gptFlags.
            (listed, r#"{"name":"x","type":"dir","readOnly":true}"#.into()),
            (listed, r#"{"name":"x","type":"lnk","readOnly":true}"#.into()),
        ] {
            assert!(check(features, &record).is_ok(), "{:?} {}", features, record);
        }
        // readOnly true with the read-only flag clear, and false with it
        // set, and the same for the fields of the other flags.
        for (features, record, field, why) in [
            (
                Features::NONE,
                r#"{"name":"x","gptFlags":0,"readOnly":true}"#.to_string(),
                Field::ReadOnly,
                "",
            ),
            (
                Features::NONE,
                format!(r#"{{"name":"x","gptFlags":{},"readOnly":false}}"#, read_only),
                Field::ReadOnly,
                "",
            ),
            (
                listed,
                r#"{"name":"x","readOnly":true}"#.to_string(),
                Field::ReadOnly,
                " ('gptFlags' is not there, which means 0 as the manifest lists 'gpt-flags')",
            ),
            (
                listed,
                format!(r#"{{"name":"x","gptFlags":{}}}"#, read_only),
                Field::ReadOnly,
                " ('readOnly' is not there, which means false as the manifest lists 'read-only')",
            ),
            (
                Features::NONE,
                format!(r#"{{"name":"x","gptFlags":{},"gptFlagNoAuto":false}}"#, no_auto),
                Field::GptFlagNoAuto,
                "",
            ),
            (
                listed,
                format!(r#"{{"name":"x","gptFlags":{}}}"#, no_auto),
                Field::GptFlagNoAuto,
                " ('gptFlagNoAuto' is not there, which means false as the manifest lists 'gpt-flag-no-auto')",
            ),
            (
                listed,
                r#"{"name":"x","gptFlagGrowFileSystem":true}"#.to_string(),
                Field::GptFlagGrowFileSystem,
                " ('gptFlags' is not there, which means 0 as the manifest lists 'gpt-flags')",
            ),
        ] {
            let e = check(features, &record).unwrap_err();
            // The error is about gptFlags where the object has it.
            let at = if record.contains(r#""gptFlags""#) {
                Field::GptFlags
            } else {
                field
            };
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::Contradiction), Some(at)),
                "{}",
                record
            );
            assert_eq!(
                e.to_string(),
                format!(
                    "manifest object 1 (x): 'gptFlags' and '{}' contradict each other{}",
                    field, why
                )
            );
        }
    }

    #[test]
    fn flags_and_the_file_system() {
        let o = object(r#"{"name":"x","flagHidden":true,"flagArchive":false,"flagNoCow":null}"#);
        assert_eq!(o.dos_flags.get(DosFlags::HIDDEN), Some(true));
        assert_eq!(o.dos_flags.get(DosFlags::ARCHIVE), Some(false));
        assert_eq!(o.inode.flags.get(InodeFlags::NO_COW), None);
        let dir = object(r#"{"name":"d","type":"dir","flagImmutable":true,"flagSystem":true}"#);
        assert_eq!(
            (dir.dos_flags.set, dir.inode.flags.set),
            (DosFlags::SYSTEM, InodeFlags::IMMUTABLE)
        );
        // Only regular files and directories have flags. The root has no
        // DOS attributes, see what_the_root_cannot_have().
        for (record, field) in [
            (r#"{"name":"l","type":"lnk","flagHidden":true}"#, Field::FlagHidden),
            (r#"{"name":"f","type":"fifo","flagNoDump":false}"#, Field::FlagNoDump),
        ] {
            let e = refused(record);
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::FieldNotPermitted), Some(field)),
                "{}",
                record
            );
        }
        assert_eq!(
            refused(r#"{"name":"x","flagHidden":"x"}"#).kind(),
            ErrorKind::Manifest(Problem::WrongFieldType)
        );
        let root = RecordDecoder::root(concat!(
            r#"{"mediaType":"application/vnd.uapi.16.manifest","flagImmutable":true,"fatSerial":"1234-abcd","#,
            r#""fsUUID":"11111111-2222-3333-4444-555555555555","fsLabel":"ESP","order":"codepoint","#,
            r#""features":["flag-immutable","x-later","size"]}"#
        ))
        .unwrap();
        assert_eq!(root.inode.flags.get(InodeFlags::IMMUTABLE), Some(true));
        assert_eq!(
            root.stated_features(),
            Features::FLAG_IMMUTABLE | Features::FAT_SERIAL | Features::FS_UUID | Features::FS_LABEL
        );
        let identity = &root.file_system;
        assert_eq!(identity.fat_serial, Some(FatSerial(0x1234_abcd)));
        assert_eq!(identity.label.as_deref(), Some("ESP"));
        assert_eq!(root.order, Some(Order::CodePoint));
        // A feature the specification does not have is passed over.
        assert_eq!(root.features, Some(Features::FLAG_IMMUTABLE | Features::SIZE));
        // An order the specification does not have is none.
        let root = RecordDecoder::root(r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"later"}"#).unwrap();
        assert_eq!(root.order, None);
        for root in [
            r#"{"mediaType":"application/vnd.uapi.16.manifest","flagHidden":true}"#,
            r#"{"mediaType":"application/vnd.uapi.16.manifest","features":["size","size"]}"#,
            r#"{"mediaType":"application/vnd.uapi.16.manifest","features":"size"}"#,
            r#"{"mediaType":"application/vnd.uapi.16.manifest","fatSerial":"1234ABCD"}"#,
            r#"{"mediaType":"application/vnd.uapi.16.manifest","fsLabel":"a\u0007"}"#,
        ] {
            assert!(RecordDecoder::root(root).is_err(), "{}", root);
        }
        // These belong to the root file object alone.
        for (record, field) in [
            (r#"{"name":"x","order":"codepoint"}"#, Field::Order),
            (r#"{"name":"x","order":"later"}"#, Field::Order),
            (r#"{"name":"x","features":[]}"#, Field::Features),
            (r#"{"name":"x","fsLabel":"ESP"}"#, Field::FsLabel),
            (r#"{"name":"x","fatSerial":"1234-ABCD"}"#, Field::FatSerial),
            (
                r#"{"name":"x","fsUUID":"11111111-2222-3333-4444-555555555555"}"#,
                Field::FsUuid,
            ),
            (
                r#"{"name":"x","gptDiskUuid":"11111111-2222-3333-4444-555555555555"}"#,
                Field::GptDiskUuid,
            ),
        ] {
            let e = refused(record);
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::FieldNotPermitted), Some(field)),
                "{}",
                record
            );
        }
    }

    #[test]
    fn extended_attributes() {
        let attributes = |text: &str| {
            let object = object(&format!(r#"{{"name":"x","extendedAttributes":{}}}"#, text));
            object.inode.user_xattrs.map(|attributes| *attributes)
        };
        // Nothing is said about the namespace, or it is empty.
        assert_eq!(attributes("{}"), None);
        assert_eq!(attributes(r#"{"user":null}"#), None);
        assert_eq!(attributes(r#"{"other":{"a":"b"},"USER":5}"#), None);
        assert_eq!(attributes(r#"{"user":{}}"#), Some(BTreeMap::new()));
        assert_eq!(attributes(r#"{"user":{"k":null}}"#), Some(BTreeMap::new()));
        let listed = attributes(concat!(
            r#"{"other":5,"user":{"b":{"text":"2"},"a":{"base64":"AAE="},"c":{"text":""},"#,
            r#""d":{"text":"t","base64":null,"more":1}}}"#
        ))
        .unwrap();
        let listed: Vec<(&str, &[u8])> = listed.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
        assert_eq!(listed, [("a", &[0u8, 1][..]), ("b", b"2"), ("c", b""), ("d", b"t")]);
        // A value that holds a NUL has to be written in Base64, and a
        // text with a noncharacter is no string of a manifest at all.
        for text in [r#"x\u0000y"#, r#"\uffff"#, "\u{fdd0}"] {
            let e = refused(&format!(
                r#"{{"name":"x","extendedAttributes":{{"user":{{"e":{{"text":"{}"}}}}}}}}"#,
                text
            ));
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::InvalidString), "{}", text);
        }
    }

    #[test]
    fn fills_in_what_follows() {
        let empty: Sha256 = EMPTY.parse().unwrap();
        let hello: Sha256 = HELLO.parse().unwrap();
        // The size 0 and the hash of no data go together.
        let o = object(r#"{"name":"x","size":0}"#);
        assert_eq!((o.size, o.sha256), (Some(0), Some(empty)));
        let o = object(&format!(r#"{{"name":"x","sha256":"{}"}}"#, EMPTY));
        assert_eq!((o.size, o.sha256), (Some(0), Some(empty)));
        let o = object(&format!(r#"{{"name":"x","type":"dir","sha256":"{}"}}"#, EMPTY));
        assert_eq!(o.size, Some(0));
        // A literal says how long it is.
        let o = object(r#"{"name":"x","contents":[{"literal":"aGVsbG8="}]}"#);
        assert_eq!(o.size, Some(5));
        assert_eq!(
            (o.contents[0].encoded_size, o.contents[0].original_size),
            (Some(5), Some(5))
        );
        let o = object(r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":2}]}"#);
        assert_eq!(o.size, Some(3));
        let o = object(r#"{"name":"x","contents":[{"literal":""}]}"#);
        assert_eq!((o.size, o.sha256), (Some(0), Some(empty)));
        // An encoded literal says how long the encoded data is.
        let o = object(
            r#"{"name":"x","size":5,"contents":[{"literal":"H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==","encoding":"GZIP"}]}"#,
        );
        let contents = &o.contents[0];
        assert_eq!(contents.encoding.as_deref(), Some("gzip"));
        assert_eq!((contents.encoded_size, contents.original_size), (Some(25), None));
        // Without an encoding the encoded data is the original data.
        let o = object(&format!(
            r#"{{"name":"x","contents":[{{"file":"a","encodedSize":5,"originalSha256":"{}"}}]}}"#,
            HELLO
        ));
        let contents = &o.contents[0];
        assert_eq!((contents.encoded_size, contents.original_size), (Some(5), Some(5)));
        assert_eq!(
            (contents.encoded_sha256, contents.original_sha256),
            (Some(hello), Some(hello))
        );
        // The object is the whole of the contents: their size and hash are
        // its own.
        assert_eq!((o.size, o.sha256), (Some(5), Some(hello)));
        // It is a part of them: the size follows, the hash does not.
        let o = object(&format!(
            r#"{{"name":"x","contents":[{{"file":"a","offset":2,"originalSize":5,"originalSha256":"{}"}}]}}"#,
            HELLO
        ));
        assert_eq!((o.size, o.sha256), (Some(3), None));
        let o = object(&format!(
            r#"{{"name":"x","size":3,"sha256":"{}","contents":[{{"file":"a","originalSize":5,"originalSha256":"{}"}}]}}"#,
            HELLO, WORLD
        ));
        assert_eq!((o.size, o.sha256), (Some(3), Some(hello)));
        // Every contents object that gives a size gives the same one,
        // whichever comes first.
        let o = object(
            r#"{"name":"x","contents":[{"file":"a","originalSize":5,"offset":1},{"file":"b","originalSize":4}]}"#,
        );
        assert_eq!(o.size, Some(4));
        for contents in [
            [r#"{"file":"a","originalSize":5}"#, r#"{"file":"b","originalSize":4}"#],
            [r#"{"literal":"YWJj"}"#, r#"{"literal":"YWJjZA=="}"#],
            [
                r#"{"url":"https://example.com/x","originalSize":3}"#,
                r#"{"literal":"YWJjZA=="}"#,
            ],
        ] {
            for [first, second] in [contents, [contents[1], contents[0]]] {
                let e = refused(&format!(r#"{{"name":"x","contents":[{},{}]}}"#, first, second));
                assert_eq!(
                    (e.kind(), e.field()),
                    (ErrorKind::Manifest(Problem::Contradiction), Some(Field::Contents)),
                    "{} {}",
                    first,
                    second
                );
            }
        }
        // A size that follows from the contents objects is held against
        // the hash, as one that is given.
        for record in [
            format!(r#"{{"name":"x","sha256":"{}","contents":[{{"literal":""}}]}}"#, HELLO),
            format!(
                r#"{{"name":"x","contents":[{{"literal":"","originalSha256":"{}"}}]}}"#,
                HELLO
            ),
            format!(
                r#"{{"name":"x","sha256":"{}","contents":[{{"literal":"aGVsbG8="}}]}}"#,
                EMPTY
            ),
        ] {
            let e = refused(&record);
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::Contradiction), "{}", record);
        }
    }

    #[test]
    fn contents_objects() {
        let contents = |text: &str| {
            object(&format!(r#"{{"name":"x","contents":[{}]}}"#, text))
                .contents
                .remove(0)
        };
        assert_eq!(contents("{}"), Contents::default());
        assert_eq!(
            contents(r#"{"file":null,"url":null,"literal":null,"offset":null,"xHeaders":{"A":"b"}}"#),
            Contents::default()
        );
        // The header fields of a request for a URL, sorted by nothing but
        // the manifest.
        let headers = contents(r#"{"url":"https://example.com/x","httpHeaders":{"X-Foo":"bar","Authorization":"t"}}"#);
        assert_eq!(
            headers.http_headers,
            [
                ("X-Foo".to_string(), "bar".to_string()),
                ("Authorization".to_string(), "t".to_string())
            ]
        );
        let headers = contents(r#"{"url":"https://example.com/x","httpHeaders":{"A":null,"B":"c","b":null}}"#);
        assert_eq!(headers.http_headers, [("B".to_string(), "c".to_string())]);
        for refused_headers in [
            r#"{"file":"y","httpHeaders":{"A":"b"}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":{"A b":"c"}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":{"":"c"}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":{"A":"b\nc"}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":{"A":"b","a":"c"}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":{"A":1}}"#,
            r#"{"url":"https://example.com/x","httpHeaders":[]}"#,
        ] {
            let e = refused(&format!(r#"{{"name":"x","contents":[{}]}}"#, refused_headers));
            assert_eq!(
                e.kind(),
                ErrorKind::Manifest(Problem::InvalidContents),
                "{}",
                refused_headers
            );
        }
        assert_eq!(
            contents(r#"{"file":"data/y.bin"}"#).file().map(Name::as_str),
            Some("data/y.bin")
        );
        for url in ["https://example.com/x", "http://example.com/x", "https://"] {
            assert_eq!(contents(&format!(r#"{{"url":"{}"}}"#, url)).url(), Some(url));
        }
        // Either alphabet of Base64.
        for (text, data) in [("aGVsbG8=", &b"hello"[..]), ("_-8=", &[0xff, 0xef]), ("", b"")] {
            assert_eq!(
                contents(&format!(r#"{{"literal":"{}"}}"#, text)).literal(),
                Some(data),
                "{:?}",
                text
            );
        }
        // Whitespace is not Base64, wherever it is.
        for text in [
            "aGVs bG8=",
            " aGVsbG8=",
            "aGVsbG8= ",
            r"aGVs\nbG8=",
            r"aGVsbG8=\r\n",
            " ",
        ] {
            let e = refused(&format!(r#"{{"name":"x","contents":[{{"literal":"{}"}}]}}"#, text));
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::InvalidContents), Some(Field::Literal)),
                "{:?}",
                text
            );
        }
        assert_eq!(
            contents(r#"{"file":"a","encoding":"Zstd"}"#).encoding.as_deref(),
            Some("zstd")
        );
        assert_eq!(contents(r#"{"file":"a","offset":7}"#).offset, 7);
        assert_eq!(contents(r#"{"file":"a","offset":5,"originalSize":5}"#).offset, 5);
        // As many as MAX_CONTENTS, and no more.
        let many = |n: usize| {
            format!(
                r#"{{"name":"x","contents":[{}]}}"#,
                vec![r#"{"literal":"AA=="}"#; n].join(",")
            )
        };
        assert_eq!(object(&many(MAX_CONTENTS)).contents.len(), MAX_CONTENTS);
        let e = refused(&many(MAX_CONTENTS + 1));
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::InvalidContents), Some(Field::Contents))
        );
        assert_eq!(e.to_string(), "manifest object 1: more than 256 contents entries");
        // Too many is what is wrong, whatever is wrong with one of them,
        // unless something was wrong before them.
        let bad_one = many(MAX_CONTENTS + 1).replacen("AA==", "!", 1);
        assert_eq!(
            refused(&bad_one).to_string(),
            "manifest object 1: more than 256 contents entries"
        );
        let bad_after = many(MAX_CONTENTS + 1).replacen("}]}", r#"}],"size":"x"}"#, 1);
        assert_eq!(refused(&bad_after).field(), Some(Field::Contents));
        let bad_before = many(MAX_CONTENTS + 1).replacen(r#""name":"x""#, r#""size":"x","name":"x""#, 1);
        assert_eq!(refused(&bad_before).field(), Some(Field::Size));
    }

    #[test]
    fn signature_objects() {
        let signature = |record: &str| {
            let mut m = read_whole(&sequence(&[ROOT, record, TRAILER])).unwrap_or_else(|e| panic!("{}: {}", record, e));
            m.signatures.remove(0)
        };
        let s = signature(SIGNATURE);
        assert_eq!(
            (s.mechanism.as_str(), s.key, s.data.as_deref()),
            ("pkcs7", None, Some(&[0u8, 0, 0][..]))
        );
        let s = signature(concat!(
            r#"{"data":null,"key":"ABcd01","mechanism":"openpgp","other":[1,2,1e300],"#,
            r#""mediaType":"application/vnd.uapi.16.signature"}"#
        ));
        assert_eq!(
            (s.mechanism.as_str(), s.key.as_deref(), s.data),
            ("openpgp", Some(&[0xab, 0xcd, 1][..]), None)
        );
        let s = signature(r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"x","key":"","data":""}"#);
        assert_eq!((s.key.as_deref(), s.data.as_deref()), (Some(&[][..]), Some(&[][..])));
        // The key is hex digits and the data Base64, without whitespace.
        for (member, field) in [
            (r#""key":"AB cd01""#, Field::Key),
            (r#""key":"ABcd01\n""#, Field::Key),
            (r#""data":"AAAA AAAA""#, Field::Data),
            (r#""data":"AAAA\nAAAA""#, Field::Data),
        ] {
            let record = format!(
                r#"{{"mediaType":"application/vnd.uapi.16.signature","mechanism":"openpgp",{}}}"#,
                member
            );
            let e = read_whole(&sequence(&[ROOT, &record, TRAILER])).unwrap_err();
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::InvalidSignature), Some(field)),
                "{}",
                member
            );
        }
    }

    /// What an error quotes of a manifest has its control characters
    /// escaped, so that it is no control sequence on a terminal and no line
    /// of a log of its own.
    #[test]
    fn errors_escape_what_they_quote() {
        // An escape sequence that sets the title of a terminal, and the
        // control sequence introducer of C1, which a name can have.
        let (esc, csi) = (r"\u001b]0;title\u0007\n", r"\u009b2J");
        let records = [
            format!(r#"{{"name":"a{}"}}"#, esc),
            format!(r#"{{"name":"x","type":"{}"}}"#, esc),
            format!(r#"{{"name":"x","userName":"{}"}}"#, esc),
            format!(r#"{{"name":"x","gptUuid":"{}"}}"#, esc),
            format!(r#"{{"name":"x","gptLabel":"{}"}}"#, esc),
            format!(
                r#"{{"name":"x","extendedAttributes":{{"user":{{"{}":{{"text":"v"}}}}}}}}"#,
                esc
            ),
            format!(r#"{{"name":"x","extendedAttributes":{{"user":{{"a{}":5}}}}}}"#, csi),
            format!(r#"{{"name":"x","contents":[{{"file":"{}"}}]}}"#, esc),
            format!(r#"{{"name":"x","contents":[{{"url":"{}"}}]}}"#, esc),
            format!(
                r#"{{"name":"x","contents":[{{"url":"https://x","httpHeaders":{{"{}":5}}}}]}}"#,
                esc
            ),
            format!(
                r#"{{"name":"x","contents":[{{"url":"https://x","httpHeaders":{{"{}":"b"}}}}]}}"#,
                esc
            ),
            format!(r#"{{"name":"x{}","type":"fifo","size":1}}"#, csi),
        ];
        let mut errors: Vec<Error> = records.iter().map(|record| refused(record)).collect();
        let root = |field: &str| format!(r#"{{"mediaType":"application/vnd.uapi.16.manifest",{}}}"#, field);
        for root in [
            root(&format!(r#""fatSerial":"{}""#, esc)),
            root(&format!(r#""features":["{0}","{0}"]"#, esc)),
            root(&format!(r#""fsLabel":"{}""#, esc)),
        ] {
            errors.push(RecordDecoder::root(&root).unwrap_err());
        }
        let ordered = root(r#""order":"codepoint""#);
        for records in [
            [format!(r#"{{"name":"b{}"}}"#, csi), r#"{"name":"a"}"#.to_string()],
            [
                format!(r#"{{"name":"d{}","type":"dir"}}"#, csi),
                format!(r#"{{"name":"e{}/x"}}"#, csi),
            ],
        ] {
            let bytes = sequence(&[&ordered, &records[0], &records[1], TRAILER]);
            errors.push(read_whole(&bytes).unwrap_err());
        }
        for e in errors {
            let message = e.to_string();
            assert!(!message.contains(char::is_control), "{:?}", message);
            assert!(
                message.contains(r"\u{1b}") || message.contains(r"\u{9b}"),
                "{:?}",
                message
            );
        }
    }

    /// The fields of the kind of object `field` is a field of.
    fn fields_of(field: Field) -> &'static [Field] {
        match field {
            Field::Name
            | Field::MediaType
            | Field::Type
            | Field::Size
            | Field::Mode
            | Field::Uid
            | Field::Gid
            | Field::UserName
            | Field::GroupName
            | Field::Major
            | Field::Minor
            | Field::MTimeNSec
            | Field::InodeToken
            | Field::ExtendedAttributes
            | Field::GptLabel
            | Field::GptUuid
            | Field::GptTypeUuid
            | Field::GptDiskUuid
            | Field::GptFlags
            | Field::GptFlagNoAuto
            | Field::GptFlagGrowFileSystem
            | Field::ReadOnly
            | Field::FlagHidden
            | Field::FlagSystem
            | Field::FlagArchive
            | Field::FlagAppendOnly
            | Field::FlagImmutable
            | Field::FlagNoAtime
            | Field::FlagNoCow
            | Field::FlagNoDump
            | Field::FatSerial
            | Field::FsUuid
            | Field::FsLabel
            | Field::Order
            | Field::Features
            | Field::Contents
            | Field::Sha256
            | Field::ValidSinceUSec
            | Field::ValidUntilUSec
            | Field::Validity => &Field::FILE_OBJECT,
            Field::File
            | Field::Url
            | Field::Literal
            | Field::Encoding
            | Field::EncodedSize
            | Field::EncodedSha256
            | Field::OriginalSize
            | Field::OriginalSha256
            | Field::Offset
            | Field::HttpHeaders => &Field::CONTENTS,
            Field::Text | Field::Base64 => &Field::EXTENDED_ATTRIBUTE,
            Field::Mechanism | Field::Key | Field::Data => &Field::SIGNATURE,
        }
    }

    /// Every field is read by the name it is written with, the one of
    /// [`Field::as_str`], in the objects it is a field of.
    #[test]
    fn fields_are_read_by_their_names() {
        let tables = [
            &Field::FILE_OBJECT,
            &Field::CONTENTS,
            &Field::EXTENDED_ATTRIBUTE,
            &Field::SIGNATURE,
        ];
        let mut names = HashSet::new();
        for table in tables {
            for (place, &field) in table.iter().enumerate() {
                assert_eq!(table.find(field.as_str()), Some((place, field)), "{}", field);
                assert_eq!(fields_of(field), &table[..], "{}", field);
                assert!(names.insert(field.as_str()), "{}", field);
            }
            assert_eq!(table.find("xUnknown"), None);
        }
        // Data is the last of the fields.
        assert_eq!(names.len(), Field::Data as usize + 1);
    }

    /// A key twice in an object is refused right behind the second one,
    /// whether it names a field of the object or not, and however it is
    /// written.
    #[test]
    fn keys_twice() {
        let records = [
            // A field of a file object, also one written with an escape.
            (r#"{"name":"x","size":1,"size":2}"#, r#""size""#),
            (r#"{"name":"x","s\u0069ze":1,"size":2}"#, r#""size""#),
            // A key that is no field of the object, between fields.
            (r#"{"name":"x","xA":1,"size":1,"xA":2}"#, r#""xA""#),
            // The name of a field as a key of a value that is passed over.
            (r#"{"name":"x","xB":{"name":1,"name":2}}"#, r#""name""#),
            // A field of a contents object, and a key that is none.
            (r#"{"name":"x","contents":[{"file":"a","file":"b"}]}"#, r#""file""#),
            (r#"{"name":"x","contents":[{"file":"a","xC":1,"xC":2}]}"#, r#""xC""#),
            // Names: of a namespace, of an extended attribute and of an HTTP
            // header field.
            (
                r#"{"name":"x","extendedAttributes":{"user":{},"user":{}}}"#,
                r#""user""#,
            ),
            (
                r#"{"name":"x","extendedAttributes":{"user":{"a":{"text":"1"},"a":{"text":"2"}}}}"#,
                r#""a""#,
            ),
            (
                r#"{"name":"x","contents":[{"url":"https://x","httpHeaders":{"A":"1","A":"2"}}]}"#,
                r#""A""#,
            ),
            // A field of the value of an extended attribute.
            (
                r#"{"name":"x","extendedAttributes":{"user":{"a":{"text":"1","text":"2"}}}}"#,
                r#""text""#,
            ),
            // A field of a signature object.
            (
                r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"a","mechanism":"b"}"#,
                r#""mechanism""#,
            ),
            // What follows the second key is not read: whitespace, the colon
            // and the value.
            (r#"{"name":"x","size":1,"size" :[}"#, r#""size""#),
            ("{\"name\":\"x\",\"xA\":1,\"xA\"\n\t2}", r#""xA""#),
            (r#"{"name":"x","xB":{"a":1,"a" :}}"#, r#""a""#),
        ];
        let root = r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint","order":"codepoint"}"#;
        let errors = records
            .iter()
            .map(|&(record, key)| (record, key, refused(record)))
            .chain([(root, r#""order""#, RecordDecoder::root(root).unwrap_err())]);
        for (record, key, e) in errors {
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::DuplicateKey), "{}", record);
            let behind = record.rfind(key).unwrap() + key.len();
            let message = format!("has a key twice in an object: duplicate key at byte {}", behind);
            assert!(e.to_string().ends_with(&message), "{}: {}", record, e);
        }
    }

    /// A key twice in an object, and a key with a noncharacter or NUL in
    /// it, is refused right behind the key, whatever follows it: the colon
    /// and the value, a comma, or the end of the object, right away or
    /// after whitespace. That holds for the fields of an object, for a
    /// value the reader passes over, and for the names of extended
    /// attributes and of HTTP header fields.
    #[test]
    fn refuses_a_key_right_behind_it() {
        // What comes in front of the key, with a member whose key is the
        // one that comes twice, and what closes the objects around the one
        // the key is in.
        let places = [
            (r#"{"name":"x","#, r#""name""#, ""),
            (r#"{"name":"x","xA":{"b":1,"#, r#""b""#, "}"),
            (
                r#"{"name":"x","extendedAttributes":{"user":{"b":{"text":"1"},"#,
                r#""b""#,
                "}}",
            ),
            (
                r#"{"name":"x","contents":[{"url":"https://x","httpHeaders":{"B":"1","#,
                r#""B""#,
                "}}]}",
            ),
        ];
        let followers = [":1}", " :1}", r#","c":1}"#, "}", " \n }"];
        for (front, twice, behind) in places {
            let keys = [
                (twice, Problem::DuplicateKey, "duplicate key"),
                (r#""\uFDD0""#, Problem::InvalidString, "noncharacter in string"),
                (r#""a\u0000""#, Problem::InvalidString, "NUL in string"),
            ];
            for (key, problem, message) in keys {
                for follower in followers {
                    let record = format!("{}{}{}{}", front, key, follower, behind);
                    let e = refused(&record);
                    assert_eq!(e.kind(), ErrorKind::Manifest(problem), "{}", record);
                    let at = format!("{} at byte {}", message, front.len() + key.len());
                    assert!(e.to_string().ends_with(&at), "{}: {}", record, e);
                }
            }
        }
    }

    /// refused.jsonl holds manifests a reader refuses, one to a line: its
    /// records, the problem by the name [`Problem::as_str`] gives it, the
    /// number of the record and the name of the object the error is about,
    /// the field, and what the error says. The test holds the reader to all
    /// of it.
    #[test]
    fn refuses_what_the_vectors_refuse() {
        let vectors = include_str!("refused.jsonl");
        let mut problems = HashSet::new();
        for line in vectors.lines() {
            let vector: serde_json::Value = serde_json::from_str(line).unwrap();
            let [records, problem, record_number, name, field, message] = vector.as_array().unwrap().as_slice() else {
                panic!("{}", line);
            };
            let records: Vec<&str> = records
                .as_array()
                .unwrap()
                .iter()
                .map(|record| match record.as_str().unwrap() {
                    "@root" => ROOT,
                    "@trailer" => TRAILER,
                    "@signature" => SIGNATURE,
                    record => record,
                })
                .collect();
            let e = match read_whole(&sequence(&records)) {
                Ok(_) => panic!("{} was taken", line),
                Err(e) => e,
            };
            let ErrorKind::Manifest(found) = e.kind() else {
                panic!("{}: {:?}", line, e);
            };
            assert_eq!(Some(found.as_str()), problem.as_str(), "{}", line);
            assert_eq!(e.record_number(), record_number.as_u64(), "{}", line);
            assert_eq!(e.name(), name.as_str(), "{}", line);
            assert_eq!(e.field().map(Field::as_str), field.as_str(), "{}", line);
            assert_eq!(Some(e.to_string().as_str()), message.as_str(), "{}", line);
            problems.insert(found);
        }
        // Every problem a manifest can have is among them, but those of
        // bytes that are not UTF-8, that come before the first record
        // separator or that make a record too large, and the one of an
        // order a consumer requires, which error.rs's problem_names test
        // pins. A NUL byte in a record is a NUL character in the string a
        // vector gives the record in.
        let elsewhere = [
            Problem::NotUtf8,
            Problem::NoRecordSeparator,
            Problem::RecordTooLarge,
            Problem::NoOrder,
        ];
        for problem in Problem::ALL
            .iter()
            .copied()
            .filter(|problem| !elsewhere.contains(problem))
        {
            assert!(problems.contains(&problem), "{:?}", problem);
        }
    }
}
