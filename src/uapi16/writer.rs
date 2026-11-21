// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing a manifest record by record: an [`Encoder`] puts the records
//! together, and a [`Writer`] writes them out.
//!
//! [`Writer`]: crate::Writer

use std::fmt;
use std::num::NonZeroU64;

use json::{ObjectWriter, ValueWriter};

use crate::base64::Base64;
use crate::decode::{Subject, ROOT_RECORD};
use crate::digest::Digest;
use crate::error::{Error, Field, Problem};
use crate::hex::Hex;
use crate::object::{
    Contents, FileObject, FileSystemIdentity, FilledIn, FlagSet, FlagStates, GptPartition, InodeAttributes, InodeType,
    RootObject, Signature, Validity, ValidityWindow,
};
use crate::sequence::SequenceCheck;
use crate::{
    Features, Name, Order, Sha256, MAX_CONTENTS, MAX_RECORD_SIZE, MEDIA_TYPE, RECORD_END, RECORD_SEPARATOR,
    SIGNATURE_MEDIA_TYPE, STRING_RULES, TRAILER_MEDIA_TYPE, USER_NAMESPACE,
};

/// How far an encoder has got in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// File objects can follow.
    Files,
    /// A signature object was appended. File objects cannot follow.
    Signatures,
    /// The trailer object was appended. Nothing can follow.
    Done,
}

/// Puts a manifest together record by record, and does no I/O.
///
/// [`Encoder::begin`] appends the record of the root file object to a
/// string, [`Encoder::file`] the record of a file object,
/// [`Encoder::signature`] that of a signature object and
/// [`Encoder::finish`] that of the trailer object. Whoever calls them sends
/// the records on, each one as it comes or many at once. A [`Writer`] is
/// an encoder whose records go to a [`Write`] one at a time.
///
/// An encoder checks every object the way a [`Reader`](crate::Reader)
/// does, see [`Writer`], and keeps the name of the last file object for
/// that: at most [`Name::MAX_LEN`] bytes. A method that fails appends
/// nothing, and the encoder goes on as if it had not been called. Nothing
/// can follow the trailer object, so after [`Encoder::finish`] every
/// method fails.
///
/// ```
/// use uapi16::{Encoder, FileObject, Name, RootObject};
///
/// let mut text = String::new();
/// let mut encoder = Encoder::begin(&RootObject::default(), &mut text)?;
/// for name in ["a", "b"] {
///     encoder.file(&FileObject::new(Name::new(name)?), &mut text)?;
/// }
/// encoder.finish(&mut text)?;
/// assert_eq!(
///     text,
///     concat!(
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
///         "\x1e{\"name\":\"a\"}\n",
///         "\x1e{\"name\":\"b\"}\n",
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
///     )
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`Write`]: std::io::Write
/// [`Writer`]: crate::Writer
#[derive(Debug)]
pub struct Encoder {
    /// The number of the record that is appended next.
    pub(crate) next_record: u64,
    stage: Stage,
    /// The check of the file objects so far, which the next one is checked
    /// against.
    sequence_check: SequenceCheck,
}

impl Encoder {
    /// Starts a manifest with the root file object `root`: appends its
    /// record to `text`.
    pub fn begin(root: &RootObject, text: &mut String) -> Result<Encoder, Error> {
        let sequence_check = SequenceCheck::new(root.recorded_features(), root.order);
        let start = text.len();
        // In the order a reader finds what is wrong with the record, see
        // Encoder::file().
        Encoder::write_record(text, |object| root.write(object))
            .and_then(|()| root.check_strings())
            .and_then(|()| root.check())
            .and_then(|()| sequence_check.check_root_fields(root))
            .map_err(|e| {
                text.truncate(start);
                e.in_record(ROOT_RECORD)
            })?;
        Ok(Encoder {
            next_record: ROOT_RECORD + 1,
            stage: Stage::Files,
            sequence_check,
        })
    }

    /// Appends the record of the file object `file` to `text`.
    pub fn file(&mut self, file: &FileObject, text: &mut String) -> Result<(), Error> {
        let record_number = self.next_record;
        if self.stage == Stage::Done {
            return Err(Error::data_after_trailer(record_number));
        }
        // An object with more than one fault is refused for the one a
        // reader finds first in its record: a record too large before it
        // is read, then a string its JSON parser refuses or a key it sees
        // twice in an object, a file object after a signature, the values
        // of the fields in the order of their keys, a missing name, a field
        // its inode type does not permit, fields that contradict each
        // other, a field of a feature the manifest does not record, a
        // symbolic link without its target, gptFlags against the fields of
        // its flags, and where it comes. So the record is put together
        // first. Admitting the object makes it the one the next one is
        // checked against, which comes last.
        let start = text.len();
        let appended = Encoder::write_record(text, |object| file.write(object))
            .and_then(|()| file.check_strings(record_number))
            .and_then(|()| match self.stage {
                Stage::Signatures => Err(Error::file_after_signature(record_number)),
                _ => Ok(()),
            })
            .and_then(|()| file.check(record_number))
            .and_then(|()| self.sequence_check.check_fields(file, record_number))
            .and_then(|()| self.sequence_check.admit(file, record_number));
        if let Err(e) = appended {
            text.truncate(start);
            let e = e.in_record(record_number);
            return Err(if file.name.is_root() {
                e
            } else {
                e.named(file.name.as_str())
            });
        }
        self.next_record += 1;
        Ok(())
    }

    /// Appends the record of the signature object `signature` to `text`.
    /// No file object can follow it: it would be one the signature does
    /// not cover.
    pub fn signature(&mut self, signature: &Signature, text: &mut String) -> Result<(), Error> {
        let record_number = self.next_record;
        if self.stage == Stage::Done {
            return Err(Error::data_after_trailer(record_number));
        }
        let start = text.len();
        Encoder::write_record(text, |object| signature.write(object))
            .and_then(|()| {
                Field::Mechanism.check_string(
                    &signature.mechanism,
                    format_args!("manifest signature object {}", record_number),
                )
            })
            .map_err(|e| {
                text.truncate(start);
                e.in_record(record_number)
            })?;
        self.stage = Stage::Signatures;
        self.next_record += 1;
        Ok(())
    }

    /// Ends the manifest: appends the record of the trailer object to
    /// `text`.
    pub fn finish(&mut self, text: &mut String) -> Result<(), Error> {
        let record_number = self.next_record;
        if self.stage == Stage::Done {
            return Err(Error::data_after_trailer(record_number));
        }
        Encoder::write_record(text, |object| {
            FieldWriter::new(object, FilledIn::default()).string(Field::MediaType, Some(TRAILER_MEDIA_TYPE));
        })
        .map_err(|e| e.in_record(record_number))?;
        self.stage = Stage::Done;
        self.next_record += 1;
        Ok(())
    }

    /// Appends a record to `text`, the members of whose object `members`
    /// writes. A record larger than [`MAX_RECORD_SIZE`], its record
    /// separator included, is refused and taken back.
    fn write_record(text: &mut String, members: impl FnOnce(&mut ObjectWriter<'_>)) -> Result<(), Error> {
        let start = text.len();
        text.push(char::from(RECORD_SEPARATOR));
        members(&mut ObjectWriter::new(text));
        text.push(char::from(RECORD_END));
        if text.len() - start > MAX_RECORD_SIZE {
            text.truncate(start);
            return Err(Error::record_too_large());
        }
        Ok(())
    }
}

/// Writes the fields of an object of a manifest in the order they come,
/// and leaves out every field a reader filled in, whatever the field.
struct FieldWriter<'w, 'o> {
    object: &'w mut ObjectWriter<'o>,
    /// The fields a reader filled in, of the object and of the parts it
    /// has, such as its inode attributes.
    filled_in: FilledIn,
}

impl<'w, 'o> FieldWriter<'w, 'o> {
    /// Writes the fields of an object into `object`, but none of those of
    /// `filled_in`.
    fn new(object: &'w mut ObjectWriter<'o>, filled_in: FilledIn) -> FieldWriter<'w, 'o> {
        FieldWriter { object, filled_in }
    }

    /// Starts the member of the field `field`, unless a reader filled the
    /// field in.
    fn field(&mut self, field: Field) -> Option<ValueWriter<'_>> {
        (!self.filled_in.contains(field)).then(|| self.object.key(field.as_str()))
    }

    /// What is written of `value`, the value of `field`: nothing where a
    /// reader filled the field in.
    fn written<T>(&self, field: Field, value: Option<T>) -> Option<T> {
        value.filter(|_| !self.filled_in.contains(field))
    }

    /// Writes `value`, if there is one, with `write` as the field `field`.
    fn put<T>(&mut self, field: Field, value: Option<T>, write: impl FnOnce(ValueWriter<'_>, T)) {
        if let Some(value) = value {
            if let Some(member) = self.field(field) {
                write(member, value);
            }
        }
    }

    /// Writes the integer `value`, if there is one, as the field `field`.
    fn unsigned(&mut self, field: Field, value: Option<u64>) {
        self.put(field, value, |member, value| member.unsigned(value));
    }

    /// Writes the boolean `value`, if there is one, as the field `field`.
    fn bool(&mut self, field: Field, value: Option<bool>) {
        self.put(field, value, |member, value| member.bool(value));
    }

    /// Writes the string `value`, if there is one, as the field `field`.
    fn string(&mut self, field: Field, value: Option<&str>) {
        self.put(field, value, |member, value| member.string(value));
    }

    /// Writes what `value` prints, if there is a value, as the field
    /// `field`.
    fn display(&mut self, field: Field, value: Option<impl fmt::Display>) {
        self.put(field, value, |member, value| member.display(value));
    }
}

impl Field {
    /// Checks `value`, a string in this field of the object `subject`
    /// names: it has none of what the strings of a manifest may not have.
    fn check_string(self, value: &str, subject: impl fmt::Display) -> Result<(), Error> {
        if STRING_RULES.admits(value) {
            return Ok(());
        }
        Err(Error::manifest(
            Problem::InvalidString,
            format!("{}: '{}' has a NUL or a noncharacter in a string", subject, self),
        )
        .at(self))
    }
}

// The specification asks generators to leave out a field that is set to
// its default, so that file objects that describe the same file compare
// as equivalent. It recommends leaving out the hash of no data next to
// the size 0, and says that without an encoding the encoded size and
// hash should not be there. They are left out next to the original ones,
// and one that is the only statement of the size or the hash goes out.
// Where a manifest records the feature of a field,
// which it does where an object has the field, an object without it has a
// flag cleared, is not read-only, has a `gptFlags` of 0 and no extended
// attributes. So these go out only where they say more.

impl RootObject {
    /// Checks every string the record of the root file object has, in the
    /// order of the keys, for what the strings of a manifest may not hold.
    fn check_strings(&self) -> Result<(), Error> {
        let subject = Subject::root();
        self.inode.check_xattr_strings(subject)?;
        if let Some(label) = &self.file_system.label {
            Field::FsLabel.check_string(label, subject)?;
        }
        self.inode.check_owner_strings(subject)
    }

    /// Checks the root file object as a reader does: the value of every
    /// field, in the order of the keys, and the fields against each other.
    fn check(&self) -> Result<(), Error> {
        let subject = Subject::root();
        let inode = &self.inode;
        inode.check_xattr_names(subject)?;
        if let Some(label) = &self.file_system.label {
            FileSystemIdentity::check_label(label, subject)?;
        }
        if let Some(gid) = inode.gid {
            FileObject::check_id(Field::Gid, u64::from(gid), subject)?;
        }
        if let Some(name) = &inode.group_name {
            FileObject::check_owner_name(Field::GroupName, name, subject)?;
        }
        if let Some(uid) = inode.uid {
            FileObject::check_id(Field::Uid, u64::from(uid), subject)?;
        }
        if let Some(name) = &inode.user_name {
            FileObject::check_owner_name(Field::UserName, name, subject)?;
        }
        self.check_consistency()
    }

    /// Writes the fields of the root file object in the order of their
    /// names. It has the media type of a manifest, and neither a name nor a
    /// type: it is a directory.
    fn write(&self, object: &mut ObjectWriter<'_>) {
        let mut fields = FieldWriter::new(object, self.inode.filled_in);
        let inode = &self.inode;
        let identity = &self.file_system;
        inode.write_xattrs(&mut fields);
        fields.display(Field::FatSerial, identity.fat_serial);
        if let Some(listed) = self.features.filter(|listed| *listed != Features::DEFAULT) {
            if let Some(member) = fields.field(Field::Features) {
                let mut array = member.array();
                for name in listed.names() {
                    array.element().string(name);
                }
            }
        }
        for field in inode.flags.set_fields() {
            fields.bool(field, Some(true));
        }
        fields.string(Field::FsLabel, identity.label.as_deref());
        fields.display(Field::FsUuid, identity.uuid);
        fields.unsigned(Field::Gid, inode.gid.map(u64::from));
        fields.display(Field::GptDiskUuid, self.gpt_disk_uuid);
        fields.string(Field::GroupName, inode.group_name.as_deref());
        fields.unsigned(Field::MTimeNSec, inode.mtime_nsec);
        fields.string(Field::MediaType, Some(MEDIA_TYPE));
        fields.unsigned(Field::Mode, inode.mode.map(|mode| u64::from(mode.bits())));
        fields.string(Field::Order, self.order.map(Order::as_str));
        fields.bool(Field::ReadOnly, inode.read_only.filter(|&read_only| read_only));
        fields.unsigned(Field::Uid, inode.uid.map(u64::from));
        fields.string(Field::UserName, inode.user_name.as_deref());
        self.validity.write(&mut fields);
    }
}

impl FileObject {
    /// Checks every string the record of the object, the one with the
    /// number `record_number`, has, in the order of the keys, for what the
    /// strings of a manifest may not hold.
    fn check_strings(&self, record_number: u64) -> Result<(), Error> {
        let subject = Subject::new(self, record_number);
        for contents in &self.contents {
            contents.check_strings(subject)?;
        }
        self.inode.check_xattr_strings(subject)?;
        if let Some(label) = self.gpt.as_deref().and_then(|gpt| gpt.label.as_deref()) {
            Field::GptLabel.check_string(label, subject)?;
        }
        self.inode.check_owner_strings(subject)
    }

    /// Checks the object, the one of the record with the number
    /// `record_number`, as a reader does: the value of every field in the
    /// order of the keys, each contents object's fields against each other
    /// right after its values, the name, the fields its inode type permits
    /// and the fields against each other. Unlike a reader it fills nothing
    /// in.
    fn check(&self, record_number: u64) -> Result<(), Error> {
        let subject = Subject::new(self, record_number);
        if self.contents.len() > MAX_CONTENTS {
            return Err(Error::too_many_contents(subject));
        }
        for contents in &self.contents {
            contents.check(subject)?;
            contents.check_consistency(subject)?;
        }
        let inode = &self.inode;
        inode.check_xattr_names(subject)?;
        if let Some(gid) = inode.gid {
            FileObject::check_id(Field::Gid, u64::from(gid), subject)?;
        }
        if let Some(label) = self.gpt.as_deref().and_then(|gpt| gpt.label.as_deref()) {
            GptPartition::check_label(label, subject)?;
        }
        if let Some(name) = &inode.group_name {
            FileObject::check_owner_name(Field::GroupName, name, subject)?;
        }
        if let Some(uid) = inode.uid {
            FileObject::check_id(Field::Uid, u64::from(uid), subject)?;
        }
        if let Some(name) = &inode.user_name {
            FileObject::check_owner_name(Field::UserName, name, subject)?;
        }
        if self.name.is_root() {
            return Err(Error::no_name(record_number));
        }
        self.check_permitted_fields(subject)?;
        // The contents objects were checked above. This is for what
        // follows from them.
        self.check_consistency(subject, |contents| contents.check_consistency(subject))?;
        Ok(())
    }

    /// Writes the fields of the object in the order of their names.
    fn write(&self, object: &mut ObjectWriter<'_>) {
        let mut fields = FieldWriter::new(object, self.filled_in.union(self.inode.filled_in));
        let inode = &self.inode;
        let gpt = self.gpt.as_deref();
        if !self.contents.is_empty() {
            if let Some(member) = fields.field(Field::Contents) {
                let mut array = member.array();
                for contents in &self.contents {
                    contents.write(array.element());
                }
            }
        }
        inode.write_xattrs(&mut fields);
        self.write_flags(&mut fields);
        fields.unsigned(Field::Gid, inode.gid.map(u64::from));
        fields.bool(
            Field::GptFlagGrowFileSystem,
            gpt.and_then(|gpt| gpt.grow_file_system).filter(|&set| set),
        );
        fields.bool(Field::GptFlagNoAuto, gpt.and_then(|gpt| gpt.no_auto).filter(|&set| set));
        fields.unsigned(
            Field::GptFlags,
            gpt.and_then(|gpt| gpt.flags).filter(|&flags| flags != 0),
        );
        fields.string(Field::GptLabel, gpt.and_then(|gpt| gpt.label.as_deref()));
        fields.display(Field::GptTypeUuid, gpt.and_then(|gpt| gpt.type_uuid));
        fields.display(Field::GptUuid, gpt.and_then(|gpt| gpt.uuid));
        fields.string(Field::GroupName, inode.group_name.as_deref());
        fields.unsigned(Field::InodeToken, self.inode_token.map(NonZeroU64::get));
        fields.unsigned(Field::MTimeNSec, inode.mtime_nsec);
        fields.unsigned(Field::Major, self.major);
        fields.unsigned(Field::Minor, self.minor);
        fields.unsigned(Field::Mode, inode.mode.map(|mode| u64::from(mode.bits())));
        fields.string(Field::Name, (!self.name.is_root()).then_some(self.name.as_str()));
        fields.bool(Field::ReadOnly, inode.read_only.filter(|&read_only| read_only));
        let size = fields.written(Field::Size, self.size);
        let sha256 = fields.written(Field::Sha256, self.sha256.as_ref());
        fields.display(Field::Sha256, sha256.filter(|sha256| !sha256.implied_by(size)));
        fields.unsigned(Field::Size, size);
        // The specification implies the type of a regular file.
        let inode_type = Some(self.inode_type).filter(|&inode_type| inode_type != InodeType::Regular);
        fields.string(Field::Type, inode_type.map(InodeType::as_str));
        fields.unsigned(Field::Uid, inode.uid.map(u64::from));
        fields.string(Field::UserName, inode.user_name.as_deref());
        self.validity.write(&mut fields);
    }

    /// Writes the fields of the flags that are set, of the DOS attributes
    /// and of the inode flags. In the order of their names the two kinds
    /// mix, so the fields of the two, each kind in that order, are merged.
    fn write_flags(&self, fields: &mut FieldWriter<'_, '_>) {
        let mut dos = self.dos_flags.set_fields();
        let mut inode = self.inode.flags.set_fields();
        let (mut next_dos, mut next_inode) = (dos.next(), inode.next());
        loop {
            let field = match (next_dos, next_inode) {
                (Some(first), Some(second)) if second.as_str() < first.as_str() => {
                    next_inode = inode.next();
                    second
                }
                (Some(first), _) => {
                    next_dos = dos.next();
                    first
                }
                (None, Some(second)) => {
                    next_inode = inode.next();
                    second
                }
                (None, None) => break,
            };
            fields.bool(field, Some(true));
        }
    }
}

impl InodeAttributes {
    /// The names of the extended attributes, in the order they are
    /// written.
    fn xattr_names(&self) -> impl Iterator<Item = &String> {
        self.user_xattrs.iter().flat_map(|attributes| attributes.keys())
    }

    /// Checks the names of the extended attributes of the object `subject`
    /// names for what the strings of a manifest may not hold.
    fn check_xattr_strings(&self, subject: Subject<'_>) -> Result<(), Error> {
        self.xattr_names()
            .try_for_each(|name| Field::ExtendedAttributes.check_string(name, subject))
    }

    /// Checks `groupName` and `userName`, in that order, for what the
    /// strings of a manifest may not hold.
    fn check_owner_strings(&self, subject: Subject<'_>) -> Result<(), Error> {
        if let Some(name) = &self.group_name {
            Field::GroupName.check_string(name, subject)?;
        }
        if let Some(name) = &self.user_name {
            Field::UserName.check_string(name, subject)?;
        }
        Ok(())
    }

    /// Checks the names of the extended attributes as a reader does.
    fn check_xattr_names(&self, subject: Subject<'_>) -> Result<(), Error> {
        self.xattr_names()
            .try_for_each(|name| FileObject::check_xattr_name(name, subject))
    }

    /// Writes `extendedAttributes`, unless there are none. A value goes out
    /// as text if it is a string a manifest can have, and as Base64
    /// otherwise.
    fn write_xattrs(&self, fields: &mut FieldWriter<'_, '_>) {
        let Some(attributes) = self.user_xattrs.as_deref().filter(|attributes| !attributes.is_empty()) else {
            return;
        };
        let Some(member) = fields.field(Field::ExtendedAttributes) else {
            return;
        };
        let mut namespaces = member.object();
        let mut user = namespaces.key(USER_NAMESPACE).object();
        for (name, value) in attributes {
            let mut value_object = user.key(name).object();
            match std::str::from_utf8(value) {
                Ok(text) if STRING_RULES.admits(text) => value_object.key(Field::Text.as_str()).string(text),
                _ => value_object.key(Field::Base64.as_str()).display(Base64(value)),
            }
        }
    }
}

impl<F: FlagSet> FlagStates<F> {
    /// The fields of the flags that are set, in the order of their names.
    fn set_fields(self) -> impl Iterator<Item = Field> {
        F::FIELDS
            .iter()
            .filter(move |&&(flag, _, _)| self.get(flag) == Some(true))
            .map(|&(_, field, _)| field)
    }
}

impl ValidityWindow {
    /// Writes the fields of the window in the order of their names, which
    /// are the last ones of the root file object and of a file object. A
    /// `validSinceUSec` of 0 and a `validity` of good are what the
    /// specification implies.
    fn write(&self, fields: &mut FieldWriter<'_, '_>) {
        fields.unsigned(Field::ValidSinceUSec, Some(self.since_usec).filter(|&since| since != 0));
        fields.unsigned(Field::ValidUntilUSec, self.until_usec);
        let state = Some(self.state).filter(|&state| state != Validity::Good);
        fields.string(Field::Validity, state.map(Validity::as_str));
    }
}

impl Contents {
    /// Checks every string of the contents object, one of those of the
    /// file object `subject` names, in the order of the keys, for what the
    /// strings of a manifest may not hold, and its header fields for two of
    /// the same name, which a JSON parser refuses as a key given twice.
    fn check_strings(&self, subject: Subject<'_>) -> Result<(), Error> {
        if let Some(encoding) = &self.encoding {
            Field::Encoding.check_string(encoding, subject)?;
        }
        // The header fields go out in the order of their names, and a JSON
        // parser refuses a name it saw before in the same object.
        let mut previous: Option<&str> = None;
        for (name, value) in self.sorted_headers() {
            Field::HttpHeaders.check_string(name, subject)?;
            if previous == Some(name) {
                return Err(Error::manifest(
                    Problem::DuplicateKey,
                    format!(
                        "{}: HTTP header field '{}' is given twice",
                        subject,
                        name.escape_debug()
                    ),
                )
                .at(Field::HttpHeaders));
            }
            Field::HttpHeaders.check_string(value, subject)?;
            previous = Some(name);
        }
        match self.url() {
            Some(url) => Field::Url.check_string(url, subject),
            None => Ok(()),
        }
    }

    /// Checks the contents object, one of those of the file object
    /// `subject` names, as a reader does: the value of every field, in the
    /// order of the keys. [`Contents::check_consistency`] checks the fields
    /// against each other.
    fn check(&self, subject: Subject<'_>) -> Result<(), Error> {
        if let Some(encoding) = &self.encoding {
            Contents::check_encoding(encoding, subject)?;
        }
        // A reader checks the header fields in the order they are written.
        if !self.http_headers.is_empty() {
            Contents::check_headers(self.sorted_headers(), subject)?;
        }
        match self.url() {
            Some(url) => Contents::check_url(url, subject),
            None => Ok(()),
        }
    }

    /// The header fields in the order of their names, which is the order
    /// they are written in.
    fn sorted_headers(&self) -> Vec<&(String, String)> {
        let mut headers: Vec<&(String, String)> = self.http_headers.iter().collect();
        headers.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        headers
    }

    /// Writes the contents object, its fields in the order of their names.
    /// Of the sizes and hashes it leaves out what a reader filled in, the
    /// hash of no data next to the size 0, and without an encoding the
    /// encoded size and hash where the original ones say the same. A reader
    /// fills them in again.
    fn write(&self, value: ValueWriter<'_>) {
        let mut object = value.object();
        let mut fields = FieldWriter::new(&mut object, self.filled_in);
        let original_size = fields.written(Field::OriginalSize, self.original_size);
        let original_sha256 = fields
            .written(Field::OriginalSha256, self.original_sha256.as_ref())
            .filter(|sha256| !sha256.implied_by(original_size));
        let mut encoded_size = fields.written(Field::EncodedSize, self.encoded_size);
        let mut encoded_sha256 = fields
            .written(Field::EncodedSha256, self.encoded_sha256.as_ref())
            .filter(|sha256| !sha256.implied_by(encoded_size));
        if self.encoding.is_none() {
            // The data is stored as it is, so the original size and hash
            // are the encoded ones. The size 0 says the hash too.
            if original_size.is_some() {
                encoded_size = None;
            }
            if original_sha256.is_some() || original_size == Some(0) {
                encoded_sha256 = None;
            }
        }
        fields.display(Field::EncodedSha256, encoded_sha256);
        fields.unsigned(Field::EncodedSize, encoded_size);
        fields.string(Field::Encoding, self.encoding.as_deref());
        fields.string(Field::File, self.file().map(Name::as_str));
        if !self.http_headers.is_empty() {
            if let Some(member) = fields.field(Field::HttpHeaders) {
                let mut members = member.object();
                for (name, value) in self.sorted_headers() {
                    members.key(name).string(value);
                }
            }
        }
        fields.display(Field::Literal, self.literal().map(Base64));
        // The specification implies an offset of 0.
        fields.unsigned(Field::Offset, Some(self.offset).filter(|&offset| offset != 0));
        fields.display(Field::OriginalSha256, original_sha256);
        fields.unsigned(Field::OriginalSize, original_size);
        fields.string(Field::Url, self.url());
    }
}

impl Sha256 {
    /// Whether the size `size` says the hash: it is 0, and the hash is
    /// the hash of no data.
    fn implied_by(&self, size: Option<u64>) -> bool {
        size == Some(0) && *self == Sha256::EMPTY
    }
}

impl Signature {
    /// Writes the fields of the signature object in the order of their
    /// names.
    fn write(&self, object: &mut ObjectWriter<'_>) {
        let mut fields = FieldWriter::new(object, FilledIn::default());
        fields.display(Field::Data, self.data.as_deref().map(Base64));
        fields.display(Field::Key, self.key.as_deref().map(Hex));
        fields.string(Field::Mechanism, Some(&self.mechanism));
        fields.string(Field::MediaType, Some(SIGNATURE_MEDIA_TYPE));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::object::{DosFlags, FatSerial, InodeFlags, Location, Mode, Uuid};
    use crate::testing::{
        directory, everything, name, read_whole, record, recording_all, sequence, write_whole, written, Whole, EMPTY,
        HELLO, ROOT, SIGNATURE, TRAILER,
    };
    use crate::{Sha256, Writer};
    use std::collections::BTreeMap;

    /// What `systemd-manifest` writes, see the manifests in tests/fixtures:
    /// the same objects give the same records.
    #[test]
    fn writes_records_the_way_systemd_does() {
        // What systemd-manifest writes with --field=default,+mtime, with
        // the features and the order the specification has since: compact,
        // keys sorted, numbers in decimal. A manifest that records extended
        // attributes needs no empty namespace for a file that has none.
        let mut root = RootObject {
            features: Some(
                Features::from_names([
                    "device",
                    "gid",
                    "hardlink",
                    "mode",
                    "mtime",
                    "sha256",
                    "size",
                    "symlink",
                    "uid",
                    "user-xattr",
                ])
                .unwrap(),
            ),
            order: Some(Order::CodePoint),
            ..RootObject::default()
        };
        root.inode.user_xattrs = Some(Box::default());
        root.inode.gid = Some(1000);
        root.inode.mtime_nsec = Some(1_699_999_000_000_000_000);
        root.inode.mode = Mode::new(0o775);
        root.inode.uid = Some(1000);
        let owned_directory = |name_of: &str| {
            let mut owned = directory(name_of);
            owned.inode.user_xattrs = Some(Box::default());
            owned.inode.gid = Some(1000);
            owned.inode.mtime_nsec = Some(1_699_999_000_000_000_000);
            owned.inode.mode = Mode::new(0o775);
            owned.inode.uid = Some(1000);
            owned
        };
        let mut file = FileObject::new(name("EFI/BOOT/BOOTX64.EFI"));
        file.inode.user_xattrs = Some(Box::default());
        file.inode.gid = Some(1000);
        file.inode.mtime_nsec = Some(1_700_000_000_000_000_000);
        file.inode.mode = Mode::new(0o664);
        file.sha256 = "608047e995ccddf55441b8ed783ac49c780b9a911aa655f47d3a4c174748f86b"
            .parse()
            .ok();
        file.size = Some(4096);
        file.inode.uid = Some(1000);
        let records = written(&root, |writer| {
            writer.file(&owned_directory("EFI")).unwrap();
            writer.file(&owned_directory("EFI/BOOT")).unwrap();
            writer.file(&file).unwrap();
        });
        assert_eq!(
            records,
            [
                concat!(
                    r#"{"features":["device","gid","hardlink","mode","mtime","sha256","size","symlink","uid","#,
                    r#""user-xattr"],"gid":1000,"mTimeNSec":1699999000000000000,"#,
                    r#""mediaType":"application/vnd.uapi.16.manifest","mode":509,"order":"codepoint","uid":1000}"#
                ),
                r#"{"gid":1000,"mTimeNSec":1699999000000000000,"mode":509,"name":"EFI","type":"dir","uid":1000}"#,
                concat!(
                    r#"{"gid":1000,"mTimeNSec":1699999000000000000,"mode":509,"name":"EFI/BOOT","type":"dir","#,
                    r#""uid":1000}"#
                ),
                concat!(
                    r#"{"gid":1000,"mTimeNSec":1700000000000000000,"#,
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
        link.inode.gid = Some(1000);
        link.inode.group_name = Some("brauner".into());
        link.size = Some(5);
        link.inode.user_name = Some("brauner".into());
        assert_eq!(
            record(&link),
            concat!(
                r#"{"contents":[{"literal":"YS50eHQ="}],"gid":1000,"groupName":"brauner","name":"link","#,
                r#""size":5,"type":"lnk","userName":"brauner"}"#
            )
        );
        let mut noted = FileObject::new(name("a.txt"));
        noted.inode.user_xattrs = Some(Box::new(BTreeMap::from([(
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
        let empty = Writer::begin(Vec::new(), &RootObject::default())
            .unwrap()
            .finish()
            .unwrap();
        assert_eq!(empty, sequence(&[ROOT, TRAILER]));
    }

    /// Where a manifest records the feature of a field, an object without
    /// the field says what the field's default is. The writer leaves those
    /// fields out, and a reader reads back what they said.
    #[test]
    fn leaves_out_what_the_features_imply() {
        let mut object = FileObject::new(name("x"));
        object.dos_flags.put(DosFlags::HIDDEN, Some(false));
        object.inode.flags.put(InodeFlags::NO_DUMP, Some(false));
        object.inode.read_only = Some(false);
        object.inode.user_xattrs = Some(Box::default());
        object.gpt = Some(Box::new(GptPartition {
            flags: Some(0),
            no_auto: Some(false),
            grow_file_system: Some(false),
            ..GptPartition::default()
        }));
        assert_eq!(record(&object), r#"{"name":"x"}"#);
        let (root, _) = recording_all();
        let whole = Whole {
            root,
            objects: vec![object.clone()],
            signatures: Vec::new(),
        };
        let read = read_whole(&write_whole(&whole).unwrap()).unwrap().objects.remove(0);
        assert_eq!(read.dos_flags.get(DosFlags::HIDDEN), Some(false));
        assert_eq!(read.inode.flags.get(InodeFlags::NO_DUMP), Some(false));
        assert_eq!(read.inode.read_only, Some(false));
        assert_eq!(read.inode.user_xattrs.as_deref(), Some(&BTreeMap::new()));
        // A reader leaves the fields of a partition as they are: a regular
        // file without any is no partition, whose flags the manifest says
        // are cleared.
        assert_eq!(read.gpt, None);
        // What a manifest does not record, an object cannot have, whatever
        // it says.
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        let e = writer.file(&object).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::UnlistedFeature));
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
        let (mut root, _) = recording_all();
        root.order = Some(Order::CodePoint);
        root.gpt_disk_uuid = Some(Uuid::new([0xab; Uuid::SIZE]));
        root.file_system = FileSystemIdentity {
            uuid: Some(Uuid::new([0xcd; Uuid::SIZE])),
            label: Some("ESP".into()),
            fat_serial: Some(FatSerial(0x1234_abcd)),
        };
        root.inode.mtime_nsec = Some(0);
        let mut signature = Signature::new("pkcs7");
        signature.key = Some(vec![0xde, 0xad]);
        signature.data = Some(vec![1, 2, 3, 4]);
        let objects = [directory("a"), object.clone(), directory("dev"), device.clone()];
        let records = written(&root, |writer| {
            for object in &objects {
                writer.file(object).unwrap();
            }
            writer.signature(&signature).unwrap();
            writer.signature(&Signature::new("openpgp")).unwrap();
        });
        // No whitespace but the one in the name and in a header, and every
        // key in its place.
        for record in &records {
            assert!(
                !record
                    .replace("a/\u{e9} \\\"quoted", "")
                    .replace("Bearer x", "")
                    .contains(char::is_whitespace),
                "{}",
                record
            );
            sorted(&json::parse(record).unwrap());
        }
        let whole = json::parse(&records[2]).unwrap();
        let keys: Vec<&str> = whole.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "contents",
                "extendedAttributes",
                "flagAppendOnly",
                "flagHidden",
                "flagImmutable",
                "flagSystem",
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
        // A flag that is set goes out as true. One that is cleared needs
        // no field in a manifest that records it.
        assert_eq!(whole.get("flagHidden"), Some(&json::Value::Bool(true)));
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
        assert_eq!(
            contents[1].to_string(),
            r#"{"httpHeaders":{"Authorization":"Bearer x","X-Foo":"bar"},"url":"https://example.com/blob"}"#
        );
        assert_eq!(contents[2].to_string(), r#"{"literal":"aGVsbG8="}"#);
        assert_eq!(contents[3].to_string(), "{}");
        let (_, recording) = recording_all();
        let listed = recording
            .split_once(r#","mediaType""#)
            .unwrap()
            .0
            .trim_start_matches('{');
        assert_eq!(
            records[0],
            format!(
                concat!(
                    r#"{{"fatSerial":"1234-ABCD",{},"fsLabel":"ESP","fsUUID":"cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd","#,
                    r#""gptDiskUuid":"abababab-abab-abab-abab-abababababab","mTimeNSec":0,"#,
                    r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}}"#
                ),
                listed
            )
        );
        assert_eq!(records[4], r#"{"major":1,"minor":3,"name":"dev/null","type":"chr"}"#);
        assert_eq!(
            records[5],
            r#"{"data":"AQIDBA==","key":"dead","mechanism":"pkcs7","mediaType":"application/vnd.uapi.16.signature"}"#
        );
        assert_eq!(
            records[6],
            r#"{"mechanism":"openpgp","mediaType":"application/vnd.uapi.16.signature"}"#
        );
        // A value that is a string of a manifest goes out as text, any
        // other as Base64: a NUL or a noncharacter makes it binary.
        assert!(records[2].contains(concat!(
            r#""extendedAttributes":{"user":{"binary":{"base64":"/wA="},"empty":{"text":""},"#,
            r#""noncharacter":{"base64":"Ye+/vg=="},"nul":{"base64":"YQBi"},"text":{"text":"value"}}}"#
        )));
        // What was written reads back as what was there, with what the
        // features of the manifest say about the fields that are not.
        let text: Vec<&str> = records.iter().map(String::as_str).collect();
        let m = read_whole(&sequence(&text)).unwrap();
        let mut expected_root = root.clone();
        expected_root.fill_in(Features::ALL);
        assert_eq!(m.root, expected_root);
        let mut expected: Vec<FileObject> = objects.to_vec();
        // The reader fills in what follows from a literal: how long it is.
        // The header fields went out in the order of their names.
        let literal = &mut expected[1].contents[2];
        (literal.encoded_size, literal.original_size) = (Some(5), Some(5));
        literal.filled_in.insert(Field::EncodedSize);
        literal.filled_in.insert(Field::OriginalSize);
        expected[1].contents[1].http_headers.sort();
        for object in &mut expected {
            object.fill_in(Features::ALL);
        }
        assert_eq!(m.objects, expected);
        assert_eq!(m.signatures, [signature, Signature::new("openpgp")]);
        assert_eq!(read_whole(&write_whole(&m).unwrap()).unwrap(), m);
    }

    #[test]
    fn the_order_of_the_objects() {
        let kind = |e: Error| match e.kind() {
            ErrorKind::Manifest(problem) => (problem, e.record_number(), e.field()),
            other => panic!("{:?}", other),
        };
        // An object has no flag its inode type does not have: the reader
        // says the same.
        let mut link = FileObject::new(name("l"));
        link.inode_type = InodeType::Symlink;
        link.inode.flags.put(InodeFlags::NO_DUMP, Some(false));
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        let e = writer.file(&link).unwrap_err();
        assert_eq!(
            e.to_string(),
            "manifest object 1 (l): 'flagNoDump' is not permitted on a lnk"
        );
        assert_eq!(kind(e), (Problem::FieldNotPermitted, Some(1), Some(Field::FlagNoDump)));
        // Every other file object has a name, and comes before the
        // signatures.
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        let e = writer.file(&FileObject::new(Name::ROOT)).unwrap_err();
        assert_eq!(kind(e), (Problem::NoName, Some(1), Some(Field::Name)));
        writer.file(&FileObject::new(name("a"))).unwrap();
        writer.signature(&Signature::new("pkcs7")).unwrap();
        let e = writer.file(&FileObject::new(name("b"))).unwrap_err();
        assert_eq!(kind(e), (Problem::FileAfterSignature, Some(3), None));
        // As for a reader, that comes before a missing name.
        let e = writer.file(&FileObject::new(Name::ROOT)).unwrap_err();
        assert_eq!(kind(e), (Problem::FileAfterSignature, Some(3), None));
        writer.signature(&Signature::new("openpgp")).unwrap();
        let bytes = writer.finish().unwrap();
        let m = read_whole(&bytes).unwrap();
        assert_eq!((m.objects.len(), m.signatures.len()), (1, 2));
        // An object comes right after the object of its directory and in
        // the order the manifest declares. One that does not is not
        // written, and the next one is checked against the one before it.
        let root = RootObject {
            order: Some(Order::CodePoint),
            ..RootObject::default()
        };
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        writer.file(&FileObject::new(name("b"))).unwrap();
        let e = writer.file(&FileObject::new(name("a"))).unwrap_err();
        assert_eq!(kind(e), (Problem::OutOfOrder, Some(2), None));
        let e = writer.file(&FileObject::new(name("c/d"))).unwrap_err();
        assert_eq!(kind(e), (Problem::Misplaced, Some(2), None));
        writer.file(&directory("c")).unwrap();
        writer.file(&FileObject::new(name("c/d"))).unwrap();
        let m = read_whole(&writer.finish().unwrap()).unwrap();
        let names: Vec<&str> = m.objects.iter().map(|object| object.name.as_str()).collect();
        assert_eq!(names, ["b", "c", "c/d"]);
        // What a writer leaves that did not finish is no manifest.
        let mut unfinished = Vec::new();
        let mut writer = Writer::begin(&mut unfinished, &RootObject::default()).unwrap();
        writer.file(&FileObject::new(name("a"))).unwrap();
        drop(writer);
        let e = read_whole(&unfinished).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoTrailer));
    }

    /// What is wrong with the root file object is wrong with record 0, as
    /// a reader has it. A root file object has neither a name nor another
    /// type than a directory, so neither can be wrong.
    #[test]
    fn errors_of_the_root_file_object() {
        let refused = |root: &RootObject| {
            let e = Writer::begin(Vec::new(), root).unwrap_err();
            let ErrorKind::Manifest(problem) = e.kind() else {
                panic!("{}", e);
            };
            (problem, e.record_number(), e.field(), e.to_string())
        };
        let mut root = RootObject::default();
        root.inode.uid = Some(u32::MAX);
        assert_eq!(
            refused(&root),
            (
                Problem::FieldOutOfRange,
                Some(0),
                Some(Field::Uid),
                "manifest object 0 (root): uid 4294967295 is out of range".to_string()
            )
        );
        // The fields of the features the specification has had the
        // longest and of those it has had the shortest.
        let mut root = RootObject::default();
        root.inode.mtime_nsec = Some(1);
        assert_eq!(refused(&root).0, Problem::UnlistedFeature);
        let mut root = RootObject::default();
        root.file_system.fat_serial = Some(FatSerial(0x1234_abcd));
        assert_eq!(
            refused(&root),
            (
                Problem::UnlistedFeature,
                Some(0),
                Some(Field::FatSerial),
                concat!(
                    "manifest object 0 (root): 'fatSerial' is a field of the feature 'fat-serial', ",
                    "which the manifest does not record"
                )
                .to_string()
            )
        );
        // readOnly against mode.
        let mut root = RootObject {
            features: Some(Features::DEFAULT | Features::READ_ONLY),
            ..RootObject::default()
        };
        root.inode.read_only = Some(true);
        root.inode.mode = Mode::new(0o755);
        assert_eq!(
            refused(&root),
            (
                Problem::Contradiction,
                Some(0),
                Some(Field::ReadOnly),
                "manifest object 0 (root): 'readOnly' and 'mode' contradict each other".to_string()
            )
        );
    }

    /// What a reader returned goes out as it came in, also where the
    /// reader filled in a field of a feature the manifest does not record.
    #[test]
    fn writes_what_it_read() {
        let hello = format!(r#""originalSha256":"{}""#, HELLO);
        for (features, record) in [
            // The size 0 follows from the hash of no data, and the other way
            // around.
            ("sha256", format!(r#"{{"name":"x","sha256":"{}"}}"#, EMPTY)),
            ("size", r#"{"name":"x","size":0}"#.to_string()),
            // The size of a symbolic link is the length of its target, and
            // so are the sizes of its contents object.
            (
                "symlink",
                r#"{"contents":[{"literal":"YS50eHQ="}],"name":"l","type":"lnk"}"#.to_string(),
            ),
            // The size of a part follows from the size of the data, and the
            // encoded data is the data without an encoding.
            (
                "",
                r#"{"contents":[{"file":"a","offset":2,"originalSize":7}],"name":"x"}"#.to_string(),
            ),
            (
                "",
                r#"{"contents":[{"encodedSize":5,"file":"a"}],"name":"x"}"#.to_string(),
            ),
            // The hash of all of the data is the hash of the object.
            (
                "size",
                format!(
                    r#"{{"contents":[{{"file":"a",{},"originalSize":5}}],"name":"x","size":5}}"#,
                    hello
                ),
            ),
            // What a manifest says without the fields of the features it
            // records.
            (
                r#"flag-hidden","flag-immutable","read-only","user-xattr"#,
                r#"{"name":"x"}"#.to_string(),
            ),
        ] {
            let root = format!(
                r#"{{"features":[{}],"mediaType":"application/vnd.uapi.16.manifest"}}"#,
                Some(features)
                    .filter(|name| !name.is_empty())
                    .map(|name| format!("\"{}\"", name))
                    .unwrap_or_default()
            );
            let bytes = sequence(&[&root, &record, TRAILER]);
            let m = read_whole(&bytes).unwrap();
            assert_eq!(
                String::from_utf8(write_whole(&m).unwrap()).unwrap(),
                String::from_utf8(bytes).unwrap()
            );
        }
        // The root file object too.
        let root = concat!(
            r#"{"features":["flag-immutable","mode","read-only","user-xattr"],"#,
            r#""mediaType":"application/vnd.uapi.16.manifest","mode":365}"#
        );
        let bytes = sequence(&[root, TRAILER]);
        let m = read_whole(&bytes).unwrap();
        assert_eq!(m.root.inode.read_only, Some(false));
        assert_eq!(write_whole(&m).unwrap(), bytes);
    }

    /// A readOnly a reader filled in is left out like every field a reader
    /// fills in, also next to a mode that nobody may write. One the
    /// manifest gives would contradict that mode, for the reader and for
    /// the writer.
    #[test]
    fn writes_back_a_read_only_a_reader_filled_in() {
        let root = r#"{"features":["mode","read-only"],"mediaType":"application/vnd.uapi.16.manifest","mode":365}"#;
        let bytes = sequence(&[root, r#"{"mode":292,"name":"x"}"#, TRAILER]);
        let m = read_whole(&bytes).unwrap();
        for inode in [&m.root.inode, &m.objects[0].inode] {
            assert_eq!(inode.read_only, Some(false));
            assert!(inode.filled_in.contains(Field::ReadOnly));
        }
        assert_eq!(write_whole(&m).unwrap(), bytes);
        // Given, it is refused.
        let contradiction = |e: Error| (e.kind(), e.field(), e.record_number(), e.to_string());
        let given = sequence(&[root, r#"{"mode":292,"name":"x","readOnly":false}"#, TRAILER]);
        let expected = (
            ErrorKind::Manifest(Problem::Contradiction),
            Some(Field::ReadOnly),
            Some(1),
            "manifest object 1 (x): 'readOnly' and 'mode' contradict each other".to_string(),
        );
        assert_eq!(contradiction(read_whole(&given).unwrap_err()), expected);
        let mut object = m.objects[0].clone();
        object.inode.filled_in.remove(Field::ReadOnly);
        let mut writer = Writer::begin(Vec::new(), &m.root).unwrap();
        assert_eq!(contradiction(writer.file(&object).unwrap_err()), expected);
        // The root file object too.
        let given = concat!(
            r#"{"features":["mode","read-only"],"mediaType":"application/vnd.uapi.16.manifest","mode":365,"#,
            r#""readOnly":false}"#
        );
        let expected = (
            ErrorKind::Manifest(Problem::Contradiction),
            Some(Field::ReadOnly),
            Some(0),
            "manifest object 0 (root): 'readOnly' and 'mode' contradict each other".to_string(),
        );
        assert_eq!(
            contradiction(read_whole(&sequence(&[given, TRAILER])).unwrap_err()),
            expected
        );
        let mut root = m.root.clone();
        root.inode.filled_in.remove(Field::ReadOnly);
        assert_eq!(contradiction(Writer::begin(Vec::new(), &root).unwrap_err()), expected);
    }

    /// The writer leaves out what the specification recommends to leave
    /// out where it says nothing more, and a reader fills it in again.
    #[test]
    fn leaves_out_what_the_specification_recommends() {
        let empty: Sha256 = EMPTY.parse().unwrap();
        // The hash of no data next to the size 0.
        let mut object = FileObject::new(name("x"));
        (object.size, object.sha256) = (Some(0), Some(empty));
        // With an encoding, that of the encoded and of the original data.
        let mut encoded = Contents::new(Location::File(name("x.gz")));
        encoded.encoding = Some("gzip".into());
        (encoded.encoded_size, encoded.encoded_sha256) = (Some(0), Some(empty));
        (encoded.original_size, encoded.original_sha256) = (Some(0), Some(empty));
        // Without an encoding, the encoded size and hash next to the
        // original ones, which say the same.
        let mut plain = Contents::new(Location::File(name("x")));
        (plain.encoded_size, plain.encoded_sha256) = (Some(0), Some(empty));
        (plain.original_size, plain.original_sha256) = (Some(0), Some(empty));
        object.contents = vec![encoded, plain];
        let written = record(&object);
        assert_eq!(
            written,
            concat!(
                r#"{"contents":[{"encodedSize":0,"encoding":"gzip","file":"x.gz","originalSize":0},"#,
                r#"{"file":"x","originalSize":0}],"name":"x","size":0}"#
            )
        );
        let (_, root) = recording_all();
        let m = read_whole(&sequence(&[&root, &written, TRAILER])).unwrap();
        let read = &m.objects[0];
        assert_eq!((read.size, read.sha256), (Some(0), Some(empty)));
        for contents in &read.contents {
            let data = (contents.encoded_size, contents.encoded_sha256);
            assert_eq!(data, (Some(0), Some(empty)));
            let data = (contents.original_size, contents.original_sha256);
            assert_eq!(data, (Some(0), Some(empty)));
        }
        // Where only the encoded size says it, it stays.
        let mut only = FileObject::new(name("y"));
        only.contents = vec![Contents {
            encoded_size: Some(5),
            ..Contents::new(Location::File(name("y")))
        }];
        assert_eq!(
            record(&only),
            r#"{"contents":[{"encodedSize":5,"file":"y"}],"name":"y"}"#
        );
    }

    /// What a reader read in another form than the one the writer writes
    /// can grow on the way back. A record close to MAX_RECORD_SIZE grows
    /// past it then, and the writer refuses it.
    #[test]
    fn a_record_that_grows_past_the_limit() {
        let root = r#"{"features":["gpt-uuid","user-xattr"],"mediaType":"application/vnd.uapi.16.manifest"}"#;
        // A UUID without its hyphens, which the writer writes with them.
        let uuid = "11".repeat(Uuid::SIZE);
        let record = |pad: usize| {
            format!(
                r#"{{"extendedAttributes":{{"user":{{"p":{{"text":"{}"}}}}}},"gptUuid":"{}","name":"a"}}"#,
                "p".repeat(pad),
                uuid
            )
        };
        let frame = sequence(&[&record(0)]).len();
        let largest = record(MAX_RECORD_SIZE - frame);
        assert_eq!(sequence(&[&largest]).len(), MAX_RECORD_SIZE);
        let m = read_whole(&sequence(&[root, &largest, TRAILER])).unwrap();
        let e = write_whole(&m).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number(), e.name()),
            (ErrorKind::Manifest(Problem::RecordTooLarge), Some(1), Some("a"))
        );
    }

    /// An object with two faults is refused for the one a reader finds
    /// first in its record, by a reader and by the writer. The one fault
    /// they do not share is an encoding that is not in lower case, which a
    /// reader lowers the case of and the writer refuses.
    #[test]
    fn the_first_of_two_faults() {
        /// Gives an object fields.
        type Give = fn(&mut FileObject);
        /// A character that no string of a manifest may hold.
        fn noncharacter() -> char {
            char::from_u32(0xfdd0).unwrap()
        }
        let root = RootObject {
            features: Some(Features::DEFAULT | Features::READ_ONLY | Features::USER_NAME | Features::FS_LABEL),
            ..RootObject::default()
        };
        let root_text = concat!(
            r#"{"features":["device","fs-label","gid","hardlink","mode","read-only","sha256","size","symlink","#,
            r#""uid","user-name"],"mediaType":"application/vnd.uapi.16.manifest"}"#
        );
        let cases: Vec<(String, Give, Problem)> = vec![
            // A record too large, before a string the JSON parser refuses.
            (
                format!(
                    r#"{{"contents":[{{"literal":"{}"}}],"name":"x","userName":"u{}"}}"#,
                    "AAAA".repeat(MAX_RECORD_SIZE / 4),
                    noncharacter()
                ),
                |o| {
                    o.contents = vec![Contents::new(Location::Literal(vec![0; MAX_RECORD_SIZE / 4 * 3]))];
                    o.inode.user_name = Some(format!("u{}", noncharacter()).into());
                },
                Problem::RecordTooLarge,
            ),
            // A string the JSON parser refuses, before any value.
            (
                "{\"name\":\"x\",\"uid\":65535,\"userName\":\"u\u{fdd0}\"}".into(),
                |o| (o.inode.uid, o.inode.user_name) = (Some(65535), Some("u\u{fdd0}".into())),
                Problem::InvalidString,
            ),
            // A key the JSON parser finds twice in an object, header fields
            // of the same name, before any value.
            (
                r#"{"contents":[{"httpHeaders":{"A":"b","A":"c"},"url":"https://example.com/x"}],"name":"x","uid":65535}"#
                    .into(),
                |o| {
                    o.contents = vec![Contents {
                        http_headers: vec![("A".into(), "b".into()), ("A".into(), "c".into())],
                        ..Contents::new(Location::Url("https://example.com/x".into()))
                    }];
                    o.inode.uid = Some(65535);
                },
                Problem::DuplicateKey,
            ),
            // Too many contents objects, before what is wrong with one of
            // them.
            (
                format!(
                    r#"{{"contents":[{{"literal":"YQ==","originalSize":5}}{}],"name":"x"}}"#,
                    r#",{"literal":"YQ=="}"#.repeat(MAX_CONTENTS)
                ),
                |o| {
                    o.contents = (0..=MAX_CONTENTS)
                        .map(|_| Contents::new(Location::Literal(b"a".to_vec())))
                        .collect();
                    o.contents[0].original_size = Some(5);
                },
                Problem::InvalidContents,
            ),
            // The fields of a contents object against each other, before
            // the value of a field behind it.
            (
                r#"{"contents":[{"file":"a","httpHeaders":{"A":"b"}}],"name":"x","uid":65535}"#.into(),
                |o| {
                    o.contents = vec![Contents {
                        http_headers: vec![("A".into(), "b".into())],
                        ..Contents::new(Location::File(name("a")))
                    }];
                    o.inode.uid = Some(65535);
                },
                Problem::InvalidContents,
            ),
            // A value, before a missing name.
            (
                r#"{"uid":65535}"#.into(),
                |o| (o.name, o.inode.uid) = (Name::ROOT, Some(65535)),
                Problem::FieldOutOfRange,
            ),
            // A value, before a field the inode type does not permit.
            (
                r#"{"name":"x","size":1,"type":"fifo","uid":65535}"#.into(),
                |o| (o.inode_type, o.size, o.inode.uid) = (InodeType::Fifo, Some(1), Some(65535)),
                Problem::FieldOutOfRange,
            ),
            // A field the inode type does not permit, before fields that
            // contradict each other.
            (
                r#"{"mode":420,"name":"x","readOnly":true,"size":1,"type":"fifo"}"#.into(),
                |o| {
                    (o.inode_type, o.size) = (InodeType::Fifo, Some(1));
                    (o.inode.mode, o.inode.read_only) = (Mode::new(0o644), Some(true));
                },
                Problem::FieldNotPermitted,
            ),
            // Fields that contradict each other, before a field of a
            // feature the manifest does not record.
            (
                r#"{"mTimeNSec":1,"mode":420,"name":"x","readOnly":true}"#.into(),
                |o| (o.inode.mtime_nsec, o.inode.mode, o.inode.read_only) = (Some(1), Mode::new(0o644), Some(true)),
                Problem::Contradiction,
            ),
            // A value, before a field of a feature the manifest does not
            // record.
            (
                r#"{"mTimeNSec":1,"name":"x","uid":65535}"#.into(),
                |o| (o.inode.mtime_nsec, o.inode.uid) = (Some(1), Some(65535)),
                Problem::FieldOutOfRange,
            ),
        ];
        for (record, give, problem) in cases {
            let label: String = record.chars().take(100).collect();
            let e = read_whole(&sequence(&[root_text, &record, TRAILER])).unwrap_err();
            assert_eq!(
                (e.kind(), e.record_number()),
                (ErrorKind::Manifest(problem), Some(1)),
                "{}",
                label
            );
            let mut object = FileObject::new(name("x"));
            give(&mut object);
            let mut writer = Writer::begin(Vec::new(), &root).unwrap();
            let w = writer.file(&object).unwrap_err();
            assert_eq!(
                (w.kind(), w.record_number()),
                (e.kind(), e.record_number()),
                "{}",
                label
            );
        }
        // A string the JSON parser refuses, before a file object after a
        // signature object.
        let record = format!(r#"{{"name":"x","userName":"u{}"}}"#, noncharacter());
        let e = read_whole(&sequence(&[root_text, SIGNATURE, &record, TRAILER])).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number()),
            (ErrorKind::Manifest(Problem::InvalidString), Some(2))
        );
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        writer.signature(&Signature::new("pkcs7")).unwrap();
        let mut object = FileObject::new(name("x"));
        object.inode.user_name = Some(format!("u{}", noncharacter()).into());
        let w = writer.file(&object).unwrap_err();
        assert_eq!((w.kind(), w.record_number()), (e.kind(), e.record_number()));
        // A file object after a signature object, before a missing name.
        let e = read_whole(&sequence(&[root_text, SIGNATURE, r#"{"uid":65535}"#, TRAILER])).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::FileAfterSignature));
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        writer.signature(&Signature::new("pkcs7")).unwrap();
        let mut nameless = FileObject::new(Name::ROOT);
        nameless.inode.uid = Some(65535);
        let w = writer.file(&nameless).unwrap_err();
        assert_eq!((w.kind(), w.record_number()), (e.kind(), e.record_number()));
        // The root file object: the label of the file system comes before
        // the user ID.
        let given = concat!(
            r#"{"features":["fs-label"],"fsLabel":"a\tb","mediaType":"application/vnd.uapi.16.manifest","#,
            r#""uid":65535}"#
        );
        let e = read_whole(&sequence(&[given, TRAILER])).unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::WrongFieldType), Some(Field::FsLabel))
        );
        let mut root = RootObject {
            features: Some(Features::FS_LABEL),
            ..RootObject::default()
        };
        root.file_system.label = Some("a\tb".into());
        root.inode.uid = Some(65535);
        let w = Writer::begin(Vec::new(), &root).unwrap_err();
        assert_eq!(
            (w.kind(), w.field(), w.record_number()),
            (e.kind(), e.field(), e.record_number())
        );
    }

    /// What the writer writes has values the reader takes: a string has
    /// no NUL and no noncharacter, and the value of a field keeps to its
    /// rules.
    #[test]
    fn checks_what_it_writes() {
        /// Gives an object a value.
        type Give = fn(&mut FileObject);
        /// Contents at a URL, with the header fields `headers`.
        fn headers(headers: &[(&str, &str)]) -> Contents {
            Contents {
                http_headers: headers
                    .iter()
                    .map(|&(name, value)| (name.into(), value.into()))
                    .collect(),
                ..Contents::new(Location::Url("https://example.com/x".into()))
            }
        }
        /// Contents in the encoding `encoding`.
        fn encoded(encoding: &str) -> Contents {
            Contents {
                encoding: Some(encoding.into()),
                ..Contents::new(Location::File(name("x.gz")))
            }
        }
        /// Gives `object` the extended attribute `name`, without a value.
        fn xattr(object: &mut FileObject, name: &str) {
            object.inode.user_xattrs = Some(Box::new(BTreeMap::from([(name.to_string(), Vec::new())])));
        }
        /// The partition label `label`.
        fn gpt(label: &str) -> Option<Box<GptPartition>> {
            Some(Box::new(GptPartition {
                label: Some(label.into()),
                ..GptPartition::default()
            }))
        }
        let cases: [(Give, Problem, Field); 19] = [
            (|o| o.inode.uid = Some(u32::MAX), Problem::FieldOutOfRange, Field::Uid),
            (|o| o.inode.gid = Some(u32::MAX), Problem::FieldOutOfRange, Field::Gid),
            // -1 as a 16-bit ID is no ID either.
            (|o| o.inode.uid = Some(65535), Problem::FieldOutOfRange, Field::Uid),
            (|o| o.inode.gid = Some(65535), Problem::FieldOutOfRange, Field::Gid),
            (
                |o| o.inode.user_name = Some("u\u{fdd0}".into()),
                Problem::InvalidString,
                Field::UserName,
            ),
            (
                |o| o.inode.user_name = Some("u\0".into()),
                Problem::InvalidString,
                Field::UserName,
            ),
            (
                |o| o.inode.group_name = Some("a:b".into()),
                Problem::WrongFieldType,
                Field::GroupName,
            ),
            (|o| xattr(o, "a\0b"), Problem::InvalidString, Field::ExtendedAttributes),
            (
                |o| xattr(o, ""),
                Problem::InvalidExtendedAttributes,
                Field::ExtendedAttributes,
            ),
            (|o| o.gpt = gpt("x\0"), Problem::InvalidString, Field::GptLabel),
            (|o| o.gpt = gpt("a\tb"), Problem::WrongFieldType, Field::GptLabel),
            (
                |o| o.contents = vec![Contents::new(Location::Url("ftp://example.com/x".into()))],
                Problem::InvalidContents,
                Field::Url,
            ),
            (
                |o| o.contents = vec![encoded("Identity")],
                Problem::InvalidContents,
                Field::Encoding,
            ),
            // A reader lowers the case of an encoding, a manifest has it in
            // lower case.
            (
                |o| o.contents = vec![encoded("GZIP")],
                Problem::InvalidContents,
                Field::Encoding,
            ),
            (
                |o| o.contents = vec![encoded("gzip\u{ffff}")],
                Problem::InvalidString,
                Field::Encoding,
            ),
            (
                |o| o.contents = vec![headers(&[("bad name", "b")])],
                Problem::InvalidContents,
                Field::HttpHeaders,
            ),
            (
                |o| o.contents = vec![headers(&[("A", "b"), ("a", "c")])],
                Problem::InvalidContents,
                Field::HttpHeaders,
            ),
            (
                |o| o.contents = vec![headers(&[("A", "b\nc")])],
                Problem::InvalidContents,
                Field::HttpHeaders,
            ),
            (
                |o| o.contents = vec![Contents::default(); MAX_CONTENTS + 1],
                Problem::InvalidContents,
                Field::Contents,
            ),
        ];
        let (root, _) = recording_all();
        for (give, problem, field) in cases {
            let mut object = FileObject::new(name("x"));
            give(&mut object);
            let mut writer = Writer::begin(Vec::new(), &root).unwrap();
            let e = writer.file(&object).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.record_number(), e.name()),
                (ErrorKind::Manifest(problem), Some(field), Some(1), Some("x")),
                "{:?}",
                object
            );
        }
        // A field of a feature the manifest does not record, also one of
        // those the specification added last.
        let mut object = FileObject::new(name("x"));
        object.inode.read_only = Some(true);
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        let e = writer.file(&object).unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::UnlistedFeature), Some(Field::ReadOnly))
        );
        // The label of the file system, which only the root has.
        for (label, problem) in [
            ("a\u{ffff}", Problem::InvalidString),
            ("a\0b", Problem::InvalidString),
            ("a\u{1}b", Problem::WrongFieldType),
        ] {
            let mut root = RootObject {
                features: Some(Features::DEFAULT | Features::FS_LABEL),
                ..RootObject::default()
            };
            root.file_system.label = Some(label.into());
            let e = Writer::begin(Vec::new(), &root).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.record_number()),
                (ErrorKind::Manifest(problem), Some(Field::FsLabel), Some(0)),
                "{:?}",
                label
            );
        }
        // The mechanism of a signature.
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        let e = writer.signature(&Signature::new("pkcs7\u{fffe}")).unwrap_err();
        assert_eq!(
            (e.kind(), e.field(), e.record_number()),
            (
                ErrorKind::Manifest(Problem::InvalidString),
                Some(Field::Mechanism),
                Some(1)
            )
        );
        // What the reader takes, the writer takes.
        let mut object = FileObject::new(name("x"));
        (object.inode.uid, object.inode.gid) = (Some(65534), Some(u32::MAX - 1));
        object.inode.user_name = Some("Domain Users".into());
        object.contents = vec![headers(&[("A", "b"), ("B", "")]); MAX_CONTENTS];
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        writer.file(&object).unwrap();
        let m = read_whole(&writer.finish().unwrap()).unwrap();
        let read = &m.objects[0];
        assert_eq!(
            (read.inode.uid, read.inode.user_name.as_deref(), read.contents.len()),
            (Some(65534), Some("Domain Users"), MAX_CONTENTS)
        );
    }

    /// The writer refuses what a reader refuses of the fields of an object
    /// against its inode type and against each other.
    #[test]
    fn checks_the_fields_against_each_other() {
        /// Gives an object fields.
        type Give = fn(&mut FileObject);
        /// The fields of a partition with the attribute flags `flags`.
        fn partition(flags: u64) -> Option<Box<GptPartition>> {
            Some(Box::new(GptPartition {
                flags: Some(flags),
                ..GptPartition::default()
            }))
        }
        /// Contents in the file "x".
        fn file() -> Contents {
            Contents::new(Location::File(name("x")))
        }
        let cases: [(Give, Problem, Option<Field>); 17] = [
            // Fields the inode type does not permit.
            (
                |o| (o.inode_type, o.size) = (InodeType::Fifo, Some(1)),
                Problem::FieldNotPermitted,
                Some(Field::Size),
            ),
            (
                |o| (o.inode_type, o.contents) = (InodeType::CharDevice, vec![file()]),
                Problem::FieldNotPermitted,
                Some(Field::Contents),
            ),
            (
                |o| (o.inode_type, o.sha256) = (InodeType::Socket, EMPTY.parse().ok()),
                Problem::FieldNotPermitted,
                Some(Field::Contents),
            ),
            (|o| o.major = Some(1), Problem::FieldNotPermitted, Some(Field::Major)),
            (
                |o| (o.inode_type, o.inode.mode) = (InodeType::Symlink, Mode::new(0o777)),
                Problem::FieldNotPermitted,
                Some(Field::Mode),
            ),
            (
                |o| (o.inode_type, o.inode_token) = (InodeType::Directory, NonZeroU64::new(1)),
                Problem::FieldNotPermitted,
                Some(Field::InodeToken),
            ),
            (
                |o| (o.inode_type, o.gpt) = (InodeType::Directory, partition(0)),
                Problem::FieldNotPermitted,
                Some(Field::GptFlags),
            ),
            (
                |o| {
                    o.inode_type = InodeType::Symlink;
                    o.dos_flags.put(DosFlags::HIDDEN, Some(true));
                },
                Problem::FieldNotPermitted,
                Some(Field::FlagHidden),
            ),
            // readOnly against mode and against gptFlags, both ways, and
            // gptFlags against the field of one of its flags.
            (
                |o| (o.inode.read_only, o.inode.mode) = (Some(true), Mode::new(0o644)),
                Problem::Contradiction,
                Some(Field::ReadOnly),
            ),
            (
                |o| (o.inode.read_only, o.gpt) = (Some(true), partition(0)),
                Problem::Contradiction,
                Some(Field::GptFlags),
            ),
            (
                |o| (o.inode.read_only, o.gpt) = (Some(false), partition(GptPartition::FLAG_READ_ONLY)),
                Problem::Contradiction,
                Some(Field::GptFlags),
            ),
            // The manifest records gptFlags, so none is 0.
            (
                |o| o.inode.read_only = Some(true),
                Problem::Contradiction,
                Some(Field::ReadOnly),
            ),
            (
                |o| {
                    o.gpt = partition(GptPartition::FLAG_NO_AUTO);
                    o.gpt.as_mut().unwrap().no_auto = Some(false);
                },
                Problem::Contradiction,
                Some(Field::GptFlags),
            ),
            // The size 0 against the hash, and the other way around.
            (
                |o| (o.size, o.sha256) = (Some(0), HELLO.parse().ok()),
                Problem::Contradiction,
                Some(Field::Size),
            ),
            (
                |o| (o.size, o.sha256) = (Some(5), EMPTY.parse().ok()),
                Problem::Contradiction,
                Some(Field::Sha256),
            ),
            // httpHeaders without a URL, and a part beyond the data.
            (
                |o| {
                    o.contents = vec![Contents {
                        http_headers: vec![("A".into(), "b".into())],
                        ..file()
                    }];
                },
                Problem::InvalidContents,
                Some(Field::HttpHeaders),
            ),
            (
                |o| {
                    o.size = Some(5);
                    o.contents = vec![Contents {
                        original_size: Some(6),
                        offset: 2,
                        ..file()
                    }];
                },
                Problem::Contradiction,
                Some(Field::Offset),
            ),
        ];
        let (root, _) = recording_all();
        for (give, problem, field) in cases {
            let mut object = FileObject::new(name("x"));
            give(&mut object);
            let mut writer = Writer::begin(Vec::new(), &root).unwrap();
            let e = writer.file(&object).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.record_number(), e.name()),
                (ErrorKind::Manifest(problem), field, Some(1), Some("x")),
                "{:?}: {}",
                object,
                e
            );
            // Nothing of it was written.
            assert_eq!(writer.finish().unwrap(), sequence(&[&recording_all().1, TRAILER]));
        }
    }

    /// An encoder appends what a writer writes, and nothing where it fails.
    #[test]
    fn encodes_what_a_writer_writes() {
        let (root, _) = recording_all();
        let whole = Whole {
            root: root.clone(),
            objects: vec![directory("a"), everything()],
            signatures: vec![Signature::new("pkcs7")],
        };
        let mut text = String::new();
        let mut encoder = Encoder::begin(&root, &mut text).unwrap();
        for object in &whole.objects {
            encoder.file(object, &mut text).unwrap();
        }
        // A name that came before is refused once the record was put
        // together, and taken back.
        let appended = text.clone();
        let e = encoder.file(&directory("a"), &mut text).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number()),
            (ErrorKind::Manifest(Problem::DuplicateName), Some(3))
        );
        assert_eq!(text, appended);
        for signature in &whole.signatures {
            encoder.signature(signature, &mut text).unwrap();
        }
        encoder.finish(&mut text).unwrap();
        assert_eq!(text.as_bytes(), write_whole(&whole).unwrap());
        // Nothing follows the trailer.
        let appended = text.len();
        for e in [
            encoder.file(&FileObject::new(name("z")), &mut text).unwrap_err(),
            encoder.file(&FileObject::new(Name::ROOT), &mut text).unwrap_err(),
            encoder.signature(&Signature::new("pkcs7"), &mut text).unwrap_err(),
            encoder.finish(&mut text).unwrap_err(),
        ] {
            assert_eq!(
                (e.kind(), e.record_number()),
                (ErrorKind::Manifest(Problem::DataAfterTrailer), Some(5))
            );
        }
        assert_eq!(text.len(), appended);
    }
}
