// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading one record of a manifest into the object it holds.
//!
//! A record is read once, member by member. Whether it is JSON at all is
//! only known at its end, and so is its media type, which says what kind
//! of object it is. So what is wrong with a field is noted and reported
//! when the record is known to be a file object. The rules are those of
//! systemd's reader, src/shared/uapi16-manifest.c.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;

use json::{ParseError, Parser};

use crate::base64::Base64;
use crate::digest::Digest;
use crate::error::{Error, Field, Problem};
use crate::hex::Hex;
use crate::object::{Contents, FileObject, Gpt, InodeType, Location, Mode, Signature, Uuid, Validity};
use crate::{Name, Sha256, MAX_CONTENTS, MEDIA_TYPE, SIGNATURE_MEDIA_TYPE, TRAILER_MEDIA_TYPE};

/// The user and group IDs that stand for nobody: -1 as 32 bits and as 16
/// bits. An ID is below the first and is not the second.
const ID_INVALID: u64 = u32::MAX as u64;
const ID_INVALID_16: u64 = u16::MAX as u64;
/// The base an access mode given as a string is written in.
const OCTAL: u32 = 8;
/// The extended attribute namespace the specification defines.
const USER_NAMESPACE: &str = "user";
/// The `validity` of a file that is not to be used.
const REVOKED: &str = "revoked";
/// The schemes a URL can have.
const URL_SCHEMES: [&str; 2] = ["http://", "https://"];
/// The encoding that stands for none in HTTP, which a manifest does not
/// take.
const IDENTITY: &str = "identity";

/// What a record holds.
pub(crate) enum Decoded {
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
    /// A file object: it has no media type, or the one of a manifest.
    File,
    /// The first object of a manifest has to have this one.
    Manifest,
    Signature,
    Trailer,
    Other,
}

/// A member that has to be a string, as it was found.
enum Member<'a> {
    /// Not there, or null.
    Absent,
    Text(Cow<'a, str>),
    /// There, and not a string.
    Other,
}

/// A hash and a size that cannot both be right.
enum Clash {
    /// The hash of no data, with a size that is not 0.
    HashOfNothing,
    /// The size 0, with a hash that is not the one of no data.
    SizeOfNothing,
}

/// The object a message is about: `manifest object 5`, and with its name
/// `manifest object 5 (EFI/BOOT)`.
#[derive(Clone, Copy)]
struct What<'a> {
    /// The number of the record the object is in.
    record: u64,
    name: Option<&'a str>,
}

impl fmt::Display for What<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "manifest object {}", self.record)?;
        match self.name {
            Some(name) => write!(f, " ({})", name),
            None => Ok(()),
        }
    }
}

impl Clash {
    /// Brings a hash and the size of what it is the hash of in line: data
    /// of size 0 has the hash of no data, and only it has. One of the two
    /// gives the other, and the two together must not break the rule.
    fn settle<D: Digest>(digest: &mut Option<D>, size: &mut Option<u64>) -> Result<(), Clash> {
        match (*digest, *size) {
            (Some(d), Some(s)) if d == D::EMPTY && s != 0 => return Err(Clash::HashOfNothing),
            (Some(d), Some(0)) if d != D::EMPTY => return Err(Clash::SizeOfNothing),
            (Some(d), None) if d == D::EMPTY => *size = Some(0),
            (None, Some(0)) => *digest = Some(D::EMPTY),
            _ => {}
        }
        Ok(())
    }

    /// The error for the object or the contents object `what`.
    fn into_error(self, what: What<'_>) -> Error {
        match self {
            Clash::HashOfNothing => Error::manifest(
                Problem::Contradiction,
                format!("{}: a zero hash with a non-zero size", what),
            )
            .at(Field::Sha256),
            Clash::SizeOfNothing => Error::manifest(
                Problem::Contradiction,
                format!("{}: a zero size with a non-zero hash", what),
            )
            .at(Field::Size),
        }
    }
}

impl Field {
    /// The field of a file object `key` is, if this crate reads it.
    fn of_file_object(key: &str) -> Option<Field> {
        Some(match key {
            "name" => Field::Name,
            "mediaType" => Field::MediaType,
            "type" => Field::Type,
            "size" => Field::Size,
            "mode" => Field::Mode,
            "uid" => Field::Uid,
            "gid" => Field::Gid,
            "userName" => Field::UserName,
            "groupName" => Field::GroupName,
            "major" => Field::Major,
            "minor" => Field::Minor,
            "mTimeNSec" => Field::MTimeNSec,
            "inodeToken" => Field::InodeToken,
            "extendedAttributes" => Field::ExtendedAttributes,
            "gptLabel" => Field::GptLabel,
            "gptUuid" => Field::GptUuid,
            "gptTypeUuid" => Field::GptTypeUuid,
            "gptDiskUuid" => Field::GptDiskUuid,
            "gptFlags" => Field::GptFlags,
            "gptFlagNoAuto" => Field::GptFlagNoAuto,
            "gptFlagGrowFileSystem" => Field::GptFlagGrowFileSystem,
            "readOnly" => Field::ReadOnly,
            "contents" => Field::Contents,
            "sha256" => Field::Sha256,
            "validSinceUSec" => Field::ValidSinceUSec,
            "validUntilUSec" => Field::ValidUntilUSec,
            "validity" => Field::Validity,
            _ => return None,
        })
    }

    /// The field of a contents object `key` is, if this crate reads it.
    fn of_contents(key: &str) -> Option<Field> {
        Some(match key {
            "file" => Field::File,
            "url" => Field::Url,
            "literal" => Field::Literal,
            "encoding" => Field::Encoding,
            "encodedSize" => Field::EncodedSize,
            "encodedSha256" => Field::EncodedSha256,
            "originalSize" => Field::OriginalSize,
            "originalSha256" => Field::OriginalSha256,
            "offset" => Field::Offset,
            _ => return None,
        })
    }
}

/// A file object as far as its record was read: what does not go into a
/// [`FileObject`] as it is.
struct Draft {
    object: Box<FileObject>,
    name: Option<Name>,
    /// The name as the record has it, when it is not a valid one.
    invalid_name: Option<String>,
    inode_type: Option<InodeType>,
}

impl Draft {
    /// The name the record gives, valid or not.
    fn stated_name(&self) -> Option<&str> {
        if !self.object.name.is_root() {
            return Some(&self.object.name);
        }
        self.name.as_deref().or(self.invalid_name.as_deref())
    }

    /// The GPT fields, which are made when the first of them is read.
    fn gpt(&mut self) -> &mut Gpt {
        self.object.gpt.get_or_insert_with(Box::default)
    }

    /// Makes the draft the file object of the record with the number
    /// `record`, the first of which is the root file object. Checks the
    /// fields against the inode type and against each other, and fills in
    /// what follows from them.
    fn settle(&mut self, record: u64) -> Result<(), Error> {
        let object = &mut *self.object;
        let stated_type = self.inode_type;
        let root = record == ROOT_RECORD;
        let fault = |problem, field: Option<Field>, message: String| {
            let e = Error::manifest(problem, message);
            Err(match field {
                Some(field) => e.at(field),
                None => e,
            })
        };
        if root {
            if self.name.is_some() {
                return fault(
                    Problem::FirstHasName,
                    Some(Field::Name),
                    "the first manifest object has a name".into(),
                );
            }
            if !matches!(stated_type, None | Some(InodeType::Directory)) {
                return fault(
                    Problem::FirstNotDirectory,
                    Some(Field::Type),
                    "the first manifest object is not a directory".into(),
                );
            }
            object.inode_type = InodeType::Directory;
        } else {
            let Some(name) = self.name.take() else {
                return fault(
                    Problem::NoName,
                    Some(Field::Name),
                    format!("manifest object {} has no name", record),
                );
            };
            object.name = name;
            object.inode_type = stated_type.unwrap_or(InodeType::Regular);
        }
        let inode_type = object.inode_type;
        let what = What {
            record,
            name: Some(if root { ROOT_NAME } else { object.name.as_str() }),
        };
        // Fields the inode type does not permit.
        if object.size.is_some() && !inode_type.has_contents() {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::Size),
                format!("{}: 'size' is not permitted on a {}", what, inode_type),
            );
        }
        if (object.major.is_some() || object.minor.is_some()) && !inode_type.is_device() {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::Major),
                format!("{}: 'major' and 'minor' are not permitted on a {}", what, inode_type),
            );
        }
        if object.mode.is_some() && inode_type == InodeType::Symlink {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::Mode),
                format!("{}: 'mode' is not permitted on a symlink", what),
            );
        }
        if object.inode_token.is_some() && inode_type == InodeType::Directory {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::InodeToken),
                format!("{}: 'inodeToken' is not permitted on a directory", what),
            );
        }
        if (!object.contents.is_empty() || object.sha256.is_some()) && !inode_type.has_contents() {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::Contents),
                format!(
                    "{}: 'contents' and 'sha256' are not permitted on a {}",
                    what, inode_type
                ),
            );
        }
        let gpt = object.gpt.as_deref();
        if gpt.is_some_and(Gpt::describes_partition) && inode_type != InodeType::Regular {
            return fault(
                Problem::FieldNotPermitted,
                None,
                format!("{}: GPT fields are only permitted on regular files", what),
            );
        }
        if gpt.is_some_and(|gpt| gpt.disk_uuid.is_some()) && !root {
            return fault(
                Problem::FieldNotPermitted,
                Some(Field::GptDiskUuid),
                format!("{}: 'gptDiskUuid' is only permitted on the first object", what),
            );
        }
        // Fields that contradict each other.
        if let (Some(read_only), Some(mode)) = (object.read_only, object.mode) {
            if read_only == mode.is_writable() {
                return fault(
                    Problem::Contradiction,
                    Some(Field::ReadOnly),
                    format!("{}: 'readOnly' and 'mode' contradict each other", what),
                );
            }
        }
        if let Some(gpt) = object.gpt.as_deref() {
            if let Some(flags) = gpt.flags {
                let differs = |flag: Option<bool>, bit: u64| flag.is_some_and(|set| set != (flags & bit != 0));
                if differs(gpt.no_auto, Gpt::FLAG_NO_AUTO) || differs(gpt.grow_file_system, Gpt::FLAG_GROW_FILE_SYSTEM)
                {
                    return fault(
                        Problem::Contradiction,
                        Some(Field::GptFlags),
                        format!("{}: 'gptFlags' and the 'gptFlag*' fields contradict each other", what),
                    );
                }
            }
        }
        Clash::settle(&mut object.sha256, &mut object.size).map_err(|clash| clash.into_error(what))?;
        // The size and the hash of the object and those of its contents
        // objects have to agree where they are about the same data.
        let (mut size, mut sha256) = (object.size, object.sha256);
        for contents in &object.contents {
            match (size, contents.original_size) {
                (Some(size), Some(total)) => {
                    if contents.offset.checked_add(size).is_none_or(|end| end > total) {
                        return fault(
                            Problem::Contradiction,
                            Some(Field::Offset),
                            format!(
                                "{}: offset {} plus size {} exceeds the contents size {}",
                                what, contents.offset, size, total
                            ),
                        );
                    }
                }
                (None, Some(total)) => size = Some(total - contents.offset),
                _ => {}
            }
            if contents.offset == 0 && size.is_some() && contents.original_size == size {
                match (sha256, contents.original_sha256) {
                    (Some(a), Some(b)) if a != b => {
                        return fault(
                            Problem::Contradiction,
                            Some(Field::Sha256),
                            format!("{}: object and contents hashes differ", what),
                        );
                    }
                    (None, Some(b)) => sha256 = Some(b),
                    _ => {}
                }
            }
        }
        (object.size, object.sha256) = (size, sha256);
        Ok(())
    }
}

impl Contents {
    /// Checks the fields of a contents object against each other, and
    /// fills in what follows from them. `places` is how many of `file`,
    /// `url` and `literal` its record has, and `what` names the object it
    /// belongs to.
    fn settle(&mut self, places: usize, what: What<'_>) -> Result<(), Error> {
        if places > 1 {
            return Err(Error::manifest(
                Problem::Contents,
                format!("{}: only one of file, url and literal may be set", what),
            ));
        }
        Clash::settle(&mut self.encoded_sha256, &mut self.encoded_size).map_err(|clash| clash.into_error(what))?;
        Clash::settle(&mut self.original_sha256, &mut self.original_size).map_err(|clash| clash.into_error(what))?;
        if self.encoding.is_none() {
            // Without an encoding the encoded and the original data are the same.
            match (self.encoded_size, self.original_size) {
                (Some(a), Some(b)) if a != b => {
                    return Err(Error::manifest(
                        Problem::Contradiction,
                        format!("{}: encoded and original size differ without an encoding", what),
                    )
                    .at(Field::EncodedSize));
                }
                (Some(a), None) => self.original_size = Some(a),
                (None, Some(b)) => self.encoded_size = Some(b),
                _ => {}
            }
            match (self.encoded_sha256, self.original_sha256) {
                (Some(a), Some(b)) if a != b => {
                    return Err(Error::manifest(
                        Problem::Contradiction,
                        format!("{}: encoded and original hash differ without an encoding", what),
                    )
                    .at(Field::EncodedSha256));
                }
                (Some(a), None) => self.original_sha256 = Some(a),
                (None, Some(b)) => self.encoded_sha256 = Some(b),
                _ => {}
            }
        }
        if let Location::Literal(literal) = &self.location {
            let len = literal.len() as u64;
            if self.encoded_size.is_some_and(|size| size != len) {
                return Err(Error::manifest(
                    Problem::Contradiction,
                    format!(
                        "{}: literal contents are {} bytes, not {}",
                        what,
                        len,
                        self.encoded_size.unwrap_or_default()
                    ),
                )
                .at(Field::Literal));
            }
            self.encoded_size = Some(len);
            if self.encoding.is_none() {
                self.original_size = self.encoded_size;
            }
        }
        if let Some(total) = self.original_size {
            if self.offset > total {
                return Err(Error::manifest(
                    Problem::Contents,
                    format!(
                        "{}: contents offset {} is beyond the data size {}",
                        what, self.offset, total
                    ),
                )
                .at(Field::Offset));
            }
        }
        Ok(())
    }
}

/// The number of the first record of a manifest, the one that holds the
/// root file object.
pub(crate) const ROOT_RECORD: u64 = 0;
/// What a message calls the root file object, which has no name.
const ROOT_NAME: &str = "root";

/// Reads the members of one record.
pub(crate) struct Decoder<'a> {
    json: Parser<'a>,
    /// The number of the record, for what is said about it.
    record: u64,
    /// The first thing found wrong with a field.
    flaw: Option<Error>,
}

/// A record that was read as a file object, before its media type said
/// whether it is one.
struct Candidate {
    draft: Draft,
    record: u64,
    flaw: Option<Error>,
}

impl Candidate {
    /// The file object the record holds, or what is wrong with it.
    fn file_object(mut self) -> Result<Box<FileObject>, Error> {
        let settled = match self.flaw {
            Some(flaw) => Err(flaw),
            None => self.draft.settle(self.record),
        };
        match settled {
            Ok(()) => Ok(self.draft.object),
            // An error names the object the way its record does.
            Err(e) => {
                let e = e.in_record(self.record);
                Err(match self.draft.stated_name() {
                    Some(name) => e.named(name),
                    None => e,
                })
            }
        }
    }
}

impl<'a> Decoder<'a> {
    /// Reads the record `text`, the one with the number `record`, as far
    /// as a file object goes, and says what its media type makes it.
    fn read(text: &'a str, record: u64) -> Result<(MediaType, Candidate), Error> {
        let mut decoder = Decoder {
            json: Parser::new(text),
            record,
            flaw: None,
        };
        let not_json = |e| Error::not_json(record, e);
        if !decoder.json.object().map_err(not_json)? {
            decoder.json.skip().map_err(not_json)?;
            decoder.json.end().map_err(not_json)?;
            return Err(Error::manifest(
                Problem::NotObject,
                format!("manifest record {} is not a JSON object", record),
            )
            .in_record(record));
        }
        let (media_type, draft) = decoder.file_object().map_err(not_json)?;
        decoder.json.end().map_err(not_json)?;
        let Some(media_type) = media_type else {
            return Err(Error::manifest(
                Problem::MediaType,
                format!("manifest object {} has a mediaType that is not a string", record),
            )
            .in_record(record));
        };
        let candidate = Candidate {
            draft,
            record,
            flaw: decoder.flaw,
        };
        Ok((media_type, candidate))
    }

    /// Reads the first record of a manifest, which holds the root file
    /// object and says with its media type that this is a manifest.
    pub(crate) fn root(text: &'a str) -> Result<FileObject, Error> {
        let (media_type, candidate) = Decoder::read(text, ROOT_RECORD)?;
        if media_type != MediaType::Manifest {
            return Err(Error::manifest(
                Problem::MediaType,
                "the first object of the manifest is not of the manifest media type".into(),
            )
            .in_record(ROOT_RECORD));
        }
        candidate.file_object().map(|root| *root)
    }

    /// Reads the record `text`, the one with the number `record`, which
    /// is not the first.
    pub(crate) fn record(text: &'a str, record: u64) -> Result<Decoded, Error> {
        let (media_type, candidate) = Decoder::read(text, record)?;
        Ok(match media_type {
            MediaType::Trailer => Decoded::Trailer,
            MediaType::Signature => Decoded::Signature(Signature::decode(text, record)?),
            MediaType::Other => Decoded::Other,
            MediaType::File | MediaType::Manifest => Decoded::File(candidate.file_object()),
        })
    }

    /// Notes what is wrong with a field, unless something was wrong
    /// before it.
    fn flaw(&mut self, problem: Problem, field: Field, message: impl FnOnce() -> String) {
        if self.flaw.is_none() {
            self.flaw = Some(Error::manifest(problem, message()).at(field));
        }
    }

    /// The object the record is about, for a message.
    fn what(&self) -> What<'static> {
        What {
            record: self.record,
            name: None,
        }
    }

    /// Reads a string. Any other value is a flaw.
    fn string(&mut self, field: Field) -> Result<Option<Cow<'a, str>>, ParseError> {
        let value = self.json.string()?;
        if value.is_none() {
            self.json.skip()?;
            self.flaw(Problem::FieldType, field, || {
                format!("manifest field '{}' is not a string", field)
            });
        }
        Ok(value)
    }

    /// Reads a boolean. Any other value is a flaw.
    fn boolean(&mut self, field: Field) -> Result<Option<bool>, ParseError> {
        let value = self.json.bool()?;
        if value.is_none() {
            self.json.skip()?;
            self.flaw(Problem::FieldType, field, || {
                format!("manifest field '{}' is not a boolean", field)
            });
        }
        Ok(value)
    }

    /// Reads an unsigned integer. 64 bit values are a problem for many
    /// JSON implementations, so like systemd we also take them as decimal
    /// strings. Any other value is a flaw.
    fn uint(&mut self, field: Field) -> Result<Option<u64>, ParseError> {
        let value = if let Some(number) = self.json.number()? {
            number.as_u64()
        } else if let Some(text) = self.json.string()? {
            let decimal = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit());
            decimal.then(|| text.parse().ok()).flatten()
        } else {
            self.json.skip()?;
            None
        };
        if value.is_none() {
            self.flaw(Problem::FieldType, field, || {
                format!("manifest field '{}' is not an unsigned integer", field)
            });
        }
        Ok(value)
    }

    /// Reads a hash. Anything but the hex digits of one is a flaw.
    fn digest(&mut self, field: Field) -> Result<Option<Sha256>, ParseError> {
        let Some(text) = self.string(field)? else {
            return Ok(None);
        };
        let digest = text.parse().ok();
        if digest.is_none() {
            self.flaw(Problem::FieldType, field, || {
                format!("manifest field '{}' is not a SHA-256 hash", field)
            });
        }
        Ok(digest)
    }

    /// Reads an access mode: a number, or a string in octal as everywhere
    /// else.
    fn mode(&mut self, field: Field) -> Result<Option<Mode>, ParseError> {
        let bits = if let Some(text) = self.json.string()? {
            if text.is_empty() || !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                self.flaw(Problem::FieldType, field, || {
                    format!("manifest field '{}' is not an octal access mode", field)
                });
                return Ok(None);
            }
            u64::from_str_radix(&text, OCTAL).unwrap_or(u64::MAX)
        } else {
            match self.uint(field)? {
                Some(bits) => bits,
                None => return Ok(None),
            }
        };
        let mode = u32::try_from(bits).ok().and_then(Mode::new);
        if mode.is_none() {
            self.flaw(Problem::FieldRange, field, || {
                format!("manifest field '{}' is out of range: {}", field, bits)
            });
        }
        Ok(mode)
    }

    /// Reads a user or group ID.
    fn id(&mut self, field: Field) -> Result<Option<u32>, ParseError> {
        let Some(id) = self.uint(field)? else {
            return Ok(None);
        };
        if id >= ID_INVALID || id == ID_INVALID_16 {
            let what = self.what();
            self.flaw(Problem::FieldRange, field, || {
                format!("{}: {} {} is out of range", what, field, id)
            });
            return Ok(None);
        }
        Ok(u32::try_from(id).ok())
    }

    /// Reads the name of a user or of a group. systemd's relaxed rules
    /// take anything that is not obviously broken or a number in
    /// disguise.
    fn user_or_group_name(&mut self, field: Field) -> Result<Option<Box<str>>, ParseError> {
        let Some(name) = self.string(field)? else {
            return Ok(None);
        };
        let digits = name.strip_prefix('-').unwrap_or(&name);
        if name.is_empty()
            || name.starts_with(' ')
            || name.ends_with(' ')
            || name == "."
            || name == ".."
            || name.chars().any(|c| c.is_ascii_control() || c == ':' || c == '/')
            || digits.bytes().all(|b| b.is_ascii_digit())
        {
            let what = self.what();
            self.flaw(Problem::FieldType, field, || {
                format!("{}: {} '{}' is not a valid name", what, field, name)
            });
            return Ok(None);
        }
        Ok(Some(name.into()))
    }

    /// Reads a UUID.
    fn uuid(&mut self, field: Field) -> Result<Option<Uuid>, ParseError> {
        let Some(text) = self.string(field)? else {
            return Ok(None);
        };
        let uuid = text.parse().ok();
        if uuid.is_none() {
            let what = self.what();
            self.flaw(Problem::FieldType, field, || {
                format!("{}: {} '{}' is not a UUID", what, field, text)
            });
        }
        Ok(uuid)
    }

    /// Reads a GPT partition label: no control characters and no more
    /// UTF-16 units than the partition table has room for.
    fn gpt_label(&mut self, field: Field) -> Result<Option<String>, ParseError> {
        let Some(label) = self.string(field)? else {
            return Ok(None);
        };
        let control = |c: char| c < ' ' || ('\x7f'..='\u{9f}').contains(&c);
        if label.chars().any(control) || label.encode_utf16().take(Gpt::LABEL_MAX + 1).count() > Gpt::LABEL_MAX {
            let what = self.what();
            self.flaw(Problem::FieldType, field, || {
                format!("{}: '{}' is not a valid GPT partition label", what, label)
            });
            return Ok(None);
        }
        Ok(Some(label.into_owned()))
    }

    /// Reads a member that has to be a string, whatever it is.
    fn member(&mut self) -> Result<Member<'a>, ParseError> {
        if self.json.null()? {
            return Ok(Member::Absent);
        }
        Ok(match self.json.string()? {
            Some(text) => Member::Text(text),
            None => {
                self.json.skip()?;
                Member::Other
            }
        })
    }

    /// What the `mediaType` in front of the parser says the record is.
    /// None is a media type that is not a string.
    fn media_type(&mut self) -> Result<Option<MediaType>, ParseError> {
        Ok(match self.json.string()?.as_deref() {
            Some(MEDIA_TYPE) => Some(MediaType::Manifest),
            Some(SIGNATURE_MEDIA_TYPE) => Some(MediaType::Signature),
            Some(TRAILER_MEDIA_TYPE) => Some(MediaType::Trailer),
            Some(_) => Some(MediaType::Other),
            None => {
                self.json.skip()?;
                None
            }
        })
    }

    /// Reads the members of the object the parser is in as those of a
    /// file object, and says what media type the record has. None is a
    /// media type that is not a string.
    fn file_object(&mut self) -> Result<(Option<MediaType>, Draft), ParseError> {
        let mut media_type = Some(MediaType::File);
        let mut draft = Draft {
            object: Box::new(FileObject::root()),
            name: None,
            invalid_name: None,
            inode_type: None,
        };
        while let Some(key) = self.json.key()? {
            let Some(field) = Field::of_file_object(&key) else {
                self.json.skip()?;
                continue;
            };
            // A media type of null is none that says what the record is.
            if field == Field::MediaType {
                media_type = self.media_type()?;
                continue;
            }
            // A field that is null is a field that is not there.
            if self.json.null()? {
                continue;
            }
            let object = &mut *draft.object;
            match field {
                Field::Name => {
                    if let Some(name) = self.string(field)? {
                        match Name::new(name.as_ref()) {
                            Ok(name) => draft.name = Some(name),
                            Err(_) => {
                                let what = self.what();
                                self.flaw(Problem::InvalidName, field, || {
                                    format!("{}: name '{}' is not a valid relative path", what, name)
                                });
                                draft.invalid_name = Some(name.into_owned());
                            }
                        }
                    }
                }
                Field::Type => {
                    if let Some(name) = self.string(field)? {
                        draft.inode_type = name.parse().ok();
                        if draft.inode_type.is_none() {
                            let what = self.what();
                            self.flaw(Problem::UnknownType, field, || {
                                format!("{}: unknown inode type '{}'", what, name)
                            });
                        }
                    }
                }
                Field::Size => object.size = self.uint(field)?,
                Field::Mode => object.mode = self.mode(field)?,
                Field::Uid => object.uid = self.id(field)?,
                Field::Gid => object.gid = self.id(field)?,
                Field::UserName => object.user_name = self.user_or_group_name(field)?,
                Field::GroupName => object.group_name = self.user_or_group_name(field)?,
                Field::Major => object.major = self.uint(field)?,
                Field::Minor => object.minor = self.uint(field)?,
                Field::MTimeNSec => object.mtime_nsec = self.uint(field)?,
                // The token 0 is that of a file with one name.
                Field::InodeToken => object.inode_token = self.uint(field)?.and_then(NonZeroU64::new),
                Field::ExtendedAttributes => object.user_xattrs = self.extended_attributes()?.map(Box::new),
                Field::GptLabel => draft.gpt().label = self.gpt_label(field)?,
                Field::GptUuid => draft.gpt().uuid = self.uuid(field)?,
                Field::GptTypeUuid => draft.gpt().type_uuid = self.uuid(field)?,
                Field::GptDiskUuid => draft.gpt().disk_uuid = self.uuid(field)?,
                Field::GptFlags => draft.gpt().flags = self.uint(field)?,
                Field::GptFlagNoAuto => draft.gpt().no_auto = self.boolean(field)?,
                Field::GptFlagGrowFileSystem => draft.gpt().grow_file_system = self.boolean(field)?,
                Field::ReadOnly => object.read_only = self.boolean(field)?,
                Field::Contents => object.contents = self.contents()?,
                Field::Sha256 => object.sha256 = self.digest(field)?,
                Field::ValidSinceUSec => object.valid_since_usec = self.uint(field)?.unwrap_or_default(),
                Field::ValidUntilUSec => object.valid_until_usec = self.uint(field)?,
                // A value the specification does not have yet is good.
                Field::Validity => {
                    if self.string(field)?.is_some_and(|validity| validity == REVOKED) {
                        object.validity = Validity::Revoked;
                    }
                }
                _ => self.json.skip()?,
            }
        }
        Ok((media_type, draft))
    }

    /// Reads the `extendedAttributes` field: namespaces that map names to
    /// values, a value being an object with exactly one of `text` and
    /// `base64`. Only the `user` namespace is defined. Others are passed
    /// over, as systemd passes over them.
    fn extended_attributes(&mut self) -> Result<Option<BTreeMap<String, Vec<u8>>>, ParseError> {
        let field = Field::ExtendedAttributes;
        let what = self.what();
        if !self.json.object()? {
            self.json.skip()?;
            self.flaw(Problem::ExtendedAttributes, field, || {
                format!("{}: 'extendedAttributes' is not an object", what)
            });
            return Ok(None);
        }
        let mut user = None;
        while let Some(namespace) = self.json.key()? {
            if namespace != USER_NAMESPACE {
                self.json.skip()?;
                continue;
            }
            // A namespace that is null says nothing about its attributes.
            if self.json.null()? {
                continue;
            }
            if !self.json.object()? {
                self.json.skip()?;
                self.flaw(Problem::ExtendedAttributes, field, || {
                    format!(
                        "{}: extended attribute namespace '{}' is not an object",
                        what, namespace
                    )
                });
                continue;
            }
            let attributes = user.insert(BTreeMap::new());
            while let Some(name) = self.json.key()? {
                if name.is_empty() || name.chars().any(|c| c.is_ascii_control()) {
                    self.json.skip()?;
                    self.flaw(Problem::ExtendedAttributes, field, || {
                        format!("{}: invalid extended attribute name '{}'", what, name)
                    });
                    continue;
                }
                if !self.json.object()? {
                    self.json.skip()?;
                    self.flaw(Problem::ExtendedAttributes, field, || {
                        format!("{}: value of extended attribute '{}' is not an object", what, name)
                    });
                    continue;
                }
                let (mut text, mut base64) = (Member::Absent, Member::Absent);
                while let Some(key) = self.json.key()? {
                    match Field::of_extended_attribute(&key) {
                        Some(Field::Text) => text = self.member()?,
                        Some(Field::Base64) => base64 = self.member()?,
                        _ => self.json.skip()?,
                    }
                }
                let value = match (text, base64) {
                    (Member::Text(text), Member::Absent) => Some(text.into_owned().into_bytes()),
                    (Member::Other, Member::Absent) => {
                        self.flaw(Problem::FieldType, Field::Text, || {
                            format!("manifest field '{}' is not a string", Field::Text)
                        });
                        None
                    }
                    (Member::Absent, Member::Text(base64)) => {
                        let value = Base64::decode(&base64);
                        if value.is_none() {
                            self.flaw(Problem::ExtendedAttributes, field, || {
                                format!("{}: extended attribute '{}' is not valid Base64", what, name)
                            });
                        }
                        value
                    }
                    (Member::Absent, Member::Other) => {
                        self.flaw(Problem::FieldType, Field::Base64, || {
                            format!("manifest field '{}' is not a string", Field::Base64)
                        });
                        None
                    }
                    _ => {
                        self.flaw(Problem::ExtendedAttributes, field, || {
                            format!(
                                "{}: extended attribute '{}' needs exactly one of 'text' and 'base64'",
                                what, name
                            )
                        });
                        None
                    }
                };
                if let Some(value) = value {
                    attributes.insert(name.into_owned(), value);
                }
            }
        }
        Ok(user)
    }

    /// Reads the `contents` field: an array of contents objects.
    fn contents(&mut self) -> Result<Vec<Contents>, ParseError> {
        let field = Field::Contents;
        let mut list = Vec::new();
        if !self.json.array()? {
            self.json.skip()?;
            self.flaw(Problem::FieldType, field, || {
                format!("manifest field '{}' is not an array", field)
            });
            return Ok(list);
        }
        let flawed_before = self.flaw.is_some();
        let mut count = 0usize;
        while self.json.element()? {
            let contents = self.contents_object()?;
            count += 1;
            if count <= MAX_CONTENTS {
                list.push(contents);
            }
        }
        // Too many of them is what is wrong with the field, whatever is
        // wrong with one of them.
        if count > MAX_CONTENTS && !flawed_before {
            let message = format!("{}: more than {} contents entries", self.what(), MAX_CONTENTS);
            self.flaw = Some(Error::manifest(Problem::Contents, message).at(field));
        }
        Ok(list)
    }

    /// Reads one contents object.
    fn contents_object(&mut self) -> Result<Contents, ParseError> {
        let what = self.what();
        let mut contents = Contents::default();
        if !self.json.object()? {
            self.json.skip()?;
            self.flaw(Problem::Contents, Field::Contents, || {
                format!("{}: contents entry is not an object", what)
            });
            return Ok(contents);
        }
        // How many of file, url and literal the object has.
        let mut places = 0;
        while let Some(key) = self.json.key()? {
            let Some(field) = Field::of_contents(&key) else {
                self.json.skip()?;
                continue;
            };
            if self.json.null()? {
                continue;
            }
            match field {
                Field::File => {
                    if let Some(file) = self.string(field)? {
                        match Name::new(file.as_ref()) {
                            Ok(file) => {
                                contents.location = Location::File(file);
                                places += 1;
                            }
                            Err(_) => self.flaw(Problem::Contents, field, || {
                                format!(
                                    "{}: contents file reference '{}' is not a valid relative path",
                                    what, file
                                )
                            }),
                        }
                    }
                }
                Field::Url => {
                    if let Some(url) = self.string(field)? {
                        if URL_SCHEMES.iter().any(|scheme| url.starts_with(scheme)) {
                            contents.location = Location::Url(url.into_owned());
                            places += 1;
                        } else {
                            self.flaw(Problem::Contents, field, || {
                                format!("{}: contents URL '{}' is not http or https", what, url)
                            });
                        }
                    }
                }
                Field::Literal => {
                    if let Some(literal) = self.string(field)? {
                        match Base64::decode(&literal) {
                            Some(literal) => {
                                contents.location = Location::Literal(literal);
                                places += 1;
                            }
                            None => self.flaw(Problem::Contents, field, || {
                                format!("{}: literal contents are not Base64", what)
                            }),
                        }
                    }
                }
                Field::Encoding => {
                    // The encodings are those of HTTP, which does not
                    // tell upper case from lower case.
                    if let Some(encoding) = self.string(field)? {
                        let encoding = encoding.to_ascii_lowercase();
                        if encoding.is_empty() || encoding == IDENTITY {
                            self.flaw(Problem::Contents, field, || {
                                format!("{}: encoding '{}' is not permitted", what, encoding)
                            });
                        } else {
                            contents.encoding = Some(encoding);
                        }
                    }
                }
                Field::EncodedSize => contents.encoded_size = self.uint(field)?,
                Field::EncodedSha256 => contents.encoded_sha256 = self.digest(field)?,
                Field::OriginalSize => contents.original_size = self.uint(field)?,
                Field::OriginalSha256 => contents.original_sha256 = self.digest(field)?,
                Field::Offset => contents.offset = self.uint(field)?.unwrap_or_default(),
                _ => self.json.skip()?,
            }
        }
        if self.flaw.is_none() {
            self.flaw = contents.settle(places, what).err();
        }
        Ok(contents)
    }
}

impl Field {
    /// The field of the value of an extended attribute `key` is.
    fn of_extended_attribute(key: &str) -> Option<Field> {
        match key {
            "text" => Some(Field::Text),
            "base64" => Some(Field::Base64),
            _ => None,
        }
    }

    /// The field of a signature object `key` is, if this crate reads it.
    fn of_signature(key: &str) -> Option<Field> {
        match key {
            "mechanism" => Some(Field::Mechanism),
            "key" => Some(Field::Key),
            "data" => Some(Field::Data),
            _ => None,
        }
    }
}

impl Signature {
    /// Reads the signature object the record `text` holds, which is known
    /// to be a JSON object. The signature is not verified, but a manifest
    /// whose signature objects are malformed is refused like systemd
    /// refuses it.
    fn decode(text: &str, record: u64) -> Result<Signature, Error> {
        let mut decoder = Decoder {
            json: Parser::new(text),
            record,
            flaw: None,
        };
        decoder
            .signature()
            .map_err(|e| Error::not_json(record, e))?
            .map_err(|e| e.in_record(record))
    }
}

impl Decoder<'_> {
    /// Reads the members of the record as those of a signature object.
    fn signature(&mut self) -> Result<Result<Signature, Error>, ParseError> {
        let record = self.record;
        let (mut mechanism, mut key, mut data) = (Member::Absent, Member::Absent, Member::Absent);
        self.json.object()?;
        while let Some(member) = self.json.key()? {
            match Field::of_signature(&member) {
                Some(Field::Mechanism) => mechanism = self.member()?,
                Some(Field::Key) => key = self.member()?,
                Some(Field::Data) => data = self.member()?,
                _ => self.json.skip()?,
            }
        }
        self.json.end()?;
        let not_a_string = |field: Field| {
            Error::manifest(
                Problem::FieldType,
                format!("manifest field '{}' is not a string", field),
            )
            .at(field)
        };
        let Member::Text(mechanism) = mechanism else {
            return Ok(Err(Error::manifest(
                Problem::Signature,
                format!("manifest signature object {} has no 'mechanism' string", record),
            )
            .at(Field::Mechanism)));
        };
        let key = match key {
            Member::Absent => None,
            Member::Other => return Ok(Err(not_a_string(Field::Key))),
            Member::Text(key) => match Hex::decode(&key) {
                Some(key) => Some(key),
                None => {
                    return Ok(Err(Error::manifest(
                        Problem::Signature,
                        format!("manifest signature object {}: 'key' is not hex", record),
                    )
                    .at(Field::Key)));
                }
            },
        };
        let data = match data {
            Member::Absent => None,
            Member::Other => return Ok(Err(not_a_string(Field::Data))),
            Member::Text(data) => match Base64::decode(&data) {
                Some(data) => Some(data),
                None => {
                    return Ok(Err(Error::manifest(
                        Problem::Signature,
                        format!("manifest signature object {}: 'data' is not Base64", record),
                    )
                    .at(Field::Data)));
                }
            },
        };
        let mut signature = Signature::new(mechanism);
        signature.key = key;
        signature.data = data;
        Ok(Ok(signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::testing::{manifest, sequence, EMPTY, HELLO, ROOT, SIGNATURE, TRAILER, WORLD};
    use crate::Manifest;

    /// The one file object of the manifest that has `record` between the
    /// root file object and the trailer.
    fn object(record: &str) -> FileObject {
        let mut m = Manifest::parse(&manifest(&[record])).unwrap_or_else(|e| panic!("{}: {}", record, e));
        assert_eq!(m.objects.len(), 1, "{}", record);
        m.objects.remove(0)
    }

    /// What is wrong with the manifest that has `record` between the root
    /// file object and the trailer.
    fn refused(record: &str) -> Error {
        match Manifest::parse(&manifest(&[record])) {
            Ok(_) => panic!("{} was taken", record),
            Err(e) => e,
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
        assert_eq!(o.mode, Mode::new(0o644));
        assert_eq!((o.uid, o.gid), (Some(1000), Some(100)));
        assert_eq!(o.user_name.as_deref(), Some("Domain Users"));
        assert_eq!(o.group_name.as_deref(), Some("users"));
        assert_eq!((o.major, o.minor), (None, None));
        assert_eq!(o.mtime_nsec, Some(1_700_000_000_000_000_005));
        assert_eq!(o.inode_token, NonZeroU64::new(7));
        let attributes = o.user_xattrs.as_ref().unwrap();
        let listed: Vec<(&str, &[u8])> = attributes.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
        assert_eq!(listed, [("a", &b"x"[..]), ("b", &[0, 0xff])]);
        let gpt = o.gpt.as_deref().unwrap();
        let uuid: Uuid = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709".parse().unwrap();
        assert_eq!(gpt.label.as_deref(), Some("root"));
        assert_eq!((gpt.uuid, gpt.type_uuid), (Some(uuid), Some(uuid)));
        assert_eq!(gpt.flags, Some(Gpt::FLAG_NO_AUTO));
        assert_eq!((gpt.no_auto, gpt.grow_file_system), (Some(true), Some(false)));
        assert_eq!(o.gpt.as_ref().and_then(|gpt| gpt.disk_uuid), None);
        assert_eq!(o.read_only, Some(false));
        assert_eq!(o.sha256, HELLO.parse().ok());
        assert_eq!(o.contents.len(), 2);
        assert_eq!(o.contents[0].url(), Some("https://example.com/x"));
        assert_eq!(o.contents[1].file().map(Name::as_str), Some("blob"));
        assert_eq!((o.contents[1].offset, o.contents[1].original_size), (2, Some(7)));
        assert_eq!(o.contents[1].original_sha256, WORLD.parse().ok());
        assert_eq!((o.valid_since_usec, o.valid_until_usec), (10, Some(20)));
        assert_eq!(o.validity, Validity::Revoked);

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
        let bytes = sequence(&[
            concat!(
                r#"{"extendedAttributes":{"user":{}},"gid":1000,"mTimeNSec":1699999000000000000,"#,
                r#""mediaType":"application/vnd.uapi.16.manifest","mode":509,"uid":1000,"#,
                r#""gptDiskUuid":"4f68bce3-e8cd-4db1-96e7-fbcaf984b709"}"#
            ),
            TRAILER,
        ]);
        let root = Manifest::parse(&bytes).unwrap().root;
        assert!(root.name.is_root());
        assert_eq!(root.inode_type, InodeType::Directory);
        assert_eq!(root.user_xattrs.as_deref().map(BTreeMap::len), Some(0));
        assert_eq!(
            (root.uid, root.gid, root.mode),
            (Some(1000), Some(1000), Mode::new(0o775))
        );
        assert_eq!(root.gpt.as_ref().and_then(|gpt| gpt.disk_uuid), Some(uuid));
        for root in [
            r#"{"mediaType":"application/vnd.uapi.16.manifest","type":"dir","name":null,"inodeToken":0}"#,
            r#"{"type":null,"mediaType":"application/vnd.uapi.16.manifest","size":5,"contents":[{"file":"sub"}]}"#,
        ] {
            assert!(Manifest::parse(&sequence(&[root, TRAILER])).is_ok(), "{}", root);
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
            r#""validUntilUSec":null,"validity":null,"xUnknown":null,"flagHidden":"x","other":{"a":[{}]}}"#
        );
        assert_eq!(object(nulls), o);
        assert_eq!(
            object(r#"{"name":"x","mediaType":"application/vnd.uapi.16.manifest"}"#),
            o
        );
        // Integers as numbers and as decimal strings, up to 64 bits.
        for (text, size) in [
            ("5", 5),
            (r#""5""#, 5),
            (r#""0005""#, 5),
            ("-0", 0),
            ("18446744073709551615", u64::MAX),
            (r#""18446744073709551615""#, u64::MAX),
        ] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","size":{}}}"#, text)).size,
                Some(size),
                "{}",
                text
            );
        }
        // Access modes as numbers and as octal strings.
        for (text, mode) in [
            ("420", 0o644),
            (r#""644""#, 0o644),
            (r#""0644""#, 0o644),
            ("4095", 0o7777),
            (r#""7777""#, 0o7777),
            ("0", 0),
        ] {
            assert_eq!(
                object(&format!(r#"{{"name":"x","mode":{}}}"#, text)).mode,
                Mode::new(mode),
                "{}",
                text
            );
        }
        // The largest ID, and the token of a file with one name.
        assert_eq!(
            object(r#"{"name":"x","uid":4294967294,"gid":"65534"}"#).uid,
            Some(u32::MAX - 1)
        );
        assert_eq!(object(r#"{"name":"x","uid":65536,"gid":65534}"#).gid, Some(65534));
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
                object(&format!(r#"{{"name":"x","validity":"{}"}}"#, text)).validity,
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
                (o.user_name.as_deref(), o.group_name.as_deref()),
                (Some(name), Some(name))
            );
        }
        // A partition label has room for 36 UTF-16 units.
        let label = "x".repeat(Gpt::LABEL_MAX);
        let o = object(&format!(r#"{{"name":"x","gptLabel":"{}"}}"#, label));
        assert_eq!(o.gpt.unwrap().label, Some(label));
        let pairs = "\u{1f600}".repeat(Gpt::LABEL_MAX / 2);
        assert!(object(&format!(r#"{{"name":"x","gptLabel":"{}"}}"#, pairs))
            .gpt
            .is_some());
        for label in [
            format!("{}x", pairs),
            "x".repeat(Gpt::LABEL_MAX + 1),
            "a\tb".into(),
            "a\u{85}b".into(),
        ] {
            let e = refused(&format!(
                r#"{{"name":"x","gptLabel":{}}}"#,
                json::Value::from(label.as_str())
            ));
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::FieldType), "{:?}", label);
        }
        // The flags of a partition agree with the fields for single ones.
        for flags in [
            r#""gptFlags":9223372036854775808,"gptFlagNoAuto":true"#,
            r#""gptFlags":576460752303423488,"gptFlagGrowFileSystem":true,"gptFlagNoAuto":false"#,
            r#""gptFlagNoAuto":true,"gptFlagGrowFileSystem":false"#,
        ] {
            assert!(object(&format!(r#"{{"name":"x",{}}}"#, flags)).gpt.is_some());
        }
        // The longest name, and one byte more.
        let name = "x".repeat(255);
        assert_eq!(object(&format!(r#"{{"name":"{}"}}"#, name)).name, name.as_str());
        let e = refused(&format!(r#"{{"name":"{}x"}}"#, name));
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::InvalidName));
    }

    #[test]
    fn extended_attributes() {
        let attributes = |text: &str| {
            let object = object(&format!(r#"{{"name":"x","extendedAttributes":{}}}"#, text));
            object.user_xattrs.map(|attributes| *attributes)
        };
        // Nothing is said about the namespace, or it is empty.
        assert_eq!(attributes("{}"), None);
        assert_eq!(attributes(r#"{"user":null}"#), None);
        assert_eq!(attributes(r#"{"other":{"a":"b"},"USER":5}"#), None);
        assert_eq!(attributes(r#"{"user":{}}"#), Some(BTreeMap::new()));
        let listed = attributes(concat!(
            r#"{"other":5,"user":{"b":{"text":"2"},"a":{"base64":"AAE="},"c":{"text":""},"#,
            r#""d":{"text":"t","base64":null,"more":1},"e":{"text":"x\u0000y"}}}"#
        ))
        .unwrap();
        let listed: Vec<(&str, &[u8])> = listed.iter().map(|(k, v)| (k.as_str(), &v[..])).collect();
        assert_eq!(
            listed,
            [
                ("a", &[0u8, 1][..]),
                ("b", b"2"),
                ("c", b""),
                ("d", b"t"),
                ("e", b"x\0y")
            ]
        );
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
        let o = object(r#"{"name":"x","contents":[{"literal":"aGVs bG8="}]}"#);
        assert_eq!(o.size, Some(5));
        assert_eq!(
            (o.contents[0].encoded_size, o.contents[0].original_size),
            (Some(5), Some(5))
        );
        let o = object(r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":2}]}"#);
        assert_eq!(o.size, Some(3));
        let o = object(r#"{"name":"x","contents":[{"literal":""}]}"#);
        assert_eq!((o.size, o.sha256), (Some(0), None));
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
        // The first contents object that gives a size gives it.
        let o = object(
            r#"{"name":"x","contents":[{"file":"a","originalSize":5,"offset":1},{"file":"b","originalSize":4}]}"#,
        );
        assert_eq!(o.size, Some(4));
        let e = refused(r#"{"name":"x","contents":[{"file":"a","originalSize":5},{"file":"b","originalSize":4}]}"#);
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::Contradiction));
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
            contents(r#"{"file":null,"url":null,"literal":null,"offset":null,"httpHeaders":{"A":"b"}}"#),
            Contents::default()
        );
        assert_eq!(
            contents(r#"{"file":"data/y.bin"}"#).file().map(Name::as_str),
            Some("data/y.bin")
        );
        for url in ["https://example.com/x", "http://example.com/x", "https://"] {
            assert_eq!(contents(&format!(r#"{{"url":"{}"}}"#, url)).url(), Some(url));
        }
        // Either alphabet of Base64, with whitespace anywhere.
        for (text, data) in [
            ("aGVsbG8=", &b"hello"[..]),
            ("aGVs bG8=", b"hello"),
            ("_-8=", &[0xff, 0xef]),
            ("", b""),
            (" ", b""),
        ] {
            assert_eq!(
                contents(&format!(r#"{{"literal":"{}"}}"#, text)).literal(),
                Some(data),
                "{:?}",
                text
            );
        }
        assert_eq!(
            contents(r#"{"file":"a","encoding":"Zstd"}"#).encoding.as_deref(),
            Some("zstd")
        );
        assert_eq!(contents(r#"{"file":"a","offset":"7"}"#).offset, 7);
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
            (ErrorKind::Manifest(Problem::Contents), Some(Field::Contents))
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
            let mut m =
                Manifest::parse(&sequence(&[ROOT, record, TRAILER])).unwrap_or_else(|e| panic!("{}: {}", record, e));
            m.signatures.remove(0)
        };
        let s = signature(SIGNATURE);
        assert_eq!(
            (s.mechanism.as_str(), s.key, s.data.as_deref()),
            ("pkcs7", None, Some(&[0u8, 0, 0][..]))
        );
        let s = signature(concat!(
            r#"{"data":null,"key":"AB cd\n01","mechanism":"openpgp","other":[1,2],"#,
            r#""mediaType":"application/vnd.uapi.16.signature"}"#
        ));
        assert_eq!(
            (s.mechanism.as_str(), s.key.as_deref(), s.data),
            ("openpgp", Some(&[0xab, 0xcd, 1][..]), None)
        );
        let s = signature(r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"x","key":"","data":""}"#);
        assert_eq!((s.key.as_deref(), s.data.as_deref()), (Some(&[][..]), Some(&[][..])));
    }

    /// The problem as the vectors spell it: its name with a small first
    /// letter.
    fn spelled(problem: Problem) -> String {
        let name = format!("{:?}", problem);
        let (first, rest) = name.split_at(1);
        format!("{}{}", first.to_ascii_lowercase(), rest)
    }

    /// refused.jsonl holds manifests a reader refuses, one to a line: its
    /// records, the problem, the number of the record and the name of the
    /// object the error is about, the field, and what the error says. This
    /// is what the reader said before it was this crate, so the vectors
    /// hold it to that.
    #[test]
    fn refuses_what_the_vectors_refuse() {
        let vectors = include_str!("refused.jsonl");
        let mut problems = std::collections::HashSet::new();
        for line in vectors.lines() {
            let vector = json::parse(line).unwrap();
            let [records, problem, record, name, field, message] = vector.as_array().unwrap() else {
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
            let e = match Manifest::parse(&sequence(&records)) {
                Ok(_) => panic!("{} was taken", line),
                Err(e) => e,
            };
            let ErrorKind::Manifest(found) = e.kind() else {
                panic!("{}: {:?}", line, e);
            };
            assert_eq!(Some(spelled(found).as_str()), problem.as_str(), "{}", line);
            assert_eq!(e.record(), record.as_u64(), "{}", line);
            assert_eq!(e.name(), name.as_str(), "{}", line);
            assert_eq!(e.field().map(Field::as_str), field.as_str(), "{}", line);
            assert_eq!(Some(e.to_string().as_str()), message.as_str(), "{}", line);
            problems.insert(found);
        }
        // Every problem a record can have is among them.
        for problem in [
            Problem::NotJson,
            Problem::NotObject,
            Problem::NoTrailer,
            Problem::DataAfterTrailer,
            Problem::FileAfterSignature,
            Problem::MediaType,
            Problem::FirstHasName,
            Problem::FirstNotDirectory,
            Problem::NoName,
            Problem::InvalidName,
            Problem::UnknownType,
            Problem::FieldType,
            Problem::FieldRange,
            Problem::FieldNotPermitted,
            Problem::Contradiction,
            Problem::Contents,
            Problem::Signature,
            Problem::ExtendedAttributes,
        ] {
            assert!(problems.contains(&problem), "{:?}", problem);
        }
    }
}
