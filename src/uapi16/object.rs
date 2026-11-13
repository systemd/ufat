// SPDX-License-Identifier: LGPL-2.1-or-later
//! The objects of a manifest.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{Error, ErrorKind, Invalid};
use crate::hex::Hex;
use crate::{Name, Sha256};

/// The inode type of a file object, its `type` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InodeType {
    /// `reg`: a regular file.
    Regular,
    /// `dir`: a directory.
    Directory,
    /// `lnk`: a symbolic link.
    Symlink,
    /// `fifo`: a FIFO.
    Fifo,
    /// `chr`: a character device node.
    CharDevice,
    /// `blk`: a block device node.
    BlockDevice,
    /// `sock`: a socket.
    Socket,
}

/// A string that is not the name of an inode type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownInodeType(());

impl fmt::Display for UnknownInodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an inode type")
    }
}

impl std::error::Error for UnknownInodeType {}

impl InodeType {
    /// The name the type has in a manifest.
    pub const fn as_str(self) -> &'static str {
        match self {
            InodeType::Regular => "reg",
            InodeType::Directory => "dir",
            InodeType::Symlink => "lnk",
            InodeType::Fifo => "fifo",
            InodeType::CharDevice => "chr",
            InodeType::BlockDevice => "blk",
            InodeType::Socket => "sock",
        }
    }

    /// Whether an object of this type has contents: a regular file its
    /// data, a symbolic link its target and a directory a manifest of its
    /// own. Only such an object has a size, contents objects and a hash.
    pub const fn has_contents(self) -> bool {
        matches!(self, InodeType::Regular | InodeType::Symlink | InodeType::Directory)
    }

    /// Whether this is a device node, which has a major and a minor
    /// number.
    pub const fn is_device(self) -> bool {
        matches!(self, InodeType::CharDevice | InodeType::BlockDevice)
    }
}

impl fmt::Display for InodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InodeType {
    type Err = UnknownInodeType;

    fn from_str(name: &str) -> Result<InodeType, UnknownInodeType> {
        Ok(match name {
            "reg" => InodeType::Regular,
            "dir" => InodeType::Directory,
            "lnk" => InodeType::Symlink,
            "fifo" => InodeType::Fifo,
            "chr" => InodeType::CharDevice,
            "blk" => InodeType::BlockDevice,
            "sock" => InodeType::Socket,
            _ => return Err(UnknownInodeType(())),
        })
    }
}

/// The access mode of a file object, its `mode` field: the permission
/// bits with the set-user-ID, the set-group-ID and the sticky bit.
///
/// ```
/// use uapi16::Mode;
///
/// let mode = Mode::new(0o644).unwrap();
/// assert!(mode.is_writable());
/// assert!(!Mode::new(0o444).unwrap().is_writable());
/// assert_eq!(Mode::new(0o10000), None);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mode(u32);

impl Mode {
    /// Every bit a mode can have.
    const ALL: u32 = libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX | libc::S_IRWXU | libc::S_IRWXG | libc::S_IRWXO;
    /// The write permission of the owner, of the group and of everybody
    /// else.
    const WRITE: u32 = libc::S_IWUSR | libc::S_IWGRP | libc::S_IWOTH;

    /// The mode with the bits `bits`, unless there are others among them
    /// than a mode has.
    pub const fn new(bits: u32) -> Option<Mode> {
        if bits & !Mode::ALL == 0 {
            Some(Mode(bits))
        } else {
            None
        }
    }

    /// The bits of the mode.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether anybody has write permission.
    pub const fn is_writable(self) -> bool {
        self.0 & Mode::WRITE != 0
    }
}

impl From<Mode> for u32 {
    fn from(mode: Mode) -> u32 {
        mode.0
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mode({:#o})", self.0)
    }
}

/// The `validity` field of a file object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Validity {
    /// `good`, and any value the specification adds later.
    #[default]
    Good,
    /// `revoked`: the file is not to be used anymore.
    Revoked,
}

/// A UUID, as the `gptUuid`, `gptTypeUuid` and `gptDiskUuid` fields carry
/// one.
///
/// It prints the way RFC 9562 writes it, in lower case. It parses from
/// that form in either case, from 32 hex digits without the hyphens, and
/// from both with `urn:uuid:` in front.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; Uuid::SIZE]);

/// A string that is not a UUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidUuid(());

impl fmt::Display for InvalidUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a UUID")
    }
}

impl std::error::Error for InvalidUuid {}

impl Uuid {
    /// The size of a UUID in bytes.
    pub const SIZE: usize = 16;
    /// The bytes of the groups the hyphens separate.
    const GROUPS: [usize; 5] = [4, 2, 2, 2, 6];
    /// What separates the groups.
    const HYPHEN: u8 = b'-';
    /// What a UUID can have in front, in either case.
    const URN: &'static str = "urn:uuid:";
    /// The hex digits of one byte.
    const DIGITS_PER_BYTE: usize = 2;

    /// The UUID with the bytes `bytes`.
    pub const fn new(bytes: [u8; Uuid::SIZE]) -> Uuid {
        Uuid(bytes)
    }

    /// The bytes of the UUID.
    pub fn as_bytes(&self) -> &[u8; Uuid::SIZE] {
        &self.0
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = &self.0[..];
        for (i, &group) in Uuid::GROUPS.iter().enumerate() {
            if i > 0 {
                fmt::Write::write_char(f, char::from(Uuid::HYPHEN))?;
            }
            let (bytes, tail) = rest.split_at(group);
            Hex(bytes).fmt(f)?;
            rest = tail;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({})", self)
    }
}

impl FromStr for Uuid {
    type Err = InvalidUuid;

    fn from_str(text: &str) -> Result<Uuid, InvalidUuid> {
        // Compare bytes: the string comes from a manifest, and cutting it
        // at a byte offset could cut a character.
        let text = match text.as_bytes().split_at_checked(Uuid::URN.len()) {
            Some((urn, rest)) if urn.eq_ignore_ascii_case(Uuid::URN.as_bytes()) => rest,
            _ => text.as_bytes(),
        };
        let mut digits = [0u8; Uuid::SIZE * Uuid::DIGITS_PER_BYTE];
        let hyphens = Uuid::GROUPS.len() - 1;
        let hyphenated = text.len() == digits.len() + hyphens;
        if !hyphenated && text.len() != digits.len() {
            return Err(InvalidUuid(()));
        }
        // The digits without the hyphens between the groups.
        let mut out = &mut digits[..];
        let mut rest = text;
        for (i, &group) in Uuid::GROUPS.iter().enumerate() {
            if hyphenated && i > 0 {
                rest = rest.strip_prefix(&[Uuid::HYPHEN]).ok_or(InvalidUuid(()))?;
            }
            let (hex, tail) = rest
                .split_at_checked(group * Uuid::DIGITS_PER_BYTE)
                .ok_or(InvalidUuid(()))?;
            let (group_digits, left) = out.split_at_mut(hex.len());
            group_digits.copy_from_slice(hex);
            out = left;
            rest = tail;
        }
        // Hex takes whitespace between digits, a UUID has none.
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(InvalidUuid(()));
        }
        std::str::from_utf8(&digits)
            .ok()
            .and_then(Hex::decode_array)
            .map(Uuid)
            .ok_or(InvalidUuid(()))
    }
}

/// The `gpt` fields of a file object: what describes a regular file as a
/// partition of a GPT partition table and, on the root file object, the
/// UUID of the table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Gpt {
    /// `gptDiskUuid`: the disk UUID of the partition table. Only the root
    /// file object has it.
    pub disk_uuid: Option<Uuid>,
    /// `gptLabel`: the partition label, at most 36 UTF-16 units.
    pub label: Option<String>,
    /// `gptUuid`: the partition UUID.
    pub uuid: Option<Uuid>,
    /// `gptTypeUuid`: the partition type UUID.
    pub type_uuid: Option<Uuid>,
    /// `gptFlags`: the attribute flags of the partition entry.
    pub flags: Option<u64>,
    /// `gptFlagNoAuto`: the flag of that name in the Discoverable
    /// Partitions Specification, [`Gpt::FLAG_NO_AUTO`].
    pub no_auto: Option<bool>,
    /// `gptFlagGrowFileSystem`: the flag of that name in the Discoverable
    /// Partitions Specification, [`Gpt::FLAG_GROW_FILE_SYSTEM`].
    pub grow_file_system: Option<bool>,
}

impl Gpt {
    /// The bits the flags of the Discoverable Partitions Specification
    /// have in the attribute flags.
    const NO_AUTO_BIT: u32 = 63;
    const GROW_FILE_SYSTEM_BIT: u32 = 59;
    /// The flag `gptFlagNoAuto` mirrors in `gptFlags`.
    pub const FLAG_NO_AUTO: u64 = 1 << Gpt::NO_AUTO_BIT;
    /// The flag `gptFlagGrowFileSystem` mirrors in `gptFlags`.
    pub const FLAG_GROW_FILE_SYSTEM: u64 = 1 << Gpt::GROW_FILE_SYSTEM_BIT;
    /// The longest partition label, in UTF-16 units.
    pub const LABEL_MAX: usize = 36;

    /// Whether any field is set that describes a partition. Only a regular
    /// file has those.
    pub fn describes_partition(&self) -> bool {
        self.label.is_some()
            || self.uuid.is_some()
            || self.type_uuid.is_some()
            || self.flags.is_some()
            || self.no_auto.is_some()
            || self.grow_file_system.is_some()
    }
}

/// Where a contents object says the data is. It names at most one place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Location {
    /// Neither `file`, `url` nor `literal` is given: the data is in the
    /// file of the object's own name, next to the manifest.
    #[default]
    Implied,
    /// `file`: the data is in this file next to the manifest.
    File(Name),
    /// `url`: the data is at this http or https URL.
    Url(String),
    /// `literal`: the data is in the manifest, and here.
    Literal(Vec<u8>),
}

/// A contents object: one place the data of a file object can be taken
/// from, and how it is stored there.
///
/// The data can be stored in an encoding, such as gzip. The encoded sizes
/// and hashes are those of the data as it is stored, the original ones
/// those of the decoded data. The file object's data is the part of the
/// decoded data that starts at `offset`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Contents {
    /// `file`, `url` or `literal`: where the data is.
    pub location: Location,
    /// `encoding`: the HTTP content coding the data is stored in, in
    /// lower case. None is no encoding.
    pub encoding: Option<String>,
    /// `encodedSize`: the size of the data as it is stored.
    pub encoded_size: Option<u64>,
    /// `encodedSha256`: the hash of the data as it is stored.
    pub encoded_sha256: Option<Sha256>,
    /// `originalSize`: the size of the decoded data.
    pub original_size: Option<u64>,
    /// `originalSha256`: the hash of the decoded data.
    pub original_sha256: Option<Sha256>,
    /// `offset`: where the file object's data starts in the decoded data.
    pub offset: u64,
}

impl Contents {
    /// A contents object for data in the place `location`, stored as it
    /// is.
    pub fn new(location: Location) -> Contents {
        Contents {
            location,
            ..Contents::default()
        }
    }

    /// The data the manifest carries itself, if this is where the data
    /// is.
    pub fn literal(&self) -> Option<&[u8]> {
        match &self.location {
            Location::Literal(data) => Some(data),
            _ => None,
        }
    }

    /// The file next to the manifest the data is in, if `file` names one.
    pub fn file(&self) -> Option<&Name> {
        match &self.location {
            Location::File(name) => Some(name),
            _ => None,
        }
    }

    /// The URL the data is at, if this is where the data is.
    pub fn url(&self) -> Option<&str> {
        match &self.location {
            Location::Url(url) => Some(url),
            _ => None,
        }
    }
}

/// A file object: what a manifest says about one file, or about the root
/// of the tree.
///
/// Every field but the name and the type is optional. A reader fills in
/// what follows from the other fields: the size 0 for the hash of no data
/// and that hash for the size 0, and the size and the hash of a file
/// whose contents object gives them.
///
/// The root file object is the first object of a manifest. It has no
/// name, which is the empty name here, and is a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileObject {
    /// `name`: the path of the file below the root. The root file object
    /// has [`Name::ROOT`].
    pub name: Name,
    /// `type`: the inode type. An object that does not say is a regular
    /// file, and the root file object is a directory.
    pub inode_type: InodeType,
    /// `size`: the size of the contents in bytes. For a symbolic link that
    /// is the length of its target, for a directory the size of the
    /// manifest of its own that `contents` refers to.
    pub size: Option<u64>,
    /// `mode`: the access mode.
    pub mode: Option<Mode>,
    /// `uid`: the owning user.
    pub uid: Option<u32>,
    /// `gid`: the owning group.
    pub gid: Option<u32>,
    /// `userName`: the name of the owning user.
    pub user_name: Option<Box<str>>,
    /// `groupName`: the name of the owning group.
    pub group_name: Option<Box<str>>,
    /// `major`: the major number of a device node.
    pub major: Option<u64>,
    /// `minor`: the minor number of a device node.
    pub minor: Option<u64>,
    /// `mTimeNSec`: the modification time in nanoseconds since the epoch,
    /// see [`FileObject::mtime`].
    pub mtime_nsec: Option<u64>,
    /// `inodeToken`: the objects that carry the same token are hard links
    /// to one file. None is a file of its own.
    pub inode_token: Option<NonZeroU64>,
    /// `extendedAttributes`: the extended attributes of the `user`
    /// namespace, by their names without the `user.` in front. None says
    /// nothing about them. A map lists them all, so an empty one says the
    /// file has none.
    pub user_xattrs: Option<Box<BTreeMap<String, Vec<u8>>>>,
    /// The `gpt` fields, if the object has any.
    pub gpt: Option<Box<Gpt>>,
    /// `readOnly`: whether the file is read-only, see
    /// [`FileObject::is_read_only`].
    pub read_only: Option<bool>,
    /// `contents`: where the contents can be taken from. Without any they
    /// are in the file of the object's name next to the manifest.
    pub contents: Vec<Contents>,
    /// `sha256`: the hash of the contents.
    pub sha256: Option<Sha256>,
    /// `validSinceUSec`: the file is not to be used before this time, in
    /// microseconds since the epoch.
    pub valid_since_usec: u64,
    /// `validUntilUSec`: the file is not to be used from this time on, in
    /// microseconds since the epoch.
    pub valid_until_usec: Option<u64>,
    /// `validity`: whether the file is revoked.
    pub validity: Validity,
}

impl FileObject {
    /// A file object of the type `inode_type` that says nothing else.
    fn blank(name: Name, inode_type: InodeType) -> FileObject {
        FileObject {
            name,
            inode_type,
            size: None,
            mode: None,
            uid: None,
            gid: None,
            user_name: None,
            group_name: None,
            major: None,
            minor: None,
            mtime_nsec: None,
            inode_token: None,
            user_xattrs: None,
            gpt: None,
            read_only: None,
            contents: Vec::new(),
            sha256: None,
            valid_since_usec: 0,
            valid_until_usec: None,
            validity: Validity::Good,
        }
    }

    /// A file object for the regular file `name` that says nothing else
    /// about it.
    pub fn new(name: Name) -> FileObject {
        FileObject::blank(name, InodeType::Regular)
    }

    /// A root file object that says nothing about the root.
    pub fn root() -> FileObject {
        FileObject::blank(Name::ROOT, InodeType::Directory)
    }

    /// The modification time, if the object has one.
    pub fn mtime(&self) -> Option<SystemTime> {
        self.mtime_nsec.map(|nsec| UNIX_EPOCH + Duration::from_nanos(nsec))
    }

    /// Sets the modification time to `time`. `mTimeNSec` counts
    /// nanoseconds since the epoch in 64 bits, which ends in the year
    /// 2554. A time it cannot express leaves the object without one.
    pub fn set_mtime(&mut self, time: SystemTime) {
        self.mtime_nsec = time
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos()).ok());
    }

    /// Whether the file is read-only: what `readOnly` says, or else
    /// whether `mode` gives nobody write permission. An object with
    /// neither is not read-only.
    pub fn is_read_only(&self) -> bool {
        match (self.read_only, self.mode) {
            (Some(read_only), _) => read_only,
            (None, Some(mode)) => !mode.is_writable(),
            (None, None) => false,
        }
    }

    /// Checks that the object may be used at the time `now_usec`, in
    /// microseconds since the epoch: that it is not revoked and that the
    /// time is inside its validity window. What is true of a directory is
    /// true of everything in it, and what is true of the root file object
    /// is true of the whole manifest.
    pub fn check_validity(&self, now_usec: u64) -> Result<(), Error> {
        let what = if self.name.is_root() {
            "the manifest"
        } else {
            self.name.as_str()
        };
        let (reason, state) = if self.validity == Validity::Revoked {
            (Invalid::Revoked, "is revoked")
        } else if now_usec < self.valid_since_usec {
            (Invalid::NotYetValid, "is not valid yet")
        } else if self.valid_until_usec.is_some_and(|until| now_usec >= until) {
            (Invalid::Expired, "has expired")
        } else {
            return Ok(());
        };
        Err(Error::new(ErrorKind::NotValid(reason), format!("{} {}", what, state)).named(self.name.as_str()))
    }
}

/// A signature object: a signature over the manifest up to the first
/// signature object.
///
/// A manifest can carry several. This crate reads them and does not
/// verify them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Signature {
    /// `mechanism`: how the signature was made. The specification has
    /// `openpgp` and `pkcs7`.
    pub mechanism: String,
    /// `key`: what identifies the key, such as its fingerprint.
    pub key: Option<Vec<u8>>,
    /// `data`: the signature.
    pub data: Option<Vec<u8>>,
}

impl Signature {
    /// A signature object of the mechanism `mechanism`, without a key
    /// and without data.
    pub fn new(mechanism: impl Into<String>) -> Signature {
        Signature {
            mechanism: mechanism.into(),
            key: None,
            data: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manifest in memory is its file objects, so their size is what a
    /// large manifest costs.
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn a_file_object_is_small() {
        const WORD: usize = size_of::<usize>();
        assert!(size_of::<FileObject>() <= 32 * WORD, "{}", size_of::<FileObject>());
        assert!(size_of::<Contents>() <= 21 * WORD, "{}", size_of::<Contents>());
    }

    #[test]
    fn inode_types() {
        for (name, inode_type) in [
            ("reg", InodeType::Regular),
            ("dir", InodeType::Directory),
            ("lnk", InodeType::Symlink),
            ("fifo", InodeType::Fifo),
            ("chr", InodeType::CharDevice),
            ("blk", InodeType::BlockDevice),
            ("sock", InodeType::Socket),
        ] {
            assert_eq!(name.parse(), Ok(inode_type));
            assert_eq!(inode_type.as_str(), name);
            assert_eq!(inode_type.to_string(), name);
            assert_eq!(
                inode_type.has_contents(),
                ["reg", "dir", "lnk"].contains(&name),
                "{}",
                name
            );
            assert_eq!(inode_type.is_device(), ["chr", "blk"].contains(&name), "{}", name);
        }
        for name in ["", "REG", "file", "symlink", "reg "] {
            assert!(name.parse::<InodeType>().is_err(), "{:?}", name);
        }
    }

    #[test]
    fn modes() {
        for bits in [0, 0o644, 0o755, 0o4755, 0o7777] {
            let mode = Mode::new(bits).unwrap();
            assert_eq!(mode.bits(), bits);
            assert_eq!(u32::from(mode), bits);
        }
        assert_eq!(Mode::new(0o10000), None);
        assert_eq!(Mode::new(0o100644), None);
        assert_eq!(Mode::new(u32::MAX), None);
        for (bits, writable) in [
            (0o644, true),
            (0o444, false),
            (0o020, true),
            (0o002, true),
            (0o555, false),
            (0o7555, false),
            (0, false),
        ] {
            assert_eq!(Mode::new(bits).unwrap().is_writable(), writable, "{:o}", bits);
        }
        assert_eq!(format!("{:?}", Mode::new(0o644).unwrap()), "Mode(0o644)");
    }

    #[test]
    fn uuids() {
        let bytes = [
            0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09,
        ];
        let uuid = Uuid::new(bytes);
        let text = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
        assert_eq!(uuid.to_string(), text);
        assert_eq!(format!("{:?}", uuid), format!("Uuid({})", text));
        assert_eq!(uuid.as_bytes(), &bytes);
        for spelling in [
            text.to_string(),
            text.to_uppercase(),
            text.replace('-', ""),
            format!("urn:uuid:{}", text),
            format!("URN:UUID:{}", text.to_uppercase()),
            format!("urn:uuid:{}", text.replace('-', "")),
        ] {
            assert_eq!(spelling.parse(), Ok(uuid), "{}", spelling);
        }
        for bad in [
            "",
            "not-a-uuid",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b7090",
            "4f68bce3e8cd-4db1-96e7-fbcaf984b709",
            "4f68bce3-e8cd-4db1-96e7fbcaf984b709-",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70g",
            "4f68bce3 e8cd 4db1 96e7 fbcaf984b709",
            "4f68bce3e8cd4db196e7fbcaf984b70 9",
            "{4f68bce3-e8cd-4db1-96e7-fbcaf984b709}",
            "urn:uuid:",
            "uuid:4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            // Characters of more than one byte, where a cut by bytes
            // would fall inside one.
            "12345678\u{e9}",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b7\u{e9}",
        ] {
            assert!(bad.parse::<Uuid>().is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn times() {
        let mut object = FileObject::new(Name::new("a").unwrap());
        assert_eq!(object.mtime(), None);
        object.set_mtime(UNIX_EPOCH);
        assert_eq!((object.mtime_nsec, object.mtime()), (Some(0), Some(UNIX_EPOCH)));
        let time = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        object.set_mtime(time);
        assert_eq!(object.mtime_nsec, Some(1_700_000_000_000_000_005));
        assert_eq!(object.mtime(), Some(time));
        // mTimeNSec holds nanoseconds since the epoch in 64 bits: up to the
        // year 2554, and nothing before 1970.
        let last = UNIX_EPOCH + Duration::from_nanos(u64::MAX);
        object.set_mtime(last);
        assert_eq!((object.mtime_nsec, object.mtime()), (Some(u64::MAX), Some(last)));
        object.set_mtime(last + Duration::from_nanos(1));
        assert_eq!(object.mtime_nsec, None);
        object.set_mtime(UNIX_EPOCH - Duration::from_secs(1));
        assert_eq!(object.mtime_nsec, None);
    }

    #[test]
    fn read_only() {
        let mut object = FileObject::new(Name::new("a").unwrap());
        assert!(!object.is_read_only());
        object.mode = Mode::new(0o444);
        assert!(object.is_read_only());
        object.mode = Mode::new(0o464);
        assert!(!object.is_read_only());
        object.read_only = Some(true);
        assert!(object.is_read_only());
        object.mode = None;
        assert!(object.is_read_only());
        object.read_only = Some(false);
        assert!(!object.is_read_only());
    }

    #[test]
    fn validity() {
        let kind = |object: &FileObject, now| object.check_validity(now).map_err(|e| e.kind());
        let mut object = FileObject::new(Name::new("d/x").unwrap());
        assert_eq!(kind(&object, 0), Ok(()));
        assert_eq!(kind(&object, u64::MAX), Ok(()));
        object.valid_since_usec = 10;
        object.valid_until_usec = Some(20);
        assert_eq!(kind(&object, 9), Err(ErrorKind::NotValid(Invalid::NotYetValid)));
        assert_eq!(kind(&object, 10), Ok(()));
        assert_eq!(kind(&object, 19), Ok(()));
        assert_eq!(kind(&object, 20), Err(ErrorKind::NotValid(Invalid::Expired)));
        let e = object.check_validity(20).unwrap_err();
        assert_eq!((e.name(), e.to_string().as_str()), (Some("d/x"), "d/x has expired"));
        assert_eq!(
            object.check_validity(9).unwrap_err().to_string(),
            "d/x is not valid yet"
        );
        // Revoked whatever the time is.
        object.validity = Validity::Revoked;
        for now in [9, 15, 20] {
            assert_eq!(kind(&object, now), Err(ErrorKind::NotValid(Invalid::Revoked)));
        }
        assert_eq!(object.check_validity(15).unwrap_err().to_string(), "d/x is revoked");
        // The root file object speaks for the manifest.
        let mut root = FileObject::root();
        assert_eq!((root.name.is_root(), root.inode_type), (true, InodeType::Directory));
        root.valid_until_usec = Some(1);
        let e = root.check_validity(1).unwrap_err();
        assert_eq!(
            (e.name(), e.to_string().as_str()),
            (Some(""), "the manifest has expired")
        );
    }

    #[test]
    fn contents_objects() {
        let contents = Contents::default();
        assert_eq!(contents.location, Location::Implied);
        assert_eq!(
            (contents.literal(), contents.file(), contents.url()),
            (None, None, None)
        );
        let literal = Contents::new(Location::Literal(b"data".to_vec()));
        assert_eq!(literal.literal(), Some(&b"data"[..]));
        assert_eq!((literal.file(), literal.url(), literal.offset), (None, None, 0));
        let file = Contents::new(Location::File(Name::new("blob").unwrap()));
        assert_eq!(file.file().map(Name::as_str), Some("blob"));
        let url = Contents::new(Location::Url("https://example.com/x".to_string()));
        assert_eq!(url.url(), Some("https://example.com/x"));
    }
}
