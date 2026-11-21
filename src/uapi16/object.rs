// SPDX-License-Identifier: LGPL-2.1-or-later
//! The objects of a manifest.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::ops::{BitAnd, BitOr, Not};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::decode::ROOT_RECORD;
use crate::error::{Error, ErrorKind, Field, Problem, ValidityProblem};
use crate::hex::Hex;
use crate::{Features, Name, Order, Sha256, STRING_RULES};

/// The inode type of a file object, its `type` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
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
#[non_exhaustive]
pub enum Validity {
    /// `good`, and any value the specification adds later.
    #[default]
    Good,
    /// `revoked`: the file is not to be used anymore.
    Revoked,
}

impl Validity {
    /// The value of `validity` that says this.
    pub const fn as_str(self) -> &'static str {
        match self {
            Validity::Good => "good",
            Validity::Revoked => "revoked",
        }
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// When a file may be used: from `validSinceUSec` on and before
/// `validUntilUSec`, unless `validity` says it is revoked.
///
/// A file object and the root file object both have these fields. What is
/// true of a directory is true of everything in it, so the window of the
/// root file object is that of the whole manifest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValidityWindow {
    /// `validSinceUSec`: the file is not to be used before this time, in
    /// microseconds since the epoch.
    pub since_usec: u64,
    /// `validUntilUSec`: the file is not to be used from this time on, in
    /// microseconds since the epoch.
    pub until_usec: Option<u64>,
    /// `validity`: whether the file is revoked.
    pub state: Validity,
}

impl ValidityWindow {
    /// Checks that what the window is of, which a message calls `subject`,
    /// may be used at the time `now_usec`, in microseconds since the epoch:
    /// that it is not revoked and that the time is inside the window.
    fn check(&self, now_usec: u64, subject: impl fmt::Display) -> Result<(), Error> {
        let (reason, state) = if self.state == Validity::Revoked {
            (ValidityProblem::Revoked, "is revoked")
        } else if now_usec < self.since_usec {
            (ValidityProblem::NotYetValid, "is not valid yet")
        } else if self.until_usec.is_some_and(|until| now_usec >= until) {
            (ValidityProblem::Expired, "has expired")
        } else {
            return Ok(());
        };
        Err(Error::new(
            ErrorKind::NotValid(reason),
            format!("{} {}", subject, state),
        ))
    }
}

/// A UUID, as the `fsUUID`, `gptUuid`, `gptTypeUuid` and `gptDiskUuid`
/// fields carry one.
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
    /// The bytes of the fields the text form writes as groups, which the
    /// hyphens separate. They are named after the fields of the time-based
    /// UUID, version 1 in RFC 9562, whose layout the text form follows.
    const TIME_LOW: usize = 4;
    const TIME_MID: usize = 2;
    const TIME_HIGH_AND_VERSION: usize = 2;
    const CLOCK_SEQ_AND_VARIANT: usize = 2;
    const NODE: usize = 6;
    const GROUPS: [usize; 5] = [
        Uuid::TIME_LOW,
        Uuid::TIME_MID,
        Uuid::TIME_HIGH_AND_VERSION,
        Uuid::CLOCK_SEQ_AND_VARIANT,
        Uuid::NODE,
    ];
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
        // The digits without the hyphens between the groups. Anything else
        // that is not a hex digit fails to decode.
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
        std::str::from_utf8(&digits)
            .ok()
            .and_then(Hex::decode_array)
            .map(Uuid)
            .ok_or(InvalidUuid(()))
    }
}

/// The `gpt` fields of a file object that describe a regular file as a
/// partition of a GPT partition table: those of its entry in the table.
///
/// `gptFlags` holds all attribute flags of the entry. `gptFlagNoAuto`,
/// `gptFlagGrowFileSystem` and `readOnly` give one of them each, and where
/// a flag is given both ways the two agree. Where the manifest lists the
/// feature of one of these fields, a regular file without the field has the
/// flags it gives cleared. A reader checks the fields against each other
/// that way and leaves them as the manifest has them: a regular file
/// without any `gpt` field has no `GptPartition`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GptPartition {
    /// `gptLabel`: the partition label, at most 36 UTF-16 units.
    pub label: Option<String>,
    /// `gptUuid`: the partition UUID.
    pub uuid: Option<Uuid>,
    /// `gptTypeUuid`: the partition type UUID.
    pub type_uuid: Option<Uuid>,
    /// `gptFlags`: the attribute flags of the partition entry.
    pub flags: Option<u64>,
    /// `gptFlagNoAuto`: the flag of that name in the Discoverable
    /// Partitions Specification, [`GptPartition::FLAG_NO_AUTO`].
    pub no_auto: Option<bool>,
    /// `gptFlagGrowFileSystem`: the flag of that name in the Discoverable
    /// Partitions Specification, [`GptPartition::FLAG_GROW_FILE_SYSTEM`].
    pub grow_file_system: Option<bool>,
}

impl GptPartition {
    /// The bits the flags of the Discoverable Partitions Specification
    /// have in the attribute flags.
    const NO_AUTO_BIT: u32 = 63;
    const READ_ONLY_BIT: u32 = 60;
    const GROW_FILE_SYSTEM_BIT: u32 = 59;
    /// The flag `gptFlagNoAuto` mirrors in `gptFlags`.
    pub const FLAG_NO_AUTO: u64 = 1 << GptPartition::NO_AUTO_BIT;
    /// The flag `readOnly` mirrors in `gptFlags`. It has no `gptFlag`
    /// field of its own.
    pub const FLAG_READ_ONLY: u64 = 1 << GptPartition::READ_ONLY_BIT;
    /// The flag `gptFlagGrowFileSystem` mirrors in `gptFlags`.
    pub const FLAG_GROW_FILE_SYSTEM: u64 = 1 << GptPartition::GROW_FILE_SYSTEM_BIT;
    /// The longest partition label, in UTF-16 units.
    pub const LABEL_MAX: usize = 36;

    /// Whether any of the fields is set. Only a regular file describes a
    /// partition.
    pub fn describes_partition(&self) -> bool {
        self.label.is_some()
            || self.uuid.is_some()
            || self.type_uuid.is_some()
            || self.flags.is_some()
            || self.no_auto.is_some()
            || self.grow_file_system.is_some()
    }
}

/// A set of flags of one kind that the specification has a field for each:
/// [`DosFlags`] and [`InodeFlags`]. [`FlagStates`] says the states of the
/// flags of one kind.
///
/// It is public only so that it can bound the methods of [`FlagStates`].
/// The crate does not export it, so no other crate can name or implement
/// it.
pub trait FlagSet:
    Copy + Default + PartialEq + BitAnd<Output = Self> + BitOr<Output = Self> + Not<Output = Self> + 'static
{
    /// Every single flag with its field and the feature that records it, in
    /// the order of the names of the fields.
    const FIELDS: &'static [(Self, Field, Features)];

    /// The flag `field` is the field of.
    fn from_field(field: Field) -> Option<Self> {
        Self::FIELDS
            .iter()
            .find(|&&(_, of, _)| of == field)
            .map(|&(flag, _, _)| flag)
    }

    /// The flags an object of the type `inode_type` may have: every one on
    /// a regular file or a directory, none on any other file.
    fn permitted(inode_type: InodeType) -> Self {
        // The default is no flag, so its complement is every flag.
        let none = Self::default();
        match inode_type {
            InodeType::Regular | InodeType::Directory => !none,
            _ => none,
        }
    }

    /// The flags `features` records.
    fn recorded_by(features: Features) -> Self {
        Self::FIELDS
            .iter()
            .filter(|&&(_, _, feature)| features.contains(feature))
            .fold(Self::default(), |flags, &(flag, _, _)| flags | flag)
    }
}

/// What [`DosFlags`] and [`InodeFlags`] both have besides their flags:
/// `contains()`, `without()`, the operators of sets and a `Debug` that
/// lists the fields of the flags.
macro_rules! flag_set {
    ($flags:ident) => {
        impl $flags {
            /// Whether every flag of `flags` is among these.
            pub const fn contains(self, flags: $flags) -> bool {
                self.0 & flags.0 == flags.0
            }

            /// These flags without those of `flags`.
            #[must_use]
            pub const fn without(self, flags: $flags) -> $flags {
                $flags(self.0 & !flags.0)
            }
        }

        impl BitOr for $flags {
            type Output = $flags;

            fn bitor(self, other: $flags) -> $flags {
                $flags(self.0 | other.0)
            }
        }

        impl BitAnd for $flags {
            type Output = $flags;

            fn bitand(self, other: $flags) -> $flags {
                $flags(self.0 & other.0)
            }
        }

        impl Not for $flags {
            type Output = $flags;

            /// The flags of this kind that are not among these.
            fn not(self) -> $flags {
                $flags::ALL.without(self)
            }
        }

        impl fmt::Debug for $flags {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($flags), "("))?;
                let fields = $flags::FIELDS.iter().filter(|(flag, _, _)| self.contains(*flag));
                for (i, (_, field, _)) in fields.enumerate() {
                    if i > 0 {
                        f.write_str(" | ")?;
                    }
                    f.write_str(field.as_str())?;
                }
                f.write_str(")")
            }
        }
    };
}

/// The DOS attributes the specification has a field for, one each: hidden,
/// system and archive.
///
/// They are the attributes of FAT, of exFAT and of file systems like them.
/// The read-only attribute has no field of its own. `readOnly` stands for
/// it, see [`InodeAttributes::read_only`]. Only regular files and
/// directories have DOS attributes, and the root directory has none: the
/// root directory of FAT has no directory entry to keep them in.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DosFlags(u8);

impl DosFlags {
    /// `flagHidden`: the DOS attribute `ATTR_HIDDEN`.
    pub const HIDDEN: DosFlags = DosFlags(1 << 0);
    /// `flagSystem`: the DOS attribute `ATTR_SYSTEM`.
    pub const SYSTEM: DosFlags = DosFlags(1 << 1);
    /// `flagArchive`: the DOS attribute `ATTR_ARCHIVE`.
    pub const ARCHIVE: DosFlags = DosFlags(1 << 2);

    /// No DOS attribute.
    pub const NONE: DosFlags = DosFlags(0);
    /// Every DOS attribute.
    pub const ALL: DosFlags = DosFlags(DosFlags::HIDDEN.0 | DosFlags::SYSTEM.0 | DosFlags::ARCHIVE.0);
}

impl FlagSet for DosFlags {
    const FIELDS: &'static [(DosFlags, Field, Features)] = &[
        (DosFlags::ARCHIVE, Field::FlagArchive, Features::FLAG_ARCHIVE),
        (DosFlags::HIDDEN, Field::FlagHidden, Features::FLAG_HIDDEN),
        (DosFlags::SYSTEM, Field::FlagSystem, Features::FLAG_SYSTEM),
    ];
}

flag_set!(DosFlags);

/// The Linux inode flags the specification has a field for, one each:
/// some of those `chattr(1)` changes.
///
/// Only regular files and directories have them, the root directory among
/// them.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct InodeFlags(u8);

impl InodeFlags {
    /// `flagAppendOnly`: the inode flag `FS_APPEND_FL`.
    pub const APPEND_ONLY: InodeFlags = InodeFlags(1 << 0);
    /// `flagImmutable`: the inode flag `FS_IMMUTABLE_FL`.
    pub const IMMUTABLE: InodeFlags = InodeFlags(1 << 1);
    /// `flagNoAtime`: the inode flag `FS_NOATIME_FL`.
    pub const NO_ATIME: InodeFlags = InodeFlags(1 << 2);
    /// `flagNoCow`: the inode flag `FS_NOCOW_FL`.
    pub const NO_COW: InodeFlags = InodeFlags(1 << 3);
    /// `flagNoDump`: the inode flag `FS_NODUMP_FL`.
    pub const NO_DUMP: InodeFlags = InodeFlags(1 << 4);

    /// No inode flag.
    pub const NONE: InodeFlags = InodeFlags(0);
    /// Every inode flag.
    pub const ALL: InodeFlags = InodeFlags(
        InodeFlags::APPEND_ONLY.0
            | InodeFlags::IMMUTABLE.0
            | InodeFlags::NO_ATIME.0
            | InodeFlags::NO_COW.0
            | InodeFlags::NO_DUMP.0,
    );
}

impl FlagSet for InodeFlags {
    const FIELDS: &'static [(InodeFlags, Field, Features)] = &[
        (
            InodeFlags::APPEND_ONLY,
            Field::FlagAppendOnly,
            Features::FLAG_APPEND_ONLY,
        ),
        (InodeFlags::IMMUTABLE, Field::FlagImmutable, Features::FLAG_IMMUTABLE),
        (InodeFlags::NO_ATIME, Field::FlagNoAtime, Features::FLAG_NO_ATIME),
        (InodeFlags::NO_COW, Field::FlagNoCow, Features::FLAG_NO_COW),
        (InodeFlags::NO_DUMP, Field::FlagNoDump, Features::FLAG_NO_DUMP),
    ];
}

flag_set!(InodeFlags);

/// What an object says about the flags of one kind, [`DosFlags`] or
/// [`InodeFlags`]: which of them it states, and which of those are set.
/// Nothing is known about the others.
///
/// ```
/// use uapi16::{DosFlags, FlagStates};
///
/// let mut states = FlagStates::default();
/// states.put(DosFlags::HIDDEN, Some(true));
/// states.put(DosFlags::ARCHIVE, Some(false));
/// assert_eq!(states.get(DosFlags::HIDDEN), Some(true));
/// assert_eq!(states.get(DosFlags::ARCHIVE), Some(false));
/// assert_eq!(states.get(DosFlags::SYSTEM), None);
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FlagStates<F> {
    /// The flags the object states.
    pub stated: F,
    /// Of those, the flags that are set.
    pub set: F,
}

impl<F: FlagSet> FlagStates<F> {
    /// Whether `flag` is set, cleared, or not known.
    pub fn get(self, flag: F) -> Option<bool> {
        ((self.stated & flag) == flag).then_some((self.set & flag) == flag)
    }

    /// States `flag` as set or cleared, or as not known.
    pub fn put(&mut self, flag: F, state: Option<bool>) {
        self.stated = self.stated & !flag;
        self.set = self.set & !flag;
        if let Some(set) = state {
            self.stated = self.stated | flag;
            if set {
                self.set = self.set | flag;
            }
        }
    }

    /// The fields of the flags the object states, each with the feature
    /// that records it.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        F::FIELDS
            .iter()
            .filter(move |(flag, _, _)| (self.stated & *flag) == *flag)
            .map(|&(_, field, feature)| (field, feature))
    }

    /// The field of the first flag stated that an object of the type
    /// `inode_type` cannot have. The flags stated are held against those
    /// the type permits all at once, and the fields are only looked through
    /// to name the first flag that is not permitted.
    pub(crate) fn unpermitted_field(&self, inode_type: InodeType) -> Option<Field> {
        let unpermitted = self.stated & !F::permitted(inode_type);
        if unpermitted == F::default() {
            return None;
        }
        F::FIELDS
            .iter()
            .find(|&&(flag, _, _)| (unpermitted & flag) == flag)
            .map(|&(_, field, _)| field)
    }

    /// Fills in what `features`, which a manifest records, say about the
    /// flags an object of the type `inode_type` does not state: a flag the
    /// manifest records is cleared.
    pub(crate) fn fill_in(&mut self, features: Features, inode_type: InodeType) {
        self.stated = self.stated | (F::recorded_by(features) & F::permitted(inode_type));
    }
}

/// The fields of an object of a manifest that a reader filled in, which
/// the record of the object does not have: the sizes and hashes that
/// follow from other fields, and `readOnly`, which is false where the
/// manifest lists `read-only`. A writer leaves them out, and the checks of
/// an object take a filled-in `readOnly` for one that is not there.
///
/// The `size` and the `sha256` of a [`FileObject`], the sizes and hashes
/// of a [`Contents`] and the `readOnly` of [`InodeAttributes`] can be
/// filled in. Each of them notes it in its own `filled_in`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FilledIn(u8);

impl FilledIn {
    /// The fields that can be filled in, in the order of their bits.
    const FIELDS: [Field; 7] = [
        Field::Size,
        Field::Sha256,
        Field::EncodedSize,
        Field::EncodedSha256,
        Field::OriginalSize,
        Field::OriginalSha256,
        Field::ReadOnly,
    ];

    /// The bit of `field`, none for one that cannot be filled in.
    fn bit(field: Field) -> u8 {
        FilledIn::FIELDS
            .iter()
            .position(|&fillable| fillable == field)
            .map_or(0, |at| 1 << at)
    }

    /// Whether `field` was filled in.
    pub fn contains(self, field: Field) -> bool {
        self.0 & FilledIn::bit(field) != 0
    }

    /// Notes that `field` was filled in, if it is one that can be.
    pub fn insert(&mut self, field: Field) {
        self.0 |= FilledIn::bit(field);
    }

    /// Notes that `field` was not filled in, for a value that was set
    /// since.
    pub fn remove(&mut self, field: Field) {
        self.0 &= !FilledIn::bit(field);
    }

    /// The fields that either this or `other` notes, such as those of an
    /// object and those of its inode attributes.
    pub(crate) const fn union(self, other: FilledIn) -> FilledIn {
        FilledIn(self.0 | other.0)
    }
}

impl fmt::Debug for FilledIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilledIn(")?;
        let filled = FilledIn::FIELDS.into_iter().filter(|&field| self.contains(field));
        for (i, field) in filled.enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(field.as_str())?;
        }
        f.write_str(")")
    }
}

/// The 32-bit volume serial number of a FAT or exFAT file system, the
/// field `fatSerial`. It is written as FAT tools show it: two groups of
/// four hexadecimal digits, the upper 16 bits first, `1234-ABCD`.
///
/// ```
/// use uapi16::FatSerial;
///
/// let serial: FatSerial = "1234-abcd".parse()?;
/// assert_eq!(serial, FatSerial(0x1234_abcd));
/// assert_eq!(serial.to_string(), "1234-ABCD");
/// # Ok::<(), uapi16::InvalidFatSerial>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FatSerial(pub u32);

/// A string that is not a FAT volume serial number, see [`FatSerial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFatSerial(());

impl fmt::Display for InvalidFatSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a FAT volume serial number")
    }
}

impl std::error::Error for InvalidFatSerial {}

impl FatSerial {
    /// The hexadecimal digits of each group.
    const GROUP_DIGITS: usize = 4;
    /// The bits of each group.
    const GROUP_BITS: u32 = 16;
    /// What separates the groups.
    const SEPARATOR: char = '-';
    /// The radix of the digits.
    const HEX: u32 = 16;

    /// The serial number the specification derives from a file system
    /// UUID: its first four bytes.
    pub fn from_uuid(uuid: &Uuid) -> FatSerial {
        let [a, b, c, d, ..] = *uuid.as_bytes();
        FatSerial(u32::from_be_bytes([a, b, c, d]))
    }
}

impl fmt::Display for FatSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04X}{}{:04X}",
            self.0 >> FatSerial::GROUP_BITS,
            FatSerial::SEPARATOR,
            self.0 & u32::from(u16::MAX)
        )
    }
}

impl FromStr for FatSerial {
    type Err = InvalidFatSerial;

    fn from_str(text: &str) -> Result<FatSerial, InvalidFatSerial> {
        let group = |digits: &str| {
            // from_str_radix would also take a sign.
            if digits.len() != FatSerial::GROUP_DIGITS || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InvalidFatSerial(()));
            }
            u32::from_str_radix(digits, FatSerial::HEX).map_err(|_| InvalidFatSerial(()))
        };
        let (upper, lower) = text.split_once(FatSerial::SEPARATOR).ok_or(InvalidFatSerial(()))?;
        Ok(FatSerial((group(upper)? << FatSerial::GROUP_BITS) | group(lower)?))
    }
}

/// The identity of the file system the file objects of a manifest are
/// placed in: the fields `fsUUID`, `fsLabel` and `fatSerial`, which only
/// the root file object has.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileSystemIdentity {
    /// `fsUUID`: the UUID of the file system.
    pub uuid: Option<Uuid>,
    /// `fsLabel`: the label of the file system, see
    /// [`FileSystemIdentity::is_valid_label`].
    pub label: Option<String>,
    /// `fatSerial`: the volume serial number of a FAT or exFAT file system.
    pub fat_serial: Option<FatSerial>,
}

impl FileSystemIdentity {
    /// Whether `label` can be the label of a file system in a manifest,
    /// in `fsLabel`: a string a manifest can have, without control
    /// characters. A file system can take less than that.
    ///
    /// ```
    /// use uapi16::FileSystemIdentity;
    ///
    /// assert!(FileSystemIdentity::is_valid_label("ESP"));
    /// assert!(FileSystemIdentity::is_valid_label("A.B \u{e9}"));
    /// assert!(!FileSystemIdentity::is_valid_label("a\tb"));
    /// assert!(!FileSystemIdentity::is_valid_label("a\u{fffe}"));
    /// ```
    pub fn is_valid_label(label: &str) -> bool {
        STRING_RULES.admits(label) && !label.chars().any(char::is_control)
    }

    /// Whether it says nothing.
    pub fn is_empty(&self) -> bool {
        self.uuid.is_none() && self.label.is_none() && self.fat_serial.is_none()
    }

    /// The volume serial number a FAT or exFAT file system takes from the
    /// identity, as the specification has it: `fatSerial`, or else the one
    /// derived from `fsUUID`, see [`FatSerial::from_uuid`]. Returned with
    /// the field it comes from.
    ///
    /// ```
    /// use uapi16::{FatSerial, Field, FileSystemIdentity};
    ///
    /// let mut identity = FileSystemIdentity::default();
    /// identity.uuid = "1234abcd-5678-4ef0-9abc-def012345678".parse().ok();
    /// assert_eq!(identity.volume_serial(), Some((FatSerial(0x1234_abcd), Field::FsUuid)));
    /// identity.fat_serial = Some(FatSerial(0x5678_9abc));
    /// assert_eq!(identity.volume_serial(), Some((FatSerial(0x5678_9abc), Field::FatSerial)));
    /// ```
    pub fn volume_serial(&self) -> Option<(FatSerial, Field)> {
        match (self.fat_serial, &self.uuid) {
            (Some(serial), _) => Some((serial, Field::FatSerial)),
            (None, Some(uuid)) => Some((FatSerial::from_uuid(uuid), Field::FsUuid)),
            (None, None) => None,
        }
    }
}

/// Where a contents object says the data is. It names at most one place.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
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
    /// `httpHeaders`: the header fields of the HTTP requests for the data
    /// at `url`, by name, in the order the manifest lists them.
    pub http_headers: Vec<(String, String)>,
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
    /// The sizes and hashes that follow from the other fields, if a reader
    /// filled them in. Whoever sets another value takes the field out.
    pub filled_in: FilledIn,
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

/// The inode attributes of a file: its access mode, its owner, its
/// modification time and extended attributes, whether it is read-only and
/// its Linux inode flags.
///
/// They are what a file is as an inode rather than as an entry of a
/// directory. A [`FileObject`] has them for its file and the
/// [`RootObject`] for the root directory. The specification calls them so
/// where a directory is described twice: by the file object of the
/// manifest it is in and by the root file object of a sub-manifest of its
/// own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InodeAttributes {
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
    /// `mTimeNSec`: the modification time in nanoseconds since the epoch,
    /// see [`InodeAttributes::mtime`].
    pub mtime_nsec: Option<u64>,
    /// `extendedAttributes`: the extended attributes of the `user`
    /// namespace, by their names without the `user.` in front. None says
    /// nothing about them. A map lists them all, so an empty one says the
    /// file has none.
    pub user_xattrs: Option<Box<BTreeMap<String, Vec<u8>>>>,
    /// `readOnly`: whether the file is read-only, see
    /// [`InodeAttributes::is_read_only`]. It stands for the read-only
    /// attribute of DOS and for [`GptPartition::FLAG_READ_ONLY`] too.
    pub read_only: Option<bool>,
    /// `flagAppendOnly` and the other fields of the inode flags: the
    /// flags the object states.
    pub flags: FlagStates<InodeFlags>,
    /// `readOnly`, if a reader filled it in. Whoever sets another value
    /// takes the field out.
    pub filled_in: FilledIn,
}

impl InodeAttributes {
    /// The fields of the inode attributes that belong to a feature, each
    /// with its feature, in the order of their names. The fields of the
    /// inode flags are in [`InodeFlags::FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 8] = [
        (Field::ExtendedAttributes, Features::USER_XATTR),
        (Field::Gid, Features::GID),
        (Field::GroupName, Features::GROUP_NAME),
        (Field::MTimeNSec, Features::MTIME),
        (Field::Mode, Features::MODE),
        (Field::ReadOnly, Features::READ_ONLY),
        (Field::Uid, Features::UID),
        (Field::UserName, Features::USER_NAME),
    ];

    /// Whether the attributes have `field`, one of
    /// [`InodeAttributes::FEATURE_FIELDS`].
    fn has_feature_field(&self, field: Field) -> bool {
        match field {
            Field::ExtendedAttributes => self.user_xattrs.is_some(),
            Field::Gid => self.gid.is_some(),
            Field::GroupName => self.group_name.is_some(),
            Field::MTimeNSec => self.mtime_nsec.is_some(),
            Field::Mode => self.mode.is_some(),
            Field::ReadOnly => self.stated_read_only().is_some(),
            Field::Uid => self.uid.is_some(),
            Field::UserName => self.user_name.is_some(),
            _ => false,
        }
    }

    /// The fields the attributes have that belong to a feature, each with
    /// its feature.
    fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        InodeAttributes::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.flags.feature_fields())
    }

    /// `readOnly` as the record of the object has it: None where a reader
    /// filled it in.
    pub(crate) fn stated_read_only(&self) -> Option<bool> {
        self.read_only.filter(|_| !self.filled_in.contains(Field::ReadOnly))
    }

    /// Fills in what `features`, which the manifest records, say about the
    /// attributes a file of the type `inode_type` does not have: an inode
    /// flag the manifest records is cleared, the file is not read-only if
    /// the manifest records `readOnly`, which is noted in `filled_in`, and
    /// it has no extended attributes if the manifest records them.
    fn fill_in(&mut self, features: Features, inode_type: InodeType) {
        self.flags.fill_in(features, inode_type);
        if features.contains(Features::READ_ONLY) && self.read_only.is_none() {
            self.read_only = Some(false);
            self.filled_in.insert(Field::ReadOnly);
        }
        if features.contains(Features::USER_XATTR) && self.user_xattrs.is_none() {
            self.user_xattrs = Some(Box::default());
        }
    }

    /// The modification time, if the attributes have one.
    pub fn mtime(&self) -> Option<SystemTime> {
        self.mtime_nsec.map(|nsec| UNIX_EPOCH + Duration::from_nanos(nsec))
    }

    /// Sets the modification time to `time`. `mTimeNSec` counts
    /// nanoseconds since the epoch in 64 bits, which ends in the year
    /// 2554. A time it cannot express leaves the attributes without one.
    pub fn set_mtime(&mut self, time: SystemTime) {
        self.mtime_nsec = time
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos()).ok());
    }

    /// Whether the file gets the read-only attribute in a file system with
    /// DOS attributes, such as FAT: what `readOnly` says, or else whether
    /// `mode` gives nobody write permission. Attributes with neither are
    /// not read-only.
    ///
    /// The specification lets `mode` stand in for `readOnly` for the DOS
    /// attribute only, and only where the manifest does not list the
    /// `read-only` feature. Where it lists it, an object without `readOnly`
    /// is not read-only, and a reader fills that in. The read-only flag of
    /// a GPT partition, [`GptPartition::FLAG_READ_ONLY`], is `readOnly`
    /// alone.
    pub fn is_read_only(&self) -> bool {
        match (self.read_only, self.mode) {
            (Some(read_only), _) => read_only,
            (None, Some(mode)) => !mode.is_writable(),
            (None, None) => false,
        }
    }
}

/// A file object: what a manifest says about one file below its root.
///
/// Every field but the name and the type is optional. What the file is as
/// an inode, its access mode, owner, time and the like, is in
/// [`FileObject::inode`], as it is for the root directory in the
/// [`RootObject`]. A reader fills in what follows from the other fields:
/// the size 0 for the hash of no data and that hash for the size 0, and
/// the size and the hash of a file whose contents object gives them. It
/// notes them in `filled_in`, and a writer leaves them out.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileObject {
    /// `name`: the path of the file below the root.
    pub name: Name,
    /// `type`: the inode type. An object that does not say is a regular
    /// file.
    pub inode_type: InodeType,
    /// `size`: the size of the contents in bytes. For a symbolic link that
    /// is the length of its target, for a directory the size of the
    /// manifest of its own that `contents` refers to.
    pub size: Option<u64>,
    /// `sha256`: the hash of the contents.
    pub sha256: Option<Sha256>,
    /// `contents`: where the contents can be taken from. Without any they
    /// are in the file of the object's name next to the manifest.
    pub contents: Vec<Contents>,
    /// `inodeToken`: the objects that carry the same token are hard links
    /// to one file. None is a file of its own.
    pub inode_token: Option<NonZeroU64>,
    /// `major`: the major number of a device node.
    pub major: Option<u64>,
    /// `minor`: the minor number of a device node.
    pub minor: Option<u64>,
    /// The `gpt` fields, if the object describes a partition.
    pub gpt: Option<Box<GptPartition>>,
    /// `flagHidden`, `flagSystem` and `flagArchive`: the DOS attributes the
    /// object states.
    pub dos_flags: FlagStates<DosFlags>,
    /// The inode attributes of the file.
    pub inode: InodeAttributes,
    /// `validSinceUSec`, `validUntilUSec` and `validity`: when the file may
    /// be used.
    pub validity: ValidityWindow,
    /// The size and the hash, if a reader filled them in. Whoever sets
    /// another value takes the field out.
    pub filled_in: FilledIn,
}

impl FileObject {
    /// The fields of a file object that belong to a feature, each with its
    /// feature, in the order of their names. Those of the DOS attributes
    /// are in [`DosFlags::FIELDS`], those of the inode attributes in
    /// [`InodeAttributes::FEATURE_FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 12] = [
        (Field::Contents, Features::SYMLINK),
        (Field::GptFlagGrowFileSystem, Features::GPT_FLAG_GROW_FILE_SYSTEM),
        (Field::GptFlagNoAuto, Features::GPT_FLAG_NO_AUTO),
        (Field::GptFlags, Features::GPT_FLAGS),
        (Field::GptLabel, Features::GPT_LABEL),
        (Field::GptTypeUuid, Features::GPT_TYPE_UUID),
        (Field::GptUuid, Features::GPT_UUID),
        (Field::InodeToken, Features::HARDLINK),
        (Field::Major, Features::DEVICE),
        (Field::Minor, Features::DEVICE),
        (Field::Sha256, Features::SHA256),
        (Field::Size, Features::SIZE),
    ];

    /// A file object for the regular file `name` that says nothing else
    /// about it.
    pub fn new(name: Name) -> FileObject {
        FileObject {
            name,
            inode_type: InodeType::Regular,
            size: None,
            sha256: None,
            contents: Vec::new(),
            inode_token: None,
            major: None,
            minor: None,
            gpt: None,
            dos_flags: FlagStates::default(),
            inode: InodeAttributes::default(),
            validity: ValidityWindow::default(),
            filled_in: FilledIn::default(),
        }
    }

    /// Whether the object has `field`, one of [`FileObject::FEATURE_FIELDS`],
    /// other than one a reader filled in. `contents` belongs to a feature on
    /// a symbolic link only.
    fn has_feature_field(&self, field: Field) -> bool {
        let gpt = self.gpt.as_deref();
        match field {
            Field::Contents => self.inode_type == InodeType::Symlink && !self.contents.is_empty(),
            Field::GptFlagGrowFileSystem => gpt.is_some_and(|gpt| gpt.grow_file_system.is_some()),
            Field::GptFlagNoAuto => gpt.is_some_and(|gpt| gpt.no_auto.is_some()),
            Field::GptFlags => gpt.is_some_and(|gpt| gpt.flags.is_some()),
            Field::GptLabel => gpt.is_some_and(|gpt| gpt.label.is_some()),
            Field::GptTypeUuid => gpt.is_some_and(|gpt| gpt.type_uuid.is_some()),
            Field::GptUuid => gpt.is_some_and(|gpt| gpt.uuid.is_some()),
            Field::InodeToken => self.inode_token.is_some(),
            Field::Major => self.major.is_some(),
            Field::Minor => self.minor.is_some(),
            Field::Sha256 => self.sha256.is_some() && !self.filled_in.contains(field),
            Field::Size => self.size.is_some() && !self.filled_in.contains(field),
            _ => false,
        }
    }

    /// The fields the object has that belong to a feature, each with its
    /// feature: the fields a manifest that does not record the feature
    /// cannot have. Its own come first, then those of its inode
    /// attributes.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        FileObject::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.dos_flags.feature_fields())
            .chain(self.inode.feature_fields())
    }

    /// The features whose fields the object has, see [`Features`]. A
    /// manifest records them all or the object is not one of its file
    /// objects. What a reader filled in, see [`FilledIn`], does not count.
    pub fn stated_features(&self) -> Features {
        self.feature_fields()
            .fold(Features::NONE, |features, (_, feature)| features | feature)
    }

    /// Fills in what `features`, which its manifest records, say about the
    /// fields the object does not have: a flag the manifest records is
    /// cleared, the file is not read-only if the manifest records
    /// `readOnly`, and it has no extended attributes if the manifest
    /// records them. The `gpt` fields are not filled in, see
    /// [`GptPartition`].
    pub(crate) fn fill_in(&mut self, features: Features) {
        self.dos_flags.fill_in(features, self.inode_type);
        self.inode.fill_in(features, self.inode_type);
    }

    /// The field of the first flag the object states that it cannot have:
    /// only regular files and directories have flags.
    pub(crate) fn unpermitted_flag(&self) -> Option<Field> {
        self.dos_flags
            .unpermitted_field(self.inode_type)
            .or_else(|| self.inode.flags.unpermitted_field(self.inode_type))
    }

    /// Checks that the object may be used at the time `now_usec`, in
    /// microseconds since the epoch: that it is not revoked and that the
    /// time is inside its validity window. What is true of a directory is
    /// true of everything in it.
    pub fn check_validity(&self, now_usec: u64) -> Result<(), Error> {
        self.validity
            .check(now_usec, self.name.escape_debug())
            .map_err(|e| e.named(self.name.as_str()))
    }
}

/// The root file object: what a manifest says about the root directory of
/// the tree it describes, and about the manifest itself.
///
/// It is the first object of a manifest. It has no name and is a
/// directory, so neither is a field here. Like a [`FileObject`] it has the
/// inode attributes of its directory and a validity window, which is that
/// of the whole manifest. The other fields only the root file object has:
/// what the manifest records and the order it lists its file objects in,
/// and the identity of the file system or of the partition table the file
/// objects are placed in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RootObject {
    /// The inode attributes of the root directory.
    pub inode: InodeAttributes,
    /// `fsUUID`, `fsLabel` and `fatSerial`: the identity of the file
    /// system the file objects are placed in.
    pub file_system: FileSystemIdentity,
    /// `gptDiskUuid`: the disk UUID of the GPT partition table the file
    /// objects are placed in as partitions.
    pub gpt_disk_uuid: Option<Uuid>,
    /// `order`: the order the manifest lists its file objects in.
    pub order: Option<Order>,
    /// `features`: what the manifest records. None is
    /// [`Features::DEFAULT`].
    pub features: Option<Features>,
    /// `validSinceUSec`, `validUntilUSec` and `validity`: when the
    /// manifest may be used.
    pub validity: ValidityWindow,
}

impl RootObject {
    /// The fields of the root file object that belong to a feature, each
    /// with its feature, in the order of their names. Those of the inode
    /// attributes are in [`InodeAttributes::FEATURE_FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 4] = [
        (Field::FatSerial, Features::FAT_SERIAL),
        (Field::FsLabel, Features::FS_LABEL),
        (Field::FsUuid, Features::FS_UUID),
        (Field::GptDiskUuid, Features::GPT_DISK_UUID),
    ];

    /// Whether the object has `field`, one of
    /// [`RootObject::FEATURE_FIELDS`].
    fn has_feature_field(&self, field: Field) -> bool {
        match field {
            Field::FatSerial => self.file_system.fat_serial.is_some(),
            Field::FsLabel => self.file_system.label.is_some(),
            Field::FsUuid => self.file_system.uuid.is_some(),
            Field::GptDiskUuid => self.gpt_disk_uuid.is_some(),
            _ => false,
        }
    }

    /// The fields the object has that belong to a feature, each with its
    /// feature: the fields a manifest that does not record the feature
    /// cannot have. Its own come first, then those of its inode
    /// attributes.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        RootObject::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.inode.feature_fields())
    }

    /// The features whose fields the object has, see [`Features`]. A
    /// manifest records them all or this is not its root file object. A
    /// `readOnly` a reader filled in, see [`FilledIn`], does not count.
    pub fn stated_features(&self) -> Features {
        self.feature_fields()
            .fold(Features::NONE, |features, (_, feature)| features | feature)
    }

    /// What the manifest records: the features the root file object lists
    /// in `features`, or [`Features::DEFAULT`] if it lists none.
    pub fn recorded_features(&self) -> Features {
        self.features.unwrap_or(Features::DEFAULT)
    }

    /// Requires the manifest to declare `order` in its root file object, as
    /// a consumer does that relies on the order: a manifest that does not is
    /// [`Problem::NoOrder`], even if its file objects are in that order. A
    /// reader checks the file objects against the order the manifest
    /// declares while it reads them.
    pub fn require_order(&self, order: Order) -> Result<(), Error> {
        if self.order == Some(order) {
            return Ok(());
        }
        Err(Error::manifest(
            Problem::NoOrder,
            format!(
                "the manifest does not declare \"{}\": \"{}\" in its root file object",
                Field::Order,
                order
            ),
        )
        .at(Field::Order)
        .in_record(ROOT_RECORD))
    }

    /// Fills in what `features`, which the manifest records, say about the
    /// fields of the root directory the object does not have, as
    /// [`FileObject::fill_in`] does for a file object.
    pub(crate) fn fill_in(&mut self, features: Features) {
        self.inode.fill_in(features, InodeType::Directory);
    }

    /// Checks that the manifest may be used at the time `now_usec`, in
    /// microseconds since the epoch: that its root file object is not
    /// revoked and that the time is inside its validity window.
    pub fn check_validity(&self, now_usec: u64) -> Result<(), Error> {
        self.validity.check(now_usec, "the manifest")
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
    use crate::Digest;

    /// Gives an object a field.
    type Give<T> = fn(&mut T);

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
        // The groups of the text form are the whole UUID.
        assert_eq!(Uuid::GROUPS.iter().sum::<usize>(), Uuid::SIZE);
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
            // Whitespace, a sign or a prefix where a digit belongs, at the
            // length of a UUID.
            "4f68bce3e8cd4db196e7fbcaf984b7 9",
            " f68bce3e8cd4db196e7fbcaf984b709",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70\n",
            "4f68bce3-e8cd-4db1-96e7-\tbcaf984b709",
            "+f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            "0x68bce3e8cd4db196e7fbcaf984b709",
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
        let mut inode = InodeAttributes::default();
        assert_eq!(inode.mtime(), None);
        inode.set_mtime(UNIX_EPOCH);
        assert_eq!((inode.mtime_nsec, inode.mtime()), (Some(0), Some(UNIX_EPOCH)));
        let time = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        inode.set_mtime(time);
        assert_eq!(inode.mtime_nsec, Some(1_700_000_000_000_000_005));
        assert_eq!(inode.mtime(), Some(time));
        // mTimeNSec holds nanoseconds since the epoch in 64 bits: up to the
        // year 2554, and nothing before 1970.
        let last = UNIX_EPOCH + Duration::from_nanos(u64::MAX);
        inode.set_mtime(last);
        assert_eq!((inode.mtime_nsec, inode.mtime()), (Some(u64::MAX), Some(last)));
        inode.set_mtime(last + Duration::from_nanos(1));
        assert_eq!(inode.mtime_nsec, None);
        inode.set_mtime(UNIX_EPOCH - Duration::from_secs(1));
        assert_eq!(inode.mtime_nsec, None);
    }

    #[test]
    fn read_only() {
        let mut inode = InodeAttributes::default();
        assert!(!inode.is_read_only());
        inode.mode = Mode::new(0o444);
        assert!(inode.is_read_only());
        inode.mode = Mode::new(0o464);
        assert!(!inode.is_read_only());
        inode.read_only = Some(true);
        assert!(inode.is_read_only());
        inode.mode = None;
        assert!(inode.is_read_only());
        inode.read_only = Some(false);
        assert!(!inode.is_read_only());
        // What readOnly says counts, the false a reader fills in too.
        inode.mode = Mode::new(0o444);
        assert!(!inode.is_read_only());
    }

    #[test]
    fn validity() {
        assert_eq!(
            (Validity::Good.as_str(), Validity::Revoked.as_str()),
            ("good", "revoked")
        );
        assert_eq!(Validity::Revoked.to_string(), "revoked");
        assert_eq!(ValidityWindow::default().state, Validity::Good);
        let kind = |object: &FileObject, now| object.check_validity(now).map_err(|e| e.kind());
        let mut object = FileObject::new(Name::new("d/x").unwrap());
        assert_eq!(kind(&object, 0), Ok(()));
        assert_eq!(kind(&object, u64::MAX), Ok(()));
        object.validity.since_usec = 10;
        object.validity.until_usec = Some(20);
        assert_eq!(kind(&object, 9), Err(ErrorKind::NotValid(ValidityProblem::NotYetValid)));
        assert_eq!(kind(&object, 10), Ok(()));
        assert_eq!(kind(&object, 19), Ok(()));
        assert_eq!(kind(&object, 20), Err(ErrorKind::NotValid(ValidityProblem::Expired)));
        let e = object.check_validity(20).unwrap_err();
        assert_eq!((e.name(), e.to_string().as_str()), (Some("d/x"), "d/x has expired"));
        assert_eq!(
            object.check_validity(9).unwrap_err().to_string(),
            "d/x is not valid yet"
        );
        // Revoked whatever the time is.
        object.validity.state = Validity::Revoked;
        for now in [9, 15, 20] {
            assert_eq!(kind(&object, now), Err(ErrorKind::NotValid(ValidityProblem::Revoked)));
        }
        assert_eq!(object.check_validity(15).unwrap_err().to_string(), "d/x is revoked");
        // The root file object speaks for the manifest, which has no name.
        let mut root = RootObject::default();
        assert_eq!(root.check_validity(u64::MAX).map_err(|e| e.kind()), Ok(()));
        root.validity.until_usec = Some(1);
        let e = root.check_validity(1).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotValid(ValidityProblem::Expired));
        assert_eq!((e.name(), e.to_string().as_str()), (None, "the manifest has expired"));
        root.validity.state = Validity::Revoked;
        assert_eq!(
            root.check_validity(0).unwrap_err().to_string(),
            "the manifest is revoked"
        );
    }

    #[test]
    fn flags() {
        // The tables are in the order of the names of the fields, and each
        // has every flag of its kind.
        let dos: Vec<&str> = DosFlags::FIELDS.iter().map(|(_, field, _)| field.as_str()).collect();
        let inode: Vec<&str> = InodeFlags::FIELDS.iter().map(|(_, field, _)| field.as_str()).collect();
        assert!(dos.windows(2).all(|pair| pair[0] < pair[1]), "{:?}", dos);
        assert!(inode.windows(2).all(|pair| pair[0] < pair[1]), "{:?}", inode);
        let every_dos = DosFlags::FIELDS
            .iter()
            .fold(DosFlags::NONE, |every, (flag, _, _)| every | *flag);
        let every_inode = InodeFlags::FIELDS
            .iter()
            .fold(InodeFlags::NONE, |every, (flag, _, _)| every | *flag);
        assert_eq!((every_dos, every_inode), (DosFlags::ALL, InodeFlags::ALL));
        // A field is the field of one kind of flags.
        assert!(dos.iter().all(|field| !inode.contains(field)));
        for &(flag, _, _) in DosFlags::FIELDS {
            assert_eq!((!flag & flag, !flag | flag), (DosFlags::NONE, DosFlags::ALL));
        }
        for &(flag, _, _) in InodeFlags::FIELDS {
            assert_eq!((!flag & flag, !flag | flag), (InodeFlags::NONE, InodeFlags::ALL));
        }
        assert_eq!((!DosFlags::NONE, !InodeFlags::ALL), (DosFlags::ALL, InodeFlags::NONE));
        let flags = DosFlags::HIDDEN | DosFlags::ARCHIVE;
        assert!(flags.contains(DosFlags::ARCHIVE) && !flags.contains(DosFlags::ALL));
        assert_eq!(flags.without(DosFlags::ARCHIVE), DosFlags::HIDDEN);
        assert_eq!(format!("{:?}", flags), "DosFlags(flagArchive | flagHidden)");
        assert_eq!(
            format!("{:?}", InodeFlags::NO_COW | InodeFlags::APPEND_ONLY),
            "InodeFlags(flagAppendOnly | flagNoCow)"
        );
        assert_eq!(format!("{:?}", InodeFlags::NONE), "InodeFlags()");
        // What an object says about the flags of one kind.
        let mut states = FlagStates::default();
        assert_eq!(states.get(InodeFlags::IMMUTABLE), None);
        states.put(InodeFlags::IMMUTABLE, Some(true));
        states.put(InodeFlags::NO_DUMP, Some(false));
        assert_eq!(states.get(InodeFlags::IMMUTABLE), Some(true));
        assert_eq!(states.get(InodeFlags::NO_DUMP), Some(false));
        assert_eq!(states.get(InodeFlags::NO_COW), None);
        assert_eq!(states.stated, InodeFlags::IMMUTABLE | InodeFlags::NO_DUMP);
        assert_eq!(states.set, InodeFlags::IMMUTABLE);
        states.put(InodeFlags::IMMUTABLE, Some(false));
        assert_eq!(states.get(InodeFlags::IMMUTABLE), Some(false));
        states.put(InodeFlags::IMMUTABLE, None);
        states.put(InodeFlags::NO_DUMP, None);
        assert_eq!(states, FlagStates::default());
    }

    #[test]
    fn features_of_the_fields() {
        const UUID: Uuid = Uuid::new([1; Uuid::SIZE]);
        // Every feature has a field, of a file object or of the root file
        // object, and every table is in the order of the names.
        let tables: [&[(Field, Features)]; 3] = [
            &InodeAttributes::FEATURE_FIELDS,
            &FileObject::FEATURE_FIELDS,
            &RootObject::FEATURE_FIELDS,
        ];
        for table in tables {
            assert!(
                table.windows(2).all(|pair| pair[0].0.as_str() < pair[1].0.as_str()),
                "{:?}",
                table
            );
        }
        let dos = DosFlags::FIELDS.iter().map(|&(_, field, feature)| (field, feature));
        let inode = InodeFlags::FIELDS.iter().map(|&(_, field, feature)| (field, feature));
        let every = tables
            .iter()
            .flat_map(|table| table.iter().copied())
            .chain(dos)
            .chain(inode)
            .fold(Features::NONE, |every, (_, feature)| every | feature);
        assert_eq!(every, Features::ALL);
        // A field makes a file object state its feature.
        assert_eq!(
            FileObject::new(Name::new("f").unwrap()).stated_features(),
            Features::NONE
        );
        let partition = |set: Give<GptPartition>| {
            let mut gpt = GptPartition::default();
            set(&mut gpt);
            Some(Box::new(gpt))
        };
        let cases: [(Give<FileObject>, Features); 14] = [
            (|o| o.size = Some(1), Features::SIZE),
            (|o| o.sha256 = Some(Sha256::EMPTY), Features::SHA256),
            (|o| o.inode_token = NonZeroU64::new(1), Features::HARDLINK),
            (|o| o.major = Some(1), Features::DEVICE),
            (|o| o.minor = Some(1), Features::DEVICE),
            (
                |o| o.dos_flags.put(DosFlags::HIDDEN, Some(false)),
                Features::FLAG_HIDDEN,
            ),
            (|o| o.dos_flags.put(DosFlags::SYSTEM, Some(true)), Features::FLAG_SYSTEM),
            (
                |o| o.dos_flags.put(DosFlags::ARCHIVE, Some(true)),
                Features::FLAG_ARCHIVE,
            ),
            (|o| o.inode.mode = Mode::new(0o644), Features::MODE),
            (|o| o.inode.uid = Some(0), Features::UID),
            (|o| o.inode.user_name = Some("u".into()), Features::USER_NAME),
            (|o| o.inode.mtime_nsec = Some(0), Features::MTIME),
            (|o| o.inode.user_xattrs = Some(Box::default()), Features::USER_XATTR),
            (|o| o.inode.read_only = Some(false), Features::READ_ONLY),
        ];
        for (set, feature) in cases {
            let mut object = FileObject::new(Name::new("f").unwrap());
            set(&mut object);
            assert_eq!(object.stated_features(), feature, "{:?}", object);
        }
        let partitions: [(Give<GptPartition>, Features); 6] = [
            (|gpt| gpt.label = Some("l".into()), Features::GPT_LABEL),
            (|gpt| gpt.uuid = Some(UUID), Features::GPT_UUID),
            (|gpt| gpt.type_uuid = Some(UUID), Features::GPT_TYPE_UUID),
            (|gpt| gpt.flags = Some(0), Features::GPT_FLAGS),
            (|gpt| gpt.no_auto = Some(false), Features::GPT_FLAG_NO_AUTO),
            (
                |gpt| gpt.grow_file_system = Some(true),
                Features::GPT_FLAG_GROW_FILE_SYSTEM,
            ),
        ];
        for (set, feature) in partitions {
            let mut object = FileObject::new(Name::new("f").unwrap());
            object.gpt = partition(set);
            assert_eq!(object.stated_features(), feature, "{:?}", object);
        }
        let mut object = FileObject::new(Name::new("f").unwrap());
        (object.inode.gid, object.inode.group_name) = (Some(0), Some("g".into()));
        assert_eq!(object.stated_features(), Features::GID | Features::GROUP_NAME);
        for &(flag, _, feature) in InodeFlags::FIELDS {
            let mut object = FileObject::new(Name::new("f").unwrap());
            object.inode.flags.put(flag, Some(true));
            assert_eq!(object.stated_features(), feature, "{:?}", flag);
        }
        // The contents of a symbolic link are its target, which a feature
        // records. Those of other files are not.
        let mut object = FileObject::new(Name::new("f").unwrap());
        object.contents = vec![Contents::new(Location::Literal(b"t".to_vec()))];
        assert_eq!(object.stated_features(), Features::NONE);
        object.inode_type = InodeType::Symlink;
        assert_eq!(object.stated_features(), Features::SYMLINK);
        // What a reader filled in does not count.
        let mut object = FileObject::new(Name::new("f").unwrap());
        (object.size, object.sha256) = (Some(0), Some(Sha256::EMPTY));
        object.filled_in.insert(Field::Size);
        assert_eq!(object.stated_features(), Features::SHA256);
        object.filled_in.insert(Field::Sha256);
        assert_eq!(object.stated_features(), Features::NONE);
        // The fields of the root file object, its inode attributes among
        // them.
        assert_eq!(RootObject::default().stated_features(), Features::NONE);
        let cases: [(Give<RootObject>, Features); 6] = [
            (|r| r.file_system.uuid = Some(UUID), Features::FS_UUID),
            (|r| r.file_system.label = Some("ESP".into()), Features::FS_LABEL),
            (|r| r.file_system.fat_serial = Some(FatSerial(1)), Features::FAT_SERIAL),
            (|r| r.gpt_disk_uuid = Some(UUID), Features::GPT_DISK_UUID),
            (|r| r.inode.mtime_nsec = Some(0), Features::MTIME),
            (
                |r| r.inode.flags.put(InodeFlags::NO_COW, Some(false)),
                Features::FLAG_NO_COW,
            ),
        ];
        for (set, feature) in cases {
            let mut root = RootObject::default();
            set(&mut root);
            assert_eq!(root.stated_features(), feature, "{:?}", root);
        }
        // order and features describe the manifest, no feature records
        // them.
        let mut root = RootObject::default();
        (root.order, root.features) = (Some(Order::CodePoint), Some(Features::ALL));
        assert_eq!(root.stated_features(), Features::NONE);
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
