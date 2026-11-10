// SPDX-License-Identifier: LGPL-2.1-or-later
//! Checking a volume for consistency.
//!
//! The check is read-only. It reads the boot sector and its backup, the
//! FSInfo sector, every FAT copy and the whole directory tree, and reports
//! each deviation from what Linux, EDK2 and the FAT specification expect.
//! Problems that make readers fail or refuse the volume, or that put data at
//! risk, are errors; everything else is a warning.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fmt;
use std::ops::Range;

use crate::boot::{
    BootSector, FsInfo, BOOT_SECTOR_SIZE, FSINFO_UNKNOWN, FS_TYPE_FAT32, NO_NAME, NT_FLAGS_OFFSET, NT_FLAG_DIRTY,
};
use crate::device::Device;
use crate::dirent::{
    short_name_checksum, RawDirEntry, ATTR_LONG_NAME, ATTR_RESERVED, DIR_ENTRY_SIZE, DOTDOT_NAME, DOT_NAME,
    ENTRY_DELETED, ENTRY_E5_ESCAPE, ENTRY_END,
};
use crate::errno::*;
use crate::fat::{
    media_entry, BitSet, Entry, Fat, CACHE_BYTES, END_OF_CHAIN_MIN, ENTRY1_CLEAN_SHUTDOWN, ENTRY1_NO_HARD_ERROR,
    ENTRY_MASK,
};
use crate::format::decode_label;
use crate::layout::Layout;
use crate::name::{
    fold_str, join_long_name, parse_long_name_entry, short_name_to_string, valid_short_char, LongNameEntry,
    LFN_MAX_ENTRIES, LONG_NAME_INVALID, MAX_LONG_NAME,
};
use crate::progress::Progress;
use crate::volume::DeviceStore;
use crate::{Detail, NotFat32Reason, Result};

/// How serious a problem is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Cosmetic or recoverable without data loss.
    Warning,
    /// Readers may fail or refuse the volume, or data is at risk.
    Error,
}

/// What a finding is about, the same for every file system; the kind says
/// which finding in FAT's own vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemClass {
    /// The boot sector, its backup or the FSInfo sector.
    Superblock,
    /// The FAT's entries, and what a file has allocated against its size.
    Allocation,
    /// The structure of a directory: its entries and their fields, the dot
    /// entries, the long name entry sets.
    Directory,
    /// The text of a name.
    Name,
    /// A timestamp field.
    Timestamp,
    /// The volume label.
    Label,
    /// A cluster chain that is broken or loops.
    Chain,
    /// A cluster two chains use.
    CrossLink,
    /// Clusters allocated but referenced by nothing.
    LostSpace,
    /// A dirty or error flag a driver left behind.
    Dirty,
    /// Copies or checksums that do not agree.
    Checksum,
    /// The journal; FAT has none.
    Journal,
    /// A volume that is valid but that some readers refuse or misread.
    Interoperability,
    /// Nothing of the above.
    Other,
}

impl ProblemClass {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ProblemClass::Superblock => "superblock",
            ProblemClass::Allocation => "allocation",
            ProblemClass::Directory => "directory",
            ProblemClass::Name => "name",
            ProblemClass::Timestamp => "timestamp",
            ProblemClass::Label => "label",
            ProblemClass::Chain => "chain",
            ProblemClass::CrossLink => "crossLink",
            ProblemClass::LostSpace => "lostSpace",
            ProblemClass::Dirty => "dirty",
            ProblemClass::Checksum => "checksum",
            ProblemClass::Journal => "journal",
            ProblemClass::Interoperability => "interoperability",
            ProblemClass::Other => "other",
        }
    }
}

/// What a finding is about, one value per kind of finding. The fields of
/// [`Problem`] a kind sets are listed with it; `path` is the entry or
/// directory the finding is about and is set wherever one exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemKind {
    /// A boot sector field makes no sense: `field` names it.
    BootSector,
    /// The boot sector claims more sectors than the device has: `value`
    /// the sectors claimed, `size_bytes` what they come to, `expected`
    /// the device's bytes.
    ClaimsMoreThanDevice,
    /// The volume is marked dirty in the boot sector's NT flags.
    DirtyFlag,
    /// Fewer clusters than the FAT32 minimum: `clusters`, `expected`.
    BelowMinimumClusters,
    /// The 0x55AA boot signature is missing.
    BootSignatureMissing,
    /// The file system type string is not "FAT32   ": `name` what it is.
    FileSystemTypeString,
    /// The backup boot sector differs from the boot sector: `copy` is its
    /// sector number.
    BackupBootSectorDiffers,
    /// The volume has no backup boot sector.
    NoBackupBootSector,
    /// The FSInfo sector's signatures are invalid.
    FsinfoSignatures,
    /// The FSInfo sector lacks its trailing signature.
    FsinfoTrailingSignature,
    /// The FSInfo free cluster count is wrong: `value` the count,
    /// `expected` the clusters that are free.
    FsinfoFreeCount,
    /// The FSInfo next free hint is not a valid cluster: `cluster`.
    FsinfoNextFree,
    /// FAT entry 0 does not carry the media byte: `value`, `expected`.
    FatMediaEntry,
    /// FAT entry 1 says the volume was not cleanly unmounted: `value`.
    FatDirtyFlag,
    /// FAT entry 1 says a driver recorded hardware errors: `value`.
    FatHardwareErrorFlag,
    /// FAT entry 1 is not an end of chain marker: `value`.
    FatEntry1,
    /// A FAT copy differs from the first: `copy`, `count` the differing
    /// bytes.
    FatCopyDiffers,
    /// A chain points at an invalid cluster: `path`, `cluster`.
    ChainInvalidCluster,
    /// A chain loops: `path`, `cluster` where it does.
    ChainLoop,
    /// Reading the FAT failed: `path` when about a chain, `cluster`.
    FatReadFailed,
    /// A cluster of a chain is marked free: `path`, `cluster`.
    ChainClusterFree,
    /// A cluster of a chain is marked bad: `path`, `cluster`.
    ChainClusterBad,
    /// A cluster of a chain holds an invalid FAT entry: `path`, `cluster`,
    /// `value`.
    ChainEntryInvalid,
    /// A cluster is used by two chains: `path`, `cluster`, `other_path`
    /// the other owner when it is known.
    CrossLinked,
    /// More cross-linked clusters than are listed: `count`.
    CrossLinkedMore,
    /// A directory spans more clusters than its slots allow: `path`,
    /// `clusters`, `slots` the maximum, `expected` the clusters checked.
    DirectoryTooLong,
    /// A slot in use after the end of directory marker: `path`, `slot`,
    /// `value` the marker's slot.
    EntryAfterEnd,
    /// Long name entries that belong to no short entry: `path`, `slot`
    /// the first, `slots` how many.
    OrphanedLongName,
    /// A long name entry carries the last-entry bit inside its set:
    /// `path`, `slot`.
    LongNameLastBitInside,
    /// A long name entry has non-zero reserved bytes: `path`, `slot`.
    LongNameReservedBytes,
    /// A long name entry with an invalid sequence byte: `path`, `slot`,
    /// `value`.
    LongNameBadSequence,
    /// Long name entries that do not belong to the short entry after them:
    /// `path`, `slot`, `slots`, `name` the short name.
    LongNameMismatch,
    /// A volume label entry outside the root directory: `path`, `name`.
    LabelOutsideRoot,
    /// A volume label entry with a cluster or size: `path`, `name`.
    LabelEntryHasData,
    /// A volume label with lower case letters: `path`, `name`.
    LabelLowerCase,
    /// An attribute byte with reserved bits set: `path`, `value`.
    AttributeReservedBits,
    /// A name used twice in a directory: `path`.
    DuplicateName,
    /// A directory entry with a size: `path`, `size_bytes`.
    DirectoryEntrySize,
    /// A directory starting at a cluster that is not allowed: `path`,
    /// `cluster`.
    DirectoryStartCluster,
    /// More than one volume label entry: `path`, `count`.
    LabelEntries,
    /// The root directory's label and the boot sector's differ: `name`,
    /// `other_name`.
    LabelMismatch,
    /// A label only in the boot sector: `name`.
    LabelOnlyInBootSector,
    /// The "." or ".." entry is missing: `path`, `name` which.
    DotEntryMissing,
    /// A long name longer than allowed: `path`, `count` its UTF-16 units,
    /// `expected` the maximum.
    LongNameTooLong,
    /// Long name entries not padded with 0x0000 then 0xFFFF: `path`.
    LongNamePadding,
    /// A long name ending with a dot: `path`.
    LongNameTrailingDot,
    /// A long name ending with a space: `path`.
    LongNameTrailingSpace,
    /// A long name with invalid characters: `path`.
    LongNameInvalidCharacters,
    /// A short name starting with a space: `path`.
    ShortNameLeadingSpace,
    /// A short name with lower case letters: `path`.
    ShortNameLowerCase,
    /// A short name with invalid characters: `path`.
    ShortNameInvalidCharacters,
    /// An invalid date: `path`, `field` which one (creation, modification,
    /// access), `value` the date word.
    DateInvalid,
    /// An invalid time: `path`, `field` which one (creation,
    /// modification), `value` the time word.
    TimeInvalid,
    /// Creation time hundredths out of range: `path`, `value`.
    CreationHundredthsInvalid,
    /// The root directory has a "." or ".." entry: `name` which.
    RootHasDotEntry,
    /// A "." or ".." entry that is not a directory: `path`, `name`.
    DotEntryNotDirectory,
    /// A "." or ".." entry pointing at the wrong cluster: `path`, `name`,
    /// `cluster`, `expected`.
    DotEntryCluster,
    /// A ".." entry pointing at the root cluster instead of 0: `path`,
    /// `cluster`.
    DotDotPointsAtRoot,
    /// A "." or ".." entry in the wrong slot: `path`, `name`, `slot`,
    /// `expected`.
    DotEntrySlot,
    /// A file with a size but no clusters: `path`, `size_bytes`.
    SizeWithoutClusters,
    /// A file with fewer clusters than its size needs: `path`,
    /// `size_bytes`, `clusters`, `clusters_needed`.
    TooFewClusters,
    /// A file with more clusters than its size needs: `path`, `size_bytes`,
    /// `clusters`, `clusters_needed`.
    TooManyClusters,
    /// Clusters allocated but referenced by nothing: `count`.
    LostClusters,
    /// FAT entries with bits set in their reserved nibble: `count`.
    ReservedBitsSet,
}

impl ProblemKind {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        use ProblemKind::*;
        match self {
            BootSector => "bootSector",
            ClaimsMoreThanDevice => "claimsMoreThanDevice",
            DirtyFlag => "dirtyFlag",
            BelowMinimumClusters => "belowMinimumClusters",
            BootSignatureMissing => "bootSignatureMissing",
            FileSystemTypeString => "fileSystemTypeString",
            BackupBootSectorDiffers => "backupBootSectorDiffers",
            NoBackupBootSector => "noBackupBootSector",
            FsinfoSignatures => "fsinfoSignatures",
            FsinfoTrailingSignature => "fsinfoTrailingSignature",
            FsinfoFreeCount => "fsinfoFreeCount",
            FsinfoNextFree => "fsinfoNextFree",
            FatMediaEntry => "fatMediaEntry",
            FatDirtyFlag => "fatDirtyFlag",
            FatHardwareErrorFlag => "fatHardwareErrorFlag",
            FatEntry1 => "fatEntry1",
            FatCopyDiffers => "fatCopyDiffers",
            ChainInvalidCluster => "chainInvalidCluster",
            ChainLoop => "chainLoop",
            FatReadFailed => "fatReadFailed",
            ChainClusterFree => "chainClusterFree",
            ChainClusterBad => "chainClusterBad",
            ChainEntryInvalid => "chainEntryInvalid",
            CrossLinked => "crossLinked",
            CrossLinkedMore => "crossLinkedMore",
            DirectoryTooLong => "directoryTooLong",
            EntryAfterEnd => "entryAfterEnd",
            OrphanedLongName => "orphanedLongName",
            LongNameLastBitInside => "longNameLastBitInside",
            LongNameReservedBytes => "longNameReservedBytes",
            LongNameBadSequence => "longNameBadSequence",
            LongNameMismatch => "longNameMismatch",
            LabelOutsideRoot => "labelOutsideRoot",
            LabelEntryHasData => "labelEntryHasData",
            LabelLowerCase => "labelLowerCase",
            AttributeReservedBits => "attributeReservedBits",
            DuplicateName => "duplicateName",
            DirectoryEntrySize => "directoryEntrySize",
            DirectoryStartCluster => "directoryStartCluster",
            LabelEntries => "labelEntries",
            LabelMismatch => "labelMismatch",
            LabelOnlyInBootSector => "labelOnlyInBootSector",
            DotEntryMissing => "dotEntryMissing",
            LongNameTooLong => "longNameTooLong",
            LongNamePadding => "longNamePadding",
            LongNameTrailingDot => "longNameTrailingDot",
            LongNameTrailingSpace => "longNameTrailingSpace",
            LongNameInvalidCharacters => "longNameInvalidCharacters",
            ShortNameLeadingSpace => "shortNameLeadingSpace",
            ShortNameLowerCase => "shortNameLowerCase",
            ShortNameInvalidCharacters => "shortNameInvalidCharacters",
            DateInvalid => "dateInvalid",
            TimeInvalid => "timeInvalid",
            CreationHundredthsInvalid => "creationHundredthsInvalid",
            RootHasDotEntry => "rootHasDotEntry",
            DotEntryNotDirectory => "dotEntryNotDirectory",
            DotEntryCluster => "dotEntryCluster",
            DotDotPointsAtRoot => "dotDotPointsAtRoot",
            DotEntrySlot => "dotEntrySlot",
            SizeWithoutClusters => "sizeWithoutClusters",
            TooFewClusters => "tooFewClusters",
            TooManyClusters => "tooManyClusters",
            LostClusters => "lostClusters",
            ReservedBitsSet => "reservedBitsSet",
        }
    }

    /// The class of the finding, see [`ProblemClass`].
    pub fn class(self) -> ProblemClass {
        use ProblemKind::*;
        match self {
            // The boot sector, its backup and the FSInfo sector.
            BootSector
            | ClaimsMoreThanDevice
            | BootSignatureMissing
            | BackupBootSectorDiffers
            | NoBackupBootSector
            | FsinfoSignatures
            | FsinfoTrailingSignature
            | FsinfoFreeCount
            | FsinfoNextFree => ProblemClass::Superblock,
            // FAT entries, the FAT itself, and a file's clusters against
            // its size.
            FatMediaEntry | FatEntry1 | FatReadFailed | ReservedBitsSet | SizeWithoutClusters | TooFewClusters
            | TooManyClusters => ProblemClass::Allocation,
            // The volume's state flags: not cleanly unmounted, hardware
            // errors seen.
            DirtyFlag | FatDirtyFlag | FatHardwareErrorFlag => ProblemClass::Dirty,
            // Copies and checksums that disagree.
            FatCopyDiffers | LongNameMismatch => ProblemClass::Checksum,
            ChainInvalidCluster | ChainLoop | ChainClusterFree | ChainClusterBad | ChainEntryInvalid => {
                ProblemClass::Chain
            }
            CrossLinked | CrossLinkedMore => ProblemClass::CrossLink,
            LostClusters => ProblemClass::LostSpace,
            // Directory structure: entries and their fields, dot entries,
            // long name entry sets.
            DirectoryTooLong
            | EntryAfterEnd
            | OrphanedLongName
            | LongNameLastBitInside
            | LongNameReservedBytes
            | LongNameBadSequence
            | LongNamePadding
            | AttributeReservedBits
            | DuplicateName
            | DirectoryEntrySize
            | DirectoryStartCluster
            | DotEntryMissing
            | RootHasDotEntry
            | DotEntryNotDirectory
            | DotEntryCluster
            | DotDotPointsAtRoot
            | DotEntrySlot => ProblemClass::Directory,
            // The text of a name.
            LongNameTooLong
            | LongNameTrailingDot
            | LongNameTrailingSpace
            | LongNameInvalidCharacters
            | ShortNameLeadingSpace
            | ShortNameLowerCase
            | ShortNameInvalidCharacters => ProblemClass::Name,
            DateInvalid | TimeInvalid | CreationHundredthsInvalid => ProblemClass::Timestamp,
            LabelOutsideRoot
            | LabelEntryHasData
            | LabelLowerCase
            | LabelEntries
            | LabelMismatch
            | LabelOnlyInBootSector => ProblemClass::Label,
            // Valid volumes that EDK2 or U-Boot refuse.
            BelowMinimumClusters | FileSystemTypeString => ProblemClass::Interoperability,
        }
    }
}

/// One finding: its kind and the facts about it, each set when the kind
/// has it (see [`ProblemKind`]). The English sentence for the command
/// line comes from its `Display`; a Varlink client renders the fields in
/// its own language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub kind: ProblemKind,
    /// The entry or directory the finding is about.
    pub path: Option<String>,
    /// The other entry involved, for a cross-link.
    pub other_path: Option<String>,
    /// A directory slot, the first of several.
    pub slot: Option<u32>,
    /// How many slots.
    pub slots: Option<u32>,
    /// A cluster.
    pub cluster: Option<u32>,
    /// How many clusters there are.
    pub clusters: Option<u64>,
    /// How many clusters were needed.
    pub clusters_needed: Option<u64>,
    /// A size in bytes.
    pub size_bytes: Option<u64>,
    /// A field's value as found: a FAT entry, a count, a timestamp word.
    pub value: Option<u64>,
    /// What the value should have been.
    pub expected: Option<u64>,
    /// A name the finding quotes: a label, a short name, "." or "..".
    pub name: Option<String>,
    /// The second name when two disagree.
    pub other_name: Option<String>,
    /// A boot sector field or a timestamp field.
    pub field: Option<&'static str>,
    /// A FAT copy or a sector number.
    pub copy: Option<u32>,
    /// A count of things.
    pub count: Option<u64>,
}

impl Problem {
    /// A finding of `kind` with no facts yet; the severity is set when it
    /// is recorded.
    pub fn new(kind: ProblemKind) -> Problem {
        Problem {
            severity: Severity::Error,
            kind,
            path: None,
            other_path: None,
            slot: None,
            slots: None,
            cluster: None,
            clusters: None,
            clusters_needed: None,
            size_bytes: None,
            value: None,
            expected: None,
            name: None,
            other_name: None,
            field: None,
            copy: None,
            count: None,
        }
    }

    fn path(mut self, path: String) -> Problem {
        self.path = Some(path);
        self
    }

    fn other_path(mut self, path: Option<String>) -> Problem {
        self.other_path = path;
        self
    }

    fn slot(mut self, slot: u32) -> Problem {
        self.slot = Some(slot);
        self
    }

    fn slots(mut self, slots: u32) -> Problem {
        self.slots = Some(slots);
        self
    }

    fn cluster(mut self, cluster: u32) -> Problem {
        self.cluster = Some(cluster);
        self
    }

    fn clusters(mut self, clusters: u64) -> Problem {
        self.clusters = Some(clusters);
        self
    }

    fn clusters_needed(mut self, clusters: u64) -> Problem {
        self.clusters_needed = Some(clusters);
        self
    }

    fn size_bytes(mut self, size: u64) -> Problem {
        self.size_bytes = Some(size);
        self
    }

    fn value(mut self, value: u64) -> Problem {
        self.value = Some(value);
        self
    }

    fn expected(mut self, expected: u64) -> Problem {
        self.expected = Some(expected);
        self
    }

    fn name(mut self, name: impl Into<String>) -> Problem {
        self.name = Some(name.into());
        self
    }

    fn other_name(mut self, name: impl Into<String>) -> Problem {
        self.other_name = Some(name.into());
        self
    }

    fn field(mut self, field: &'static str) -> Problem {
        self.field = Some(field);
        self
    }

    fn copy(mut self, copy: u32) -> Problem {
        self.copy = Some(copy);
        self
    }

    fn count(mut self, count: u64) -> Problem {
        self.count = Some(count);
        self
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProblemKind::*;
        let path = self.path.as_deref().unwrap_or("?");
        let name = self.name.as_deref().unwrap_or("");
        let other_name = self.other_name.as_deref().unwrap_or("");
        let field = self.field.unwrap_or("?");
        let slot = self.slot.unwrap_or(0);
        let slots = self.slots.unwrap_or(0);
        let cluster = self.cluster.unwrap_or(0);
        let clusters = self.clusters.unwrap_or(0);
        let needed = self.clusters_needed.unwrap_or(0);
        let size = self.size_bytes.unwrap_or(0);
        let value = self.value.unwrap_or(0);
        let expected = self.expected.unwrap_or(0);
        let copy = self.copy.unwrap_or(0);
        let count = self.count.unwrap_or(0);
        match self.kind {
            BootSector => write!(f, "boot sector: the {} field is invalid", field),
            ClaimsMoreThanDevice => write!(
                f,
                "the boot sector claims {} sectors ({} bytes) but the device has only {} bytes",
                value, size, expected
            ),
            DirtyFlag => f.write_str(
                "the volume is marked dirty in the boot sector: it is mounted read-write or was not cleanly unmounted; Linux leaves the mark, Windows offers to scan the volume and fsck.fat -a acts on it",
            ),
            BelowMinimumClusters => write!(
                f,
                "{} clusters is below the FAT32 minimum of {}: EDK2 firmware refuses the volume, Linux and the Windows driver still mount it as FAT32",
                clusters, expected
            ),
            BootSignatureMissing => f.write_str("boot sector signature is missing"),
            FileSystemTypeString => write!(
                f,
                "the file system type string is {:?} instead of \"FAT32   \"; U-Boot does not recognise the volume without it",
                name
            ),
            BackupBootSectorDiffers => {
                write!(f, "the backup boot sector in sector {} differs from the boot sector", copy)
            }
            NoBackupBootSector => f.write_str("the volume has no backup boot sector"),
            FsinfoSignatures => f.write_str("the FSInfo sector has invalid signatures"),
            FsinfoTrailingSignature => {
                f.write_str("the FSInfo sector lacks its trailing signature, EDK2 ignores its contents")
            }
            FsinfoFreeCount => write!(
                f,
                "the FSInfo free cluster count is {} but {} clusters are free",
                value, expected
            ),
            FsinfoNextFree => write!(f, "the FSInfo next free hint {} is not a valid cluster", cluster),
            FatMediaEntry => write!(
                f,
                "FAT entry 0 is 0x{:08x}, expected 0x{:08x}; GRUB refuses the volume",
                value, expected
            ),
            FatDirtyFlag => write!(
                f,
                "FAT entry 1 is 0x{:08x}, bit 27 is clear: the volume was not cleanly unmounted; EDK2 firmware and Windows read it as dirty",
                value
            ),
            FatHardwareErrorFlag => write!(
                f,
                "FAT entry 1 is 0x{:08x}, bit 26 is clear: a driver recorded hardware errors",
                value
            ),
            FatEntry1 => write!(f, "FAT entry 1 is 0x{:08x}, expected an end of chain marker", value),
            FatCopyDiffers => write!(
                f,
                "FAT copy {} differs from the first FAT in {} bytes; Linux and EDK2 read the first copy, fsck.fat copies it over the others",
                copy, count
            ),
            ChainInvalidCluster => write!(f, "{}: chain points at invalid cluster {}", path, cluster),
            ChainLoop => write!(f, "{}: cluster chain loops at cluster {}", path, cluster),
            FatReadFailed => match &self.path {
                Some(p) => write!(f, "{}: reading the FAT failed at cluster {}", p, cluster),
                None => write!(f, "reading the FAT failed at cluster {}", cluster),
            },
            ChainClusterFree => write!(f, "{}: cluster {} in the chain is marked free", path, cluster),
            ChainClusterBad => write!(f, "{}: cluster {} in the chain is marked bad", path, cluster),
            ChainEntryInvalid => write!(
                f,
                "{}: cluster {} holds the invalid FAT entry 0x{:08x}",
                path, cluster, value
            ),
            CrossLinked => match &self.other_path {
                Some(other) => write!(
                    f,
                    "{}: cluster {} is also used by {} (cross-linked)",
                    path, cluster, other
                ),
                None => write!(
                    f,
                    "{}: cluster {} is also used by another chain (cross-linked)",
                    path, cluster
                ),
            },
            CrossLinkedMore => write!(f, "{} more cross-linked clusters are not listed", count),
            DirectoryTooLong => write!(
                f,
                "{}: directory spans {} clusters, more than the {} entry slots a directory can have (Linux stops adding entries at 2 MiB); only the first {} clusters are checked",
                path, clusters, slots, expected
            ),
            EntryAfterEnd => write!(
                f,
                "{}: slot {} is in use after the end of directory marker in slot {}; Linux (since 7.2) stops reading at the marker and refuses to create an entry over it",
                path, slot, value
            ),
            OrphanedLongName if slots == 1 => write!(f, "{}: orphaned long name entry in slot {}", path, slot),
            OrphanedLongName => write!(
                f,
                "{}: orphaned long name entries in slots {}..{}",
                path,
                slot,
                slot + slots
            ),
            LongNameLastBitInside => write!(
                f,
                "{}: long name entry in slot {} carries the last-entry bit inside its set; EDK2 cuts the name there",
                path, slot
            ),
            LongNameReservedBytes => write!(
                f,
                "{}: long name entry in slot {} has non-zero bytes at offset 12 or 26; EDK2 does not accept the entry",
                path, slot
            ),
            LongNameBadSequence => write!(
                f,
                "{}: long name entry in slot {} has the invalid sequence byte {:#04x}; Linux skips it",
                path, slot, value
            ),
            LongNameMismatch => write!(
                f,
                "{}: long name entries in slots {}..{} do not belong to '{}' (checksum or sequence mismatch)",
                path,
                slot,
                slot + slots,
                name
            ),
            LabelOutsideRoot => write!(f, "{}: volume label entry '{}' outside the root directory", path, name),
            LabelEntryHasData => write!(f, "{}: volume label entry '{}' has a cluster or size", path, name),
            LabelLowerCase => write!(f, "{}: volume label '{}' contains lower case letters", path, name),
            AttributeReservedBits => write!(
                f,
                "{}: attribute byte 0x{:02x} has reserved bits set; GRUB hides the entry",
                path, value
            ),
            DuplicateName => write!(f, "{}: duplicate name in the directory", path),
            DirectoryEntrySize => write!(f, "{}: directory entry has a size of {}", path, size),
            DirectoryStartCluster => write!(
                f,
                "{}: directory starts at cluster {}, which is not allowed",
                path, cluster
            ),
            LabelEntries => write!(f, "{}: {} volume label entries", path, count),
            LabelMismatch => write!(
                f,
                "the volume label is '{}' in the root directory but '{}' in the boot sector; readers use the root entry",
                name, other_name
            ),
            LabelOnlyInBootSector => write!(
                f,
                "the volume label '{}' is only in the boot sector; GRUB and EDK2 read it from the root directory and see none",
                name
            ),
            DotEntryMissing => write!(f, "{}: the \"{}\" entry is missing", path, name),
            LongNameTooLong => write!(f, "{}: long name is longer than {} characters", path, expected),
            LongNamePadding => write!(f, "{}: long name entries are not padded with 0x0000 then 0xFFFF", path),
            LongNameTrailingDot => write!(
                f,
                "{}: long name ends with a dot, which Linux strips on lookup, so it cannot be opened by that name there",
                path
            ),
            LongNameTrailingSpace => write!(
                f,
                "{}: long name ends with a space, which Linux refuses to create (it can still open it)",
                path
            ),
            LongNameInvalidCharacters => write!(f, "{}: long name contains invalid characters", path),
            ShortNameLeadingSpace => write!(f, "{}: short name starts with a space", path),
            ShortNameLowerCase => write!(
                f,
                "{}: short name contains lower case letters, Windows and EDK2 expect upper case",
                path
            ),
            ShortNameInvalidCharacters => write!(f, "{}: short name contains invalid characters", path),
            DateInvalid => write!(f, "{}: {} date 0x{:04x} is invalid", path, field, value),
            TimeInvalid => write!(
                f,
                "{}: {} time 0x{:04x} is invalid; GRUB rejects a seconds field above 29, Windows shows such times as 1601",
                path, field, value
            ),
            CreationHundredthsInvalid => {
                write!(f, "{}: creation time hundredths {} are out of range", path, value)
            }
            RootHasDotEntry => write!(
                f,
                "/: the root directory contains a \"{}\" entry, Linux shows it twice",
                name
            ),
            DotEntryNotDirectory => write!(f, "{}: the \"{}\" entry is not a directory", path, name),
            DotEntryCluster => write!(
                f,
                "{}: the \"{}\" entry points at cluster {} instead of {}",
                path, name, cluster, expected
            ),
            DotDotPointsAtRoot => write!(
                f,
                "{}: the \"..\" entry points at the root cluster {} instead of 0",
                path, cluster
            ),
            DotEntrySlot => write!(
                f,
                "{}: the \"{}\" entry is in slot position {} instead of {}",
                path, name, slot, expected
            ),
            SizeWithoutClusters => write!(
                f,
                "{}: has {} bytes but no clusters; Linux reads it as zeros",
                path, size
            ),
            TooFewClusters => write!(
                f,
                "{}: has {} bytes but only {} of the {} clusters needed; reading it on Linux fails with EIO and remounts the volume read-only",
                path, size, clusters, needed
            ),
            TooManyClusters => write!(
                f,
                "{}: has {} bytes but {} clusters, {} too many; Linux refuses to append to it (\"clusters badly computed\") and so does EDK2",
                path,
                size,
                clusters,
                clusters.saturating_sub(needed)
            ),
            LostClusters => write!(
                f,
                "{} clusters are allocated but not referenced by any file or directory",
                count
            ),
            ReservedBitsSet => write!(
                f,
                "{} FAT entries have bits set in their reserved high nibble; GRUB does not mask them and cuts chains short",
                count
            ),
        }
    }
}

/// Problems a report keeps, at most. A damaged directory can yield one per
/// slot and a damaged FAT one per cluster; the counts stay exact, the
/// messages beyond this many are dropped.
pub const MAX_PROBLEMS: usize = 10_000;

/// The outcome of a check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Everything found, in the order found, up to [`MAX_PROBLEMS`].
    pub problems: Vec<Problem>,
    /// Problems found but not kept, beyond [`MAX_PROBLEMS`].
    pub dropped: usize,
    errors: usize,
    warnings: usize,
    /// Files seen.
    pub files: u64,
    /// Directories seen, the root not counted: the subdirectories, which
    /// is what fsck.fat counts and what a copy of the tree has.
    pub directories: u64,
    /// Clusters referenced by files and directories.
    pub used_clusters: u32,
    /// Clusters marked free in the FAT.
    pub free_clusters: u32,
    /// Clusters marked bad in the FAT.
    pub bad_clusters: u32,
    /// Clusters allocated in the FAT but referenced by nothing.
    pub lost_clusters: u32,
    /// The volume layout, once the boot sector could be read.
    pub layout: Option<Layout>,
}

impl Report {
    /// Number of errors, dropped ones included.
    pub fn errors(&self) -> usize {
        self.errors
    }

    /// Number of warnings, dropped ones included.
    pub fn warnings(&self) -> usize {
        self.warnings
    }

    /// Whether nothing at all was found.
    pub fn is_clean(&self) -> bool {
        self.errors == 0 && self.warnings == 0
    }

    /// Records a problem. It is only built while the report has room for
    /// it: rendering a path means reading the directories above it, which
    /// no image should make us do more than MAX_PROBLEMS times.
    fn add(&mut self, severity: Severity, make: impl FnOnce() -> Problem) {
        match severity {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
        }
        if self.problems.len() < MAX_PROBLEMS {
            let mut problem = make();
            problem.severity = severity;
            self.problems.push(problem);
        } else {
            self.dropped += 1;
        }
    }

    fn error(&mut self, make: impl FnOnce() -> Problem) {
        self.add(Severity::Error, make);
    }

    fn warning(&mut self, make: impl FnOnce() -> Problem) {
        self.add(Severity::Warning, make);
    }
}

/// Where a directory entry is: the chain of the directory holding it and
/// the slot of its short entry. That is all the checker keeps of a name;
/// the name itself is read back from the directory when a message needs
/// it, so what is kept per chain does not grow with the names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EntryAt {
    dir: u32,
    slot: u32,
}

/// The root directory has no entry anywhere.
const ROOT_AT: EntryAt = EntryAt { dir: NO_OWNER, slot: 0 };

/// An entry by the chain of its directory and its name, for messages. Copy,
/// so that a message can render it without holding on to the checker.
#[derive(Clone, Copy)]
struct EntryRef<'n> {
    dir: u32,
    name: &'n str,
}

/// A claimed chain: the entry it belongs to, its first cluster and how
/// many clusters it claimed.
struct Chain {
    at: EntryAt,
    first: u32,
    len: u32,
}

/// A cluster a chain ran into that another chain had claimed already.
struct Collision {
    cluster: u32,
    /// The chain that ran into it, and after how many clusters.
    chain: u32,
}

/// How many collisions are kept with their chains; the rest are counted.
const MAX_COLLISIONS: usize = 1024;

/// A directory waiting to be checked.
struct Pending {
    at: EntryAt,
    /// Its chain, once claimed.
    chain: u32,
    first_cluster: u32,
    parent_cluster: u32,
}

/// Marks a cluster no chain has claimed yet, and the parent of the root.
const NO_OWNER: u32 = u32::MAX;

struct Checker<'a> {
    device: &'a Device,
    boot: BootSector,
    layout: Layout,
    fat: Fat,
    /// One bit per cluster: claimed by a chain. Who claimed it is found
    /// again by walking the chains, see `name_cross_links`, so this stays
    /// at 32 MiB for the largest FAT32 volume.
    claimed: BitSet,
    /// Every chain claimed so far, sixteen bytes each.
    chains: Vec<Chain>,
    /// Clusters claimed twice, up to MAX_COLLISIONS of them.
    collisions: Vec<Collision>,
    collisions_dropped: usize,
    /// The chain of the directory being checked and its rendered path, so
    /// that the messages about one directory render it once.
    current_dir: Cell<u32>,
    dir_path: RefCell<Option<(u32, String)>>,
    /// The label entry of the root directory, if there is one.
    root_label: Option<[u8; 11]>,
    report: RefCell<Report>,
    progress: RefCell<&'a mut dyn FnMut(&Progress)>,
}

/// Checks the FAT32 volume on `device`. I/O errors and a device that does
/// not hold FAT32 at all are returned as errors; everything else lands in
/// the report.
pub fn check(device: &Device) -> Result<Report> {
    check_with_progress(device, &mut |_| {})
}

/// [`check`], telling `progress` how many files and directories it went
/// through so far after every one of them, and after every chunk of the
/// FAT copies it compares.
pub fn check_with_progress(device: &Device, progress: &mut dyn FnMut(&Progress)) -> Result<Report> {
    let mut report = Report::default();
    if device.len() < BOOT_SECTOR_SIZE as u64 {
        bail!(
            EMEDIUMTYPE,
            Detail::NotFat32 {
                reason: NotFat32Reason::TooSmall,
                sector_size: None,
            },
            "{} bytes are too few to hold a file system",
            device.len()
        );
    }
    let mut sector = [0u8; BOOT_SECTOR_SIZE];
    device.read_at(0, &mut sector)?;
    let boot = BootSector::parse(&sector)?;
    if let Err(e) = boot.validate() {
        if e.errno() == EMEDIUMTYPE {
            return Err(e);
        }
        report.error(|| boot_sector_problem(&e));
        return Ok(report);
    }
    let layout = match boot.layout() {
        Ok(l) => l,
        Err(e) => {
            report.error(|| boot_sector_problem(&e));
            return Ok(report);
        }
    };
    report.layout = Some(layout);
    if layout.size() > device.len() {
        report.error(|| {
            Problem::new(ProblemKind::ClaimsMoreThanDevice)
                .value(u64::from(layout.total_sectors))
                .size_bytes(layout.size())
                .expected(device.len())
        });
        return Ok(report);
    }
    let mut c = Checker {
        device,
        fat: Fat::open(&layout, &DeviceStore { device, layout }, 0, CACHE_BYTES)?,
        boot,
        layout,
        claimed: BitSet::new(layout.max_cluster() as usize + 1),
        chains: Vec::new(),
        collisions: Vec::new(),
        collisions_dropped: 0,
        current_dir: Cell::new(NO_OWNER),
        dir_path: RefCell::new(None),
        root_label: None,
        report: RefCell::new(report),
        progress: RefCell::new(progress),
    };
    c.check_reserved_area()?;
    c.check_fats()?;
    c.check_tree()?;
    c.name_cross_links();
    c.check_unreferenced();
    Ok(c.report.into_inner())
}

/// The finding for a boot sector whose fields make no sense: the field
/// the validation named.
fn boot_sector_problem(e: &crate::Error) -> Problem {
    let mut problem = Problem::new(ProblemKind::BootSector);
    if let Some(Detail::Corrupt { field, .. }) = e.detail() {
        problem.field = *field;
    }
    problem
}

impl<'a> Checker<'a> {
    fn ss(&self) -> u64 {
        u64::from(self.layout.sector_size)
    }

    fn store(&self) -> DeviceStore<'a> {
        DeviceStore {
            device: self.device,
            layout: self.layout,
        }
    }

    /// Tells the progress callback how many files and directories the
    /// check went through so far.
    fn tick(&self) {
        let done = {
            let report = self.report.borrow();
            Progress {
                files: report.files,
                directories: report.directories,
                bytes: 0,
            }
        };
        (self.progress.borrow_mut())(&done);
    }

    fn is_claimed(&self, cluster: u32) -> bool {
        self.claimed.contains(cluster as usize)
    }

    fn claim(&mut self, cluster: u32) {
        self.claimed.insert(cluster as usize);
    }

    fn error(&self, make: impl FnOnce() -> Problem) {
        self.report.borrow_mut().error(make);
    }

    fn warning(&self, make: impl FnOnce() -> Problem) {
        self.report.borrow_mut().warning(make);
    }

    /// Reports the long name entries in `slots` of the directory `chain` as
    /// belonging to no short entry.
    fn orphaned(&self, chain: u32, slots: Range<usize>) {
        self.warning(|| {
            Problem::new(ProblemKind::OrphanedLongName)
                .path(self.chain_path(chain))
                .slot(slots.start as u32)
                .slots(slots.len() as u32)
        });
    }

    /// Reports and forgets the long name entries collected from `start` up
    /// to `end`, which no short entry claimed.
    fn drop_orphans(&self, chain: u32, pending: &mut Vec<LongNameEntry>, start: usize, end: usize) {
        if !pending.is_empty() {
            self.orphaned(chain, start..end);
            pending.clear();
        }
    }

    /// The path of the entry a chain belongs to, read back from the
    /// directories above it. Rendering stops at MAX_PATH bytes, the rest is
    /// shown as "/...". The directory being checked is rendered once.
    fn chain_path(&self, id: u32) -> String {
        if let Some((cached, path)) = self.dir_path.borrow().as_ref() {
            if *cached == id {
                return path.clone();
            }
        }
        let mut parts: Vec<String> = Vec::new();
        let mut len = 0;
        let mut cur = id;
        let mut truncated = false;
        // A chain's directory was claimed before it, so this walks up through
        // smaller ids and ends at the root.
        while cur != NO_OWNER {
            let at = self.chains[cur as usize].at;
            if at.dir == NO_OWNER {
                break;
            }
            let name = self.entry_name(at);
            len += name.len() + 1;
            if len > crate::path::MAX_PATH {
                truncated = true;
                break;
            }
            parts.push(name);
            cur = at.dir;
        }
        let mut path = String::new();
        if truncated {
            path.push_str("/...");
        }
        for part in parts.iter().rev() {
            path.push('/');
            path.push_str(part);
        }
        if path.is_empty() {
            path.push('/');
        }
        if id == self.current_dir.get() {
            *self.dir_path.borrow_mut() = Some((id, path.clone()));
        }
        path
    }

    /// The path of an entry.
    fn path_of(&self, entry: EntryRef<'_>) -> String {
        self.entry_path(entry.dir, entry.name)
    }

    /// The path of `name` in the directory of chain `dir`.
    fn entry_path(&self, dir: u32, name: &str) -> String {
        let dir = self.chain_path(dir);
        if dir == "/" {
            format!("/{}", name)
        } else {
            format!("{}/{}", dir, name)
        }
    }

    /// The name of the entry at `at`: its long name if the slots before the
    /// short entry hold one, else the short name.
    fn entry_name(&self, at: EntryAt) -> String {
        let first = self.chains[at.dir as usize].first;
        let short = match self.read_slot(first, at.slot) {
            Some(raw) => RawDirEntry::from_bytes(&raw),
            None => return format!("<slot {}>", at.slot),
        };
        let checksum = short_name_checksum(&short.name);
        let mut long: Vec<LongNameEntry> = Vec::new();
        let mut slot = at.slot;
        let mut complete = false;
        while slot > 0 && long.len() < LFN_MAX_ENTRIES {
            slot -= 1;
            match self.read_slot(first, slot).and_then(|raw| parse_long_name_entry(&raw)) {
                Some(l) if l.sequence as usize == long.len() + 1 && l.checksum == checksum => {
                    complete = l.last;
                    long.push(l);
                    if complete {
                        break;
                    }
                }
                _ => break,
            }
        }
        if complete {
            String::from_utf16_lossy(&join_long_name(&long))
        } else {
            short_name_to_string(&short)
        }
    }

    /// Reads one slot of the directory whose chain starts at `first`.
    fn read_slot(&self, first: u32, slot: u32) -> Option<[u8; DIR_ENTRY_SIZE]> {
        let per_cluster = self.layout.cluster_size() / DIR_ENTRY_SIZE as u32;
        let cluster = self
            .fat
            .chain(&self.store(), first)
            .nth((slot / per_cluster) as usize)?;
        if !self.layout.valid_cluster(cluster) {
            return None;
        }
        let offset = self.layout.cluster_offset(cluster).ok()? + u64::from(slot % per_cluster) * DIR_ENTRY_SIZE as u64;
        let mut raw = [0u8; DIR_ENTRY_SIZE];
        self.device.read_at(offset, &mut raw).ok()?;
        Some(raw)
    }

    fn check_reserved_area(&mut self) -> Result<()> {
        if self.boot.nt_flags & NT_FLAG_DIRTY != 0 {
            self.warning(|| Problem::new(ProblemKind::DirtyFlag));
        }
        if self.layout.below_spec_minimum() {
            self.warning(|| {
                Problem::new(ProblemKind::BelowMinimumClusters)
                    .clusters(u64::from(self.layout.clusters))
                    .expected(u64::from(crate::layout::MIN_CLUSTERS))
            });
        }
        if self.boot.signature != crate::boot::BOOT_SIGNATURE {
            self.error(|| Problem::new(ProblemKind::BootSignatureMissing));
        }
        if self.boot.fs_type != FS_TYPE_FAT32 {
            self.warning(|| {
                Problem::new(ProblemKind::FileSystemTypeString).name(String::from_utf8_lossy(&self.boot.fs_type))
            });
        }
        let backup = u64::from(self.boot.backup_boot_sector);
        if backup != 0 {
            let mut b = [0u8; BOOT_SECTOR_SIZE];
            self.device.read_at(backup * self.ss(), &mut b)?;
            // Linux maintains the dirty flag in sector 0 only, so the two
            // legitimately differ in that bit while the volume is mounted.
            let mut primary = self.boot.to_bytes();
            primary[NT_FLAGS_OFFSET] &= !NT_FLAG_DIRTY;
            b[NT_FLAGS_OFFSET] &= !NT_FLAG_DIRTY;
            if b != primary {
                self.warning(|| Problem::new(ProblemKind::BackupBootSectorDiffers).copy(backup as u32));
            }
        } else {
            self.warning(|| Problem::new(ProblemKind::NoBackupBootSector));
        }
        let mut f = vec![0u8; self.layout.sector_size as usize];
        self.device
            .read_at(u64::from(self.boot.fsinfo_sector) * self.ss(), &mut f)?;
        match FsInfo::parse(&f) {
            None => self.warning(|| Problem::new(ProblemKind::FsinfoSignatures)),
            Some(info) => {
                if !FsInfo::has_trail_signature(&f) {
                    self.warning(|| Problem::new(ProblemKind::FsinfoTrailingSignature));
                }
                let free = self.fat.free_count();
                if info.free_clusters != FSINFO_UNKNOWN && info.free_clusters != free {
                    self.warning(|| {
                        Problem::new(ProblemKind::FsinfoFreeCount)
                            .value(u64::from(info.free_clusters))
                            .expected(u64::from(free))
                    });
                }
                if info.next_free != FSINFO_UNKNOWN && !self.layout.valid_cluster(info.next_free) {
                    self.warning(|| Problem::new(ProblemKind::FsinfoNextFree).cluster(info.next_free));
                }
            }
        }
        Ok(())
    }

    fn check_fats(&mut self) -> Result<()> {
        let entry0 = self.fat.raw(&self.store(), 0)?;
        if entry0 & 0xFF != u32::from(self.boot.media) || entry0 < END_OF_CHAIN_MIN {
            // Linux and EDK2 accept anything here, GRUB refuses to mount.
            self.error(|| {
                Problem::new(ProblemKind::FatMediaEntry)
                    .value(u64::from(entry0))
                    .expected(u64::from(media_entry(self.boot.media)))
            });
        }
        let entry1 = self.fat.raw(&self.store(), 1)?;
        if entry1 < END_OF_CHAIN_MIN {
            // The specification keeps two flags in entry 1, and EDK2 and
            // Windows act on them: bit 27 clear means the volume was not
            // cleanly unmounted, bit 26 clear that a driver saw hardware
            // errors. Windows NT writes 0x7FFFFFFF for dirty, which masks
            // to the same thing.
            if entry1 & ENTRY1_CLEAN_SHUTDOWN == 0 {
                self.warning(|| Problem::new(ProblemKind::FatDirtyFlag).value(u64::from(entry1)));
            }
            if entry1 & ENTRY1_NO_HARD_ERROR == 0 {
                self.warning(|| Problem::new(ProblemKind::FatHardwareErrorFlag).value(u64::from(entry1)));
            }
            if entry1 | ENTRY1_CLEAN_SHUTDOWN | ENTRY1_NO_HARD_ERROR < END_OF_CHAIN_MIN {
                self.warning(|| Problem::new(ProblemKind::FatEntry1).value(u64::from(entry1)));
            }
        }
        if self.layout.fats > 1 {
            // Compare the copies in chunks: the FAT size is whatever the boot
            // sector claims, up to the volume size.
            const CHUNK: u64 = 1 << 20;
            let size = self.layout.fat_size();
            let mut first = vec![0u8; size.min(CHUNK) as usize];
            let mut other = vec![0u8; size.min(CHUNK) as usize];
            for i in 1..self.layout.fats {
                let mut differing = 0usize;
                let mut done = 0;
                while done < size {
                    let n = (size - done).min(CHUNK) as usize;
                    self.device.read_at(self.layout.fat_offset(0) + done, &mut first[..n])?;
                    self.device.read_at(self.layout.fat_offset(i) + done, &mut other[..n])?;
                    differing += first[..n].iter().zip(&other[..n]).filter(|(a, b)| a != b).count();
                    done += n as u64;
                    self.tick();
                }
                if differing > 0 {
                    // Linux and EDK2 read the first copy and never the
                    // others; fsck.fat offers to copy the first over them.
                    // A crash between the two writes leaves this behind.
                    self.warning(|| {
                        Problem::new(ProblemKind::FatCopyDiffers)
                            .copy(i)
                            .count(differing as u64)
                    });
                }
            }
        }
        let bad = (2..=self.layout.max_cluster())
            .filter(|&c| matches!(self.fat.get(&self.store(), c), Ok(Entry::Bad)))
            .count() as u32;
        self.report.borrow_mut().bad_clusters = bad;
        Ok(())
    }

    /// Follows a chain, claiming its clusters for the entry at `at`, and
    /// stops where it runs into a cluster claimed before, a loop, or a
    /// damaged entry. Returns the chain's id, how many clusters it claimed
    /// and the first `keep` of them.
    fn claim_chain(&mut self, at: EntryAt, first: u32, keep: usize) -> (u32, u64, Vec<u32>) {
        let id = self.chains.len() as u32;
        self.chains.push(Chain { at, first, len: 0 });
        let mut kept = Vec::new();
        let mut steps: u64 = 0;
        let mut cluster = first;
        loop {
            if !self.layout.valid_cluster(cluster) {
                self.error(|| {
                    Problem::new(ProblemKind::ChainInvalidCluster)
                        .path(self.chain_path(id))
                        .cluster(cluster)
                });
                break;
            }
            if self.is_claimed(cluster) {
                // Claimed by this chain itself, or by another one? Walking
                // this chain again for as many steps as it took tells; the
                // clusters are intact, we just came that way.
                if self.rewalk_reaches(first, cluster, steps) {
                    self.error(|| {
                        Problem::new(ProblemKind::ChainLoop)
                            .path(self.chain_path(id))
                            .cluster(cluster)
                    });
                } else if self.collisions.len() < MAX_COLLISIONS {
                    self.collisions.push(Collision { cluster, chain: id });
                } else {
                    self.collisions_dropped += 1;
                }
                break;
            }
            // The cluster is the chain's whatever its entry says; a chain
            // that ends in a free, bad or invalid entry still owns the
            // clusters up to and including that one.
            self.claim(cluster);
            steps += 1;
            if kept.len() < keep {
                kept.push(cluster);
            }
            let Ok(entry) = self.fat.get(&self.store(), cluster) else {
                self.error(|| {
                    Problem::new(ProblemKind::FatReadFailed)
                        .path(self.chain_path(id))
                        .cluster(cluster)
                });
                break;
            };
            match entry {
                Entry::Free => {
                    self.error(|| {
                        Problem::new(ProblemKind::ChainClusterFree)
                            .path(self.chain_path(id))
                            .cluster(cluster)
                    });
                    break;
                }
                Entry::Bad => {
                    self.error(|| {
                        Problem::new(ProblemKind::ChainClusterBad)
                            .path(self.chain_path(id))
                            .cluster(cluster)
                    });
                    break;
                }
                Entry::Invalid(v) => {
                    self.error(|| {
                        Problem::new(ProblemKind::ChainEntryInvalid)
                            .path(self.chain_path(id))
                            .cluster(cluster)
                            .value(u64::from(v))
                    });
                    break;
                }
                Entry::End => break,
                Entry::Next(next) => cluster = next,
            }
        }
        self.chains[id as usize].len = u32::try_from(steps).unwrap_or(u32::MAX);
        self.report.borrow_mut().used_clusters += steps as u32;
        (id, steps, kept)
    }

    /// Whether the first `steps` clusters of the chain at `first` include
    /// `target`. The clusters were just walked, so this cannot fail.
    fn rewalk_reaches(&self, first: u32, target: u32, steps: u64) -> bool {
        let steps = usize::try_from(steps).unwrap_or(usize::MAX);
        self.fat.chain(&self.store(), first).take(steps).any(|c| c == target)
    }

    /// Names both owners of every cluster two chains ran into. The first
    /// owner is not recorded when a chain claims its clusters, one bit per
    /// cluster cannot say who; it is found by walking every chain again
    /// for as far as it got, which costs no more than the first walk did.
    fn name_cross_links(&mut self) {
        if self.collisions.is_empty() {
            return;
        }
        let wanted: HashSet<u32> = self.collisions.iter().map(|c| c.cluster).collect();
        let mut owners: Vec<(u32, u32)> = Vec::new();
        for (id, chain) in self.chains.iter().enumerate() {
            for cluster in self.fat.chain(&self.store(), chain.first).take(chain.len as usize) {
                if wanted.contains(&cluster) {
                    owners.push((cluster, id as u32));
                }
            }
        }
        for c in &self.collisions {
            let (cluster, chain) = (c.cluster, c.chain);
            let other = owners
                .iter()
                .find(|&&(c, id)| c == cluster && id != chain)
                .map(|&(_, id)| id);
            self.error(|| {
                Problem::new(ProblemKind::CrossLinked)
                    .path(self.chain_path(chain))
                    .cluster(cluster)
                    .other_path(other.map(|o| self.chain_path(o)))
            });
        }
        if self.collisions_dropped > 0 {
            let dropped = self.collisions_dropped;
            self.error(|| Problem::new(ProblemKind::CrossLinkedMore).count(dropped as u64));
        }
    }

    fn check_tree(&mut self) -> Result<()> {
        let root = self.boot.root_cluster;
        let mut stack = vec![Pending {
            at: ROOT_AT,
            chain: NO_OWNER,
            first_cluster: root,
            parent_cluster: 0,
        }];
        while let Some(mut dir) = stack.pop() {
            if dir.at != ROOT_AT {
                self.report.borrow_mut().directories += 1;
                self.tick();
            }
            let cs = self.layout.cluster_size() as usize;
            // Read no more than a directory can hold; the chain itself may
            // run through the whole volume on a damaged image.
            let max_clusters = crate::dir::MAX_SLOTS * DIR_ENTRY_SIZE / cs;
            let (id, len, mut chain) = self.claim_chain(dir.at, dir.first_cluster, max_clusters);
            dir.chain = id;
            self.current_dir.set(id);
            if chain.is_empty() {
                continue;
            }
            if len as usize > max_clusters {
                self.error(|| {
                    Problem::new(ProblemKind::DirectoryTooLong)
                        .path(self.chain_path(dir.chain))
                        .clusters(len)
                        .slots(crate::dir::MAX_SLOTS as u32)
                        .expected(max_clusters as u64)
                });
                chain.truncate(max_clusters);
            }
            let mut data = vec![0u8; chain.len() * cs];
            for (i, &c) in chain.iter().enumerate() {
                self.device
                    .read_at(self.layout.cluster_offset(c)?, &mut data[i * cs..(i + 1) * cs])?;
            }
            self.check_directory(&dir, &data, &mut stack);
        }
        Ok(())
    }

    fn check_directory(&mut self, dir: &Pending, data: &[u8], stack: &mut Vec<Pending>) {
        let is_root = dir.first_cluster == self.boot.root_cluster;
        let mut names: HashSet<Vec<u16>> = HashSet::new();
        let mut pending: Vec<LongNameEntry> = Vec::new();
        let mut pending_start = 0;
        let mut ended_at: Option<usize> = None;
        let mut labels: u64 = 0;
        let mut index = 0;
        let mut saw_dot = false;
        let mut saw_dotdot = false;
        for (slot, raw) in data.chunks_exact(DIR_ENTRY_SIZE).enumerate() {
            let raw: &[u8; DIR_ENTRY_SIZE] = raw.try_into().expect("slot size");
            if let Some(end) = ended_at {
                if raw.iter().any(|&b| b != 0) {
                    self.error(|| {
                        Problem::new(ProblemKind::EntryAfterEnd)
                            .path(self.chain_path(dir.chain))
                            .slot(slot as u32)
                            .value(end as u64)
                    });
                    break;
                }
                continue;
            }
            if raw[0] == ENTRY_END {
                ended_at = Some(slot);
                self.drop_orphans(dir.chain, &mut pending, pending_start, slot);
                continue;
            }
            if raw[0] == ENTRY_DELETED {
                self.drop_orphans(dir.chain, &mut pending, pending_start, slot);
                continue;
            }
            if let Some(l) = parse_long_name_entry(raw) {
                let continues = match pending.last() {
                    Some(prev) => l.sequence + 1 == prev.sequence && l.checksum == prev.checksum,
                    None => false,
                };
                if continues && l.last {
                    self.warning(|| {
                        Problem::new(ProblemKind::LongNameLastBitInside)
                            .path(self.chain_path(dir.chain))
                            .slot(slot as u32)
                    });
                }
                if raw[12] != 0 || raw[26] != 0 || raw[27] != 0 {
                    self.warning(|| {
                        Problem::new(ProblemKind::LongNameReservedBytes)
                            .path(self.chain_path(dir.chain))
                            .slot(slot as u32)
                    });
                }
                if continues {
                    pending.push(l);
                } else {
                    self.drop_orphans(dir.chain, &mut pending, pending_start, slot);
                    if l.last {
                        pending_start = slot;
                        pending.push(l);
                    } else {
                        self.orphaned(dir.chain, slot..slot + 1);
                    }
                }
                continue;
            }
            if raw[11] == ATTR_LONG_NAME {
                self.drop_orphans(dir.chain, &mut pending, pending_start, slot);
                self.warning(|| {
                    Problem::new(ProblemKind::LongNameBadSequence)
                        .path(self.chain_path(dir.chain))
                        .slot(slot as u32)
                        .value(u64::from(raw[0]))
                });
                continue;
            }
            let short = RawDirEntry::from_bytes(raw);
            let short_text = short_name_to_string(&short);
            let mut long_name = None;
            if let Some(last) = pending.last() {
                if last.sequence == 1 && pending[0].checksum == short_name_checksum(&short.name) {
                    let entries: Vec<LongNameEntry> = pending.iter().rev().copied().collect();
                    let units = join_long_name(&entries);
                    self.check_long_name_text(dir.chain, &short_text, &entries, &units);
                    long_name = Some(String::from_utf16_lossy(&units));
                } else {
                    self.warning(|| {
                        Problem::new(ProblemKind::LongNameMismatch)
                            .path(self.chain_path(dir.chain))
                            .slot(pending_start as u32)
                            .slots((slot - pending_start) as u32)
                            .name(short_text.as_str())
                    });
                }
                pending.clear();
            }
            let name = long_name.clone().unwrap_or_else(|| short_text.clone());
            let at = EntryAt {
                dir: dir.chain,
                slot: slot as u32,
            };
            let path = EntryRef {
                dir: dir.chain,
                name: &name,
            };
            if short.is_volume_label() {
                // Labels are not file names; they have their own rules.
                labels += 1;
                if is_root && self.root_label.is_none() {
                    self.root_label = Some(short.name);
                }
                let label = decode_label(&short.name);
                if !is_root {
                    self.warning(|| {
                        Problem::new(ProblemKind::LabelOutsideRoot)
                            .path(self.chain_path(dir.chain))
                            .name(label.as_str())
                    });
                }
                if short.first_cluster != 0 || short.size != 0 {
                    self.warning(|| {
                        Problem::new(ProblemKind::LabelEntryHasData)
                            .path(self.chain_path(dir.chain))
                            .name(label.as_str())
                    });
                }
                if short.name.iter().any(u8::is_ascii_lowercase) {
                    self.warning(|| {
                        Problem::new(ProblemKind::LabelLowerCase)
                            .path(self.chain_path(dir.chain))
                            .name(label.as_str())
                    });
                }
                continue;
            }
            let is_dot = short.name == DOT_NAME || short.name == DOTDOT_NAME;
            if is_dot {
                if short.name[1] == b'.' {
                    saw_dotdot = true;
                } else {
                    saw_dot = true;
                }
                self.check_dot_entry(dir, index, &short, is_root);
                index += 1;
                continue;
            }
            self.check_short_name(dir.chain, &name, &short);
            if short.attr & ATTR_RESERVED != 0 {
                self.warning(|| {
                    Problem::new(ProblemKind::AttributeReservedBits)
                        .path(self.path_of(path))
                        .value(u64::from(short.attr))
                });
            }
            index += 1;
            // An entry answers to its short and its long name; both must be
            // unique in the directory, but they may equal each other.
            let mut own: Vec<Vec<u16>> = vec![fold_str(&short_text)];
            if let Some(l) = &long_name {
                let f = fold_str(l);
                if !own.contains(&f) {
                    own.push(f);
                }
            }
            if own.iter().any(|n| names.contains(n)) {
                self.error(|| Problem::new(ProblemKind::DuplicateName).path(self.path_of(path)));
            }
            names.extend(own);
            if short.is_directory() {
                if short.size != 0 {
                    self.warning(|| {
                        Problem::new(ProblemKind::DirectoryEntrySize)
                            .path(self.path_of(path))
                            .size_bytes(u64::from(short.size))
                    });
                }
                if short.first_cluster == 0 || short.first_cluster == self.boot.root_cluster {
                    self.error(|| {
                        Problem::new(ProblemKind::DirectoryStartCluster)
                            .path(self.path_of(path))
                            .cluster(short.first_cluster)
                    });
                    continue;
                }
                stack.push(Pending {
                    at,
                    chain: NO_OWNER,
                    first_cluster: short.first_cluster,
                    parent_cluster: dir.first_cluster,
                });
            } else {
                self.report.borrow_mut().files += 1;
                self.tick();
                self.check_file(at, &name, &short);
            }
        }
        if labels > 1 {
            self.warning(|| {
                Problem::new(ProblemKind::LabelEntries)
                    .path(self.chain_path(dir.chain))
                    .count(labels)
            });
        }
        if is_root {
            // GRUB and EDK2 read the label from the root entry; the boot
            // sector's copy is a mirror that should agree.
            match (self.root_label, self.boot.volume_label) {
                (Some(root), boot) if boot != NO_NAME && boot != root => self.warning(|| {
                    Problem::new(ProblemKind::LabelMismatch)
                        .name(decode_label(&root))
                        .other_name(decode_label(&boot))
                }),
                (None, boot) if boot != NO_NAME => {
                    self.warning(|| Problem::new(ProblemKind::LabelOnlyInBootSector).name(decode_label(&boot)))
                }
                _ => {}
            }
        }
        if !is_root && !(saw_dot && saw_dotdot) {
            self.error(|| {
                Problem::new(ProblemKind::DotEntryMissing)
                    .path(self.chain_path(dir.chain))
                    .name(if saw_dot { ".." } else { "." })
            });
        }
    }

    fn check_long_name_text(&mut self, dir: u32, short: &str, entries: &[LongNameEntry], units: &[u16]) {
        let path = EntryRef { dir, name: short };
        if units.len() > MAX_LONG_NAME {
            self.warning(|| {
                Problem::new(ProblemKind::LongNameTooLong)
                    .path(self.path_of(path))
                    .count(units.len() as u64)
                    .expected(MAX_LONG_NAME as u64)
            });
        }
        // After the name there must be one 0x0000 and then only 0xFFFF.
        let all: Vec<u16> = entries.iter().flat_map(|e| e.units).collect();
        if units.len() < all.len() {
            let tail = &all[units.len()..];
            if tail[0] != 0 || tail[1..].iter().any(|&u| u != 0xFFFF) {
                self.warning(|| Problem::new(ProblemKind::LongNamePadding).path(self.path_of(path)));
            }
        }
        let text = String::from_utf16_lossy(units);
        if text.ends_with('.') {
            self.warning(|| Problem::new(ProblemKind::LongNameTrailingDot).path(self.path_of(path)));
        } else if text.ends_with(' ') {
            self.warning(|| Problem::new(ProblemKind::LongNameTrailingSpace).path(self.path_of(path)));
        }
        // Readers refuse the control characters below 0x20; DEL they take.
        if text
            .chars()
            .any(|c| u32::from(c) < 0x20 || LONG_NAME_INVALID.contains(&c))
        {
            self.warning(|| Problem::new(ProblemKind::LongNameInvalidCharacters).path(self.path_of(path)));
        }
    }

    fn check_short_name(&mut self, dir: u32, name: &str, short: &RawDirEntry) {
        let path = EntryRef { dir, name };
        let name = short.name;
        if name[0] == b' ' {
            self.error(|| Problem::new(ProblemKind::ShortNameLeadingSpace).path(self.path_of(path)));
        }
        // A stored short name also holds its padding and the characters of
        // the OEM code page.
        let valid = |b: u8| valid_short_char(b) || b >= 0x80 || b == b' ';
        if name.iter().any(u8::is_ascii_lowercase) {
            self.warning(|| Problem::new(ProblemKind::ShortNameLowerCase).path(self.path_of(path)));
        } else if name.iter().skip(1).any(|&b| !valid(b)) || !(valid(name[0]) || name[0] == ENTRY_E5_ESCAPE) {
            self.error(|| Problem::new(ProblemKind::ShortNameInvalidCharacters).path(self.path_of(path)));
        }
        for (what, stamp) in [
            ("creation", short.create_timestamp()),
            ("modification", short.write_timestamp()),
            ("access", short.access_timestamp()),
        ] {
            if !stamp.date_is_valid() {
                self.warning(|| {
                    Problem::new(ProblemKind::DateInvalid)
                        .path(self.path_of(path))
                        .field(what)
                        .value(u64::from(stamp.date))
                });
            }
        }
        for (what, stamp) in [
            ("creation", short.create_timestamp()),
            ("modification", short.write_timestamp()),
        ] {
            if !stamp.time_is_valid() {
                self.warning(|| {
                    Problem::new(ProblemKind::TimeInvalid)
                        .path(self.path_of(path))
                        .field(what)
                        .value(u64::from(stamp.time))
                });
            }
        }
        if short.create_tenths > 199 {
            self.warning(|| {
                Problem::new(ProblemKind::CreationHundredthsInvalid)
                    .path(self.path_of(path))
                    .value(u64::from(short.create_tenths))
            });
        }
    }

    fn check_dot_entry(&mut self, dir: &Pending, index: usize, short: &RawDirEntry, is_root: bool) {
        let which = if short.name[1] == b'.' { ".." } else { "." };
        if is_root {
            self.error(|| Problem::new(ProblemKind::RootHasDotEntry).name(which));
            return;
        }
        if !short.is_directory() {
            self.error(|| {
                Problem::new(ProblemKind::DotEntryNotDirectory)
                    .path(self.chain_path(dir.chain))
                    .name(which)
            });
        }
        match (which, index) {
            (".", 0) => {
                if short.first_cluster != dir.first_cluster {
                    self.error(|| {
                        Problem::new(ProblemKind::DotEntryCluster)
                            .path(self.chain_path(dir.chain))
                            .name(".")
                            .cluster(short.first_cluster)
                            .expected(u64::from(dir.first_cluster))
                    });
                }
            }
            ("..", 1) => {
                let expected = if dir.parent_cluster == self.boot.root_cluster {
                    0
                } else {
                    dir.parent_cluster
                };
                if short.first_cluster != expected {
                    if expected == 0 && short.first_cluster == self.boot.root_cluster {
                        self.warning(|| {
                            Problem::new(ProblemKind::DotDotPointsAtRoot)
                                .path(self.chain_path(dir.chain))
                                .cluster(short.first_cluster)
                        });
                    } else {
                        self.error(|| {
                            Problem::new(ProblemKind::DotEntryCluster)
                                .path(self.chain_path(dir.chain))
                                .name("..")
                                .cluster(short.first_cluster)
                                .expected(u64::from(expected))
                        });
                    }
                }
            }
            _ => self.error(|| {
                Problem::new(ProblemKind::DotEntrySlot)
                    .path(self.chain_path(dir.chain))
                    .name(which)
                    .slot(index as u32)
                    .expected(u64::from(which == ".."))
            }),
        }
    }

    fn check_file(&mut self, at: EntryAt, name: &str, short: &RawDirEntry) {
        let path = EntryRef { dir: at.dir, name };
        let cs = u64::from(self.layout.cluster_size());
        let expected = u64::from(short.size).div_ceil(cs);
        if short.first_cluster == 0 {
            if short.size != 0 {
                self.error(|| {
                    Problem::new(ProblemKind::SizeWithoutClusters)
                        .path(self.path_of(path))
                        .size_bytes(u64::from(short.size))
                });
            }
            return;
        }
        let (_, got, _) = self.claim_chain(at, short.first_cluster, 0);
        if got < expected {
            self.error(|| {
                Problem::new(ProblemKind::TooFewClusters)
                    .path(self.path_of(path))
                    .size_bytes(u64::from(short.size))
                    .clusters(got)
                    .clusters_needed(expected)
            });
        } else if got > expected {
            self.error(|| {
                Problem::new(ProblemKind::TooManyClusters)
                    .path(self.path_of(path))
                    .size_bytes(u64::from(short.size))
                    .clusters(got)
                    .clusters_needed(expected)
            });
        }
    }

    fn check_unreferenced(&mut self) {
        let mut lost = 0;
        let mut reserved_bits = 0u64;
        for c in 2..=self.layout.max_cluster() {
            let Ok(raw) = self.fat.raw_entry(&self.store(), c) else {
                self.error(|| Problem::new(ProblemKind::FatReadFailed).cluster(c));
                break;
            };
            if raw & !ENTRY_MASK != 0 {
                reserved_bits += 1;
            }
            match raw & ENTRY_MASK {
                crate::fat::FREE | crate::fat::BAD_CLUSTER => {}
                _ if !self.is_claimed(c) => lost += 1,
                _ => {}
            }
        }
        {
            let mut report = self.report.borrow_mut();
            report.lost_clusters = lost;
            report.free_clusters = self.fat.free_count();
        }
        if lost > 0 {
            self.warning(|| Problem::new(ProblemKind::LostClusters).count(u64::from(lost)));
        }
        if reserved_bits > 0 {
            // Linux and EDK2 mask the nibble, GRUB does not and takes such
            // an entry for an end of chain marker, so files end early there.
            self.error(|| Problem::new(ProblemKind::ReservedBitsSet).count(reserved_bits));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{volume, TempImage};
    use std::io::Write;
    use std::time::{Duration, UNIX_EPOCH};

    fn t(secs: u64) -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn populated() -> (TempImage, crate::volume::Volume) {
        let (img, mut v) = volume(8 << 20, 512, 512);
        v.create_dir_all("/EFI/Linux", t(1_700_000_000)).unwrap();
        for i in 0..3 {
            let mut w = v
                .create_file(&format!("/EFI/Linux/kernel {}.efi", i), t(1_700_000_000), false)
                .unwrap();
            w.write_all(&vec![i as u8; 2000 + i * 300]).unwrap();
            w.finish().unwrap();
        }
        v.create_file("/empty", t(1_700_000_000), false)
            .unwrap()
            .finish()
            .unwrap();
        (img, v)
    }

    /// The check tells its progress callback how far it got after every
    /// file and directory, and ends at what the report counts.
    #[test]
    fn check_reports_progress() {
        let (img, v) = populated();
        v.close().unwrap();
        let mut seen = Vec::new();
        let report = check_with_progress(&img.device(), &mut |p| seen.push(*p)).unwrap();
        assert!(
            seen.windows(2)
                .all(|w| w[0].files <= w[1].files && w[0].directories <= w[1].directories),
            "{:?}",
            seen
        );
        let last = seen.last().unwrap();
        assert_eq!((last.files, last.directories), (report.files, report.directories));
        assert_eq!((report.files, report.directories), (4, 2));
    }

    #[test]
    fn clean_volume() {
        let (img, v) = populated();
        v.close().unwrap();
        let r = check(&img.device()).unwrap();
        // The test volume is deliberately small, which is worth one warning.
        assert_eq!(r.errors(), 0, "{:?}", r.problems);
        assert_eq!(r.warnings(), 1, "{:?}", r.problems);
        assert_eq!(r.problems[0].kind, ProblemKind::BelowMinimumClusters);
        assert_eq!((r.files, r.directories), (4, 2));
        assert_eq!(r.used_clusters, 3 + 4 + 5 + 6);
        assert_eq!(r.lost_clusters, 0);
    }

    #[test]
    fn detects_damage() {
        let (img, v) = populated();
        let layout = *v.layout();
        let kernel = v.metadata("/EFI/Linux/kernel 1.efi").unwrap();
        let linux = v.metadata("/EFI/Linux").unwrap();
        v.close().unwrap();
        let dev = img.device();

        // Shorten a file's chain: its second cluster becomes free.
        let fat0 = layout.fat_offset(0);
        let entry = |c: u32| fat0 + u64::from(c) * 4;
        dev.write_at(entry(kernel.first_cluster), &0u32.to_le_bytes()).unwrap();
        let r = check(&dev).unwrap();
        let has = |r: &Report, kind: ProblemKind| r.problems.iter().any(|p| p.kind == kind);
        assert!(has(&r, ProblemKind::ChainClusterFree));
        assert!(r
            .problems
            .iter()
            .any(|p| p.kind == ProblemKind::FatCopyDiffers && p.copy == Some(1)));
        assert!(r.problems.iter().any(|p| {
            p.kind == ProblemKind::TooFewClusters && p.clusters == Some(1) && p.clusters_needed == Some(5)
        }));
        assert!(has(&r, ProblemKind::FsinfoFreeCount));
        assert!(r.lost_clusters > 0);

        // A loop in a directory chain.
        let (img, v) = populated();
        v.close().unwrap();
        let dev = img.device();
        dev.write_at(entry(linux.first_cluster), &linux.first_cluster.to_le_bytes())
            .unwrap();
        let r = check(&dev).unwrap();
        assert!(has(&r, ProblemKind::ChainLoop));

        // Garbage after the end marker and a bad ".." entry.
        let (img, v) = populated();
        v.close().unwrap();
        let dev = img.device();
        let off = layout.cluster_offset(linux.first_cluster).unwrap();
        dev.write_at(off + 15 * 32, b"X").unwrap();
        dev.write_at(off + 32 + 26, &[7u8, 0]).unwrap();
        let r = check(&dev).unwrap();
        assert!(has(&r, ProblemKind::EntryAfterEnd));
        assert!(r.problems.iter().any(|p| {
            p.kind == ProblemKind::DotEntryCluster && p.name.as_deref() == Some("..") && p.cluster == Some(7)
        }));
        assert!(r.errors() >= 2);

        // A missing boot sector signature is reported, not refused: Linux
        // mounts such a volume.
        let (img, v) = populated();
        v.close().unwrap();
        let dev = img.device();
        dev.write_at(510, &[0, 0]).unwrap();
        let r = check(&dev).unwrap();
        assert!(has(&r, ProblemKind::BootSignatureMissing), "{:?}", r.problems);
        drop(dev);
        assert_eq!(
            crate::volume::Volume::open(img.device())
                .unwrap()
                .read_dir("/")
                .unwrap()
                .len(),
            2
        );

        // Not FAT32 at all.
        let dev = img.device();
        dev.write_at(0, &[0u8; 512]).unwrap();
        assert_eq!(check(&dev).unwrap_err().errno(), EMEDIUMTYPE);
    }

    #[test]
    fn reports_are_bounded() {
        let mut r = Report::default();
        for i in 0..MAX_PROBLEMS + 7 {
            if i % 3 == 0 {
                r.error(|| Problem::new(ProblemKind::DuplicateName).count(i as u64));
            } else {
                r.warning(|| Problem::new(ProblemKind::LostClusters).count(i as u64));
            }
        }
        assert_eq!(r.problems.len(), MAX_PROBLEMS);
        assert_eq!(r.dropped, 7);
        assert_eq!(r.errors() + r.warnings(), MAX_PROBLEMS + 7);
        assert!(!r.is_clean());
    }

    #[test]
    fn what_boot_loaders_trip_over() {
        let (img, v) = populated();
        let layout = *v.layout();
        let root = v.boot_sector().root_cluster;
        let kernel = v.metadata("/EFI/Linux/kernel 1.efi").unwrap();
        let linux = v.metadata("/EFI/Linux").unwrap();
        v.close().unwrap();
        let dev = img.device();
        let fat_entry = |copy: u32, c: u32| layout.fat_offset(copy) + u64::from(c) * 4;
        let has = |r: &Report, kind: ProblemKind| r.problems.iter().any(|p| p.kind == kind);

        // Entry 1 says "not cleanly unmounted" in both FAT copies.
        for copy in 0..2 {
            dev.write_at(fat_entry(copy, 1), &0x07FF_FFFFu32.to_le_bytes()).unwrap();
        }
        // The reserved nibble of the kernel's first entry is set.
        let mut raw = [0u8; 4];
        dev.read_at(fat_entry(0, kernel.first_cluster), &mut raw).unwrap();
        let value = u32::from_le_bytes(raw) | 0xA000_0000;
        for copy in 0..2 {
            dev.write_at(fat_entry(copy, kernel.first_cluster), &value.to_le_bytes())
                .unwrap();
        }
        // A wrong type string and a label only in the boot sector.
        dev.write_at(0x52, b"FAT32XX ").unwrap();
        dev.write_at(0x47, b"OTHER      ").unwrap();
        // The root's "empty" entry gets a seconds field of 31 and its "EFI"
        // entry a reserved attribute bit; the first long name entry of
        // /EFI/Linux gets a non-zero first cluster field.
        let root_off = layout.cluster_offset(root).unwrap();
        dev.write_at(root_off + 32 + 22, &[0x1F, 0x00]).unwrap();
        dev.write_at(root_off + 11, &[0x50]).unwrap();
        let linux_off = layout.cluster_offset(linux.first_cluster).unwrap();
        dev.write_at(linux_off + 2 * 32 + 26, &[1, 0]).unwrap();
        // The root's last entry is followed by a long name slot with a
        // sequence byte that is out of range.
        let mut root_raw = vec![0u8; layout.cluster_size() as usize];
        dev.read_at(root_off, &mut root_raw).unwrap();
        let end = root_raw.chunks_exact(32).position(|s| s[0] == ENTRY_END).unwrap();
        let mut slot = [0u8; 32];
        slot[0] = 0x40 | 31;
        slot[11] = ATTR_LONG_NAME;
        dev.write_at(root_off + end as u64 * 32, &slot).unwrap();

        let r = check(&dev).unwrap();
        for kind in [
            ProblemKind::FatDirtyFlag,
            ProblemKind::ReservedBitsSet,
            ProblemKind::FileSystemTypeString,
            ProblemKind::LabelOnlyInBootSector,
            ProblemKind::AttributeReservedBits,
            ProblemKind::LongNameReservedBytes,
        ] {
            assert!(has(&r, kind), "missing {:?} in {:?}", kind, r.problems);
        }
        assert!(r.problems.iter().any(|p| {
            p.kind == ProblemKind::TimeInvalid && p.field == Some("modification") && p.value == Some(0x1f)
        }));
        assert!(r
            .problems
            .iter()
            .any(|p| p.kind == ProblemKind::LongNameBadSequence && p.value == Some(0x5f)));
        assert!(!has(&r, ProblemKind::FatHardwareErrorFlag), "{:?}", r.problems);
        // The nibble is an error: GRUB loses the file.
        assert!(r
            .problems
            .iter()
            .any(|p| p.severity == Severity::Error && p.kind == ProblemKind::ReservedBitsSet));
        // Every finding renders as a sentence that names its facts.
        for p in &r.problems {
            assert!(!p.to_string().contains('?'), "{} from {:?}", p, p);
        }

        // Entry 0 without the media byte is an error, GRUB refuses to mount.
        let (img, v) = populated();
        v.close().unwrap();
        let dev = img.device();
        for copy in 0..2 {
            dev.write_at(fat_entry(copy, 0), &0x0FFF_FFF0u32.to_le_bytes()).unwrap();
        }
        let r = check(&dev).unwrap();
        assert!(r
            .problems
            .iter()
            .any(|p| p.severity == Severity::Error && p.kind == ProblemKind::FatMediaEntry));
    }

    #[test]
    fn dot_entries_and_labels() {
        use crate::dirent::{RawDirEntry, ATTR_VOLUME_ID};
        use crate::format::{self, FormatOptions};

        // A subdirectory whose ".." entry was deleted.
        let (img, mut v) = volume(1 << 20, 512, 512);
        v.create_dir("/sub", t(0)).unwrap();
        v.create_file("/sub/F", t(0), false).unwrap().finish().unwrap();
        let sub = v.metadata("/sub").unwrap().first_cluster;
        let layout = *v.layout();
        v.close().unwrap();
        let dev = img.device();
        let off = layout.cluster_offset(sub).unwrap();
        dev.write_at(off + 32, &[0xE5]).unwrap();
        let r = check(&dev).unwrap();
        let missing = |r: &Report, which: &str| {
            r.problems
                .iter()
                .any(|p| p.kind == ProblemKind::DotEntryMissing && p.name.as_deref() == Some(which))
        };
        assert!(missing(&r, ".."), "{:?}", r.problems);
        assert!(!missing(&r, "."), "{:?}", r.problems);
        assert_eq!(r.errors(), 1, "{:?}", r.problems);

        // A label entry outside the root directory, in the free slot after
        // "F": a warning, not a name problem.
        let label = RawDirEntry {
            name: *b"LABEL      ",
            attr: ATTR_VOLUME_ID,
            ..RawDirEntry::default()
        };
        dev.write_at(off + 32, b".").unwrap();
        dev.write_at(off + 3 * 32, &label.to_bytes()).unwrap();
        let r = check(&dev).unwrap();
        assert_eq!(r.errors(), 0, "{:?}", r.problems);
        assert!(
            r.problems
                .iter()
                .any(|p| p.kind == ProblemKind::LabelOutsideRoot && p.name.as_deref() == Some("LABEL")),
            "{:?}",
            r.problems
        );
        let about_short_names = |r: &Report| {
            r.problems.iter().any(|p| {
                matches!(
                    p.kind,
                    ProblemKind::ShortNameLeadingSpace
                        | ProblemKind::ShortNameLowerCase
                        | ProblemKind::ShortNameInvalidCharacters
                )
            })
        };
        assert!(!about_short_names(&r), "{:?}", r.problems);

        // A lower case label is a warning about the label, as with fsck.fat.
        let img = TempImage::new(1 << 20);
        let opts = FormatOptions {
            sector_size: Some(512),
            cluster_size: Some(512),
            allow_small: true,
            label: Some("lower case".into()),
            ..FormatOptions::default()
        };
        format::format(&img.device(), &opts).unwrap();
        let r = check(&img.device()).unwrap();
        assert_eq!(r.errors(), 0, "{:?}", r.problems);
        assert!(
            r.problems
                .iter()
                .any(|p| p.kind == ProblemKind::LabelLowerCase && p.name.as_deref() == Some("lower case")),
            "{:?}",
            r.problems
        );
        assert!(!about_short_names(&r), "{:?}", r.problems);
    }

    /// The class names are the `ProblemClass` enum of the interface, in
    /// its order.
    #[test]
    fn classes_match_the_interface() {
        use ProblemClass::*;
        const CLASSES: [ProblemClass; 14] = [
            Superblock,
            Allocation,
            Directory,
            Name,
            Timestamp,
            Label,
            Chain,
            CrossLink,
            LostSpace,
            Dirty,
            Checksum,
            Journal,
            Interoperability,
            Other,
        ];
        let idl = include_str!("../docs/org.uapi-group.FileSystem.varlink");
        let line = idl
            .lines()
            .find(|l| l.starts_with("type ProblemClass("))
            .expect("the IDL defines ProblemClass");
        let names: Vec<&str> = line
            .trim_start_matches("type ProblemClass(")
            .trim_end_matches(')')
            .split(',')
            .map(str::trim)
            .collect();
        let ours: Vec<&str> = CLASSES.iter().map(|c| c.as_str()).collect();
        assert_eq!(ours, names);
    }

    /// Every kind has a class, none falls back to `other`, and none needs
    /// the journal FAT does not have.
    #[test]
    fn every_kind_has_a_class() {
        use ProblemKind::*;
        // Every variant, in the order of the enum.
        const KINDS: [ProblemKind; 64] = [
            BootSector,
            ClaimsMoreThanDevice,
            DirtyFlag,
            BelowMinimumClusters,
            BootSignatureMissing,
            FileSystemTypeString,
            BackupBootSectorDiffers,
            NoBackupBootSector,
            FsinfoSignatures,
            FsinfoTrailingSignature,
            FsinfoFreeCount,
            FsinfoNextFree,
            FatMediaEntry,
            FatDirtyFlag,
            FatHardwareErrorFlag,
            FatEntry1,
            FatCopyDiffers,
            ChainInvalidCluster,
            ChainLoop,
            FatReadFailed,
            ChainClusterFree,
            ChainClusterBad,
            ChainEntryInvalid,
            CrossLinked,
            CrossLinkedMore,
            DirectoryTooLong,
            EntryAfterEnd,
            OrphanedLongName,
            LongNameLastBitInside,
            LongNameReservedBytes,
            LongNameBadSequence,
            LongNameMismatch,
            LabelOutsideRoot,
            LabelEntryHasData,
            LabelLowerCase,
            AttributeReservedBits,
            DuplicateName,
            DirectoryEntrySize,
            DirectoryStartCluster,
            LabelEntries,
            LabelMismatch,
            LabelOnlyInBootSector,
            DotEntryMissing,
            LongNameTooLong,
            LongNamePadding,
            LongNameTrailingDot,
            LongNameTrailingSpace,
            LongNameInvalidCharacters,
            ShortNameLeadingSpace,
            ShortNameLowerCase,
            ShortNameInvalidCharacters,
            DateInvalid,
            TimeInvalid,
            CreationHundredthsInvalid,
            RootHasDotEntry,
            DotEntryNotDirectory,
            DotEntryCluster,
            DotDotPointsAtRoot,
            DotEntrySlot,
            SizeWithoutClusters,
            TooFewClusters,
            TooManyClusters,
            LostClusters,
            ReservedBitsSet,
        ];
        let mut seen = HashSet::new();
        for kind in KINDS {
            assert!(seen.insert(kind.as_str()), "{:?} is listed twice", kind);
            let class = kind.class();
            assert!(
                !matches!(class, ProblemClass::Other | ProblemClass::Journal),
                "{:?} is {:?}",
                kind,
                class
            );
        }
        // The rules behind the mapping, one kind each.
        for (kind, class) in [
            (BootSector, ProblemClass::Superblock),
            (FsinfoFreeCount, ProblemClass::Superblock),
            (BackupBootSectorDiffers, ProblemClass::Superblock),
            (FatMediaEntry, ProblemClass::Allocation),
            (TooFewClusters, ProblemClass::Allocation),
            (ReservedBitsSet, ProblemClass::Allocation),
            (ChainLoop, ProblemClass::Chain),
            (ChainClusterFree, ProblemClass::Chain),
            (CrossLinked, ProblemClass::CrossLink),
            (LostClusters, ProblemClass::LostSpace),
            (DotEntryMissing, ProblemClass::Directory),
            (OrphanedLongName, ProblemClass::Directory),
            (AttributeReservedBits, ProblemClass::Directory),
            (LongNameTrailingDot, ProblemClass::Name),
            (ShortNameLowerCase, ProblemClass::Name),
            (TimeInvalid, ProblemClass::Timestamp),
            (LabelLowerCase, ProblemClass::Label),
            (LabelOnlyInBootSector, ProblemClass::Label),
            (DirtyFlag, ProblemClass::Dirty),
            (FatDirtyFlag, ProblemClass::Dirty),
            (FatCopyDiffers, ProblemClass::Checksum),
            (LongNameMismatch, ProblemClass::Checksum),
            (BelowMinimumClusters, ProblemClass::Interoperability),
        ] {
            assert_eq!(kind.class(), class, "{:?}", kind);
        }
    }
}
