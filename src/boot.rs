// SPDX-License-Identifier: LGPL-2.1-or-later
//! The FAT32 boot sector (BPB) and the FSInfo sector.

use crate::bytes::{bytes_at, le16_at, le32_at, size};
use crate::errno::*;
use crate::layout::Layout;
use crate::Result;
use crate::{CorruptPlace, Detail, NotFat32Reason};

/// The detail of a boot sector field that makes no sense.
fn bad_field(field: &'static str) -> Detail {
    Detail::Corrupt {
        place: CorruptPlace::BootSector,
        field: Some(field),
        path: None,
        cluster: None,
    }
}

/// Size of the boot sector structure. On 4096-byte sector volumes the rest
/// of the first sector is zero.
pub const BOOT_SECTOR_SIZE: usize = 512;
/// Size of the FSInfo structure, which takes the first bytes of its sector
/// whatever the sector size.
pub const FSINFO_SIZE: usize = 512;
/// The 0xAA55 signature at the end of the boot sector and the FSInfo sector.
pub const BOOT_SIGNATURE: u16 = 0xAA55;
/// The extended boot signature announcing the volume id/label/type fields.
pub const EXT_BOOT_SIGNATURE: u8 = 0x29;
/// The size of a volume label, [`field::VOLUME_LABEL`].
pub const LABEL_SIZE: usize = size(field::VOLUME_LABEL);
/// The size of an OEM name, [`field::OEM_NAME`].
pub const OEM_NAME_SIZE: usize = size(field::OEM_NAME);
/// The file system type string for FAT32.
pub const FS_TYPE_FAT32: [u8; size(field::FS_TYPE)] = *b"FAT32   ";
/// The label stored when the volume has none.
pub const NO_NAME: [u8; LABEL_SIZE] = *b"NO NAME    ";
/// The OEM name the FAT specification recommends for maximum compatibility.
pub const OEM_NAME_DEFAULT: [u8; OEM_NAME_SIZE] = *b"MSWIN4.1";
/// The media descriptor for fixed media.
pub const MEDIA_FIXED: u8 = 0xF8;
/// The media descriptor for removable media.
pub const MEDIA_REMOVABLE: u8 = 0xF0;

/// Whether `media` is a media descriptor FAT allows: 0xF0, or 0xF8 to 0xFF.
pub fn valid_media(media: u8) -> bool {
    media == MEDIA_REMOVABLE || media >= MEDIA_FIXED
}
/// Bit in the NT flags byte ([`field::NT_FLAGS`]) marking a volume that was
/// not cleanly unmounted. Linux sets it when it mounts a clean volume
/// read-write and clears it on unmount, in sector 0 only (fs/fat/inode.c,
/// fat_set_state()); a volume it finds dirty it mounts anyway, warns about,
/// and leaves dirty for good.
pub const NT_FLAG_DIRTY: u8 = 0x01;
/// Bit in the extended flags that turns FAT mirroring off: then only one
/// FAT is active.
pub const EXT_FLAGS_NO_MIRRORING: u16 = 0x80;
/// The BIOS drive number of the first fixed disk.
pub const DRIVE_NUMBER_FIXED: u8 = 0x80;
/// The jump over the BPB to the boot code that mkfs.fat writes.
pub const BOOT_JUMP: [u8; size(field::JUMP)] = [0xEB, 0x58, 0x90];
/// Size of the boot code area in a FAT32 boot sector.
pub const BOOT_CODE_SIZE: usize = size(field::BOOT_CODE);
/// Lead signature of the FSInfo sector ("RRaA").
pub const FSINFO_LEAD_SIGNATURE: u32 = 0x4161_5252;
/// Structure signature of the FSInfo sector ("rrAa").
pub const FSINFO_STRUCT_SIGNATURE: u32 = 0x6141_7272;
/// Trailing signature of the FSInfo sector.
pub const FSINFO_TRAIL_SIGNATURE: u32 = 0xAA55_0000;
/// Marker for an unknown free cluster count or next free hint.
pub const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

/// Where the fields of a FAT32 boot sector are, as the FAT specification
/// lays them out: the offset of a field of one byte, the bytes of a longer
/// one. Each comment gives the specification's name of the field.
pub mod field {
    use std::ops::Range;

    /// BS_jmpBoot, the jump to the boot code.
    pub const JUMP: Range<usize> = 0..3;
    /// BS_OEMName.
    pub const OEM_NAME: Range<usize> = 3..11;
    /// BPB_BytsPerSec.
    pub const BYTES_PER_SECTOR: Range<usize> = 11..13;
    /// BPB_SecPerClus.
    pub const SECTORS_PER_CLUSTER: usize = 13;
    /// BPB_RsvdSecCnt.
    pub const RESERVED_SECTORS: Range<usize> = 14..16;
    /// BPB_NumFATs.
    pub const FATS: usize = 16;
    /// BPB_RootEntCnt.
    pub const ROOT_ENTRIES: Range<usize> = 17..19;
    /// BPB_TotSec16.
    pub const TOTAL_SECTORS_16: Range<usize> = 19..21;
    /// BPB_Media.
    pub const MEDIA: usize = 21;
    /// BPB_FATSz16.
    pub const FAT_SECTORS_16: Range<usize> = 22..24;
    /// BPB_SecPerTrk.
    pub const SECTORS_PER_TRACK: Range<usize> = 24..26;
    /// BPB_NumHeads.
    pub const HEADS: Range<usize> = 26..28;
    /// BPB_HiddSec.
    pub const HIDDEN_SECTORS: Range<usize> = 28..32;
    /// BPB_TotSec32.
    pub const TOTAL_SECTORS_32: Range<usize> = 32..36;
    /// BPB_FATSz32.
    pub const FAT_SECTORS_32: Range<usize> = 36..40;
    /// BPB_ExtFlags.
    pub const EXT_FLAGS: Range<usize> = 40..42;
    /// BPB_FSVer.
    pub const FS_VERSION: Range<usize> = 42..44;
    /// BPB_RootClus.
    pub const ROOT_CLUSTER: Range<usize> = 44..48;
    /// BPB_FSInfo.
    pub const FSINFO_SECTOR: Range<usize> = 48..50;
    /// BPB_BkBootSec.
    pub const BACKUP_BOOT_SECTOR: Range<usize> = 50..52;
    /// BPB_Reserved.
    pub const RESERVED: Range<usize> = 52..64;
    /// BS_DrvNum.
    pub const DRIVE_NUMBER: usize = 64;
    /// BS_Reserved1, where Windows NT keeps its flags.
    pub const NT_FLAGS: usize = 65;
    /// BS_BootSig.
    pub const EXT_BOOT_SIGNATURE: usize = 66;
    /// BS_VolID.
    pub const VOLUME_ID: Range<usize> = 67..71;
    /// BS_VolLab.
    pub const VOLUME_LABEL: Range<usize> = 71..82;
    /// BS_FilSysType.
    pub const FS_TYPE: Range<usize> = 82..90;
    /// The boot code.
    pub const BOOT_CODE: Range<usize> = 90..510;
    /// Signature_word.
    pub const SIGNATURE: Range<usize> = 510..512;
}

/// Where the fields of the FSInfo structure are, as the FAT specification
/// lays them out. Each comment gives the specification's name of the field.
pub mod fsinfo_field {
    use std::ops::Range;

    /// FSI_LeadSig.
    pub const LEAD_SIGNATURE: Range<usize> = 0..4;
    /// FSI_Reserved1.
    pub const RESERVED1: Range<usize> = 4..484;
    /// FSI_StrucSig.
    pub const STRUCT_SIGNATURE: Range<usize> = 484..488;
    /// FSI_Free_Count.
    pub const FREE_CLUSTERS: Range<usize> = 488..492;
    /// FSI_Nxt_Free.
    pub const NEXT_FREE: Range<usize> = 492..496;
    /// FSI_Reserved2.
    pub const RESERVED2: Range<usize> = 496..508;
    /// FSI_TrailSig.
    pub const TRAIL_SIGNATURE: Range<usize> = 508..512;
}

/// The machine code part of the dummy boot code mkfs.fat installs: it prints
/// the message that follows it and waits for a key press. The 16-bit offset
/// at bytes 3-4 points at the message, which lives at 0x7c00 + 90 + 29.
const BOOT_CODE_HEAD: [u8; 29] = [
    0x0e, 0x1f, 0xbe, 0x77, 0x7c, 0xac, 0x22, 0xc0, 0x74, 0x0b, 0x56, 0xb4, 0x0e, 0xbb, 0x07, 0x00, 0xcd, 0x10, 0x5e,
    0xeb, 0xf0, 0x32, 0xe4, 0xcd, 0x16, 0xcd, 0x19, 0xeb, 0xfe,
];
const BOOT_MESSAGE: &[u8] =
    b"This is not a bootable disk.  Please insert a bootable floppy and\r\npress any key to try again ... \r\n";

/// Returns the boot code mkfs.fat writes into FAT32 boot sectors.
pub fn default_boot_code() -> [u8; BOOT_CODE_SIZE] {
    let mut code = [0u8; BOOT_CODE_SIZE];
    code[..BOOT_CODE_HEAD.len()].copy_from_slice(&BOOT_CODE_HEAD);
    code[BOOT_CODE_HEAD.len()..BOOT_CODE_HEAD.len() + BOOT_MESSAGE.len()].copy_from_slice(BOOT_MESSAGE);
    code
}

/// A decoded FAT32 boot sector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootSector {
    /// Jump instruction, normally EB 58 90.
    pub jump: [u8; size(field::JUMP)],
    /// OEM name.
    pub oem_name: [u8; OEM_NAME_SIZE],
    /// Bytes per logical sector.
    pub bytes_per_sector: u16,
    /// Sectors per cluster, a power of two up to 128.
    pub sectors_per_cluster: u8,
    /// Reserved sectors before the first FAT, including the boot sector.
    pub reserved_sectors: u16,
    /// Number of FAT copies.
    pub fats: u8,
    /// Root directory entries, 0 on FAT32.
    pub root_entries: u16,
    /// 16-bit total sector count, 0 on FAT32 (mkfs.fat still uses it for
    /// volumes below 65536 sectors).
    pub total_sectors_16: u16,
    /// Media descriptor, 0xF8 for fixed media.
    pub media: u8,
    /// 16-bit sectors per FAT, 0 on FAT32.
    pub fat_sectors_16: u16,
    /// Sectors per track, informational.
    pub sectors_per_track: u16,
    /// Heads, informational.
    pub heads: u16,
    /// Sectors preceding the volume on the medium, informational.
    pub hidden_sectors: u32,
    /// 32-bit total sector count.
    pub total_sectors_32: u32,
    /// Sectors per FAT.
    pub fat_sectors_32: u32,
    /// Extended flags: mirroring and active FAT. Always 0 here.
    pub ext_flags: u16,
    /// File system version, must be 0.
    pub fs_version: u16,
    /// First cluster of the root directory.
    pub root_cluster: u32,
    /// Sector holding the FSInfo structure.
    pub fsinfo_sector: u16,
    /// Sector holding the backup boot sector, 0 if none.
    pub backup_boot_sector: u16,
    /// Reserved, zero.
    pub reserved: [u8; size(field::RESERVED)],
    /// BIOS drive number, 0x80 for fixed media.
    pub drive_number: u8,
    /// Windows NT flags, bit 0 is the dirty flag.
    pub nt_flags: u8,
    /// Extended boot signature, 0x29.
    pub ext_boot_signature: u8,
    /// Volume serial number.
    pub volume_id: u32,
    /// Volume label as stored in the boot sector.
    pub volume_label: [u8; LABEL_SIZE],
    /// File system type string, "FAT32   ".
    pub fs_type: [u8; size(field::FS_TYPE)],
    /// Boot code.
    pub boot_code: [u8; BOOT_CODE_SIZE],
    /// Boot sector signature, 0xAA55.
    pub signature: u16,
}

impl BootSector {
    /// Decodes a boot sector from at least 512 bytes. No validation is done,
    /// use [`BootSector::validate`] for that.
    pub fn parse(b: &[u8]) -> Result<BootSector> {
        if b.len() < BOOT_SECTOR_SIZE {
            bail!(EINVAL, "boot sector buffer too small");
        }
        if b[..BOOT_SECTOR_SIZE].iter().all(|&x| x == 0) {
            bail!(
                EMEDIUMTYPE,
                Detail::NotFat32 {
                    reason: NotFat32Reason::Blank,
                    sector_size: None,
                },
                "no file system found, the boot sector is blank"
            );
        }
        Ok(BootSector {
            jump: bytes_at(b, field::JUMP),
            oem_name: bytes_at(b, field::OEM_NAME),
            bytes_per_sector: le16_at(b, field::BYTES_PER_SECTOR),
            sectors_per_cluster: b[field::SECTORS_PER_CLUSTER],
            reserved_sectors: le16_at(b, field::RESERVED_SECTORS),
            fats: b[field::FATS],
            root_entries: le16_at(b, field::ROOT_ENTRIES),
            total_sectors_16: le16_at(b, field::TOTAL_SECTORS_16),
            media: b[field::MEDIA],
            fat_sectors_16: le16_at(b, field::FAT_SECTORS_16),
            sectors_per_track: le16_at(b, field::SECTORS_PER_TRACK),
            heads: le16_at(b, field::HEADS),
            hidden_sectors: le32_at(b, field::HIDDEN_SECTORS),
            total_sectors_32: le32_at(b, field::TOTAL_SECTORS_32),
            fat_sectors_32: le32_at(b, field::FAT_SECTORS_32),
            ext_flags: le16_at(b, field::EXT_FLAGS),
            fs_version: le16_at(b, field::FS_VERSION),
            root_cluster: le32_at(b, field::ROOT_CLUSTER),
            fsinfo_sector: le16_at(b, field::FSINFO_SECTOR),
            backup_boot_sector: le16_at(b, field::BACKUP_BOOT_SECTOR),
            reserved: bytes_at(b, field::RESERVED),
            drive_number: b[field::DRIVE_NUMBER],
            nt_flags: b[field::NT_FLAGS],
            ext_boot_signature: b[field::EXT_BOOT_SIGNATURE],
            volume_id: le32_at(b, field::VOLUME_ID),
            volume_label: bytes_at(b, field::VOLUME_LABEL),
            fs_type: bytes_at(b, field::FS_TYPE),
            boot_code: bytes_at(b, field::BOOT_CODE),
            signature: le16_at(b, field::SIGNATURE),
        })
    }

    /// Encodes the boot sector into its 512-byte on-disk form.
    pub fn to_bytes(&self) -> [u8; BOOT_SECTOR_SIZE] {
        let mut b = [0u8; BOOT_SECTOR_SIZE];
        b[field::JUMP].copy_from_slice(&self.jump);
        b[field::OEM_NAME].copy_from_slice(&self.oem_name);
        b[field::BYTES_PER_SECTOR].copy_from_slice(&self.bytes_per_sector.to_le_bytes());
        b[field::SECTORS_PER_CLUSTER] = self.sectors_per_cluster;
        b[field::RESERVED_SECTORS].copy_from_slice(&self.reserved_sectors.to_le_bytes());
        b[field::FATS] = self.fats;
        b[field::ROOT_ENTRIES].copy_from_slice(&self.root_entries.to_le_bytes());
        b[field::TOTAL_SECTORS_16].copy_from_slice(&self.total_sectors_16.to_le_bytes());
        b[field::MEDIA] = self.media;
        b[field::FAT_SECTORS_16].copy_from_slice(&self.fat_sectors_16.to_le_bytes());
        b[field::SECTORS_PER_TRACK].copy_from_slice(&self.sectors_per_track.to_le_bytes());
        b[field::HEADS].copy_from_slice(&self.heads.to_le_bytes());
        b[field::HIDDEN_SECTORS].copy_from_slice(&self.hidden_sectors.to_le_bytes());
        b[field::TOTAL_SECTORS_32].copy_from_slice(&self.total_sectors_32.to_le_bytes());
        b[field::FAT_SECTORS_32].copy_from_slice(&self.fat_sectors_32.to_le_bytes());
        b[field::EXT_FLAGS].copy_from_slice(&self.ext_flags.to_le_bytes());
        b[field::FS_VERSION].copy_from_slice(&self.fs_version.to_le_bytes());
        b[field::ROOT_CLUSTER].copy_from_slice(&self.root_cluster.to_le_bytes());
        b[field::FSINFO_SECTOR].copy_from_slice(&self.fsinfo_sector.to_le_bytes());
        b[field::BACKUP_BOOT_SECTOR].copy_from_slice(&self.backup_boot_sector.to_le_bytes());
        b[field::RESERVED].copy_from_slice(&self.reserved);
        b[field::DRIVE_NUMBER] = self.drive_number;
        b[field::NT_FLAGS] = self.nt_flags;
        b[field::EXT_BOOT_SIGNATURE] = self.ext_boot_signature;
        b[field::VOLUME_ID].copy_from_slice(&self.volume_id.to_le_bytes());
        b[field::VOLUME_LABEL].copy_from_slice(&self.volume_label);
        b[field::FS_TYPE].copy_from_slice(&self.fs_type);
        b[field::BOOT_CODE].copy_from_slice(&self.boot_code);
        b[field::SIGNATURE].copy_from_slice(&self.signature.to_le_bytes());
        b
    }

    /// The total sector count, honouring the 16-bit field when it is set the
    /// way Linux and EDK2 do.
    pub fn total_sectors(&self) -> u32 {
        if self.total_sectors_16 != 0 {
            u32::from(self.total_sectors_16)
        } else {
            self.total_sectors_32
        }
    }

    /// Whether this boot sector describes a FAT32 volume. Like Linux and EDK2
    /// we decide structurally: a zero 16-bit FAT size with a non-zero 32-bit
    /// one.
    pub fn is_fat32(&self) -> bool {
        self.fat_sectors_16 == 0 && self.fat_sectors_32 != 0
    }

    /// Checks that the boot sector describes a FAT32 volume this crate can
    /// work with. Returns EMEDIUMTYPE if it is not FAT32 at all and EUCLEAN
    /// if the FAT32 fields are inconsistent.
    pub fn validate(&self) -> Result<()> {
        // The 0x55AA signature is not checked: Linux mounts a volume without
        // it (fat_read_bpb() never looks), the structural checks below are
        // what tells FAT32 apart, and fsck reports the missing signature.
        let ss = u32::from(self.bytes_per_sector);
        if !crate::layout::valid_sector_size(ss) {
            bail!(
                EMEDIUMTYPE,
                Detail::NotFat32 {
                    reason: NotFat32Reason::SectorSize,
                    sector_size: Some(ss),
                },
                "unsupported sector size {}",
                ss
            );
        }
        if !self.is_fat32() {
            bail!(
                EMEDIUMTYPE,
                Detail::NotFat32 {
                    reason: NotFat32Reason::NotFat32,
                    sector_size: None,
                },
                "not a FAT32 file system"
            );
        }
        if !self.sectors_per_cluster.is_power_of_two() {
            bail!(
                EUCLEAN,
                bad_field("sectorsPerCluster"),
                "invalid sectors per cluster {}",
                self.sectors_per_cluster
            );
        }
        if self.reserved_sectors < 2 {
            bail!(
                EUCLEAN,
                bad_field("reservedSectors"),
                "invalid reserved sector count {}",
                self.reserved_sectors
            );
        }
        if self.fats == 0 {
            bail!(EUCLEAN, bad_field("fatCount"), "invalid FAT count 0");
        }
        if !valid_media(self.media) {
            bail!(
                EUCLEAN,
                bad_field("mediaDescriptor"),
                "invalid media descriptor 0x{:02x}",
                self.media
            );
        }
        if self.root_entries != 0 {
            bail!(
                EUCLEAN,
                bad_field("rootEntries"),
                "FAT32 root entry count {} is not 0",
                self.root_entries
            );
        }
        if self.fs_version != 0 {
            bail!(
                EUCLEAN,
                bad_field("version"),
                "unsupported FAT32 version 0x{:04x}",
                self.fs_version
            );
        }
        if self.ext_flags & EXT_FLAGS_NO_MIRRORING != 0 {
            bail!(
                EUCLEAN,
                bad_field("extFlags"),
                "FAT mirroring is disabled (ext flags 0x{:04x}), unsupported",
                self.ext_flags
            );
        }
        if self.total_sectors() == 0 {
            bail!(EUCLEAN, bad_field("totalSectors"), "total sector count is 0");
        }
        if self.fsinfo_sector == 0 || self.fsinfo_sector >= self.reserved_sectors {
            bail!(
                EUCLEAN,
                bad_field("fsinfoSector"),
                "FSInfo sector {} is not inside the reserved area",
                self.fsinfo_sector
            );
        }
        if self.backup_boot_sector != 0
            && (self.backup_boot_sector >= self.reserved_sectors || self.backup_boot_sector == self.fsinfo_sector)
        {
            bail!(
                EUCLEAN,
                bad_field("backupBootSector"),
                "backup boot sector {} is invalid",
                self.backup_boot_sector
            );
        }
        Ok(())
    }

    /// Derives the volume layout from the boot sector. The cluster count is
    /// clamped to what the FAT can address, like Linux does.
    pub fn layout(&self) -> Result<Layout> {
        self.validate()?;
        let spc = u32::from(self.sectors_per_cluster);
        let data_start = u64::from(self.reserved_sectors) + u64::from(self.fats) * u64::from(self.fat_sectors_32);
        let total = u64::from(self.total_sectors());
        if total <= data_start {
            bail!(
                EUCLEAN,
                bad_field("totalSectors"),
                "total sector count {} does not reach past the FATs ({} sectors)",
                total,
                data_start
            );
        }
        let mut clusters = ((total - data_start) / u64::from(spc)) as u32;
        // Entries the FAT has room for; compared in 64 bits since a 4096
        // byte sector FAT of 2^22 sectors overflows a u32.
        let capacity =
            (u64::from(self.fat_sectors_32) * u64::from(self.bytes_per_sector) / 4).min(u64::from(u32::MAX) + 2);
        if capacity < 3 {
            bail!(EUCLEAN, bad_field("fatSectors"), "FAT too small for any cluster");
        }
        if u64::from(clusters) > capacity - 2 {
            clusters = (capacity - 2) as u32;
        }
        if clusters == 0 {
            bail!(EUCLEAN, bad_field("clusters"), "volume has no data clusters");
        }
        if clusters > crate::layout::MAX_CLUSTERS {
            bail!(
                EUCLEAN,
                bad_field("clusters"),
                "cluster count {} exceeds the FAT32 maximum",
                clusters
            );
        }
        if self.root_cluster < 2 || self.root_cluster > clusters + 1 {
            bail!(
                EUCLEAN,
                bad_field("rootCluster"),
                "root directory cluster {} is out of range",
                self.root_cluster
            );
        }
        Ok(Layout {
            sector_size: u32::from(self.bytes_per_sector),
            sectors_per_cluster: spc,
            reserved_sectors: u32::from(self.reserved_sectors),
            fats: u32::from(self.fats),
            fat_sectors: self.fat_sectors_32,
            total_sectors: self.total_sectors(),
            clusters,
        })
    }
}

/// The FSInfo sector contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsInfo {
    /// Number of free clusters, or [`FSINFO_UNKNOWN`].
    pub free_clusters: u32,
    /// Hint where to start looking for free clusters, or
    /// [`FSINFO_UNKNOWN`].
    pub next_free: u32,
}

impl FsInfo {
    /// Decodes an FSInfo sector. Returns None if the signatures are wrong.
    /// The structure always lives in the first 512 bytes of the sector,
    /// whatever the sector size.
    pub fn parse(b: &[u8]) -> Option<FsInfo> {
        if b.len() < FSINFO_SIZE {
            return None;
        }
        if le32_at(b, fsinfo_field::LEAD_SIGNATURE) != FSINFO_LEAD_SIGNATURE
            || le32_at(b, fsinfo_field::STRUCT_SIGNATURE) != FSINFO_STRUCT_SIGNATURE
        {
            return None;
        }
        Some(FsInfo {
            free_clusters: le32_at(b, fsinfo_field::FREE_CLUSTERS),
            next_free: le32_at(b, fsinfo_field::NEXT_FREE),
        })
    }

    /// Whether the trailing signature is present. Linux does not check it,
    /// EDK2 does.
    pub fn has_trail_signature(b: &[u8]) -> bool {
        b.len() >= FSINFO_SIZE && le32_at(b, fsinfo_field::TRAIL_SIGNATURE) == FSINFO_TRAIL_SIGNATURE
    }

    /// Writes the two counters and the trailing signature into an FSInfo
    /// sector read from disk, leaving the reserved bytes as they are.
    pub fn patch(&self, sector: &mut [u8; FSINFO_SIZE]) {
        sector[fsinfo_field::FREE_CLUSTERS].copy_from_slice(&self.free_clusters.to_le_bytes());
        sector[fsinfo_field::NEXT_FREE].copy_from_slice(&self.next_free.to_le_bytes());
        sector[fsinfo_field::TRAIL_SIGNATURE].copy_from_slice(&FSINFO_TRAIL_SIGNATURE.to_le_bytes());
    }

    /// Encodes the FSInfo sector into its 512-byte on-disk form.
    pub fn to_bytes(&self) -> [u8; FSINFO_SIZE] {
        let mut b = [0u8; FSINFO_SIZE];
        b[fsinfo_field::LEAD_SIGNATURE].copy_from_slice(&FSINFO_LEAD_SIGNATURE.to_le_bytes());
        b[fsinfo_field::STRUCT_SIGNATURE].copy_from_slice(&FSINFO_STRUCT_SIGNATURE.to_le_bytes());
        b[fsinfo_field::FREE_CLUSTERS].copy_from_slice(&self.free_clusters.to_le_bytes());
        b[fsinfo_field::NEXT_FREE].copy_from_slice(&self.next_free.to_le_bytes());
        b[fsinfo_field::TRAIL_SIGNATURE].copy_from_slice(&FSINFO_TRAIL_SIGNATURE.to_le_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_code_matches_mkfs_fat() {
        let code = default_boot_code();
        assert_eq!(&code[..5], &[0x0e, 0x1f, 0xbe, 0x77, 0x7c]);
        let message = &code[BOOT_CODE_HEAD.len()..];
        assert_eq!(&message[..4], b"This");
        assert_eq!(message[BOOT_MESSAGE.len() - 1], b'\n');
        assert!(message[BOOT_MESSAGE.len()..].iter().all(|&b| b == 0));
    }

    #[test]
    fn fsinfo_round_trip() {
        let fi = FsInfo {
            free_clusters: 1234,
            next_free: 7,
        };
        let b = fi.to_bytes();
        assert_eq!(FsInfo::parse(&b), Some(fi));
        assert!(FsInfo::has_trail_signature(&b));
        assert_eq!(&b[fsinfo_field::LEAD_SIGNATURE], b"RRaA");
        assert_eq!(&b[fsinfo_field::STRUCT_SIGNATURE], b"rrAa");
        assert_eq!(b[fsinfo_field::TRAIL_SIGNATURE], FSINFO_TRAIL_SIGNATURE.to_le_bytes());
        let mut bad = b;
        bad[fsinfo_field::LEAD_SIGNATURE.start + 1] = 0;
        assert_eq!(FsInfo::parse(&bad), None);
    }
}
