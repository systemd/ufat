// SPDX-License-Identifier: LGPL-2.1-or-later
//! The FAT32 boot sector (BPB) and the FSInfo sector.

use crate::bytes::{le16, le32};
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
/// The file system type string for FAT32.
pub const FS_TYPE_FAT32: [u8; 8] = *b"FAT32   ";
/// The label stored when the volume has none.
pub const NO_NAME: [u8; 11] = *b"NO NAME    ";
/// The OEM name the FAT specification recommends for maximum compatibility.
pub const OEM_NAME_DEFAULT: [u8; 8] = *b"MSWIN4.1";
/// The media descriptor for fixed media.
pub const MEDIA_FIXED: u8 = 0xF8;
/// The media descriptor for removable media.
pub const MEDIA_REMOVABLE: u8 = 0xF0;

/// Whether `media` is a media descriptor FAT allows: 0xF0, or 0xF8 to 0xFF.
pub fn valid_media(media: u8) -> bool {
    media == MEDIA_REMOVABLE || media >= MEDIA_FIXED
}
/// Bit in the NT flags byte (offset 0x41) marking a volume that was not
/// cleanly unmounted. Linux sets it when it mounts a clean volume read-write
/// and clears it on unmount, in sector 0 only (fs/fat/inode.c,
/// fat_set_state()); a volume it finds dirty it mounts anyway, warns about,
/// and leaves dirty for good.
pub const NT_FLAG_DIRTY: u8 = 0x01;
/// Offset of the NT flags byte in the boot sector.
pub const NT_FLAGS_OFFSET: usize = 0x41;
/// Bit in the extended flags that turns FAT mirroring off: then only one
/// FAT is active.
pub const EXT_FLAGS_NO_MIRRORING: u16 = 0x80;
/// The BIOS drive number of the first fixed disk.
pub const DRIVE_NUMBER_FIXED: u8 = 0x80;
/// The jump over the BPB to the boot code that mkfs.fat writes.
pub const BOOT_JUMP: [u8; 3] = [0xEB, 0x58, 0x90];
/// Size of the boot code area in a FAT32 boot sector.
pub const BOOT_CODE_SIZE: usize = 420;
/// Lead signature of the FSInfo sector ("RRaA").
pub const FSINFO_LEAD_SIGNATURE: u32 = 0x4161_5252;
/// Structure signature of the FSInfo sector ("rrAa").
pub const FSINFO_STRUCT_SIGNATURE: u32 = 0x6141_7272;
/// Trailing signature of the FSInfo sector.
pub const FSINFO_TRAIL_SIGNATURE: u32 = 0xAA55_0000;
/// Marker for an unknown free cluster count or next free hint.
pub const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

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
    pub jump: [u8; 3],
    /// OEM name.
    pub oem_name: [u8; 8],
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
    pub reserved: [u8; 12],
    /// BIOS drive number, 0x80 for fixed media.
    pub drive_number: u8,
    /// Windows NT flags, bit 0 is the dirty flag.
    pub nt_flags: u8,
    /// Extended boot signature, 0x29.
    pub ext_boot_signature: u8,
    /// Volume serial number.
    pub volume_id: u32,
    /// Volume label as stored in the boot sector.
    pub volume_label: [u8; 11],
    /// File system type string, "FAT32   ".
    pub fs_type: [u8; 8],
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
        let mut bs = BootSector {
            jump: [b[0], b[1], b[2]],
            oem_name: [0; 8],
            bytes_per_sector: le16(b, 11),
            sectors_per_cluster: b[13],
            reserved_sectors: le16(b, 14),
            fats: b[16],
            root_entries: le16(b, 17),
            total_sectors_16: le16(b, 19),
            media: b[21],
            fat_sectors_16: le16(b, 22),
            sectors_per_track: le16(b, 24),
            heads: le16(b, 26),
            hidden_sectors: le32(b, 28),
            total_sectors_32: le32(b, 32),
            fat_sectors_32: le32(b, 36),
            ext_flags: le16(b, 40),
            fs_version: le16(b, 42),
            root_cluster: le32(b, 44),
            fsinfo_sector: le16(b, 48),
            backup_boot_sector: le16(b, 50),
            reserved: [0; 12],
            drive_number: b[64],
            nt_flags: b[65],
            ext_boot_signature: b[66],
            volume_id: le32(b, 67),
            volume_label: [0; 11],
            fs_type: [0; 8],
            boot_code: [0; BOOT_CODE_SIZE],
            signature: le16(b, 510),
        };
        bs.oem_name.copy_from_slice(&b[3..11]);
        bs.reserved.copy_from_slice(&b[52..64]);
        bs.volume_label.copy_from_slice(&b[71..82]);
        bs.fs_type.copy_from_slice(&b[82..90]);
        bs.boot_code.copy_from_slice(&b[90..510]);
        Ok(bs)
    }

    /// Encodes the boot sector into its 512-byte on-disk form.
    pub fn to_bytes(&self) -> [u8; BOOT_SECTOR_SIZE] {
        let mut b = [0u8; BOOT_SECTOR_SIZE];
        b[0..3].copy_from_slice(&self.jump);
        b[3..11].copy_from_slice(&self.oem_name);
        b[11..13].copy_from_slice(&self.bytes_per_sector.to_le_bytes());
        b[13] = self.sectors_per_cluster;
        b[14..16].copy_from_slice(&self.reserved_sectors.to_le_bytes());
        b[16] = self.fats;
        b[17..19].copy_from_slice(&self.root_entries.to_le_bytes());
        b[19..21].copy_from_slice(&self.total_sectors_16.to_le_bytes());
        b[21] = self.media;
        b[22..24].copy_from_slice(&self.fat_sectors_16.to_le_bytes());
        b[24..26].copy_from_slice(&self.sectors_per_track.to_le_bytes());
        b[26..28].copy_from_slice(&self.heads.to_le_bytes());
        b[28..32].copy_from_slice(&self.hidden_sectors.to_le_bytes());
        b[32..36].copy_from_slice(&self.total_sectors_32.to_le_bytes());
        b[36..40].copy_from_slice(&self.fat_sectors_32.to_le_bytes());
        b[40..42].copy_from_slice(&self.ext_flags.to_le_bytes());
        b[42..44].copy_from_slice(&self.fs_version.to_le_bytes());
        b[44..48].copy_from_slice(&self.root_cluster.to_le_bytes());
        b[48..50].copy_from_slice(&self.fsinfo_sector.to_le_bytes());
        b[50..52].copy_from_slice(&self.backup_boot_sector.to_le_bytes());
        b[52..64].copy_from_slice(&self.reserved);
        b[64] = self.drive_number;
        b[65] = self.nt_flags;
        b[66] = self.ext_boot_signature;
        b[67..71].copy_from_slice(&self.volume_id.to_le_bytes());
        b[71..82].copy_from_slice(&self.volume_label);
        b[82..90].copy_from_slice(&self.fs_type);
        b[90..510].copy_from_slice(&self.boot_code);
        b[510..512].copy_from_slice(&self.signature.to_le_bytes());
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
        if le32(b, 0) != FSINFO_LEAD_SIGNATURE || le32(b, 484) != FSINFO_STRUCT_SIGNATURE {
            return None;
        }
        Some(FsInfo {
            free_clusters: le32(b, 488),
            next_free: le32(b, 492),
        })
    }

    /// Whether the trailing signature at offset 508 is present. Linux does
    /// not check it, EDK2 does.
    pub fn has_trail_signature(b: &[u8]) -> bool {
        b.len() >= FSINFO_SIZE && le32(b, 508) == FSINFO_TRAIL_SIGNATURE
    }

    /// Writes the two counters and the trailing signature into an FSInfo
    /// sector read from disk, leaving the reserved bytes as they are.
    pub fn patch(&self, sector: &mut [u8; FSINFO_SIZE]) {
        sector[488..492].copy_from_slice(&self.free_clusters.to_le_bytes());
        sector[492..496].copy_from_slice(&self.next_free.to_le_bytes());
        sector[508..512].copy_from_slice(&FSINFO_TRAIL_SIGNATURE.to_le_bytes());
    }

    /// Encodes the FSInfo sector into its 512-byte on-disk form.
    pub fn to_bytes(&self) -> [u8; FSINFO_SIZE] {
        let mut b = [0u8; FSINFO_SIZE];
        b[0..4].copy_from_slice(&FSINFO_LEAD_SIGNATURE.to_le_bytes());
        b[484..488].copy_from_slice(&FSINFO_STRUCT_SIGNATURE.to_le_bytes());
        b[488..492].copy_from_slice(&self.free_clusters.to_le_bytes());
        b[492..496].copy_from_slice(&self.next_free.to_le_bytes());
        b[508..512].copy_from_slice(&FSINFO_TRAIL_SIGNATURE.to_le_bytes());
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
        assert_eq!(&code[29..33], b"This");
        assert_eq!(code[29 + BOOT_MESSAGE.len() - 1], b'\n');
        assert!(code[29 + BOOT_MESSAGE.len()..].iter().all(|&b| b == 0));
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
        assert_eq!(&b[0..4], b"RRaA");
        assert_eq!(&b[484..488], b"rrAa");
        assert_eq!(b[510], 0x55);
        assert_eq!(b[511], 0xAA);
        let mut bad = b;
        bad[1] = 0;
        assert_eq!(FsInfo::parse(&bad), None);
    }
}
