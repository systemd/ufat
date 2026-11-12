// SPDX-License-Identifier: LGPL-2.1-or-later
//! What an image holds when it holds no FAT32 file system.
//!
//! A caller that is told that an image is blank may well format it, so
//! blank has to mean that nothing is there. When the boot sector does not
//! describe a FAT32 volume, the first 256 KiB of the image are read and
//! searched for the signatures of other file systems and partition tables,
//! at the offsets where blkid looks for them. Only an image that is zeros
//! all through those 256 KiB is blank.

use crate::bytes::{le16, le32};
use crate::device::Device;
use crate::errno::{EMEDIUMTYPE, EUCLEAN};
use crate::layout::valid_sector_size;
use crate::{CorruptPlace, Detail, Error, NotFat32Reason};

/// How much of the start of an image is searched. Every signature below
/// lies inside it: btrfs keeps its superblock at 64 KiB, and swap space
/// keeps its signature at the end of its first page, which can be 64 KiB.
pub(crate) const HEAD_SIZE: usize = 256 * 1024;

/// Signatures at fixed offsets, with the name blkid gives what carries
/// them.
const SIGNATURES: &[(usize, &[u8], &str)] = &[
    (0, b"LUKS\xba\xbe", "crypto_LUKS"),
    (0, b"XFSB", "xfs"),
    (0, b"hsqs", "squashfs"),
    (3, b"NTFS    ", "ntfs"),
    (3, b"EXFAT   ", "exfat"),
    // The GPT header is in the second sector: at 512 bytes, or at 4096
    // with 4096-byte sectors.
    (512, b"EFI PART", "gpt"),
    (4096, b"EFI PART", "gpt"),
    (32769, b"CD001", "iso9660"),
    (65536 + 64, b"_BHRfS_M", "btrfs"),
];

/// The offset of the ext2, ext3 and ext4 superblock.
const EXT_SUPERBLOCK: usize = 1024;

/// What the start of an image holds, when it is no FAT32 file system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Finding {
    /// Why it is not FAT32.
    pub(crate) reason: NotFat32Reason,
    /// The other file system or partition table, named the way blkid
    /// names it, except for FAT12 and FAT16, which are `fat12` and
    /// `fat16`.
    pub(crate) found: Option<&'static str>,
    /// The sector size of a FAT boot sector with one ufat does not
    /// support.
    pub(crate) sector_size: Option<u32>,
}

impl Finding {
    fn other(found: &'static str) -> Finding {
        Finding {
            reason: NotFat32Reason::NotFat32,
            found: Some(found),
            sector_size: None,
        }
    }

    fn reason(reason: NotFat32Reason) -> Finding {
        Finding {
            reason,
            found: None,
            sector_size: None,
        }
    }
}

/// Whether `head` holds `magic` at `offset`.
fn has(head: &[u8], offset: usize, magic: &[u8]) -> bool {
    head.get(offset..offset + magic.len()) == Some(magic)
}

/// The name blkid gives an ext2, ext3 or ext4 superblock. ext2 and ext3
/// have only the features they had, and ext3 has a journal. Anything else
/// is ext4.
fn ext_name(head: &[u8]) -> &'static str {
    let compat = le32(head, EXT_SUPERBLOCK + 0x5c);
    let incompat = le32(head, EXT_SUPERBLOCK + 0x60);
    let ro_compat = le32(head, EXT_SUPERBLOCK + 0x64);
    // has_journal; filetype, recover and meta_bg; sparse_super, large_file
    // and btree_dir.
    let journal = compat & 0x4 != 0;
    let old_ro_compat = ro_compat & !0x7 == 0;
    if journal && incompat & !(0x2 | 0x4 | 0x10) == 0 && old_ro_compat {
        "ext3"
    } else if !journal && incompat & !(0x2 | 0x10) == 0 && old_ro_compat {
        "ext2"
    } else {
        "ext4"
    }
}

/// Whether the boot sector looks like that of a FAT volume: the jump
/// instruction the FAT specification asks for, a media descriptor and one
/// or two FATs. A master boot record can start with the same jump, but it
/// has no media descriptor in its place.
fn looks_like_fat(head: &[u8]) -> bool {
    let jump = (head[0] == 0xeb && head[2] == 0x90) || head[0] == 0xe9;
    let media = head[21] == 0xf0 || head[21] >= 0xf8;
    jump && media && matches!(head[16], 1 | 2)
}

/// FAT12 or FAT16, told apart by the number of clusters as the FAT
/// specification says, for a boot sector with a 16-bit FAT size. None when
/// the fields don't add up.
fn fat12_or_16(head: &[u8]) -> Option<&'static str> {
    let bytes_per_sector = u64::from(le16(head, 11));
    let sectors_per_cluster = u64::from(head[13]);
    let reserved = u64::from(le16(head, 14));
    let fats = u64::from(head[16]);
    let root_entries = u64::from(le16(head, 17));
    let total = match le16(head, 19) {
        0 => u64::from(le32(head, 32)),
        n => u64::from(n),
    };
    let fat_sectors = u64::from(le16(head, 22));
    if bytes_per_sector == 0 || fat_sectors == 0 || !sectors_per_cluster.is_power_of_two() || reserved == 0 {
        return None;
    }
    let root_sectors = (root_entries * 32).div_ceil(bytes_per_sector);
    let data = total.checked_sub(reserved + fats * fat_sectors + root_sectors)?;
    match data / sectors_per_cluster {
        0 => None,
        1..4085 => Some("fat12"),
        4085..65525 => Some("fat16"),
        _ => None,
    }
}

/// An MBR partition table: the boot signature and four entries whose boot
/// flags are valid, at least one of them in use.
fn has_mbr(head: &[u8]) -> bool {
    if !has(head, 510, b"\x55\xaa") {
        return false;
    }
    let entries = || (0..4).map(|i| &head[446 + 16 * i..446 + 16 * (i + 1)]);
    entries().all(|e| matches!(e[0], 0x00 | 0x80))
        && entries().any(|e| e[4] != 0 && le32(e, 8) != 0 && le32(e, 12) != 0)
}

/// What `head`, the first [`HEAD_SIZE`] bytes of an image or all of a
/// smaller one, holds instead of a FAT32 file system. It is at least a
/// boot sector long.
pub(crate) fn classify(head: &[u8]) -> Finding {
    if let Some(&(_, _, name)) = SIGNATURES.iter().find(|(offset, magic, _)| has(head, *offset, magic)) {
        return Finding::other(name);
    }
    if head.len() >= EXT_SUPERBLOCK + 0x68 && has(head, EXT_SUPERBLOCK + 0x38, &0xef53u16.to_le_bytes()) {
        return Finding::other(ext_name(head));
    }
    // The signature ends the first page, whatever the page size is.
    let swap = [4096, 8192, 16384, 32768, 65536]
        .iter()
        .any(|page| has(head, page - 10, b"SWAPSPACE2") || has(head, page - 10, b"SWAP-SPACE"));
    if swap {
        return Finding::other("swap");
    }
    if looks_like_fat(head) {
        let bytes_per_sector = u32::from(le16(head, 11));
        if !valid_sector_size(bytes_per_sector) {
            return Finding {
                reason: NotFat32Reason::SectorSize,
                found: None,
                sector_size: Some(bytes_per_sector),
            };
        }
        return match fat12_or_16(head) {
            Some(name) => Finding::other(name),
            None => Finding::reason(NotFat32Reason::Unknown),
        };
    }
    if has_mbr(head) {
        return Finding::other("dos");
    }
    if head.iter().all(|&b| b == 0) {
        return Finding::reason(NotFat32Reason::Blank);
    }
    Finding::reason(NotFat32Reason::Unknown)
}

/// How the error message names what was found.
fn describe(found: &str) -> &str {
    match found {
        "crypto_LUKS" => "a LUKS volume",
        "swap" => "swap space",
        "gpt" => "a GPT partition table",
        "dos" => "an MBR partition table",
        "iso9660" => "an ISO 9660 file system",
        "fat12" => "a FAT12 file system",
        "fat16" => "a FAT16 file system",
        "ext2" => "an ext2 file system",
        "ext3" => "an ext3 file system",
        "ext4" => "an ext4 file system",
        "xfs" => "an XFS file system",
        "btrfs" => "a btrfs file system",
        "squashfs" => "a squashfs file system",
        "ntfs" => "an NTFS file system",
        "exfat" => "an exFAT file system",
        other => other,
    }
}

/// The error for a finding.
pub(crate) fn error(finding: Finding) -> Error {
    let detail = Detail::NotFat32 {
        reason: finding.reason,
        found: finding.found,
        sector_size: finding.sector_size,
    };
    match (finding.reason, finding.found, finding.sector_size) {
        (_, Some(found), _) => err!(
            EMEDIUMTYPE,
            detail,
            "the image holds {}, not a FAT32 file system",
            describe(found)
        ),
        (NotFat32Reason::SectorSize, _, Some(ss)) => err!(EMEDIUMTYPE, detail, "unsupported sector size {}", ss),
        (NotFat32Reason::Blank, _, _) => err!(EMEDIUMTYPE, detail, "no file system found, the image is blank"),
        _ => err!(
            EMEDIUMTYPE,
            detail,
            "no FAT32 file system found, and the image is not blank"
        ),
    }
}

/// Turns the error of a boot sector that is not FAT32, from
/// [`crate::boot::BootSector::parse`] or [`crate::boot::BootSector::validate`],
/// into one that says what `device` holds instead. A boot sector with a
/// field that makes no sense may well belong to another file system: an
/// NTFS boot sector reads like a FAT32 one up to its reserved sector
/// count. It stays a damaged FAT32 boot sector unless another file system
/// or partition table is found. Other errors pass through unchanged.
pub(crate) fn refine(e: Error, device: &Device) -> Error {
    let not_fat32 = matches!(
        e.detail(),
        Some(Detail::NotFat32 {
            reason: NotFat32Reason::Blank | NotFat32Reason::NotFat32 | NotFat32Reason::SectorSize,
            ..
        })
    );
    let damaged = e.errno() == EUCLEAN
        && matches!(
            e.detail(),
            Some(Detail::Corrupt {
                place: CorruptPlace::BootSector,
                ..
            })
        );
    if !not_fat32 && !damaged {
        return e;
    }
    let len = usize::try_from(device.len()).map_or(HEAD_SIZE, |len| len.min(HEAD_SIZE));
    let mut head = vec![0u8; len];
    if let Err(read) = device.read_at(0, &mut head) {
        return read;
    }
    let finding = classify(&head);
    if damaged && finding.found.is_none() {
        return e;
    }
    error(finding)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The start of an image, all zeros, with `magic` written at `offset`.
    fn head_with(offset: usize, magic: &[u8]) -> Vec<u8> {
        let mut head = vec![0u8; HEAD_SIZE];
        head[offset..offset + magic.len()].copy_from_slice(magic);
        head
    }

    fn found(head: &[u8]) -> Option<&'static str> {
        let f = classify(head);
        assert!(f.found.is_none() || f.reason == NotFat32Reason::NotFat32, "{:?}", f);
        f.found
    }

    #[test]
    fn zeros_are_blank_and_anything_else_is_not() {
        assert_eq!(classify(&vec![0u8; HEAD_SIZE]).reason, NotFat32Reason::Blank);
        assert_eq!(classify(&[0u8; 512]).reason, NotFat32Reason::Blank);
        // A single byte anywhere in the first 256 KiB is enough.
        let head = head_with(HEAD_SIZE - 1, b"x");
        assert_eq!(classify(&head).reason, NotFat32Reason::Unknown);
        assert_eq!(classify(&head_with(200_000, b"junk")).reason, NotFat32Reason::Unknown);
    }

    #[test]
    fn signatures_name_what_carries_them() {
        for &(offset, magic, name) in SIGNATURES {
            assert_eq!(found(&head_with(offset, magic)), Some(name), "{}", name);
        }
        for page in [4096, 65536] {
            assert_eq!(found(&head_with(page - 10, b"SWAPSPACE2")), Some("swap"));
        }
        // Too short to hold the btrfs superblock: whatever else it is, not
        // btrfs.
        assert_eq!(
            classify(&head_with(65600, b"_BHRfS_M")[..65600]).reason,
            NotFat32Reason::Blank
        );
    }

    #[test]
    fn ext_versions_go_by_their_features() {
        let ext = |compat: u32, incompat: u32, ro_compat: u32| {
            let mut head = head_with(EXT_SUPERBLOCK + 0x38, &0xef53u16.to_le_bytes());
            head[EXT_SUPERBLOCK + 0x5c..][..4].copy_from_slice(&compat.to_le_bytes());
            head[EXT_SUPERBLOCK + 0x60..][..4].copy_from_slice(&incompat.to_le_bytes());
            head[EXT_SUPERBLOCK + 0x64..][..4].copy_from_slice(&ro_compat.to_le_bytes());
            found(&head)
        };
        // What mke2fs writes for ext2, for ext3 and for ext4.
        assert_eq!(ext(0x38, 0x2, 0x3), Some("ext2"));
        assert_eq!(ext(0x3c, 0x2, 0x3), Some("ext3"));
        assert_eq!(ext(0x103c, 0x22c2, 0x46b), Some("ext4"));
        // A journal with extents is ext4, and so is no journal with them.
        assert_eq!(ext(0x3c, 0x42, 0x3), Some("ext4"));
        assert_eq!(ext(0x38, 0x42, 0x3), Some("ext4"));
    }

    /// A FAT12 or FAT16 boot sector the way mkfs.fat writes one.
    fn fat_boot_sector(bytes_per_sector: u16, total: u16, fat_sectors: u16) -> Vec<u8> {
        let mut head = vec![0u8; HEAD_SIZE];
        head[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
        head[11..13].copy_from_slice(&bytes_per_sector.to_le_bytes());
        head[13] = 4;
        head[14..16].copy_from_slice(&1u16.to_le_bytes());
        head[16] = 2;
        head[17..19].copy_from_slice(&512u16.to_le_bytes());
        head[19..21].copy_from_slice(&total.to_le_bytes());
        head[21] = 0xf8;
        head[22..24].copy_from_slice(&fat_sectors.to_le_bytes());
        head[510..512].copy_from_slice(b"\x55\xaa");
        head
    }

    #[test]
    fn fat12_and_fat16_go_by_their_cluster_count() {
        // 8192 sectors: 8192 - 1 - 2 * 6 - 32 = 8147 data sectors, 2036
        // clusters.
        assert_eq!(found(&fat_boot_sector(512, 8192, 6)), Some("fat12"));
        // 65535 sectors: 65535 - 1 - 2 * 64 - 32 = 65374 data sectors, 16343
        // clusters.
        assert_eq!(found(&fat_boot_sector(512, 65535, 64)), Some("fat16"));
        // A FAT boot sector with a sector size ufat does not support.
        let f = classify(&fat_boot_sector(1000, 8192, 6));
        assert_eq!((f.reason, f.sector_size), (NotFat32Reason::SectorSize, Some(1000)));
        // A FAT boot sector whose sizes don't add up is neither.
        assert_eq!(classify(&fat_boot_sector(512, 10, 6)).reason, NotFat32Reason::Unknown);
    }

    #[test]
    fn a_master_boot_record_is_a_partition_table() {
        let mut head = head_with(510, b"\x55\xaa");
        // One Linux partition from sector 2048 on, 20480 sectors long.
        head[446 + 4] = 0x83;
        head[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
        head[446 + 12..446 + 16].copy_from_slice(&20480u32.to_le_bytes());
        assert_eq!(found(&head), Some("dos"));
        // A boot flag other than 0x00 and 0x80 makes it no partition table.
        head[446 + 16] = 0x42;
        assert_eq!(classify(&head).reason, NotFat32Reason::Unknown);
        // The same jump as FAT's but no media descriptor: still the table.
        head[446 + 16] = 0;
        head[..3].copy_from_slice(&[0xeb, 0x63, 0x90]);
        assert_eq!(found(&head), Some("dos"));
    }

    #[test]
    fn errors_say_what_was_found() {
        let message = |head: &[u8]| error(classify(head)).to_string();
        assert!(message(&vec![0u8; HEAD_SIZE]).contains("the image is blank"));
        assert!(message(&head_with(0, b"XFSB")).contains("an XFS file system"));
        assert!(message(&head_with(200_000, b"junk")).contains("the image is not blank"));
        let e = error(classify(&head_with(65600, b"_BHRfS_M")));
        assert_eq!(e.errno(), EMEDIUMTYPE);
        assert!(matches!(
            e.detail(),
            Some(Detail::NotFat32 {
                reason: NotFat32Reason::NotFat32,
                found: Some("btrfs"),
                sector_size: None,
            })
        ));
    }
}
