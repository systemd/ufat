// SPDX-License-Identifier: LGPL-2.1-or-later
//! What an image holds when it holds no FAT32 file system.
//!
//! A caller that is told that an image is blank may well format it, so
//! blank has to mean that nothing is there. ext2, ext3, ext4, btrfs, swap
//! space and ISO 9660 leave the first sector zeroed and keep their
//! signatures further in. So an image counts as blank only when its first
//! 256 KiB are zeros. A sector size this crate does not support is the
//! reason only for a boot sector that looks like that of a FAT volume.
//! Anything else is data this crate does not recognize.

use crate::boot::{BootSector, BOOT_SECTOR_SIZE};
use crate::device::Device;
use crate::errno::EMEDIUMTYPE;
use crate::{Detail, Error, NotFat32Reason, Result};

/// How much of the start of an image has to be zeros for it to count as
/// blank. File systems and partition tables keep their signatures in
/// there: btrfs its superblock at 64 KiB, swap space its signature at the
/// end of its first page, which can be 64 KiB long.
const HEAD_SIZE: u64 = 256 * 1024;

/// What an image holds instead of a FAT32 file system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Contents {
    /// Its first [`HEAD_SIZE`] bytes are zeros, or all of a smaller image.
    Blank,
    /// Data this crate does not recognize.
    Unknown,
}

impl Contents {
    /// What `device` holds.
    fn of(device: &Device) -> Result<Contents> {
        let mut head = vec![0u8; device.len().min(HEAD_SIZE) as usize];
        device.read_at(0, &mut head)?;
        Ok(if head.iter().all(|&b| b == 0) {
            Contents::Blank
        } else {
            Contents::Unknown
        })
    }

    /// The error of an image that holds this instead of a FAT32 file
    /// system.
    fn error(self) -> Error {
        let (reason, message) = match self {
            Contents::Blank => (NotFat32Reason::Blank, "no file system found, the image is blank"),
            Contents::Unknown => (
                NotFat32Reason::Unknown,
                "no FAT32 file system found, and the image is not blank",
            ),
        };
        err!(
            EMEDIUMTYPE,
            Detail::NotFat32 {
                reason,
                sector_size: None,
            },
            "{}",
            message
        )
    }
}

/// Turns the error of a boot sector that is not FAT32's, from
/// [`crate::boot::BootSector::parse`], [`crate::boot::BootSector::validate`]
/// or [`crate::boot::BootSector::layout`], into one that says what `device`
/// holds instead: nothing, when its first [`HEAD_SIZE`] bytes are zeros,
/// or data this crate does not recognize. A sector size this crate does
/// not support stays the reason when `boot`, the first sector of
/// `device`, looks like a FAT boot sector. Other errors pass through
/// unchanged.
pub(crate) fn refine(e: Error, device: &Device, boot: &[u8; BOOT_SECTOR_SIZE]) -> Error {
    let reason = match e.detail() {
        Some(Detail::NotFat32 { reason, .. }) => *reason,
        _ => return e,
    };
    match reason {
        NotFat32Reason::SectorSize if BootSector::looks_like_fat(boot) => e,
        NotFat32Reason::Blank | NotFat32Reason::NotFat32 | NotFat32Reason::SectorSize => match Contents::of(device) {
            Ok(contents) => contents.error(),
            Err(read) => read,
        },
        NotFat32Reason::TooSmall | NotFat32Reason::Unknown => e,
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;
    use crate::boot::{field, short_jump, BOOT_SIGNATURE, MEDIA_FIXED};
    use crate::device::Access;
    use crate::layout::{DEFAULT_FATS, MIN_SECTOR_SIZE};
    use crate::test_util::TempImage;

    /// Where an ext2, ext3 or ext4 file system keeps its magic number: the
    /// s_magic field of the superblock, which starts 1024 bytes in.
    const EXT2_MAGIC_FIELD: Range<usize> = 1080..1082;
    /// The magic number of an ext2, ext3 or ext4 superblock.
    const EXT2_SUPER_MAGIC: u16 = 0xEF53;
    /// An image smaller than [`HEAD_SIZE`], which is looked at as a whole.
    const SMALL_IMAGE: u64 = 4096;
    /// A byte that fills an image with data. Two of it, 0x5555, make no
    /// sector size.
    const GARBAGE: u8 = 0x55;
    /// The sector size of the FAT16 boot sectors the tests write, and one
    /// that no FAT file system has, as it is not a power of two.
    const SECTOR_SIZE: u16 = MIN_SECTOR_SIZE as u16;
    const ODD_SECTOR_SIZE: u16 = 1000;
    /// Where the boot code of a FAT12 or FAT16 boot sector starts, behind
    /// its BPB, and the geometry of the FAT16 boot sectors the tests write:
    /// four sectors per cluster, one reserved sector, FATs of 64 sectors
    /// and 512 entries in the root directory.
    const FAT16_BOOT_CODE: usize = 62;
    const FAT16_SECTORS_PER_CLUSTER: u8 = 4;
    const FAT16_RESERVED_SECTORS: u16 = 1;
    const FAT16_FAT_SECTORS: u16 = 64;
    const FAT16_ROOT_ENTRIES: u16 = 512;

    /// An image of `len` zeros with `bytes` written at each offset.
    fn image(len: u64, edits: &[(u64, &[u8])]) -> TempImage {
        let img = TempImage::new(len);
        let device = Device::open(img.path(), Access::ReadWrite).unwrap();
        for &(offset, bytes) in edits {
            device.write_at(offset, bytes).unwrap();
        }
        img
    }

    /// What opening a volume says about the image, through the first
    /// error the boot sector gives.
    fn reason(img: &TempImage) -> (NotFat32Reason, Option<u32>) {
        let device = Device::open(img.path(), Access::ReadOnly).unwrap();
        let mut boot = [0u8; BOOT_SECTOR_SIZE];
        device.read_at(0, &mut boot).unwrap();
        let e = BootSector::parse(&boot)
            .and_then(|b| b.validate())
            .expect_err("not a FAT32 boot sector");
        match refine(e, &device, &boot).detail() {
            Some(Detail::NotFat32 { reason, sector_size }) => (*reason, *sector_size),
            other => panic!("{:?}", other),
        }
    }

    /// A FAT16 boot sector the way mkfs.fat writes one, with
    /// `bytes_per_sector` and as many sectors as its 16-bit count holds.
    fn fat16(bytes_per_sector: u16) -> [u8; BOOT_SECTOR_SIZE] {
        let mut b = [0u8; BOOT_SECTOR_SIZE];
        b[field::JUMP].copy_from_slice(&short_jump(FAT16_BOOT_CODE));
        b[field::BYTES_PER_SECTOR].copy_from_slice(&bytes_per_sector.to_le_bytes());
        b[field::SECTORS_PER_CLUSTER] = FAT16_SECTORS_PER_CLUSTER;
        b[field::RESERVED_SECTORS].copy_from_slice(&FAT16_RESERVED_SECTORS.to_le_bytes());
        b[field::FATS] = DEFAULT_FATS as u8;
        b[field::ROOT_ENTRIES].copy_from_slice(&FAT16_ROOT_ENTRIES.to_le_bytes());
        b[field::TOTAL_SECTORS_16].copy_from_slice(&u16::MAX.to_le_bytes());
        b[field::MEDIA] = MEDIA_FIXED;
        b[field::FAT_SECTORS_16].copy_from_slice(&FAT16_FAT_SECTORS.to_le_bytes());
        b[field::SIGNATURE].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
        b
    }

    #[test]
    fn only_zeros_are_blank() {
        assert_eq!(reason(&image(1 << 20, &[])), (NotFat32Reason::Blank, None));
        // An ext2 superblock behind a first sector of zeros.
        let ext2 = image(
            1 << 20,
            &[(EXT2_MAGIC_FIELD.start as u64, &EXT2_SUPER_MAGIC.to_le_bytes())],
        );
        assert_eq!(reason(&ext2).0, NotFat32Reason::Unknown);
        // A single byte anywhere in the first 256 KiB is enough, and what
        // lies behind them does not count.
        assert_eq!(
            reason(&image(1 << 20, &[(HEAD_SIZE - 1, b"x")])).0,
            NotFat32Reason::Unknown
        );
        assert_eq!(reason(&image(1 << 20, &[(HEAD_SIZE, b"x")])).0, NotFat32Reason::Blank);
        // An image smaller than that is looked at as a whole.
        assert_eq!(reason(&image(SMALL_IMAGE, &[])).0, NotFat32Reason::Blank);
        assert_eq!(
            reason(&image(SMALL_IMAGE, &[(SMALL_IMAGE - 1, b"x")])).0,
            NotFat32Reason::Unknown
        );
    }

    #[test]
    fn sector_size_is_for_fat_boot_sectors() {
        // A FAT boot sector with a sector size this crate does not support.
        let odd = image(1 << 20, &[(0, &fat16(ODD_SECTOR_SIZE))]);
        assert_eq!(
            reason(&odd),
            (NotFat32Reason::SectorSize, Some(u32::from(ODD_SECTOR_SIZE)))
        );
        // Data whose sector size field makes no sector size: not FAT at all.
        let garbage = TempImage::new(0);
        std::fs::write(garbage.path(), vec![GARBAGE; 1 << 20]).unwrap();
        assert_eq!(reason(&garbage).0, NotFat32Reason::Unknown);
        // A FAT16 boot sector is not one of FAT32.
        assert_eq!(
            reason(&image(1 << 20, &[(0, &fat16(SECTOR_SIZE))])).0,
            NotFat32Reason::Unknown
        );
        // The jump of a master boot record without a media descriptor.
        let mut mbr = fat16(ODD_SECTOR_SIZE);
        mbr[field::MEDIA] = 0;
        assert_eq!(reason(&image(1 << 20, &[(0, &mbr)])).0, NotFat32Reason::Unknown);
    }

    /// An image too small for a boot sector stays that, and an error that
    /// is not about the boot sector stays what it is.
    #[test]
    fn other_errors_pass_through() {
        let device = Device::open(image(SMALL_IMAGE, &[]).path(), Access::ReadOnly).unwrap();
        let boot = [0u8; BOOT_SECTOR_SIZE];
        let e = err!(EMEDIUMTYPE, "unrelated");
        assert_eq!(refine(e.clone(), &device, &boot), e);
        let e = err!(
            EMEDIUMTYPE,
            Detail::NotFat32 {
                reason: NotFat32Reason::TooSmall,
                sector_size: None,
            },
            "too small"
        );
        assert_eq!(refine(e.clone(), &device, &boot), e);
    }
}
