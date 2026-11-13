// SPDX-License-Identifier: LGPL-2.1-or-later
//! What an image holds when it holds no FAT32 file system.
//!
//! A caller that is told that an image is blank may well format it, so
//! blank has to mean that nothing is there. ext2, ext3, ext4, btrfs, swap
//! space and ISO 9660 leave the first sector zeroed and keep their
//! signatures further in. So an image counts as blank only when its first
//! 256 KiB are zeros.
//!
//! libblkid names what an image holds instead: another file system, a
//! partition table, an encrypted volume and so on. ufat loads it at run
//! time, the first time it needs it, and works without it. Without
//! libblkid an image that is not blank holds data this crate does not
//! recognize, except for a FAT boot sector with a sector size this crate
//! does not support.

use std::os::fd::AsFd;

use blkid::{Blkid, Found};

use crate::boot::{BootSector, BOOT_SECTOR_SIZE};
use crate::device::Device;
use crate::errno::{EMEDIUMTYPE, EUCLEAN};
use crate::sys::{reopen, O_NOCTTY, O_NONBLOCK, O_RDONLY};
use crate::{Context, CorruptPlace, Detail, Error, NotFat32Reason, Result};

/// How much of the start of an image has to be zeros for it to count as
/// blank. File systems and partition tables keep their signatures in
/// there: btrfs its superblock at 64 KiB, swap space its signature at the
/// end of its first page, which can be 64 KiB long.
const HEAD_SIZE: u64 = 256 * 1024;

/// What kind of [`ImageType`] libblkid found: libblkid's USAGE for a
/// superblock, or a partition table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    FileSystem,
    Crypto,
    Raid,
    Other,
    PartitionTable,
}

/// A file system, a partition table or anything else libblkid
/// recognizes, named the way libblkid names it. A FAT12 or FAT16 volume,
/// which is vfat to libblkid, is fat12 or fat16 after the version libblkid
/// gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ImageType {
    name: String,
    kind: Kind,
}

impl ImageType {
    /// What libblkid found: the superblock when there is one, the
    /// partition table otherwise.
    fn from_blkid(found: &Found) -> Option<ImageType> {
        let Some(name) = &found.name else {
            return found.partition_table.as_ref().map(|name| ImageType {
                name: name.clone(),
                kind: Kind::PartitionTable,
            });
        };
        let name = match (name.as_str(), found.version.as_deref()) {
            ("vfat", Some("FAT12")) => "fat12".to_string(),
            ("vfat", Some("FAT16")) => "fat16".to_string(),
            _ => name.clone(),
        };
        let kind = match found.usage.as_deref() {
            Some("filesystem") => Kind::FileSystem,
            Some("crypto") => Kind::Crypto,
            Some("raid") => Kind::Raid,
            _ => Kind::Other,
        };
        Some(ImageType { name, kind })
    }

    /// Whether it is a FAT volume.
    fn is_fat(&self) -> bool {
        matches!(self.name.as_str(), "vfat" | "fat12" | "fat16")
    }

    /// How a message names it.
    fn describe(&self) -> String {
        match (self.name.as_str(), self.kind) {
            ("fat12", _) => "a FAT12 file system".to_string(),
            ("fat16", _) => "a FAT16 file system".to_string(),
            ("vfat", _) => "a FAT file system".to_string(),
            (name, Kind::FileSystem) => format!("a file system of type {}", name),
            (name, Kind::Crypto) => format!("an encrypted volume of type {}", name),
            (name, Kind::Raid) => format!("a RAID or volume manager member of type {}", name),
            (name, Kind::Other) => format!("data of type {}", name),
            (name, Kind::PartitionTable) => format!("a partition table of type {}", name),
        }
    }
}

/// What an image holds.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Contents {
    /// Its first [`HEAD_SIZE`] bytes are zeros, or all of a smaller image,
    /// and libblkid, where it was asked, found nothing.
    Blank,
    /// Something libblkid recognizes.
    Found(ImageType),
    /// Data. `probed` says whether libblkid looked at it and recognized
    /// nothing, or was not there to ask.
    Unknown { probed: bool },
}

impl Contents {
    /// The error of an image that holds this instead of a FAT32 file
    /// system.
    fn error(&self) -> Error {
        let detail = |reason, found| Detail::NotFat32 {
            reason,
            found,
            sector_size: None,
        };
        match self {
            Contents::Blank => err!(
                EMEDIUMTYPE,
                detail(NotFat32Reason::Blank, None),
                "no file system found, the image is blank"
            ),
            Contents::Found(image_type) => err!(
                EMEDIUMTYPE,
                detail(NotFat32Reason::NotFat32, Some(image_type.name.clone())),
                "no FAT32 file system found, the image holds {}",
                image_type.describe()
            ),
            Contents::Unknown { probed } => err!(
                EMEDIUMTYPE,
                detail(NotFat32Reason::Unknown, None),
                "no FAT32 file system found, the image is not blank and libblkid {}",
                if *probed {
                    "does not recognize it"
                } else {
                    "is not available"
                }
            ),
        }
    }
}

/// What went wrong with a boot sector.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Failure {
    /// It is zeros, or not FAT32's.
    NotFat32,
    /// A sector size this crate does not support.
    SectorSize,
    /// A field of a FAT32 boot sector makes no sense.
    Damaged,
}

impl Failure {
    /// What went wrong with the boot sector that `e` is about, None when
    /// `e` is about something else.
    fn of(e: &Error) -> Option<Failure> {
        match e.detail() {
            Some(Detail::NotFat32 {
                reason: NotFat32Reason::Blank | NotFat32Reason::NotFat32,
                ..
            }) => Some(Failure::NotFat32),
            Some(Detail::NotFat32 {
                reason: NotFat32Reason::SectorSize,
                ..
            }) => Some(Failure::SectorSize),
            Some(Detail::Corrupt {
                place: CorruptPlace::BootSector,
                ..
            }) if e.errno() == EUCLEAN => Some(Failure::Damaged),
            _ => None,
        }
    }
}

/// Looks at what an image holds, with libblkid when it can be loaded.
#[derive(Clone, Copy)]
pub struct Prober {
    blkid: Option<&'static Blkid>,
}

impl Default for Prober {
    fn default() -> Prober {
        Prober::new()
    }
}

impl Prober {
    /// A prober with libblkid when it can be loaded. The first one loads
    /// it.
    pub fn new() -> Prober {
        Prober { blkid: Blkid::get() }
    }

    /// A prober without libblkid, as on a system that does not have it.
    #[cfg(test)]
    fn without_libblkid() -> Prober {
        Prober { blkid: None }
    }

    /// Whether libblkid is there to name what an image holds.
    pub fn has_libblkid(&self) -> bool {
        self.blkid.is_some()
    }

    /// What `device` holds.
    fn examine(&self, device: &Device) -> Result<Contents> {
        if device.is_empty() {
            return Ok(Contents::Blank);
        }
        if let Some(blkid) = self.blkid {
            // libblkid seeks and reads with the descriptor it is given, and
            // sets advice and flags on it. So it gets an open file
            // description of its own, opened anew through the descriptor
            // of the image, and the offset and flags of that one, which a
            // Varlink client shares with the service, stay as they are.
            let found = reopen(device.fd(), O_RDONLY | O_NONBLOCK | O_NOCTTY)
                .and_then(|own| blkid.probe(own.as_fd(), device.offset(), device.len()))
                .with_context(|| "libblkid could not probe the image")?;
            if let Some(image_type) = found.as_ref().and_then(ImageType::from_blkid) {
                return Ok(Contents::Found(image_type));
            }
        }
        let mut head = vec![0u8; device.len().min(HEAD_SIZE) as usize];
        device.read_at(0, &mut head)?;
        Ok(if head.iter().all(|&b| b == 0) {
            Contents::Blank
        } else {
            Contents::Unknown {
                probed: self.has_libblkid(),
            }
        })
    }

    /// Turns the error of a boot sector that is not FAT32's, from
    /// [`crate::boot::BootSector::parse`],
    /// [`crate::boot::BootSector::validate`] or
    /// [`crate::boot::BootSector::layout`], into one that says what
    /// `device` holds instead: another file system or a partition table
    /// libblkid names, nothing when its first [`HEAD_SIZE`] bytes are
    /// zeros, or data nobody recognizes. `boot` is the first sector of
    /// `device`.
    ///
    /// A boot sector that looks like FAT's keeps a sector size this crate
    /// does not support as the reason. A damaged FAT32 boot sector stays
    /// damaged, unless libblkid finds another file system there: an NTFS
    /// boot sector reads like a FAT32 one up to its reserved sector count.
    /// Other errors pass through unchanged.
    pub(crate) fn refine(&self, e: Error, device: &Device, boot: &[u8; BOOT_SECTOR_SIZE]) -> Error {
        let Some(failure) = Failure::of(&e) else {
            return e;
        };
        let contents = match self.examine(device) {
            Ok(contents) => contents,
            Err(read) => return read,
        };
        let fat = BootSector::looks_like_fat(boot);
        match contents {
            // The signature at the end of a FAT boot sector is that of a
            // master boot record as well. libblkid takes a boot sector it
            // does not accept as FAT's for an empty partition table.
            Contents::Found(s) if s.kind == Kind::PartitionTable && fat => match failure {
                Failure::NotFat32 => Contents::Unknown { probed: true }.error(),
                Failure::SectorSize | Failure::Damaged => e,
            },
            // libblkid agrees that the boot sector is FAT's.
            Contents::Found(s) if s.is_fat() && failure != Failure::NotFat32 => e,
            found @ Contents::Found(_) => found.error(),
            _ if failure == Failure::Damaged => e,
            Contents::Unknown { .. } if failure == Failure::SectorSize && fat => e,
            other => other.error(),
        }
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
    /// Few enough sectors for that geometry to make a FAT12 volume: 8192 -
    /// 1 - 2 * 64 - 32 = 8031 data sectors, 2007 clusters. The most sectors
    /// it can have, u16::MAX, make 16343 clusters, a FAT16 volume.
    const FAT12_SECTORS: u16 = 8192;
    /// Where the partition table of a master boot record starts, and the
    /// fields of one of its entries: the partition type, the first sector
    /// and the number of sectors.
    const MBR_PARTITION_TABLE: u64 = 446;
    const PARTITION_ENTRY_SIZE: usize = 16;
    const PARTITION_TYPE: usize = 4;
    const PARTITION_FIRST_SECTOR: Range<usize> = 8..12;
    const PARTITION_SECTORS: Range<usize> = 12..16;
    /// The partition type of a Linux file system.
    const PARTITION_TYPE_LINUX: u8 = 0x83;
    /// Where the partition of the tests starts, 1 MiB in, and how long it
    /// is, 10 MiB, both in sectors of 512 bytes.
    const PARTITION_START: u32 = 2048;
    const PARTITION_LENGTH: u32 = 20480;

    /// An image of `len` zeros with `bytes` written at each offset.
    fn image(len: u64, edits: &[(u64, &[u8])]) -> TempImage {
        let img = TempImage::new(len);
        let device = Device::open(img.path(), Access::ReadWrite).unwrap();
        for &(offset, bytes) in edits {
            device.write_at(offset, bytes).unwrap();
        }
        img
    }

    /// What opening a volume says about the image, with `prober`: the
    /// reason, what was found, and the sector size, or the error when it
    /// is not about a missing FAT32 file system.
    fn opened(
        img: &TempImage,
        prober: Prober,
    ) -> std::result::Result<(NotFat32Reason, Option<String>, Option<u32>), Error> {
        let device = Device::open(img.path(), Access::ReadOnly).unwrap();
        let mut boot = [0u8; BOOT_SECTOR_SIZE];
        device.read_at(0, &mut boot).unwrap();
        let e = BootSector::parse(&boot)
            .and_then(|b| b.layout())
            .expect_err("not a FAT32 file system");
        let e = prober.refine(e, &device, &boot);
        match e.detail() {
            Some(Detail::NotFat32 {
                reason,
                found,
                sector_size,
            }) => Ok((*reason, found.clone(), *sector_size)),
            _ => Err(e),
        }
    }

    /// The reason without libblkid.
    fn reason(img: &TempImage) -> NotFat32Reason {
        opened(img, Prober::without_libblkid()).unwrap().0
    }

    /// What libblkid names, if it is there to ask.
    fn named(img: &TempImage) -> Option<(NotFat32Reason, Option<String>)> {
        let prober = Prober::new();
        if !prober.has_libblkid() {
            return None;
        }
        let (reason, found, _) = opened(img, prober).unwrap();
        Some((reason, found))
    }

    /// The probers to try: without libblkid, and with it when it is there.
    fn probers() -> Vec<Prober> {
        let mut probers = vec![Prober::without_libblkid()];
        if Prober::new().has_libblkid() {
            probers.push(Prober::new());
        }
        probers
    }

    /// A FAT16 boot sector the way mkfs.fat writes one, with
    /// `bytes_per_sector` and `total` sectors.
    fn fat16(bytes_per_sector: u16, total: u16) -> [u8; BOOT_SECTOR_SIZE] {
        let mut b = [0u8; BOOT_SECTOR_SIZE];
        b[field::JUMP].copy_from_slice(&short_jump(FAT16_BOOT_CODE));
        b[field::BYTES_PER_SECTOR].copy_from_slice(&bytes_per_sector.to_le_bytes());
        b[field::SECTORS_PER_CLUSTER] = FAT16_SECTORS_PER_CLUSTER;
        b[field::RESERVED_SECTORS].copy_from_slice(&FAT16_RESERVED_SECTORS.to_le_bytes());
        b[field::FATS] = DEFAULT_FATS as u8;
        b[field::ROOT_ENTRIES].copy_from_slice(&FAT16_ROOT_ENTRIES.to_le_bytes());
        b[field::TOTAL_SECTORS_16].copy_from_slice(&total.to_le_bytes());
        b[field::MEDIA] = MEDIA_FIXED;
        b[field::FAT_SECTORS_16].copy_from_slice(&FAT16_FAT_SECTORS.to_le_bytes());
        b[field::SIGNATURE].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
        b
    }

    /// An image of `total` sectors with a [`fat16`] boot sector.
    fn fat16_image(total: u16) -> TempImage {
        let len = u64::from(total) * u64::from(SECTOR_SIZE);
        image(len, &[(0, &fat16(SECTOR_SIZE, total))])
    }

    /// An image with an ext2 superblock behind a first sector of zeros.
    fn ext2() -> TempImage {
        image(
            1 << 20,
            &[(EXT2_MAGIC_FIELD.start as u64, &EXT2_SUPER_MAGIC.to_le_bytes())],
        )
    }

    #[test]
    fn only_zeros_are_blank() {
        let zeros = image(1 << 20, &[]);
        assert_eq!(reason(&zeros), NotFat32Reason::Blank);
        assert_eq!(
            named(&zeros).map(|n| n.0),
            Prober::new().has_libblkid().then_some(NotFat32Reason::Blank)
        );
        // A single byte anywhere in the first 256 KiB is enough, and what
        // lies behind them does not count.
        assert_eq!(
            reason(&image(1 << 20, &[(HEAD_SIZE - 1, b"x")])),
            NotFat32Reason::Unknown
        );
        assert_eq!(reason(&image(1 << 20, &[(HEAD_SIZE, b"x")])), NotFat32Reason::Blank);
        // An image smaller than that is looked at as a whole.
        assert_eq!(reason(&image(SMALL_IMAGE, &[])), NotFat32Reason::Blank);
        assert_eq!(
            reason(&image(SMALL_IMAGE, &[(SMALL_IMAGE - 1, b"x")])),
            NotFat32Reason::Unknown
        );
    }

    /// An ext2 superblock behind a first sector of zeros is not blank, and
    /// libblkid names it.
    #[test]
    fn signatures_further_in_are_found() {
        let ext2 = ext2();
        assert_eq!(reason(&ext2), NotFat32Reason::Unknown);
        if let Some(n) = named(&ext2) {
            assert_eq!(n, (NotFat32Reason::NotFat32, Some("ext2".to_string())));
        }
    }

    #[test]
    fn sector_size_is_for_fat_boot_sectors() {
        // A FAT boot sector with a sector size this crate does not support,
        // which libblkid takes for an empty partition table.
        let odd = image(1 << 20, &[(0, &fat16(ODD_SECTOR_SIZE, u16::MAX))]);
        for prober in probers() {
            assert_eq!(
                opened(&odd, prober).unwrap(),
                (NotFat32Reason::SectorSize, None, Some(u32::from(ODD_SECTOR_SIZE)))
            );
        }
        // Data whose sector size field makes no sector size: not FAT at all.
        let garbage = TempImage::new(0);
        std::fs::write(garbage.path(), vec![GARBAGE; 1 << 20]).unwrap();
        assert_eq!(reason(&garbage), NotFat32Reason::Unknown);
        assert_eq!(
            named(&garbage).map(|n| n.0),
            Prober::new().has_libblkid().then_some(NotFat32Reason::Unknown)
        );
        // The jump of a master boot record without a media descriptor.
        let mut mbr = fat16(ODD_SECTOR_SIZE, u16::MAX);
        mbr[field::MEDIA] = 0;
        assert_eq!(reason(&image(1 << 20, &[(0, &mbr)])), NotFat32Reason::Unknown);
    }

    /// FAT12 and FAT16 are vfat to libblkid, and fat12 and fat16 here.
    #[test]
    fn fat12_and_fat16_are_named_after_their_version() {
        let fat12 = fat16_image(FAT12_SECTORS);
        let fat16 = fat16_image(u16::MAX);
        assert_eq!(reason(&fat12), NotFat32Reason::Unknown);
        assert_eq!(reason(&fat16), NotFat32Reason::Unknown);
        if Prober::new().has_libblkid() {
            assert_eq!(named(&fat12).unwrap(), (NotFat32Reason::NotFat32, Some("fat12".into())));
            assert_eq!(named(&fat16).unwrap(), (NotFat32Reason::NotFat32, Some("fat16".into())));
        }
    }

    /// A master boot record with one partition in it.
    #[test]
    fn partition_tables_are_found() {
        let mut entry = [0u8; PARTITION_ENTRY_SIZE];
        entry[PARTITION_TYPE] = PARTITION_TYPE_LINUX;
        entry[PARTITION_FIRST_SECTOR].copy_from_slice(&PARTITION_START.to_le_bytes());
        entry[PARTITION_SECTORS].copy_from_slice(&PARTITION_LENGTH.to_le_bytes());
        let dos = image(
            16 << 20,
            &[
                (MBR_PARTITION_TABLE, &entry),
                (field::SIGNATURE.start as u64, &BOOT_SIGNATURE.to_le_bytes()),
            ],
        );
        assert_eq!(reason(&dos), NotFat32Reason::Unknown);
        if let Some(n) = named(&dos) {
            assert_eq!(n, (NotFat32Reason::NotFat32, Some("dos".to_string())));
        }
    }

    /// A FAT32 file system with a damaged boot sector stays damaged, with
    /// and without libblkid, which takes its boot sector for an empty
    /// partition table.
    #[test]
    fn a_damaged_boot_sector_stays_damaged() {
        let (img, volume) = crate::test_util::volume(40 << 20, MIN_SECTOR_SIZE, MIN_SECTOR_SIZE);
        drop(volume);
        let device = Device::open(img.path(), Access::ReadWrite).unwrap();
        device
            .write_at(field::RESERVED_SECTORS.start as u64, &0u16.to_le_bytes())
            .unwrap();
        drop(device);
        for prober in probers() {
            let e = opened(&img, prober).unwrap_err();
            assert_eq!(e.errno(), EUCLEAN);
            assert!(matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::BootSector,
                    field: Some("reservedSectors"),
                    ..
                })
            ));
        }
    }

    /// What libblkid says becomes a name and the words for it.
    #[test]
    fn libblkid_values_make_names() {
        let found = |name: Option<&str>, usage: Option<&str>, version: Option<&str>, table: Option<&str>| {
            let found = Found {
                name: name.map(str::to_string),
                usage: usage.map(str::to_string),
                version: version.map(str::to_string),
                partition_table: table.map(str::to_string),
            };
            ImageType::from_blkid(&found).map(|t| (t.name.clone(), t.kind, t.describe()))
        };
        let fs = Some("filesystem");
        assert_eq!(found(None, None, None, None), None);
        assert_eq!(
            found(Some("ext4"), fs, Some("1.0"), None),
            Some(("ext4".into(), Kind::FileSystem, "a file system of type ext4".into()))
        );
        assert_eq!(
            found(Some("vfat"), fs, Some("FAT12"), None),
            Some(("fat12".into(), Kind::FileSystem, "a FAT12 file system".into()))
        );
        assert_eq!(
            found(Some("vfat"), fs, Some("FAT16"), None),
            Some(("fat16".into(), Kind::FileSystem, "a FAT16 file system".into()))
        );
        assert_eq!(
            found(Some("vfat"), fs, Some("FAT32"), None),
            Some(("vfat".into(), Kind::FileSystem, "a FAT file system".into()))
        );
        assert_eq!(
            found(Some("crypto_LUKS"), Some("crypto"), Some("2"), None),
            Some((
                "crypto_LUKS".into(),
                Kind::Crypto,
                "an encrypted volume of type crypto_LUKS".into()
            ))
        );
        assert_eq!(
            found(Some("LVM2_member"), Some("raid"), None, None),
            Some((
                "LVM2_member".into(),
                Kind::Raid,
                "a RAID or volume manager member of type LVM2_member".into()
            ))
        );
        assert_eq!(
            found(Some("swap"), Some("other"), Some("1"), None),
            Some(("swap".into(), Kind::Other, "data of type swap".into()))
        );
        assert_eq!(
            found(None, None, None, Some("gpt")),
            Some((
                "gpt".into(),
                Kind::PartitionTable,
                "a partition table of type gpt".into()
            ))
        );
        // A superblock wins over a partition table.
        assert_eq!(found(Some("iso9660"), fs, None, Some("dos")).unwrap().0, "iso9660");
    }

    /// An image too small for a boot sector stays that, and an error that
    /// is not about the boot sector stays what it is.
    #[test]
    fn other_errors_pass_through() {
        let img = image(SMALL_IMAGE, &[]);
        let device = Device::open(img.path(), Access::ReadOnly).unwrap();
        let boot = [0u8; BOOT_SECTOR_SIZE];
        let e = err!(EMEDIUMTYPE, "unrelated");
        for prober in probers() {
            assert_eq!(prober.refine(e.clone(), &device, &boot), e);
        }
        let e = err!(
            EMEDIUMTYPE,
            Detail::NotFat32 {
                reason: NotFat32Reason::TooSmall,
                found: None,
                sector_size: None,
            },
            "too small"
        );
        for prober in probers() {
            assert_eq!(prober.refine(e.clone(), &device, &boot), e);
        }
    }
}
