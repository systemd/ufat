// SPDX-License-Identifier: LGPL-2.1-or-later
//! Formatting: writing a fresh FAT32 file system.
//!
//! With [`FormatOptions::mkfs_fat_compat`] set and the same parameters, the
//! result is byte for byte what `mkfs.fat -F 32` writes, which is what the
//! test suite checks. Without it a few legacy quirks are dropped: the total
//! sector count is not truncated to a multiple of the made-up track size and
//! is always stored in the 32-bit field.

use std::fmt;
use std::str::FromStr;
use std::time::SystemTime;

use crate::boot::{
    default_boot_code, valid_media, BootSector, FsInfo, BOOT_JUMP, BOOT_SIGNATURE, DRIVE_NUMBER_FIXED,
    EXT_BOOT_SIGNATURE, FS_TYPE_FAT32, MEDIA_FIXED, NO_NAME, OEM_NAME_DEFAULT,
};
use crate::device::Device;
use crate::dirent::{RawDirEntry, ATTR_VOLUME_ID, DIR_ENTRY_SIZE, ENTRY_DELETED, ENTRY_E5_ESCAPE};
use crate::errno::*;
use crate::fat::Fat;
use crate::layout::{self, default_geometry, Geometry, Layout, LayoutParams, MAX_SECTOR_SIZE, MIN_SECTOR_SIZE};
use crate::sys;
use crate::time::FatTimestamp;
use crate::{Context, Result};
use crate::{Detail, IdentifierProblem, LabelProblem};

/// Options for [`format`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatOptions {
    /// Bytes per sector. None uses the logical block size of a block device
    /// and 512 for image files.
    pub sector_size: Option<u32>,
    /// Bytes per cluster. None uses the size mkfs.fat picks for the volume
    /// size.
    pub cluster_size: Option<u32>,
    /// Reserved sectors, 32 by default.
    pub reserved_sectors: u32,
    /// FAT copies, 2 by default.
    pub fats: u32,
    /// Volume serial number. Pick it deterministically for reproducible
    /// images.
    pub volume_id: u32,
    /// Volume label, up to 11 ASCII characters.
    pub label: Option<String>,
    /// OEM name field.
    pub oem_name: [u8; 8],
    /// The time stamped on the volume label entry. None uses 1980-01-01.
    pub timestamp: Option<SystemTime>,
    /// Hidden sectors field. None uses the start of the partition the
    /// device is, in sectors of the file system, and 0 for an image file,
    /// as mkfs.fat does.
    pub hidden_sectors: Option<u32>,
    /// Media descriptor, 0xF8 by default.
    pub media: u8,
    /// BIOS drive number. None derives it from the media descriptor.
    pub drive_number: Option<u8>,
    /// Heads and sectors per track. None uses mkfs.fat's table.
    pub geometry: Option<Geometry>,
    /// Align FATs and data area to cluster boundaries.
    pub align: bool,
    /// Allow fewer than 65525 clusters. See [`layout::MIN_CLUSTERS`].
    pub allow_small: bool,
    /// Reproduce mkfs.fat's legacy quirks exactly.
    pub mkfs_fat_compat: bool,
    /// Zero the whole data area, not just the root directory cluster.
    pub zero_data_area: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        FormatOptions {
            sector_size: None,
            cluster_size: None,
            reserved_sectors: layout::DEFAULT_RESERVED_SECTORS,
            fats: layout::DEFAULT_FATS,
            volume_id: 0,
            label: None,
            oem_name: OEM_NAME_DEFAULT,
            timestamp: None,
            hidden_sectors: None,
            media: MEDIA_FIXED,
            drive_number: None,
            geometry: None,
            align: true,
            allow_small: false,
            mkfs_fat_compat: false,
            zero_data_area: false,
        }
    }
}

/// Characters mkfs.fat refuses in a label.
const LABEL_INVALID: &[u8] = b"*?.,;:/\\|+=<>[]\"";

/// Validates a volume label and returns its space padded on-disk form.
pub fn encode_label(label: &str) -> Result<[u8; 11]> {
    let invalid = |problem: LabelProblem| Detail::Label {
        label: label.to_string(),
        problem,
    };
    let bytes = label.as_bytes();
    if bytes.len() > 11 {
        bail!(
            EINVAL,
            invalid(LabelProblem::TooLong),
            "label '{}' is longer than 11 characters",
            label
        );
    }
    if bytes.iter().all(|&c| c == b' ') {
        return Ok(NO_NAME);
    }
    if bytes.first() == Some(&b' ') {
        bail!(
            EINVAL,
            invalid(LabelProblem::InvalidCharacter),
            "label must not start with a space"
        );
    }
    for &c in bytes {
        if !(0x20..0x7f).contains(&c) {
            bail!(
                EINVAL,
                invalid(LabelProblem::InvalidCharacter),
                "label '{}' contains a non-printable or non-ASCII character",
                label
            );
        }
        if LABEL_INVALID.contains(&c) {
            bail!(
                EINVAL,
                invalid(LabelProblem::InvalidCharacter),
                "label '{}' contains the invalid character '{}'",
                label,
                c as char
            );
        }
    }
    let mut out = [b' '; 11];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// Validates an OEM name and returns its space padded on-disk form: up to
/// eight printable ASCII characters.
pub fn encode_oem_name(name: &str) -> Result<[u8; 8]> {
    let bytes = name.as_bytes();
    if bytes.len() > 8 || !bytes.iter().all(|b| (0x20..0x7f).contains(b)) {
        bail!(
            EINVAL,
            Detail::InvalidOption("oemName"),
            "OEM name '{}' is not up to 8 printable ASCII characters",
            name
        );
    }
    let mut out = [b' '; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

/// A FAT volume serial number. It reads and prints as `XXXX-XXXX`, the way
/// blkid shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VolumeId(pub u32);

impl FromStr for VolumeId {
    type Err = crate::Error;

    /// Parses `XXXX-XXXX` or eight hex digits, case-insensitively.
    fn from_str(text: &str) -> Result<VolumeId> {
        let malformed = || {
            err!(
                EINVAL,
                Detail::Identifier {
                    identifier: text.to_string(),
                    problem: IdentifierProblem::Malformed,
                },
                "'{}' is not a volume serial number of the form XXXX-XXXX or XXXXXXXX",
                text
            )
        };
        let bytes = text.as_bytes();
        let (high, low) = match bytes.len() {
            8 => (&bytes[..4], &bytes[4..]),
            9 if bytes[4] == b'-' => (&bytes[..4], &bytes[5..]),
            _ => return Err(malformed()),
        };
        let mut serial = 0u32;
        for &b in high.iter().chain(low) {
            let digit = (b as char).to_digit(16).ok_or_else(malformed)?;
            serial = (serial << 4) | digit;
        }
        Ok(VolumeId(serial))
    }
}

impl fmt::Display for VolumeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}-{:04X}", self.0 >> 16, self.0 & 0xffff)
    }
}

/// Everything [`write`] needs, computed without touching the device.
#[derive(Clone, Debug)]
pub struct Prepared {
    /// The volume geometry.
    pub layout: Layout,
    /// The boot sector.
    pub boot_sector: BootSector,
    /// The FSInfo sector.
    pub fsinfo: FsInfo,
    /// The volume label entry for the root directory, if any.
    pub root_entry: Option<RawDirEntry>,
}

/// Picks the backup boot sector the way mkfs.fat does: sector 6 when the
/// reserved area is large enough.
fn backup_boot_sector(reserved: u32, info: u32) -> u16 {
    let s = if reserved >= 7 && info != 6 {
        6
    } else if reserved >= 3 + info && info != reserved - 2 && info != reserved - 1 {
        reserved - 2
    } else if reserved >= 3 && info != reserved - 1 {
        reserved - 1
    } else {
        0
    };
    s as u16
}

/// Resolves the sector size to use.
pub fn resolve_sector_size(requested: Option<u32>, device_block_size: Option<u32>) -> Result<u32> {
    let ss = match (requested, device_block_size) {
        (Some(s), Some(d)) if s < d => {
            bail!(
                EINVAL,
                Detail::InvalidOption("sectorSize"),
                "sector size {} is smaller than the device's logical block size {}",
                s,
                d
            )
        }
        (Some(s), _) => s,
        (None, Some(d)) => d,
        (None, None) => MIN_SECTOR_SIZE,
    };
    if !layout::valid_sector_size(ss) {
        bail!(
            EINVAL,
            Detail::InvalidOption("sectorSize"),
            "sector size {} is not a power of two between {} and {}",
            ss,
            MIN_SECTOR_SIZE,
            MAX_SECTOR_SIZE
        );
    }
    Ok(ss)
}

/// A random volume serial number from the kernel's random number
/// generator, for a file system that need not be reproducible. GRUB's
/// `search --fs-uuid`, fstab and blkid tell volumes apart by this number.
pub fn random_volume_id() -> Result<u32> {
    let mut bytes = [0u8; 4];
    sys::random_bytes(&mut bytes).with_context(|| "getrandom failed")?;
    Ok(u32::from_le_bytes(bytes))
}

/// Computes the layout and on-disk structures for a volume of `device_len`
/// bytes on a device with the given logical block size, which starts
/// `partition_start` bytes into its disk (0 for an image file or a whole
/// disk).
pub fn prepare(
    options: &FormatOptions,
    device_len: u64,
    device_block_size: Option<u32>,
    partition_start: u64,
) -> Result<Prepared> {
    let sector_size = resolve_sector_size(options.sector_size, device_block_size)?;
    // The field is informational on an ESP; Windows boot code reads it
    // when it boots from the volume. mkfs.fat fills in the partition
    // start, in 512 byte units whatever the sector size (dosfstools issue
    // 221); we convert.
    let hidden_sectors = options
        .hidden_sectors
        .unwrap_or_else(|| u32::try_from(partition_start / u64::from(sector_size)).unwrap_or(0));
    let total_sectors = device_len / u64::from(sector_size);
    let geometry = options.geometry.unwrap_or_else(|| default_geometry(total_sectors));
    let sectors_per_cluster = match options.cluster_size {
        Some(c) if c == 0 || c % sector_size != 0 => {
            bail!(
                EINVAL,
                "cluster size {} is not a multiple of the sector size {}",
                c,
                sector_size
            )
        }
        Some(c) => Some(c / sector_size),
        None => None,
    };
    if !valid_media(options.media) {
        bail!(
            EINVAL,
            "media descriptor 0x{:02x} is not 0xf0 or 0xf8..0xff",
            options.media
        );
    }
    let params = LayoutParams {
        sector_size,
        sectors_per_cluster,
        reserved_sectors: options.reserved_sectors,
        fats: options.fats,
        align: options.align,
        track_sectors: if options.mkfs_fat_compat {
            Some(u32::from(geometry.sectors_per_track))
        } else {
            None
        },
        allow_small: options.allow_small,
    };
    let layout = layout::compute(&params, total_sectors)?;
    let label = match &options.label {
        Some(l) => encode_label(l)?,
        None => NO_NAME,
    };
    let use_16bit_total = options.mkfs_fat_compat && layout.total_sectors < 65_536;
    let boot_sector = BootSector {
        jump: BOOT_JUMP,
        oem_name: options.oem_name,
        bytes_per_sector: sector_size as u16,
        sectors_per_cluster: layout.sectors_per_cluster as u8,
        reserved_sectors: layout.reserved_sectors as u16,
        fats: layout.fats as u8,
        root_entries: 0,
        total_sectors_16: if use_16bit_total {
            layout.total_sectors as u16
        } else {
            0
        },
        media: options.media,
        fat_sectors_16: 0,
        sectors_per_track: geometry.sectors_per_track,
        heads: geometry.heads,
        hidden_sectors,
        total_sectors_32: if use_16bit_total { 0 } else { layout.total_sectors },
        fat_sectors_32: layout.fat_sectors,
        ext_flags: 0,
        fs_version: 0,
        root_cluster: 2,
        fsinfo_sector: 1,
        backup_boot_sector: backup_boot_sector(layout.reserved_sectors, 1),
        reserved: [0; 12],
        drive_number: options.drive_number.unwrap_or(if options.media == MEDIA_FIXED {
            DRIVE_NUMBER_FIXED
        } else {
            0
        }),
        nt_flags: 0,
        ext_boot_signature: EXT_BOOT_SIGNATURE,
        volume_id: options.volume_id,
        volume_label: label,
        fs_type: FS_TYPE_FAT32,
        boot_code: default_boot_code(),
        signature: BOOT_SIGNATURE,
    };
    let fsinfo = FsInfo {
        free_clusters: layout.clusters - 1,
        next_free: 2,
    };
    let root_entry = if label == NO_NAME {
        None
    } else {
        let mut e = RawDirEntry {
            name: label,
            attr: ATTR_VOLUME_ID,
            ..RawDirEntry::default()
        };
        if e.name[0] == ENTRY_DELETED {
            e.name[0] = ENTRY_E5_ESCAPE;
        }
        let t = options
            .timestamp
            .map_or(FatTimestamp::EPOCH, FatTimestamp::from_system_time);
        e.set_times(t);
        // mkfs.fat leaves the hundredths field at zero.
        e.create_tenths = 0;
        Some(e)
    };
    Ok(Prepared {
        layout,
        boot_sector,
        fsinfo,
        root_entry,
    })
}

/// Writes the prepared structures to the device.
pub fn write(device: &Device, p: &Prepared, zero_data_area: bool) -> Result<()> {
    let l = &p.layout;
    let ss = u64::from(l.sector_size);
    if l.size() > device.len() {
        bail!(
            EINVAL,
            "layout of {} bytes does not fit the device of {} bytes",
            l.size(),
            device.len()
        );
    }
    // The reserved area: zero it, then place the boot sector, the FSInfo
    // sector and their backups.
    device.zero(0, u64::from(l.reserved_sectors) * ss)?;
    let boot = p.boot_sector.to_bytes();
    let fsinfo = p.fsinfo.to_bytes();
    let fsinfo_sector = u64::from(p.boot_sector.fsinfo_sector);
    device.write_at(0, &boot)?;
    device.write_at(fsinfo_sector * ss, &fsinfo)?;
    let backup = u64::from(p.boot_sector.backup_boot_sector);
    if backup != 0 {
        device.write_at(backup * ss, &boot)?;
        let backup_info = backup + fsinfo_sector;
        if backup_info != fsinfo_sector && backup_info < u64::from(l.reserved_sectors) {
            device.write_at(backup_info * ss, &fsinfo)?;
        }
    }
    // The FATs: the two reserved entries, the root directory's end of chain
    // marker, zeros for everything else.
    let first = Fat::first_sector(l, p.boot_sector.media);
    for i in 0..l.fats {
        let off = l.fat_offset(i);
        device.write_at(off, &first)?;
        device.zero(off + ss, l.fat_size() - ss)?;
    }
    // The root directory: a zeroed cluster, with the label entry if any.
    let mut root = vec![0u8; l.cluster_size() as usize];
    if let Some(e) = &p.root_entry {
        root[..DIR_ENTRY_SIZE].copy_from_slice(&e.to_bytes());
    }
    device.write_at(l.data_start(), &root)?;
    if zero_data_area && l.clusters > 1 {
        let start = l.data_start() + u64::from(l.cluster_size());
        device.zero(start, (u64::from(l.clusters) - 1) * u64::from(l.cluster_size()))?;
    }
    device.sync()
}

/// Formats the device as FAT32 and returns the resulting layout.
pub fn format(device: &Device, options: &FormatOptions) -> Result<Layout> {
    let prepared = prepare(
        options,
        device.len(),
        device.logical_block_size()?,
        device.partition_start()?,
    )?;
    write(device, &prepared, options.zero_data_area)?;
    Ok(prepared.layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert_eq!(encode_label("ESP").unwrap(), *b"ESP        ");
        assert_eq!(encode_label("").unwrap(), NO_NAME);
        assert_eq!(encode_label("           ").unwrap(), NO_NAME);
        assert!(encode_label("TOOLONGLABEL").is_err());
        assert!(encode_label(" X").is_err());
        assert!(encode_label("A.B").is_err());
        assert!(encode_label("Ä").is_err());
        assert_eq!(encode_label("lower case").unwrap(), *b"lower case ");
    }

    /// A rejected label says what is wrong with it in the detail.
    #[test]
    fn label_details() {
        let e = encode_label("TOOLONGLABEL").unwrap_err();
        assert_eq!(e.errno(), EINVAL);
        assert_eq!(
            e.detail(),
            Some(&Detail::Label {
                label: "TOOLONGLABEL".into(),
                problem: LabelProblem::TooLong,
            })
        );
        for bad in [" X", "A.B", "Ä", "A\tB", "A\"B", "a:b"] {
            let e = encode_label(bad).unwrap_err();
            assert_eq!(e.errno(), EINVAL, "{:?}", bad);
            assert_eq!(
                e.detail(),
                Some(&Detail::Label {
                    label: bad.into(),
                    problem: LabelProblem::InvalidCharacter,
                }),
                "{:?}",
                bad
            );
        }
    }

    #[test]
    fn oem_names() {
        assert_eq!(encode_oem_name("mkfs.fat").unwrap(), *b"mkfs.fat");
        assert_eq!(encode_oem_name("MSWIN").unwrap(), *b"MSWIN   ");
        assert_eq!(encode_oem_name("").unwrap(), [b' '; 8]);
        for bad in ["TOOLONGNAME", "\u{c4}", "A\tB"] {
            let e = encode_oem_name(bad).unwrap_err();
            assert_eq!(e.detail(), Some(&Detail::InvalidOption("oemName")), "{:?}", bad);
        }
    }

    #[test]
    fn serials() {
        assert_eq!("1234-ABCD".parse(), Ok(VolumeId(0x1234_abcd)));
        assert_eq!("1234-abcd".parse(), Ok(VolumeId(0x1234_abcd)));
        assert_eq!("1234ABCD".parse(), Ok(VolumeId(0x1234_abcd)));
        assert_eq!("1234abCd".parse(), Ok(VolumeId(0x1234_abcd)));
        assert_eq!("0000-0000".parse(), Ok(VolumeId(0)));
        assert_eq!("FFFF-FFFF".parse(), Ok(VolumeId(u32::MAX)));
        assert_eq!("00000001".parse(), Ok(VolumeId(1)));
        assert_eq!(VolumeId(0x1234_abcd).to_string(), "1234-ABCD");
        assert_eq!(VolumeId(1).to_string(), "0000-0001");
        for bad in [
            "",
            "1",
            "1234",
            "1234-ABC",
            "1234-ABCDE",
            "12345-ABC",
            "123-4ABCD",
            "1234ABCD-",
            "-1234ABCD",
            "1234_ABCD",
            "1234:ABCD",
            "1234 ABCD",
            "1234-ABCG",
            "1234ABCG",
            "0x1234ABCD",
            " 1234-ABCD",
            "1234-ABCD ",
            "1234-ABCD\n",
            "\u{c4}\u{c4}-\u{c4}\u{c4}",
            "\u{c4}\u{c4}\u{c4}\u{c4}",
        ] {
            let e = bad.parse::<VolumeId>().unwrap_err();
            assert_eq!(e.errno(), EINVAL, "{:?}", bad);
            assert_eq!(
                e.detail(),
                Some(&Detail::Identifier {
                    identifier: bad.into(),
                    problem: IdentifierProblem::Malformed,
                }),
                "{:?}",
                bad
            );
        }
    }

    #[test]
    fn backup_sector_selection() {
        assert_eq!(backup_boot_sector(32, 1), 6);
        assert_eq!(backup_boot_sector(7, 1), 6);
        assert_eq!(backup_boot_sector(6, 1), 4);
        assert_eq!(backup_boot_sector(4, 1), 2);
        assert_eq!(backup_boot_sector(3, 1), 2);
        assert_eq!(backup_boot_sector(2, 1), 0);
    }

    #[test]
    fn hidden_sectors_follow_the_partition_start() {
        let o = FormatOptions {
            sector_size: Some(4096),
            allow_small: true,
            ..FormatOptions::default()
        };
        // A partition one MiB into its disk: 256 sectors of 4096 bytes.
        let p = prepare(&o, 64 * 1024 * 1024, None, 1 << 20).unwrap();
        assert_eq!(p.boot_sector.hidden_sectors, 256);
        // An image file, or a start that does not fit the field, gives 0.
        assert_eq!(
            prepare(&o, 64 * 1024 * 1024, None, 0)
                .unwrap()
                .boot_sector
                .hidden_sectors,
            0
        );
        assert_eq!(
            prepare(&o, 64 * 1024 * 1024, None, 1 << 50)
                .unwrap()
                .boot_sector
                .hidden_sectors,
            0
        );
        let explicit = FormatOptions {
            hidden_sectors: Some(7),
            ..o
        };
        assert_eq!(
            prepare(&explicit, 64 * 1024 * 1024, None, 1 << 20)
                .unwrap()
                .boot_sector
                .hidden_sectors,
            7
        );
    }

    #[test]
    fn prepare_small_volume() {
        let o = FormatOptions {
            allow_small: true,
            volume_id: 0x1234_abcd,
            label: Some("ESP".into()),
            timestamp: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_426_325_213)),
            ..FormatOptions::default()
        };
        let p = prepare(&o, 64 * 1024 * 1024, None, 0).unwrap();
        assert_eq!(p.layout.total_sectors, 131_072);
        assert_eq!(p.boot_sector.total_sectors_32, 131_072);
        assert_eq!(p.boot_sector.total_sectors_16, 0);
        assert_eq!(p.boot_sector.backup_boot_sector, 6);
        assert_eq!(p.boot_sector.volume_label, *b"ESP        ");
        let e = p.root_entry.unwrap();
        assert_eq!(e.attr, ATTR_VOLUME_ID);
        assert_eq!(e.create_tenths, 0);
        assert_eq!(e.write_date, ((2015 - 1980) << 9) | (3 << 5) | 14);
        let bs = BootSector::parse(&p.boot_sector.to_bytes()).unwrap();
        assert_eq!(bs, p.boot_sector);
        assert_eq!(bs.layout().unwrap(), p.layout);
    }

    #[test]
    fn sector_size_resolution() {
        assert_eq!(resolve_sector_size(None, None).unwrap(), 512);
        assert_eq!(resolve_sector_size(None, Some(4096)).unwrap(), 4096);
        assert_eq!(resolve_sector_size(Some(4096), Some(512)).unwrap(), 4096);
        assert!(resolve_sector_size(Some(512), Some(4096)).is_err());
        assert!(resolve_sector_size(Some(8192), None).is_err());
        assert!(resolve_sector_size(Some(1000), None).is_err());
    }
}
