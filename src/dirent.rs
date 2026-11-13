// SPDX-License-Identifier: LGPL-2.1-or-later
//! The 32-byte on-disk directory entry.

use crate::bytes::{le16_at, le32_at};
use crate::time::FatTimestamp;

/// Size of a directory entry.
pub const DIR_ENTRY_SIZE: usize = 32;
/// Read-only attribute.
pub const ATTR_READ_ONLY: u8 = 0x01;
/// Hidden attribute.
pub const ATTR_HIDDEN: u8 = 0x02;
/// System attribute.
pub const ATTR_SYSTEM: u8 = 0x04;
/// Volume label attribute.
pub const ATTR_VOLUME_ID: u8 = 0x08;
/// Directory attribute.
pub const ATTR_DIRECTORY: u8 = 0x10;
/// Archive attribute; set on every file.
pub const ATTR_ARCHIVE: u8 = 0x20;
/// The attribute combination marking a long file name entry.
pub const ATTR_LONG_NAME: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;
/// The attribute bits the specification reserves.
pub const ATTR_RESERVED: u8 = 0xC0;
/// First byte of a deleted entry.
pub const ENTRY_DELETED: u8 = 0xE5;
/// First byte of an unused entry; everything after it is unused too.
pub const ENTRY_END: u8 = 0x00;
/// First byte stored for a name that really starts with 0xE5.
pub const ENTRY_E5_ESCAPE: u8 = 0x05;
/// Flag in the NT reserved byte: the base name is lower case.
pub const CASE_LOWER_BASE: u8 = 0x08;
/// Flag in the NT reserved byte: the extension is lower case.
pub const CASE_LOWER_EXT: u8 = 0x10;
/// The 8.3 name of the "." entry of a subdirectory.
pub const DOT_NAME: [u8; 11] = *b".          ";
/// The 8.3 name of the ".." entry of a subdirectory.
pub const DOTDOT_NAME: [u8; 11] = *b"..         ";

/// Byte offsets of the fields of a short entry. The names in the comments
/// are the ones the FAT specification uses.
pub mod field {
    use std::ops::Range;

    /// 8.3 name, DIR_Name.
    pub const NAME: Range<usize> = 0..11;
    /// First byte of the name, which also marks a deleted or an unused
    /// entry: `DIR_Name[0]`.
    pub const MARKER: usize = 0;
    /// Attribute bits, DIR_Attr.
    pub const ATTR: usize = 11;
    /// Windows NT case flags, DIR_NTRes.
    pub const NT_FLAGS: usize = 12;
    /// Hundredths of a second of the creation time, DIR_CrtTimeTenth.
    pub const CREATE_TENTHS: usize = 13;
    /// Creation time, DIR_CrtTime.
    pub const CREATE_TIME: Range<usize> = 14..16;
    /// Creation date, DIR_CrtDate.
    pub const CREATE_DATE: Range<usize> = 16..18;
    /// Last access date, DIR_LstAccDate.
    pub const ACCESS_DATE: Range<usize> = 18..20;
    /// High half of the first cluster, DIR_FstClusHI.
    pub const FIRST_CLUSTER_HI: Range<usize> = 20..22;
    /// Last modification time, DIR_WrtTime.
    pub const WRITE_TIME: Range<usize> = 22..24;
    /// Last modification date, DIR_WrtDate.
    pub const WRITE_DATE: Range<usize> = 24..26;
    /// Low half of the first cluster, DIR_FstClusLO.
    pub const FIRST_CLUSTER_LO: Range<usize> = 26..28;
    /// File size in bytes, DIR_FileSize.
    pub const SIZE: Range<usize> = 28..32;
}

/// A decoded short directory entry.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RawDirEntry {
    /// 8.3 name, space padded, as stored on disk (0x05 escaping included).
    pub name: [u8; 11],
    /// Attribute bits.
    pub attr: u8,
    /// Windows NT case flags.
    pub nt_flags: u8,
    /// Creation time: hundredths of a second, 0..=199. The specification
    /// calls the field DIR_CrtTimeTenth.
    pub create_tenths: u8,
    /// Creation time.
    pub create_time: u16,
    /// Creation date.
    pub create_date: u16,
    /// Last access date.
    pub access_date: u16,
    /// Last modification time.
    pub write_time: u16,
    /// Last modification date.
    pub write_date: u16,
    /// First cluster, 0 for empty files.
    pub first_cluster: u32,
    /// File size in bytes, 0 for directories.
    pub size: u32,
}

impl RawDirEntry {
    /// Decodes an entry from 32 bytes.
    pub fn from_bytes(b: &[u8; DIR_ENTRY_SIZE]) -> RawDirEntry {
        let mut name = [0u8; 11];
        name.copy_from_slice(&b[field::NAME]);
        RawDirEntry {
            name,
            attr: b[field::ATTR],
            nt_flags: b[field::NT_FLAGS],
            create_tenths: b[field::CREATE_TENTHS],
            create_time: le16_at(b, field::CREATE_TIME),
            create_date: le16_at(b, field::CREATE_DATE),
            access_date: le16_at(b, field::ACCESS_DATE),
            first_cluster: (u32::from(le16_at(b, field::FIRST_CLUSTER_HI)) << u16::BITS)
                | u32::from(le16_at(b, field::FIRST_CLUSTER_LO)),
            write_time: le16_at(b, field::WRITE_TIME),
            write_date: le16_at(b, field::WRITE_DATE),
            size: le32_at(b, field::SIZE),
        }
    }

    /// Encodes the entry into its on-disk form.
    pub fn to_bytes(&self) -> [u8; DIR_ENTRY_SIZE] {
        let mut b = [0u8; DIR_ENTRY_SIZE];
        b[field::NAME].copy_from_slice(&self.name);
        b[field::ATTR] = self.attr;
        b[field::NT_FLAGS] = self.nt_flags;
        b[field::CREATE_TENTHS] = self.create_tenths;
        b[field::CREATE_TIME].copy_from_slice(&self.create_time.to_le_bytes());
        b[field::CREATE_DATE].copy_from_slice(&self.create_date.to_le_bytes());
        b[field::ACCESS_DATE].copy_from_slice(&self.access_date.to_le_bytes());
        b[field::FIRST_CLUSTER_HI].copy_from_slice(&((self.first_cluster >> u16::BITS) as u16).to_le_bytes());
        b[field::WRITE_TIME].copy_from_slice(&self.write_time.to_le_bytes());
        b[field::WRITE_DATE].copy_from_slice(&self.write_date.to_le_bytes());
        b[field::FIRST_CLUSTER_LO].copy_from_slice(&(self.first_cluster as u16).to_le_bytes());
        b[field::SIZE].copy_from_slice(&self.size.to_le_bytes());
        b
    }

    /// Whether this is a long file name entry: the attribute byte is exactly
    /// 0x0F, as the kernel tests it (fs/fat/dir.c). An entry with 0x0F plus
    /// other bits is a volume label to both of us and therefore hidden.
    pub fn is_long_name(&self) -> bool {
        self.attr == ATTR_LONG_NAME
    }

    /// Whether this is a directory.
    pub fn is_directory(&self) -> bool {
        self.attr & ATTR_DIRECTORY != 0
    }

    /// Whether this is a volume label entry.
    pub fn is_volume_label(&self) -> bool {
        !self.is_long_name() && self.attr & ATTR_VOLUME_ID != 0
    }

    /// Sets the creation time (with hundredths), the modification time and
    /// the access date from one timestamp.
    pub fn set_times(&mut self, t: FatTimestamp) {
        self.create_tenths = t.tenths;
        self.create_time = t.time;
        self.create_date = t.date;
        self.access_date = t.date;
        self.write_time = t.time;
        self.write_date = t.date;
    }

    /// The modification time.
    pub fn write_timestamp(&self) -> FatTimestamp {
        FatTimestamp {
            date: self.write_date,
            time: self.write_time,
            tenths: 0,
        }
    }

    /// The creation time.
    pub fn create_timestamp(&self) -> FatTimestamp {
        FatTimestamp {
            date: self.create_date,
            time: self.create_time,
            tenths: self.create_tenths,
        }
    }

    /// The access date, which comes without a time.
    pub fn access_timestamp(&self) -> FatTimestamp {
        FatTimestamp {
            date: self.access_date,
            time: 0,
            tenths: 0,
        }
    }
}

/// Computes the checksum of an 8.3 name that long name entries carry.
pub fn short_name_checksum(name: &[u8; 11]) -> u8 {
    name.iter().fold(0u8, |sum, &c| sum.rotate_right(1).wrapping_add(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut e = RawDirEntry {
            name: *b"HELLO   TXT",
            attr: ATTR_ARCHIVE,
            first_cluster: 0x0001_2345,
            size: 0xDEAD_BEEF,
            ..RawDirEntry::default()
        };
        e.set_times(FatTimestamp::from_unix(1_426_325_213, 450_000_000));
        let b = e.to_bytes();
        // Cluster 0x0001_2345 is stored as its high half, 0x0001, and its
        // low half, 0x2345, each in little-endian order.
        assert_eq!(b[field::FIRST_CLUSTER_HI], [0x01, 0x00]);
        assert_eq!(b[field::FIRST_CLUSTER_LO], [0x45, 0x23]);
        assert_eq!(RawDirEntry::from_bytes(&b), e);
    }

    #[test]
    fn checksum() {
        // Checksum of "FILENAMEEXT" from the Microsoft specification's
        // worked example style: just check a couple of properties.
        assert_eq!(short_name_checksum(b"           "), 0xf7);
        assert_ne!(short_name_checksum(b"A          "), short_name_checksum(b"B          "));
    }
}
