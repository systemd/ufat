// SPDX-License-Identifier: LGPL-2.1-or-later
//! The header of an entry in the "new ASCII" cpio format, and the
//! arithmetic of where things are in an archive.
//!
//! An entry is a header of 110 bytes, the name with its terminating NUL,
//! and the data. The header is a magic of six characters followed by
//! thirteen numbers of eight hexadecimal digits each, see [`Field`]. Name
//! and data are each followed by NUL bytes up to the next multiple of
//! four, counted from the start of the archive. An entry named
//! `TRAILER!!!` ends the archive.
//!
//! This is the format the kernel unpacks an initramfs from
//! (Documentation/driver-api/early-userspace/buffer-format.rst). The
//! kernel reads the header with hex2bin(), which takes digits and the
//! letters a to f in either case and nothing else, so that is what
//! [`Header::decode`] takes. [`Header::encode`] writes lower case.

use std::fmt;
use std::ops::{Index, IndexMut, Range};

/// Length of the magic at the start of a header.
pub const MAGIC_LEN: usize = 6;
/// The name the kernel's documentation has for the magic.
pub const MAGIC_NAME: &str = "c_magic";
/// What both magics start with. The kernel takes what starts with it at a
/// multiple of [`ALIGNMENT`] for an entry.
pub const MAGIC_START: u8 = b'0';
/// The byte an archive is stopped with while it is written or entries are
/// added to it, in the place of [`MAGIC_START`]. No entry starts with it
/// and no compressed archive does, so the kernel stops there and says that
/// unpacking failed, whatever lies behind it.
pub const STOPPER: u8 = b'X';
/// Length of a header in bytes: the magic and the fields.
pub const HEADER_LEN: usize = MAGIC_LEN + Field::COUNT * Field::LEN;
/// Header, name and data of an entry each start at a multiple of this,
/// counted from the start of the archive.
pub const ALIGNMENT: u64 = 4;
/// The name of the entry that ends an archive.
pub const TRAILER: &[u8] = b"TRAILER!!!";
/// The largest `namesize`, the name with its NUL: PATH_MAX. The kernel
/// drops an entry with a longer name without a word.
pub const MAX_NAME_SIZE: u32 = 4096;
/// The longest name, without its NUL.
pub const MAX_NAME_LEN: usize = MAX_NAME_SIZE as usize - 1;
/// The longest symbolic link target. The header has room for one byte
/// more, but the kernel cannot create a link that long.
pub const MAX_TARGET_LEN: usize = MAX_NAME_SIZE as usize - 1;
/// The largest file: the size field has eight hexadecimal digits.
pub const MAX_FILE_SIZE: u64 = u32::MAX as u64;
/// The last modification time a header holds, in seconds since the epoch:
/// one in the year 2106.
pub const MAX_MTIME: u32 = u32::MAX;
/// How many bits of the minor number of a device node the kernel takes
/// from the header: MKDEV() shifts the major number by MINORBITS.
pub const MINOR_BITS: u32 = 20;
/// How many bits of the major number are left in a dev_t of 32 bits.
pub const MAJOR_BITS: u32 = u32::BITS - MINOR_BITS;
/// The largest major number of a device node the kernel can take from the
/// header.
pub const MAX_MAJOR: u32 = (1 << MAJOR_BITS) - 1;
/// The largest minor number of a device node.
pub const MAX_MINOR: u32 = (1 << MINOR_BITS) - 1;

/// The bits of the mode that say what an entry is. They and the file
/// types are the ones of stat(2) on Linux, on every architecture.
pub const S_IFMT: u32 = 0o170000;
/// The type bits of a regular file.
pub const S_IFREG: u32 = 0o100000;
/// The type bits of a directory.
pub const S_IFDIR: u32 = 0o040000;
/// The type bits of a symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// The type bits of a character device node.
pub const S_IFCHR: u32 = 0o020000;
/// The type bits of a block device node.
pub const S_IFBLK: u32 = 0o060000;
/// The type bits of a FIFO.
pub const S_IFIFO: u32 = 0o010000;
/// The type bits of a socket.
pub const S_IFSOCK: u32 = 0o140000;
/// The bits of the mode that are permissions: the access modes and the
/// set-user-ID, set-group-ID and sticky bits.
pub const PERMISSIONS: u32 = 0o7777;

/// Which of the two forms of the format a header is in. They differ in the
/// magic and in whether the last field of the header counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// `070701`: the last field is zero.
    Newc,
    /// `070702`: the last field is the sum of the bytes of the data of a
    /// regular file, modulo 2^32. cpio(1) calls it a CRC, which it is not.
    Crc,
}

impl Format {
    /// The magic a header of this form starts with.
    pub const fn magic(self) -> &'static [u8; MAGIC_LEN] {
        match self {
            Format::Newc => b"070701",
            Format::Crc => b"070702",
        }
    }

    /// The form a magic stands for, if it is one of the two.
    pub fn from_magic(magic: &[u8]) -> Option<Format> {
        if magic == Format::Newc.magic() {
            Some(Format::Newc)
        } else if magic == Format::Crc.magic() {
            Some(Format::Crc)
        } else {
            None
        }
    }

    /// What a header of this form starts with while it is stopped: its
    /// magic with [`STOPPER`] for its first byte. A reader that knows it
    /// can tell an archive that was not finished from an image that holds
    /// none.
    pub const fn stopped_magic(self) -> [u8; MAGIC_LEN] {
        let mut magic = *self.magic();
        if let Some(first) = magic.first_mut() {
            *first = STOPPER;
        }
        magic
    }
}

/// What an entry is, from the type bits of its mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link. Its target is the data of the entry.
    Symlink,
    /// A character device node.
    CharDevice,
    /// A block device node.
    BlockDevice,
    /// A FIFO.
    Fifo,
    /// A socket.
    Socket,
}

impl Kind {
    /// The kind the type bits of `mode` stand for. None for bits the
    /// kernel has no file type for; it ignores such an entry.
    pub const fn from_mode(mode: u32) -> Option<Kind> {
        match mode & S_IFMT {
            S_IFREG => Some(Kind::Regular),
            S_IFDIR => Some(Kind::Directory),
            S_IFLNK => Some(Kind::Symlink),
            S_IFCHR => Some(Kind::CharDevice),
            S_IFBLK => Some(Kind::BlockDevice),
            S_IFIFO => Some(Kind::Fifo),
            S_IFSOCK => Some(Kind::Socket),
            _ => None,
        }
    }

    /// The type bits of the mode of an entry of this kind.
    pub const fn bits(self) -> u32 {
        match self {
            Kind::Regular => S_IFREG,
            Kind::Directory => S_IFDIR,
            Kind::Symlink => S_IFLNK,
            Kind::CharDevice => S_IFCHR,
            Kind::BlockDevice => S_IFBLK,
            Kind::Fifo => S_IFIFO,
            Kind::Socket => S_IFSOCK,
        }
    }

    /// Whether this is a device node, the one kind whose device number
    /// fields mean something.
    pub const fn is_device(self) -> bool {
        matches!(self, Kind::CharDevice | Kind::BlockDevice)
    }
}

/// The number of a device: of the one a device node stands for, or of
/// the one a file was on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct DeviceNumber {
    /// The major number.
    pub major: u32,
    /// The minor number.
    pub minor: u32,
}

impl DeviceNumber {
    /// What everything that is no device node has in the place of a
    /// number.
    pub const NONE: DeviceNumber = DeviceNumber::new(0, 0);

    /// The number `major`:`minor`.
    pub const fn new(major: u32, minor: u32) -> DeviceNumber {
        DeviceNumber { major, minor }
    }

    /// The number `major`:`minor` as other interfaces have it, in more
    /// bits than a header holds. What is beyond 32 bits becomes the
    /// largest number, which does not fit.
    pub fn saturating(major: u64, minor: u64) -> DeviceNumber {
        DeviceNumber {
            major: u32::try_from(major).unwrap_or(u32::MAX),
            minor: u32::try_from(minor).unwrap_or(u32::MAX),
        }
    }

    /// Whether the kernel takes the number from a header as it is.
    pub const fn fits(self) -> bool {
        self.major <= MAX_MAJOR && self.minor <= MAX_MINOR
    }

    /// What the kernel makes of the number when it takes it from a
    /// header. It packs the two into the 32 bits of a dev_t: what does not
    /// fit is cut off the major number and spills from the minor number
    /// into the major.
    pub const fn packed(self) -> DeviceNumber {
        DeviceNumber {
            major: (self.major | (self.minor >> MINOR_BITS)) & MAX_MAJOR,
            minor: self.minor & MAX_MINOR,
        }
    }
}

impl fmt::Display for DeviceNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// The numbers of a header, in the order they are stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// The inode number: `c_ino`.
    Ino,
    /// The file type and the permissions: `c_mode`.
    Mode,
    /// The owning user: `c_uid`.
    Uid,
    /// The owning group: `c_gid`.
    Gid,
    /// The number of names the file has: `c_nlink`.
    Nlink,
    /// The modification time: `c_mtime`.
    Mtime,
    /// The length of the data: `c_filesize`.
    Filesize,
    /// The major number of the device the file was on: `c_maj`.
    Devmajor,
    /// The minor number of the device the file was on: `c_min`.
    Devminor,
    /// The major number of a device node: `c_rmaj`.
    Rdevmajor,
    /// The minor number of a device node: `c_rmin`.
    Rdevminor,
    /// The length of the name: `c_namesize`.
    Namesize,
    /// The sum of the data's bytes: `c_chksum`.
    Check,
}

/// How many bits a hexadecimal digit holds.
const DIGIT_BITS: u32 = 4;
/// The base the fields are written in.
const RADIX: u32 = 1 << DIGIT_BITS;
/// The digits [`Field::encode`] writes.
const DIGITS: &[u8; RADIX as usize] = b"0123456789abcdef";
/// What [`VALUES`] has for a byte that is no digit. No digit's value has
/// all of its bits.
const NO_DIGIT: u8 = u8::MAX;
/// What every byte stands for in a field: the value of a hexadecimal
/// digit, in either case, or [`NO_DIGIT`].
const VALUES: [u8; 1 << u8::BITS] = {
    let mut values = [NO_DIGIT; 1 << u8::BITS];
    let mut value = 0;
    while value < DIGITS.len() {
        let digit = DIGITS[value];
        values[digit as usize] = value as u8;
        values[digit.to_ascii_uppercase() as usize] = value as u8;
        value += 1;
    }
    values
};

impl Field {
    /// How many fields a header has.
    pub const COUNT: usize = Field::Check as usize + 1;
    /// How many hexadecimal digits a field has: what a number of 32 bits
    /// takes.
    pub const LEN: usize = (u32::BITS / DIGIT_BITS) as usize;
    /// The fields in the order they are stored.
    pub const ALL: [Field; Field::COUNT] = [
        Field::Ino,
        Field::Mode,
        Field::Uid,
        Field::Gid,
        Field::Nlink,
        Field::Mtime,
        Field::Filesize,
        Field::Devmajor,
        Field::Devminor,
        Field::Rdevmajor,
        Field::Rdevminor,
        Field::Namesize,
        Field::Check,
    ];

    /// The name the kernel's documentation has for the field.
    pub const fn name(self) -> &'static str {
        match self {
            Field::Ino => "c_ino",
            Field::Mode => "c_mode",
            Field::Uid => "c_uid",
            Field::Gid => "c_gid",
            Field::Nlink => "c_nlink",
            Field::Mtime => "c_mtime",
            Field::Filesize => "c_filesize",
            Field::Devmajor => "c_maj",
            Field::Devminor => "c_min",
            Field::Rdevmajor => "c_rmaj",
            Field::Rdevminor => "c_rmin",
            Field::Namesize => "c_namesize",
            Field::Check => "c_chksum",
        }
    }

    /// Where the field starts in a header. A writer needs this for the
    /// checksum, which it fills in once it has seen the data.
    pub const fn offset(self) -> usize {
        MAGIC_LEN + Field::LEN * self as usize
    }

    /// The bytes of a header the field is in.
    pub const fn range(self) -> Range<usize> {
        self.offset()..self.offset() + Field::LEN
    }

    /// `value` as a field stores it: in lower case digits with leading
    /// zeros.
    pub fn encode(value: u32) -> [u8; Field::LEN] {
        std::array::from_fn(|at| {
            // The first digit holds the highest bits.
            let shift = DIGIT_BITS * (Field::LEN - 1 - at) as u32;
            DIGITS[((value >> shift) % RADIX) as usize]
        })
    }

    /// The number the digits of a field stand for. None if one of them is
    /// no hexadecimal digit.
    fn decode(digits: &[u8]) -> Option<u32> {
        // Every digit is looked at, with nothing to decide on the way: a
        // byte that is no digit leaves bits in `seen` that no digit has.
        let (value, seen) = digits.iter().fold((0, 0), |(value, seen), &digit| {
            let digit = VALUES[usize::from(digit)];
            ((value << DIGIT_BITS) | u32::from(digit), seen | digit)
        });
        (u32::from(seen) < RADIX).then_some(value)
    }
}

/// The thirteen numbers of a header.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// The inode number. Together with the device numbers it tells the
    /// names of one hard-linked file from other files.
    pub ino: u32,
    /// The file type and the permissions, as stat(2) has them.
    pub mode: u32,
    /// The owning user.
    pub uid: u32,
    /// The owning group.
    pub gid: u32,
    /// The number of names the file has.
    pub nlink: u32,
    /// The modification time in seconds since the epoch.
    pub mtime: u32,
    /// The length of the data.
    pub filesize: u32,
    /// The major number of the device the file was on.
    pub devmajor: u32,
    /// The minor number of the device the file was on.
    pub devminor: u32,
    /// The major number of a device node.
    pub rdevmajor: u32,
    /// The minor number of a device node.
    pub rdevminor: u32,
    /// The length of the name with its terminating NUL, and with any NUL
    /// bytes after it that are there to move the data.
    pub namesize: u32,
    /// The sum of the data's bytes in the `070702` form, zero otherwise.
    pub check: u32,
}

impl Index<Field> for Header {
    type Output = u32;

    fn index(&self, field: Field) -> &u32 {
        match field {
            Field::Ino => &self.ino,
            Field::Mode => &self.mode,
            Field::Uid => &self.uid,
            Field::Gid => &self.gid,
            Field::Nlink => &self.nlink,
            Field::Mtime => &self.mtime,
            Field::Filesize => &self.filesize,
            Field::Devmajor => &self.devmajor,
            Field::Devminor => &self.devminor,
            Field::Rdevmajor => &self.rdevmajor,
            Field::Rdevminor => &self.rdevminor,
            Field::Namesize => &self.namesize,
            Field::Check => &self.check,
        }
    }
}

impl IndexMut<Field> for Header {
    fn index_mut(&mut self, field: Field) -> &mut u32 {
        match field {
            Field::Ino => &mut self.ino,
            Field::Mode => &mut self.mode,
            Field::Uid => &mut self.uid,
            Field::Gid => &mut self.gid,
            Field::Nlink => &mut self.nlink,
            Field::Mtime => &mut self.mtime,
            Field::Filesize => &mut self.filesize,
            Field::Devmajor => &mut self.devmajor,
            Field::Devminor => &mut self.devminor,
            Field::Rdevmajor => &mut self.rdevmajor,
            Field::Rdevminor => &mut self.rdevminor,
            Field::Namesize => &mut self.namesize,
            Field::Check => &mut self.check,
        }
    }
}

/// Why 110 bytes are not a header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The first six bytes are neither of the two magics.
    Magic,
    /// A field holds something else than hexadecimal digits.
    Field(Field),
}

impl Header {
    /// The header of the entry that ends an archive: everything zero but
    /// the link count, which the `070702` form wants to be one, and the
    /// name's length.
    pub const fn trailer() -> Header {
        Header {
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            filesize: 0,
            devmajor: 0,
            devminor: 0,
            rdevmajor: 0,
            rdevminor: 0,
            namesize: TRAILER.len() as u32 + 1,
            check: 0,
        }
    }

    /// The header as it is stored, in the form `format`.
    pub fn encode(&self, format: Format) -> [u8; HEADER_LEN] {
        let mut raw = [0u8; HEADER_LEN];
        let (magic, fields) = raw.split_at_mut(MAGIC_LEN);
        magic.copy_from_slice(format.magic());
        let values = Field::ALL.map(|field| self[field]);
        for (value, digits) in values.into_iter().zip(fields.chunks_exact_mut(Field::LEN)) {
            for (digit, encoded) in digits.iter_mut().zip(Field::encode(value)) {
                *digit = encoded;
            }
        }
        raw
    }

    /// Reads a stored header.
    pub fn decode(raw: &[u8; HEADER_LEN]) -> Result<(Format, Header), HeaderError> {
        let (magic, fields) = raw.split_at(MAGIC_LEN);
        let format = Format::from_magic(magic).ok_or(HeaderError::Magic)?;
        let mut header = Header::default();
        for (field, digits) in Field::ALL.into_iter().zip(fields.chunks_exact(Field::LEN)) {
            header[field] = Field::decode(digits).ok_or(HeaderError::Field(field))?;
        }
        Ok((format, header))
    }

    /// What the entry is. None for type bits the kernel knows no file
    /// type for.
    pub const fn kind(&self) -> Option<Kind> {
        Kind::from_mode(self.mode)
    }

    /// The number of the device the file was on.
    pub const fn dev(&self) -> DeviceNumber {
        DeviceNumber::new(self.devmajor, self.devminor)
    }

    /// The number of the device a device node stands for.
    pub const fn rdev(&self) -> DeviceNumber {
        DeviceNumber::new(self.rdevmajor, self.rdevminor)
    }

    /// The length of the name field: the name as `namesize` counts it
    /// plus the NUL bytes that bring header and name to a multiple of
    /// [`ALIGNMENT`].
    pub const fn name_field_len(&self) -> u64 {
        let len = self.namesize as u64;
        len + padding(HEADER_LEN as u64 + len)
    }

    /// The length of the data field: the data plus the NUL bytes after it.
    pub const fn data_field_len(&self) -> u64 {
        let len = self.filesize as u64;
        len + padding(len)
    }

    /// The length of the whole entry, a multiple of [`ALIGNMENT`].
    pub const fn entry_len(&self) -> u64 {
        HEADER_LEN as u64 + self.name_field_len() + self.data_field_len()
    }

    /// The `namesize` that makes the data of an entry begin at a multiple
    /// of `alignment`, for a name of `name_len` bytes whose header starts
    /// at `offset` in the archive: the name, its NUL, and as many more NUL
    /// bytes as it takes. This is how file contents get to sit at a block
    /// boundary (the kernel takes the name up to its first NUL and skips
    /// the rest). None when the name would exceed [`MAX_NAME_SIZE`] that
    /// way. `alignment` has to be a multiple of [`ALIGNMENT`] and not
    /// zero.
    pub fn aligned_namesize(offset: u64, name_len: usize, alignment: u32) -> Option<u32> {
        let alignment = u64::from(alignment);
        let plain = name_len as u64 + 1;
        let data = offset.checked_add(HEADER_LEN as u64)?.checked_add(plain)?;
        let extra = (alignment - data % alignment) % alignment;
        let namesize = plain.checked_add(extra)?;
        if namesize > u64::from(MAX_NAME_SIZE) {
            return None;
        }
        Some(namesize as u32)
    }
}

/// How many NUL bytes follow `len` bytes to reach a multiple of
/// [`ALIGNMENT`].
pub const fn padding(len: u64) -> u64 {
    (ALIGNMENT - len % ALIGNMENT) % ALIGNMENT
}

/// The length of the trailer entry, padding included.
pub const TRAILER_LEN: u64 = Header::trailer().entry_len();

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            ino: 1,
            mode: 0o100644,
            uid: 1000,
            gid: 0xffff_fffe,
            nlink: 2,
            mtime: 0x5e0d_5ee5,
            filesize: 0xdead_beef,
            devmajor: 0,
            devminor: 0,
            rdevmajor: 8,
            rdevminor: 1,
            namesize: 5,
            check: 0x1234_abcd,
        }
    }

    #[test]
    fn a_header_reads_back() {
        for format in [Format::Newc, Format::Crc] {
            let raw = sample().encode(format);
            assert_eq!(Header::decode(&raw), Ok((format, sample())));
        }
        assert_eq!(
            &sample().encode(Format::Newc)[..],
            &b"07070100000001000081a4000003e8fffffffe000000025e0d5ee5deadbeef000000000000000000000008000000010000000512\
34abcd"[..]
        );
    }

    /// The kernel's own example: 4780 is 000012ac.
    #[test]
    fn fields_are_eight_digits_padded_with_zeros() {
        assert_eq!(&Field::encode(4780), b"000012ac");
        assert_eq!(Field::decode(b"000012AC"), Some(4780));
        assert_eq!(Field::decode(b"ffffffff"), Some(u32::MAX));
        assert_eq!(&Field::encode(u32::MAX), b"ffffffff");
        assert_eq!(&Field::encode(0), b"00000000");
    }

    #[test]
    fn the_fields_fill_the_header_behind_the_magic() {
        assert_eq!(HEADER_LEN, 110);
        assert_eq!(Field::COUNT, 13);
        assert_eq!(Field::LEN, 8);
        let mut next = MAGIC_LEN;
        for (at, field) in Field::ALL.into_iter().enumerate() {
            assert_eq!(field as usize, at);
            assert_eq!(field.range(), next..next + Field::LEN);
            next = field.range().end;
        }
        assert_eq!(next, HEADER_LEN);
        assert_eq!(Field::Ino.name(), "c_ino");
        assert_eq!(Field::Check.name(), "c_chksum");
        // Each field is read from and written to its own place.
        for field in Field::ALL {
            let mut header = Header::default();
            header[field] = 0x1234_abcd;
            let raw = header.encode(Format::Newc);
            for other in Field::ALL {
                let digits: &[u8] = if other == field { b"1234abcd" } else { b"00000000" };
                assert_eq!(&raw[other.range()], digits);
            }
            assert_eq!(Header::decode(&raw), Ok((Format::Newc, header)));
        }
    }

    #[test]
    fn only_hexadecimal_digits_are_taken() {
        let good = sample().encode(Format::Newc);
        // What strtoul() would take and hex2bin() does not.
        for (at, c) in [(6, b' '), (7, b'x'), (13, b'g'), (20, b'-'), (30, b'+'), (109, 0)] {
            let mut raw = good;
            raw[at] = c;
            let field = Field::ALL
                .into_iter()
                .find(|field| field.range().contains(&at))
                .unwrap();
            assert_eq!(Header::decode(&raw), Err(HeaderError::Field(field)));
        }
        let mut raw = good;
        raw[Field::Mode.offset()..][..2].copy_from_slice(b"0x");
        assert_eq!(Header::decode(&raw), Err(HeaderError::Field(Field::Mode)));
        // Upper case is fine.
        let mut raw = good;
        raw.make_ascii_uppercase();
        assert_eq!(Header::decode(&raw), Ok((Format::Newc, sample())));
    }

    #[test]
    fn other_magics_are_refused() {
        for magic in [&b"070707"[..], b"070703", b"070700", b"\0\0\0\0\0\0", b"\xc7\x71    "] {
            let mut raw = sample().encode(Format::Newc);
            raw[..MAGIC_LEN].copy_from_slice(magic);
            assert_eq!(Header::decode(&raw), Err(HeaderError::Magic));
        }
    }

    /// The format has the numbers of Linux. They are spelled out here, so
    /// that an archive never depends on where it is written.
    #[test]
    fn the_numbers_are_the_ones_of_linux() {
        use crate::sys;
        assert_eq!(MAX_NAME_SIZE as usize, sys::PATH_MAX);
        assert_eq!(S_IFMT, sys::S_IFMT);
        for (kind, bits) in [
            (Kind::Regular, sys::S_IFREG),
            (Kind::Directory, sys::S_IFDIR),
            (Kind::Symlink, sys::S_IFLNK),
            (Kind::CharDevice, sys::S_IFCHR),
            (Kind::BlockDevice, sys::S_IFBLK),
            (Kind::Fifo, sys::S_IFIFO),
            (Kind::Socket, sys::S_IFSOCK),
        ] {
            assert_eq!(kind.bits(), bits);
        }
    }

    #[test]
    fn kinds_and_type_bits() {
        let kinds = [
            Kind::Regular,
            Kind::Directory,
            Kind::Symlink,
            Kind::CharDevice,
            Kind::BlockDevice,
            Kind::Fifo,
            Kind::Socket,
        ];
        for kind in kinds {
            assert_eq!(Kind::from_mode(kind.bits() | 0o7777), Some(kind));
        }
        // The trailer's mode, and the bit patterns no file type has.
        for bits in [
            0, 0o030000, 0o050000, 0o070000, 0o110000, 0o130000, 0o150000, 0o160000, 0o170000,
        ] {
            assert_eq!(Kind::from_mode(bits | 0o644), None);
        }
    }

    /// The lengths as the kernel computes them: N_ALIGN() for the name,
    /// rounding up to four for the data.
    #[test]
    fn lengths_match_the_kernel() {
        let n_align = |len: u64| ((len + 1) & !3) + 2;
        for namesize in 1..=MAX_NAME_SIZE {
            let header = Header {
                namesize,
                ..Header::default()
            };
            assert_eq!(header.name_field_len(), n_align(u64::from(namesize)));
            assert_eq!((HEADER_LEN as u64 + header.name_field_len()) % 4, 0);
        }
        for filesize in [0u32, 1, 2, 3, 4, 5, 4095, 4096, u32::MAX - 1, u32::MAX] {
            let header = Header {
                namesize: 11,
                filesize,
                ..Header::default()
            };
            assert_eq!(header.data_field_len(), (u64::from(filesize) + 3) & !3);
            assert_eq!(header.entry_len() % 4, 0);
        }
        for (len, zeros) in [(0u64, 0u64), (1, 3), (2, 2), (3, 1), (4, 0), (5, 3), (u64::MAX, 1)] {
            assert_eq!(padding(len), zeros);
        }
        assert_eq!(TRAILER_LEN, 124);
        assert_eq!(MAX_NAME_SIZE, 4096);
        assert_eq!((MAX_NAME_LEN, MAX_TARGET_LEN), (4095, 4095));
        assert_eq!((MAX_MAJOR, MAX_MINOR), (0xfff, 0xf_ffff));
    }

    #[test]
    fn device_numbers_are_packed_like_the_kernel_packs_them() {
        let largest = DeviceNumber::new(MAX_MAJOR, MAX_MINOR);
        assert!(largest.fits());
        assert_eq!(largest.packed(), largest);
        assert!(DeviceNumber::NONE.fits());
        assert_eq!(DeviceNumber::new(8, 1).to_string(), "8:1");
        assert_eq!(DeviceNumber::saturating(8, 1), DeviceNumber::new(8, 1));
        assert!(!DeviceNumber::saturating(1 << 32, 1).fits());
        assert!(!DeviceNumber::saturating(1, u64::MAX).fits());
        // What is beyond the major number is cut off.
        let major = DeviceNumber::new(MAX_MAJOR + 1 + 8, 1);
        assert!(!major.fits());
        assert_eq!(major.packed(), DeviceNumber::new(8, 1));
        // What is beyond the minor number lands in the major number.
        let minor = DeviceNumber::new(8, (3 << MINOR_BITS) | 5);
        assert!(!minor.fits());
        assert_eq!(minor.packed(), DeviceNumber::new(8 | 3, 5));
        let header = Header {
            devmajor: 1,
            devminor: 2,
            rdevmajor: 3,
            rdevminor: 4,
            ..Header::default()
        };
        assert_eq!(
            (header.dev(), header.rdev()),
            (DeviceNumber::new(1, 2), DeviceNumber::new(3, 4))
        );
    }

    #[test]
    fn names_are_padded_to_align_the_data() {
        // Nothing to do when the data is aligned as it is.
        assert_eq!(Header::aligned_namesize(0, 1, 4), Some(2));
        assert_eq!(Header::aligned_namesize(0, 2, 4), Some(6));
        for (offset, name_len, alignment) in [
            (0u64, 3usize, 4096u32),
            (112, 1, 4096),
            (8192 - 4, 20, 512),
            (4, 4000, 8),
        ] {
            let namesize = Header::aligned_namesize(offset, name_len, alignment).unwrap();
            assert!(namesize as usize > name_len);
            assert_eq!(
                (offset + HEADER_LEN as u64 + u64::from(namesize)) % u64::from(alignment),
                0
            );
            // No further padding is added behind an aligned name.
            let header = Header {
                namesize,
                ..Header::default()
            };
            assert_eq!(header.name_field_len(), u64::from(namesize));
        }
        // 4096 bytes of name are the limit.
        assert_eq!(Header::aligned_namesize(0, 3, 4096), Some(4096 - 110));
        assert_eq!(Header::aligned_namesize(0, 4, 8192), None);
        assert_eq!(Header::aligned_namesize(4, 4000, 4096), None);
        assert_eq!(Header::aligned_namesize(u64::MAX - 100, 3, 4), None);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_header() -> Header {
        Header {
            ino: kani::any(),
            mode: kani::any(),
            uid: kani::any(),
            gid: kani::any(),
            nlink: kani::any(),
            mtime: kani::any(),
            filesize: kani::any(),
            devmajor: kani::any(),
            devminor: kani::any(),
            rdevmajor: kani::any(),
            rdevminor: kani::any(),
            namesize: kani::any(),
            check: kani::any(),
        }
    }

    /// Every header reads back as it was written, in both forms.
    #[kani::proof]
    #[kani::unwind(14)]
    fn encode_then_decode_is_the_identity() {
        let header = any_header();
        let format = if kani::any() { Format::Newc } else { Format::Crc };
        let raw = header.encode(format);
        assert!(Header::decode(&raw) == Ok((format, header)));
    }

    /// decode() never panics, whatever the bytes, and what it accepts
    /// holds nothing but a magic and hexadecimal digits.
    #[kani::proof]
    #[kani::unwind(111)]
    fn decode_is_total_and_strict() {
        let raw: [u8; HEADER_LEN] = kani::any();
        if Header::decode(&raw).is_ok() {
            assert!(raw[..5] == *b"07070");
            assert!(raw[5] == b'1' || raw[5] == b'2');
            let at: usize = kani::any_where(|i: &usize| *i >= MAGIC_LEN && *i < HEADER_LEN);
            assert!(raw[at].is_ascii_hexdigit());
        }
    }

    /// Entries are multiples of four long and the lengths do not overflow.
    #[kani::proof]
    fn lengths_are_aligned() {
        let header = any_header();
        assert!((HEADER_LEN as u64 + header.name_field_len()) % ALIGNMENT == 0);
        assert!(header.data_field_len() % ALIGNMENT == 0);
        assert!(header.entry_len() % ALIGNMENT == 0);
        assert!(header.name_field_len() - (header.namesize as u64) < ALIGNMENT);
        assert!(header.data_field_len() - (header.filesize as u64) < ALIGNMENT);
    }

    /// An aligned name puts the data where it was asked for and stays
    /// within the limit.
    #[kani::proof]
    fn aligned_names_align() {
        let offset: u64 = kani::any();
        let name_len: usize = kani::any_where(|l: &usize| *l <= MAX_NAME_LEN);
        let quarter: u32 = kani::any_where(|q: &u32| *q >= 1 && *q <= (1 << 28));
        let alignment = quarter * 4;
        if let Some(namesize) = Header::aligned_namesize(offset, name_len, alignment) {
            assert!(namesize as usize > name_len);
            assert!(namesize <= MAX_NAME_SIZE);
            assert!((offset + HEADER_LEN as u64 + namesize as u64) % alignment as u64 == 0);
        }
    }
}
