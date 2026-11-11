// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading an archive: one entry after the other, the way the kernel does.
//!
//! [`Scanner`] follows init/initramfs.c step by step and says of every
//! entry what the kernel makes of it, see [`Standing`]. That is more than
//! whether the entry is well formed: the kernel passes over several kinds
//! of entries without a word, and one kind takes something away instead
//! of adding to what is unpacked.
//!
//! An archive ends with its trailer. The kernel reads on behind it, since
//! an initramfs can be several archives in a row, but this crate deals
//! with one archive: what follows the trailer is not read here, and
//! [`Source::first_nonzero`] tells whether anything but padding is there.
//!
//! Nothing that is read is trusted. Every length comes out of the
//! archive, so every offset is checked against the archive's end before it
//! is used, and a damaged archive is an error, never a panic.

use std::fmt;

use crate::device::Device;

use crate::errno::*;
use crate::header::{
    Field, Format, Header, HeaderError, Kind, ALIGNMENT, HEADER_LEN, MAGIC_LEN, MAGIC_NAME, MAGIC_START, MAX_NAME_SIZE,
    TRAILER,
};
use crate::{CorruptPlace, Detail, NotCpioReason, Result};

/// Size of the window a scanner reads headers and names through. A header
/// and the longest name fit several times.
const WINDOW: usize = 64 * 1024;

/// Size of the window behind the data of a file that was passed over. The
/// next entry may be all that is wanted there before the data of the next
/// file is passed over, so only as much is read as an entry usually is
/// long.
const SHORT_WINDOW: usize = 4096;

/// How far behind the entry before it an entry starts for what is
/// between the two to count as data that was passed over. Below that a
/// full window holds several entries and costs less than a short window
/// for each of them.
const FAR: u64 = (WINDOW / 4) as u64;

/// The bytes of an archive, to be read at any offset.
pub trait Source {
    /// How many bytes there are.
    fn len(&self) -> u64;

    /// Whether there are none.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Fills `buf` from `offset`. The range lies within [`Source::len`].
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;

    /// The offset of the first byte from `from` on that is not NUL, if
    /// there is one: whether anything but padding follows the trailer of
    /// an archive.
    fn first_nonzero(&self, from: u64) -> Result<Option<u64>> {
        let len = self.len();
        let mut buf = vec![0u8; WINDOW];
        let mut offset = from;
        while offset < len {
            let chunk = (len - offset).min(WINDOW as u64) as usize;
            self.read_at(offset, &mut buf[..chunk])?;
            if let Some(at) = buf[..chunk].iter().position(|&b| b != 0) {
                return Ok(Some(offset + at as u64));
            }
            offset += chunk as u64;
        }
        Ok(None)
    }

    /// What is at `offset`, the first byte behind the trailer of an
    /// archive that is not NUL.
    fn follower(&self, offset: u64) -> Result<Follower> {
        // Behind padding the kernel takes nothing that is off a multiple
        // of four.
        let left = self.len().saturating_sub(offset);
        if offset % ALIGNMENT != 0 || left == 0 {
            return Ok(Follower::Unknown);
        }
        let mut start = [0u8; MAGIC_LEN];
        let len = left.min(MAGIC_LEN as u64) as usize;
        self.read_at(offset, &mut start[..len])?;
        let start = &start[..len];
        if start.first() == Some(&MAGIC_START) {
            // An entry, to the kernel. One that is cut short in its header
            // it passes over without a word.
            let entry = left < HEADER_LEN as u64 || Format::from_magic(start).is_some();
            return Ok(if entry { Follower::Archive } else { Follower::Unknown });
        }
        Ok(match Foreign::of(start) {
            Some(format) if format.is_compression() => Follower::Compressed(format),
            _ => Follower::Unknown,
        })
    }

    /// The sum of the bytes of `len` bytes at `offset`, the checksum of
    /// the `070702` form.
    fn checksum(&self, offset: u64, len: u64) -> Result<u32> {
        let mut buf = vec![0u8; WINDOW.min(usize::try_from(len).unwrap_or(WINDOW)).max(1)];
        let mut sum = 0u32;
        let mut done = 0u64;
        while done < len {
            let chunk = (len - done).min(buf.len() as u64) as usize;
            self.read_at(offset + done, &mut buf[..chunk])?;
            sum = buf[..chunk].iter().fold(sum, |sum, &b| sum.wrapping_add(u32::from(b)));
            done += chunk as u64;
        }
        Ok(sum)
    }
}

impl Source for Device {
    fn len(&self) -> u64 {
        Device::len(self)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        Device::read_at(self, offset, buf)
    }
}

impl Source for [u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let range = usize::try_from(offset)
            .ok()
            .and_then(|start| Some(start..start.checked_add(buf.len())?))
            .filter(|range| range.end <= <[u8]>::len(self));
        match range {
            Some(range) => {
                buf.copy_from_slice(&self[range]);
                Ok(())
            }
            None => bail!(EINVAL, "a read at offset {} is outside of the archive", offset),
        }
    }
}

impl Source for Vec<u8> {
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        Source::read_at(self.as_slice(), offset, buf)
    }
}

/// Why the kernel passes over an entry without unpacking it and without
/// an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// The name's size is zero or more than 4096.
    NameSize,
    /// A symbolic link whose target is longer than 4096 bytes.
    TargetSize,
    /// Something that is neither a regular file nor a symbolic link and
    /// yet has data: a directory or a device node with a size, or an entry
    /// without a file type that has one.
    Data,
}

/// What the kernel makes of an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// It unpacks it as a file of this kind.
    Entry(Kind),
    /// The entry has no file type the kernel knows and no data. The kernel
    /// creates nothing for it, but it removes a file or an empty directory
    /// that is at its path already.
    Removal,
    /// The trailer: the archive ends here.
    Trailer,
    /// It passes over the entry.
    Skipped(Skip),
}

/// One entry of an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Where its header starts in the archive.
    pub offset: u64,
    /// How many NUL bytes lie between the entry before and this one.
    /// Only the kernel reads an archive with such a gap in it.
    pub gap: u64,
    /// The form of the header.
    pub format: Format,
    /// The header.
    pub header: Header,
    /// The name as it is stored, up to its first NUL. Empty for an entry
    /// passed over for the size of its name.
    pub name: Vec<u8>,
    /// How many NUL bytes the name carries beyond the one that ends it.
    pub name_padding: u32,
    /// Where the data starts in the archive.
    pub data_offset: u64,
    /// For a symbolic link that is unpacked, the length of its target: the
    /// data up to its first NUL byte, which is where the kernel's string
    /// ends. Zero for everything else.
    pub target_len: u32,
    /// What the kernel makes of the entry.
    pub standing: Standing,
}

impl Record {
    /// Where the entry ends: the next one starts here.
    pub fn end(&self) -> u64 {
        self.data_offset + self.header.data_field_len()
    }
}

/// Which part of an entry an archive ends in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// The header.
    Header,
    /// The name.
    Name,
    /// The data.
    Data,
}

impl Part {
    /// What the part is called.
    pub const fn name(self) -> &'static str {
        match self {
            Part::Header => "header",
            Part::Name => "name",
            Part::Data => "data",
        }
    }

    /// The field of the header that says how long the part is. The
    /// header's own length is fixed.
    pub const fn length_field(self) -> Option<Field> {
        match self {
            Part::Header => None,
            Part::Name => Some(Field::Namesize),
            Part::Data => Some(Field::Filesize),
        }
    }
}

/// What is wrong with an archive at the point where reading it stops. The
/// kernel stops unpacking there too, or goes wrong: it reports none of
/// these but the first four.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Damage {
    /// No header where one has to be. `found` is what is there instead,
    /// when it is something known.
    Magic {
        /// Where the header would start.
        offset: u64,
        /// What the bytes are, if they are the start of something known.
        found: Option<Foreign>,
    },
    /// A header field holds something else than hexadecimal digits.
    Field {
        /// Where the header starts.
        offset: u64,
        /// Which field.
        field: Field,
    },
    /// A name does not end in a NUL byte.
    Unterminated {
        /// Where the header starts.
        offset: u64,
    },
    /// The entry behind a gap of NUL bytes does not start at a multiple of
    /// four.
    Misaligned {
        /// Where the entry starts.
        offset: u64,
    },
    /// The archive ends in the middle of an entry. The kernel unpacks what
    /// is there and says nothing.
    Truncated {
        /// Where the header of the entry starts.
        offset: u64,
        /// Which part of the entry is cut short.
        part: Part,
    },
}

/// What starts where an entry is expected and is none: the compression
/// formats as the kernel tells them, by their first two bytes
/// (lib/decompress.c), the older cpio formats, and a header that is
/// stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Foreign {
    /// gzip.
    Gzip,
    /// bzip2.
    Bzip2,
    /// LZMA.
    Lzma,
    /// XZ.
    Xz,
    /// LZO.
    Lzo,
    /// LZ4.
    Lz4,
    /// Zstandard.
    Zstd,
    /// A cpio archive in the old portable ASCII format.
    CpioOdc,
    /// A cpio archive in the old binary format, in either byte order.
    CpioBin,
    /// A header that is stopped: an archive that was being written, or
    /// added to, where the header is, and was not finished. See
    /// [`STOPPER`](crate::header::STOPPER).
    Unfinished,
}

impl Foreign {
    /// What each of them starts with.
    const MAGICS: &'static [(&'static [u8], Foreign)] = &[
        (b"\x1f\x8b", Foreign::Gzip),
        (b"\x1f\x9e", Foreign::Gzip),
        (b"BZ", Foreign::Bzip2),
        (b"\x5d\x00", Foreign::Lzma),
        (b"\xfd\x37", Foreign::Xz),
        (b"\x89\x4c", Foreign::Lzo),
        (b"\x02\x21", Foreign::Lz4),
        (b"\x28\xb5", Foreign::Zstd),
        (b"070707", Foreign::CpioOdc),
        (b"\xc7\x71", Foreign::CpioBin),
        (b"\x71\xc7", Foreign::CpioBin),
        (&Format::Newc.stopped_magic(), Foreign::Unfinished),
        (&Format::Crc.stopped_magic(), Foreign::Unfinished),
    ];

    /// What `bytes` are the start of, if it is one of these.
    pub fn of(bytes: &[u8]) -> Option<Foreign> {
        Foreign::MAGICS
            .iter()
            .find(|(magic, _)| bytes.starts_with(magic))
            .map(|&(_, foreign)| foreign)
    }

    /// The name it goes by.
    pub const fn name(self) -> &'static str {
        match self {
            Foreign::Gzip => "gzip",
            Foreign::Bzip2 => "bzip2",
            Foreign::Lzma => "lzma",
            Foreign::Xz => "xz",
            Foreign::Lzo => "lzo",
            Foreign::Lz4 => "lz4",
            Foreign::Zstd => "zstd",
            Foreign::CpioOdc => "cpio-odc",
            Foreign::CpioBin => "cpio-bin",
            Foreign::Unfinished => "cpio-unfinished",
        }
    }

    /// Whether it is a compression format. The kernel unpacks an archive
    /// compressed with one it was built with.
    pub const fn is_compression(self) -> bool {
        match self {
            Foreign::Gzip
            | Foreign::Bzip2
            | Foreign::Lzma
            | Foreign::Xz
            | Foreign::Lzo
            | Foreign::Lz4
            | Foreign::Zstd => true,
            Foreign::CpioOdc | Foreign::CpioBin | Foreign::Unfinished => false,
        }
    }
}

impl fmt::Display for Foreign {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl Damage {
    /// Where in the archive the damage is.
    pub fn offset(&self) -> u64 {
        match *self {
            Damage::Magic { offset, .. }
            | Damage::Field { offset, .. }
            | Damage::Unterminated { offset }
            | Damage::Misaligned { offset }
            | Damage::Truncated { offset, .. } => offset,
        }
    }

    /// The damage as the error of an operation that needs the archive
    /// sound. Something else than an entry at the very start means the
    /// image holds no archive at all; everything else is an archive that
    /// is damaged, and so is one that is stopped at its start.
    pub fn into_error(self) -> crate::Error {
        let corrupt = |field: Option<&'static str>| Detail::Corrupt {
            place: CorruptPlace::Entry,
            field,
            path: None,
            cluster: None,
        };
        match self {
            Damage::Magic {
                offset,
                found: Some(Foreign::Unfinished),
            } => err!(
                EUCLEAN,
                corrupt(Some(MAGIC_NAME)),
                "the archive was not finished at offset {}: writing it failed or was cut off",
                offset
            ),
            Damage::Magic { offset: 0, found } => {
                let reason = if found.is_some() {
                    NotCpioReason::OtherFormat
                } else {
                    NotCpioReason::Unknown
                };
                let what = found.map_or(String::new(), |f| format!(", it starts like {}", f));
                err!(
                    EMEDIUMTYPE,
                    Detail::NotCpio {
                        reason,
                        found: found.map(Foreign::name),
                    },
                    "the image holds no cpio archive in the new ASCII format{}",
                    what
                )
            }
            Damage::Magic { offset, found } => {
                let what = found.map_or(String::new(), |f| format!(", something that starts like {}", f));
                err!(
                    EUCLEAN,
                    corrupt(Some(MAGIC_NAME)),
                    "the archive is damaged: no entry at offset {}{}",
                    offset,
                    what
                )
            }
            Damage::Field { offset, field } => err!(
                EUCLEAN,
                corrupt(Some(field.name())),
                "the archive is damaged: the header at offset {} holds no number in {}",
                offset,
                field.name()
            ),
            Damage::Unterminated { offset } => err!(
                EUCLEAN,
                corrupt(Some(Field::Namesize.name())),
                "the archive is damaged: the name of the entry at offset {} does not end in a NUL byte",
                offset
            ),
            Damage::Misaligned { offset } => err!(
                EUCLEAN,
                corrupt(None),
                "the archive is damaged: the entry at offset {} does not start at a multiple of four",
                offset
            ),
            Damage::Truncated { offset, part } => err!(
                EUCLEAN,
                corrupt(part.length_field().map(Field::name)),
                "the archive is damaged: it ends inside the {} of the entry at offset {}",
                part.name(),
                offset
            ),
        }
    }
}

/// How a scan ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// With the trailer, which ends at this offset. Whatever follows is
    /// not part of the archive.
    Trailer(u64),
    /// At the end of the bytes, without a trailer. The kernel unpacks such
    /// an archive, cpio(1) calls it cut short.
    NoTrailer,
}

/// Where a scan stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// There may be more entries.
    Reading,
    /// The archive ended.
    Ended(End),
    /// The archive is damaged where the scan stands. Nothing behind that
    /// is read.
    Damaged,
}

/// Reads the entries of an archive in order. The scan ends with the
/// trailer, at the end of the bytes, or with the damage it comes to.
pub struct Scanner<'a, S: Source + ?Sized> {
    source: &'a S,
    len: u64,
    /// Where the next entry starts.
    offset: u64,
    /// A window of the archive, for the headers and the names.
    window: Vec<u8>,
    window_at: u64,
    /// Where the header that was read last starts.
    last_header: u64,
    state: State,
}

impl<'a, S: Source + ?Sized> Scanner<'a, S> {
    /// Starts at the first byte of `source`.
    pub fn new(source: &'a S) -> Scanner<'a, S> {
        Scanner {
            source,
            len: source.len(),
            offset: 0,
            window: Vec::new(),
            window_at: 0,
            last_header: 0,
            state: State::Reading,
        }
    }

    /// How the scan ended, once it came to no further entry. None while
    /// there may be more entries, and for an archive that is damaged.
    pub fn end(&self) -> Option<End> {
        match self.state {
            State::Ended(end) => Some(end),
            State::Reading | State::Damaged => None,
        }
    }

    /// Where the next entry starts, or where the scan ended.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// `len` bytes of the archive at `offset`, through the window. The
    /// caller made sure they lie within the archive; `len` is at most a
    /// header or a name.
    fn bytes(&mut self, offset: u64, len: usize) -> Result<&[u8]> {
        let inside = offset >= self.window_at && offset + len as u64 <= self.window_at + self.window.len() as u64;
        if !inside {
            self.fill(offset, len)?;
        }
        let start = (offset - self.window_at) as usize;
        Ok(&self.window[start..start + len])
    }

    /// Reads the window anew from `offset` on, `len` bytes of the archive
    /// at least. Entries that follow each other closely are read a full
    /// window at a time. An entry that starts far behind the one before
    /// it comes after the data of a file, and so may the next one: a
    /// short window is read there, so that a scan of an archive of large
    /// files reads little more than the headers. A run of zero bytes goes
    /// on where the window ended and is read a full window at a time.
    fn fill(&mut self, offset: u64, len: usize) -> Result<()> {
        let end = self.window_at + self.window.len() as u64;
        let far = offset != end && offset.saturating_sub(self.last_header) >= FAR;
        let size = if far { SHORT_WINDOW } else { WINDOW };
        let want = (self.len - offset).min(size.max(len) as u64) as usize;
        self.window.resize(want, 0);
        self.window_at = offset;
        if let Err(e) = self.source.read_at(offset, &mut self.window) {
            // Nothing of what the window holds now is the archive.
            self.window.clear();
            return Err(e);
        }
        Ok(())
    }

    /// What the window has of the archive from `offset` on, which lies
    /// within the archive: one byte at least. The window is filled again
    /// only when `offset` is not in it.
    fn rest(&mut self, offset: u64) -> Result<&[u8]> {
        let inside = offset >= self.window_at && offset < self.window_at + self.window.len() as u64;
        if !inside {
            self.fill(offset, 1)?;
        }
        Ok(&self.window[(offset - self.window_at) as usize..])
    }

    /// Passes over NUL bytes from the current offset on. Returns how many
    /// there were.
    fn skip_zeros(&mut self) -> Result<u64> {
        let start = self.offset;
        while self.offset < self.len {
            // Most of the time the next byte is the first of an entry
            // and is in the window already.
            let bytes = self.rest(self.offset)?;
            match bytes.iter().position(|&b| b != 0) {
                Some(at) => {
                    self.offset += at as u64;
                    break;
                }
                None => self.offset += bytes.len() as u64,
            }
        }
        Ok(self.offset - start)
    }

    /// The next entry: None behind the trailer or at the end of the bytes.
    /// The outer error is one of reading, the inner one says the archive is
    /// damaged where the scan stands.
    fn entry(&mut self) -> Result<std::result::Result<Option<Record>, Damage>> {
        if self.state != State::Reading {
            return Ok(Ok(None));
        }
        let gap = self.skip_zeros()?;
        let offset = self.offset;
        if offset == self.len {
            self.state = State::Ended(End::NoTrailer);
            return Ok(Ok(None));
        }
        if offset % ALIGNMENT != 0 {
            return Ok(Err(Damage::Misaligned { offset }));
        }
        let left = self.len - offset;
        if left < HEADER_LEN as u64 {
            // What is there may still say that this is no entry at all.
            let bytes = self.bytes(offset, left as usize)?;
            let start = &bytes[..bytes.len().min(MAGIC_LEN)];
            let entry = Format::Newc.magic().starts_with(start) || Format::Crc.magic().starts_with(start);
            let found = Foreign::of(bytes);
            return Ok(Err(if entry {
                Damage::Truncated {
                    offset,
                    part: Part::Header,
                }
            } else {
                Damage::Magic { offset, found }
            }));
        }
        let raw: [u8; HEADER_LEN] = self
            .bytes(offset, HEADER_LEN)?
            .try_into()
            .map_err(|_| err!(EIO, "short read of a header"))?;
        self.last_header = offset;
        let (format, header) = match Header::decode(&raw) {
            Ok(decoded) => decoded,
            Err(HeaderError::Magic) => {
                return Ok(Err(Damage::Magic {
                    offset,
                    found: Foreign::of(&raw),
                }))
            }
            Err(HeaderError::Field(field)) => return Ok(Err(Damage::Field { offset, field })),
        };
        let name_offset = offset + HEADER_LEN as u64;
        // Both lengths are 32 bits wide, so the sums stay far below 2^64.
        let data_offset = name_offset + header.name_field_len();
        let symlink = header.kind() == Some(Kind::Symlink);
        let regular = header.kind() == Some(Kind::Regular);
        // The order of these is the order of do_header().
        let skip = if header.namesize == 0 || header.namesize > MAX_NAME_SIZE {
            Some(Skip::NameSize)
        } else if symlink && header.filesize > MAX_NAME_SIZE {
            Some(Skip::TargetSize)
        } else if !symlink && !regular && header.filesize != 0 {
            Some(Skip::Data)
        } else {
            None
        };
        let mut name = Vec::new();
        let mut name_padding = 0;
        if skip != Some(Skip::NameSize) {
            if name_offset + u64::from(header.namesize) > self.len {
                return Ok(Err(Damage::Truncated {
                    offset,
                    part: Part::Name,
                }));
            }
            let stored = self.bytes(name_offset, header.namesize as usize)?;
            // The kernel looks at the name of what it unpacks only.
            if skip.is_none() && stored.last() != Some(&0) {
                return Ok(Err(Damage::Unterminated { offset }));
            }
            let len = stored.iter().position(|&b| b == 0).unwrap_or(stored.len());
            name_padding = (stored.len() - len).saturating_sub(1) as u32;
            name = stored[..len].to_vec();
        }
        if data_offset + u64::from(header.filesize) > self.len {
            let part = if data_offset > self.len { Part::Name } else { Part::Data };
            return Ok(Err(Damage::Truncated { offset, part }));
        }
        let mut target_len = 0;
        if skip.is_none() && symlink {
            let target = self.bytes(data_offset, header.filesize as usize)?;
            target_len = target.iter().position(|&b| b == 0).unwrap_or(target.len()) as u32;
        }
        let standing = match (skip, header.kind()) {
            (Some(skip), _) => Standing::Skipped(skip),
            (None, Some(Kind::Symlink)) => Standing::Entry(Kind::Symlink),
            // do_name() looks for the trailer before it looks at the type.
            (None, _) if name == TRAILER => Standing::Trailer,
            (None, Some(kind)) => Standing::Entry(kind),
            (None, None) => Standing::Removal,
        };
        let record = Record {
            offset,
            gap,
            format,
            header,
            name,
            name_padding,
            data_offset,
            target_len,
            standing,
        };
        // An archive may end right behind the data of its last entry,
        // without the padding.
        self.offset = record.end().min(self.len);
        if standing == Standing::Trailer {
            self.state = State::Ended(End::Trailer(self.offset));
        }
        Ok(Ok(Some(record)))
    }
}

impl<S: Source + ?Sized> Iterator for Scanner<'_, S> {
    /// An entry, or the damage the archive has where the scan stands,
    /// which ends the scan. The outer error is one of reading: the scan
    /// goes on from the same entry after it.
    type Item = Result<std::result::Result<Record, Damage>>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entry();
        if matches!(entry, Ok(Err(_))) {
            self.state = State::Damaged;
        }
        entry.map(std::result::Result::transpose).transpose()
    }
}

/// What the kernel takes the bytes behind a trailer for, when they are no
/// padding. It reads on there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Follower {
    /// Another archive in the form the kernel takes. It unpacks it too.
    Archive,
    /// A compressed archive, in the format named. The kernel unpacks it
    /// if it was built with that format.
    Compressed(Foreign),
    /// Nothing the kernel takes. It fails there, having unpacked what is
    /// before.
    Unknown,
}

/// What an image is when it holds no archive: nothing at all, or nothing
/// but NUL bytes. The kernel unpacks nothing from either and is content.
pub fn blank() -> crate::Error {
    err!(
        ENODATA,
        Detail::NotCpio {
            reason: NotCpioReason::Blank,
            found: None,
        },
        "the image holds no cpio archive, it is empty"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::DeviceNumber;
    use crate::test_util::named;
    use crate::write::{Attributes, Options, Writer};

    const ATTRIBUTES: Attributes = Attributes {
        mode: 0o644,
        uid: 1,
        gid: 2,
        mtime: 3,
    };

    /// An entry put together by hand, without the padding of its data when
    /// `cut` says so.
    fn raw(magic: &[u8; 6], mode: u32, nlink: u32, name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = magic.to_vec();
        for field in [
            7,
            mode,
            0,
            0,
            nlink,
            0,
            data.len() as u32,
            0,
            0,
            0,
            0,
            name.len() as u32,
            0,
        ] {
            out.extend_from_slice(format!("{:08X}", field).as_bytes());
        }
        out.extend_from_slice(name);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn trailer() -> Vec<u8> {
        raw(b"070701", 0, 1, b"TRAILER!!!\0", b"")
    }

    fn scan(archive: &[u8]) -> (Vec<Record>, std::result::Result<End, Damage>) {
        let mut scanner = Scanner::new(archive);
        let mut records = Vec::new();
        for entry in scanner.by_ref() {
            match entry.unwrap() {
                Ok(record) => records.push(record),
                Err(damage) => {
                    // The scan ends with the damage and has no end to tell.
                    assert!(scanner.next().is_none());
                    assert_eq!(scanner.end(), None);
                    return (records, Err(damage));
                }
            }
        }
        (records, Ok(scanner.end().unwrap()))
    }

    fn sample() -> Vec<u8> {
        let mut w = Writer::new(Vec::new(), Options::default()).unwrap();
        w.directory(named(b"."), &ATTRIBUTES).unwrap();
        w.directory(named(b"d"), &ATTRIBUTES).unwrap();
        w.file(named(b"d/f"), &ATTRIBUTES, None, 5, &mut &b"hello"[..]).unwrap();
        w.symlink(named(b"l"), &ATTRIBUTES, b"d/f").unwrap();
        w.node(
            named(b"n"),
            Kind::CharDevice,
            &ATTRIBUTES,
            DeviceNumber::new(1, 3),
            None,
        )
        .unwrap();
        w.finish().unwrap().0
    }

    #[test]
    fn what_the_writer_wrote_is_read() {
        let archive = sample();
        let (records, end) = scan(&archive);
        // Two directories and a node of 112 bytes each, the file with 124,
        // the link with 116 and the trailer with 124.
        assert_eq!(end, Ok(End::Trailer(3 * 112 + 124 + 116 + 124)));
        assert_eq!(archive.len(), 1024);
        let names: Vec<&[u8]> = records.iter().map(|r| r.name.as_slice()).collect();
        assert_eq!(names, [&b"."[..], b"d", b"d/f", b"l", b"n", b"TRAILER!!!"]);
        let standings: Vec<Standing> = records.iter().map(|r| r.standing).collect();
        assert_eq!(
            standings,
            [
                Standing::Entry(Kind::Directory),
                Standing::Entry(Kind::Directory),
                Standing::Entry(Kind::Regular),
                Standing::Entry(Kind::Symlink),
                Standing::Entry(Kind::CharDevice),
                Standing::Trailer,
            ]
        );
        let f = &records[2];
        assert_eq!((f.header.uid, f.header.gid, f.header.mtime), (1, 2, 3));
        assert_eq!(&archive[f.data_offset as usize..][..5], b"hello");
        assert_eq!(records[3].header.filesize, 3);
        assert!(records
            .iter()
            .all(|r| r.gap == 0 && r.name_padding == 0 && r.format == Format::Newc));
        // The offsets chain up.
        for pair in records.windows(2) {
            assert_eq!(pair[0].end(), pair[1].offset);
        }
        assert_eq!(archive.first_nonzero(records[5].end()).unwrap(), None);
    }

    #[test]
    fn padded_names_are_cut_at_their_first_nul() {
        let options = Options {
            data_alignment: 4096,
            ..Options::default()
        };
        let mut w = Writer::new(Vec::new(), options).unwrap();
        let data = vec![b'x'; 5000];
        w.file(named(b"big"), &ATTRIBUTES, None, 5000, &mut &data[..]).unwrap();
        let (records, end) = scan(&w.finish().unwrap().0);
        assert!(end.is_ok());
        assert_eq!(records[0].name, b"big");
        assert_eq!(records[0].data_offset, 4096);
        assert_eq!(records[0].name_padding, 4096 - 110 - 4);
    }

    #[test]
    fn the_kernel_passes_over_some_entries() {
        let mut archive = Vec::new();
        // A directory with data, a device with data, an entry without a
        // type and with data.
        archive.extend(raw(b"070701", 0o040755, 2, b"dir\0", b"data"));
        archive.extend(raw(b"070701", 0o020600, 1, b"dev\0", b"data"));
        archive.extend(raw(b"070701", 0, 1, b"none\0", b"data"));
        // Without a type and without data: a removal.
        archive.extend(raw(b"070701", 0, 1, b"gone\0", b""));
        archive.extend(raw(b"070701", 0o030644, 1, b"odd\0", b""));
        // A symbolic link of 4097 bytes, and one of 4096.
        archive.extend(raw(b"070701", 0o120777, 1, b"long\0", &[b't'; 4097]));
        archive.extend(raw(b"070701", 0o120777, 1, b"fits\0", &[b't'; 4096]));
        // A name of 4097 bytes with its NUL, and no name at all.
        let mut name = vec![b'n'; 4096];
        name.push(0);
        archive.extend(raw(b"070701", 0o100644, 1, &name, b"x"));
        archive.extend(raw(b"070701", 0o100644, 1, b"", b"x"));
        // A name without a NUL does not matter where the kernel does not
        // look at it.
        archive.extend(raw(b"070701", 0o040755, 2, b"nonul", b"data"));
        archive.extend(trailer());
        let (records, end) = scan(&archive);
        assert_eq!(end, Ok(End::Trailer(archive.len() as u64)));
        let standings: Vec<Standing> = records.iter().map(|r| r.standing).collect();
        assert_eq!(
            standings,
            [
                Standing::Skipped(Skip::Data),
                Standing::Skipped(Skip::Data),
                Standing::Skipped(Skip::Data),
                Standing::Removal,
                Standing::Removal,
                Standing::Skipped(Skip::TargetSize),
                Standing::Entry(Kind::Symlink),
                Standing::Skipped(Skip::NameSize),
                Standing::Skipped(Skip::NameSize),
                Standing::Skipped(Skip::Data),
                Standing::Trailer,
            ]
        );
        assert_eq!(records[7].name, b"");
        assert_eq!(records[9].name, b"nonul");
    }

    #[test]
    fn the_trailer_is_what_the_kernel_takes_for_one() {
        // A regular file of that name with data ends the archive.
        let mut archive = raw(b"070701", 0o100644, 1, b"TRAILER!!!\0", b"data");
        let len = archive.len() as u64;
        archive.extend(raw(b"070701", 0o100644, 1, b"after\0", b""));
        let (records, end) = scan(&archive);
        assert_eq!(records.len(), 1);
        assert_eq!(end, Ok(End::Trailer(len)));
        assert_eq!(archive.first_nonzero(len).unwrap(), Some(len));
        // A symbolic link of that name does not, and neither does a name
        // that only ends in it or goes on behind a NUL.
        let mut archive = raw(b"070701", 0o120777, 1, b"TRAILER!!!\0", b"target");
        archive.extend(raw(b"070701", 0o100644, 1, b"./TRAILER!!!\0", b""));
        archive.extend(raw(b"070701", 0o100644, 1, b"d/TRAILER!!!\0", b""));
        let (records, end) = scan(&archive);
        assert_eq!(records.len(), 3);
        assert_eq!(end, Ok(End::NoTrailer));
        // The name is compared up to its first NUL.
        let archive = raw(b"070701", 0, 1, b"TRAILER!!!\0\0\0\0\0", b"");
        let (records, end) = scan(&archive);
        assert_eq!(records[0].standing, Standing::Trailer);
        assert_eq!(records[0].name_padding, 4);
        assert_eq!(end, Ok(End::Trailer(archive.len() as u64)));
    }

    #[test]
    fn gaps_of_nul_bytes_are_passed_over_as_the_kernel_does() {
        let entry = raw(b"070702", 0o100644, 1, b"f\0", b"x");
        let mut archive = vec![0u8; 8];
        archive.extend(&entry);
        archive.extend([0u8; 512]);
        archive.extend(&entry);
        let (records, end) = scan(&archive);
        assert_eq!(end, Ok(End::NoTrailer));
        assert_eq!(records.len(), 2);
        assert_eq!((records[0].offset, records[0].gap), (8, 8));
        assert_eq!(records[1].gap, 512);
        assert_eq!(records[1].format, Format::Crc);
        // A gap that is not a multiple of four leaves the next entry where
        // the kernel does not take it.
        let mut archive = entry.clone();
        archive.extend([0u8; 3]);
        archive.extend(&entry);
        let (records, end) = scan(&archive);
        assert_eq!(records.len(), 1);
        assert_eq!(end, Err(Damage::Misaligned { offset: 119 }));
        // Nothing but NUL bytes is no archive, and no damage either.
        let (records, end) = scan(&[0u8; 100]);
        assert!(records.is_empty());
        assert_eq!(end, Ok(End::NoTrailer));
        let (records, end) = scan(&[]);
        assert!(records.is_empty());
        assert_eq!(end, Ok(End::NoTrailer));
    }

    #[test]
    fn damage_is_found_and_named() {
        let good = sample();
        // Every way of cutting the archive short.
        let (records, _) = scan(&good);
        let f = &records[2];
        for (cut, part) in [
            (f.offset + 1, Part::Header),
            (f.offset + 109, Part::Header),
            (f.offset + 110, Part::Name),
            (f.offset + 112, Part::Name),
            (f.data_offset, Part::Data),
            (f.data_offset + 4, Part::Data),
        ] {
            let (seen, end) = scan(&good[..cut as usize]);
            assert_eq!(seen.len(), 2, "cut at {}", cut);
            assert_eq!(end, Err(Damage::Truncated { offset: f.offset, part }), "cut at {}", cut);
        }
        // Cut behind the data, before its padding: the entry is whole.
        let (seen, end) = scan(&good[..(f.data_offset + 5) as usize]);
        assert_eq!(seen.len(), 3);
        assert_eq!(end, Ok(End::NoTrailer));
        // Something that is no digit.
        let mut bad = good.clone();
        bad[f.offset as usize + Field::Filesize.offset() + 3] = b'x';
        assert_eq!(
            scan(&bad).1,
            Err(Damage::Field {
                offset: f.offset,
                field: Field::Filesize
            })
        );
        assert_eq!(scan(&bad).1.unwrap_err().into_error().errno(), EUCLEAN);
        // No magic.
        let mut bad = good.clone();
        bad[f.offset as usize + 5] = b'7';
        assert_eq!(
            scan(&bad).1,
            Err(Damage::Magic {
                offset: f.offset,
                found: Some(Foreign::CpioOdc)
            })
        );
        // A name that does not end.
        let mut bad = good.clone();
        bad[f.offset as usize + 110 + 3] = b'!';
        assert_eq!(scan(&bad).1, Err(Damage::Unterminated { offset: f.offset }));
        // Sizes that point beyond the end, as large as they get.
        let mut bad = good.clone();
        bad[f.offset as usize + 6 + 8 * 6..][..8].copy_from_slice(b"ffffffff");
        assert_eq!(
            scan(&bad).1,
            Err(Damage::Truncated {
                offset: f.offset,
                part: Part::Data
            })
        );
        let mut bad = good.clone();
        bad[f.offset as usize + 6 + 8 * 11..][..8].copy_from_slice(b"ffffffff");
        assert_eq!(
            scan(&bad).1,
            Err(Damage::Truncated {
                offset: f.offset,
                part: Part::Name
            })
        );
    }

    /// An archive that is stopped is one that is damaged where the stopper
    /// is, at its start as anywhere else, and not an image without one.
    #[test]
    fn a_stopped_archive_is_called_unfinished() {
        use crate::header::STOPPER;
        let good = files_of(2, 10);
        let second = scan(&good).0[1].offset as usize;
        for format in [Format::Newc, Format::Crc] {
            for at in [0, second] {
                let mut stopped = good.clone();
                stopped[at..at + MAGIC_LEN].copy_from_slice(&format.stopped_magic());
                assert_eq!(stopped[at], STOPPER);
                let (records, end) = scan(&stopped);
                assert_eq!(records.len(), usize::from(at != 0));
                let damage = end.unwrap_err();
                assert_eq!(
                    damage,
                    Damage::Magic {
                        offset: at as u64,
                        found: Some(Foreign::Unfinished)
                    }
                );
                let error = damage.into_error();
                assert_eq!(error.errno(), EUCLEAN);
                assert!(matches!(
                    error.detail(),
                    Some(Detail::Corrupt {
                        field: Some("c_magic"),
                        ..
                    })
                ));
                assert!(error.message().contains("not finished"), "{}", error.message());
            }
        }
        // A stopped magic and nothing behind it, as little as there can
        // be.
        let short = Format::Newc.stopped_magic();
        assert_eq!(
            scan(&short).1,
            Err(Damage::Magic {
                offset: 0,
                found: Some(Foreign::Unfinished)
            })
        );
        // Behind a trailer it is nothing the kernel takes, like anything
        // else that is no archive.
        let mut followed = good.clone();
        followed.extend_from_slice(&Format::Newc.stopped_magic());
        let end = match scan(&good).1.unwrap() {
            End::Trailer(end) => end,
            End::NoTrailer => panic!("no trailer"),
        };
        let at = followed.first_nonzero(end).unwrap().unwrap();
        assert_eq!(followed.follower(at).unwrap(), Follower::Unknown);
    }

    #[test]
    fn what_is_no_archive_is_told_apart() {
        let detail = |bytes: &[u8]| match scan(bytes).1.unwrap_err().into_error().detail() {
            Some(Detail::NotCpio { reason, found }) => (*reason, *found),
            other => panic!("{:?}", other),
        };
        assert_eq!(
            detail(b"\x1f\x8b\x08\x00 some gzip"),
            (NotCpioReason::OtherFormat, Some("gzip"))
        );
        assert_eq!(
            detail(&[0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]),
            (NotCpioReason::OtherFormat, Some("zstd"))
        );
        let mut odc = vec![b'0'; 200];
        odc[..6].copy_from_slice(b"070707");
        assert_eq!(detail(&odc), (NotCpioReason::OtherFormat, Some("cpio-odc")));
        assert_eq!(detail(&[b'x'; 200]), (NotCpioReason::Unknown, None));
        assert_eq!(detail(b"x"), (NotCpioReason::Unknown, None));
        // The stopper alone says nothing: only with the rest of a magic
        // behind it is it the start of an archive that was not finished.
        assert_eq!(detail(&[crate::header::STOPPER; 200]), (NotCpioReason::Unknown, None));
        assert_eq!(detail(b"X"), (NotCpioReason::Unknown, None));
        // A few bytes of a header are an archive cut short.
        assert_eq!(
            scan(b"0707").1,
            Err(Damage::Truncated {
                offset: 0,
                part: Part::Header
            })
        );
        assert_eq!(blank().errno(), ENODATA);
    }

    #[test]
    fn checksums_are_summed_over_the_data() {
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let expected = data.iter().fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
        assert_eq!(data.checksum(0, data.len() as u64).unwrap(), expected);
        assert_eq!(data.checksum(10, 0).unwrap(), 0);
        assert_eq!(data.checksum(1, 3).unwrap(), 1 + 2 + 3);
    }

    /// A source that counts what is read from it and fails the reads it
    /// is told to fail.
    struct Counting<'a> {
        bytes: &'a [u8],
        reads: std::cell::Cell<u64>,
        read: std::cell::Cell<u64>,
        failing: std::cell::Cell<u32>,
    }

    impl<'a> Counting<'a> {
        fn new(bytes: &'a [u8]) -> Counting<'a> {
            Counting {
                bytes,
                reads: std::cell::Cell::new(0),
                read: std::cell::Cell::new(0),
                failing: std::cell::Cell::new(0),
            }
        }
    }

    impl Source for Counting<'_> {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }

        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            if self.failing.get() > 0 {
                self.failing.set(self.failing.get() - 1);
                // What a reader that failed half way leaves behind.
                buf.fill(b'0');
                bail!(EIO, "the read failed");
            }
            self.reads.set(self.reads.get() + 1);
            self.read.set(self.read.get() + buf.len() as u64);
            Source::read_at(self.bytes, offset, buf)
        }
    }

    /// An archive of `files` files of `size` bytes each, with names of the
    /// same length.
    fn files_of(files: usize, size: usize) -> Vec<u8> {
        let mut w = Writer::new(Vec::new(), Options::default()).unwrap();
        let data = vec![7u8; size];
        for i in 0..files {
            let name = format!("f{:06}", i);
            w.file(named(name.as_bytes()), &ATTRIBUTES, None, size as u64, &mut &data[..])
                .unwrap();
        }
        w.finish().unwrap().0
    }

    /// How many entries a scan of `source` sees before the trailer.
    fn count(source: &Counting<'_>) -> usize {
        let mut seen = 0;
        for entry in Scanner::new(source) {
            if entry.unwrap().unwrap().standing != Standing::Trailer {
                seen += 1;
            }
        }
        seen
    }

    /// The header and the name of an entry of [`files_of`], which is what
    /// a window that ends inside an entry is read of again.
    const ENTRY: u64 = 120;

    /// A scan reads what it needs, not the data it passes over.
    #[test]
    fn large_files_are_stepped_over() {
        let archive = files_of(3, 4 << 20);
        let source = Counting::new(&archive);
        assert_eq!(count(&source), 3);
        // The three files and the trailer, a full window for the first.
        assert_eq!(source.reads.get(), 4);
        assert!(
            source.read.get() <= (WINDOW + 3 * SHORT_WINDOW) as u64,
            "read {} bytes",
            source.read.get()
        );
    }

    /// Entries that follow each other closely are read a window at a
    /// time, not one by one.
    #[test]
    fn small_entries_are_read_a_window_at_a_time() {
        let archive = files_of(10_000, 3);
        let source = Counting::new(&archive);
        assert_eq!(count(&source), 10_000);
        let windows = archive.len().div_ceil(WINDOW - ENTRY as usize) as u64;
        assert!(source.reads.get() <= windows, "{} reads", source.reads.get());
        assert!(
            source.read.get() <= archive.len() as u64 + source.reads.get() * ENTRY,
            "read {} bytes of {}",
            source.read.get(),
            archive.len()
        );
    }

    /// Whatever the size of the files is, no entry takes more than one
    /// read and nothing but the start of an entry that a window ends in
    /// is read twice. Files that are close to each other are read a full
    /// window at a time, and behind files that are far from each other
    /// only short windows are read.
    #[test]
    fn a_scan_reads_no_more_than_the_archive() {
        let far = FAR as usize;
        for size in [
            0,
            1,
            1000,
            4000,
            4100,
            6000,
            10_000,
            far - 200,
            far,
            40_000,
            WINDOW - 200,
            WINDOW,
            WINDOW + 4000,
            200_000,
        ] {
            let files = 150;
            let archive = files_of(files, size);
            let source = Counting::new(&archive);
            assert_eq!(count(&source), files, "size {}", size);
            let (reads, read) = (source.reads.get(), source.read.get());
            assert!(reads <= files as u64 + 1, "size {}: {} reads", size, reads);
            assert!(
                read <= archive.len() as u64 + reads * ENTRY,
                "size {}: read {} bytes of {}",
                size,
                read,
                archive.len()
            );
            if ENTRY + size as u64 >= FAR {
                assert!(
                    read <= (WINDOW + files * SHORT_WINDOW) as u64,
                    "size {}: read {} bytes",
                    size,
                    read
                );
            } else {
                let windows = archive.len().div_ceil(WINDOW - ENTRY as usize) as u64;
                assert!(reads <= windows, "size {}: {} reads", size, reads);
            }
        }
    }

    /// Zero bytes between entries are passed over a window at a time,
    /// behind a small file and behind the data of a large one.
    #[test]
    fn a_long_run_of_zero_bytes_is_read_once() {
        for size in [3, 3 * WINDOW] {
            let mut archive = raw(b"070701", 0o100644, 1, b"first\0", &vec![1u8; size]);
            archive.extend_from_slice(&vec![0u8; 20 * WINDOW]);
            archive.extend_from_slice(&raw(b"070701", 0o100644, 1, b"second\0", b"abc"));
            archive.extend_from_slice(&trailer());
            let source = Counting::new(&archive);
            assert_eq!(count(&source), 2);
            // One read for the first entry, at most a short one behind
            // its data and full windows from there on.
            assert!(source.reads.get() <= 23, "size {}: {} reads", size, source.reads.get());
            assert!(
                source.read.get() <= archive.len() as u64 + ENTRY,
                "size {}: read {} bytes of {}",
                size,
                source.read.get(),
                archive.len()
            );
        }
    }

    /// A read that failed leaves nothing in the window that a later call
    /// could take for the archive.
    #[test]
    fn a_failed_read_leaves_nothing_behind() {
        let archive = files_of(2, 10);
        let source = Counting::new(&archive);
        source.failing.set(1);
        let mut scanner = Scanner::new(&source);
        assert_eq!(scanner.next().unwrap().map(|_| ()).unwrap_err().errno(), EIO);
        let first = scanner.next().unwrap().unwrap().unwrap();
        assert_eq!(first.name, b"f000000");
        assert_eq!(first.offset, 0);
    }
}
