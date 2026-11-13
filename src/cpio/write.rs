// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing an archive: one entry after the other, then the trailer.
//!
//! The writer puts out what the kernel unpacks without dropping anything,
//! and nothing that depends on where or when it runs:
//!
//! - Names are in the one form of a [`Name`].
//! - Inode numbers count up from one in the order of the entries. The
//!   kernel only looks at them to tell the names of a hard-linked file, but
//!   other readers take two entries with the same number for one file.
//! - The device numbers of the file system the files came from are zero.
//! - A file with several names is stored once: the data comes with the
//!   last of its names and the names before it carry none. That is where
//!   cpio(1) puts it. The kernel takes the data with any of the names.
//! - What the format cannot hold is refused: a file of more than
//!   [`MAX_FILE_SIZE`] bytes, a name the kernel would drop, a device number
//!   it would truncate.
//!
//! The kernel creates nothing but what an entry names. A directory has to
//! come before what is in it, which is for the caller to see to.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errno::*;
use crate::header::{
    padding, DeviceNumber, Field, Format, Header, Kind, ALIGNMENT, MAX_FILE_SIZE, MAX_MAJOR, MAX_MINOR, MAX_MTIME,
    MAX_TARGET_LEN, PERMISSIONS, TRAILER, TRAILER_LEN,
};
use crate::name::Name;
use crate::{Detail, Result};

/// The end of an archive is padded to a multiple of this by default, the
/// block size cpio(1) writes in.
pub const DEFAULT_END_ALIGNMENT: u32 = 512;
/// The smallest alignment the end of an archive can have, the one every
/// entry has.
pub const MIN_END_ALIGNMENT: u32 = ALIGNMENT as u32;
/// The largest alignment that can be asked for.
pub const MAX_ALIGNMENT: u32 = 1 << 30;
/// Size of the buffer file contents are copied through.
const COPY_BUFFER: usize = 1024 * 1024;
/// How many names a directory counts: its own and the one it has inside
/// itself.
const DIRECTORY_LINKS: u32 = 2;
/// NUL bytes for the padding.
const ZEROS: [u8; 4096] = [0; 4096];

/// Where an archive goes.
pub trait Sink {
    /// Appends `buf`.
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;
    /// Overwrites bytes that were appended before. `offset` counts from the
    /// first byte appended. The writer does this to a header whose
    /// checksum it knows only after the data went out.
    fn patch(&mut self, offset: u64, buf: &[u8]) -> Result<()>;
}

impl Sink for Vec<u8> {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.extend_from_slice(buf);
        Ok(())
    }

    fn patch(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let range = usize::try_from(offset)
            .ok()
            .and_then(|start| Some(start..start.checked_add(buf.len())?))
            .filter(|range| range.end <= self.len());
        match range {
            Some(range) => {
                self[range].copy_from_slice(buf);
                Ok(())
            }
            None => bail!(EINVAL, "a patch at offset {} is outside of what was written", offset),
        }
    }
}

impl<S: Sink + ?Sized> Sink for &mut S {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        (**self).write_all(buf)
    }

    fn patch(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        (**self).patch(offset, buf)
    }
}

/// How an archive is laid out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The form of the headers. [`Format::Crc`] stores a checksum with
    /// every regular file. Kernels before 5.19 do not take it.
    pub format: Format,
    /// The archive ends at a multiple of this many bytes, padded with NUL
    /// bytes behind the trailer. A multiple of four and not zero.
    pub end_alignment: u32,
    /// The contents of a regular file of at least this many bytes begin at
    /// a multiple of it, by NUL bytes added to the file's name. Zero for no
    /// alignment, a multiple of four otherwise. A name that would get
    /// longer than the format allows that way is left as it is.
    pub data_alignment: u32,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            format: Format::Newc,
            end_alignment: DEFAULT_END_ALIGNMENT,
            data_alignment: 0,
        }
    }
}

impl Options {
    /// Refuses alignments an archive cannot have.
    pub fn check(&self) -> Result<()> {
        let aligned = |alignment: u32| u64::from(alignment) % ALIGNMENT == 0 && alignment <= MAX_ALIGNMENT;
        if self.end_alignment == 0 || !aligned(self.end_alignment) {
            bail!(
                EINVAL,
                Detail::InvalidOption("endAlignment"),
                "the alignment {} of the end of the archive is not a multiple of four up to {}",
                self.end_alignment,
                MAX_ALIGNMENT
            );
        }
        if !aligned(self.data_alignment) {
            bail!(
                EINVAL,
                Detail::InvalidOption("dataAlignment"),
                "the alignment {} of file contents is not a multiple of four up to {}",
                self.data_alignment,
                MAX_ALIGNMENT
            );
        }
        Ok(())
    }

    /// The `namesize` of an entry that starts at `offset`: the name and
    /// its NUL, and for a regular file large enough the NUL bytes that
    /// move its contents to the alignment asked for, where they fit.
    fn namesize(&self, offset: u64, name_len: usize, kind: Kind, filesize: u32) -> u32 {
        let alignment = self.data_alignment;
        let aligned = if kind == Kind::Regular && alignment != 0 && filesize >= alignment {
            Header::aligned_namesize(offset, name_len, alignment)
        } else {
            None
        };
        aligned.unwrap_or(name_len as u32 + 1)
    }

    /// The length of an archive that holds nothing but the trailer.
    pub fn empty_len(&self) -> u64 {
        Cursor::new(*self, 0).finish()
    }
}

/// What an entry says about itself beside its name and its kind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Attributes {
    /// The permissions: the access modes and the set-user-ID, set-group-ID
    /// and sticky bits.
    pub mode: u32,
    /// The owning user.
    pub uid: u32,
    /// The owning group.
    pub gid: u32,
    /// The modification time in seconds since the epoch.
    pub mtime: u32,
}

impl Attributes {
    /// The permissions of a directory that nothing says the permissions
    /// of.
    pub const DIRECTORY_MODE: u32 = 0o755;
    /// The permissions of anything else that nothing says the permissions
    /// of.
    pub const FILE_MODE: u32 = 0o644;
    /// The same for what is said to be read-only.
    pub const READ_ONLY_MODE: u32 = 0o444;
    /// The permissions a symbolic link has on Linux. The kernel ignores
    /// what an archive says they are.
    pub const SYMLINK_MODE: u32 = 0o777;

    /// `time` as an archive stores one: whole seconds since the epoch in
    /// 32 bits. A time before the epoch becomes the epoch and one after
    /// [`MAX_MTIME`] becomes that.
    pub fn seconds(time: SystemTime) -> u32 {
        match time.duration_since(UNIX_EPOCH) {
            Ok(since) => u32::try_from(since.as_secs()).unwrap_or(MAX_MTIME),
            Err(_) => 0,
        }
    }
}

/// A file with more than one name, from [`Writer::links`]: every name is
/// written with it, so that a reader knows them for one file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Links {
    ino: u32,
    nlink: u32,
}

impl Links {
    /// The inode number the names share.
    pub fn ino(&self) -> u32 {
        self.ino
    }

    /// How many names the file has.
    pub fn count(&self) -> u32 {
        self.nlink
    }
}

impl Name<'_> {
    /// Refuses a target a symbolic link of this name cannot have in an
    /// archive: an empty one, one longer than [`MAX_TARGET_LEN`] and one
    /// with a NUL byte, at which the kernel would cut it off.
    pub fn check_target(self, target: &[u8]) -> Result<()> {
        if target.is_empty() || target.len() > MAX_TARGET_LEN || target.contains(&0) {
            bail!(
                EINVAL,
                "the target of the symbolic link '{}' is empty, longer than {} bytes or contains a NUL byte",
                self,
                MAX_TARGET_LEN
            );
        }
        Ok(())
    }

    /// Refuses what cannot be a node of this name: what is no device
    /// node, FIFO or socket, a device number the kernel would truncate,
    /// and a device number on what is no device.
    pub fn check_node(self, kind: Kind, rdev: DeviceNumber) -> Result<()> {
        match kind {
            Kind::CharDevice | Kind::BlockDevice => {
                if !rdev.fits() {
                    bail!(
                        EOVERFLOW,
                        "the device number {} of '{}' is beyond {}, the largest the kernel takes from an archive",
                        rdev,
                        self,
                        DeviceNumber::new(MAX_MAJOR, MAX_MINOR)
                    );
                }
            }
            Kind::Fifo | Kind::Socket => {
                if rdev != DeviceNumber::NONE {
                    bail!(EINVAL, "'{}' is no device node and has a device number", self);
                }
            }
            Kind::Regular | Kind::Directory | Kind::Symlink => {
                bail!(EINVAL, "'{}' is no device node, FIFO or socket", self)
            }
        }
        Ok(())
    }
}

/// Writes an archive to a [`Sink`].
#[derive(Debug)]
pub struct Writer<S: Sink> {
    sink: S,
    options: Options,
    /// Where in the archive the next byte goes.
    offset: u64,
    /// How many bytes went to the sink.
    written: u64,
    next_ino: u32,
    /// The regular file whose contents are being written.
    open: Option<Open>,
    buffer: Vec<u8>,
}

/// A regular file between [`Writer::file_begin`] and [`Writer::file_end`].
#[derive(Debug)]
struct Open {
    /// Where its header went, counted in bytes handed to the sink.
    at: u64,
    /// How many bytes of contents are still to come.
    left: u64,
    /// The sum of the bytes so far.
    sum: u32,
}

/// Where the entries of an archive go, worked out without writing one:
/// how long an archive gets, and where each entry starts.
#[derive(Clone, Copy, Debug)]
pub struct Cursor {
    options: Options,
    offset: u64,
}

impl Cursor {
    /// Starts at `offset` in an archive laid out with `options`.
    pub fn new(options: Options, offset: u64) -> Cursor {
        Cursor { options, offset }
    }

    /// Where the next entry starts.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Passes over an entry of `kind` with a name of `name_len` bytes and
    /// `filesize` bytes of data, the length of the contents of a regular
    /// file or of the target of a symbolic link.
    pub fn place(&mut self, name_len: usize, kind: Kind, filesize: u32) {
        let header = Header {
            namesize: self.options.namesize(self.offset, name_len, kind, filesize),
            filesize,
            ..Header::default()
        };
        self.offset += header.entry_len();
    }

    /// The length of the archive once the trailer is behind the entries
    /// and the end is padded.
    pub fn finish(self) -> u64 {
        let end = self.offset + TRAILER_LEN;
        end.div_ceil(u64::from(self.options.end_alignment)) * u64::from(self.options.end_alignment)
    }
}

impl<S: Sink> Writer<S> {
    /// Starts an archive.
    pub fn new(sink: S, options: Options) -> Result<Writer<S>> {
        Writer::resume(sink, options, 0, 1)
    }

    /// Goes on with an archive at `offset`, where its trailer was: the
    /// entries written follow the ones that are there, and the inode
    /// numbers go on from `next_ino`, which has to be above every number
    /// the archive uses.
    pub fn resume(sink: S, options: Options, offset: u64, next_ino: u32) -> Result<Writer<S>> {
        options.check()?;
        if offset % ALIGNMENT != 0 {
            bail!(EINVAL, "an entry cannot start at offset {}", offset);
        }
        Ok(Writer {
            sink,
            options,
            offset,
            written: 0,
            next_ino,
            open: None,
            buffer: Vec::new(),
        })
    }

    /// Where in the archive the next entry starts.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The inode number the next entry gets.
    pub fn next_ino(&self) -> u32 {
        self.next_ino
    }

    fn put(&mut self, buf: &[u8]) -> Result<()> {
        self.sink.write_all(buf)?;
        self.offset += buf.len() as u64;
        self.written += buf.len() as u64;
        Ok(())
    }

    fn put_zeros(&mut self, mut count: u64) -> Result<()> {
        while count > 0 {
            let n = count.min(ZEROS.len() as u64) as usize;
            self.put(&ZEROS[..n])?;
            count -= n as u64;
        }
        Ok(())
    }

    /// A number for an inode of its own. The format has 32 bits for it.
    fn take_ino(&mut self) -> Result<u32> {
        let ino = self.next_ino;
        match ino.checked_add(1) {
            Some(next) if ino != 0 => self.next_ino = next,
            _ => bail!(EOVERFLOW, "the archive has more entries than the format can number"),
        }
        Ok(ino)
    }

    /// Writes header and name of an entry, which is one name of the file
    /// `links` stands for or gets a number of its own. Returns where the
    /// header went, counted in bytes handed to the sink.
    fn entry(
        &mut self,
        name: Name<'_>,
        kind: Kind,
        attributes: &Attributes,
        links: Option<&Links>,
        rdev: DeviceNumber,
        filesize: u32,
    ) -> Result<u64> {
        if attributes.mode & !PERMISSIONS != 0 {
            bail!(
                EINVAL,
                "the mode {:o} of '{}' has bits that are not permissions",
                attributes.mode,
                name
            );
        }
        if self.open.is_some() {
            bail!(EINVAL, "'{}' cannot start, the file before it is not complete", name);
        }
        // A directory counts its own name and the one it has inside itself.
        let (ino, nlink) = match links {
            Some(links) => (links.ino, links.nlink),
            None => (
                self.take_ino()?,
                if kind == Kind::Directory { DIRECTORY_LINKS } else { 1 },
            ),
        };
        let name = name.as_bytes();
        let namesize = self.options.namesize(self.offset, name.len(), kind, filesize);
        let header = Header {
            ino,
            mode: kind.bits() | attributes.mode,
            uid: attributes.uid,
            gid: attributes.gid,
            nlink,
            mtime: attributes.mtime,
            filesize,
            devmajor: 0,
            devminor: 0,
            rdevmajor: rdev.major,
            rdevminor: rdev.minor,
            namesize,
            check: 0,
        };
        let at = self.written;
        self.put(&header.encode(self.options.format))?;
        self.put(name)?;
        self.put_zeros(u64::from(namesize) - name.len() as u64)?;
        self.put_zeros(padding(self.offset))?;
        Ok(at)
    }

    /// Declares a file with `names` names, at least two. Every one of them
    /// is then written with what this returns: all but the last with
    /// [`Writer::file_link`], the last with [`Writer::file`], or all of them
    /// with [`Writer::node`].
    pub fn links(&mut self, names: u32) -> Result<Links> {
        if names <= 1 {
            bail!(EINVAL, "a file with {} names is not hard-linked", names);
        }
        Ok(Links {
            ino: self.take_ino()?,
            nlink: names,
        })
    }

    /// Writes a directory. The kernel sets its time once everything in the
    /// archive is unpacked.
    pub fn directory(&mut self, name: Name<'_>, attributes: &Attributes) -> Result<()> {
        self.entry(name, Kind::Directory, attributes, None, DeviceNumber::NONE, 0)?;
        Ok(())
    }

    /// Writes a symbolic link to `target`. The kernel ignores the mode.
    pub fn symlink(&mut self, name: Name<'_>, attributes: &Attributes, target: &[u8]) -> Result<()> {
        name.check_target(target)?;
        self.entry(
            name,
            Kind::Symlink,
            attributes,
            None,
            DeviceNumber::NONE,
            target.len() as u32,
        )?;
        self.put(target)?;
        self.put_zeros(padding(self.offset))
    }

    /// Writes a device node, a FIFO or a socket. `rdev` is the major and
    /// minor number of a device node and zero for the others. With `links`
    /// the entry is one name of a node that has several.
    pub fn node(
        &mut self,
        name: Name<'_>,
        kind: Kind,
        attributes: &Attributes,
        rdev: DeviceNumber,
        links: Option<&Links>,
    ) -> Result<()> {
        name.check_node(kind, rdev)?;
        self.entry(name, kind, attributes, links, rdev, 0)?;
        Ok(())
    }

    /// Writes a name of a hard-linked regular file that is not its last
    /// one. It carries no data.
    pub fn file_link(&mut self, name: Name<'_>, attributes: &Attributes, links: &Links) -> Result<()> {
        self.entry(name, Kind::Regular, attributes, Some(links), DeviceNumber::NONE, 0)?;
        Ok(())
    }

    /// Starts a regular file of `size` bytes: its header and its name. All
    /// of its contents follow through [`Writer::file_data`], and
    /// [`Writer::file_end`] ends the entry. With `links` this is the last
    /// name of a file that has several.
    pub fn file_begin(
        &mut self,
        name: Name<'_>,
        attributes: &Attributes,
        links: Option<&Links>,
        size: u64,
    ) -> Result<()> {
        if size > MAX_FILE_SIZE {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: Some(name.to_string()),
                    size,
                    maximum: MAX_FILE_SIZE,
                },
                "'{}' has {} bytes, more than the {} a cpio archive can hold",
                name,
                size,
                MAX_FILE_SIZE
            );
        }
        if self.open.is_some() {
            bail!(EINVAL, "'{}' cannot start, the file before it is not complete", name);
        }
        let at = self.entry(name, Kind::Regular, attributes, links, DeviceNumber::NONE, size as u32)?;
        self.open = Some(Open { at, left: size, sum: 0 });
        Ok(())
    }

    /// Writes the next bytes of the contents of the file that was started.
    /// More bytes than the file was started with are refused.
    pub fn file_data(&mut self, buf: &[u8]) -> Result<()> {
        let checksum = self.options.format == Format::Crc;
        let Some(open) = &mut self.open else {
            bail!(EINVAL, "there is no file to write contents to");
        };
        if buf.len() as u64 > open.left {
            bail!(
                EFBIG,
                "{} bytes of contents are more than the {} the file has left",
                buf.len(),
                open.left
            );
        }
        open.left -= buf.len() as u64;
        if checksum {
            open.sum = buf.iter().fold(open.sum, |sum, &b| sum.wrapping_add(u32::from(b)));
        }
        self.put(buf)
    }

    /// Ends the file that was started. Contents that fall short of its
    /// size are an error: the header says how many bytes follow, and it is
    /// written.
    pub fn file_end(&mut self) -> Result<()> {
        let Some(open) = self.open.take() else {
            bail!(EINVAL, "there is no file to end");
        };
        if open.left != 0 {
            bail!(EIO, "the contents of the file are {} bytes short", open.left);
        }
        self.put_zeros(padding(self.offset))?;
        if self.options.format == Format::Crc && open.sum != 0 {
            self.sink
                .patch(open.at + Field::Check.offset() as u64, &Field::encode(open.sum))?;
        }
        Ok(())
    }

    /// Writes a regular file of `size` bytes, read from `data`. With
    /// `links` this is the last name of a file that has several. A source
    /// that ends before `size` bytes is an error, and what it holds beyond
    /// them is left unread.
    pub fn file(
        &mut self,
        name: Name<'_>,
        attributes: &Attributes,
        links: Option<&Links>,
        size: u64,
        data: &mut dyn Read,
    ) -> Result<()> {
        self.file_begin(name, attributes, links, size)?;
        let mut buffer = std::mem::take(&mut self.buffer);
        if buffer.len() != COPY_BUFFER {
            buffer = vec![0u8; COPY_BUFFER];
        }
        let mut left = size;
        let result = loop {
            if left == 0 {
                break Ok(());
            }
            let want = left.min(COPY_BUFFER as u64) as usize;
            let n = match crate::host::read_some(data, &mut buffer[..want]) {
                Ok(n) => n,
                Err(e) => break Err(crate::Error::from(e).context(format!("reading '{}'", name))),
            };
            if n == 0 {
                break Err(err!(EIO, "'{}' ended after {} of {} bytes", name, size - left, size));
            }
            if let Err(e) = self.file_data(&buffer[..n]) {
                break Err(e);
            }
            left -= n as u64;
        };
        self.buffer = buffer;
        result?;
        self.file_end()
    }

    /// Ends the archive: the trailer, then NUL bytes up to the alignment
    /// of the end. Returns the sink and the length of the archive.
    pub fn finish(mut self) -> Result<(S, u64)> {
        if self.open.is_some() {
            bail!(EINVAL, "the archive cannot end, its last file is not complete");
        }
        self.put(&Header::trailer().encode(self.options.format))?;
        self.put(TRAILER)?;
        self.put_zeros(1)?;
        self.put_zeros(padding(self.offset))?;
        let alignment = u64::from(self.options.end_alignment);
        self.put_zeros((alignment - self.offset % alignment) % alignment)?;
        Ok((self.sink, self.offset))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::HEADER_LEN;
    use crate::test_util::named;
    use crate::NameProblem;

    const ATTRIBUTES: Attributes = Attributes {
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0x5e0d_5ee5,
    };

    /// An entry of an archive, as far as the tests look at one.
    #[derive(Debug, PartialEq, Eq)]
    struct Seen {
        offset: usize,
        format: Format,
        header: Header,
        name: Vec<u8>,
        data_offset: usize,
        data: Vec<u8>,
    }

    /// Walks an archive the way the kernel does.
    fn entries(archive: &[u8]) -> Vec<Seen> {
        let mut seen = Vec::new();
        let mut offset = 0;
        loop {
            let raw: &[u8; HEADER_LEN] = archive[offset..offset + HEADER_LEN].try_into().unwrap();
            let (format, header) = Header::decode(raw).unwrap();
            let name_at = offset + HEADER_LEN;
            let stored = &archive[name_at..name_at + header.namesize as usize];
            assert_eq!(stored.last(), Some(&0), "the name is terminated");
            let name = stored.split(|&b| b == 0).next().unwrap().to_vec();
            assert!(stored[name.len()..].iter().all(|&b| b == 0));
            let data_offset = name_at + header.name_field_len() as usize;
            assert!(archive[name_at + header.namesize as usize..data_offset]
                .iter()
                .all(|&b| b == 0));
            let data = archive[data_offset..data_offset + header.filesize as usize].to_vec();
            let next = data_offset + header.data_field_len() as usize;
            assert!(archive[data_offset + data.len()..next].iter().all(|&b| b == 0));
            let trailer = name == TRAILER;
            seen.push(Seen {
                offset,
                format,
                header,
                name,
                data_offset,
                data,
            });
            offset = next;
            if trailer {
                assert!(
                    archive[offset..].iter().all(|&b| b == 0),
                    "only NUL bytes follow the trailer"
                );
                return seen;
            }
        }
    }

    fn writer(options: Options) -> Writer<Vec<u8>> {
        Writer::new(Vec::new(), options).unwrap()
    }

    /// An entry as it is stored, put together without the code under
    /// test: the magic, thirteen numbers of eight digits, the name padded
    /// to four from the start of the header, the data padded to four.
    fn stored(fields: [u32; 13], name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut raw = b"070701".to_vec();
        for field in fields {
            raw.extend_from_slice(format!("{:08x}", field).as_bytes());
        }
        raw.extend_from_slice(name);
        while raw.len() % 4 != 0 {
            raw.push(0);
        }
        raw.extend_from_slice(data);
        while raw.len() % 4 != 0 {
            raw.push(0);
        }
        raw
    }

    #[test]
    fn an_archive_without_entries_is_a_trailer() {
        let (archive, len) = writer(Options::default()).finish().unwrap();
        assert_eq!(len, 512);
        assert_eq!(archive.len(), 512);
        assert_eq!(Options::default().empty_len(), 512);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"070701");
        for field in [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0] {
            expected.extend_from_slice(format!("{:08x}", field).as_bytes());
        }
        expected.extend_from_slice(b"TRAILER!!!\0\0\0\0");
        assert_eq!(expected.len() as u64, TRAILER_LEN);
        assert_eq!(&archive[..124], &expected[..]);
        assert!(archive[124..].iter().all(|&b| b == 0));
        for (alignment, len) in [(4, 124), (8, 128), (512, 512), (4096, 4096)] {
            let options = Options {
                end_alignment: alignment,
                ..Options::default()
            };
            assert_eq!(writer(options).finish().unwrap().1, len);
            assert_eq!(options.empty_len(), len);
        }
    }

    /// One entry of every kind, as bytes: this is the format.
    #[test]
    fn entries_are_laid_out_as_the_kernel_reads_them() {
        let mut w = writer(Options {
            end_alignment: 4,
            ..Options::default()
        });
        let root = Attributes {
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 1,
        };
        w.directory(named(b"."), &root).unwrap();
        w.directory(named(b"dev"), &root).unwrap();
        let console = Attributes {
            mode: 0o600,
            uid: 0,
            gid: 5,
            mtime: 2,
        };
        w.node(
            named(b"dev/console"),
            Kind::CharDevice,
            &console,
            DeviceNumber::new(5, 1),
            None,
        )
        .unwrap();
        w.file(
            named(b"init"),
            &Attributes {
                mode: 0o4755,
                uid: 1000,
                gid: 100,
                mtime: 3,
            },
            None,
            5,
            &mut &b"hello"[..],
        )
        .unwrap();
        w.symlink(
            named(b"sh"),
            &Attributes {
                mode: 0o777,
                uid: 0,
                gid: 0,
                mtime: 4,
            },
            b"init",
        )
        .unwrap();
        w.node(named(b"fifo"), Kind::Fifo, &ATTRIBUTES, DeviceNumber::NONE, None)
            .unwrap();
        w.node(named(b"sock"), Kind::Socket, &ATTRIBUTES, DeviceNumber::NONE, None)
            .unwrap();
        w.node(
            named(b"sda"),
            Kind::BlockDevice,
            &ATTRIBUTES,
            DeviceNumber::new(MAX_MAJOR, MAX_MINOR),
            None,
        )
        .unwrap();
        let (archive, len) = w.finish().unwrap();
        assert_eq!(archive.len() as u64, len);
        // The fields in the order of the header: ino, mode, uid, gid, nlink,
        // mtime, filesize, the device numbers twice, namesize, checksum.
        let expected = [
            stored([1, 0o040755, 0, 0, 2, 1, 0, 0, 0, 0, 0, 2, 0], b".\0", b""),
            stored([2, 0o040755, 0, 0, 2, 1, 0, 0, 0, 0, 0, 4, 0], b"dev\0", b""),
            stored([3, 0o020600, 0, 5, 1, 2, 0, 0, 0, 5, 1, 12, 0], b"dev/console\0", b""),
            stored([4, 0o104755, 1000, 100, 1, 3, 5, 0, 0, 0, 0, 5, 0], b"init\0", b"hello"),
            stored([5, 0o120777, 0, 0, 1, 4, 4, 0, 0, 0, 0, 3, 0], b"sh\0", b"init"),
            stored([6, 0o010644, 0, 0, 1, 0x5e0d_5ee5, 0, 0, 0, 0, 0, 5, 0], b"fifo\0", b""),
            stored([7, 0o140644, 0, 0, 1, 0x5e0d_5ee5, 0, 0, 0, 0, 0, 5, 0], b"sock\0", b""),
            stored(
                [8, 0o060644, 0, 0, 1, 0x5e0d_5ee5, 0, 0, 0, 0xfff, 0xf_ffff, 4, 0],
                b"sda\0",
                b"",
            ),
            stored([0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0], b"TRAILER!!!\0", b""),
        ]
        .concat();
        assert_eq!(String::from_utf8_lossy(&archive), String::from_utf8_lossy(&expected));
        assert_eq!(archive, expected);
        let names: Vec<Vec<u8>> = entries(&archive).into_iter().map(|e| e.name).collect();
        assert_eq!(names.len(), 9);
    }

    #[test]
    fn a_hard_linked_file_is_stored_once_with_its_last_name() {
        let mut w = writer(Options::default());
        w.directory(named(b"d"), &ATTRIBUTES).unwrap();
        let links = w.links(3).unwrap();
        assert_eq!((links.ino(), links.count()), (2, 3));
        w.file_link(named(b"a"), &ATTRIBUTES, &links).unwrap();
        w.file(named(b"b"), &ATTRIBUTES, None, 1, &mut &b"B"[..]).unwrap();
        w.file_link(named(b"d/c"), &ATTRIBUTES, &links).unwrap();
        w.file(named(b"e"), &ATTRIBUTES, Some(&links), 4, &mut &b"data"[..])
            .unwrap();
        let (archive, _) = w.finish().unwrap();
        let seen = entries(&archive);
        let of = |name: &[u8]| seen.iter().find(|e| e.name == name).unwrap();
        for name in [&b"a"[..], b"d/c", b"e"] {
            assert_eq!((of(name).header.ino, of(name).header.nlink), (2, 3));
        }
        assert_eq!(of(b"a").data, b"");
        assert_eq!(of(b"d/c").data, b"");
        assert_eq!(of(b"e").data, b"data");
        // The numbers go on behind the group's.
        assert_eq!((of(b"d").header.ino, of(b"d").header.nlink), (1, 2));
        assert_eq!((of(b"b").header.ino, of(b"b").header.nlink), (3, 1));
        assert_eq!(writer(Options::default()).links(1).unwrap_err().errno(), EINVAL);
        // Device nodes can be linked as well.
        let mut w = writer(Options::default());
        let links = w.links(2).unwrap();
        w.node(
            named(b"n1"),
            Kind::CharDevice,
            &ATTRIBUTES,
            DeviceNumber::new(1, 3),
            Some(&links),
        )
        .unwrap();
        w.node(
            named(b"n2"),
            Kind::CharDevice,
            &ATTRIBUTES,
            DeviceNumber::new(1, 3),
            Some(&links),
        )
        .unwrap();
        let (archive, _) = w.finish().unwrap();
        let seen = entries(&archive);
        assert_eq!((seen[0].header.ino, seen[0].header.nlink), (1, 2));
        assert_eq!((seen[1].header.ino, seen[1].header.nlink), (1, 2));
    }

    #[test]
    fn the_checksum_form_sums_the_bytes_of_regular_files() {
        let mut w = writer(Options {
            format: Format::Crc,
            ..Options::default()
        });
        w.directory(named(b"d"), &ATTRIBUTES).unwrap();
        w.file(named(b"d/f"), &ATTRIBUTES, None, 4, &mut &b"ASDF"[..]).unwrap();
        w.file(named(b"empty"), &ATTRIBUTES, None, 0, &mut &b""[..]).unwrap();
        w.symlink(named(b"l"), &ATTRIBUTES, b"d/f").unwrap();
        let big = vec![0xffu8; 3 * COPY_BUFFER + 17];
        w.file(named(b"big"), &ATTRIBUTES, None, big.len() as u64, &mut &big[..])
            .unwrap();
        let (archive, _) = w.finish().unwrap();
        let seen = entries(&archive);
        assert!(seen.iter().all(|e| e.format == Format::Crc));
        let check = |name: &[u8]| seen.iter().find(|e| e.name == name).unwrap().header.check;
        assert_eq!(check(b"d"), 0);
        assert_eq!(
            check(b"d/f"),
            u32::from(b'A') + u32::from(b'S') + u32::from(b'D') + u32::from(b'F')
        );
        assert_eq!(check(b"empty"), 0);
        assert_eq!(check(b"l"), 0);
        assert_eq!(check(b"big"), (big.len() as u32).wrapping_mul(0xff));
        assert_eq!(check(TRAILER), 0);
        // The plain form stores none.
        let mut w = writer(Options::default());
        w.file(named(b"f"), &ATTRIBUTES, None, 4, &mut &b"ASDF"[..]).unwrap();
        let (archive, _) = w.finish().unwrap();
        assert_eq!(entries(&archive)[0].header.check, 0);
    }

    #[test]
    fn large_files_are_aligned_by_their_names() {
        let options = Options {
            data_alignment: 4096,
            ..Options::default()
        };
        let mut w = writer(options);
        let large = vec![b'L'; 5000];
        w.file(named(b"small"), &ATTRIBUTES, None, 4095, &mut &large[..])
            .unwrap();
        w.file(named(b"exact"), &ATTRIBUTES, None, 4096, &mut &large[..])
            .unwrap();
        w.file(named(b"large"), &ATTRIBUTES, None, 5000, &mut &large[..])
            .unwrap();
        w.directory(named(b"d"), &ATTRIBUTES).unwrap();
        w.symlink(named(b"l"), &ATTRIBUTES, &large[..4095]).unwrap();
        let (archive, len) = w.finish().unwrap();
        assert_eq!(len % 512, 0);
        let seen = entries(&archive);
        let of = |name: &[u8]| seen.iter().find(|e| e.name == name).unwrap();
        assert_eq!(of(b"small").header.namesize, 6);
        assert_eq!(of(b"exact").data_offset % 4096, 0);
        assert_eq!(of(b"large").data_offset % 4096, 0);
        assert!(of(b"large").header.namesize > 6);
        assert_eq!(of(b"large").data, large);
        // Only regular files move.
        assert_eq!(of(b"l").header.namesize, 2);
        // A name that would not fit is left alone: with the header 116 bytes
        // before a boundary the data starts two bytes behind it, and the
        // name would need 4094 bytes more to reach the next one.
        let mut sink = Vec::new();
        let mut w = Writer::resume(&mut sink, options, 4096 - 116, 1).unwrap();
        w.file(named(b"unlucky"), &ATTRIBUTES, None, 5000, &mut &large[..])
            .unwrap();
        assert_eq!(
            Header::decode(sink[..HEADER_LEN].try_into().unwrap())
                .unwrap()
                .1
                .namesize,
            8
        );
    }

    #[test]
    fn an_archive_is_continued_where_its_trailer_was() {
        let mut first = writer(Options::default());
        first.directory(named(b"d"), &ATTRIBUTES).unwrap();
        let at = first.offset();
        let next = first.next_ino();
        assert_eq!((at, next), (112, 2));
        let (mut archive, _) = first.finish().unwrap();
        archive.truncate(at as usize);
        let mut tail = Vec::new();
        let mut w = Writer::resume(
            &mut tail,
            Options {
                format: Format::Crc,
                ..Options::default()
            },
            at,
            next,
        )
        .unwrap();
        w.file(named(b"d/f"), &ATTRIBUTES, None, 3, &mut &b"abc"[..]).unwrap();
        let (_, len) = w.finish().unwrap();
        archive.extend_from_slice(&tail);
        assert_eq!(archive.len() as u64, len);
        assert_eq!(len, 512);
        let seen = entries(&archive);
        assert_eq!(seen[1].name, b"d/f");
        assert_eq!(seen[1].header.ino, 2);
        // The patch of the checksum counts from where the sink began.
        assert_eq!(seen[1].header.check, 0x61 + 0x62 + 0x63);
        assert_eq!(
            Writer::resume(Vec::new(), Options::default(), 2, 1)
                .unwrap_err()
                .errno(),
            EINVAL
        );
    }

    #[test]
    fn what_the_format_cannot_hold_is_refused() {
        let mut w = writer(Options::default());
        let e = w
            .file(
                named(b"huge"),
                &ATTRIBUTES,
                None,
                MAX_FILE_SIZE + 1,
                &mut std::io::empty(),
            )
            .unwrap_err();
        assert_eq!(e.errno(), EFBIG);
        assert_eq!(
            e.detail(),
            Some(&Detail::TooLarge {
                path: Some("huge".into()),
                size: 1 << 32,
                maximum: MAX_FILE_SIZE,
            })
        );
        // Nothing of a refused entry is written.
        assert_eq!(w.offset(), 0);
        // What is no name does not get as far as the writer.
        for name in [&b""[..], b"/a", b"a/", b"./a", b"a/../b", b"TRAILER!!!", b"a\0"] {
            assert!(
                matches!(Name::new(name).unwrap_err().detail(), Some(Detail::Name { .. })),
                "{:?}",
                name
            );
        }
        assert!(matches!(
            Name::new(b"TRAILER!!!").unwrap_err().detail(),
            Some(Detail::Name {
                problem: NameProblem::Reserved,
                ..
            })
        ));
        for target in [&b""[..], b"a\0b", &[b't'; MAX_TARGET_LEN + 1]] {
            assert_eq!(w.symlink(named(b"l"), &ATTRIBUTES, target).unwrap_err().errno(), EINVAL);
        }
        w.symlink(named(b"l"), &ATTRIBUTES, &[b't'; MAX_TARGET_LEN]).unwrap();
        let at = w.offset();
        for rdev in [DeviceNumber::new(MAX_MAJOR + 1, 0), DeviceNumber::new(0, MAX_MINOR + 1)] {
            assert_eq!(
                w.node(named(b"n"), Kind::CharDevice, &ATTRIBUTES, rdev, None)
                    .unwrap_err()
                    .errno(),
                EOVERFLOW
            );
        }
        assert_eq!(
            w.node(named(b"n"), Kind::Fifo, &ATTRIBUTES, DeviceNumber::new(1, 0), None)
                .unwrap_err()
                .errno(),
            EINVAL
        );
        assert_eq!(
            w.node(named(b"n"), Kind::Regular, &ATTRIBUTES, DeviceNumber::NONE, None)
                .unwrap_err()
                .errno(),
            EINVAL
        );
        let setuid_and_more = Attributes {
            mode: 0o100644,
            ..ATTRIBUTES
        };
        assert_eq!(w.directory(named(b"d"), &setuid_and_more).unwrap_err().errno(), EINVAL);
        // A source that ends early.
        assert_eq!(w.offset(), at);
        assert_eq!(
            w.file(named(b"short"), &ATTRIBUTES, None, 10, &mut &b"12345"[..])
                .unwrap_err()
                .errno(),
            EIO
        );
        for options in [
            Options {
                end_alignment: 0,
                ..Options::default()
            },
            Options {
                end_alignment: 6,
                ..Options::default()
            },
            Options {
                data_alignment: 510,
                ..Options::default()
            },
            Options {
                data_alignment: MAX_ALIGNMENT + 4,
                ..Options::default()
            },
        ] {
            assert!(matches!(
                Writer::new(Vec::new(), options).unwrap_err().detail(),
                Some(Detail::InvalidOption(_))
            ));
        }
    }

    #[test]
    fn inode_numbers_run_out_instead_of_wrapping() {
        let mut w = Writer::resume(Vec::new(), Options::default(), 0, u32::MAX - 1).unwrap();
        w.directory(named(b"a"), &ATTRIBUTES).unwrap();
        assert_eq!(w.directory(named(b"b"), &ATTRIBUTES).unwrap_err().errno(), EOVERFLOW);
        assert_eq!(w.links(2).unwrap_err().errno(), EOVERFLOW);
        let mut w = Writer::resume(Vec::new(), Options::default(), 0, 0).unwrap();
        assert_eq!(w.directory(named(b"a"), &ATTRIBUTES).unwrap_err().errno(), EOVERFLOW);
    }

    #[test]
    fn contents_can_be_pushed() {
        let crc = Options {
            format: Format::Crc,
            ..Options::default()
        };
        let mut w = writer(crc);
        w.file_begin(named(b"f"), &ATTRIBUTES, None, 6).unwrap();
        // Nothing else goes in between.
        assert_eq!(w.directory(named(b"d"), &ATTRIBUTES).unwrap_err().errno(), EINVAL);
        assert_eq!(
            w.file_begin(named(b"g"), &ATTRIBUTES, None, 1).unwrap_err().errno(),
            EINVAL
        );
        w.file_data(b"abc").unwrap();
        w.file_data(b"").unwrap();
        // Contents that fall short.
        assert_eq!(w.file_end().unwrap_err().errno(), EIO);
        let mut w = writer(crc);
        assert_eq!(w.file_data(b"x").unwrap_err().errno(), EINVAL);
        assert_eq!(w.file_end().unwrap_err().errno(), EINVAL);
        w.file_begin(named(b"f"), &ATTRIBUTES, None, 6).unwrap();
        w.file_data(b"abc").unwrap();
        w.file_data(b"def").unwrap();
        assert_eq!(w.file_data(b"g").unwrap_err().errno(), EFBIG);
        w.file_end().unwrap();
        let (archive, _) = w.finish().unwrap();
        let seen = entries(&archive);
        assert_eq!(seen[0].data, b"abcdef");
        assert_eq!(seen[0].header.check, (0x61..=0x66).sum::<u32>());
        let mut w = writer(Options::default());
        w.file_begin(named(b"f"), &ATTRIBUTES, None, 1).unwrap();
        assert_eq!(w.finish().unwrap_err().errno(), EINVAL);
    }

    /// The cursor is where the writer is, entry for entry.
    #[test]
    fn the_cursor_goes_where_the_writer_goes() {
        for data_alignment in [0, 4, 512, 4096] {
            for end_alignment in [4, 512, 4096] {
                let options = Options {
                    data_alignment,
                    end_alignment,
                    ..Options::default()
                };
                let mut w = writer(options);
                let mut cursor = Cursor::new(options, 0);
                let data = vec![b'x'; 9000];
                let mut name = Vec::new();
                for i in 0..200usize {
                    name.push(b'a' + (i % 26) as u8);
                    if i % 37 == 36 {
                        name.clear();
                        name.push(b'z');
                    }
                    assert_eq!(cursor.offset(), w.offset());
                    let size = (i * 131) % 9000;
                    match i % 4 {
                        0 => {
                            w.file(named(&name), &ATTRIBUTES, None, size as u64, &mut &data[..])
                                .unwrap();
                            cursor.place(name.len(), Kind::Regular, size as u32);
                        }
                        1 => {
                            w.symlink(named(&name), &ATTRIBUTES, &data[..size % 4000 + 1]).unwrap();
                            cursor.place(name.len(), Kind::Symlink, (size % 4000 + 1) as u32);
                        }
                        2 => {
                            w.directory(named(&name), &ATTRIBUTES).unwrap();
                            cursor.place(name.len(), Kind::Directory, 0);
                        }
                        _ => {
                            w.node(named(&name), Kind::Fifo, &ATTRIBUTES, DeviceNumber::NONE, None)
                                .unwrap();
                            cursor.place(name.len(), Kind::Fifo, 0);
                        }
                    }
                }
                assert_eq!(cursor.offset(), w.offset());
                let (archive, len) = w.finish().unwrap();
                assert_eq!(cursor.finish(), len);
                assert_eq!(archive.len() as u64, len);
            }
        }
    }

    /// The same calls give the same bytes.
    #[test]
    fn writing_is_deterministic() {
        let build = || {
            let mut w = writer(Options::default());
            w.directory(named(b"."), &ATTRIBUTES).unwrap();
            w.file(named(b"f"), &ATTRIBUTES, None, 3, &mut &b"abc"[..]).unwrap();
            w.finish().unwrap().0
        };
        assert_eq!(build(), build());
    }
}
