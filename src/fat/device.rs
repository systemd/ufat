// SPDX-License-Identifier: LGPL-2.1-or-later
//! Access to the image file or block device that holds the file system.
//!
//! A [`Device`] is a window of `len` bytes starting at `offset` into an open
//! file, so a file system inside a partition of a larger image can be
//! addressed as if it started at byte 0.
//!
//! Built with `--cfg ufat_trace` the device can also record what it does to
//! the file, for the crash consistency harness in tests/crash.rs; see
//! [`Device::trace_to`]. The ordinary build has neither the field nor the
//! code for it.

use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::path::Path;

use crate::errno::*;
use crate::sys;
use crate::{Context, Error, Result};

/// Size of the buffer used for zeroing ranges.
const ZERO_CHUNK: usize = 1024 * 1024;

/// How much of `left` bytes the next write of at most `chunk` bytes covers.
/// The comparison is made in 64 bits: a length of 4 GiB or more does not fit
/// a 32-bit usize.
fn chunk_len(left: u64, chunk: usize) -> usize {
    usize::try_from(left).map_or(chunk, |left| left.min(chunk))
}

/// What an image is opened for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Reading only, O_RDONLY.
    ReadOnly,
    /// Reading and writing, O_RDWR.
    ReadWrite,
}

/// A byte range inside an image file or block device.
#[derive(Debug)]
pub struct Device {
    file: File,
    offset: u64,
    len: u64,
    block_device: bool,
    /// The directory and the name of a file [`Device::create`] made, kept
    /// so that [`Device::remove_if_created`] can take it away again while
    /// nothing has been written to it.
    created_in: Option<(OwnedFd, Vec<u8>)>,
    /// Where the records of every write, zero and sync go; see
    /// [`Device::trace_to`].
    #[cfg(ufat_trace)]
    trace: Option<File>,
}

impl Device {
    /// Opens `path`, read-only or read-write.
    ///
    /// The path is looked up exactly once: what it names is pinned as an
    /// O_PATH descriptor, checked to be a regular file or a block device
    /// (EINVAL otherwise, without a FIFO or a device node in its place ever
    /// being opened), and then opened through that descriptor with the
    /// flags the type asks for. That is how systemd's xopenat_full() opens
    /// a file it has to verify first, and it closes the window between
    /// looking at a path and opening it.
    ///
    /// Two things keep writers apart. A block device opened for writing is
    /// claimed exclusively, so the open fails with EBUSY while a file system
    /// is mounted on it, and mounting it fails while the device is open. And
    /// a BSD lock on the file, shared for reading and exclusive for writing,
    /// keeps a second instance of this library off the same image; a
    /// conflict is EBUSY as well. [`Device::from_fd`] does neither, the
    /// caller owns that descriptor.
    pub fn open(path: &Path, access: Access) -> Result<Device> {
        let pinned = sys::open_path(None, path, false).with_context(|| format!("failed to open {}", path.display()))?;
        Device::open_pinned(pinned.as_fd(), &path.display(), access)
    }

    /// Creates the regular file `path` for a new image, open for writing,
    /// or opens the regular file or block device of that name when one
    /// exists already, the way systemd's openat_report_new() does: the
    /// parent directory is looked up once, the file is created relative to
    /// it with O_CREAT|O_EXCL|O_NOFOLLOW so that nothing is ever created
    /// through a symbolic link, and an existing file is opened like
    /// [`Device::open`] does (a dangling symbolic link in its place is
    /// ELOOP).
    pub fn create(path: &Path) -> Result<Device> {
        let failed = || format!("failed to create {}", path.display());
        let (parent, name) = crate::host::open_parent(path).with_context(failed)?;
        let name = name.as_bytes();
        let created = sys::create_file_at(parent.as_fd(), name, 0o666);
        match created {
            Ok(file) => {
                let mut device = Device::lock_and_wrap(file, &path.display(), Access::ReadWrite)?;
                device.created_in = Some((parent, name.to_vec()));
                Ok(device)
            }
            Err(e) if e.raw_os_error() == Some(EEXIST) => {
                let pinned = match sys::pin_name(parent.as_fd(), name, false) {
                    Ok(p) => p,
                    Err(e) if e.raw_os_error() == Some(ENOENT) => {
                        // Gone again, or a dangling symbolic link, which
                        // O_NOFOLLOW would have reported as ELOOP.
                        let entry = sys::pin_entry(parent.as_fd(), name).with_context(failed)?;
                        if sys::fstat(entry.as_fd())?.file_type().is_symlink() {
                            bail!(ELOOP, "{} is a dangling symbolic link", path.display());
                        }
                        return Err(e).with_context(failed);
                    }
                    Err(e) => return Err(e).with_context(failed),
                };
                Device::open_pinned(pinned.as_fd(), &path.display(), Access::ReadWrite)
            }
            Err(e) => Err(e).with_context(failed),
        }
    }

    /// Opens the pinned inode `pinned`, a regular file or block device, for
    /// real: the type decides the flags, and the exclusive claim on a block
    /// device opened for writing comes with them.
    fn open_pinned(pinned: BorrowedFd<'_>, what: &dyn std::fmt::Display, access: Access) -> Result<Device> {
        let ft = sys::fstat(pinned)?.file_type();
        if !ft.is_file() && !ft.is_block_device() {
            bail!(EINVAL, "{} is not a regular file or block device", what);
        }
        // O_EXCL means "claim" for block devices only; on a regular file
        // without O_CREAT it has no defined meaning. The type is known, so
        // nothing we open here can make us wait or become our terminal,
        // but the flags cost nothing.
        let mut flags = sys::O_NONBLOCK | sys::O_NOCTTY;
        match access {
            Access::ReadOnly => flags |= sys::O_RDONLY,
            Access::ReadWrite if ft.is_block_device() => flags |= sys::O_RDWR | sys::O_EXCL,
            Access::ReadWrite => flags |= sys::O_RDWR,
        }
        let file = sys::reopen(pinned, flags).map_err(|e| {
            let hint = if e.raw_os_error() == Some(EBUSY) {
                ", it is in use (mounted?)"
            } else {
                ""
            };
            Error::from(e).context(format!("failed to open {}{}", what, hint))
        })?;
        Device::lock_and_wrap(File::from(file), what, access)
    }

    /// Takes the BSD lock, exclusive for writing, and wraps the file.
    fn lock_and_wrap(file: File, what: &dyn std::fmt::Display, access: Access) -> Result<Device> {
        if !sys::try_lock(file.as_fd(), access == Access::ReadWrite)? {
            bail!(EBUSY, "{} is being used by another process", what);
        }
        Device::from_file(file)
    }

    /// Wraps an open regular file or block device. The window covers the
    /// whole file.
    pub fn from_file(file: File) -> Result<Device> {
        let md = file.metadata()?;
        let ft = md.file_type();
        let block_device = ft.is_block_device();
        // A block device's size comes from an ioctl rather than a seek, so
        // that a descriptor shared with the caller keeps its offset.
        let len = if ft.is_file() {
            md.len()
        } else if block_device {
            // Opened without waiting, a removable device without a medium
            // opens fine and reports a size of 0.
            let len = sys::block_device_size(file.as_fd())?;
            if len == 0 {
                bail!(ENOMEDIUM, "the block device has no medium");
            }
            len
        } else {
            bail!(EINVAL, "not a regular file or block device");
        };
        Ok(Device {
            file,
            offset: 0,
            len,
            block_device,
            created_in: None,
            #[cfg(ufat_trace)]
            trace: None,
        })
    }

    /// Duplicates `fd` and wraps it. The caller keeps ownership of `fd`.
    pub fn from_fd(fd: BorrowedFd<'_>) -> Result<Device> {
        let owned = fd.try_clone_to_owned()?;
        Device::from_file(File::from(owned))
    }

    /// Takes a descriptor another process handed over as the image, already
    /// vetted by [`crate::host::passed_image`] to be a regular file or block
    /// device open the right way. A block device to be written is claimed
    /// exclusively, the way a mount claims it, by reopening it through the
    /// descriptor with O_EXCL: a passed descriptor cannot carry a claim, a
    /// mounted device is EBUSY, and reopening grants nothing the client did
    /// not have since the descriptor was checked to be open for reading and
    /// writing already. The BSD lock [`Device::open`] takes is not taken
    /// here: it would live on the caller's open file description, outlast
    /// the call for as long as the caller keeps its descriptor, and
    /// releasing it would release a lock the caller holds itself. Whoever
    /// hands over a descriptor is in charge of locking what it refers to.
    pub fn from_passed(fd: OwnedFd, access: Access) -> Result<Device> {
        let md = sys::fstat(fd.as_fd())?;
        let file = if access == Access::ReadWrite && md.file_type().is_block_device() {
            let flags = sys::O_RDWR | sys::O_EXCL | sys::O_NONBLOCK | sys::O_NOCTTY;
            File::from(sys::reopen(fd.as_fd(), flags).map_err(|e| {
                let hint = if e.raw_os_error() == Some(EBUSY) {
                    ", it is in use (mounted?)"
                } else {
                    ""
                };
                Error::from(e).context(format!("failed to claim the block device{}", hint))
            })?)
        } else {
            File::from(fd)
        };
        Device::from_file(file)
    }

    /// Narrows the device to `len` bytes (or everything up to the end when
    /// None) starting at `offset`, relative to the current window.
    pub fn window(mut self, offset: u64, len: Option<u64>) -> Result<Device> {
        if offset > self.len {
            bail!(
                EINVAL,
                "offset {} is beyond the end of the device ({} bytes)",
                offset,
                self.len
            );
        }
        let avail = self.len - offset;
        let len = match len {
            Some(l) if l > avail => {
                bail!(
                    EINVAL,
                    "size {} exceeds the {} bytes available at offset {}",
                    l,
                    avail,
                    offset
                )
            }
            Some(l) => l,
            None => avail,
        };
        self.offset += offset;
        self.len = len;
        Ok(self)
    }

    /// Grows a regular image file so that it holds `total` bytes, before
    /// the device is narrowed with [`Device::window`]. A file that is large
    /// enough already is left alone: shrinking it would cut off whatever
    /// lives behind the file system in a disk image. A block device has the
    /// size it has.
    pub fn grow(&mut self, total: u64) -> Result<()> {
        if self.offset != 0 {
            bail!(EINVAL, "cannot grow a window into an image");
        }
        if self.block_device || self.len >= total {
            return Ok(());
        }
        self.file
            .set_len(total)
            .with_context(|| format!("failed to grow the image to {} bytes", total))?;
        self.len = total;
        Ok(())
    }

    /// Removes the file [`Device::create`] made, if this device is one, and
    /// closes it. A caller that learns before the first write that it has
    /// no use for the image after all, because the content does not fit the
    /// size it was given or a source cannot be read, takes back what it
    /// created so that a failed command leaves nothing behind. The name is
    /// looked up in the directory the file was created in and unlinked only
    /// while it still refers to this file; something else of that name is
    /// left alone. Returns whether a file was removed.
    pub fn remove_if_created(self) -> Result<bool> {
        let Some((parent, name)) = &self.created_in else {
            return Ok(false);
        };
        let ours = sys::fstat(self.file.as_fd())?;
        let entry = match sys::pin_entry(parent.as_fd(), name) {
            Ok(entry) => entry,
            Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        let there = sys::fstat(entry.as_fd())?;
        if (there.dev(), there.ino()) != (ours.dev(), ours.ino()) {
            return Ok(false);
        }
        sys::unlink_at(parent.as_fd(), name)
            .with_context(|| "failed to remove the image created for the file system")?;
        Ok(true)
    }

    /// Length of the window in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the window is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Byte offset of the window into the underlying file.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Whether the underlying file is a block device.
    pub fn is_block_device(&self) -> bool {
        self.block_device
    }

    /// The descriptor of the underlying file, for libblkid to probe the
    /// image through.
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// Where a partition starts on its disk, in bytes: 0 for regular files
    /// and whole disks.
    pub fn partition_start(&self) -> Result<u64> {
        if !self.block_device {
            return Ok(0);
        }
        Ok(sys::partition_start(self.file.as_fd())?)
    }

    /// The logical block size of a block device, or None for regular files.
    pub fn logical_block_size(&self) -> Result<Option<u32>> {
        if !self.block_device {
            return Ok(None);
        }
        Ok(Some(sys::block_device_logical_block_size(self.file.as_fd())?))
    }

    fn check_range(&self, offset: u64, len: usize) -> Result<u64> {
        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| err!(EINVAL, "I/O range overflows"))?;
        if end > self.len {
            bail!(
                EINVAL,
                "I/O at offset {} for {} bytes is beyond the end of the device ({} bytes)",
                offset,
                len,
                self.len
            );
        }
        Ok(self.offset + offset)
    }

    /// Reads exactly `buf.len()` bytes at `offset`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let abs = self.check_range(offset, buf.len())?;
        self.file
            .read_exact_at(buf, abs)
            .with_context(|| format!("read of {} bytes at offset {} failed", buf.len(), offset))
    }

    /// Writes all of `buf` at `offset`.
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> Result<()> {
        let abs = self.check_range(offset, buf.len())?;
        self.file
            .write_all_at(buf, abs)
            .with_context(|| format!("write of {} bytes at offset {} failed", buf.len(), offset))?;
        #[cfg(ufat_trace)]
        self.record(TRACE_WRITE, abs, buf.len() as u64, buf)?;
        Ok(())
    }

    /// Makes `len` bytes at `offset` read as zeros: through a hole punched
    /// into an image file or a zero-out command to a block device where the
    /// kernel offers them, by writing zeros otherwise. The bytes are the
    /// same either way.
    pub fn zero(&self, offset: u64, len: u64) -> Result<()> {
        if len > self.len || offset > self.len - len {
            bail!(
                EINVAL,
                "zeroing {} bytes at offset {} is beyond the end of the device ({} bytes)",
                len,
                offset,
                self.len
            );
        }
        if len == 0 {
            return Ok(());
        }
        if sys::zero_range(&self.file, self.block_device, self.offset + offset, len)? {
            #[cfg(ufat_trace)]
            self.record(TRACE_ZERO, self.offset + offset, len, &[])?;
            return Ok(());
        }
        let zeros = vec![0u8; chunk_len(len, ZERO_CHUNK)];
        let mut pos = offset;
        let end = offset + len;
        while pos < end {
            let n = chunk_len(end - pos, zeros.len());
            self.write_at(pos, &zeros[..n])?;
            pos += n as u64;
        }
        Ok(())
    }

    /// Makes the data written so far reach stable storage (fdatasync): the
    /// barrier between a write and the one that publishes it.
    pub fn sync_data(&self) -> Result<()> {
        self.file.sync_data().with_context(|| "fdatasync failed")?;
        #[cfg(ufat_trace)]
        self.record(TRACE_BARRIER, 0, 0, &[])?;
        Ok(())
    }

    /// Flushes everything written so far to stable storage.
    pub fn sync(&self) -> Result<()> {
        self.file.sync_all()?;
        #[cfg(ufat_trace)]
        self.record(TRACE_SYNC, 0, 0, &[])?;
        Ok(())
    }
}

/// The record tags of a write trace: a write with its bytes, a range made
/// to read as zeros, the fdatasync barrier, the fsync, and a note from the
/// program driving the device.
#[cfg(ufat_trace)]
const TRACE_WRITE: u8 = b'W';
#[cfg(ufat_trace)]
const TRACE_ZERO: u8 = b'Z';
#[cfg(ufat_trace)]
const TRACE_BARRIER: u8 = b'F';
#[cfg(ufat_trace)]
const TRACE_SYNC: u8 = b'S';
#[cfg(ufat_trace)]
const TRACE_NOTE: u8 = b'N';

#[cfg(ufat_trace)]
impl Device {
    /// Records everything that changes the file from now on to `file`, in
    /// the order it happens: every write with its bytes, every range made
    /// to read as zeros, every fdatasync and fsync. The crash consistency
    /// harness replays such a trace to build the states a crash can leave
    /// behind. Each record is a tag byte, the absolute file offset as a
    /// little endian u64 and a length as a little endian u64; a write
    /// (`W`) and a note (`N`) are followed by that many bytes, a zeroed
    /// range (`Z`) names its length and carries no bytes, a barrier (`F`)
    /// and a sync (`S`) have offset and length zero. Reads are not
    /// recorded; they do not matter for what a crash leaves behind.
    pub fn trace_to(&mut self, file: File) {
        self.trace = Some(file);
    }

    /// Puts a note into the trace, for the program driving the device to
    /// mark where one of its operations begins.
    pub fn trace_note(&self, text: &str) -> Result<()> {
        self.record(TRACE_NOTE, 0, text.len() as u64, text.as_bytes())
    }

    fn record(&self, tag: u8, offset: u64, len: u64, data: &[u8]) -> Result<()> {
        use std::io::Write;
        let Some(mut trace) = self.trace.as_ref() else {
            return Ok(());
        };
        let mut header = [0u8; 17];
        header[0] = tag;
        header[1..9].copy_from_slice(&offset.to_le_bytes());
        header[9..17].copy_from_slice(&len.to_le_bytes());
        trace
            .write_all(&header)
            .and_then(|()| trace.write_all(data))
            .with_context(|| "writing the device trace failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TempDir, TempImage};
    use std::os::unix::fs::symlink;
    use std::time::{Duration, Instant};

    #[test]
    fn locks_keep_writers_apart() {
        let img = TempImage::new(4096);
        let path = img.path();
        let writer = Device::open(path, Access::ReadWrite).unwrap();
        assert_eq!(Device::open(path, Access::ReadWrite).unwrap_err().errno(), EBUSY);
        assert_eq!(Device::open(path, Access::ReadOnly).unwrap_err().errno(), EBUSY);
        drop(writer);
        let reader = Device::open(path, Access::ReadOnly).unwrap();
        let _another = Device::open(path, Access::ReadOnly).unwrap();
        assert_eq!(Device::open(path, Access::ReadWrite).unwrap_err().errno(), EBUSY);
        drop(reader);
    }

    /// A FIFO nobody writes to: a blocking open would wait forever. The
    /// type is checked on the pinned inode and the FIFO is never opened.
    #[test]
    fn a_fifo_is_refused_without_waiting() {
        let dir = TempDir::new("fifo");
        let path = dir.path().join("fifo");
        sys::make_fifo(&path).unwrap();
        let started = Instant::now();
        assert_eq!(Device::open(&path, Access::ReadOnly).unwrap_err().errno(), EINVAL);
        assert_eq!(Device::create(&path).unwrap_err().errno(), EINVAL);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A path to an image is resolved once, through symbolic links, and
    /// a directory or a missing file is refused.
    #[test]
    fn paths_are_resolved_once() {
        let tmp = TempDir::new("open");
        let dir = tmp.path();
        File::create(dir.join("img")).unwrap().set_len(4096).unwrap();
        symlink("img", dir.join("link")).unwrap();
        let dev = Device::open(&dir.join("link"), Access::ReadWrite).unwrap();
        assert_eq!(dev.len(), 4096);
        assert_eq!(
            Device::open(&dir.join("img"), Access::ReadOnly).unwrap_err().errno(),
            EBUSY
        );
        drop(dev);
        assert_eq!(Device::open(dir, Access::ReadOnly).unwrap_err().errno(), EINVAL);
        assert_eq!(
            Device::open(&dir.join("missing"), Access::ReadOnly)
                .unwrap_err()
                .errno(),
            ENOENT
        );
    }

    /// Creating an image makes a new file, opens an existing one as it is
    /// and never goes through a symbolic link to create something.
    #[test]
    fn create_makes_or_opens_a_file() {
        let tmp = TempDir::new("create");
        let dir = tmp.path();
        let mut dev = Device::create(&dir.join("new.img")).unwrap();
        assert_eq!(dev.len(), 0);
        dev.grow(8192).unwrap();
        assert_eq!(dev.len(), 8192);
        dev.write_at(0, b"kept").unwrap();
        drop(dev);
        // Existing: opened, not truncated, not grown when large enough.
        let mut dev = Device::create(&dir.join("new.img")).unwrap();
        assert_eq!(dev.len(), 8192);
        dev.grow(4096).unwrap();
        assert_eq!(dev.len(), 8192);
        let mut back = [0u8; 4];
        dev.read_at(0, &mut back).unwrap();
        assert_eq!(&back, b"kept");
        drop(dev);
        // Through a link to an existing file: fine. A dangling link: ELOOP,
        // and nothing is created where it points.
        symlink("new.img", dir.join("link.img")).unwrap();
        assert_eq!(Device::create(&dir.join("link.img")).unwrap().len(), 8192);
        symlink("nowhere.img", dir.join("dangling.img")).unwrap();
        assert_eq!(Device::create(&dir.join("dangling.img")).unwrap_err().errno(), ELOOP);
        assert!(!dir.join("nowhere.img").exists());
        assert_eq!(Device::create(dir).unwrap_err().errno(), EINVAL);
        assert_eq!(
            Device::create(&dir.join("missing-dir/x.img")).unwrap_err().errno(),
            ENOENT
        );
        // A window cannot be grown.
        let mut dev = Device::open(&dir.join("new.img"), Access::ReadWrite)
            .unwrap()
            .window(4096, None)
            .unwrap();
        assert_eq!(dev.grow(1 << 20).unwrap_err().errno(), EINVAL);
    }

    #[test]
    fn zero_makes_a_range_read_as_zeros() {
        let img = TempImage::new(0);
        let path = img.path();
        std::fs::write(path, vec![0xFFu8; 1 << 20]).unwrap();
        {
            let dev = Device::open(path, Access::ReadWrite).unwrap();
            // A whole number of pages, which a hole can cover, and an odd
            // range, which is written.
            dev.zero(4096, 65536).unwrap();
            dev.zero(200_000, 100).unwrap();
            dev.zero(1 << 20, 0).unwrap();
            assert_eq!(dev.zero(1 << 20, 1).unwrap_err().errno(), EINVAL);
        }
        let dev = Device::open(path, Access::ReadWrite)
            .unwrap()
            .window(8192, None)
            .unwrap();
        dev.zero(1 << 19, 4096).unwrap();
        drop(dev);
        let data = std::fs::read(path).unwrap();
        assert_eq!(data.len(), 1 << 20);
        let zero = |from: usize, to: usize| data[from..to].iter().all(|&b| b == 0);
        let intact = |from: usize, to: usize| data[from..to].iter().all(|&b| b == 0xFF);
        assert!(intact(0, 4096));
        assert!(zero(4096, 4096 + 65536));
        assert!(intact(4096 + 65536, 200_000));
        assert!(zero(200_000, 200_100));
        assert!(intact(200_100, 8192 + (1 << 19)));
        assert!(zero(8192 + (1 << 19), 8192 + (1 << 19) + 4096));
        assert!(intact(8192 + (1 << 19) + 4096, 1 << 20));
    }

    /// The writes that zero a range cover it to the end in steps of at most
    /// a chunk, whatever its length.
    #[test]
    fn zeroing_steps_through_any_length() {
        assert_eq!(chunk_len(0, ZERO_CHUNK), 0);
        assert_eq!(chunk_len(5, ZERO_CHUNK), 5);
        assert_eq!(chunk_len(ZERO_CHUNK as u64, ZERO_CHUNK), ZERO_CHUNK);
        for left in [1 << 32, (1 << 32) + 5, 5 << 32, u64::MAX] {
            assert_eq!(chunk_len(left, ZERO_CHUNK), ZERO_CHUNK, "{}", left);
        }
    }
}
