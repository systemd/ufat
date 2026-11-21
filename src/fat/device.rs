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
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::Path;

use crate::errno::*;
use crate::host::{Naming, NewFile};
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
    /// The file [`Device::create`] made, until [`Device::take_created`]
    /// hands it over to get its name. A device that keeps it gives it up
    /// when it is dropped.
    created: Option<NewFile>,
    /// How often the data was synced, for the tests of the write order.
    #[cfg(test)]
    pub(crate) syncs: std::sync::Arc<std::sync::atomic::AtomicUsize>,
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

    /// Makes a new regular file for an image that is to be named `path`,
    /// open for writing, or opens the regular file or block device of that
    /// name when one exists, the way [`Device::open`] does. The parent
    /// directory is looked up once, and the name is looked up in it. A
    /// dangling symbolic link in its place is ELOOP, so that nothing is ever
    /// created through one. A new file is made as a [`NewFile`] that does
    /// not take the place of another file: it has no name, or a temporary
    /// one, and gets `path` only from [`NewFile::link`] once the image is
    /// complete, after [`Device::take_created`] handed it over. Until then
    /// nothing is under that name, so a command that fails, is killed or
    /// crashes leaves nothing there, and a file that takes the name
    /// meanwhile is never replaced. A file system that can neither rename
    /// without replacing nor make hard links gets the file under `path`
    /// right away, the last resort of [`NewFile`].
    pub fn create(path: &Path) -> Result<Device> {
        let failed = || format!("failed to create {}", path.display());
        let (parent, name) = crate::host::open_parent(path).with_context(failed)?;
        let pinned = match sys::pin_name(parent.as_fd(), name.as_bytes(), false) {
            Ok(pinned) => Some(pinned),
            // Nothing of that name, or a dangling symbolic link, which
            // following it reports as missing too.
            Err(e) if e.raw_os_error() == Some(ENOENT) => match sys::pin_entry(parent.as_fd(), name.as_bytes()) {
                Ok(entry) if sys::fstat(entry.as_fd())?.file_type().is_symlink() => {
                    bail!(ELOOP, "{} is a dangling symbolic link", path.display())
                }
                // There since the lookup before.
                Ok(entry) => Some(entry),
                Err(e) if e.raw_os_error() == Some(ENOENT) => None,
                Err(e) => return Err(e).with_context(failed),
            },
            Err(e) => return Err(e).with_context(failed),
        };
        if let Some(pinned) = pinned {
            return Device::open_pinned(pinned.as_fd(), &path.display(), Access::ReadWrite);
        }
        let new = NewFile::create_in(parent, name, path, Naming::Exclusive).with_context(failed)?;
        // A descriptor of its own for the device. It shares the open file
        // description with the new file's, and so the lock the new file took
        // and the device takes again, which stays as long as the new file is
        // held.
        let device = new
            .file()
            .try_clone()
            .map_err(Error::from)
            .and_then(|file| Device::lock_and_wrap(file, &path.display(), Access::ReadWrite));
        match device {
            Ok(mut device) => {
                device.created = Some(new);
                Ok(device)
            }
            Err(e) => Err(new.given_up(e.context(failed()))),
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
            created: None,
            #[cfg(test)]
            syncs: Default::default(),
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

    /// Hands over the new file [`Device::create`] made, if it made one: to
    /// get its name once the image is complete, or to be given up without
    /// it. The device goes on working with the file either way.
    pub fn take_created(&mut self) -> Option<NewFile> {
        self.created.take()
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
        #[cfg(test)]
        self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    use crate::host::{LinkError, Linked, Removal};
    use crate::test_util::{TempDir, TempImage};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    /// The names in the directory `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

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

    /// Creating an image makes a new file, which gets its name when it is
    /// linked, opens an existing one as it is and never goes through a
    /// symbolic link to create something.
    #[test]
    fn create_makes_or_opens_a_file() {
        let tmp = TempDir::new("create");
        let dir = tmp.path();
        let path = dir.join("new.img");
        let mut dev = Device::create(&path).unwrap();
        assert_eq!(dev.len(), 0);
        dev.grow(8192).unwrap();
        assert_eq!(dev.len(), 8192);
        dev.write_at(0, b"kept").unwrap();
        assert!(!path.exists());
        Linked::sync_directories(&[dev.take_created().unwrap().link().unwrap()]).unwrap();
        assert!(dev.take_created().is_none());
        // The device goes on with the file it named, and keeps its lock.
        dev.write_at(4, b"more").unwrap();
        assert_eq!(Device::open(&path, Access::ReadOnly).unwrap_err().errno(), EBUSY);
        drop(dev);
        assert_eq!(names_in(dir), ["new.img"]);
        // Existing: opened, not truncated, not grown when large enough, and
        // nothing new to hand over.
        let mut dev = Device::create(&path).unwrap();
        assert!(dev.take_created().is_none());
        assert_eq!(dev.len(), 8192);
        dev.grow(4096).unwrap();
        assert_eq!(dev.len(), 8192);
        let mut back = [0u8; 8];
        dev.read_at(0, &mut back).unwrap();
        assert_eq!(&back, b"keptmore");
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

    /// A new image that does not get its name leaves nothing behind,
    /// whatever was written to it, whether the device keeps the new file or
    /// hands it over. The lock of the device stays while the new file is
    /// held, after the device is gone as well.
    #[test]
    fn a_new_image_without_its_name_leaves_nothing() {
        let tmp = TempDir::new("unnamed");
        let dir = tmp.path();
        let path = dir.join("a.img");
        let mut dev = Device::create(&path).unwrap();
        dev.grow(4096).unwrap();
        dev.write_at(0, b"half").unwrap();
        drop(dev);
        assert!(names_in(dir).is_empty());
        let mut dev = Device::create(&path).unwrap();
        dev.grow(4096).unwrap();
        let created = dev.take_created().unwrap();
        drop(dev);
        let file = PathBuf::from(format!("/proc/self/fd/{}", created.file().as_raw_fd()));
        assert_eq!(Device::open(&file, Access::ReadOnly).unwrap_err().errno(), EBUSY);
        assert_eq!(created.discard().unwrap(), Removal::Removed);
        assert!(names_in(dir).is_empty());
    }

    /// A name that something else took while the image was made is left
    /// as it is: the image does not get it (EEXIST).
    #[test]
    fn a_name_taken_meanwhile_stays_as_it_is() {
        let tmp = TempDir::new("taken");
        let dir = tmp.path();
        let path = dir.join("a.img");
        let mut dev = Device::create(&path).unwrap();
        dev.grow(4096).unwrap();
        std::fs::write(&path, b"theirs").unwrap();
        let LinkError::Unnamed { error, file } = dev.take_created().unwrap().link().unwrap_err() else {
            panic!("the image got the name");
        };
        assert_eq!(error.errno(), EEXIST);
        drop(dev);
        assert_eq!(file.discard().unwrap(), Removal::Removed);
        assert_eq!(std::fs::read(&path).unwrap(), b"theirs");
        assert_eq!(names_in(dir), ["a.img"]);
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
