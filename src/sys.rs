// SPDX-License-Identifier: LGPL-2.1-or-later
//! The raw system calls std does not wrap, and the descriptor based file
//! access built on them. This is the only module with unsafe code.
//!
//! Everything here names an open descriptor and at most one directory
//! entry below it. A path is looked up exactly once, at the edge, with
//! [`open_path`]; from then on a directory is listed with [`list_dir`], an
//! entry pinned with [`pin_entry`], a path below a root resolved with
//! [`chase`] and a pinned inode opened for real with [`reopen`]. The shape
//! follows systemd's src/basic/chase.c, fs-util.c, fd-util.c and
//! recurse-dir.c, see the individual functions.
#![allow(unsafe_code)]

mod uapi;

use std::ffi::{c_int, c_uint, CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::errno::{EBADF, EINVAL, ELOOP, ENODEV, ENOENT, ENOSYS, ENOTTY, ENXIO, EOPNOTSUPP};

// The open(2) flags. libc has the values of each architecture: alpha,
// arm, arm64, m68k, mips, parisc, powerpc and sparc number some of them
// differently from include/uapi/asm-generic/fcntl.h.
pub(crate) const O_RDONLY: c_int = libc::O_RDONLY;
pub(crate) const O_RDWR: c_int = libc::O_RDWR;
pub(crate) const O_CREAT: c_int = libc::O_CREAT;
/// On a block device O_EXCL asks for the exclusive claim a mounted file
/// system holds.
pub(crate) const O_EXCL: c_int = libc::O_EXCL;
/// No terminal becomes ours when what we open turns out to be one.
pub(crate) const O_NOCTTY: c_int = libc::O_NOCTTY;
/// No waiting for the other end when what we open turns out to be a FIFO.
pub(crate) const O_NONBLOCK: c_int = libc::O_NONBLOCK;
pub(crate) const O_DIRECTORY: c_int = libc::O_DIRECTORY;
pub(crate) const O_NOFOLLOW: c_int = libc::O_NOFOLLOW;
pub(crate) const O_CLOEXEC: c_int = libc::O_CLOEXEC;
/// A descriptor that pins an inode without opening it: fstat, openat and
/// a later [`reopen`] work on it, reading and writing do not.
pub(crate) const O_PATH: c_int = libc::O_PATH;
pub(crate) use uapi::O_EMPTYPATH;

/// NAME_MAX, include/uapi/linux/limits.h: the longest file name.
const NAME_MAX: usize = libc::NAME_MAX as usize;

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

fn cstring(bytes: &[u8]) -> io::Result<CString> {
    CString::new(bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))
}

/// A single file name, as systemd's filename_is_valid() has it: not empty,
/// not "." or "..", no slash, at most NAME_MAX bytes. Everything that walks
/// relative to a directory descriptor takes one name at a time.
fn filename(name: &[u8]) -> io::Result<CString> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.len() > NAME_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a file name"));
    }
    cstring(name)
}

/// `openat(2)`. `mode` matters with O_CREAT only; O_CLOEXEC is always set.
/// openat64() opens files of any size on 32-bit targets too.
fn open_at(dirfd: c_int, path: &CStr, flags: c_int, mode: c_uint) -> io::Result<OwnedFd> {
    // SAFETY: a NUL terminated path and plain integers; openat64 reads the
    // path for the duration of the call and nothing else.
    let fd = unsafe { libc::openat64(dirfd, path.as_ptr(), flags | O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a descriptor the kernel just handed to us and nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

/// Looks `path` up once, relative to `dir` or to the working directory, and
/// pins what it names as an O_PATH descriptor. Symbolic links in the path
/// are followed, the way a user naming a device by `/dev/disk/by-...`
/// expects; with `directory` the result has to be one (ENOTDIR). This is
/// the one lookup a path given to us at the edge gets: systemd's chase()
/// without a root boundary is a single xopenat(path, O_PATH) as well.
pub(crate) fn open_path(dir: Option<BorrowedFd<'_>>, path: &Path, directory: bool) -> io::Result<OwnedFd> {
    let path = cstring(path.as_os_str().as_bytes())?;
    let flags = O_PATH | if directory { O_DIRECTORY } else { 0 };
    open_at(dir.map_or(libc::AT_FDCWD, |d| d.as_raw_fd()), &path, flags, 0)
}

/// Pins the entry `name` of the directory `dir` as an O_PATH descriptor
/// without following it when it is a symbolic link: the way recurse_dir()
/// in systemd's src/basic/recurse-dir.c takes hold of every entry before
/// looking at it. What the descriptor is, is told by [`fstat`].
pub(crate) fn pin_entry(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<OwnedFd> {
    open_at(dir.as_raw_fd(), &filename(name)?, O_PATH | O_NOFOLLOW, 0)
}

/// Looks the single name `name` up in the directory `dir` and pins what it
/// names, following a symbolic link in its place: [`pin_entry`] for the
/// last component of a path whose parent is pinned already, the way
/// chase_and_open() opens the final component relative to the parent it
/// chased. With `directory` the result has to be one.
pub(crate) fn pin_name(dir: BorrowedFd<'_>, name: &[u8], directory: bool) -> io::Result<OwnedFd> {
    let flags = O_PATH | if directory { O_DIRECTORY } else { 0 };
    open_at(dir.as_raw_fd(), &filename(name)?, flags, 0)
}

/// Creates the regular file `name` in `dir`, failing when something of
/// that name exists (EEXIST) and never following a symbolic link in its
/// place: the first step of systemd's openat_report_new(). The file is
/// open for reading and writing and does not wait for anything.
pub(crate) fn create_file_at(dir: BorrowedFd<'_>, name: &[u8], mode: u32) -> io::Result<File> {
    let flags = O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY;
    Ok(File::from(open_at(dir.as_raw_fd(), &filename(name)?, flags, mode)?))
}

/// Removes the entry `name` of the directory `dir`, which must not be a
/// directory itself: `unlinkat(2)` without AT_REMOVEDIR.
pub(crate) fn unlink_at(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<()> {
    let name = filename(name)?;
    // SAFETY: a NUL terminated name and plain integers; unlinkat reads the
    // name for the duration of the call and nothing else.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// What a probe of the running kernel found out so far: nothing yet, that
/// it offers the feature, or that it does not.
const PROBE_UNKNOWN: u8 = 0;
const PROBE_WORKS: u8 = 1;
const PROBE_MISSING: u8 = 2;

/// Whether the kernel reopens a descriptor through O_EMPTYPATH.
static EMPTYPATH: AtomicU8 = AtomicU8::new(PROBE_UNKNOWN);

/// Opens what `fd` refers to anew with `flags`: an O_PATH descriptor
/// becomes one that can read, a pinned directory one that can be listed.
/// This is systemd's fd_reopen() (src/basic/fd-util.c), in its order: an
/// empty path with O_EMPTYPATH on kernels that have it (7.2), "." relative
/// to the descriptor for a directory, and otherwise the magic link
/// /proc/self/fd/N.
///
/// The magic link is not a lookup of anything the user named: it resolves
/// to the inode the descriptor already pins, so no path component is
/// walked a second time and nothing can be swapped underneath us. Its only
/// dependency is procfs being mounted, which is told apart from a stale
/// descriptor the way proc_fd_enoent_errno() does. Nothing can be created
/// through a descriptor (EINVAL, where fd_reopen() asserts), and
/// O_NOFOLLOW is ELOOP as it is there: the magic link is a symbolic link,
/// so the flag could only ever fail.
pub(crate) fn reopen(fd: BorrowedFd<'_>, flags: c_int) -> io::Result<OwnedFd> {
    if flags & O_CREAT != 0 {
        return Err(errno(EINVAL));
    }
    if flags & O_NOFOLLOW != 0 {
        return Err(errno(ELOOP));
    }
    let state = EMPTYPATH.load(Ordering::Relaxed);
    if state != PROBE_MISSING {
        match open_at(fd.as_raw_fd(), c"", flags | O_EMPTYPATH, 0) {
            Ok(new) => {
                EMPTYPATH.store(PROBE_WORKS, Ordering::Relaxed);
                return Ok(new);
            }
            // An older kernel ignores the flag and refuses the empty
            // path. Once it worked, ENOENT comes from the file itself.
            Err(e) if e.raw_os_error() == Some(ENOENT) && state != PROBE_WORKS => {
                EMPTYPATH.store(PROBE_MISSING, Ordering::Relaxed);
            }
            Err(e) => return Err(e),
        }
    }
    if flags & O_DIRECTORY != 0 {
        // A directory is reopened through its own "." entry, which needs no
        // procfs at all.
        return open_at(fd.as_raw_fd(), c".", flags, 0);
    }
    let link = cstring(format!("/proc/self/fd/{}", fd.as_raw_fd()).as_bytes())?;
    match open_at(libc::AT_FDCWD, &link, flags, 0) {
        Err(e) if e.raw_os_error() == Some(ENOENT) => Err(proc_fd_enoent_errno()),
        r => r,
    }
}

/// ENOENT from /proc/self/fd/N means either that procfs is not mounted or
/// that the descriptor is gone; systemd's proc_fd_enoent_errno() tells
/// them apart by looking at /proc itself: ENOSYS when procfs is not there,
/// EBADF when it is and the descriptor is not, and the ENOENT itself when
/// it cannot tell.
fn proc_fd_enoent_errno() -> io::Error {
    match open_path(None, Path::new("/proc"), true).and_then(|proc| fs_kind(proc.as_fd())) {
        Ok(FsKind::Proc) => errno(EBADF),
        Ok(_) => procfs_missing(),
        Err(e) if e.raw_os_error() == Some(ENOENT) => procfs_missing(),
        Err(_) => errno(ENOENT),
    }
}

fn procfs_missing() -> io::Error {
    crate::Error::new(ENOSYS, "procfs is not mounted on /proc, cannot reopen a descriptor").into()
}

/// The metadata of what `fd` refers to, an O_PATH descriptor included:
/// fstat (statx where std has it) on the descriptor, never on a path.
pub(crate) fn fstat(fd: BorrowedFd<'_>) -> io::Result<std::fs::Metadata> {
    // SAFETY: the File is never dropped, so the descriptor, which we do not
    // own, stays open; std only calls fstat or statx on it.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd.as_raw_fd()) });
    file.metadata()
}

/// The file systems we tell apart, by the magic numbers of
/// include/uapi/linux/magic.h.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FsKind {
    Proc,
    Sysfs,
    Other,
}

/// The kind of file system `fd` is on, fstatfs(2). fstatfs64() works on
/// 32-bit targets too when a count of the file system does not fit 32
/// bits.
pub(crate) fn fs_kind(fd: BorrowedFd<'_>) -> io::Result<FsKind> {
    let mut st = MaybeUninit::<libc::statfs64>::uninit();
    // SAFETY: fstatfs64 writes one struct statfs64 through the pointer.
    if unsafe { libc::fstatfs64(fd.as_raw_fd(), st.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatfs64 succeeded, so it filled in the struct.
    let st = unsafe { st.assume_init() };
    // f_type and the magic numbers have the same type, a long or, on
    // s390x, an unsigned int.
    Ok(if st.f_type == libc::PROC_SUPER_MAGIC {
        FsKind::Proc
    } else if st.f_type == libc::SYSFS_MAGIC {
        FsKind::Sysfs
    } else {
        FsKind::Other
    })
}

/// Takes a BSD lock on `fd` without waiting: shared for reading, exclusive
/// for writing. Returns false when another open file description holds a
/// conflicting lock.
pub(crate) fn try_lock(fd: BorrowedFd<'_>, exclusive: bool) -> io::Result<bool> {
    let operation = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH } | libc::LOCK_NB;
    // SAFETY: flock takes a descriptor and flags, nothing else.
    if unsafe { libc::flock(fd.as_raw_fd(), operation) } < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

/// Makes `len` bytes at `offset` of `file` read as zeros without writing
/// them: a hole punched into a regular file (fallocate, which shmem and
/// ext4 support), or a zero-out command sent to a block device. Returns
/// false when the kernel or the file system offers neither, so that the
/// caller writes the zeros instead.
pub(crate) fn zero_range(file: &File, block_device: bool, offset: u64, len: u64) -> io::Result<bool> {
    let fd = file.as_raw_fd();
    let r = if block_device {
        let range = [offset, len];
        // SAFETY: BLKZEROOUT reads two u64 through the pointer and nothing
        // else; the array lives for the duration of the call.
        unsafe { libc::ioctl(fd, uapi::BLKZEROOUT, range.as_ptr()) }
    } else {
        let (Ok(offset), Ok(len)) = (i64::try_from(offset), i64::try_from(len)) else {
            return Ok(false);
        };
        // SAFETY: fallocate64 takes a descriptor, a mode and two 64-bit
        // offsets, also on 32-bit targets.
        unsafe { libc::fallocate64(fd, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, offset, len) }
    };
    if r == 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        // Not offered here, or a range the device cannot take: write instead.
        Some(code) if [EOPNOTSUPP, ENOSYS, EINVAL, ENOTTY, ENODEV].contains(&code) => Ok(false),
        _ => Err(e),
    }
}

/// Returns the size in bytes of the block device behind `fd`.
pub(crate) fn block_device_size(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let mut size: u64 = 0;
    // SAFETY: BLKGETSIZE64 stores a u64 through the pointer and nothing
    // else; the pointer is valid for the duration of the call.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), uapi::BLKGETSIZE64, &mut size as *mut u64) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(size)
}

/// Reads the sysfs attribute `name` of the device directory `dir`: a short
/// text, read through a descriptor opened relative to the directory.
fn read_sysattr(dir: BorrowedFd<'_>, name: &[u8]) -> io::Result<String> {
    let fd = open_at(
        dir.as_raw_fd(),
        &filename(name)?,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY,
        0,
    )?;
    let mut text = String::new();
    File::from(fd).take(4096).read_to_string(&mut text)?;
    Ok(text)
}

/// The major and minor number of a device number: the split glibc's
/// gnu_dev_major() and gnu_dev_minor() make.
fn devnum_parts(dev: u64) -> (u64, u64) {
    (u64::from(libc::major(dev)), u64::from(libc::minor(dev)))
}

/// The sysfs directory of the block device with the device number `dev`,
/// found the way sd_device_new_from_devnum() finds it, or None when sysfs
/// does not know the device or is not mounted at all.
///
/// /sys/dev/block/MAJOR:MINOR is the kernel's stable map from a device
/// number to its device and the one path spelled out here. It is opened
/// once as a directory (the kernel's symbolic link to the device is
/// followed, that is what the map is for), has to be on sysfs, and has to
/// describe that very device number: its "dev" attribute is read back and
/// compared, as device_new_from_mode_and_devnum() compares it (ENXIO).
/// Attributes are then read relative to the directory.
fn sysfs_block_device(dev: u64) -> io::Result<Option<OwnedFd>> {
    let (major, minor) = devnum_parts(dev);
    let devnum = format!("{}:{}", major, minor);
    let dir = match open_path(None, Path::new(&format!("/sys/dev/block/{}", devnum)), true) {
        Ok(dir) => dir,
        Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(None),
        Err(e) => return Err(e),
    };
    if fs_kind(dir.as_fd())? != FsKind::Sysfs {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "/sys/dev/block is not on sysfs",
        ));
    }
    if read_sysattr(dir.as_fd(), b"dev")?.trim() != devnum {
        return Err(errno(ENXIO));
    }
    Ok(Some(dir))
}

/// The "start" attribute of a block device's sysfs directory, in bytes:
/// the partition's first sector in 512 byte units whatever the device's
/// block size (block/partitions/core.c, part_start_show), or 0 for a whole
/// disk, which has no such attribute.
fn sysfs_partition_start(dir: BorrowedFd<'_>) -> io::Result<u64> {
    match read_sysattr(dir, b"start") {
        Ok(text) => text
            .trim()
            .parse::<u64>()
            .ok()
            .and_then(|sectors| sectors.checked_mul(512))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bogus partition start in sysfs")),
        Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(0),
        Err(e) => Err(e),
    }
}

/// Where the partition behind the block device `fd` starts on its disk, in
/// bytes; 0 for a whole disk.
///
/// No ioctl tells; the kernel publishes a partition's start in sysfs only.
/// systemd reads such attributes through sd_device_new_from_devnum() and
/// sd_device_get_sysattr_value(), and mkfs.fat takes the same value from
/// libudev for its hidden sectors field. The device number comes from
/// fstat() on the descriptor, [`sysfs_block_device`] finds and verifies
/// the device's directory, and the attribute is read relative to it.
pub(crate) fn partition_start(fd: BorrowedFd<'_>) -> io::Result<u64> {
    let md = fstat(fd)?;
    if !md.file_type().is_block_device() {
        return Err(errno(ENOTTY));
    }
    match sysfs_block_device(md.rdev())? {
        // No sysfs, or a device it does not know: nothing to learn, and a
        // whole disk has no start anyway.
        None => Ok(0),
        Some(dir) => sysfs_partition_start(dir.as_fd()),
    }
}

/// Returns the logical block size of the block device behind `fd`.
pub(crate) fn block_device_logical_block_size(fd: BorrowedFd<'_>) -> io::Result<u32> {
    let mut size: c_int = 0;
    // SAFETY: BLKSSZGET stores an int through the pointer and nothing else;
    // the pointer is valid for the duration of the call.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::BLKSSZGET, &mut size as *mut c_int) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(size)
        .ok()
        .filter(|&size| size > 0)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bogus logical block size"))
}

/// Creates a FIFO, for the tests of the opens. Spawning mkfifo(1) would
/// hand the child every open descriptor until it execs, locks included.
#[cfg(test)]
pub(crate) fn make_fifo(path: &Path) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: a valid NUL terminated path; mkfifo touches nothing else.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::EEXIST;
    use crate::test_util::TempDir;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn code(e: io::Error) -> i32 {
        e.raw_os_error().unwrap_or(0)
    }

    #[test]
    fn pin_entry_takes_one_name_and_never_follows() {
        let tmp = TempDir::new("pin");
        let dir = tmp.path();
        fs::write(dir.join("file"), b"data").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        let d = open_path(None, dir, true).unwrap();
        assert!(fstat(pin_entry(d.as_fd(), b"file").unwrap().as_fd()).unwrap().is_file());
        assert!(fstat(pin_entry(d.as_fd(), b"sub").unwrap().as_fd()).unwrap().is_dir());
        let link = pin_entry(d.as_fd(), b"link").unwrap();
        assert!(fstat(link.as_fd()).unwrap().file_type().is_symlink());
        assert_eq!(code(pin_entry(d.as_fd(), b"missing").unwrap_err()), ENOENT);
        for bad in [&b""[..], b".", b"..", b"sub/file", b"a\0b"] {
            assert_eq!(
                pin_entry(d.as_fd(), bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        // pin_name() follows the link in its place but takes one name only.
        assert!(fstat(pin_name(d.as_fd(), b"link", false).unwrap().as_fd())
            .unwrap()
            .is_file());
        assert!(fstat(pin_name(d.as_fd(), b"sub", true).unwrap().as_fd())
            .unwrap()
            .is_dir());
        assert_eq!(code(pin_name(d.as_fd(), b"missing", false).unwrap_err()), ENOENT);
        assert_eq!(
            pin_name(d.as_fd(), b"sub/file", false).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// A pinned regular file becomes readable, a pinned directory listable;
    /// the inode is the one that was pinned even after a rename.
    #[test]
    fn reopen_turns_pinned_inodes_into_open_files() {
        let tmp = TempDir::new("reopen");
        let dir = tmp.path();
        fs::write(dir.join("file"), b"contents").unwrap();
        let d = open_path(None, dir, true).unwrap();
        let pinned = pin_entry(d.as_fd(), b"file").unwrap();
        fs::rename(dir.join("file"), dir.join("moved")).unwrap();
        fs::write(dir.join("file"), b"impostor").unwrap();
        let mut text = String::new();
        File::from(reopen(pinned.as_fd(), O_RDONLY).unwrap())
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "contents");
        assert_eq!(code(reopen(pinned.as_fd(), O_RDONLY | O_CREAT).unwrap_err()), EINVAL);
        assert_eq!(code(reopen(pinned.as_fd(), O_RDONLY | O_NOFOLLOW).unwrap_err()), ELOOP);
        // Each way of reopening works, whatever the kernel offers.
        EMPTYPATH.store(PROBE_MISSING, Ordering::Relaxed);
        let mut text = String::new();
        File::from(reopen(pinned.as_fd(), O_RDONLY).unwrap())
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "contents");
        assert!(reopen(d.as_fd(), O_RDONLY | O_DIRECTORY).is_ok());
        EMPTYPATH.store(PROBE_UNKNOWN, Ordering::Relaxed);
    }

    #[test]
    fn create_file_at_never_replaces_anything() {
        let tmp = TempDir::new("create");
        let dir = tmp.path();
        let d = open_path(None, dir, true).unwrap();
        let f = create_file_at(d.as_fd(), b"new", 0o644).unwrap();
        assert!(f.metadata().unwrap().is_file());
        assert_eq!(code(create_file_at(d.as_fd(), b"new", 0o644).unwrap_err()), EEXIST);
        symlink("elsewhere", dir.join("dangling")).unwrap();
        assert_eq!(code(create_file_at(d.as_fd(), b"dangling", 0o644).unwrap_err()), EEXIST);
        assert!(!dir.join("elsewhere").exists());
    }

    #[test]
    fn fs_kind_tells_file_systems_apart() {
        let proc = open_path(None, Path::new("/proc"), true).unwrap();
        let sys = open_path(None, Path::new("/sys"), true).unwrap();
        // Either may be missing in a chroot; where it is there it is itself.
        if let Ok(k) = fs_kind(proc.as_fd()) {
            assert_ne!(k, FsKind::Sysfs);
        }
        if let Ok(k) = fs_kind(sys.as_fd()) {
            assert_ne!(k, FsKind::Proc);
        }
        let tmp = TempDir::new("fstype");
        let dir = tmp.path();
        let d = open_path(None, dir, true).unwrap();
        assert_eq!(fs_kind(d.as_fd()).unwrap(), FsKind::Other);
    }

    /// Every device sysfs lists under /sys/dev/block is found again by its
    /// device number and reports that number back; a device number nobody
    /// has is None. Needs no root, sysfs is world readable.
    #[test]
    fn sysfs_block_devices_are_found_by_devnum() {
        assert_eq!(devnum_parts(libc::makedev(8, 17)), (8, 17));
        assert_eq!(devnum_parts(libc::makedev(259, 0x1_2345)), (259, 0x1_2345));
        assert_eq!(devnum_parts(libc::makedev(0xf_ffff, 0xf_ffff)), (0xf_ffff, 0xf_ffff));
        let Ok(all) = open_path(None, Path::new("/sys/dev/block"), true) else {
            return eprintln!("skipping: no /sys/dev/block");
        };
        if fs_kind(all.as_fd()).unwrap() != FsKind::Sysfs {
            return eprintln!("skipping: /sys is not sysfs");
        }
        // Major 0 is no block device major; sysfs knows no such device.
        assert!(sysfs_block_device(libc::makedev(0, 0)).unwrap().is_none());
        assert!(sysfs_block_device(libc::makedev(0, 12345)).unwrap().is_none());
    }

    #[test]
    fn partition_start_wants_a_block_device() {
        let tmp = TempDir::new("partstart");
        let dir = tmp.path();
        let d = open_path(None, dir, true).unwrap();
        assert_eq!(code(partition_start(d.as_fd()).unwrap_err()), ENOTTY);
    }
}
