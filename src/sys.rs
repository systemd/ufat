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

use std::collections::VecDeque;
use std::ffi::{c_int, c_long, c_uint, CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::mem::{ManuallyDrop, MaybeUninit};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::errno::{
    EAGAIN, EBADF, EINVAL, EIO, ELOOP, ENODEV, ENOENT, ENOSYS, ENOTDIR, ENOTTY, ENXIO, EOPNOTSUPP, EPERM,
};

// The open(2) flags. libc has the values of each architecture: alpha,
// arm, arm64, m68k, mips, parisc, powerpc and sparc number some of them
// differently from include/uapi/asm-generic/fcntl.h.
pub(crate) const O_RDONLY: c_int = libc::O_RDONLY;
pub(crate) const O_WRONLY: c_int = libc::O_WRONLY;
pub(crate) const O_RDWR: c_int = libc::O_RDWR;
/// The access mode bits of the flags.
pub(crate) const O_ACCMODE: c_int = libc::O_ACCMODE;
/// Every write goes to the end, whatever offset it names: pwrite() on
/// such a descriptor appends (pwrite(2), BUGS), which is why an image
/// descriptor must not carry it.
pub(crate) const O_APPEND: c_int = libc::O_APPEND;
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
pub(crate) use uapi::{O_EMPTYPATH, O_LARGEFILE};

/// NAME_MAX, include/uapi/linux/limits.h: the longest file name.
const NAME_MAX: usize = libc::NAME_MAX as usize;

/// Steps a resolution by hand may take before we assume a loop, the
/// CHASE_MAX of src/basic/chase.h: if people change the tree behind our
/// back they might send us in circles.
const CHASE_MAX: usize = 128;

fn errno(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// Makes a system call until no signal interrupts it, and turns a negative
/// return into the error in errno.
fn retry(mut call: impl FnMut() -> isize) -> io::Result<usize> {
    loop {
        if let Ok(n) = usize::try_from(call()) {
            return Ok(n);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
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

/// Whether openat2 is available: unknown, yes, or no (an old kernel, or a
/// seccomp filter that answers ENOSYS on purpose, as systemd's does).
static OPENAT2: AtomicU8 = AtomicU8::new(PROBE_UNKNOWN);

fn openat2(dir: BorrowedFd<'_>, path: &CStr, how: &libc::open_how) -> io::Result<OwnedFd> {
    // SAFETY: the arguments are a directory descriptor, a NUL terminated
    // path, a pointer to an open_how of the size passed along; the kernel
    // reads them for the duration of the call. glibc reads every argument
    // after the number as a long.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            c_long::from(dir.as_raw_fd()),
            path.as_ptr(),
            std::ptr::from_ref(how),
            size_of::<libc::open_how>() as c_long,
        )
    };
    let fd = RawFd::try_from(fd)
        .ok()
        .filter(|&fd| fd >= 0)
        .ok_or_else(io::Error::last_os_error)?;
    // SAFETY: a descriptor the kernel just handed to us and nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Resolves `path` below the directory `root` and pins the result as an
/// O_PATH descriptor. The root is the boundary the way it is for systemd's
/// chase() with a root: an absolute symbolic link target starts over at
/// the root, ".." at the root stays there, and nothing resolves to
/// anything outside it. Ordinary symbolic links are followed only when
/// `follow_symlinks` is set, otherwise any on the way fails with ELOOP.
/// Magic links (the ones under /proc) are never followed: that is
/// RESOLVE_NO_MAGICLINKS, which chase() itself does not ask for; a link
/// that jumps to an inode has no business in a tree we copy. With
/// `directory` the result has to be one, as it has when the path ends in
/// a slash.
///
/// The kernel does the walk through openat2(RESOLVE_IN_ROOT) when it can;
/// without openat2 (Linux before 5.6, or a seccomp filter saying ENOSYS or
/// EPERM), and when the kernel reports EAGAIN because a mount or rename
/// elsewhere raced with a ".." step, the walk is done by hand in
/// [`chase_by_hand`], as chase() falls back to its own loop.
pub(crate) fn chase(root: BorrowedFd<'_>, path: &[u8], follow_symlinks: bool, directory: bool) -> io::Result<OwnedFd> {
    if OPENAT2.load(Ordering::Relaxed) != PROBE_MISSING {
        let c = cstring(if path.is_empty() { b"." } else { path })?;
        // SAFETY: open_how is made of integers, and zero is a valid value
        // for each. libc marks it non_exhaustive, so it is zeroed and then
        // filled in.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (O_PATH | O_CLOEXEC | if directory { O_DIRECTORY } else { 0 }) as u64;
        how.resolve = libc::RESOLVE_IN_ROOT
            | libc::RESOLVE_NO_MAGICLINKS
            | if follow_symlinks { 0 } else { libc::RESOLVE_NO_SYMLINKS };
        match openat2(root, &c, &how) {
            Ok(fd) => return Ok(fd),
            Err(e) => match e.raw_os_error() {
                Some(ENOSYS) => OPENAT2.store(PROBE_MISSING, Ordering::Relaxed),
                // EPERM may be a filter or a real permission problem, the
                // walk by hand will report the latter again; EAGAIN is the
                // kernel giving up on a ".." step after a concurrent mount
                // or rename anywhere on the system.
                Some(EPERM | EAGAIN) => {}
                _ => return Err(e),
            },
        }
    }
    chase_by_hand(root, path, follow_symlinks, directory)
}

/// The components of a path for the walk by hand: empty ones and "." carry
/// nothing.
fn components(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".")
}

/// [`chase`] without openat2: one component at a time, each pinned as an
/// O_PATH descriptor relative to the previous one and never followed by the
/// kernel, a symbolic link read through its own descriptor and its target
/// put back in front of what is left to do, ".." checked against the
/// root's identity. After [`CHASE_MAX`] steps the walk gives up with ELOOP.
pub(crate) fn chase_by_hand(
    root: BorrowedFd<'_>,
    path: &[u8],
    follow_symlinks: bool,
    directory: bool,
) -> io::Result<OwnedFd> {
    let root_md = fstat(root)?;
    if !root_md.is_dir() {
        return Err(errno(ENOTDIR));
    }
    // A path ending in "/", "/." or "/..", and "." or ".." itself, can only
    // name a directory. The kernel enforces that on its own walk; chaseat()
    // turns it into CHASE_MUST_BE_DIRECTORY for its own, and so do we.
    let directory = directory
        || path.ends_with(b"/")
        || path.ends_with(b"/.")
        || path.ends_with(b"/..")
        || path == b"."
        || path == b"..";
    let todo = components(path).map(<[u8]>::to_vec).collect();
    walk_from(
        root,
        &root_md,
        root.try_clone_to_owned()?,
        todo,
        follow_symlinks,
        directory,
    )
}

/// Follows the symbolic link `link`, an entry of the directory `dir` pinned
/// without following it, to what it names below `root`: the way the walk by
/// hand treats a link it meets, except that it starts from the directory the
/// link is in rather than from the root, so nothing between the root and
/// the link is looked up by name again. An absolute target starts over at
/// `root`, ".." at the root stays there. openat2 cannot express a start
/// that is not the root, so this is always the walk by hand.
pub(crate) fn follow_link_at(root: BorrowedFd<'_>, dir: BorrowedFd<'_>, link: BorrowedFd<'_>) -> io::Result<OwnedFd> {
    let root_md = fstat(root)?;
    if !root_md.is_dir() {
        return Err(errno(ENOTDIR));
    }
    let (todo, absolute) = link_target(link)?;
    let start = if absolute { root } else { dir };
    walk_from(root, &root_md, start.try_clone_to_owned()?, todo, true, false)
}

/// The components of the target of the symbolic link `link`, read through
/// the link's own descriptor, and whether the target is absolute. An empty
/// target is EINVAL. A magic link jumps to an inode rather than to a path;
/// its text is what the inode would be called ("/dev/pts/3") or a
/// "type:[inode]" tag. Resolving that text below the root could not escape
/// anyway, but openat2 refuses the link with RESOLVE_NO_MAGICLINKS and so
/// do we (ELOOP). The plain symbolic links of procfs, /proc/self or
/// /proc/mounts, name a relative path.
fn link_target(link: BorrowedFd<'_>) -> io::Result<(VecDeque<Vec<u8>>, bool)> {
    let target = readlink(link)?;
    if target.is_empty() {
        return Err(errno(EINVAL));
    }
    if (target[0] == b'/' || target.contains(&b':')) && fs_kind(link)? == FsKind::Proc {
        return Err(errno(ELOOP));
    }
    Ok((components(&target).map(<[u8]>::to_vec).collect(), target[0] == b'/'))
}

/// The steps of the walk by hand: `todo` resolved component by component
/// from the pinned directory `fd`, with `root` as the boundary.
fn walk_from(
    root: BorrowedFd<'_>,
    root_md: &std::fs::Metadata,
    mut fd: OwnedFd,
    mut todo: VecDeque<Vec<u8>>,
    follow_symlinks: bool,
    directory: bool,
) -> io::Result<OwnedFd> {
    let mut steps = 0;
    while let Some(first) = todo.pop_front() {
        steps += 1;
        if steps > CHASE_MAX {
            return Err(errno(ELOOP));
        }
        if first == b".." {
            // At the root going up changes nothing, as with RESOLVE_IN_ROOT.
            let md = fstat(fd.as_fd())?;
            if md.dev() == root_md.dev() && md.ino() == root_md.ino() {
                continue;
            }
            fd = open_at(fd.as_raw_fd(), c"..", O_PATH | O_NOFOLLOW | O_DIRECTORY, 0)?;
            continue;
        }
        let child = open_at(fd.as_raw_fd(), &cstring(&first)?, O_PATH | O_NOFOLLOW, 0)?;
        if fstat(child.as_fd())?.file_type().is_symlink() {
            if !follow_symlinks {
                return Err(errno(ELOOP));
            }
            let (target, absolute) = link_target(child.as_fd())?;
            if absolute {
                fd = root.try_clone_to_owned()?;
            }
            for c in target.into_iter().rev() {
                todo.push_front(c);
            }
            continue;
        }
        fd = child;
    }
    if directory && !fstat(fd.as_fd())?.is_dir() {
        return Err(errno(ENOTDIR));
    }
    Ok(fd)
}

/// The target of the symbolic link `link` refers to, read through the
/// descriptor itself (`readlinkat(fd, "")`), so that nothing is looked up
/// again.
fn readlink(link: BorrowedFd<'_>) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    loop {
        // SAFETY: an empty path makes readlinkat read the link the
        // descriptor refers to; it writes at most buf.len() bytes into buf.
        let n = unsafe { libc::readlinkat(link.as_raw_fd(), c"".as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
        if n < buf.len() {
            buf.truncate(n);
            return Ok(buf);
        }
        // Filled to the brim: the target may be longer, try again with
        // more room, up to the longest path there is.
        if buf.len() >= 65536 {
            return Err(errno(ELOOP));
        }
        buf.resize(buf.len() * 2, 0);
    }
}

/// The open flags of a descriptor as the kernel keeps them (F_GETFL): the
/// access mode and the status flags; O_CREAT, O_EXCL, O_NOCTTY and
/// O_TRUNC are not kept and O_CLOEXEC lives elsewhere.
pub(crate) fn descriptor_flags(fd: BorrowedFd<'_>) -> io::Result<c_int> {
    // SAFETY: F_GETFL takes no argument and reads nothing through a
    // pointer.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(flags)
}

/// Raises the soft limit on open descriptors to the hard limit and returns
/// the soft limit in force afterwards, the way systemd's
/// rlimit_nofile_bump() does for every tool: the soft limit of 1024 a
/// process starts with is select()'s and nothing here uses select().
pub(crate) fn raise_descriptor_limit() -> io::Result<u64> {
    // prlimit64() carries 64 bits on every architecture, unlike struct
    // rlimit.
    let mut old = libc::rlimit64 {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: pid 0 is the calling process; no new limit is passed and
    // `old` is a struct of the layout the kernel fills in.
    if unsafe { libc::prlimit64(0, libc::RLIMIT_NOFILE, std::ptr::null(), &mut old) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if old.rlim_cur >= old.rlim_max {
        return Ok(old.rlim_cur);
    }
    let new = libc::rlimit64 {
        rlim_cur: old.rlim_max,
        rlim_max: old.rlim_max,
    };
    // SAFETY: as above, with a new limit of that layout and no old one asked for.
    if unsafe { libc::prlimit64(0, libc::RLIMIT_NOFILE, &new, std::ptr::null_mut()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(new.rlim_cur)
}

/// The metadata of what `fd` refers to, an O_PATH descriptor included:
/// fstat (statx where std has it) on the descriptor, never on a path.
pub(crate) fn fstat(fd: BorrowedFd<'_>) -> io::Result<std::fs::Metadata> {
    // SAFETY: the File is never dropped, so the descriptor, which we do not
    // own, stays open; std only calls fstat or statx on it.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd.as_raw_fd()) });
    file.metadata()
}

/// Reads from `fd` at `offset` without touching its file position.
pub(crate) fn pread(fd: BorrowedFd<'_>, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    // SAFETY: the File is never dropped, so the descriptor, which we do not
    // own, stays open; std only calls pread on it.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd.as_raw_fd()) });
    file.read_at(buf, offset)
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
    // f_type and the magic numbers are a long with glibc and an unsigned
    // int on s390x. With musl f_type is an unsigned long and the magic
    // numbers are a long. All of them widen, and the two magic numbers
    // asked for here are positive as a long of 32 bits too.
    let fs_type = i128::from(st.f_type);
    Ok(if fs_type == i128::from(libc::PROC_SUPER_MAGIC) {
        FsKind::Proc
    } else if fs_type == i128::from(libc::SYSFS_MAGIC) {
        FsKind::Sysfs
    } else {
        FsKind::Other
    })
}

/// The names in the directory `dir`, in the order the file system hands
/// them out, without "." and "..": getdents64 on the descriptor into a
/// buffer, the records walked by their d_reclen, as systemd's
/// readdir_all() does. The descriptor has to be open for reading
/// (O_DIRECTORY, not O_PATH); its position ends up at the end.
pub(crate) fn list_dir(dir: BorrowedFd<'_>) -> io::Result<Vec<Vec<u8>>> {
    // struct linux_dirent64: d_ino u64, d_off s64, d_reclen u16, d_type u8,
    // then d_name, NUL terminated and padded to the record length.
    const HEADER: usize = 8 + 8 + 2 + 1;
    const RECLEN: usize = 8 + 8;
    // The kernel stores d_ino and d_off of every record at an offset
    // aligned for them, so the buffer is made of u64: 32 KiB.
    let mut words = vec![0u64; 4 * 1024];
    let len = size_of_val(words.as_slice());
    let mut names = Vec::new();
    loop {
        let n = retry(|| {
            // SAFETY: getdents64 writes at most `len` bytes into the
            // buffer. The libc crate has no getdents64(), and glibc's
            // syscall() reads every argument after the number as a long.
            unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    c_long::from(dir.as_raw_fd()),
                    words.as_mut_ptr(),
                    len as c_long,
                ) as isize
            }
        })?;
        if n == 0 {
            return Ok(names);
        }
        if n > len {
            return Err(errno(EIO));
        }
        // SAFETY: the bytes of the buffer, all initialized; a u8 has no
        // alignment and every value is valid.
        let buf = unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), len) };
        let mut off = 0;
        while off < n {
            if n - off < HEADER {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "truncated directory entry"));
            }
            let reclen = usize::from(u16::from_ne_bytes([buf[off + RECLEN], buf[off + RECLEN + 1]]));
            if reclen < HEADER || reclen > n - off {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "bogus directory entry length",
                ));
            }
            let name = &buf[off + HEADER..off + reclen];
            let name = CStr::from_bytes_until_nul(name).map_or(name, CStr::to_bytes);
            if !name.is_empty() && name != b"." && name != b".." {
                names.push(name.to_vec());
            }
            off += reclen;
        }
    }
}

/// Fills `buf` from the kernel's random number generator, getrandom(2),
/// going on after a short read or a signal. There is no reason to open
/// /dev/urandom for this, systemd's random_bytes() doesn't either.
pub(crate) fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let rest = &mut buf[done..];
        let n = retry(|| {
            // SAFETY: getrandom writes at most rest.len() bytes into rest.
            unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) }
        })?;
        if n == 0 {
            return Err(errno(EIO));
        }
        done += n;
    }
    Ok(())
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

    fn sorted(mut names: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        names.sort();
        names
    }

    /// Many names, the longest name there is, and more entries than one
    /// getdents64 buffer holds: the listing matches std's.
    #[test]
    fn list_dir_reads_whole_directories() {
        let tmp = TempDir::new("list");
        let dir = tmp.path();
        let long = "n".repeat(255);
        fs::write(dir.join(&long), b"").unwrap();
        for i in 0..2000 {
            fs::write(dir.join(format!("f{:04}", i)), b"").unwrap();
        }
        // 300 names of 255 bytes take 300 records of 280 bytes, several
        // 32 KiB buffers.
        for i in 0..300 {
            fs::write(dir.join(format!("{:03}{}", i, &long[3..])), b"").unwrap();
        }
        let expected: Vec<Vec<u8>> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().as_bytes().to_vec())
            .collect();
        assert_eq!(expected.len(), 2301);
        let listing = open_path(None, dir, true).unwrap();
        let listing = reopen(listing.as_fd(), O_RDONLY | O_DIRECTORY).unwrap();
        let names = list_dir(listing.as_fd()).unwrap();
        assert_eq!(sorted(names), sorted(expected));
        // Read to the end, a second call sees nothing more.
        assert!(list_dir(listing.as_fd()).unwrap().is_empty());
        // An O_PATH descriptor cannot be listed.
        let pinned = open_path(None, dir, true).unwrap();
        assert!(list_dir(pinned.as_fd()).is_err());
        let empty = dir.join("empty");
        fs::create_dir(&empty).unwrap();
        let e = reopen(open_path(None, &empty, true).unwrap().as_fd(), O_RDONLY | O_DIRECTORY).unwrap();
        assert!(list_dir(e.as_fd()).unwrap().is_empty());
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
        assert_eq!(readlink(link.as_fd()).unwrap(), b"file");
        assert_eq!(code(pin_entry(d.as_fd(), b"missing").unwrap_err()), ENOENT);
        for bad in [&b""[..], b".", b"..", b"sub/file", b"a\0b"] {
            assert_eq!(
                pin_entry(d.as_fd(), bad).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(code(open_path(None, &dir.join("file"), true).unwrap_err()), ENOTDIR);
        // pin_name() follows the link in its place but takes one name only.
        assert!(fstat(pin_name(d.as_fd(), b"link", false).unwrap().as_fd())
            .unwrap()
            .is_file());
        assert!(fstat(pin_name(d.as_fd(), b"sub", true).unwrap().as_fd())
            .unwrap()
            .is_dir());
        assert_eq!(code(pin_name(d.as_fd(), b"link", true).unwrap_err()), ENOTDIR);
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
        let listing = reopen(d.as_fd(), O_RDONLY | O_DIRECTORY).unwrap();
        assert_eq!(
            sorted(list_dir(listing.as_fd()).unwrap()),
            vec![b"file".to_vec(), b"moved".to_vec()]
        );
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

    /// The escapes a resolution below a root has to refuse, against the
    /// kernel's walk and against ours.
    fn check_chase(chase: fn(BorrowedFd<'_>, &[u8], bool, bool) -> io::Result<OwnedFd>, name: &str) {
        let tmp = TempDir::new(name);
        let dir = tmp.path();
        fs::create_dir_all(dir.join("root/sub/deep")).unwrap();
        fs::write(dir.join("root/sub/deep/file"), b"inside").unwrap();
        fs::write(dir.join("root/top"), b"top").unwrap();
        fs::write(dir.join("outside"), b"outside").unwrap();
        symlink("deep/file", dir.join("root/sub/rel")).unwrap();
        symlink("/top", dir.join("root/sub/abs")).unwrap();
        symlink("../../outside", dir.join("root/sub/up")).unwrap();
        symlink(dir.join("outside"), dir.join("root/sub/far")).unwrap();
        symlink("loop", dir.join("root/loop")).unwrap();
        symlink("/proc/self/fd/0", dir.join("root/magic")).unwrap();
        let root = open_path(None, &dir.join("root"), true).unwrap();
        let text = |fd: OwnedFd| {
            let mut s = String::new();
            File::from(reopen(fd.as_fd(), O_RDONLY).unwrap())
                .read_to_string(&mut s)
                .unwrap();
            s
        };
        assert_eq!(
            text(chase(root.as_fd(), b"sub/deep/file", false, false).unwrap()),
            "inside"
        );
        assert_eq!(
            text(chase(root.as_fd(), b"/sub//deep/./file", false, false).unwrap()),
            "inside"
        );
        assert!(fstat(chase(root.as_fd(), b"", false, true).unwrap().as_fd())
            .unwrap()
            .is_dir());
        assert!(fstat(chase(root.as_fd(), b"sub", false, true).unwrap().as_fd())
            .unwrap()
            .is_dir());
        assert_eq!(code(chase(root.as_fd(), b"top", false, true).unwrap_err()), ENOTDIR);
        // A trailing slash, "/." or "/.." names a directory or nothing.
        for dir in [&b"sub/"[..], b"sub/.", b"sub/deep/..", b".", b"..", b"/"] {
            assert!(
                fstat(chase(root.as_fd(), dir, false, false).unwrap().as_fd())
                    .unwrap()
                    .is_dir(),
                "{:?}",
                dir
            );
        }
        assert_eq!(code(chase(root.as_fd(), b"top/", false, false).unwrap_err()), ENOTDIR);
        assert_eq!(code(chase(root.as_fd(), b"top/.", false, false).unwrap_err()), ENOTDIR);
        assert_eq!(code(chase(root.as_fd(), b"missing", false, false).unwrap_err()), ENOENT);
        assert_eq!(code(chase(root.as_fd(), b"top/x", false, false).unwrap_err()), ENOTDIR);
        // Without following, every symbolic link is a dead end.
        for link in [&b"sub/rel"[..], b"sub/abs", b"sub/up", b"sub/far", b"loop"] {
            assert_eq!(
                code(chase(root.as_fd(), link, false, false).unwrap_err()),
                ELOOP,
                "{:?}",
                link
            );
        }
        // Following stays inside the root: an absolute target starts at
        // the root, ".." above the root stays at the root, a target that
        // leads outside is looked for inside.
        assert_eq!(text(chase(root.as_fd(), b"sub/rel", true, false).unwrap()), "inside");
        assert_eq!(text(chase(root.as_fd(), b"sub/abs", true, false).unwrap()), "top");
        assert_eq!(text(chase(root.as_fd(), b"../../top", true, false).unwrap()), "top");
        assert_eq!(text(chase(root.as_fd(), b"sub/../top", true, false).unwrap()), "top");
        assert_eq!(code(chase(root.as_fd(), b"sub/up", true, false).unwrap_err()), ENOENT);
        assert_eq!(code(chase(root.as_fd(), b"sub/far", true, false).unwrap_err()), ENOENT);
        assert_eq!(code(chase(root.as_fd(), b"loop", true, false).unwrap_err()), ELOOP);
        assert_eq!(code(chase(root.as_fd(), b"magic", true, false).unwrap_err()), ENOENT);
        // A magic link itself is refused, with the root being /proc.
        let proc = open_path(None, Path::new("/proc"), true).unwrap();
        if fs_kind(proc.as_fd()).unwrap() == FsKind::Proc {
            assert_eq!(code(chase(proc.as_fd(), b"self/fd/0", true, false).unwrap_err()), ELOOP);
            assert!(fstat(chase(proc.as_fd(), b"self/fd", true, true).unwrap().as_fd())
                .unwrap()
                .is_dir());
        }
    }

    #[test]
    fn chase_stays_below_the_root() {
        check_chase(chase, "chase");
    }

    #[test]
    fn chase_by_hand_stays_below_the_root() {
        check_chase(chase_by_hand, "chase-by-hand");
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
    fn raising_the_descriptor_limit_sticks() {
        let raised = raise_descriptor_limit().unwrap();
        assert!(raised > 0);
        // Raised already: the same limit comes back.
        assert_eq!(raise_descriptor_limit().unwrap(), raised);
        // And it is the limit on open files, RLIMIT_NOFILE, which mips and
        // sparc number differently.
        let Ok(limits) = fs::read_to_string("/proc/self/limits") else {
            return eprintln!("skipping: no /proc/self/limits");
        };
        let line = limits.lines().find(|l| l.starts_with("Max open files")).unwrap();
        assert_eq!(line.split_whitespace().nth(3), Some(raised.to_string().as_str()));
    }

    /// F_GETFL shows exactly what a plain open sets: the access mode and
    /// O_LARGEFILE, which the kernel adds for a 64-bit process and glibc's
    /// open64() for a 32-bit one. With a wrong O_LARGEFILE every descriptor
    /// passed to the service would be refused.
    #[test]
    fn a_plain_open_has_the_access_mode_and_o_largefile() {
        let tmp = TempDir::new("flags");
        let path = tmp.path().join("file");
        fs::write(&path, b"").unwrap();
        let file = File::open(&path).unwrap();
        assert_eq!(descriptor_flags(file.as_fd()).unwrap(), O_RDONLY | O_LARGEFILE);
    }

    /// Where the kernel knows O_EMPTYPATH, an empty path with it reopens
    /// what a descriptor pins, and F_GETFL shows the flag. With a wrong
    /// value [`reopen`] would fall back to procfs without a word. openat2
    /// tells whether the kernel knows the flag: it refuses unknown flags
    /// with EINVAL, where openat ignores them.
    #[test]
    fn o_emptypath_reopens_where_the_kernel_has_it() {
        let tmp = TempDir::new("emptypath");
        let path = tmp.path().join("file");
        fs::write(&path, b"").unwrap();
        let pinned = open_path(None, &path, false).unwrap();
        // SAFETY: open_how is made of integers, and zero is a valid value
        // for each.
        let mut how: libc::open_how = unsafe { std::mem::zeroed() };
        how.flags = (O_RDONLY | O_CLOEXEC | O_EMPTYPATH) as u64;
        match openat2(pinned.as_fd(), c"", &how) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(EINVAL) => {
                return eprintln!("skipping: the kernel does not know O_EMPTYPATH");
            }
            Err(e) if e.raw_os_error() == Some(ENOSYS) => {
                return eprintln!("skipping: the kernel has no openat2");
            }
            Err(e) => panic!("openat2 with O_EMPTYPATH failed: {}", e),
        }
        let file = open_at(pinned.as_raw_fd(), c"", O_RDONLY | O_EMPTYPATH, 0).unwrap();
        assert_eq!(
            descriptor_flags(file.as_fd()).unwrap(),
            O_RDONLY | O_LARGEFILE | O_EMPTYPATH
        );
    }

    #[test]
    fn random_bytes_fills_the_buffer() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        random_bytes(&mut a).unwrap();
        random_bytes(&mut b).unwrap();
        assert_ne!(a, b);
        random_bytes(&mut []).unwrap();
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
        let listing = reopen(all.as_fd(), O_RDONLY | O_DIRECTORY).unwrap();
        for name in sorted(list_dir(listing.as_fd()).unwrap()).iter().take(8) {
            let text = std::str::from_utf8(name).unwrap();
            let (major, minor) = text.split_once(':').unwrap();
            let dev = libc::makedev(major.parse().unwrap(), minor.parse().unwrap());
            // Gone between the listing and the open: a device was removed.
            let Some(dir) = sysfs_block_device(dev).unwrap() else {
                continue;
            };
            assert_eq!(read_sysattr(dir.as_fd(), b"dev").unwrap().trim(), text);
            // A partition has a start, a whole disk reports 0.
            assert_eq!(sysfs_partition_start(dir.as_fd()).unwrap() % 512, 0);
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
