// SPDX-License-Identifier: LGPL-2.1-or-later
//! Host directories: resolving the paths we are given once, and listing
//! trees by descriptor in a reproducible order.
//!
//! The populator, the planner and the manifest generator all walk trees on
//! the host. They share this listing so that they see the same entries in
//! the same order: sorted by the bytes of the file name. That makes images
//! independent of the host file system's readdir order and lets the planner
//! and the generator describe exactly what the populator is going to do.
//!
//! Nothing below the root of a tree is ever named by a path again. Every
//! entry is pinned as an O_PATH descriptor relative to the descriptor of its
//! directory and examined through that descriptor; a file is read and a
//! directory listed by reopening the pinned inode. One entry is pinned at a
//! time and the walk holds one directory per level of the tree, so a large
//! directory costs no descriptors and a deep tree one per level. That is
//! how systemd's recurse_dir() (src/basic/recurse-dir.c) walks a tree, and
//! it means that what we copy is what we looked at, whatever happens to
//! the tree meanwhile.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::device::{Access, Device};
use crate::errno::*;
use crate::sys::{self, Refusal};
use crate::{Context, Error, Result};
use crate::{DescriptorProblem, Detail};

/// The detail of a passed descriptor that cannot be used, passed as
/// `parameter` where the caller named it.
fn unusable(problem: DescriptorProblem, flags: Option<i32>, parameter: Option<&'static str>) -> Detail {
    Detail::Descriptor {
        problem,
        flags,
        parameter,
    }
}

/// Resolves `path`, a directory, once and returns it pinned: the descriptor
/// everything below it is opened relative to. Symbolic links in the path
/// are followed, as the caller naming the directory expects; what is named
/// has to be a directory (ENOTDIR). This is where a path given to us on a
/// command line or over Varlink turns into a descriptor.
pub fn open_dir(path: &Path) -> Result<OwnedFd> {
    sys::open_path(None, path, true).with_context(|| format!("failed to open {}", path.display()))
}

/// Resolves `path`, a regular file, once and opens it for reading: the
/// inode is pinned first, checked to be a regular file (EINVAL otherwise)
/// and only then opened, so a FIFO or a device node in its place is
/// refused without being opened. Symbolic links in the path are followed.
pub fn open_file(path: &Path) -> Result<File> {
    let pinned = sys::open_path(None, path, false).with_context(|| format!("failed to open {}", path.display()))?;
    open_pinned_file(pinned.as_fd(), &path.display())
}

/// Resolves the directory part of `path` once and names its last
/// component: the parent pinned as a descriptor, and the file name to open
/// relative to it with [`open_file_at`]. This is how systemd's
/// chase_and_open() opens a file, and the pair chase_and_open_parent_at()
/// hands out. A path without a file name ("/", "..") is EINVAL; the
/// parent of a bare name is the working directory.
pub fn open_parent(path: &Path) -> Result<(OwnedFd, OsString)> {
    let name = match path.file_name() {
        Some(n) => n.to_os_string(),
        None => bail!(EINVAL, "{} is not the path of a file", path.display()),
    };
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    Ok((open_dir(dir)?, name))
}

/// Checks the open flags of a descriptor another process handed over, the
/// way systemd's fd_verify_safe_flags_full() checks an extrinsic
/// descriptor before a privileged service works with it: an O_PATH
/// descriptor is refused, since it cannot be read or written and reopening
/// it would give the client access it does not have; so is every status
/// flag that is not on the allowlist (the access mode, O_NOFOLLOW,
/// O_EMPTYPATH and O_LARGEFILE, which stick to a descriptor without
/// meaning anything once it is open, plus `extra`). O_APPEND among them
/// would make positional writes append, O_DIRECT would make them fail on
/// alignment, O_NONBLOCK would make reads from a pipe fail at random.
/// Returns the access mode; O_WRONLY is refused since everything here reads.
/// The errors name `parameter`, the name the descriptor was passed as,
/// where the caller has one.
fn vet_flags(fd: BorrowedFd<'_>, extra: i32, what: &str, parameter: Option<&'static str>) -> Result<Access> {
    match vet_status(fd, extra, what, parameter)? {
        sys::O_RDONLY => Ok(Access::ReadOnly),
        sys::O_RDWR => Ok(Access::ReadWrite),
        _ => bail!(
            EBADFD,
            unusable(DescriptorProblem::WriteOnly, None, parameter),
            "the {} descriptor is open for writing only",
            what
        ),
    }
}

/// The checks of [`vet_flags`] up to the access mode, which is returned as
/// it is (O_RDONLY, O_WRONLY or O_RDWR) for the caller to judge.
fn vet_status(fd: BorrowedFd<'_>, extra: i32, what: &str, parameter: Option<&'static str>) -> Result<i32> {
    let flags = sys::descriptor_flags(fd)?;
    if flags & sys::O_PATH != 0 {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::OPath, None, parameter),
            "the {} descriptor was opened with O_PATH and cannot be read",
            what
        );
    }
    let allowed = sys::O_ACCMODE | sys::O_NOFOLLOW | sys::O_EMPTYPATH | sys::O_LARGEFILE | extra;
    let unexpected = flags & !allowed;
    if unexpected != 0 {
        let culprit = if unexpected & sys::O_APPEND != 0 {
            " (O_APPEND among them: writes would append)"
        } else {
            ""
        };
        bail!(
            EBADFD,
            unusable(DescriptorProblem::Flags, Some(unexpected), parameter),
            "the {} descriptor has flags set we cannot work with: 0o{:o}{}",
            what,
            unexpected,
            culprit
        );
    }
    match flags & sys::O_ACCMODE {
        mode @ (sys::O_RDONLY | sys::O_WRONLY | sys::O_RDWR) => Ok(mode),
        other => bail!(
            EBADFD,
            unusable(DescriptorProblem::Flags, Some(other), parameter),
            "the {} descriptor has no valid access mode",
            what
        ),
    }
}

/// Takes a descriptor another process handed over as the image: a regular
/// file or block device, open for reading when the image is only read and
/// for reading and writing when it is written (O_RDWR, since every write
/// reads too; O_WRONLY and O_APPEND are refused), with O_NONBLOCK accepted
/// as it is meaningless on both. A block device to be written is claimed
/// exclusively; no lock is taken on a passed descriptor, the caller holds
/// its own, see [`crate::device::Device::from_passed`].
pub fn passed_image(fd: OwnedFd, access: Access) -> Result<Device> {
    let open_for = vet_flags(fd.as_fd(), sys::O_NONBLOCK, "image", None)?;
    if access == Access::ReadWrite && open_for != Access::ReadWrite {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadWrite, None, None),
            "the image descriptor is not open for reading and writing"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_block_device() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, None),
            "the image descriptor is not a regular file or block device"
        );
    }
    Device::from_passed(fd, access)
}

/// Takes a descriptor another process handed over as a source directory,
/// the root everything below is resolved against: a directory, open for
/// reading only (O_DIRECTORY accepted, O_PATH refused).
pub fn passed_directory(fd: OwnedFd) -> Result<OwnedFd> {
    if vet_flags(fd.as_fd(), sys::O_DIRECTORY, "source directory", None)? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None, None),
            "the source directory descriptor is not open read-only"
        );
    }
    if !sys::fstat(fd.as_fd())?.is_dir() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, None),
            "the source directory descriptor is not a directory"
        );
    }
    Ok(fd)
}

/// Takes a descriptor another process handed over as a file to copy: a
/// regular file open for reading only, read with positional reads from
/// its start, so the position of the client's descriptor is left alone.
pub fn passed_file(fd: OwnedFd) -> Result<File> {
    if vet_flags(fd.as_fd(), 0, "source file", None)? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None, None),
            "the source file descriptor is not open read-only"
        );
    }
    if !sys::fstat(fd.as_fd())?.is_file() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, None),
            "the source file descriptor is not a regular file"
        );
    }
    Ok(File::from(fd))
}

/// A regular file or pipe another process handed over, read or written
/// from where it stands to its end: a manifest, the contents of files in
/// manifest order, or the sink a manifest goes to.
///
/// It was vetted without O_NONBLOCK, but the flag belongs to the open file
/// description, which the client shares through the copy it kept, and the
/// client can set it during the call. A blocking pipe or a regular file
/// never fails with EAGAIN, so a read or write that does while O_NONBLOCK
/// is set fails as the vetting fails a descriptor with the flag: EBADFD
/// with the `Flags` problem. Its detail names the parameter the stream was
/// passed as, since a call can read a manifest and the contents of its
/// files from two streams at once.
#[derive(Debug)]
pub struct PassedStream {
    file: File,
    parameter: &'static str,
}

impl PassedStream {
    /// The metadata of the file or pipe.
    pub fn metadata(&self) -> io::Result<fs::Metadata> {
        self.file.metadata()
    }

    /// The error a read or write returned, or the flags problem when it
    /// would have blocked because O_NONBLOCK is set now.
    fn explain(&self, e: io::Error) -> io::Error {
        if e.kind() != io::ErrorKind::WouldBlock {
            return e;
        }
        match sys::descriptor_flags(self.file.as_fd()) {
            Ok(flags) if flags & sys::O_NONBLOCK != 0 => err!(
                EBADFD,
                unusable(DescriptorProblem::Flags, Some(sys::O_NONBLOCK), Some(self.parameter)),
                "the descriptor was made non-blocking during the call"
            )
            .into(),
            _ => e,
        }
    }
}

impl Read for PassedStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf).map_err(|e| self.explain(e))
    }
}

impl Write for PassedStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf).map_err(|e| self.explain(e))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl AsFd for PassedStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

/// What a source descriptor turned out to be.
#[derive(Debug)]
pub enum PassedSource {
    /// A directory, the tree the files come from.
    Directory(OwnedFd),
    /// A regular file or pipe carrying the files' contents in order.
    Stream(PassedStream),
}

/// Takes a descriptor another process handed over as the source of a
/// manifest's file contents, which its type decides, the way the command
/// line's SOURCE is a directory or "-": a directory, open read-only
/// (O_DIRECTORY accepted), is the tree the manifest describes; a regular
/// file or pipe, open read-only and blocking, carries the contents in
/// manifest order. Anything else is EBADFD. `parameter` is the name the
/// descriptor was passed as, which its errors name, those of reading a
/// stream included.
pub fn passed_source(fd: OwnedFd, parameter: &'static str) -> Result<PassedSource> {
    if vet_flags(fd.as_fd(), sys::O_DIRECTORY, "source", Some(parameter))? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None, Some(parameter)),
            "the source descriptor is not open read-only"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if ft.is_dir() {
        Ok(PassedSource::Directory(fd))
    } else if ft.is_file() || ft.is_fifo() {
        Ok(PassedSource::Stream(PassedStream {
            file: File::from(fd),
            parameter,
        }))
    } else {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, Some(parameter)),
            "the source descriptor is not a directory, a regular file or a pipe"
        );
    }
}

/// Takes a descriptor another process handed over as a stream to read to
/// its end from where it stands, a manifest or the contents of files in
/// manifest order: a regular file or a pipe, open for reading only, without
/// O_NONBLOCK since a pipe would then fail instead of wait. A socket is
/// always open for reading and writing and so never passes here.
/// `parameter` is the name the descriptor was passed as, which its errors
/// name, those of reading the stream included.
pub fn passed_stream(fd: OwnedFd, parameter: &'static str) -> Result<PassedStream> {
    if vet_flags(fd.as_fd(), 0, "stream", Some(parameter))? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None, Some(parameter)),
            "the stream descriptor is not open read-only"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_fifo() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, Some(parameter)),
            "the stream descriptor is not a regular file or pipe"
        );
    }
    Ok(PassedStream {
        file: File::from(fd),
        parameter,
    })
}

/// Takes a descriptor another process handed over as the sink a manifest
/// is written to: a regular file or a pipe, open for writing (O_WRONLY or
/// O_RDWR). O_APPEND is accepted, since the manifest goes out sequentially
/// and where in its file the caller wants it is the caller's business;
/// O_NONBLOCK is not, since a full pipe would then fail instead of wait.
/// A descriptor open read-only is `NotWritable`, anything but a regular
/// file or pipe `WrongType`. `parameter` is the name the descriptor was
/// passed as, which its errors name, those of writing to it included.
pub fn passed_sink(fd: OwnedFd, parameter: &'static str) -> Result<PassedStream> {
    if vet_status(fd.as_fd(), sys::O_APPEND, "sink", Some(parameter))? == sys::O_RDONLY {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotWritable, None, Some(parameter)),
            "the sink descriptor is not open for writing"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_fifo() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None, Some(parameter)),
            "the sink descriptor is not a regular file or pipe"
        );
    }
    Ok(PassedStream {
        file: File::from(fd),
        parameter,
    })
}

/// Raises the soft limit on open descriptors to the hard limit and returns
/// the soft limit in force afterwards: what systemd's tools do when they
/// start (rlimit_nofile_bump()). A tree walk holds one descriptor per level
/// of the tree, so a deep tree wants more than the traditional soft limit
/// of 1024, which only select() ever needed. The tool calls this once at
/// startup; a program embedding the library decides for itself.
pub fn raise_descriptor_limit() -> Result<u64> {
    Ok(sys::raise_descriptor_limit()?)
}

/// Opens the regular file `name` in the directory `dir` for reading, like
/// [`open_file`] does for a path: `name` is a single file name (EINVAL
/// otherwise), looked up relative to the descriptor, so a path the caller
/// already resolved to `dir` is not walked again. That is the last step
/// of systemd's chase_and_open(): the parent is pinned and the final
/// component is opened relative to it.
pub fn open_file_at(dir: BorrowedFd<'_>, name: &OsStr) -> Result<File> {
    let shown = Path::new(name).display();
    let pinned = sys::pin_name(dir, name.as_bytes(), false).with_context(|| format!("failed to open {}", shown))?;
    open_pinned_file(pinned.as_fd(), &shown)
}

/// Checks that the pinned inode is a regular file and reopens it for
/// reading, without waiting for anything and without adopting a terminal.
fn open_pinned_file(pinned: BorrowedFd<'_>, what: &dyn std::fmt::Display) -> Result<File> {
    let md = sys::fstat(pinned)?;
    if !md.is_file() {
        bail!(EINVAL, "{} is not a regular file", what);
    }
    let fd = sys::reopen(pinned, sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)
        .with_context(|| format!("failed to open {}", what))?;
    Ok(File::from(fd))
}

/// The mode a new file is made with before the umask takes its part: read
/// and write for everyone, as std's File::create() and the shell make one.
const NEW_FILE_MODE: u32 = 0o666;

/// A regular file made for a name in a directory, which it gets only once
/// it is complete, so that a command that fails, is killed or crashes
/// before leaves nothing under that name. It is made with O_TMPFILE, without
/// any name, and goes away with its last descriptor until
/// [`NewFile::link`] gives it its name. Where O_TMPFILE is refused, by a
/// file system without it or a kernel that does not know it, it is made
/// under a temporary name in the same directory instead, and the link
/// renames it then. A kill or a crash leaves that temporary name behind.
///
/// A file that must not take the place of another one, [`Naming::Exclusive`],
/// is locked with the exclusive BSD lock an image is written under as soon
/// as it is made. If it has a temporary name, it finds out how it gets its
/// name before anything is written to it: with RENAME_NOREPLACE, or else
/// with a link of its descriptor. Where the file system has neither, as
/// vboxsf and orangefs have neither, the file is made under its name right
/// away with O_CREAT|O_EXCL as the last resort, and a kill or a crash
/// leaves it there.
///
/// Giving a file up removes a temporary name, or the name of the last
/// resort, after checking by device and inode number that the name still
/// refers to the file. A rename onto the name between that check and the
/// removal gets the other file removed, since no unlink is conditional on
/// the inode. That crosses no privilege boundary: whoever can rename onto a
/// name in that directory can remove it as well. An exclusive file has its
/// names removed only while it is locked, by this process, or where the
/// lock cannot be had at all right after the file was made, as NFS without
/// its lock manager refuses it. A file another process locked first keeps
/// its name. Dropping a file that did not get its name gives it up the way
/// [`NewFile::discard`] does, without saying how that went.
#[derive(Debug)]
pub struct NewFile {
    /// The file, open for reading and writing.
    file: File,
    /// The directory it is made in.
    parent: OwnedFd,
    /// The name it is made for.
    name: OsString,
    /// That name as the caller named it, for messages.
    path: PathBuf,
    /// What it does where something has that name when it gets it.
    naming: Naming,
    /// How it waits for that name, which it removes when it is given up.
    /// None once it has that name, or where removing it is not up to it.
    waiting: Option<Waiting>,
}

/// What a [`NewFile`] does where something has its name by the time the
/// file gets that name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Naming {
    /// It does not get the name (EEXIST): a new image, which must not take
    /// the place of a file that came meanwhile.
    Exclusive,
    /// It takes the place of what has the name, as a file a command writes
    /// anew does. Other hard links to a file that is replaced keep what it
    /// held.
    Replacing,
}

/// How a [`NewFile`] waits for its name.
#[derive(Debug)]
enum Waiting {
    /// Without any name: made with O_TMPFILE.
    Unnamed,
    /// Under a temporary name in the same directory.
    Temporary(TemporaryName),
    /// Under its own name already, made with O_CREAT|O_EXCL as the last
    /// resort, see [`NewFile`].
    Claimed,
}

/// What has a name in the directory of a [`NewFile`], told apart by device
/// and inode number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holder {
    /// The file itself.
    Itself,
    /// Another file.
    Another,
    /// Nothing: the name does not exist.
    Nothing,
}

/// A temporary name in the directory of a [`NewFile`]: `.#`, the name it
/// stands in for and 16 random hex digits, as systemd's tempfn_random()
/// makes one. The name is cut short where the whole would be longer than a
/// file name can be.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TemporaryName(OsString);

impl TemporaryName {
    /// What a temporary name starts with: the dot hides it from ls, as
    /// systemd's do.
    const PREFIX: &'static str = ".#";
    /// The random hex digits it ends with: two for each byte of the 64 bits
    /// tempfn_random() takes.
    const DIGITS: usize = 2 * size_of::<u64>();

    /// A new temporary name for `name`.
    fn new(name: &OsStr) -> io::Result<TemporaryName> {
        let mut random = [0u8; size_of::<u64>()];
        sys::random_bytes(&mut random)?;
        let name = name.as_bytes();
        let room = sys::NAME_MAX - TemporaryName::PREFIX.len() - TemporaryName::DIGITS;
        let mut temporary = Vec::with_capacity(sys::NAME_MAX);
        temporary.extend_from_slice(TemporaryName::PREFIX.as_bytes());
        temporary.extend_from_slice(&name[..name.len().min(room)]);
        let digits = format!("{:0width$x}", u64::from_ne_bytes(random), width = TemporaryName::DIGITS);
        temporary.extend_from_slice(digits.as_bytes());
        Ok(TemporaryName(OsString::from_vec(temporary)))
    }

    /// The name.
    fn as_os_str(&self) -> &OsStr {
        &self.0
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// What [`NewFile::discard`] did with the name of a file it gave up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Removal {
    /// The file waits under no name any more: it had none and goes away
    /// with its last descriptor, the name it waited under was removed, or
    /// it has its own name already, which stays.
    Removed,
    /// The name it had was gone already: someone else removed or renamed
    /// it.
    AlreadyGone,
    /// The name it had refers to another file now, which is left alone.
    NameTaken,
}

/// Why [`NewFile::link`] failed, and what became of the file.
#[derive(Debug)]
pub enum LinkError {
    /// The file does not have its name: EEXIST where something has the name
    /// or took the temporary name meanwhile, ENOENT where the name is gone
    /// again. The file comes back to be given up with [`NewFile::discard`]
    /// or [`NewFile::give_up`], which removes a temporary name it still
    /// waits under.
    Unnamed {
        /// Why.
        error: Error,
        /// The file.
        file: NewFile,
    },
    /// The file got its name, but checking by device and inode number that
    /// the name refers to it failed, as for want of descriptors or memory,
    /// and the error says so. Nothing undoes the name. A temporary name the
    /// file was linked from stays as well, since it can be the one name the
    /// file has, and the error names it.
    Unchecked {
        /// Why.
        error: Error,
        /// The file with its name, to sync its directory with
        /// [`Linked::sync_directories`].
        linked: Linked,
    },
}

/// A [`NewFile`] that got its name.
#[derive(Debug)]
#[must_use]
pub struct Linked {
    /// The directory it got its name in, pinned to sync it.
    directory: OwnedFd,
    /// The name as the caller named it, for messages.
    path: PathBuf,
    /// A temporary name the file was linked from that stays.
    stray: Option<Stray>,
}

/// A temporary name a [`NewFile`] was linked from, not renamed from, that
/// stays after the file got its name, as where the file system refuses
/// RENAME_NOREPLACE. Its display is a line that says so.
#[derive(Debug)]
pub enum Stray {
    /// It refers to another file now, which is left alone: the path of the
    /// temporary name.
    Taken(PathBuf),
    /// Removing it failed: the error says that it stays, and why.
    Kept(Error),
}

impl std::fmt::Display for Stray {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stray::Taken(path) => write!(f, "{} refers to another file now, which is left alone", path.display()),
            Stray::Kept(error) => write!(f, "{}", error),
        }
    }
}

impl Linked {
    /// Makes the names of `linked` last: syncs each directory they got
    /// their names in, once. Without it a power cut can lose a name although
    /// the data of its file was synced, which is why systemd's
    /// link_tmpfile_at() syncs it with LINK_TMPFILE_SYNC. A file system
    /// without an fsync for directories, as vboxsf, orangefs, AFS and 9p
    /// without 9P2000.L have none, refuses it with EINVAL
    /// (vfs_fsync_range()), and a directory that cannot be read, as one of
    /// mode 0300, cannot be opened to sync it (EACCES). Both are left as
    /// they are. A sync that fails otherwise fails this, and the error says
    /// that the first file of `linked` in that directory is complete and
    /// has its name.
    pub fn sync_directories(linked: &[Linked]) -> Result<()> {
        let mut directories = linked
            .iter()
            .map(|linked| Ok((linked.directory_id()?, linked)))
            .collect::<Result<Vec<_>>>()?;
        // A stable sort keeps the first file of each directory first.
        directories.sort_by_key(|(id, _)| *id);
        directories.dedup_by_key(|(id, _)| *id);
        directories
            .into_iter()
            .try_for_each(|(_, linked)| linked.sync_directory())
    }

    /// The temporary name the file was linked from where it stays.
    pub fn stray(&self) -> Option<&Stray> {
        self.stray.as_ref()
    }

    /// The device and inode number of the directory.
    fn directory_id(&self) -> Result<(u64, u64)> {
        let metadata = sys::fstat(self.directory.as_fd()).with_context(|| self.unsynced())?;
        Ok((metadata.dev(), metadata.ino()))
    }

    /// Syncs the directory, where the file system and the permissions of
    /// the directory let it be synced, see [`Linked::sync_directories`].
    fn sync_directory(&self) -> Result<()> {
        let synced = match sys::reopen(self.directory.as_fd(), sys::O_RDONLY | sys::O_DIRECTORY) {
            Ok(directory) => match File::from(directory).sync_all() {
                Err(e) if e.refuses_syncing_directories() => Ok(()),
                synced => synced,
            },
            Err(e) if e.refuses_reading() => Ok(()),
            Err(e) => Err(e),
        };
        synced.with_context(|| self.unsynced())
    }

    /// What an error of [`Linked::sync_directories`] says first.
    fn unsynced(&self) -> String {
        format!(
            "{} is complete and has its name, but syncing its directory failed",
            self.path.display()
        )
    }
}

impl NewFile {
    /// Makes a regular file for `path`, open for reading and writing, to
    /// get that name as `naming` says. Only the directory of `path` is
    /// looked up, once, as [`open_parent`] does it. What is there under the
    /// name is left alone until the file gets that name, but for the last
    /// resort of [`Naming::Exclusive`], see [`NewFile`].
    pub fn create(path: &Path, naming: Naming) -> Result<NewFile> {
        let (parent, name) = open_parent(path)?;
        NewFile::create_in(parent, name, path, naming)
    }

    /// Makes a regular file in the directory `parent` for the name `name`,
    /// to get it as `naming` says. `path` is that name as the caller named
    /// it, for messages. Where something fails after the file was made, the
    /// file is given up, and the error says what of it stays.
    pub(crate) fn create_in(parent: OwnedFd, name: OsString, path: &Path, naming: Naming) -> Result<NewFile> {
        let mut new = match sys::create_unnamed_file(parent.as_fd(), NEW_FILE_MODE) {
            Ok(file) => NewFile {
                file,
                parent,
                name,
                path: path.to_path_buf(),
                naming,
                waiting: Some(Waiting::Unnamed),
            },
            Err(e) if e.refuses_unnamed_files() => NewFile::create_named_in(parent, name, path, naming)?,
            Err(e) => return Err(e.into()),
        };
        match naming {
            Naming::Exclusive => match new.lock().and_then(|()| new.probe_exclusive_naming()) {
                Ok(()) => Ok(new),
                Err(e) => Err(new.given_up(e)),
            },
            // A plain rename replaces on every file system.
            Naming::Replacing => Ok(new),
        }
    }

    /// Makes a regular file in the directory `parent` for the name `name`
    /// under a temporary name, as where O_TMPFILE is refused.
    fn create_named_in(parent: OwnedFd, name: OsString, path: &Path, naming: Naming) -> io::Result<NewFile> {
        let temporary = TemporaryName::new(&name)?;
        let file = sys::create_file_at(parent.as_fd(), temporary.as_bytes(), NEW_FILE_MODE)?;
        Ok(NewFile {
            file,
            parent,
            name,
            path: path.to_path_buf(),
            naming,
            waiting: Some(Waiting::Temporary(temporary)),
        })
    }

    /// Takes the exclusive BSD lock that a device takes for writing, see
    /// [`crate::device::Device::create`], before anything can remove a name
    /// of the file. A file another process locked between its creation and
    /// this is in its hands: the file keeps its name, and this fails with
    /// EBUSY. Where the lock cannot be had at all, as NFS without its lock
    /// manager refuses it with ENOLCK, this fails with that, and giving the
    /// file up removes its name.
    fn lock(&mut self) -> Result<()> {
        match sys::try_lock(self.file.as_fd(), true) {
            Ok(true) => Ok(()),
            Ok(false) => {
                let shown = self.shown();
                self.waiting = None;
                bail!(EBUSY, "{} is being used by another process", shown)
            }
            Err(e) => Err(Error::from(e).context(format!("failed to lock {}", self.shown()))),
        }
    }

    /// The file, for messages: the path of the name it has in its directory
    /// now, a temporary name or the one it is made for, or "the new file"
    /// where it has no name.
    fn shown(&self) -> String {
        match &self.waiting {
            Some(Waiting::Temporary(temporary)) => {
                self.path.with_file_name(temporary.as_os_str()).display().to_string()
            }
            Some(Waiting::Claimed) => self.path.display().to_string(),
            Some(Waiting::Unnamed) | None => "the new file".to_string(),
        }
    }

    /// Finds out how the file, under a temporary name and with nothing
    /// written to it yet, gets its name without taking the place of another
    /// file. It is renamed to another temporary name with RENAME_NOREPLACE,
    /// or else linked to one by its descriptor, and that name is removed
    /// again. NFS, CephFS and 9p refuse the flag with EINVAL (their rename
    /// operations take no flags), and a file system without hard links
    /// refuses the link, see [`sys::Refusal`]. Right before the rename the
    /// temporary name is checked to refer to the file still, as
    /// [`NewFile::link`] checks it. Where both are refused the temporary
    /// file goes and the file is made under its name, locked before it can
    /// be removed again: the last resort of [`NewFile`].
    fn probe_exclusive_naming(&mut self) -> Result<()> {
        let Some(Waiting::Temporary(temporary)) = &self.waiting else {
            return Ok(());
        };
        // Until the file waits under another name, giving it up removes
        // this one.
        let temporary = temporary.clone();
        let other = TemporaryName::new(&self.name)?;
        self.check_temporary(&temporary)?;
        let parent = self.parent.as_fd();
        match sys::rename_noreplace_at(parent, temporary.as_bytes(), other.as_bytes()) {
            Ok(()) => {
                self.waiting = Some(Waiting::Temporary(other));
                return Ok(());
            }
            Err(e) if e.refuses_rename_flags() => {}
            Err(e) => return Err(e.into()),
        }
        match sys::link_fd(self.file.as_fd(), parent, other.as_bytes()) {
            Ok(()) => {
                self.remove_name(other.as_os_str())?;
                return Ok(());
            }
            Err(e) if e.refuses_hard_links() => {}
            Err(e) => return Err(e.into()),
        }
        self.remove_name(temporary.as_os_str())?;
        self.waiting = None;
        self.file = sys::create_file_at(parent, self.name.as_bytes(), NEW_FILE_MODE)?;
        // Armed before the lock: a file another process locked first is
        // left to it, see NewFile::lock().
        self.waiting = Some(Waiting::Claimed);
        self.lock()
    }

    /// The file, to write it.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// The name the file is made for, as the caller named it.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Gives the file its name as its [`Naming`] says, and checks by device
    /// and inode number that the name refers to the file then. A file that
    /// did not get its name comes back in the error, to be given up. One
    /// that got its name where checking that failed comes back linked, see
    /// [`LinkError::Unchecked`].
    ///
    /// [`Naming::Exclusive`]: a file without a name is linked by its
    /// descriptor as systemd's link_fd() links one, with AT_EMPTY_PATH, else
    /// through /proc/self/fd; a file system that makes files without a name
    /// but cannot link them fails here. A temporary name is renamed with
    /// RENAME_NOREPLACE, or where the file system refuses the flag the file
    /// is linked by its descriptor and the temporary name removed after the
    /// check, the way the probe of [`NewFile`] found out. Where something
    /// has the name by now that is EEXIST. A file made under its name as the
    /// last resort has it already.
    ///
    /// [`Naming::Replacing`]: a file without a name that cannot be linked
    /// under it because the name exists is linked under a temporary name
    /// and renamed onto it, as systemd's linkat_replace() does it, and a
    /// temporary name is renamed onto it right away.
    ///
    /// A rename moves whatever has the temporary name by then. So right
    /// before it the temporary name is checked to refer to the file, and a
    /// file that took it meanwhile is left where it is (EEXIST). One that
    /// takes it between that check and the rename gets the name: the check
    /// after fails then, and leaves that file there.
    pub fn link(mut self) -> std::result::Result<Linked, LinkError> {
        // A descriptor of the directory to sync it, taken before the file
        // gets its name, which nothing may undo. Opening the directory for
        // the sync can fail: that waits for Linked::sync_directories().
        let directory = match self.parent.try_clone() {
            Ok(directory) => directory,
            Err(e) => return Err(self.unnamed(e.into())),
        };
        if let Err(e) = self.give_name() {
            return Err(self.unnamed(e));
        }
        let shown = self.path.display().to_string();
        match self.holder(&self.name) {
            Ok(Holder::Itself) => {}
            Ok(Holder::Another) => {
                let e = err!(
                    EEXIST,
                    "{} is not the file made for it: another file took its name or its temporary name meanwhile",
                    shown
                );
                return Err(self.unnamed(e));
            }
            Ok(Holder::Nothing) => {
                let e = err!(ENOENT, "{} is gone: something removed or renamed it meanwhile", shown);
                return Err(self.unnamed(e));
            }
            Err(e) => {
                let stays = match self.waiting.take() {
                    Some(Waiting::Temporary(temporary)) => {
                        format!(
                            ", and {} stays",
                            self.path.with_file_name(temporary.as_os_str()).display()
                        )
                    }
                    _ => String::new(),
                };
                let error = Error::from(e).context(format!("{} has its name, but checking it failed{}", shown, stays));
                let linked = Linked {
                    directory,
                    path: self.path.clone(),
                    stray: None,
                };
                return Err(LinkError::Unchecked { error, linked });
            }
        }
        let stray = match self.waiting.take() {
            Some(Waiting::Temporary(temporary)) => {
                let stays = self.path.with_file_name(temporary.as_os_str());
                match self.remove_name(temporary.as_os_str()) {
                    Ok(Removal::Removed | Removal::AlreadyGone) => None,
                    Ok(Removal::NameTaken) => Some(Stray::Taken(stays)),
                    Err(e) => Some(Stray::Kept(e.context(format!(
                        "{}, which {} was linked from, stays",
                        stays.display(),
                        shown
                    )))),
                }
            }
            _ => None,
        };
        Ok(Linked {
            directory,
            path: self.path.clone(),
            stray,
        })
    }

    /// The error of a [`NewFile::link`] that failed with `error` before
    /// the file got its name, or found it gone after.
    fn unnamed(self, error: Error) -> LinkError {
        LinkError::Unnamed { error, file: self }
    }

    /// The naming of [`NewFile::link`]. A temporary name the file is linked
    /// from rather than renamed from stays in `waiting`, to be removed once
    /// the name is checked.
    fn give_name(&mut self) -> Result<()> {
        let (parent, name) = (self.parent.as_fd(), self.name.as_bytes());
        match (&self.waiting, self.naming) {
            (Some(Waiting::Unnamed), Naming::Exclusive) => {
                self.link_unnamed(name)?;
                self.waiting = None;
            }
            (Some(Waiting::Unnamed), Naming::Replacing) => {
                match self.link_unnamed(name) {
                    Err(e) if e.errno() == EEXIST => {}
                    linked => {
                        linked?;
                        self.waiting = None;
                        return Ok(());
                    }
                }
                let temporary = TemporaryName::new(&self.name)?;
                self.link_unnamed(temporary.as_bytes())?;
                // From here on giving the file up removes it.
                self.waiting = Some(Waiting::Temporary(temporary.clone()));
                self.check_temporary(&temporary)?;
                sys::rename_at(parent, temporary.as_bytes(), name)?;
                self.waiting = None;
            }
            (Some(Waiting::Temporary(temporary)), naming) => {
                let temporary = temporary.clone();
                self.check_temporary(&temporary)?;
                let renamed = match naming {
                    Naming::Exclusive => sys::rename_noreplace_at(parent, temporary.as_bytes(), name),
                    Naming::Replacing => sys::rename_at(parent, temporary.as_bytes(), name),
                };
                match renamed {
                    Ok(()) => self.waiting = None,
                    Err(e) if naming == Naming::Exclusive && e.refuses_rename_flags() => {
                        sys::link_fd(self.file.as_fd(), parent, name)?;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            // Made under its name by the last resort.
            (Some(Waiting::Claimed) | None, _) => {}
        }
        Ok(())
    }

    /// Links the file, made without a name, under `name` by its descriptor.
    /// A file system that refuses hard links has made the file but refuses
    /// it a name, which shows only here, at the end.
    fn link_unnamed(&self, name: &[u8]) -> Result<()> {
        sys::link_fd(self.file.as_fd(), self.parent.as_fd(), name).map_err(|e| {
            if e.refuses_hard_links() {
                Error::from(e).context("the file system made the file but refuses to give it its name")
            } else {
                e.into()
            }
        })
    }

    /// Checks right before a rename of the temporary name `temporary` that
    /// it refers to the file still: a rename moves whatever has the name by
    /// then. A file that took it meanwhile is left where it is (EEXIST).
    fn check_temporary(&self, temporary: &TemporaryName) -> Result<()> {
        let shown = self.path.with_file_name(temporary.as_os_str());
        let holder = self
            .holder(temporary.as_os_str())
            .with_context(|| format!("failed to check {}", shown.display()))?;
        match holder {
            Holder::Itself => Ok(()),
            Holder::Another => bail!(
                EEXIST,
                "{} refers to another file now: something took that name meanwhile",
                shown.display()
            ),
            Holder::Nothing => bail!(
                ENOENT,
                "{} is gone: something removed or renamed it meanwhile",
                shown.display()
            ),
        }
    }

    /// What has the name `name` of the directory: the file, another file or
    /// nothing.
    fn holder(&self, name: &OsStr) -> io::Result<Holder> {
        let ours = self.file.metadata()?;
        let entry = match sys::pin_entry(self.parent.as_fd(), name.as_bytes()) {
            Ok(entry) => entry,
            Err(e) if e.raw_os_error() == Some(ENOENT) => return Ok(Holder::Nothing),
            Err(e) => return Err(e),
        };
        let there = sys::fstat(entry.as_fd())?;
        if (there.dev(), there.ino()) == (ours.dev(), ours.ino()) {
            Ok(Holder::Itself)
        } else {
            Ok(Holder::Another)
        }
    }

    /// Gives the file up. One without a name goes away with its last
    /// descriptor. A temporary name, or the name the last resort made the
    /// file under, is removed after checking that it refers to the file,
    /// see [`NewFile`]. A file that has its name already keeps it.
    pub fn discard(mut self) -> Result<Removal> {
        match self.waiting.take() {
            Some(Waiting::Temporary(temporary)) => self.remove_name(temporary.as_os_str()),
            Some(Waiting::Claimed) => {
                let name = self.name.clone();
                self.remove_name(&name)
            }
            Some(Waiting::Unnamed) | None => Ok(Removal::Removed),
        }
    }

    /// Gives the file up the way [`NewFile::discard`] does, and says what of
    /// it stays where something does, for a message: a name that refers to
    /// another file now, which is left alone, or one that removing failed
    /// for.
    pub fn give_up(self) -> Option<String> {
        let (shown, path) = (self.shown(), self.path.clone());
        match self.discard() {
            Ok(Removal::Removed | Removal::AlreadyGone) => None,
            Ok(Removal::NameTaken) => Some(format!("{} refers to another file now, which is left alone", shown)),
            Err(e) => Some(format!("the unfinished {} stays: {}", path.display(), e)),
        }
    }

    /// `cause`, after which the file is given up, followed by what of it
    /// stays where something does.
    pub(crate) fn given_up(self, cause: Error) -> Error {
        let Some(stays) = self.give_up() else {
            return cause;
        };
        let detail = cause.detail().cloned();
        let error = Error::new(cause.errno(), format!("{}, and {}", cause.message(), stays));
        match detail {
            Some(detail) => error.with(detail),
            None => error,
        }
    }

    /// Removes the name `name` of the directory after checking by device
    /// and inode number that it refers to this file.
    fn remove_name(&self, name: &OsStr) -> Result<Removal> {
        let failed = || format!("failed to remove {}", self.path.with_file_name(name).display());
        match self.holder(name).with_context(failed)? {
            Holder::Itself => {}
            Holder::Another => return Ok(Removal::NameTaken),
            Holder::Nothing => return Ok(Removal::AlreadyGone),
        }
        match sys::unlink_at(self.parent.as_fd(), name.as_bytes()) {
            Ok(()) => Ok(Removal::Removed),
            Err(e) if e.raw_os_error() == Some(ENOENT) => Ok(Removal::AlreadyGone),
            Err(e) => Err(e).with_context(failed),
        }
    }
}

impl Drop for NewFile {
    fn drop(&mut self) {
        // The file is still open here, so its inode is not reused while the
        // name is compared, and a lock it took is still held.
        let name = match self.waiting.take() {
            Some(Waiting::Temporary(temporary)) => temporary.0,
            Some(Waiting::Claimed) => self.name.clone(),
            Some(Waiting::Unnamed) | None => return,
        };
        let _ = self.remove_name(&name);
    }
}

/// Opens the directory `dir`, pinned or open, for listing: a descriptor of
/// our own with its own position, so a caller's descriptor keeps its state.
pub(crate) fn listing_of(dir: BorrowedFd<'_>) -> Result<OwnedFd> {
    Ok(sys::reopen(dir, sys::O_RDONLY | sys::O_DIRECTORY)?)
}

/// An entry of a host directory, pinned while it is being visited.
pub(crate) struct HostEntry {
    /// Where the entry is inside the tree, relative to the tree's root: for
    /// messages and the lists of skipped entries.
    pub path: PathBuf,
    /// Its metadata, that of the link target if links are followed.
    pub metadata: fs::Metadata,
    /// The inode itself, pinned as an O_PATH descriptor; the link target if
    /// links are followed.
    fd: OwnedFd,
}

impl HostEntry {
    pub(crate) fn is_dir(&self) -> bool {
        self.metadata.is_dir()
    }

    pub(crate) fn is_file(&self) -> bool {
        self.metadata.is_file()
    }

    /// Opens the entry, a regular file, for reading: the pinned inode
    /// reopened, so what is read is what the metadata describes.
    pub(crate) fn open_file(&self) -> Result<File> {
        let fd = sys::reopen(self.fd.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        Ok(File::from(fd))
    }

    /// Whether the entry, a regular file open as `file`, is no longer what
    /// the walk found: its size, its modification time or its change time
    /// differs from the metadata. tar checks a file it read the same way.
    pub(crate) fn has_changed(&self, file: &File) -> Result<bool> {
        let now = sys::fstat(file.as_fd()).with_context(|| format!("failed to stat {}", self.path.display()))?;
        let then = &self.metadata;
        Ok(now.len() != then.len()
            || (now.mtime(), now.mtime_nsec()) != (then.mtime(), then.mtime_nsec())
            || (now.ctime(), now.ctime_nsec()) != (then.ctime(), then.ctime_nsec()))
    }
}

/// What a walk does with an entry it cannot give a path inside the volume:
/// one whose name is not UTF-8, which could not be stored as a long name
/// anyway, or whose path inside the volume would be longer than
/// [`crate::path::MAX_PATH`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnnamableEntry {
    /// The walk fails, with EINVAL for the name and ENAMETOOLONG for the
    /// path.
    Fail,
    /// The walk leaves the entry out, a directory with everything below
    /// it, and counts it if it is a regular file or a directory, which a
    /// user of the walk would have stored. Other files are left out
    /// uncounted, as the users of the walk leave them out.
    Omit,
}

/// How a directory path reads in a message: "." for the root.
fn shown(path: &Path) -> std::path::Display<'_> {
    if path.as_os_str().is_empty() {
        Path::new(".").display()
    } else {
        path.display()
    }
}

/// The names in the directory `dir`, pinned or open, sorted by their bytes.
/// `dir_path` is where the directory is below the root, for messages. The
/// listing is read through a descriptor of our own that is closed again
/// right here; the names are all that is kept.
fn list_names(dir: BorrowedFd<'_>, dir_path: &Path) -> Result<Vec<Vec<u8>>> {
    let listing = listing_of(dir).with_context(|| format!("failed to open {}", shown(dir_path)))?;
    let mut names = sys::list_dir(listing.as_fd()).with_context(|| format!("failed to read {}", shown(dir_path)))?;
    names.sort();
    Ok(names)
}

/// One level of a walk: the directory, pinned, its identity, the names in
/// it still to visit, and where it is on the host and inside the volume.
struct Level {
    dir: OwnedFd,
    dev: u64,
    ino: u64,
    names: std::vec::IntoIter<Vec<u8>>,
    path: PathBuf,
    target: String,
}

/// Walks the tree under the directory `root` in byte order of the names,
/// level by level: `visit` is called for every entry with the path it gets
/// inside the volume (`dest` plus the names below) and decides whether to
/// descend into a directory. The populator, the planner and the manifest
/// generator all walk through here, so they see the same tree.
///
/// Every entry is pinned relative to the descriptor of its directory,
/// without following it, when the walk reaches it, and examined through
/// that descriptor; a symbolic link is followed below `root` from the
/// directory it is in when `follow_symlinks` asks for it, the target
/// replacing the link. One entry is pinned at a time, as systemd's
/// recurse_dir() pins them, so the size of a directory costs no
/// descriptors. The walk keeps the pinned directory of every level on an
/// explicit stack instead of recursing, so the depth of the tree is one
/// descriptor per level, not the depth of our stack. An entry that
/// vanishes between the listing and the pin is left out, as recurse_dir()
/// leaves it out: it is not there to copy. A directory that is already on
/// the stack, reached through a followed link or a bind mount of a
/// directory into itself, is ELOOP: the tree would otherwise go on until
/// the path limit. An entry the walk cannot give a path inside the volume
/// fails the walk or is left out, as `unnamable` says. The walk returns how
/// many entries it left out that way.
pub(crate) fn walk_tree(
    root: BorrowedFd<'_>,
    dest: &str,
    follow_symlinks: bool,
    unnamable: UnnamableEntry,
    visit: &mut dyn FnMut(&str, &HostEntry) -> Result<bool>,
) -> Result<u64> {
    let names = list_names(root, Path::new("")).with_context(|| "failed to list the source directory")?;
    let root_md = sys::fstat(root).with_context(|| "failed to stat the source directory")?;
    let mut stack = vec![Level {
        dir: root.try_clone_to_owned()?,
        dev: root_md.dev(),
        ino: root_md.ino(),
        names: names.into_iter(),
        path: PathBuf::new(),
        target: dest.to_string(),
    }];
    let mut omitted = 0;
    loop {
        let Some(level) = stack.last_mut() else {
            return Ok(omitted);
        };
        let Some(name) = level.names.next() else {
            stack.pop();
            continue;
        };
        let path = level.path.join(OsStr::from_bytes(&name));
        // The path inside the volume, or why the entry has none.
        let target = match std::str::from_utf8(&name) {
            Err(_) => Err(err!(EINVAL, "{} is not valid UTF-8", path.display())),
            Ok(text) => {
                let target = crate::path::join(&level.target, text);
                if target.len() > crate::path::MAX_PATH {
                    Err(err!(
                        ENAMETOOLONG,
                        "{}: its path inside the volume is longer than {} bytes",
                        path.display(),
                        crate::path::MAX_PATH
                    ))
                } else {
                    Ok(target)
                }
            }
        };
        let target = match (target, unnamable) {
            (Ok(target), _) => Some(target),
            (Err(e), UnnamableEntry::Fail) => return Err(e),
            (Err(_), UnnamableEntry::Omit) => None,
        };
        let stat = || format!("failed to stat {}", path.display());
        let mut fd = match sys::pin_entry(level.dir.as_fd(), &name) {
            Ok(fd) => fd,
            // Vanished since the listing: nothing to copy, as for
            // recurse_dir().
            Err(e) if e.raw_os_error() == Some(ENOENT) => continue,
            Err(e) => return Err(e).with_context(stat),
        };
        let mut metadata = sys::fstat(fd.as_fd()).with_context(stat)?;
        if follow_symlinks && metadata.file_type().is_symlink() {
            fd = sys::follow_link_at(root, level.dir.as_fd(), fd.as_fd()).with_context(stat)?;
            metadata = sys::fstat(fd.as_fd()).with_context(stat)?;
        }
        let Some(target) = target else {
            if metadata.is_dir() || metadata.is_file() {
                omitted += 1;
            }
            continue;
        };
        let entry = HostEntry { path, metadata, fd };
        if visit(&target, &entry)? && entry.is_dir() {
            let (dev, ino) = (entry.metadata.dev(), entry.metadata.ino());
            if stack.iter().any(|level| level.dev == dev && level.ino == ino) {
                bail!(
                    ELOOP,
                    "{} is a directory above it, the tree loops",
                    entry.path.display()
                );
            }
            let names = list_names(entry.fd.as_fd(), &entry.path)?;
            stack.push(Level {
                dir: entry.fd,
                dev,
                ino,
                names: names.into_iter(),
                path: entry.path,
                target,
            });
        }
    }
}

/// Reads into `buf` once, retrying when a signal interrupted the read. A
/// bare read() fails with EINTR when a handler that returns is installed,
/// as it is in a process such as systemd that hosts this library; std
/// retries only in read_exact() and friends.
pub(crate) fn read_some(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buf) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

/// Reads a descriptor from its start with positional reads, so the file
/// position of a descriptor somebody else owns is neither used nor
/// changed.
pub(crate) struct FromStart<'a> {
    fd: BorrowedFd<'a>,
    pos: u64,
}

impl<'a> FromStart<'a> {
    pub(crate) fn new(fd: BorrowedFd<'a>) -> FromStart<'a> {
        FromStart { fd, pos: 0 }
    }
}

impl Read for FromStart<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = sys::pread(self.fd, buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    /// The names in the directory `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// The temporary name `new` waits under in its directory, where
    /// O_TMPFILE was refused.
    fn temporary_name(new: &NewFile) -> Option<&TemporaryName> {
        match &new.waiting {
            Some(Waiting::Temporary(temporary)) => Some(temporary),
            _ => None,
        }
    }

    /// Whether `temporary` is a temporary name for `name`: `.#`, the name
    /// and 16 hex digits.
    fn is_temporary_name_of(temporary: &OsStr, name: &str) -> bool {
        let temporary = temporary.to_str().unwrap();
        let digits = temporary.strip_prefix(".#").and_then(|rest| rest.strip_prefix(name));
        digits.is_some_and(|digits| {
            digits.len() == TemporaryName::DIGITS && digits.bytes().all(|b| b.is_ascii_hexdigit())
        })
    }

    /// A new file is written without a name and gets it when it is linked.
    /// An exclusive one does not take the name where something has it, one
    /// that replaces does, by a rename, so another hard link to the file
    /// it replaces keeps what that held. One that is given up leaves
    /// nothing.
    #[test]
    fn new_files_get_their_names_at_the_end() {
        let tmp = TempDir::new("new");
        let dir = tmp.path();
        let path = dir.join("m.json");
        let new = NewFile::create(&path, Naming::Exclusive).unwrap();
        new.file().write_all(b"first").unwrap();
        assert!(!path.exists());
        if temporary_name(&new).is_none() {
            assert!(names_in(dir).is_empty());
        }
        Linked::sync_directories(&[new.link().unwrap()]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");
        let new = NewFile::create(&path, Naming::Exclusive).unwrap();
        new.file().write_all(b"second").unwrap();
        let (error, file) = unnamed(new.link().unwrap_err());
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(file.discard().unwrap(), Removal::Removed);
        assert_eq!(fs::read(&path).unwrap(), b"first");
        fs::hard_link(&path, dir.join("other")).unwrap();
        let new = NewFile::create(&path, Naming::Replacing).unwrap();
        new.file().write_all(b"third").unwrap();
        Linked::sync_directories(&[new.link().unwrap()]).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"third");
        assert_eq!(fs::read(dir.join("other")).unwrap(), b"first");
        drop(NewFile::create(&dir.join("dropped"), Naming::Exclusive).unwrap());
        assert_eq!(names_in(dir), ["m.json", "other"]);
        assert_eq!(
            NewFile::create(&dir.join("missing/m.json"), Naming::Exclusive)
                .unwrap_err()
                .errno(),
            ENOENT
        );
    }

    /// The error and the file of a link that left the file without its
    /// name.
    fn unnamed(failed: LinkError) -> (Error, NewFile) {
        match failed {
            LinkError::Unnamed { error, file } => (error, file),
            LinkError::Unchecked { error, .. } => panic!("the file got its name: {}", error),
        }
    }

    /// A new file made in the directory `dir` for the name `name` under a
    /// temporary name, as where O_TMPFILE is refused.
    fn named_in(dir: &Path, name: &str, naming: Naming) -> NewFile {
        NewFile::create_named_in(open_dir(dir).unwrap(), name.into(), &dir.join(name), naming).unwrap()
    }

    /// Where O_TMPFILE is refused a new file waits under a temporary name
    /// in its directory. An exclusive one finds out how it gets its name
    /// first, where RENAME_NOREPLACE works by a rename to another temporary
    /// name. Linking renames it, never onto a name that is taken unless it
    /// replaces, and giving it up removes the temporary name while it names
    /// the file, which tells apart a name that is gone and one that another
    /// file took.
    #[test]
    fn new_files_under_a_temporary_name() {
        let tmp = TempDir::new("temporary");
        let dir = tmp.path();
        let mut new = named_in(dir, "a.img", Naming::Exclusive);
        let first = temporary_name(&new).unwrap().as_os_str().to_os_string();
        new.probe_exclusive_naming().unwrap();
        let temporary = temporary_name(&new).unwrap().as_os_str().to_os_string();
        assert_ne!(temporary, first);
        assert!(is_temporary_name_of(&temporary, "a.img"), "{:?}", temporary);
        assert_eq!(names_in(dir), [temporary.to_str().unwrap()]);
        new.file().write_all(b"first").unwrap();
        Linked::sync_directories(&[new.link().unwrap()]).unwrap();
        assert_eq!(names_in(dir), ["a.img"]);
        assert_eq!(fs::read(dir.join("a.img")).unwrap(), b"first");
        let (error, file) = unnamed(named_in(dir, "a.img", Naming::Exclusive).link().unwrap_err());
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(file.discard().unwrap(), Removal::Removed);
        assert_eq!(names_in(dir), ["a.img"]);
        let new = named_in(dir, "a.img", Naming::Replacing);
        new.file().write_all(b"second").unwrap();
        Linked::sync_directories(&[new.link().unwrap()]).unwrap();
        assert_eq!(fs::read(dir.join("a.img")).unwrap(), b"second");
        drop(named_in(dir, "b.img", Naming::Exclusive));
        assert_eq!(names_in(dir), ["a.img"]);
        let new = named_in(dir, "c.img", Naming::Exclusive);
        fs::remove_file(dir.join(temporary_name(&new).unwrap().as_os_str())).unwrap();
        assert_eq!(new.discard().unwrap(), Removal::AlreadyGone);
        let new = named_in(dir, "c.img", Naming::Exclusive);
        let temporary = dir.join(temporary_name(&new).unwrap().as_os_str());
        fs::remove_file(&temporary).unwrap();
        fs::write(&temporary, b"theirs").unwrap();
        assert_eq!(new.discard().unwrap(), Removal::NameTaken);
        assert_eq!(fs::read(&temporary).unwrap(), b"theirs");
    }

    /// A rename moves whatever has the temporary name by then, so right
    /// before each rename the temporary name is checked to refer to the
    /// file still. A file that took it meanwhile stays where it is: the
    /// probe does not move it to another temporary name, an exclusive file
    /// does not get its name, and one that replaces does not replace what
    /// has its name. Giving the file up says that the temporary name refers
    /// to another file now.
    #[test]
    fn a_temporary_name_taken_meanwhile_is_left_alone() {
        let tmp = TempDir::new("taken");
        let dir = tmp.path();
        let take = |new: &NewFile| {
            let temporary = dir.join(temporary_name(new).unwrap().as_os_str());
            fs::write(dir.join("theirs"), b"theirs").unwrap();
            fs::rename(dir.join("theirs"), &temporary).unwrap();
            temporary
        };
        let mut new = named_in(dir, "a.img", Naming::Exclusive);
        let taken = take(&new);
        assert_eq!(new.probe_exclusive_naming().unwrap_err().errno(), EEXIST);
        assert_eq!(names_in(dir), [taken.file_name().unwrap().to_str().unwrap()]);
        let left_alone = format!("{} refers to another file now, which is left alone", taken.display());
        assert_eq!(new.give_up().unwrap(), left_alone);
        fs::remove_file(&taken).unwrap();
        let mut new = named_in(dir, "a.img", Naming::Exclusive);
        new.probe_exclusive_naming().unwrap();
        let taken = take(&new);
        let (error, file) = unnamed(new.link().unwrap_err());
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(file.discard().unwrap(), Removal::NameTaken);
        assert!(!dir.join("a.img").exists());
        assert_eq!(fs::read(&taken).unwrap(), b"theirs");
        fs::remove_file(&taken).unwrap();
        fs::write(dir.join("m.json"), b"old").unwrap();
        let new = named_in(dir, "m.json", Naming::Replacing);
        let taken = take(&new);
        let (error, _) = unnamed(new.link().unwrap_err());
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(fs::read(dir.join("m.json")).unwrap(), b"old");
        assert_eq!(fs::read(&taken).unwrap(), b"theirs");
    }

    /// Where the file system refuses RENAME_NOREPLACE, an exclusive file
    /// under a temporary name is linked by its descriptor and the temporary
    /// name is removed after: one that cannot be removed stays, and the
    /// link says so. Filters of the test's own thread refuse the flag, as
    /// NFS refuses it, and the removal.
    /// A kernel without renameat2() says ENOSYS, and so does a seccomp
    /// filter that does not know the call, as systemd's do. That is refused
    /// like the flag: the probe of an exclusive file under a temporary name
    /// leaves it under that name, and the link gives it its name by its
    /// descriptor and removes the temporary name. A filter of the test's own
    /// thread says ENOSYS for renameat2().
    #[test]
    fn a_kernel_without_renameat2_links_the_file() {
        let tmp = TempDir::new("norenameat2");
        let dir = tmp.path().to_path_buf();
        let mut new = named_in(&dir, "a.img", Naming::Exclusive);
        new.file().write_all(b"image").unwrap();
        let first = temporary_name(&new).unwrap().clone();
        let linked = std::thread::spawn(move || {
            sys::refuse_in_this_thread(libc::SYS_renameat2, ENOSYS).then(|| {
                new.probe_exclusive_naming().unwrap();
                let waits = temporary_name(&new) == Some(&first);
                (waits, new.link().unwrap().stray().is_none())
            })
        })
        .join()
        .unwrap();
        let Some((waits, unstrayed)) = linked else {
            return eprintln!("skipping: no seccomp filters here");
        };
        assert!(waits, "the probe renamed the file");
        assert!(unstrayed, "the temporary name stays");
        assert_eq!(names_in(&dir), ["a.img"]);
        assert_eq!(fs::read(dir.join("a.img")).unwrap(), b"image");
    }

    #[test]
    fn a_temporary_name_that_cannot_be_removed_stays() {
        let tmp = TempDir::new("stray");
        let dir = tmp.path();
        let mut new = named_in(dir, "a.img", Naming::Exclusive);
        new.probe_exclusive_naming().unwrap();
        let temporary = dir.join(temporary_name(&new).unwrap().as_os_str());
        let stray = std::thread::spawn(move || {
            let refused = sys::refuse_in_this_thread(libc::SYS_renameat2, EINVAL)
                && sys::refuse_in_this_thread(libc::SYS_unlinkat, EIO);
            refused.then(|| new.link().unwrap().stray().map(ToString::to_string))
        })
        .join()
        .unwrap();
        let Some(stray) = stray else {
            return eprintln!("skipping: no seccomp filters here");
        };
        let stray = stray.unwrap();
        let stays = format!(
            "{}, which {} was linked from, stays: failed to remove {}: ",
            temporary.display(),
            dir.join("a.img").display(),
            temporary.display()
        );
        assert!(stray.starts_with(&stays), "{}", stray);
        assert!(dir.join("a.img").exists());
        assert!(temporary.exists());
    }

    /// The directories new files got their names in are synced, each once.
    /// A file system without an fsync for its directories refuses it with
    /// EINVAL (vfs_fsync_range()), and a directory that cannot be read
    /// cannot be opened to sync it: those are left as they are. Any other
    /// failure fails, and says that the first of the files in that
    /// directory is complete and has its name. Filters of the test's own
    /// threads refuse the fsync.
    #[test]
    fn directories_that_cannot_be_synced() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new("unsynced");
        let dir = tmp.path();
        let linked = |name: &str| {
            NewFile::create(&dir.join(name), Naming::Exclusive)
                .unwrap()
                .link()
                .unwrap()
        };
        let synced = |linked: &[Linked], errno| {
            std::thread::scope(|scope| {
                scope
                    .spawn(move || {
                        sys::refuse_in_this_thread(libc::SYS_fsync, errno)
                            .then(|| Linked::sync_directories(linked).map_err(|e| e.to_string()))
                    })
                    .join()
                    .unwrap()
            })
        };
        let unsynced = |name| {
            format!(
                "{} is complete and has its name, but syncing its directory failed: ",
                dir.join(name).display()
            )
        };
        let files = [linked("a.img"), linked("b.img")];
        let Some(skipped) = synced(&files, EINVAL) else {
            return eprintln!("skipping: no seccomp filters here");
        };
        assert_eq!(skipped, Ok(()));
        let failed = synced(&files, EIO).unwrap().unwrap_err();
        assert!(failed.starts_with(&unsynced("a.img")), "{}", failed);
        let [a, b] = files;
        let failed = synced(&[b, a], EIO).unwrap().unwrap_err();
        assert!(failed.starts_with(&unsynced("b.img")), "{}", failed);
        let c = linked("c.img");
        fs::set_permissions(dir, fs::Permissions::from_mode(0o300)).unwrap();
        let unreadable = fs::read_dir(dir).is_err();
        let synced = Linked::sync_directories(&[c]);
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        if unreadable {
            synced.unwrap();
        }
    }

    /// A new file whose name cannot be checked once it got it, as for want
    /// of descriptors, keeps the name, and the error says so. A filter of
    /// the test's own thread refuses the open the check needs.
    #[test]
    fn a_name_that_cannot_be_checked_stays() {
        let tmp = TempDir::new("unchecked");
        let path = tmp.path().join("a.img");
        let new = NewFile::create(&path, Naming::Exclusive).unwrap();
        if temporary_name(&new).is_some() {
            return eprintln!("skipping: no O_TMPFILE here");
        }
        let failed = std::thread::spawn(move || {
            sys::refuse_in_this_thread(libc::SYS_openat, libc::EMFILE).then(|| new.link().map(drop))
        })
        .join()
        .unwrap();
        let Some(failed) = failed else {
            return eprintln!("skipping: no seccomp filters here");
        };
        let LinkError::Unchecked { error, linked } = failed.unwrap_err() else {
            panic!("the name was checked or not given");
        };
        assert_eq!(error.errno(), libc::EMFILE);
        let checked = format!("{} has its name, but checking it failed: ", path.display());
        assert!(error.message().starts_with(&checked), "{}", error);
        Linked::sync_directories(&[linked]).unwrap();
        assert!(path.exists());
    }

    /// Where the last resort cannot lock the file it made under its name,
    /// it removes the name again, with the check by device and inode
    /// number. Where another process holds the lock, the file is in its
    /// hands and keeps the name (EBUSY). Filters of the test's own thread
    /// refuse RENAME_NOREPLACE and hard links, as vboxsf does, and the
    /// lock: with ENOLCK, as NFS without its lock manager, or with
    /// EWOULDBLOCK, as where another process holds it.
    #[test]
    fn the_last_resort_without_its_lock() {
        let tmp = TempDir::new("unlocked");
        let path = tmp.path().join("a.img");
        let failures = [
            (libc::ENOLCK, format!("failed to lock {}: ", path.display()), false),
            (
                libc::EWOULDBLOCK,
                format!("{} is being used by another process", path.display()),
                true,
            ),
        ];
        for (refused, failed, kept) in failures {
            let given_up = std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut new = named_in(tmp.path(), "a.img", Naming::Exclusive);
                        new.lock().unwrap();
                        let filtered = sys::refuse_in_this_thread(libc::SYS_renameat2, EINVAL)
                            && sys::refuse_in_this_thread(libc::SYS_linkat, EPERM)
                            && sys::refuse_in_this_thread(libc::SYS_flock, refused);
                        filtered.then(|| {
                            let e = new.probe_exclusive_naming().unwrap_err();
                            assert!(path.exists(), "{}", e);
                            new.given_up(e)
                        })
                    })
                    .join()
                    .unwrap()
            });
            let Some(e) = given_up else {
                return eprintln!("skipping: no seccomp filters here");
            };
            assert!(e.message().starts_with(&failed), "{}", e);
            assert_eq!(e.errno(), if kept { EBUSY } else { refused });
            assert_eq!(path.exists(), kept, "{}", e);
            assert_eq!(names_in(tmp.path()).len(), usize::from(kept));
            if kept {
                fs::remove_file(&path).unwrap();
            }
        }
    }

    /// A temporary name is a file name: one for the longest name is that
    /// long, the name cut short. Two are never the same.
    #[test]
    fn temporary_names_are_file_names() {
        let longest = "x".repeat(sys::NAME_MAX);
        let temporary = TemporaryName::new(OsStr::new(&longest)).unwrap().0;
        assert_eq!(temporary.len(), sys::NAME_MAX);
        let kept = sys::NAME_MAX - TemporaryName::PREFIX.len() - TemporaryName::DIGITS;
        assert!(is_temporary_name_of(&temporary, &longest[..kept]));
        let short = TemporaryName::new(OsStr::new("a.img")).unwrap().0;
        assert!(is_temporary_name_of(&short, "a.img"));
        assert_ne!(short, TemporaryName::new(OsStr::new("a.img")).unwrap().0);
    }

    /// The listing of a walk, as (path in the volume, kind) pairs.
    fn walk(root: &Path, follow: bool) -> Result<Vec<(String, char)>> {
        let fd = open_dir(root)?;
        let mut seen = Vec::new();
        walk_tree(fd.as_fd(), "/", follow, UnnamableEntry::Fail, &mut |target, entry| {
            let kind = if entry.is_dir() {
                'd'
            } else if entry.is_file() {
                'f'
            } else {
                '?'
            };
            seen.push((target.to_string(), kind));
            Ok(true)
        })?;
        Ok(seen)
    }

    /// What the walk yields is the tree in byte order of the names, level
    /// by level, the order std's listing has once sorted.
    #[test]
    fn the_walk_order_is_the_byte_order_of_the_names() {
        let tmp = TempDir::new("walk-order");
        let root = tmp.path();
        for name in ["b", "a", "B", "A", "a b", "a-b", "a.b", "\u{e9}", "z", "10", "9", "_x"] {
            fs::write(root.join(name), b"").unwrap();
        }
        fs::create_dir_all(root.join("dir/sub")).unwrap();
        fs::write(root.join("dir/sub/leaf"), b"").unwrap();
        fs::write(root.join("dir/file"), b"").unwrap();
        fs::create_dir(root.join("Dir2")).unwrap();
        let seen = walk(root, false).unwrap();
        let mut top: Vec<String> = fs::read_dir(root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        top.sort_unstable();
        let mut expected = Vec::new();
        for name in top {
            match name.as_str() {
                "dir" => {
                    expected.push(("/dir".to_string(), 'd'));
                    expected.push(("/dir/file".to_string(), 'f'));
                    expected.push(("/dir/sub".to_string(), 'd'));
                    expected.push(("/dir/sub/leaf".to_string(), 'f'));
                }
                "Dir2" => expected.push(("/Dir2".to_string(), 'd')),
                _ => expected.push((format!("/{}", name), 'f')),
            }
        }
        assert_eq!(seen, expected);
        assert_eq!(seen[0].0, "/10");
        assert_eq!(seen.last().unwrap().0, "/\u{e9}");
        // The entries themselves can be opened.
        let fd = open_dir(root).unwrap();
        walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Fail, &mut |_, entry| {
            if entry.is_file() {
                entry.open_file().unwrap();
            }
            Ok(true)
        })
        .unwrap();
    }

    /// Symbolic links are entries of their own unless followed; followed,
    /// they are what they point to, resolved below the root and never
    /// outside it.
    #[test]
    fn symlinks_are_skipped_or_resolved_below_the_root() {
        let tmp = TempDir::new("walk-links");
        let base = tmp.path();
        let root = base.join("root");
        fs::create_dir_all(root.join("dir")).unwrap();
        fs::write(root.join("dir/file"), b"inside").unwrap();
        fs::write(base.join("outside"), b"outside").unwrap();
        symlink("dir/file", root.join("to-file")).unwrap();
        symlink("dir", root.join("to-dir")).unwrap();
        symlink("/dir/file", root.join("abs")).unwrap();
        let seen = walk(&root, false).unwrap();
        assert_eq!(
            seen,
            vec![
                ("/abs".to_string(), '?'),
                ("/dir".to_string(), 'd'),
                ("/dir/file".to_string(), 'f'),
                ("/to-dir".to_string(), '?'),
                ("/to-file".to_string(), '?'),
            ]
        );
        let seen = walk(&root, true).unwrap();
        assert_eq!(
            seen,
            vec![
                ("/abs".to_string(), 'f'),
                ("/dir".to_string(), 'd'),
                ("/dir/file".to_string(), 'f'),
                ("/to-dir".to_string(), 'd'),
                ("/to-dir/file".to_string(), 'f'),
                ("/to-file".to_string(), 'f'),
            ]
        );
        // A link leading out of the root is looked for inside it, and a
        // dangling one is an error either way, as a stat of it was.
        symlink("../outside", root.join("escape")).unwrap();
        let err = walk(&root, true).unwrap_err();
        assert_eq!(err.errno(), ENOENT);
        assert!(err.message().contains("escape"), "{}", err);
        assert_eq!(walk(&root, false).unwrap().len(), 6);
    }

    /// A tree whose paths inside the volume pass the limit: 300 levels of
    /// "n" under a long destination. The walk must stop at the limit
    /// without having recursed through the levels.
    #[test]
    fn a_deep_tree_ends_at_the_path_limit() {
        let tmp = TempDir::new("walk");
        let root = tmp.path();
        let mut deep = root.to_path_buf();
        for _ in 0..300 {
            deep.push("n");
        }
        fs::create_dir_all(&deep).unwrap();
        let dest = format!("/{}", "d".repeat(3500));
        let fd = open_dir(root).unwrap();
        let mut seen = 0;
        let err = walk_tree(fd.as_fd(), &dest, false, UnnamableEntry::Fail, &mut |target, entry| {
            assert!(target.starts_with(&dest) && target.ends_with("/n"));
            assert!(entry.is_dir());
            seen += 1;
            Ok(true)
        })
        .unwrap_err();
        assert_eq!(err.errno(), ENAMETOOLONG);
        // Every level adds "/n" to `dest`.
        let levels = (crate::path::MAX_PATH - dest.len()) / 2;
        assert_eq!(seen, levels);
        // Left out instead, the level past the limit is one entry, with
        // everything below it.
        seen = 0;
        let omitted = walk_tree(fd.as_fd(), &dest, false, UnnamableEntry::Omit, &mut |_, _| {
            seen += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!((seen, omitted), (levels, 1));
        // Not descending ends the walk after the first level.
        seen = 0;
        walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Fail, &mut |_, _| {
            seen += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(seen, 1);
    }

    /// A name that is not UTF-8 fails the walk, or is left out with what is
    /// below it and counted, if it is that of a regular file or a directory.
    #[test]
    fn names_that_are_not_utf8() {
        let tmp = TempDir::new("walk-utf8");
        let root = tmp.path();
        fs::create_dir_all(root.join(OsStr::from_bytes(b"d\xff")).join("inside")).unwrap();
        fs::write(root.join(OsStr::from_bytes(b"f\xfe")), b"x").unwrap();
        fs::write(root.join("kept"), b"x").unwrap();
        // A symbolic link is no file a user of the walk stores, so it is not
        // counted, whatever its name.
        symlink("kept", root.join(OsStr::from_bytes(b"l\xfd"))).unwrap();
        let fd = open_dir(root).unwrap();
        let err = walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Fail, &mut |_, _| Ok(true)).unwrap_err();
        assert_eq!(err.errno(), EINVAL);
        assert!(err.message().contains("not valid UTF-8"), "{}", err);
        let mut seen = Vec::new();
        let omitted = walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Omit, &mut |target, _| {
            seen.push(target.to_string());
            Ok(true)
        })
        .unwrap();
        assert_eq!((seen, omitted), (vec!["/kept".to_string()], 2));
    }

    /// A directory that links to itself, and one that links to its parent:
    /// the walk notices the directory it is about to enter is one it is in
    /// already and ends with ELOOP, not by running on to the path limit.
    #[test]
    fn a_looping_tree_ends_with_eloop() {
        let tmp = TempDir::new("loop");
        let root = tmp.path();
        symlink(".", root.join("loop")).unwrap();
        let fd = open_dir(root).unwrap();
        let mut seen = 0;
        let err = walk_tree(fd.as_fd(), "/", true, UnnamableEntry::Fail, &mut |_, entry| {
            assert!(entry.is_dir());
            seen += 1;
            Ok(true)
        })
        .unwrap_err();
        assert_eq!(err.errno(), ELOOP);
        assert!(err.message().contains("loop"), "{}", err);
        assert_eq!(seen, 1);
        fs::remove_file(root.join("loop")).unwrap();
        fs::create_dir_all(root.join("a/b")).unwrap();
        symlink("..", root.join("a/b/up")).unwrap();
        let err = walk(root, true).unwrap_err();
        assert_eq!(err.errno(), ELOOP);
        assert!(err.message().contains("a/b/up"), "{}", err);
        // Not following, the links are entries of their own.
        assert_eq!(walk(root, false).unwrap().len(), 3);
        symlink(".", root.join("loop")).unwrap();
        fs::remove_dir_all(root.join("a")).unwrap();
        // Without following links the link is one entry, not a directory.
        seen = 0;
        walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Fail, &mut |_, entry| {
            assert!(!entry.is_dir() && !entry.is_file());
            seen += 1;
            Ok(true)
        })
        .unwrap();
        assert_eq!(seen, 1);
    }

    #[test]
    fn opening_the_edges() {
        let tmp = TempDir::new("edges");
        let root = tmp.path();
        fs::write(root.join("file"), b"data").unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        symlink("dir", root.join("to-dir")).unwrap();
        symlink("file", root.join("to-file")).unwrap();
        sys::make_fifo(&root.join("fifo")).unwrap();
        assert!(open_dir(&root.join("dir")).is_ok());
        assert!(open_dir(&root.join("to-dir")).is_ok());
        assert_eq!(open_dir(&root.join("file")).unwrap_err().errno(), ENOTDIR);
        assert_eq!(open_dir(&root.join("missing")).unwrap_err().errno(), ENOENT);
        let mut text = String::new();
        open_file(&root.join("to-file"))
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "data");
        assert_eq!(open_file(&root.join("dir")).unwrap_err().errno(), EINVAL);
        // A FIFO nobody writes to is refused before it could make us wait.
        let started = std::time::Instant::now();
        assert_eq!(open_file(&root.join("fifo")).unwrap_err().errno(), EINVAL);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        let dir = open_dir(root).unwrap();
        let mut text = String::new();
        open_file_at(dir.as_fd(), OsStr::new("file"))
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "data");
        assert_eq!(
            open_file_at(dir.as_fd(), OsStr::new("fifo")).unwrap_err().errno(),
            EINVAL
        );
        assert_eq!(
            open_file_at(dir.as_fd(), OsStr::new("missing")).unwrap_err().errno(),
            ENOENT
        );
        assert_eq!(
            open_file_at(dir.as_fd(), OsStr::new("dir/../file"))
                .unwrap_err()
                .errno(),
            EINVAL
        );
        // The parent of a path is resolved once, the last component is
        // opened relative to it.
        let (parent, name) = open_parent(&root.join("dir/../file")).unwrap();
        assert_eq!(name, "file");
        let mut text = String::new();
        open_file_at(parent.as_fd(), &name)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "data");
        assert_eq!(open_parent(Path::new("/")).unwrap_err().errno(), EINVAL);
        assert_eq!(open_parent(Path::new("..")).unwrap_err().errno(), EINVAL);
        assert_eq!(open_parent(&root.join("missing/file")).unwrap_err().errno(), ENOENT);
        assert_eq!(open_parent(Path::new("bare-name")).unwrap().1, "bare-name");
        let mut from_start = FromStart::new(dir.as_fd());
        assert!(from_start.read(&mut [0u8; 4]).is_err());
    }

    /// An entry removed after the directory was listed but before the walk
    /// reached it is left out; the walk goes on with the next one.
    #[test]
    fn an_entry_that_vanishes_is_left_out() {
        let tmp = TempDir::new("walk-vanish");
        let root = tmp.path();
        for name in ["a0", "a1", "a2", "a3", "a4"] {
            fs::write(root.join(name), b"").unwrap();
        }
        let fd = open_dir(root).unwrap();
        let mut seen = Vec::new();
        walk_tree(fd.as_fd(), "/", false, UnnamableEntry::Fail, &mut |target, _| {
            if target == "/a1" {
                fs::remove_file(root.join("a2")).unwrap();
            }
            seen.push(target.to_string());
            Ok(true)
        })
        .unwrap();
        assert_eq!(seen, vec!["/a0", "/a1", "/a3", "/a4"]);
    }

    /// A followed link is resolved from the directory it was found in, the
    /// one the walk has pinned, not by its name from the root: when the
    /// directories are swapped around after the walk looked at them, the
    /// link still leads to the file next to it.
    #[test]
    fn a_followed_link_is_resolved_from_its_own_directory() {
        let tmp = TempDir::new("walk-swap");
        let root = tmp.path();
        for (dir, text) in [("c", "C"), ("d", "D")] {
            fs::create_dir(root.join(dir)).unwrap();
            fs::write(root.join(dir).join("t"), text).unwrap();
            symlink("t", root.join(dir).join("link")).unwrap();
        }
        let fd = open_dir(root).unwrap();
        let mut contents = Vec::new();
        walk_tree(fd.as_fd(), "/", true, UnnamableEntry::Fail, &mut |target, entry| {
            if target == "/d" {
                // "d" is pinned; now root/d is what used to be root/c.
                fs::rename(root.join("d"), root.join("e")).unwrap();
                fs::rename(root.join("c"), root.join("d")).unwrap();
            }
            if entry.is_file() {
                let mut text = String::new();
                entry.open_file().unwrap().read_to_string(&mut text).unwrap();
                contents.push((target.to_string(), text));
            }
            Ok(true)
        })
        .unwrap();
        let link_in_d = contents.iter().find(|(t, _)| t == "/d/link").unwrap();
        assert_eq!(link_in_d.1, "D");
        assert_eq!(contents.len(), 4);
    }

    /// What another process hands us is taken only when it is open the way
    /// the use needs: no O_PATH, nothing beyond the access mode, read-only
    /// for everything we read, read-write without O_APPEND for the image.
    #[test]
    fn passed_descriptors_are_vetted() {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = TempDir::new("passed");
        let root = tmp.path();
        fs::write(root.join("file"), b"data").unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        let open = |name: &str, flags: i32| -> OwnedFd {
            let mut o = fs::OpenOptions::new();
            o.read(flags & sys::O_ACCMODE != sys::O_WRONLY)
                .write(flags & sys::O_ACCMODE != sys::O_RDONLY)
                .custom_flags(flags & !sys::O_ACCMODE);
            OwnedFd::from(o.open(root.join(name)).unwrap())
        };
        // Sources must be read-only.
        assert!(passed_file(open("file", sys::O_RDONLY)).is_ok());
        assert_eq!(passed_file(open("file", sys::O_RDWR)).unwrap_err().errno(), EBADFD);
        assert_eq!(passed_file(open("dir", sys::O_RDONLY)).unwrap_err().errno(), EBADFD);
        let pinned = sys::open_path(None, &root.join("file"), false).unwrap();
        let err = passed_file(pinned).unwrap_err();
        assert_eq!(err.errno(), EBADFD);
        assert!(
            matches!(
                err.detail(),
                Some(Detail::Descriptor {
                    problem: DescriptorProblem::OPath,
                    ..
                })
            ),
            "{:?}",
            err
        );
        assert!(passed_directory(open("dir", sys::O_RDONLY | sys::O_DIRECTORY)).is_ok());
        assert!(passed_directory(open("dir", sys::O_RDONLY)).is_ok());
        assert_eq!(
            passed_directory(open("file", sys::O_RDONLY)).unwrap_err().errno(),
            EBADFD
        );
        // Streams: a regular file or a pipe, blocking.
        assert!(passed_stream(open("file", sys::O_RDONLY), "stream").is_ok());
        assert_eq!(
            passed_stream(open("dir", sys::O_RDONLY), "stream").unwrap_err().errno(),
            EBADFD
        );
        sys::make_fifo(&root.join("fifo")).unwrap();
        let reader = open("fifo", sys::O_RDONLY | sys::O_NONBLOCK);
        let _writer = open("fifo", sys::O_WRONLY);
        let err = passed_stream(open("fifo", sys::O_RDONLY | sys::O_NONBLOCK), "stream").unwrap_err();
        assert!(
            matches!(
                err.detail(),
                Some(Detail::Descriptor {
                    problem: DescriptorProblem::Flags,
                    flags: Some(f),
                    parameter: Some("stream"),
                }) if f & sys::O_NONBLOCK != 0
            ),
            "{:?}",
            err
        );
        assert!(passed_stream(open("fifo", sys::O_RDONLY), "stream").is_ok());
        drop(reader);
        // The image: read-write for writing, O_APPEND never.
        assert!(passed_image(open("file", sys::O_RDONLY), Access::ReadOnly).is_ok());
        assert!(passed_image(open("file", sys::O_RDWR), Access::ReadOnly).is_ok());
        assert!(passed_image(open("file", sys::O_RDWR), Access::ReadWrite).is_ok());
        assert_eq!(
            passed_image(open("file", sys::O_RDONLY), Access::ReadWrite)
                .unwrap_err()
                .errno(),
            EBADFD
        );
        assert_eq!(
            passed_image(open("file", sys::O_WRONLY), Access::ReadWrite)
                .unwrap_err()
                .errno(),
            EBADFD
        );
        let err = passed_image(open("file", sys::O_RDWR | sys::O_APPEND), Access::ReadWrite).unwrap_err();
        assert_eq!(err.errno(), EBADFD);
        assert!(
            matches!(
                err.detail(),
                Some(Detail::Descriptor {
                    problem: DescriptorProblem::Flags,
                    flags: Some(f),
                    parameter: None,
                }) if f & sys::O_APPEND != 0
            ),
            "{:?}",
            err
        );
        assert_eq!(
            passed_image(open("dir", sys::O_RDONLY), Access::ReadOnly)
                .unwrap_err()
                .errno(),
            EBADFD
        );
        assert!(passed_image(open("file", sys::O_RDWR | sys::O_NONBLOCK), Access::ReadWrite).is_ok());
        // A source is whatever its type says, as long as it is read-only.
        assert!(matches!(
            passed_source(open("dir", sys::O_RDONLY), "source").unwrap(),
            PassedSource::Directory(_)
        ));
        assert!(matches!(
            passed_source(open("file", sys::O_RDONLY), "source").unwrap(),
            PassedSource::Stream(_)
        ));
        let _reader = open("fifo", sys::O_RDONLY | sys::O_NONBLOCK);
        let _writer = open("fifo", sys::O_WRONLY);
        assert!(matches!(
            passed_source(open("fifo", sys::O_RDONLY), "source").unwrap(),
            PassedSource::Stream(_)
        ));
        assert_eq!(
            passed_source(open("file", sys::O_RDWR), "source").unwrap_err().errno(),
            EBADFD
        );
    }

    /// What a full pipe is filled with at a time.
    const FILL: &[u8] = &[0; 4096];

    /// A client that kept copies of the ends of a pipe it passed sets
    /// O_NONBLOCK on them after the vetting: the read from the empty pipe
    /// and the write to the full one fail with the vetting's flags problem
    /// instead of a bare EAGAIN. Other errors are left as they are, and so
    /// is EAGAIN while the pipe still blocks.
    #[test]
    fn a_pipe_made_non_blocking_during_the_call_is_refused() {
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = TempDir::new("flipped");
        let fifo = tmp.path().join("fifo");
        sys::make_fifo(&fifo).unwrap();
        // Opened without waiting for a writer, then made blocking for the
        // vetting.
        let reader = fs::OpenOptions::new()
            .read(true)
            .custom_flags(sys::O_NONBLOCK)
            .open(&fifo)
            .unwrap();
        let flags = sys::descriptor_flags(reader.as_fd()).unwrap();
        sys::set_status_flags(reader.as_fd(), flags & !sys::O_NONBLOCK).unwrap();
        let writer = fs::OpenOptions::new().write(true).open(&fifo).unwrap();
        let clients = [reader.try_clone().unwrap(), writer.try_clone().unwrap()];
        let mut stream = passed_stream(OwnedFd::from(reader), "stream").unwrap();
        let mut sink = passed_sink(OwnedFd::from(writer), "sink").unwrap();
        let again = stream.explain(io::Error::from_raw_os_error(EAGAIN));
        assert_eq!(again.raw_os_error(), Some(EAGAIN));
        for client in &clients {
            let flags = sys::descriptor_flags(client.as_fd()).unwrap();
            sys::set_status_flags(client.as_fd(), flags | sys::O_NONBLOCK).unwrap();
        }
        let refused = |e: io::Error, parameter: &'static str| {
            let e = Error::from(e);
            assert_eq!(e.errno(), EBADFD);
            assert_eq!(
                e.detail(),
                Some(&Detail::Descriptor {
                    problem: DescriptorProblem::Flags,
                    flags: Some(sys::O_NONBLOCK),
                    parameter: Some(parameter),
                })
            );
            assert_eq!(e.message(), "the descriptor was made non-blocking during the call");
        };
        refused(stream.read(&mut [0; 1]).unwrap_err(), "stream");
        let full = loop {
            if let Err(e) = sink.write(FILL) {
                break e;
            }
        };
        refused(full, "sink");
        let other = stream.explain(io::Error::from_raw_os_error(EIO));
        assert_eq!(other.raw_os_error(), Some(EIO));
    }
}
