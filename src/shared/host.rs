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
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use crate::device::{Access, Device};
use crate::errno::*;
use crate::sys;
use crate::{Context, Result};
use crate::{DescriptorProblem, Detail};

/// The detail of a passed descriptor that cannot be used.
fn unusable(problem: DescriptorProblem, flags: Option<i32>) -> Detail {
    Detail::Descriptor { problem, flags }
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
fn vet_flags(fd: BorrowedFd<'_>, extra: i32, what: &str) -> Result<Access> {
    match vet_status(fd, extra, what)? {
        sys::O_RDONLY => Ok(Access::ReadOnly),
        sys::O_RDWR => Ok(Access::ReadWrite),
        _ => bail!(
            EBADFD,
            unusable(DescriptorProblem::WriteOnly, None),
            "the {} descriptor is open for writing only",
            what
        ),
    }
}

/// The checks of [`vet_flags`] up to the access mode, which is returned as
/// it is (O_RDONLY, O_WRONLY or O_RDWR) for the caller to judge.
fn vet_status(fd: BorrowedFd<'_>, extra: i32, what: &str) -> Result<i32> {
    let flags = sys::descriptor_flags(fd)?;
    if flags & sys::O_PATH != 0 {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::OPath, None),
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
            unusable(DescriptorProblem::Flags, Some(unexpected)),
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
            unusable(DescriptorProblem::Flags, Some(other)),
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
    let open_for = vet_flags(fd.as_fd(), sys::O_NONBLOCK, "image")?;
    if access == Access::ReadWrite && open_for != Access::ReadWrite {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadWrite, None),
            "the image descriptor is not open for reading and writing"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_block_device() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the image descriptor is not a regular file or block device"
        );
    }
    Device::from_passed(fd, access)
}

/// Takes a descriptor another process handed over as a source directory,
/// the root everything below is resolved against: a directory, open for
/// reading only (O_DIRECTORY accepted, O_PATH refused).
pub fn passed_directory(fd: OwnedFd) -> Result<OwnedFd> {
    if vet_flags(fd.as_fd(), sys::O_DIRECTORY, "source directory")? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None),
            "the source directory descriptor is not open read-only"
        );
    }
    if !sys::fstat(fd.as_fd())?.is_dir() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the source directory descriptor is not a directory"
        );
    }
    Ok(fd)
}

/// Takes a descriptor another process handed over as a file to copy: a
/// regular file open for reading only, read with positional reads from
/// its start, so the position of the client's descriptor is left alone.
pub fn passed_file(fd: OwnedFd) -> Result<File> {
    if vet_flags(fd.as_fd(), 0, "source file")? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None),
            "the source file descriptor is not open read-only"
        );
    }
    if !sys::fstat(fd.as_fd())?.is_file() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the source file descriptor is not a regular file"
        );
    }
    Ok(File::from(fd))
}

/// What a source descriptor turned out to be.
#[derive(Debug)]
pub enum PassedSource {
    /// A directory, the tree the files come from.
    Directory(OwnedFd),
    /// A regular file or pipe carrying the files' contents in order.
    Stream(File),
}

/// Takes a descriptor another process handed over as the source of a
/// manifest's file contents, which its type decides, the way the command
/// line's SOURCE is a directory or "-": a directory, open read-only
/// (O_DIRECTORY accepted), is the tree the manifest describes; a regular
/// file or pipe, open read-only and blocking, carries the contents in
/// manifest order. Anything else is EBADFD.
pub fn passed_source(fd: OwnedFd) -> Result<PassedSource> {
    if vet_flags(fd.as_fd(), sys::O_DIRECTORY, "source")? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None),
            "the source descriptor is not open read-only"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if ft.is_dir() {
        Ok(PassedSource::Directory(fd))
    } else if ft.is_file() || ft.is_fifo() {
        Ok(PassedSource::Stream(File::from(fd)))
    } else {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the source descriptor is not a directory, a regular file or a pipe"
        );
    }
}

/// Takes a descriptor another process handed over as a stream to read to
/// its end from where it stands, a manifest or the contents of files in
/// manifest order: a regular file or a pipe, open for reading only, without
/// O_NONBLOCK since a pipe would then fail instead of wait. A socket is
/// always open for reading and writing and so never passes here.
pub fn passed_stream(fd: OwnedFd) -> Result<File> {
    if vet_flags(fd.as_fd(), 0, "stream")? != Access::ReadOnly {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotReadOnly, None),
            "the stream descriptor is not open read-only"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_fifo() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the stream descriptor is not a regular file or pipe"
        );
    }
    Ok(File::from(fd))
}

/// Takes a descriptor another process handed over as the sink a manifest
/// is written to: a regular file or a pipe, open for writing (O_WRONLY or
/// O_RDWR). O_APPEND is accepted, since the manifest goes out sequentially
/// and where in its file the caller wants it is the caller's business;
/// O_NONBLOCK is not, since a full pipe would then fail instead of wait.
/// A descriptor open read-only is `NotWritable`, anything but a regular
/// file or pipe `WrongType`.
pub fn passed_sink(fd: OwnedFd) -> Result<File> {
    if vet_status(fd.as_fd(), sys::O_APPEND, "sink")? == sys::O_RDONLY {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::NotWritable, None),
            "the sink descriptor is not open for writing"
        );
    }
    let ft = sys::fstat(fd.as_fd())?.file_type();
    if !ft.is_file() && !ft.is_fifo() {
        bail!(
            EBADFD,
            unusable(DescriptorProblem::WrongType, None),
            "the sink descriptor is not a regular file or pipe"
        );
    }
    Ok(File::from(fd))
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

/// Opens the directory `dir`, pinned or open, for listing: a descriptor of
/// our own with its own position, so a caller's descriptor keeps its state.
pub fn listing_of(dir: BorrowedFd<'_>) -> Result<OwnedFd> {
    Ok(sys::reopen(dir, sys::O_RDONLY | sys::O_DIRECTORY)?)
}

/// An entry of a host directory, pinned while it is being visited.
pub struct HostEntry {
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
    /// Whether the entry is a directory.
    pub fn is_dir(&self) -> bool {
        self.metadata.is_dir()
    }

    /// Whether the entry is a regular file.
    pub fn is_file(&self) -> bool {
        self.metadata.is_file()
    }

    /// Opens the entry, a regular file, for reading: the pinned inode
    /// reopened, so what is read is what the metadata describes.
    pub fn open_file(&self) -> Result<File> {
        let fd = sys::reopen(self.fd.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)
            .with_context(|| format!("failed to open {}", self.path.display()))?;
        Ok(File::from(fd))
    }
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
/// the path limit. A name that is not UTF-8 is an error since it could not
/// be stored as a long name anyway, and so is a path inside the volume
/// longer than [`crate::path::MAX_PATH`].
pub fn walk_tree(
    root: BorrowedFd<'_>,
    dest: &str,
    follow_symlinks: bool,
    visit: &mut dyn FnMut(&str, &HostEntry) -> Result<bool>,
) -> Result<()> {
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
    loop {
        let Some(level) = stack.last_mut() else { return Ok(()) };
        let Some(name) = level.names.next() else {
            stack.pop();
            continue;
        };
        let path = level.path.join(OsStr::from_bytes(&name));
        let name = String::from_utf8(name).map_err(|_| err!(EINVAL, "{} is not valid UTF-8", path.display()))?;
        let target = crate::path::join(&level.target, &name);
        if target.len() > crate::path::MAX_PATH {
            bail!(
                ENAMETOOLONG,
                "{}: its path inside the volume is longer than {} bytes",
                path.display(),
                crate::path::MAX_PATH
            );
        }
        let stat = || format!("failed to stat {}", path.display());
        let mut fd = match sys::pin_entry(level.dir.as_fd(), name.as_bytes()) {
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
pub fn read_some(reader: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
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
pub struct FromStart<'a> {
    fd: BorrowedFd<'a>,
    pos: u64,
}

impl<'a> FromStart<'a> {
    /// Reads `fd` from its first byte.
    pub fn new(fd: BorrowedFd<'a>) -> FromStart<'a> {
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
    use std::os::unix::fs::symlink;

    /// The listing of a walk, as (path in the volume, kind) pairs.
    fn walk(root: &Path, follow: bool) -> Result<Vec<(String, char)>> {
        let fd = open_dir(root)?;
        let mut seen = Vec::new();
        walk_tree(fd.as_fd(), "/", follow, &mut |target, entry| {
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
        top.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
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
        walk_tree(fd.as_fd(), "/", false, &mut |_, entry| {
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
        let err = walk_tree(fd.as_fd(), &dest, false, &mut |target, entry| {
            assert!(target.starts_with(&dest) && target.ends_with("/n"));
            assert!(entry.is_dir());
            seen += 1;
            Ok(true)
        })
        .unwrap_err();
        assert_eq!(err.errno(), ENAMETOOLONG);
        // Every level adds "/n" to `dest`.
        assert_eq!(seen, (crate::path::MAX_PATH - dest.len()) / 2);
        // Not descending ends the walk after the first level.
        seen = 0;
        walk_tree(fd.as_fd(), "/", false, &mut |_, _| {
            seen += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(seen, 1);
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
        let err = walk_tree(fd.as_fd(), "/", true, &mut |_, entry| {
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
        walk_tree(fd.as_fd(), "/", false, &mut |_, entry| {
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

    /// The descriptors of this process that refer to something below
    /// `root`. Other tests run in other threads of this process with
    /// descriptors of their own, so only ours are counted.
    fn descriptors_below(root: &Path) -> usize {
        fs::read_dir("/proc/self/fd")
            .unwrap()
            .filter(|e| match fs::read_link(e.as_ref().unwrap().path()) {
                Ok(target) => target.starts_with(root),
                Err(_) => false,
            })
            .count()
    }

    /// A directory of 1500 entries, more than the usual soft limit of 1024
    /// descriptors: the walk pins one entry at a time and holds one
    /// directory per level, so it never needs more than a handful.
    #[test]
    fn a_large_directory_costs_no_descriptors() {
        let tmp = TempDir::new("walk-large");
        let root = tmp.path();
        fs::create_dir(root.join("big")).unwrap();
        for i in 0..1500 {
            fs::write(root.join(format!("big/f{:04}", i)), b"x").unwrap();
        }
        let fd = open_dir(root).unwrap();
        let mut seen = 0;
        let mut most = 0;
        walk_tree(fd.as_fd(), "/", false, &mut |_, entry| {
            if entry.is_file() {
                let mut text = String::new();
                entry.open_file().unwrap().read_to_string(&mut text).unwrap();
                assert_eq!(text, "x");
            }
            seen += 1;
            most = most.max(descriptors_below(root));
            Ok(true)
        })
        .unwrap();
        assert_eq!(seen, 1501);
        // The test's own root descriptor, the walk's dup of it, the pinned
        // "big" and the pinned entry being visited.
        assert!(most <= 4, "{} descriptors open below the root", most);
        assert_eq!(descriptors_below(root), 1);
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
        walk_tree(fd.as_fd(), "/", false, &mut |target, _| {
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
        walk_tree(fd.as_fd(), "/", true, &mut |target, entry| {
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
        assert!(passed_stream(open("file", sys::O_RDONLY)).is_ok());
        assert_eq!(passed_stream(open("dir", sys::O_RDONLY)).unwrap_err().errno(), EBADFD);
        sys::make_fifo(&root.join("fifo")).unwrap();
        let reader = open("fifo", sys::O_RDONLY | sys::O_NONBLOCK);
        let _writer = open("fifo", sys::O_WRONLY);
        let err = passed_stream(open("fifo", sys::O_RDONLY | sys::O_NONBLOCK)).unwrap_err();
        assert!(
            matches!(
                err.detail(),
                Some(Detail::Descriptor {
                    problem: DescriptorProblem::Flags,
                    flags: Some(f),
                }) if f & sys::O_NONBLOCK != 0
            ),
            "{:?}",
            err
        );
        assert!(passed_stream(open("fifo", sys::O_RDONLY)).is_ok());
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
            passed_source(open("dir", sys::O_RDONLY)).unwrap(),
            PassedSource::Directory(_)
        ));
        assert!(matches!(
            passed_source(open("file", sys::O_RDONLY)).unwrap(),
            PassedSource::Stream(_)
        ));
        let _reader = open("fifo", sys::O_RDONLY | sys::O_NONBLOCK);
        let _writer = open("fifo", sys::O_WRONLY);
        assert!(matches!(
            passed_source(open("fifo", sys::O_RDONLY)).unwrap(),
            PassedSource::Stream(_)
        ));
        assert_eq!(passed_source(open("file", sys::O_RDWR)).unwrap_err().errno(), EBADFD);
    }
}
