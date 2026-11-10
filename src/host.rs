// SPDX-License-Identifier: LGPL-2.1-or-later
//! Host directories: resolving the paths we are given once.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::errno::*;
use crate::sys;
use crate::{Context, Result};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TempDir;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

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
    }
}
