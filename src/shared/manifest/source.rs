// SPDX-License-Identifier: LGPL-2.1-or-later
//! The directory on the host the contents of the files of a manifest
//! come from.

use std::os::fd::{AsFd, OwnedFd};

use uapi16::{Directory, Name, OpenError};

use crate::sys;

/// The directory on the host the files of a manifest are taken from: the
/// one the manifest lives in, or the one the caller chose instead.
#[derive(Debug)]
pub struct SourceDirectory {
    dir: OwnedFd,
    follow_symlinks: bool,
}

impl SourceDirectory {
    /// The files below the open directory `dir`, which the caller resolved
    /// once (with [`crate::host::open_dir`] when it has a path) and which is
    /// never looked up again. A file reference is resolved below it the way
    /// systemd's chase() resolves a path below a root: an absolute symbolic
    /// link target starts over at `dir`, `..` at `dir` stays there, nothing
    /// resolves to anything outside it, and symbolic links are followed
    /// only when [`SourceDirectory::follow_symlinks`] allows them.
    pub fn new(dir: OwnedFd) -> SourceDirectory {
        SourceDirectory {
            dir,
            follow_symlinks: false,
        }
    }

    /// Follows symbolic links inside the source tree, as long as they stay
    /// inside it. Off by default, like the populator: a link planted in a
    /// tree would otherwise make a privileged assembly read any file on the
    /// host.
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> SourceDirectory {
        self.follow_symlinks = follow;
        self
    }

    /// Pins the file `file` names below the directory and checks that it
    /// is a regular file. Returns it with its size.
    fn pin(&self, file: &Name) -> Result<(OwnedFd, u64), OpenError> {
        let pinned = sys::chase(self.dir.as_fd(), file.as_bytes(), self.follow_symlinks, false)?;
        let md = sys::fstat(pinned.as_fd())?;
        if !md.is_file() {
            return Err(OpenError::NotRegular);
        }
        Ok((pinned, md.len()))
    }
}

impl Directory for SourceDirectory {
    type File = std::fs::File;

    /// Opens the file: pinned, checked to be a regular file, and only then
    /// opened for reading.
    fn open(&self, file: &Name) -> Result<(std::fs::File, u64), OpenError> {
        let (pinned, len) = self.pin(file)?;
        let fd = sys::reopen(pinned.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)?;
        Ok((std::fs::File::from(fd), len))
    }

    /// One lookup and one fstat, found the way [`Directory::open`] finds
    /// the file.
    fn size(&self, file: &Name) -> Result<u64, OpenError> {
        self.pin(file).map(|(_, len)| len)
    }
}

/// Reads file data from a [`SourceDirectory`].
///
/// Its `verify()` checks, without reading any data, that every file a
/// manifest would read from the directory is there, is a regular file and
/// is as long as the manifest says. Run before an image is created or
/// formatted, it makes a wrong source directory fail with nothing
/// half-made left behind.
pub type DirectorySource = uapi16::DirectorySource<SourceDirectory>;
