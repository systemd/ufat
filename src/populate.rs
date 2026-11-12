// SPDX-License-Identifier: LGPL-2.1-or-later
//! Copying files and directory trees from the host into a volume.
//!
//! Trees are walked in byte order of the file names, so the directory
//! entries and the cluster allocation do not depend on the host file
//! system's readdir order. Only regular files and directories are copied;
//! everything else is reported as skipped.

use std::fs;
use std::io::{self, Read};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::PathBuf;
use std::time::SystemTime;

use crate::errno::*;
use crate::host::{walk_tree, FromStart};
use crate::progress::Progress;
use crate::sys;
use crate::volume::{Volume, MAX_FILE_SIZE};
use crate::Detail;
use crate::{Context, Error, Result};

/// Size of the buffer used when copying file contents.
const COPY_BUFFER: usize = 1024 * 1024;

/// How copied files and directories get their timestamps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimePolicy {
    /// Keep the source's modification time.
    Preserve,
    /// Stamp everything with this time.
    Fixed(SystemTime),
    /// Keep the source's modification time unless it is later than this,
    /// the SOURCE_DATE_EPOCH convention.
    Clamp(SystemTime),
}

impl TimePolicy {
    /// The time to store for a source modified at `source`.
    pub fn resolve(self, source: SystemTime) -> SystemTime {
        match self {
            TimePolicy::Preserve => source,
            TimePolicy::Fixed(t) => t,
            TimePolicy::Clamp(t) => source.min(t),
        }
    }
}

/// Options for copying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyOptions {
    /// Timestamp handling.
    pub times: TimePolicy,
    /// Replace files that already exist in the volume instead of failing
    /// with EEXIST.
    pub replace: bool,
    /// Follow symbolic links in the source tree instead of skipping them.
    pub follow_symlinks: bool,
}

impl Default for CopyOptions {
    fn default() -> Self {
        CopyOptions {
            times: TimePolicy::Preserve,
            replace: true,
            follow_symlinks: false,
        }
    }
}

/// What a tree copy did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopyReport {
    /// Files copied.
    pub files: u64,
    /// Directories created or reused below the destination. The
    /// destination itself, created when it is missing, is not counted, so
    /// this is the number of subdirectories in the source tree.
    pub directories: u64,
    /// File bytes copied.
    pub bytes: u64,
    /// Source entries that were neither regular files nor directories,
    /// relative to the source directory. An entry removed while the tree
    /// was being read is left out as if it had not been there and is not
    /// listed here.
    pub skipped: Vec<PathBuf>,
}

/// The source's modification time, or the epoch when it cannot be read.
fn source_mtime(md: &fs::Metadata) -> SystemTime {
    md.modified().unwrap_or(SystemTime::UNIX_EPOCH)
}

impl CopyReport {
    /// What the copy has done so far, as a progress callback hears it.
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}

/// A source that tells `progress` after every read how many bytes it
/// handed out, on top of what `done` counts.
struct Counted<'a> {
    inner: &'a mut dyn Read,
    done: Progress,
    progress: &'a mut dyn FnMut(&Progress),
}

impl Read for Counted<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.done.bytes += n as u64;
        (self.progress)(&self.done);
        Ok(n)
    }
}

impl Volume {
    /// Copies the contents of `source` into a new file at `dest` and returns
    /// how many bytes it copied.
    pub fn write_file(&mut self, dest: &str, source: &mut dyn Read, time: SystemTime, replace: bool) -> Result<u64> {
        let mut file = self.begin_file(dest, time, replace).map_err(|e| e.at_path(dest))?;
        // The volume keeps one copy buffer, allocated on first use; the
        // file token lets us hold it while the file is open.
        let mut buf = std::mem::take(&mut self.copy_buffer);
        if buf.len() != COPY_BUFFER {
            buf = vec![0u8; COPY_BUFFER];
        }
        let mut total = 0u64;
        let result = loop {
            let n = match crate::host::read_some(source, &mut buf) {
                Ok(n) => n,
                Err(e) => break Err(Error::from(e).context(format!("reading source of '{}'", dest))),
            };
            if n == 0 {
                break Ok(());
            }
            if let Err(e) = self.write_file_data(&mut file, &buf[..n]) {
                break Err(e.at_path(dest));
            }
            total += n as u64;
        };
        self.copy_buffer = buf;
        match result {
            Ok(()) => {
                self.finish_file(file).map_err(|e| e.at_path(dest))?;
                Ok(total)
            }
            Err(e) => {
                let _ = self.abort_file(file);
                Err(e)
            }
        }
    }

    /// Copies the open regular file `source` to `dest` in the volume and
    /// returns the number of bytes copied. The descriptor is what the caller
    /// resolved its path to, with [`crate::host::open_file`] when it has a
    /// path; it has to be a regular file (EINVAL) and is read from its start
    /// with positional reads, so its file position is neither used nor
    /// changed.
    pub fn copy_file(&mut self, source: BorrowedFd<'_>, dest: &str, options: &CopyOptions) -> Result<u64> {
        self.copy_file_with_progress(source, dest, options, &mut |_| {})
    }

    /// [`Volume::copy_file`], telling `progress` how many bytes it copied so
    /// far after every read of the source.
    pub fn copy_file_with_progress(
        &mut self,
        source: BorrowedFd<'_>,
        dest: &str,
        options: &CopyOptions,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<u64> {
        self.copy_counted(source, dest, options, Progress::default(), progress)
    }

    /// Copies a file as [`Volume::copy_file`] does and tells `progress`
    /// about its bytes on top of what `done` counts.
    fn copy_counted(
        &mut self,
        source: BorrowedFd<'_>,
        dest: &str,
        options: &CopyOptions,
        done: Progress,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<u64> {
        let md = sys::fstat(source)?;
        if !md.is_file() {
            bail!(EINVAL, "the source of '{}' is not a regular file", dest);
        }
        if md.len() > MAX_FILE_SIZE {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: Some(dest.to_string()),
                    size: md.len(),
                    maximum: MAX_FILE_SIZE,
                },
                "the source of '{}' is larger than FAT32 allows ({} bytes)",
                dest,
                MAX_FILE_SIZE
            );
        }
        let time = options.times.resolve(source_mtime(&md));
        let mut counted = Counted {
            inner: &mut FromStart::new(source),
            done,
            progress,
        };
        self.write_file(dest, &mut counted, time, options.replace)
    }

    /// Copies the tree below the open directory `source` into the directory
    /// `dest` of the volume, creating `dest` and missing parents as needed.
    /// The descriptor is what the caller resolved its path to, with
    /// [`crate::host::open_dir`] when it has a path, and may be O_PATH;
    /// everything below it is reached by descriptor and nothing is looked
    /// up by path again. The skipped entries are reported relative to
    /// `source`.
    pub fn copy_tree(&mut self, source: BorrowedFd<'_>, dest: &str, options: &CopyOptions) -> Result<CopyReport> {
        self.copy_tree_with_progress(source, dest, options, &mut |_| {})
    }

    /// [`Volume::copy_tree`], telling `progress` what it copied so far after
    /// every directory, every file and every read of a file.
    pub fn copy_tree_with_progress(
        &mut self,
        source: BorrowedFd<'_>,
        dest: &str,
        options: &CopyOptions,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<CopyReport> {
        let md = sys::fstat(source).with_context(|| "failed to stat the source directory")?;
        if !md.is_dir() {
            bail!(ENOTDIR, "the source is not a directory");
        }
        let mut report = CopyReport::default();
        self.create_dir_all(dest, options.times.resolve(source_mtime(&md)))?;
        walk_tree(source, dest, options.follow_symlinks, &mut |target, entry| {
            if entry.is_dir() {
                let time = options.times.resolve(source_mtime(&entry.metadata));
                match self.metadata(target) {
                    Ok(m) if m.is_dir => {}
                    Ok(_) => bail!(ENOTDIR, "'{}' exists in the volume and is not a directory", target),
                    Err(e) if e.errno() == ENOENT => self.create_dir(target, time)?,
                    Err(e) => return Err(e),
                }
                report.directories += 1;
                progress(&report.progress());
                Ok(true)
            } else if entry.is_file() {
                let file = entry.open_file()?;
                report.bytes += self
                    .copy_counted(file.as_fd(), target, options, report.progress(), progress)
                    .map_err(|e| e.at_path(target).context(format!("copying {}", entry.path.display())))?;
                report.files += 1;
                progress(&report.progress());
                Ok(false)
            } else {
                report.skipped.push(entry.path.clone());
                Ok(false)
            }
        })?;
        Ok(report)
    }
}
