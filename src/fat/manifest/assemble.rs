// SPDX-License-Identifier: LGPL-2.1-or-later
//! Assembling a volume from a manifest: the walk over the manifest that
//! creates directories and files and verifies sizes and hashes.

use std::fmt;
use std::io::Write;
use std::ops::{BitOr, BitOrAssign};
use std::time::{SystemTime, UNIX_EPOCH};

use uapi16::{ContentSource, FileObject};

use super::{volume_path, Manifest, Storable};
use crate::errno::*;
use crate::progress::Progress;
use crate::volume::Volume;
use crate::{Detail, ManifestProblem, Result};

/// What an assembly does where it could also fail.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AssembleFlags(u8);

impl AssembleFlags {
    /// Replace files that exist in the volume instead of failing.
    pub const REPLACE: AssembleFlags = AssembleFlags(1 << 0);
    /// Skip entries this crate cannot store (see [`Storable`]) instead of
    /// failing.
    pub const SKIP_UNSUPPORTED: AssembleFlags = AssembleFlags(1 << 1);
    /// No flag: an assembly fails in both cases.
    pub const NONE: AssembleFlags = AssembleFlags(0);

    /// Every single flag with its name.
    const NAMES: [(AssembleFlags, &'static str); 2] = [
        (AssembleFlags::REPLACE, "REPLACE"),
        (AssembleFlags::SKIP_UNSUPPORTED, "SKIP_UNSUPPORTED"),
    ];

    /// Whether every flag of `flags` is among these.
    pub const fn contains(self, flags: AssembleFlags) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// These flags with `flags` among them if `on` says so, and without
    /// them if not.
    #[must_use]
    pub const fn with(self, flags: AssembleFlags, on: bool) -> AssembleFlags {
        if on {
            AssembleFlags(self.0 | flags.0)
        } else {
            AssembleFlags(self.0 & !flags.0)
        }
    }
}

impl Default for AssembleFlags {
    /// [`AssembleFlags::REPLACE`].
    fn default() -> AssembleFlags {
        AssembleFlags::REPLACE
    }
}

impl BitOr for AssembleFlags {
    type Output = AssembleFlags;

    fn bitor(self, other: AssembleFlags) -> AssembleFlags {
        AssembleFlags(self.0 | other.0)
    }
}

impl BitOrAssign for AssembleFlags {
    fn bitor_assign(&mut self, other: AssembleFlags) {
        self.0 |= other.0;
    }
}

impl fmt::Debug for AssembleFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = AssembleFlags::NAMES.iter().filter(|(flag, _)| self.contains(*flag));
        f.write_str("AssembleFlags(")?;
        for (i, (_, name)) in names.enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

/// Options for [`Volume::assemble`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembleOptions {
    /// Time stamped on entries without `mTimeNSec` and on directories
    /// created implicitly.
    pub default_time: SystemTime,
    /// What to do where an assembly could also fail.
    pub flags: AssembleFlags,
    /// The current time for validity checks, or None to skip them.
    pub now_usec: Option<u64>,
}

impl Default for AssembleOptions {
    fn default() -> Self {
        AssembleOptions {
            default_time: UNIX_EPOCH,
            flags: AssembleFlags::default(),
            now_usec: None,
        }
    }
}

/// What an assembly did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssembleReport {
    /// Files written.
    pub files: u64,
    /// Directory objects applied: directories created, or existing ones
    /// that got the manifest's timestamp.
    pub directories: u64,
    /// File bytes written.
    pub bytes: u64,
    /// Entries skipped because they cannot be stored.
    pub skipped: Vec<String>,
}

/// Tells `progress` after every write how many bytes went through, on top
/// of what `done` counts.
struct Reporting<'a> {
    inner: &'a mut dyn Write,
    written: u64,
    done: Progress,
    progress: &'a mut dyn FnMut(&Progress),
}

impl Write for Reporting<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write_all(buf)?;
        self.written += buf.len() as u64;
        (self.progress)(&Progress {
            bytes: self.done.bytes + self.written,
            ..self.done
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl AssembleReport {
    /// What the assembly has done so far, as a progress callback hears it.
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}

impl Volume {
    /// Creates the directories and files a manifest describes, each at its
    /// name below the root directory. Data comes from `source` for regular
    /// files without literal contents. Sizes and SHA-256 hashes in the
    /// manifest are verified; a mismatch removes the file again and fails
    /// with EBADMSG. So does data the source has after the last file it
    /// supplies. A directory object listed after its children, or for a
    /// directory that already exists, sets the directory's timestamp.
    pub fn assemble(
        &mut self,
        manifest: &Manifest,
        source: &mut dyn ContentSource,
        options: &AssembleOptions,
    ) -> Result<AssembleReport> {
        self.assemble_with_progress(manifest, source, options, &mut |_| {})
    }

    /// [`Volume::assemble`], telling `progress` what it wrote so far after
    /// every directory, every file and every chunk of a file.
    pub fn assemble_with_progress(
        &mut self,
        manifest: &Manifest,
        source: &mut dyn ContentSource,
        options: &AssembleOptions,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<AssembleReport> {
        let mut report = AssembleReport::default();
        if let Some(now) = options.now_usec {
            manifest.root.check_validity(now)?;
        }
        // The source has to end with the last file it supplies.
        let last = manifest.entries.iter().rposition(FileObject::is_streamed);
        for (index, entry) in manifest.entries.iter().enumerate() {
            let name = entry.name.as_str();
            let path = volume_path(name);
            // An invalid directory takes its children with it: the directory
            // object comes first and fails the whole assembly here.
            if let Some(now) = options.now_usec {
                entry.check_validity(now)?;
            }
            let storable = match Storable::try_from(entry) {
                Ok(storable) => storable,
                Err(e) if e.errno() == EOPNOTSUPP && options.flags.contains(AssembleFlags::SKIP_UNSUPPORTED) => {
                    report.skipped.push(name.to_string());
                    continue;
                }
                Err(e) => return Err(e),
            };
            let time = entry.mtime().unwrap_or(options.default_time);
            if let Some((parent, _)) = name.rsplit_once('/') {
                self.create_dir_all(&volume_path(parent), options.default_time)?;
            }
            match storable {
                Storable::Directory => {
                    match self.metadata(&path) {
                        Ok(m) if m.is_dir => self.set_times(&path, time)?,
                        Ok(_) => bail!(
                            ENOTDIR,
                            Detail::Path(path.clone()),
                            "'{}' exists in the volume and is not a directory",
                            path
                        ),
                        Err(e) if e.errno() == ENOENT => self.create_dir(&path, time)?,
                        Err(e) => return Err(e),
                    }
                    report.directories += 1;
                    progress(&report.progress());
                }
                Storable::File => {
                    // The writer aborts the file when it is dropped on an
                    // error.
                    let replace = options.flags.contains(AssembleFlags::REPLACE);
                    let mut writer = self.create_file(&path, time, replace)?;
                    writer.set_read_only(entry.is_read_only());
                    let mut reporting = Reporting {
                        inner: &mut writer,
                        written: 0,
                        done: report.progress(),
                        progress: &mut *progress,
                    };
                    let written = entry.copy_contents(source, &mut reporting)?;
                    if last == Some(index) {
                        source.end(entry)?;
                    }
                    writer.finish()?;
                    report.files += 1;
                    report.bytes += written;
                    progress(&report.progress());
                }
            }
        }
        Ok(report)
    }
}

impl crate::plan::Plan {
    /// Adds the files and directories of a manifest. Returns the entries
    /// that cannot be stored (see [`Storable`]), which the assembler skips
    /// or refuses, so a plan and an assembly that skips them cover the same
    /// entries.
    pub fn add_manifest(&mut self, manifest: &Manifest) -> Result<Vec<String>> {
        let mut skipped = Vec::new();
        for entry in &manifest.entries {
            let name = entry.name.as_str();
            let path = volume_path(name);
            let storable = match Storable::try_from(entry) {
                Ok(storable) => storable,
                Err(e) if e.errno() == EOPNOTSUPP => {
                    skipped.push(name.to_string());
                    continue;
                }
                Err(e) => return Err(e),
            };
            match storable {
                Storable::Directory => self.add_dir(&path)?,
                Storable::File => {
                    let Some(size) = entry.size else {
                        bail!(
                            EINVAL,
                            Detail::Manifest {
                                problem: ManifestProblem::NoSize,
                                record: None,
                                name: Some(path),
                                field: Some("size".into()),
                            },
                            "'{}' has no size in the manifest",
                            name
                        );
                    };
                    self.add_file(&path, size)?;
                }
            }
        }
        Ok(skipped)
    }
}
