// SPDX-License-Identifier: LGPL-2.1-or-later
//! Removing a directory with everything below it, one entry at a time.

use super::Volume;
use crate::errno::*;
use crate::path::{components, join};
use crate::progress::Progress;
use crate::Detail;
use crate::Result;

/// What a recursive removal took out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RemoveReport {
    /// Files removed.
    pub files: u64,
    /// Directories removed, the one named included.
    pub directories: u64,
}

impl RemoveReport {
    /// What the removal has done so far, as a progress callback hears it.
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: 0,
        }
    }
}

/// A directory on the walk: entered, with its contents still to be listed,
/// or left, with everything below it gone.
enum Step {
    Enter(String),
    Leave(String),
}

impl Volume {
    /// Removes `path` with everything below it: a file like
    /// [`Volume::remove_file`], a directory with its contents, children
    /// first and depth first, each step one [`Volume::remove_file`] or
    /// [`Volume::remove_dir`]. So a crash in the middle leaves a consistent
    /// volume with part of the tree gone, never an entry without its
    /// clusters. The root directory is refused with EINVAL; a path that
    /// does not exist fails the way [`Volume::metadata`] fails for it.
    pub fn remove_tree(&mut self, path: &str) -> Result<RemoveReport> {
        self.remove_tree_with_progress(path, &mut |_| {})
    }

    /// [`Volume::remove_tree`], telling `progress` what it removed so far
    /// after every file and directory.
    pub fn remove_tree_with_progress(
        &mut self,
        path: &str,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<RemoveReport> {
        if components(path)?.is_empty() {
            bail!(
                EINVAL,
                Detail::InvalidOption("path"),
                "the root directory cannot be removed"
            );
        }
        let mut report = RemoveReport::default();
        if !self.metadata(path)?.is_dir {
            self.remove_file(path)?;
            report.files = 1;
            return Ok(report);
        }
        // Depth first with a stack of our own: a path may be PATH_MAX bytes
        // long, which is more directories deep than recursion should go.
        let mut stack = vec![Step::Enter(path.to_string())];
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(dir) => {
                    // The directory itself goes once its subdirectories,
                    // pushed after it, have come off the stack.
                    stack.push(Step::Leave(dir.clone()));
                    for child in self.read_dir(&dir)? {
                        let p = join(&dir, &child.name);
                        if child.is_dir {
                            stack.push(Step::Enter(p));
                        } else {
                            self.remove_file(&p)?;
                            report.files += 1;
                            progress(&report.progress());
                        }
                    }
                }
                Step::Leave(dir) => {
                    self.remove_dir(&dir)?;
                    report.directories += 1;
                    progress(&report.progress());
                }
            }
        }
        Ok(report)
    }
}
