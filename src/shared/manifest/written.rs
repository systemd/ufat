// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a written manifest covers.

use crate::progress::Progress;

/// What a written manifest covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Regular files listed.
    pub files: u64,
    /// Directories listed, the root not counted.
    pub directories: u64,
    /// Bytes of the regular files listed.
    pub bytes: u64,
    /// What is there that the manifest could not record: entries whose
    /// names a manifest cannot carry, a directory with everything below it
    /// counting once. A field that what the manifest is written of has no
    /// notion of is not an omission. A manifest with omissions does not
    /// describe all of it, which is what repart refuses.
    pub omitted: u64,
}

impl WriteReport {
    /// What the manifest covers so far, as a progress callback hears it.
    pub fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}
