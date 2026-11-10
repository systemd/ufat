// SPDX-License-Identifier: LGPL-2.1-or-later
//! How far a long operation has got, for a caller that reports it while
//! the operation runs.

/// What a long operation has done so far. An operation counts what it
/// does and leaves the rest at 0, and every count only grows. The
/// operations that take a progress callback call it after every entry and
/// every chunk of file contents, so the callback decides how often it acts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// Regular files done.
    pub files: u64,
    /// Directories done.
    pub directories: u64,
    /// Bytes of file contents done.
    pub bytes: u64,
}
