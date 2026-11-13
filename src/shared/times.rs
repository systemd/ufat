// SPDX-License-Identifier: LGPL-2.1-or-later
//! What time a copy of a file gets, and what the tools share to handle
//! times.

use std::time::SystemTime;

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

/// The current time.
pub fn now() -> SystemTime {
    SystemTime::now()
}
