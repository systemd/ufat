// SPDX-License-Identifier: LGPL-2.1-or-later
//! ucpio creates, fills and checks cpio archives without unpacking them.
//!
//! Its purpose is the initramfs: the archive the kernel unpacks into its
//! root file system at boot. It reads and writes the "new ASCII" format,
//! the one the kernel takes, as one archive that is not compressed, and it
//! runs on Linux only. It uses the standard library and the libc and sha2
//! crates.
//!
//! The crate is built with cargo; see HACKING.md.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// The error type, images, access to the host and the hashes are the
// shared crate's. They are part of this crate's interface too.
#[macro_use]
extern crate shared;
pub(crate) use shared::sys;
pub use shared::{bail, err};
pub use shared::{device, errno, host, progress, sha256, sha512};
pub use shared::{Context, Detail, Error, NameProblem, Result};

pub mod header;
pub mod name;
#[cfg(test)]
mod test_util;
pub mod write;
