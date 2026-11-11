// SPDX-License-Identifier: LGPL-2.1-or-later
//! ufat creates and populates FAT32 file systems without mounting them.
//!
//! Its purpose is the EFI System Partition: format a partition or image,
//! copy files and directory trees into it in a reproducible way, check the
//! result, and work out beforehand how large the partition has to be. It
//! implements only FAT32 with long file names, writes files sequentially
//! only, and runs on Linux only. It uses the standard library and the
//! libc and sha2 crates.
//!
//! The crate is built with cargo; see HACKING.md.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// The error type, images, access to the host and the hashes live in the
// shared crate. They are part of this crate's interface under the names
// they always had.
#[macro_use]
extern crate shared;
pub use shared::{bail, err};
pub use shared::{device, errno, host, progress, sha256, sha512};
pub(crate) use shared::{path, sys};
pub use shared::{
    ContentProblem, Context, CorruptPlace, DescriptorProblem, Detail, Error, IdentifierProblem, LabelProblem,
    ManifestProblem, NameProblem, NoSpaceReason, NotFat32Reason, Result, SourceProblem, UnsupportedKind,
    ValidityProblem,
};

pub mod boot;
mod bytes;
pub(crate) mod dir;
pub mod dirent;
pub mod fat;
pub mod format;
pub mod fsck;
pub mod layout;
pub mod manifest;
pub mod name;
pub mod plan;
pub mod populate;
pub mod probe;
#[cfg(test)]
mod test_util;
pub mod time;
pub mod volume;
