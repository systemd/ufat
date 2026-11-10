// SPDX-License-Identifier: LGPL-2.1-or-later
//! ufat creates and populates FAT32 file systems without mounting them.
//!
//! Its purpose is the EFI System Partition: format a partition or image,
//! copy files and directory trees into it in a reproducible way, check the
//! result, and work out beforehand how large the partition has to be. It
//! implements only FAT32 with long file names, writes files sequentially
//! only, and runs on Linux only. It uses nothing but the standard library
//! and the libc crate.
//!
//! The crate is built with cargo; see HACKING.md.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

// sys.rs calls the LFS64 functions of glibc, such as openat64(), which
// musl does not have.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("ufat supports Linux with glibc only");

#[macro_use]
mod error;
pub use error::{
    Context, CorruptPlace, Detail, Error, IdentifierProblem, LabelProblem, NameProblem, NoSpaceReason, NotFat32Reason,
    Result,
};

pub mod boot;
mod bytes;
pub mod device;
pub(crate) mod dir;
pub mod dirent;
pub mod errno;
pub mod fat;
pub mod format;
pub mod fsck;
pub mod host;
pub mod layout;
pub mod name;
mod path;
pub mod plan;
pub mod populate;
mod sys;
#[cfg(test)]
mod test_util;
pub mod time;
pub mod volume;
