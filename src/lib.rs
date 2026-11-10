// SPDX-License-Identifier: LGPL-2.1-or-later
//! ufat creates and populates FAT32 file systems without mounting them.
//!
//! Its purpose is the EFI System Partition: format a partition or image,
//! copy files and directory trees into it in a reproducible way, check the
//! result, and work out beforehand how large the partition has to be. It
//! implements only FAT32 with long file names, writes files sequentially
//! only, and runs on Linux only. It uses nothing but the standard library.
//!
//! The crate is built with meson and plain rustc; see HACKING.md.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!("ufat supports Linux only");

#[macro_use]
mod error;
pub use error::{
    ContentProblem, Context, CorruptPlace, DescriptorProblem, Detail, Error, IdentifierProblem, LabelProblem,
    ManifestProblem, NameProblem, NoSpaceReason, NotFat32Reason, Result, SourceProblem, UnsupportedKind,
    ValidityProblem,
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
pub mod manifest;
pub mod name;
mod path;
pub mod plan;
pub mod populate;
pub mod progress;
pub mod sha256;
pub mod sha512;
mod sys;
#[cfg(test)]
mod test_util;
pub mod time;
pub mod volume;
