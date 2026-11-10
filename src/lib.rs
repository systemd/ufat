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

#[cfg(not(target_os = "linux"))]
compile_error!("ufat supports Linux only");

#[macro_use]
mod error;
pub use error::{Context, Detail, Error, NoSpaceReason, Result};

pub mod errno;
pub mod layout;
