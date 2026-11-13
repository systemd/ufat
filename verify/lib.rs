// SPDX-License-Identifier: LGPL-2.1-or-later
//! The crate root for verify/run.sh: the pure modules of the library, so
//! that Kani needs neither the json crate nor any I/O. The Kani harnesses
//! live in `#[cfg(kani)] mod proofs` blocks inside the modules themselves.
#![allow(dead_code, unused_imports, unreachable_pub)]
#![cfg_attr(kani, feature(rustc_private))]

// errno.rs takes its values from libc; Kani's sysroot ships std's libc.
#[cfg(kani)]
extern crate libc;

#[macro_use]
#[path = "../src/fat/error.rs"]
mod error;
pub use error::{CorruptPlace, Detail, Error, NameProblem, NoSpaceReason, NotFat32Reason, Result};

#[path = "../src/fat/boot.rs"]
pub mod boot;
#[path = "../src/fat/bytes.rs"]
mod bytes;
#[path = "../src/fat/dir.rs"]
pub mod dir;
#[path = "../src/fat/dirent.rs"]
pub mod dirent;
#[path = "../src/fat/errno.rs"]
pub mod errno;
#[path = "../src/fat/fat.rs"]
pub mod fat;
#[path = "../src/fat/layout.rs"]
pub mod layout;
#[path = "../src/fat/name.rs"]
pub mod name;
#[path = "../src/fat/time.rs"]
pub mod time;
