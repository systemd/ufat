// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the libraries of this repository have in common: the error type,
//! images and block devices, access to the host by descriptor, and the
//! hashes.
//!
//! This crate is the ground the tools stand on. It is not an interface of
//! its own and changes with them. It uses the standard library and the
//! libc and sha2 crates.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!("only Linux is supported");

#[macro_use]
mod error;
pub use error::{
    ContentProblem, Context, CorruptPlace, DescriptorProblem, Detail, Error, IdentifierProblem, LabelProblem,
    ManifestProblem, NameProblem, NoSpaceReason, NotCpioReason, NotFat32Reason, Result, SourceProblem, UnsupportedKind,
    ValidityProblem,
};

pub mod device;
pub mod errno;
mod flags;
pub mod host;
pub mod manifest;
pub mod path;
pub mod progress;
pub mod sha256;
pub mod sha512;
pub mod sys;
#[cfg(test)]
mod test_util;
pub mod times;
