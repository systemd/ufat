// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the libraries make of UAPI.16 file manifests is the same where it
//! is not about what they write. The manifests themselves are the business
//! of the `uapi16` crate.

mod error;
mod source;

pub use source::{DirectorySource, SourceDirectory};
