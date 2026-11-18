// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: reading, checking and writing them.
//!
//! A [UAPI.16 file manifest] describes a tree of files. It is an RFC 7464
//! JSON text sequence: one JSON object per record, each record after an
//! ASCII record separator. The first object describes the root of the
//! tree. One object for every file follows, with its name, its type and
//! what else is known of it: size, hash, owner, mode, time. Signature
//! objects can come after the file objects, and a trailer object ends the
//! manifest.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod name;

pub use name::{InvalidName, Name};

/// The name of a manifest that is stored in the tree it describes.
pub const FILENAME: &str = "Uapi16Manifest";
/// What the name of a manifest ends in that is stored next to what it
/// describes.
pub const SUFFIX: &str = ".Uapi16Manifest";

/// What the strings of a manifest may not hold beyond what JSON forbids:
/// noncharacters and the NUL character, escaped or not.
pub(crate) const STRING_RULES: json::StringRules = json::StringRules::NO_NONCHARACTERS.union(json::StringRules::NO_NUL);

/// What the tests of this crate build manifests from.
#[cfg(test)]
pub(crate) mod testing {
    use super::Name;

    /// The names of the full tree in which every directory has an entry
    /// for each of `pieces`, down to `depth` components: every name of at
    /// most `depth` components made of `pieces`, the root among them.
    pub(crate) fn full_tree_names(pieces: &[&str], depth: usize) -> Vec<Name> {
        let mut names = vec![Name::ROOT];
        let mut level = vec![Name::ROOT];
        for _ in 0..depth {
            level = level
                .iter()
                .flat_map(|parent| pieces.iter().map(move |piece| parent.join(piece).unwrap()))
                .collect();
            names.extend(level.iter().cloned());
        }
        names
    }
}
