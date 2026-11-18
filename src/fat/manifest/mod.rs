// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: assembling a volume from one while it is read,
//! and writing the manifest of a volume or of a tree on the host.
//!
//! The manifests themselves are the business of the `uapi16` crate: the
//! objects, the [`Reader`] that checks them against the specification
//! record by record, the writer and the sources of file contents. This
//! module adds what FAT has to say. A FAT volume holds regular files and
//! directories, no file of 4 GiB or more, and no two names that differ in
//! case only.
//!
//! An assembly reads one record at a time and writes what it describes
//! right away. It never holds a whole manifest, so a manifest of any size
//! can come through a pipe. The planner in [`crate::plan`] takes the
//! records as they come too, but it keeps the name of every file and
//! directory it is given.
//!
//! Signatures are recognised but not verified: that needs an X.509 stack.
//! Callers who need authenticated manifests must verify them before handing
//! them over.
//!
//! Assembling a volume turns `dir` objects into directories and `reg`
//! objects into files whose contents come from a [`ContentSource`]: either
//! the files next to the manifest, or one stream carrying the contents of
//! every file in manifest order. Everything FAT cannot store (symlinks,
//! device nodes, FIFOs, sockets) is refused unless the caller asks for it to
//! be skipped.

use crate::errno::*;
use crate::path::SEPARATOR;
use crate::volume::MAX_FILE_SIZE;
use crate::{Detail, Result, UnsupportedKind};

mod assemble;
mod error;
mod generate;
#[cfg(test)]
mod tests;
mod volume;

pub use assemble::{AssembleFlags, AssembleObserver, AssembleOptions, AssembleReport, PinnedDirectory, SkipReason};
pub use generate::HostTree;
pub use uapi16::{
    ContentSource, Contents, DirectorySource, Features, FileObject, Finalize, InodeType, Location, Name, Object, Order,
    Problem, Reader, RootObject, Sha256, Sha256Context, StreamSource,
};
pub use volume::WriteReport;

pub(crate) use error::SizePurpose;

/// The path inside a volume of the file object with the name `name`: the
/// name below the root directory.
pub(crate) fn path_in_volume(name: &str) -> String {
    crate::path::join("/", name)
}

/// What a file object becomes in a FAT volume.
///
/// FAT stores regular files and directories. Symbolic links, device
/// nodes, FIFOs and sockets it cannot store. Neither can this crate store
/// a directory that refers to a manifest of its own, nor a file whose
/// contents would have to be decoded or fetched. Converting any of them
/// fails with EOPNOTSUPP. A regular file larger than a FAT32 file can be
/// fails with EFBIG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

impl TryFrom<&FileObject> for EntryKind {
    type Error = crate::Error;

    fn try_from(object: &FileObject) -> Result<EntryKind> {
        let unsupported = |what, value: Option<&str>| Detail::Unsupported {
            name: Some(path_in_volume(&object.name)),
            what,
            value: value.map(str::to_string),
        };
        match object.inode_type {
            InodeType::Regular => {
                object.data()?;
                if let Some(size) = object.size.filter(|&size| size > MAX_FILE_SIZE) {
                    let path = path_in_volume(&object.name);
                    bail!(
                        EFBIG,
                        Detail::TooLarge {
                            path: Some(path.clone()),
                            size,
                            maximum: MAX_FILE_SIZE,
                        },
                        "'{}' is {} bytes, a FAT32 file holds at most {}",
                        path,
                        size,
                        MAX_FILE_SIZE
                    );
                }
                Ok(EntryKind::File)
            }
            InodeType::Directory => {
                if !object.contents.is_empty() || object.sha256.is_some() {
                    bail!(
                        EOPNOTSUPP,
                        unsupported(UnsupportedKind::SubManifest, None),
                        "'{}' refers to a sub-manifest, which is not supported",
                        path_in_volume(&object.name)
                    );
                }
                Ok(EntryKind::Directory)
            }
            other => bail!(
                EOPNOTSUPP,
                unsupported(UnsupportedKind::InodeType, Some(other.as_str())),
                "'{}' is a {}, which FAT cannot store",
                path_in_volume(&object.name),
                other
            ),
        }
    }
}

/// What an assembly, and the plan of one, do with a file object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectAction {
    /// Store it as a file or as a directory.
    Store(EntryKind),
    /// Leave it out.
    Skip(SkipReason),
}

/// Decides what an assembly, and the plan of one, do with the file objects
/// of a manifest, one after the other in manifest order: store each as a
/// file or as a directory, or leave it out.
///
/// The objects below a directory come right after it in a manifest, so the
/// name of the last directory left out is all that has to be kept.
#[derive(Debug, Default)]
pub(crate) struct ObjectTriage {
    /// The name of the last directory left out, as long as the objects
    /// after it are below it, and empty otherwise: no file object has an
    /// empty name. The string is kept and filled again, so leaving out a
    /// directory allocates only for a name longer than any before.
    skipped_directory: String,
}

impl ObjectTriage {
    /// What to do with `object`, the file object that comes after the ones
    /// decided on before. An object below a directory that is left out is
    /// left out as well. One that this crate cannot store, see
    /// [`EntryKind`], is left out where [`AssembleFlags::SKIP_UNSUPPORTED`]
    /// among `flags` allows it, and fails otherwise.
    pub(crate) fn decide(&mut self, object: &FileObject, flags: AssembleFlags) -> Result<ObjectAction> {
        if !self.skipped_directory.is_empty() {
            let below = object
                .name
                .strip_prefix(self.skipped_directory.as_str())
                .is_some_and(|rest| rest.starts_with(SEPARATOR));
            if below {
                return Ok(ObjectAction::Skip(SkipReason::BelowSkipped));
            }
            self.skipped_directory.clear();
        }
        match EntryKind::try_from(object) {
            Ok(kind) => Ok(ObjectAction::Store(kind)),
            Err(e) if e.errno() == EOPNOTSUPP && flags.contains(AssembleFlags::SKIP_UNSUPPORTED) => {
                if object.inode_type == InodeType::Directory {
                    self.skipped_directory.push_str(&object.name);
                }
                Ok(ObjectAction::Skip(SkipReason::Unsupported))
            }
            Err(e) => Err(e),
        }
    }
}
