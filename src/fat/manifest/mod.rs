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
//! Nothing here holds a whole manifest. An assembly reads one record at a
//! time and writes what it describes right away, so a manifest of any size
//! can come through a pipe. The planner in [`crate::plan`] counts what the
//! records take as they come. It keeps the path of the deepest open
//! directory, and a count for each directory on that path.
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
//! be skipped. `readOnly` and the flags of the hidden, system and archive
//! attributes set and clear those attributes of files and directories.
//!
//! The root file object can name the volume the manifest is for, see
//! [`VolumeIdentity`]: a volume made from the manifest takes the serial
//! number and the label, and a volume the content goes into has to have
//! them. A manifest that names no serial number gives a volume the one
//! derived from its bytes, see [`VolumeId::from_manifest_digest`].
//!
//! [`VolumeId::from_manifest_digest`]: crate::format::VolumeId::from_manifest_digest

use crate::dirent::{ATTR_ARCHIVE, ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
use crate::errno::*;
use crate::path::SEPARATOR;
use crate::volume::{MAX_FILE_SIZE, NO_ATTRIBUTES, SETTABLE_ATTRIBUTES};
use crate::{Detail, Result, UnsupportedKind};

mod assemble;
mod error;
mod generate;
mod identity;
#[cfg(test)]
mod tests;
mod volume;

pub use assemble::{AssembleFlags, AssembleObserver, AssembleOptions, AssembleReport, PinnedDirectory, SkipReason};
pub use generate::HostTree;
pub use identity::{ManifestLabel, SerialSource, VolumeIdentity};
pub use uapi16::{
    ContentSource, Contents, DirectorySource, DosFlags, Features, FileObject, Finalize, FlagStates, InodeFlags,
    InodeType, Location, Name, Object, Order, Problem, Reader, RootObject, Sha256, Sha256Context, StreamSource,
};
pub use volume::WriteReport;

pub(crate) use error::SizePurpose;

/// The path inside a volume of the file object with the name `name`: the
/// name below the root directory.
fn path_in_volume(name: &str) -> String {
    let mut path = String::with_capacity(SEPARATOR.len_utf8() + name.len());
    path_in_volume_into(name, &mut path);
    path
}

/// Puts [`path_in_volume`] of `name` into `path`, in place of what `path`
/// held, so that the paths of all objects can share one buffer.
pub(crate) fn path_in_volume_into(name: &str, path: &mut String) {
    path.clear();
    path.push(SEPARATOR);
    path.push_str(name);
}

/// The attribute byte of a FAT directory entry, as far as a manifest has
/// fields for it: `readOnly` is its read-only attribute, see
/// [`uapi16::InodeAttributes::is_read_only`], and `flagHidden`,
/// `flagSystem` and `flagArchive` are its hidden, system and archive
/// attributes. The root directory has no entry and so none of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DosAttributes(u8);

impl DosAttributes {
    /// The attributes a manifest has a flag for, each with its flag and
    /// the feature that records it.
    const FLAGS: [(u8, DosFlags, Features); 3] = [
        (ATTR_HIDDEN, DosFlags::HIDDEN, Features::FLAG_HIDDEN),
        (ATTR_SYSTEM, DosFlags::SYSTEM, Features::FLAG_SYSTEM),
        (ATTR_ARCHIVE, DosFlags::ARCHIVE, Features::FLAG_ARCHIVE),
    ];

    /// No attribute.
    pub(crate) const NONE: DosAttributes = DosAttributes(NO_ATTRIBUTES);

    /// The attributes of the attribute byte `attributes`.
    pub(crate) const fn new(attributes: u8) -> DosAttributes {
        DosAttributes(attributes)
    }

    /// The read-only, hidden, system and archive attributes, the ones a
    /// caller sets on an entry.
    pub(crate) const fn settable(self) -> u8 {
        self.0 & SETTABLE_ATTRIBUTES
    }

    /// These attributes as `object` gives them to the entry it describes,
    /// a file or a directory: the read-only one as
    /// [`uapi16::InodeAttributes::is_read_only`] says, and the hidden,
    /// system and archive ones set or cleared where the flags of the
    /// object say. Those the flags say nothing about stay as they are.
    #[must_use]
    pub(crate) fn with_object(self, object: &FileObject) -> DosAttributes {
        self.with_read_only(object.inode.is_read_only())
            .with_flags(object.dos_flags)
    }

    /// Records these attributes of an entry in `object`, the file object
    /// of the entry in a manifest that records `features`: `readOnly` and
    /// the flags, each where `features` records it.
    pub(crate) fn record_in(self, object: &mut FileObject, features: Features) {
        if features.contains(Features::READ_ONLY) {
            object.inode.read_only = Some(self.0 & ATTR_READ_ONLY != 0);
        }
        object.dos_flags = self.flag_states(features);
    }

    /// These attributes with the read-only one set or cleared as
    /// `read_only` says.
    #[must_use]
    fn with_read_only(self, read_only: bool) -> DosAttributes {
        if read_only {
            DosAttributes(self.0 | ATTR_READ_ONLY)
        } else {
            DosAttributes(self.0 & !ATTR_READ_ONLY)
        }
    }

    /// These attributes with those set or cleared that the flags `states`
    /// say are set or cleared. The others stay as they are.
    #[must_use]
    fn with_flags(self, states: FlagStates<DosFlags>) -> DosAttributes {
        let bits = DosAttributes::FLAGS
            .into_iter()
            .fold(self.0, |bits, (attribute, flag, _)| match states.get(flag) {
                Some(true) => bits | attribute,
                Some(false) => bits & !attribute,
                None => bits,
            });
        DosAttributes(bits)
    }

    /// The flags of an entry with these attributes, in a manifest that
    /// records `features`: set or cleared for every flag whose feature it
    /// records, not known for the others.
    fn flag_states(self, features: Features) -> FlagStates<DosFlags> {
        let mut states = FlagStates::default();
        for (attribute, flag, feature) in DosAttributes::FLAGS {
            if features.contains(feature) {
                states.put(flag, Some(self.0 & attribute != 0));
            }
        }
        states
    }
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
