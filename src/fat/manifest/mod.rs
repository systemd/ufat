// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: reading them, assembling a volume from one and
//! writing the manifest of a volume or of a tree on the host.
//!
//! The manifests themselves are the business of the `uapi16` crate: the
//! objects, the reader that checks them against the specification the way
//! systemd's reader does, the writer and the sources of file contents.
//! This module adds what FAT has to say. A FAT volume holds regular files
//! and directories, no file of 4 GiB or more, and no two names that
//! differ in case only.
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

use std::collections::hash_map::{Entry, HashMap};
use std::io::Read;

use uapi16::{Reader, Record};

use crate::errno::*;
use crate::volume::MAX_FILE_SIZE;
use crate::{Detail, Error, ManifestProblem, Result, UnsupportedKind};

mod assemble;
mod error;
mod generate;
#[cfg(test)]
mod tests;
mod volume;

pub use assemble::{AssembleOptions, AssembleReport, DirectorySource, SourceDirectory};
pub use generate::HostTree;
pub use uapi16::{ContentSource, Contents, Fields, FileObject, InodeType, Location, Name, Sha256, StreamSource};
pub use volume::WriteReport;

/// The path inside a volume of the file object with the name `name`: the
/// name below the root directory.
fn volume_path(name: &str) -> String {
    crate::path::join("/", name)
}

/// What a file object is to a FAT volume.
///
/// FAT stores regular files and directories. Symbolic links, device
/// nodes, FIFOs and sockets it cannot store. Neither can this crate store
/// a directory that refers to a manifest of its own, nor a file whose
/// contents would have to be decoded or fetched. Converting any of them
/// fails with EOPNOTSUPP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storable {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

impl TryFrom<&FileObject> for Storable {
    type Error = Error;

    fn try_from(object: &FileObject) -> Result<Storable> {
        let unsupported = |what, value: Option<&str>| Detail::Unsupported {
            name: Some(volume_path(&object.name)),
            what,
            value: value.map(str::to_string),
        };
        match object.inode_type {
            InodeType::Regular => {
                object.data()?;
                Ok(Storable::File)
            }
            InodeType::Directory => {
                if !object.contents.is_empty() || object.sha256.is_some() {
                    bail!(
                        EOPNOTSUPP,
                        unsupported(UnsupportedKind::SubManifest, None),
                        "'{}' refers to a sub-manifest, which is not supported",
                        volume_path(&object.name)
                    );
                }
                Ok(Storable::Directory)
            }
            other => bail!(
                EOPNOTSUPP,
                unsupported(UnsupportedKind::InodeType, Some(other.as_str())),
                "'{}' is a {}, which FAT cannot store",
                volume_path(&object.name),
                other
            ),
        }
    }
}

/// The key under which FAT, which folds case, files a name.
#[derive(Debug, PartialEq, Eq, Hash)]
struct FatKey(Vec<u16>);

impl From<&Name> for FatKey {
    fn from(name: &Name) -> FatKey {
        let mut key = Vec::new();
        for (i, component) in name.split('/').enumerate() {
            if i > 0 {
                key.push(u16::from(b'/'));
            }
            key.extend(crate::name::fold_str(component));
        }
        FatKey(key)
    }
}

/// A manifest as far as a FAT volume is concerned: its file objects, and
/// how many signature objects it has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// The root file object.
    pub root: FileObject,
    /// The file objects, in manifest order.
    pub entries: Vec<FileObject>,
    /// Number of signature objects seen. None of them was verified.
    pub signatures: usize,
}

impl Manifest {
    /// Reads a manifest to its end. Every object is checked against the
    /// specification. A regular file larger than FAT32 can store is
    /// refused with EFBIG, and so are two names FAT cannot tell apart,
    /// with EEXIST.
    pub fn read(input: impl Read) -> Result<Manifest> {
        let mut reader = Reader::open(input)?;
        let root = reader.root().clone();
        let mut entries: Vec<FileObject> = Vec::new();
        // FAT folds case, so names are keyed by their folded form.
        let mut names: HashMap<FatKey, usize> = HashMap::new();
        let mut signatures = 0;
        while let Some(record) = reader.next() {
            let object = match record? {
                Record::File(object) => *object,
                Record::Signature(_) => {
                    signatures += 1;
                    continue;
                }
                _ => continue,
            };
            let name = &object.name;
            if let Some(size) = object
                .size
                .filter(|&size| size > MAX_FILE_SIZE && object.inode_type == InodeType::Regular)
            {
                bail!(
                    EFBIG,
                    Detail::TooLarge {
                        path: Some(volume_path(name)),
                        size,
                        maximum: MAX_FILE_SIZE,
                    },
                    "manifest object {} ({}): {} bytes exceed what FAT32 can store",
                    reader.record(),
                    name,
                    size
                );
            }
            match names.entry(FatKey::from(name)) {
                Entry::Vacant(free) => {
                    free.insert(entries.len());
                }
                Entry::Occupied(taken) => {
                    let other = &entries[*taken.get()].name;
                    let twice = Detail::Manifest {
                        problem: ManifestProblem::DuplicateName,
                        record: None,
                        name: None,
                        field: None,
                    };
                    if other == name {
                        bail!(EBADMSG, twice, "manifest lists '{}' twice", name);
                    }
                    bail!(
                        EEXIST,
                        twice,
                        "manifest lists '{}' and '{}', which FAT cannot tell apart",
                        other,
                        name
                    );
                }
            }
            entries.push(object);
        }
        Ok(Manifest {
            root,
            entries,
            signatures,
        })
    }

    /// Reads a manifest that is held in memory, see [`Manifest::read`].
    pub fn parse(bytes: &[u8]) -> Result<Manifest> {
        Manifest::read(bytes)
    }

    /// Fails with EOPNOTSUPP for the first entry this crate cannot store,
    /// see [`Storable`]. Assembling without `skip_unsupported` would fail
    /// at that entry; checking first avoids formatting for nothing.
    pub fn check_supported(&self) -> Result<()> {
        self.entries
            .iter()
            .try_for_each(|object| Storable::try_from(object).map(drop))
    }

    /// Total size of the data a [`ContentSource`] has to deliver: the sizes
    /// of all regular files without literal contents, in manifest order.
    /// Every such file needs a known size. Entries that cannot be stored do
    /// not count, since they are skipped or stop the assembly.
    pub fn streamed_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        for object in self.entries.iter().filter(|object| object.is_streamed()) {
            let size = object.size.ok_or_else(|| {
                let path = volume_path(&object.name);
                err!(
                    EINVAL,
                    Detail::Manifest {
                        problem: ManifestProblem::NoSize,
                        record: None,
                        name: Some(path.clone()),
                        field: Some("size".into()),
                    },
                    "'{}' has no size, so its contents cannot be streamed",
                    path
                )
            })?;
            total = total
                .checked_add(size)
                .ok_or_else(|| err!(EOVERFLOW, "total manifest size overflows"))?;
        }
        Ok(total)
    }
}
