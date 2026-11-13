// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing a manifest for a host tree, the way `systemd-manifest make`
//! writes it.

use std::io::Write;
use std::os::fd::BorrowedFd;
use std::time::UNIX_EPOCH;

use json::ObjectWriter;
use uapi16::{Field, FileObject, InodeType, Name, Sha256, Writer, RECORD_SEPARATOR};

use crate::host::HostEntry;
use crate::sha256;
use crate::sys;
use crate::Result;

/// How much of a file is read at a time for its hash.
const READ_SIZE: usize = 1024 * 1024;

/// A directory tree on the host, by the open directory at its top.
///
/// The descriptor is what the caller resolved its path to, with
/// [`crate::host::open_dir`] when it has a path, and may be O_PATH.
/// Everything below it is reached by descriptor.
#[derive(Clone, Copy, Debug)]
pub struct HostTree<'a> {
    root: BorrowedFd<'a>,
}

impl<'a> HostTree<'a> {
    /// The tree below the open directory `root`.
    pub fn new(root: BorrowedFd<'a>) -> HostTree<'a> {
        HostTree { root }
    }

    /// Writes the manifest of the tree to `out` the way `systemd-manifest
    /// make --field=size,hash,mtime` would, for tests and for the command
    /// line tool. Only regular files and directories are listed, and a
    /// manifest stored in the tree's top level is left out since its name
    /// is reserved.
    pub fn write_manifest(&self, out: impl Write) -> Result<()> {
        // The leading object carries the tree's own time, as systemd's does.
        let mut top = FileObject::root();
        if let Ok(time) = sys::fstat(self.root)?.modified() {
            top.set_mtime(time);
        }
        let mut listing = Listing {
            writer: Writer::begin(out, &top)?,
            buffer: vec![0u8; READ_SIZE],
        };
        crate::host::walk_tree(self.root, "", false, &mut |target, entry| listing.entry(target, entry))?;
        listing.writer.finish()?;
        Ok(())
    }
}

/// The manifest of a host tree while it is written.
struct Listing<W: Write> {
    writer: Writer<W>,
    /// What a file is read through for its hash.
    buffer: Vec<u8>,
}

impl<W: Write> Listing<W> {
    /// Writes the object of the entry that gets the path `target` inside
    /// a volume, and says whether the walk is to go into it.
    fn entry(&mut self, target: &str, entry: &HostEntry) -> Result<bool> {
        let md = &entry.metadata;
        // walk_tree joins with a leading slash; manifests want none.
        let path = &target[1..];
        let mut object = match Name::new(path) {
            Ok(name) => FileObject::new(name),
            Err(_) if md.is_dir() => {
                self.unnameable_directory(path, md)?;
                return Ok(true);
            }
            Err(_) => return Ok(false),
        };
        if let Ok(time) = md.modified() {
            object.set_mtime(time);
        }
        if md.is_dir() {
            object.inode_type = InodeType::Directory;
        } else if md.is_file() {
            let mut file = entry.open_file()?;
            let mut hasher = sha256::Sha256::new();
            loop {
                let n = crate::host::read_some(&mut file, &mut self.buffer)?;
                if n == 0 {
                    break;
                }
                hasher.update(&self.buffer[..n]);
            }
            object.sha256 = Some(Sha256::from(hasher.finalize()));
            object.size = Some(md.len());
        } else {
            return Ok(false);
        }
        self.writer.file(&object)?;
        Ok(md.is_dir())
    }

    /// Writes the object of a directory whose name no manifest can carry:
    /// one with a control character in it, or one that is reserved for
    /// the manifest itself. No reader takes such an object. It is written
    /// all the same, as it was before file objects had checked names, and
    /// the walk goes on below it. `systemd-manifest` leaves such a
    /// directory out with everything in it.
    fn unnameable_directory(&mut self, path: &str, md: &std::fs::Metadata) -> Result<()> {
        let since_epoch = md.modified().ok().and_then(|time| time.duration_since(UNIX_EPOCH).ok());
        let mut record = String::from(char::from(RECORD_SEPARATOR));
        let mut object = ObjectWriter::new(&mut record);
        if let Some(nsec) = since_epoch.and_then(|since| u64::try_from(since.as_nanos()).ok()) {
            object.key(Field::MTimeNSec.as_str()).unsigned(nsec);
        }
        object.key(Field::Name.as_str()).string(path);
        object.key(Field::Type.as_str()).string(InodeType::Directory.as_str());
        drop(object);
        record.push('\n');
        self.writer.get_mut().write_all(record.as_bytes())?;
        Ok(())
    }
}
