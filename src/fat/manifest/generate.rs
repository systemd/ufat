// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing a manifest for a host tree, the way `systemd-manifest make`
//! writes it.

use std::io::{Read, Write};
use std::os::fd::BorrowedFd;

use uapi16::{Features, FileObject, Finalize, InodeType, Name, Order, RootObject, Sha256Context, Writer};

use super::WriteReport;
use crate::host::{read_some, HostEntry, UnnamableEntry};
use crate::path::SEPARATOR;
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
    /// What the manifest of a host tree records: sizes, hashes and times,
    /// what `systemd-manifest make --field=size,hash,mtime` records.
    const MANIFEST_FEATURES: Features = Features::SIZE.union(Features::SHA256).union(Features::MTIME);

    /// The tree below the open directory `root`.
    pub fn new(root: BorrowedFd<'a>) -> HostTree<'a> {
        HostTree { root }
    }

    /// Writes the manifest of the tree to `out`, for tests and for the
    /// command line tool, and returns what it covers. It records sizes,
    /// hashes and times, as `systemd-manifest make --field=size,hash,mtime`
    /// does, lists these features and declares the code point ordering it
    /// is in. Each record goes out in one write, so a descriptor wants a
    /// `BufWriter` around it. When writing fails, what `out` got is a
    /// manifest without its trailer, which a reader refuses as incomplete.
    ///
    /// Only regular files and directories are listed. The names the
    /// specification reserves in the top level for the manifest itself and
    /// its signatures are left out silently, as `systemd-manifest` leaves
    /// them out. Any other name no manifest can carry, one that is not
    /// UTF-8 or that has a control character for instance, and a path
    /// longer than a volume takes, is left out and counted in the report's
    /// `omitted`, a directory with everything below it as one.
    ///
    /// A file is read up to the size the walk found it with, so one that
    /// keeps growing ends, and the manifest has the size and the hash of
    /// what was read. Then its size, modification time and change time are
    /// compared with those the walk found. A file where one of them differs
    /// changed while it was read and is counted in the report's `changed`.
    pub fn write_manifest(&self, out: impl Write) -> Result<WriteReport> {
        // The root file object carries the tree's own time, as systemd's
        // does.
        let mut root = RootObject::default();
        root.features = Some(HostTree::MANIFEST_FEATURES);
        root.order = Some(Order::CodePoint);
        if let Ok(time) = sys::fstat(self.root)?.modified() {
            root.inode.set_mtime(time);
        }
        let mut listing = Listing {
            writer: Writer::begin(out, &root)?,
            report: WriteReport::default(),
            buf: vec![0; READ_SIZE],
        };
        let omitted = crate::host::walk_tree(self.root, "", false, UnnamableEntry::Omit, &mut |target, entry| {
            listing.entry(target, entry)
        })?;
        listing.report.omitted += omitted;
        listing.writer.finish()?;
        Ok(listing.report)
    }
}

/// The manifest of a host tree while it is written.
struct Listing<W: Write> {
    writer: Writer<W>,
    report: WriteReport,
    /// What a file is read into for its hash, one for all of them.
    buf: Vec<u8>,
}

impl<W: Write> Listing<W> {
    /// Writes the object of the entry that gets the path `target` inside
    /// a volume, and says whether the walk is to go into it.
    fn entry(&mut self, target: &str, entry: &HostEntry) -> Result<bool> {
        let md = &entry.metadata;
        if !md.is_dir() && !md.is_file() {
            return Ok(false);
        }
        // walk_tree joins with a leading slash; manifests want none.
        let path = target.strip_prefix(SEPARATOR).unwrap_or(target);
        let mut object = match Name::new(path) {
            Ok(name) => FileObject::new(name),
            // Only a name at the top can be one of the names reserved for
            // the manifest. It is no omission.
            Err(uapi16::NameProblem::Reserved) => return Ok(false),
            Err(_) => {
                self.report.omitted += 1;
                return Ok(false);
            }
        };
        if let Ok(time) = md.modified() {
            object.inode.set_mtime(time);
        }
        if md.is_dir() {
            object.inode_type = InodeType::Directory;
            self.writer.file(&object)?;
            self.report.directories += 1;
            return Ok(true);
        }
        // Read no more than the walk found, so that a file that keeps
        // growing ends. The size is that of what was hashed, so the two
        // agree for a file that changes while it is read.
        let found = md.len();
        let mut context = Sha256Context::default();
        let mut size = 0;
        let file = entry.open_file()?;
        let mut data = (&file).take(found);
        loop {
            let n = read_some(&mut data, &mut self.buf)?;
            if n == 0 {
                break;
            }
            context.update(&self.buf[..n]);
            size += n as u64;
        }
        if size != found || entry.has_changed(&file)? {
            self.report.changed += 1;
        }
        object.sha256 = Some(context.finalize());
        object.size = Some(size);
        self.writer.file(&object)?;
        self.report.files += 1;
        self.report.bytes += size;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::{open_dir, walk_tree};
    use crate::test_util::TempDir;
    use std::fs;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    use std::time::UNIX_EPOCH;
    use uapi16::{Object, Reader, Sha256};

    /// Files that change after the walk found them and before they are
    /// read: one grows, one shrinks, one gets another time and one stays.
    /// The manifest has what was read, no more than the walk found, and the
    /// report counts the three that changed.
    #[test]
    fn files_that_change_while_they_are_read() {
        let tmp = TempDir::new("generate-changed");
        let top = tmp.path();
        for name in ["grows", "shrinks", "stays", "touched"] {
            fs::write(top.join(name), b"hello world").unwrap();
        }
        let dir = open_dir(top).unwrap();
        let mut root = RootObject::default();
        root.features = Some(HostTree::MANIFEST_FEATURES);
        root.order = Some(Order::CodePoint);
        let mut listing = Listing {
            writer: Writer::begin(Vec::new(), &root).unwrap(),
            report: WriteReport::default(),
            buf: vec![0; READ_SIZE],
        };
        walk_tree(dir.as_fd(), "", false, UnnamableEntry::Omit, &mut |target, entry| {
            let file = || fs::File::options().write(true).open(top.join(&entry.path)).unwrap();
            match entry.path.to_str() {
                Some("grows") => file().write_all_at(b" and more", 11).unwrap(),
                Some("shrinks") => file().set_len(5).unwrap(),
                Some("touched") => file().set_modified(UNIX_EPOCH).unwrap(),
                _ => {}
            }
            listing.entry(target, entry)
        })
        .unwrap();
        assert_eq!((listing.report.files, listing.report.changed), (4, 3));
        let bytes = listing.writer.finish().unwrap();
        let read: Vec<(String, u64, Sha256)> = Reader::open(&bytes[..])
            .unwrap()
            .filter_map(|object| match object.unwrap() {
                Object::File(file) => Some((file.name.to_string(), file.size.unwrap(), file.sha256.unwrap())),
                _ => None,
            })
            .collect();
        let whole = Sha256::digest(b"hello world");
        assert_eq!(
            read,
            [
                ("grows".to_string(), 11, whole),
                ("shrinks".to_string(), 5, Sha256::digest(b"hello")),
                ("stays".to_string(), 11, whole),
                ("touched".to_string(), 11, whole),
            ]
        );
    }
}
