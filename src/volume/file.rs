// SPDX-License-Identifier: LGPL-2.1-or-later
//! Files being written and read: the tokens that carry the state, the
//! guards that borrow the volume for Rust callers, and the volume methods
//! that do the work. Data goes to disk in whole clusters as it arrives; the
//! directory entry is completed when the file is finished, after the FAT.

use std::io::{self, Read, Write};
use std::time::SystemTime;

use super::{check_attributes, writable, Located, Placement, Volume, MAX_FILE_SIZE, SETTABLE_ATTRIBUTES};
use crate::dir::{DirEntry, Directory};
use crate::dirent::{RawDirEntry, ATTR_ARCHIVE, ATTR_READ_ONLY};
use crate::errno::*;
use crate::fat::{Entry, Extent};
use crate::time::FatTimestamp;
use crate::{Context, CorruptPlace, Detail, Result};

/// The detail of a damaged structure.
fn damaged(place: CorruptPlace, path: Option<&str>, cluster: Option<u32>) -> Detail {
    Detail::Corrupt {
        place,
        field: None,
        path: path.map(str::to_string),
        cluster,
    }
}

impl Volume {
    /// Creates a file and returns the token for writing it. Nothing is
    /// written to the directory until the file is finished: its slots are
    /// reserved in memory and the entry goes in, complete, after the data
    /// and the FAT. So a crash while the file is written leaves the
    /// directory as it was, never an empty file. With `replace` an existing
    /// file of the same name stays in place until the new one is complete
    /// and is removed then; without it an existing file is an EEXIST error.
    ///
    /// The token borrows nothing, so any number of files can be open at
    /// once and the volume stays usable in between; whether another
    /// operation took the slots or the name is checked when the file is
    /// finished. A token that is dropped leaves its clusters allocated until
    /// the next fsck; [`Volume::create_file`] wraps it in a guard that
    /// aborts instead.
    pub fn begin_file(&mut self, path: &str, time: SystemTime, replace: bool) -> Result<OpenFile> {
        self.begin_write()?;
        let (dir_cluster, name) = self.locate_parent(path)?;
        let (placement, replaced) = self.with_directory_mut(dir_cluster, |vol, parent| {
            let replaced = match Self::find(parent, name.as_str()) {
                Some(existing) if existing.short.is_directory() => {
                    bail!(EISDIR, Detail::Path(path.to_string()), "'{}' is a directory", path);
                }
                Some(_) if !replace => bail!(EEXIST, Detail::Path(path.to_string()), "'{}' exists", path),
                existing => existing,
            };
            let placement = vol
                .place_entry(parent, &name, replaced.as_ref())
                .map_err(|e| e.at_path(path))?;
            if !vol.reserve_slots(parent, placement.start, placement.long.len() + 1) {
                bail!(
                    EUCLEAN,
                    damaged(CorruptPlace::Directory, Some(path), None),
                    "the slots found for '{}' are not free",
                    path
                );
            }
            // A grown directory has its new cluster linked in the FAT.
            if let Err(e) = vol.flush() {
                vol.release_slots(parent, placement.start);
                return Err(e);
            }
            Ok((placement, replaced))
        })?;
        let mut entry = RawDirEntry {
            attr: ATTR_ARCHIVE,
            ..RawDirEntry::default()
        };
        entry.set_times(FatTimestamp::from_system_time(time));
        let cs = self.layout.cluster_size() as usize;
        Ok(OpenFile {
            dir_cluster,
            placement,
            name: name.as_str().to_string(),
            folded: name.folded(),
            entry,
            replaced,
            first: 0,
            last: 0,
            size: 0,
            pending: Vec::with_capacity(cs),
            failed: false,
            published: false,
        })
    }

    /// Creates a file and returns a writer for its contents; see
    /// [`Volume::begin_file`] for what happens when and [`FileWriter`] for
    /// the guard that aborts an unfinished file on drop.
    pub fn create_file(&mut self, path: &str, time: SystemTime, replace: bool) -> Result<FileWriter<'_>> {
        let file = self.begin_file(path, time, replace)?;
        Ok(FileWriter {
            volume: self,
            file: Some(file),
        })
    }

    /// Opens a file for sequential reading and returns the token for it.
    /// Like a write token it borrows nothing; [`Volume::open_file`] wraps it
    /// in a [`FileReader`].
    pub fn begin_read(&self, path: &str) -> Result<OpenRead> {
        let Located::Entry { entry, .. } = self.locate(path)? else {
            bail!(EISDIR, Detail::Path("/".into()), "the root directory is not a file");
        };
        if entry.short.is_directory() {
            bail!(EISDIR, Detail::Path(path.to_string()), "'{}' is a directory", path);
        }
        let size = u64::from(entry.short.size);
        let first = entry.short.first_cluster;
        // The chain is walked once here to see that it is intact and long
        // enough; nothing of it is kept but the first cluster.
        let clusters = if first == 0 { 0 } else { self.chain_len(first)? };
        let needed = size.div_ceil(u64::from(self.layout.cluster_size()));
        if u64::from(clusters) < needed {
            bail!(
                EUCLEAN,
                damaged(CorruptPlace::Chain, Some(path), Some(first)),
                "'{}' has {} bytes but only {} clusters",
                path,
                size,
                clusters
            );
        }
        Ok(OpenRead {
            first,
            size,
            pos: 0,
            current: None,
        })
    }

    /// The cluster holding the `index`th cluster of an open file's chain,
    /// stepping on from where the last read left off.
    fn cluster_at(&self, file: &mut OpenRead, index: u64) -> Result<u32> {
        let (mut cluster, mut at) = match file.current {
            Some((c, i)) if i <= index => (c, i),
            _ => (file.first, 0),
        };
        while at < index {
            cluster = match self.fat_entry(cluster)? {
                Entry::Next(next) => next,
                other => bail!(
                    EUCLEAN,
                    "the chain of the file ends after {} clusters ({:?})",
                    at + 1,
                    other
                ),
            };
            at += 1;
        }
        file.current = Some((cluster, at));
        Ok(cluster)
    }

    /// Opens a file for sequential reading.
    pub fn open_file(&self, path: &str) -> Result<FileReader<'_>> {
        Ok(FileReader {
            volume: self,
            file: self.begin_read(path)?,
        })
    }

    /// Reads from an open file into `buf`, up to the end of a cluster or of
    /// the file. Returns the number of bytes read, 0 at the end.
    pub fn read_file_data(&self, file: &mut OpenRead, buf: &mut [u8]) -> Result<usize> {
        if file.pos >= file.size || buf.is_empty() {
            return Ok(0);
        }
        let cs = u64::from(self.layout.cluster_size());
        let index = file.pos / cs;
        let within = file.pos % cs;
        let n = (buf.len() as u64).min(cs - within).min(file.size - file.pos) as usize;
        let cluster = self.cluster_at(file, index)?;
        let off = self.layout.cluster_offset(cluster)? + within;
        self.device.read_at(off, &mut buf[..n])?;
        file.pos += n as u64;
        Ok(n)
    }

    /// Appends `buf` to an open file. Whole clusters go to disk as they
    /// fill; the rest waits for more data or for the finish. A failed write
    /// poisons the file: further writes fail with EIO and finishing it
    /// discards it.
    pub fn write_file_data(&mut self, file: &mut OpenFile, buf: &[u8]) -> Result<()> {
        if file.failed {
            bail!(EIO, "an earlier write failed, the file is discarded");
        }
        if file.size + buf.len() as u64 > MAX_FILE_SIZE {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: None,
                    size: file.size + buf.len() as u64,
                    maximum: MAX_FILE_SIZE,
                },
                "FAT32 files cannot be larger than {} bytes",
                MAX_FILE_SIZE
            );
        }
        let result = self.append_inner(file, buf);
        if result.is_err() {
            file.failed = true;
        }
        result
    }

    /// Allocates clusters for `data`, a whole number of clusters, and
    /// writes it.
    fn write_clusters(&mut self, file: &mut OpenFile, mut data: &[u8]) -> Result<()> {
        let cs = self.layout.cluster_size() as usize;
        debug_assert_eq!(data.len() % cs, 0);
        while !data.is_empty() {
            let wanted = (data.len() / cs) as u32;
            let Extent { first, count } = self.allocate(wanted)?;
            if file.first == 0 {
                file.first = first;
            } else {
                self.link(file.last, first)?;
            }
            file.last = first + count - 1;
            let len = count as usize * cs;
            self.device.write_at(self.layout.cluster_offset(first)?, &data[..len])?;
            data = &data[len..];
        }
        Ok(())
    }

    fn append_inner(&mut self, file: &mut OpenFile, mut buf: &[u8]) -> Result<()> {
        let cs = self.layout.cluster_size() as usize;
        if !file.pending.is_empty() {
            let take = buf.len().min(cs - file.pending.len());
            file.pending.extend_from_slice(&buf[..take]);
            file.size += take as u64;
            buf = &buf[take..];
            if file.pending.len() == cs {
                let full = std::mem::take(&mut file.pending);
                self.write_clusters(file, &full)?;
                file.pending = full;
                file.pending.clear();
            }
        }
        let whole = buf.len() / cs * cs;
        if whole > 0 {
            self.write_clusters(file, &buf[..whole])?;
            file.size += whole as u64;
        }
        file.pending.extend_from_slice(&buf[whole..]);
        file.size += (buf.len() - whole) as u64;
        Ok(())
    }

    fn finish_inner(&mut self, file: &mut OpenFile) -> Result<()> {
        if !file.pending.is_empty() {
            let cs = self.layout.cluster_size() as usize;
            // The slack after the data is zeroed so images are reproducible.
            let mut pending = std::mem::take(&mut file.pending);
            pending.resize(cs, 0);
            self.write_clusters(file, &pending)?;
        }
        file.entry.first_cluster = file.first;
        file.entry.size = file.size as u32;
        // The chain goes to disk before the entry that points at it, and
        // reaches the device first where the device may reorder.
        self.flush()?;
        self.commit_barrier()?;
        let replaced = self.with_directory_mut(file.dir_cluster, |vol, dir| vol.publish(file, dir))?;
        // From here on the file is on the volume. Whatever fails below
        // leaves at worst the old chain allocated, which fsck reports as
        // lost clusters.
        file.published = true;
        if let Some(old) = replaced {
            if old.short.first_cluster != 0 {
                // The old entry is gone before its clusters are free for
                // reuse: a FAT that reaches the device first would leave
                // the entry pointing at free clusters, and the next file
                // could be written into them.
                self.commit_barrier()?;
                self.free_chain(old.short.first_cluster)?;
            }
        }
        self.flush()
    }

    /// Writes the entry of a finished file into its slots in `dir`, the
    /// directory it belongs to, and returns the file it replaces, if that
    /// is still there and has gone with it.
    fn publish(&mut self, file: &mut OpenFile, dir: &mut Directory) -> Result<Option<DirEntry>> {
        writable(dir)?;
        if !dir.is_reserved(file.placement.start, file.placement.long.len() + 1) {
            bail!(
                EUCLEAN,
                damaged(CorruptPlace::Directory, None, None),
                "the directory changed underneath an open file"
            );
        }
        // The file being replaced goes only if it is still where it was; an
        // operation in between may have removed it, or put something else
        // into its slots. And nothing else may have taken the name since.
        let replaced = file.replaced.take().filter(|old| {
            dir.entry_at(old.slot)
                .is_some_and(|e| e.first_slot() == old.first_slot() && e.short.name == old.short.name)
        });
        if dir.name_taken(&file.folded, replaced.as_ref()) {
            bail!(EEXIST, "'{}' was created by someone else meanwhile", file.name);
        }
        // The old file's chain is freed once the new entry is on the volume
        // and cannot be given up then; a damaged chain is found out now,
        // while the old file is still untouched.
        if let Some(old) = &replaced {
            if old.short.first_cluster != 0 {
                self.chain_len(old.short.first_cluster)
                    .with_context(|| format!("'{}' cannot be replaced", file.name))?;
            }
        }
        // The new entry takes the old one's slots when it fits there: the
        // switch is then one run of slots, within one sector for all but
        // the longest names, and a torn directory write leaves the old
        // entry or the new one, not both and not neither. The slots that
        // were reserved for it go back. Deleting the old entry may move the
        // end of the directory back over deleted slots before it; the new
        // entry starts at that end when those slots are free, so that no
        // gap of zeros is left in front of it, and at the old slots when
        // they are not, say reserved for another open file.
        let mut in_place = false;
        if let Some(old) = &replaced {
            let count = file.placement.long.len() + 1;
            if count <= old.slot - old.first_slot() + 1 {
                self.release_slots(dir, file.placement.start);
                dir.delete(old);
                let mut start = old.first_slot().min(dir.end());
                if !self.reserve_slots(dir, start, count) {
                    start = old.first_slot();
                    self.reserve_slots(dir, start, count);
                }
                file.placement.start = start;
                in_place = true;
            }
        }
        // The entry takes the reserved slots.
        Self::write_placed(dir, &file.placement, file.entry);
        self.dirs.borrow_mut().release(file.dir_cluster, file.placement.start);
        if let Some(old) = &replaced {
            if !in_place {
                dir.delete(old);
            }
        }
        self.save_directory(dir)?;
        Ok(replaced)
    }

    /// Writes the last partial cluster, completes the directory entry and
    /// flushes. A file whose write failed earlier is discarded instead and
    /// reported as EIO.
    pub fn finish_file(&mut self, mut file: OpenFile) -> Result<()> {
        if file.failed {
            let _ = self.abort_inner(&mut file);
            bail!(EIO, "an earlier write failed, the file is discarded");
        }
        let result = self.finish_inner(&mut file);
        if result.is_err() && !file.published {
            let _ = self.abort_inner(&mut file);
        }
        result
    }

    fn abort_inner(&mut self, file: &mut OpenFile) -> Result<()> {
        // Nothing of the file is in the directory; the reservation goes, if
        // it is still there, and the clusters are freed.
        self.dirs.borrow_mut().release(file.dir_cluster, file.placement.start);
        if file.first != 0 {
            self.free_chain(file.first)?;
            file.first = 0;
        }
        self.flush()
    }

    /// Discards an open file: removes its entry and frees its clusters. A
    /// file being replaced stays as it was.
    pub fn abort_file(&mut self, mut file: OpenFile) -> Result<()> {
        self.abort_inner(&mut file)
    }
}

/// A file being written: the state the volume needs to continue, finish
/// or abort it, without a borrow of the volume. See [`Volume::begin_file`].
#[derive(Debug)]
pub struct OpenFile {
    dir_cluster: u32,
    /// The reserved slots and the names to write into them.
    placement: Placement,
    name: String,
    folded: Vec<u16>,
    /// Attributes, times, and at the end size and first cluster.
    entry: RawDirEntry,
    /// The file this one replaces, removed when the new one is complete.
    replaced: Option<DirEntry>,
    first: u32,
    last: u32,
    size: u64,
    pending: Vec<u8>,
    /// A write failed; the file will be discarded.
    failed: bool,
    /// The entry is on the volume; a failure after that must not take the
    /// file's clusters away again.
    published: bool,
}

impl OpenFile {
    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Sets or clears the read-only attribute the entry gets when the file
    /// is finished.
    pub fn set_read_only(&mut self, read_only: bool) {
        if read_only {
            self.entry.attr |= ATTR_READ_ONLY;
        } else {
            self.entry.attr &= !ATTR_READ_ONLY;
        }
    }

    /// Sets the read-only, hidden, system and archive attributes the entry
    /// gets when the file is finished, in place of the archive attribute
    /// alone that a new file carries. Any other bit is refused with EINVAL,
    /// as by [`Volume::set_attributes`].
    pub fn set_attributes(&mut self, attributes: u8) -> Result<()> {
        check_attributes(attributes)?;
        self.entry.attr = (self.entry.attr & !SETTABLE_ATTRIBUTES) | attributes;
        Ok(())
    }
}

/// Writes a file sequentially: an [`OpenFile`] plus the volume it belongs
/// to. Data is written in whole clusters as it arrives; the directory entry
/// is completed by [`FileWriter::finish`]. Dropping the writer without
/// finishing it discards the file, and so does a failed write.
#[derive(Debug)]
pub struct FileWriter<'a> {
    volume: &'a mut Volume,
    file: Option<OpenFile>,
}

impl FileWriter<'_> {
    /// Bytes written so far.
    pub fn size(&self) -> u64 {
        self.file.as_ref().map_or(0, OpenFile::size)
    }

    /// Sets or clears the read-only attribute the entry gets when the writer
    /// is finished.
    pub fn set_read_only(&mut self, read_only: bool) {
        if let Some(file) = self.file.as_mut() {
            file.set_read_only(read_only);
        }
    }

    /// Sets the attributes the entry gets when the writer is finished, see
    /// [`OpenFile::set_attributes`].
    pub fn set_attributes(&mut self, attributes: u8) -> Result<()> {
        match self.file.as_mut() {
            Some(file) => file.set_attributes(attributes),
            None => Ok(()),
        }
    }

    fn take(&mut self) -> Result<OpenFile> {
        self.file
            .take()
            .ok_or_else(|| err!(EBADF, "the file writer is finished"))
    }

    /// Writes the last partial cluster, completes the directory entry and
    /// flushes. A writer whose write failed earlier discards the file and
    /// reports EIO.
    pub fn finish(mut self) -> Result<()> {
        let file = self.take()?;
        self.volume.finish_file(file)
    }

    /// Discards the file: removes its entry and frees its clusters. A file
    /// being replaced stays as it was.
    pub fn abort(mut self) -> Result<()> {
        let file = self.take()?;
        self.volume.abort_file(file)
    }
}

impl Write for FileWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| err!(EBADF, "the file writer is finished"))?;
        self.volume.write_file_data(file, buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for FileWriter<'_> {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = self.volume.abort_file(file);
        }
    }
}

/// A file being read, without a borrow of the volume. See
/// [`Volume::begin_read`].
#[derive(Debug)]
pub struct OpenRead {
    first: u32,
    size: u64,
    pos: u64,
    /// The cluster holding `pos` and its index in the chain, once known.
    current: Option<(u32, u64)>,
}

impl OpenRead {
    /// The file size.
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Reads a file sequentially: an [`OpenRead`] plus the volume it belongs to.
#[derive(Debug)]
pub struct FileReader<'a> {
    volume: &'a Volume,
    file: OpenRead,
}

impl FileReader<'_> {
    /// The file size.
    pub fn size(&self) -> u64 {
        self.file.size
    }
}

impl Read for FileReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.volume.read_file_data(&mut self.file, buf)?)
    }
}
