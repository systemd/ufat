// SPDX-License-Identifier: LGPL-2.1-or-later
//! An open FAT32 volume: lookups, directory operations and sequential file
//! I/O.
//!
//! Paths inside the volume use '/' as separator, are looked up case
//! insensitively against long and short names, and may not contain "." or
//! ".." components. All times are UTC.
//!
//! Every operation leaves the on-disk directories consistent before it
//! returns and writes changed FAT sectors and the FSInfo sector through
//! [`Volume::flush`]. Data reaches stable storage with [`Volume::sync`] or
//! [`Volume::close`].
//!
//! Directories stay in memory between operations. An operation borrows the
//! directories it works on from the volume's cache, which reads them from
//! disk only when they are not there, and they go back once their changes
//! are written. A path therefore costs one lookup per component and a new
//! file one directory write, never a reread of the directory.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

use crate::boot::{self, BootSector, FsInfo, BOOT_SECTOR_SIZE, FSINFO_SIZE, FSINFO_UNKNOWN, NO_NAME, NT_FLAG_DIRTY};
use crate::device::Device;
use crate::dir::{DirEntry, Directory, MAX_SLOTS};
use crate::dirent::{
    short_name_checksum, RawDirEntry, ATTR_ARCHIVE, ATTR_DIRECTORY, ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM,
    ATTR_VOLUME_ID, DIR_ENTRY_SIZE, DOTDOT_NAME, DOT_NAME, ENTRY_DELETED, ENTRY_E5_ESCAPE, ENTRY_END,
};
use crate::errno::*;
use crate::fat::{Entry, Extent, Fat, FatStore, CACHE_BYTES, ENTRY1_CLEAN_SHUTDOWN};
use crate::layout::Layout;
use crate::name::{fold_str, long_name_entries, short_name_to_string, Alias, LongName};
use crate::path::components;
use crate::probe::Prober;
use crate::time::FatTimestamp;
use crate::Result;
use crate::{Detail, NoSpaceReason, NotFat32Reason};

mod file;
#[cfg(test)]
mod tests;
mod tree;

pub use file::{FileReader, FileWriter, OpenFile, OpenRead};
pub use tree::RemoveReport;

/// Largest file FAT32 can store.
pub const MAX_FILE_SIZE: u64 = u32::MAX as u64;

/// Directory data kept in memory between operations, at most. A maximal
/// directory holds 2 MiB of entries; the index it keeps of itself is a few
/// times that for long names.
const DIRECTORY_CACHE_BYTES: usize = 8 << 20;

/// What is known about a file or directory in the volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    /// The name, long if there is one.
    pub name: String,
    /// The 8.3 name as text.
    pub short_name: String,
    /// Whether this is a directory.
    pub is_dir: bool,
    /// File size in bytes; 0 for directories.
    pub size: u64,
    /// Last modification time, 2 second resolution.
    pub modified: SystemTime,
    /// Creation time, 10 ms resolution.
    pub created: SystemTime,
    /// The attribute byte.
    pub attributes: u8,
    /// First cluster, 0 for empty files.
    pub(crate) first_cluster: u32,
}

/// Where a path led: the root, or an entry and the first cluster of the
/// directory holding it.
enum Located {
    Root,
    Entry { parent: u32, entry: DirEntry },
}

/// A placed, not yet written entry: its slot and its names.
#[derive(Debug)]
struct Placement {
    start: usize,
    name: [u8; 11],
    case_flags: u8,
    long: Vec<[u8; DIR_ENTRY_SIZE]>,
}

/// Directories read earlier and written out, by first cluster, and the
/// slots reserved in them for files being written. The least recently used
/// directories go when the cache is over its size; the reservations stay
/// until their files are finished or aborted and are applied again to a
/// directory read back from disk.
#[derive(Debug, Default)]
struct DirectoryCache {
    dirs: HashMap<u32, (Directory, u64)>,
    by_use: BTreeMap<u64, u32>,
    bytes: usize,
    tick: u64,
    /// The reserved runs of each directory, start to length.
    reserved: HashMap<u32, BTreeMap<usize, usize>>,
    /// Directories read from disk because they were not here.
    #[cfg(test)]
    loads: u64,
}

impl DirectoryCache {
    fn take(&mut self, first_cluster: u32) -> Option<Directory> {
        let (dir, tick) = self.dirs.remove(&first_cluster)?;
        self.by_use.remove(&tick);
        self.bytes -= dir.data_len();
        Some(dir)
    }

    fn keep(&mut self, dir: Directory) {
        debug_assert!(!dir.has_dirty_clusters(), "a cached directory matches the disk");
        self.take(dir.first_cluster());
        self.tick += 1;
        self.bytes += dir.data_len();
        self.by_use.insert(self.tick, dir.first_cluster());
        self.dirs.insert(dir.first_cluster(), (dir, self.tick));
        while self.bytes > DIRECTORY_CACHE_BYTES && self.dirs.len() > 1 {
            let Some((_, &victim)) = self.by_use.first_key_value() else {
                break;
            };
            self.take(victim);
        }
    }

    /// Records a run reserved in the directory starting at `first_cluster`.
    fn add_reservation(&mut self, first_cluster: u32, start: usize, count: usize) {
        self.reserved.entry(first_cluster).or_default().insert(start, count);
    }

    /// Forgets the run reserved at `start`, here and in the cached copy of
    /// the directory.
    fn release(&mut self, first_cluster: u32, start: usize) {
        if let Some(runs) = self.reserved.get_mut(&first_cluster) {
            runs.remove(&start);
            if runs.is_empty() {
                self.reserved.remove(&first_cluster);
            }
        }
        if let Some((dir, _)) = self.dirs.get_mut(&first_cluster) {
            dir.release_reservation(start);
        }
    }
}

/// The FAT copies on a device, for the FAT cache.
pub(crate) struct DeviceStore<'a> {
    pub(crate) device: &'a Device,
    pub(crate) layout: Layout,
}

impl FatStore for DeviceStore<'_> {
    fn read_fat(&self, copy: u32, sector: u64, buf: &mut [u8]) -> Result<()> {
        let offset = self.layout.fat_offset(copy) + sector * u64::from(self.layout.sector_size);
        self.device.read_at(offset, buf)
    }

    fn write_fat(&self, copy: u32, sector: u64, buf: &[u8]) -> Result<()> {
        let offset = self.layout.fat_offset(copy) + sector * u64::from(self.layout.sector_size);
        self.device.write_at(offset, buf)
    }
}

/// An open volume.
#[derive(Debug)]
pub struct Volume {
    device: Device,
    boot: BootSector,
    /// The boot sector as read, for the dirty bit.
    boot_raw: [u8; BOOT_SECTOR_SIZE],
    /// FAT entry 1 as read, restored when the session ends.
    entry1_at_open: u32,
    /// Something has been written since open() or the last sync(): the
    /// volume carries its dirty marks, see [`Volume::begin_write`].
    writing: bool,
    /// Closed with [`Volume::close_unfinished`]: the marks stay.
    unfinished: bool,
    layout: Layout,
    fat: Fat,
    /// The FSInfo structure as it is on disk, the start of its sector: the
    /// counters are patched into it, the reserved bytes stay what they were.
    fsinfo_raw: [u8; FSINFO_SIZE],
    fsinfo_on_disk: Option<FsInfo>,
    dirs: RefCell<DirectoryCache>,
    /// The buffer file contents are copied through, kept between files.
    pub(crate) copy_buffer: Vec<u8>,
    /// Flush before every write that publishes new state. See
    /// [`Volume::set_durable`].
    durable: bool,
}

/// Refuses to change a directory that holds data after its end marker.
fn writable(dir: &Directory) -> Result<()> {
    if dir.is_damaged() {
        bail!(
            EUCLEAN,
            "directory at cluster {} has data after its end marker and is not written to",
            dir.first_cluster()
        );
    }
    Ok(())
}

/// The attributes a caller may set on an entry: the four DOS bits a file or
/// a directory carries. The others say what the entry is and are not for
/// setting.
const SETTABLE_ATTRIBUTES: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCHIVE;

/// Refuses attribute bits outside [`SETTABLE_ATTRIBUTES`].
fn check_attributes(attributes: u8) -> Result<()> {
    if attributes & !SETTABLE_ATTRIBUTES != 0 {
        bail!(
            EINVAL,
            Detail::InvalidOption("attributes"),
            "attributes 0x{:02x} have bits other than read-only, hidden, system and archive",
            attributes
        );
    }
    Ok(())
}

/// Whether a label field says the volume has no label: `NO NAME`, which
/// mkfs.fat and Windows put there, or blanks.
fn is_no_name(label: &[u8; 11]) -> bool {
    *label == NO_NAME || label.iter().all(|&b| b == b' ')
}

impl Volume {
    /// Formats `device` with `options` and opens the new volume.
    pub fn create(device: Device, options: &crate::format::FormatOptions) -> Result<Volume> {
        crate::format::format(&device, options)?;
        Volume::open(device)
    }

    /// Opens the FAT32 volume on `device`.
    pub fn open(device: Device) -> Result<Volume> {
        if device.len() < BOOT_SECTOR_SIZE as u64 {
            bail!(
                EMEDIUMTYPE,
                Detail::NotFat32 {
                    reason: NotFat32Reason::TooSmall,
                    found: None,
                    sector_size: None,
                },
                "{} bytes are too few to hold a file system",
                device.len()
            );
        }
        let mut sector = [0u8; BOOT_SECTOR_SIZE];
        device.read_at(0, &mut sector)?;
        let boot = BootSector::parse(&sector).map_err(|e| Prober::new().refine(e, &device, &sector))?;
        let layout = boot.layout().map_err(|e| Prober::new().refine(e, &device, &sector))?;
        if layout.size() > device.len() {
            bail!(
                EUCLEAN,
                "file system claims {} bytes but the device has {}",
                layout.size(),
                device.len()
            );
        }
        let mut fsinfo_raw = [0u8; FSINFO_SIZE];
        device.read_at(
            u64::from(boot.fsinfo_sector) * u64::from(layout.sector_size),
            &mut fsinfo_raw,
        )?;
        let fsinfo = FsInfo::parse(&fsinfo_raw);
        let store = DeviceStore {
            device: &device,
            layout,
        };
        let fat = Fat::open(&layout, &store, fsinfo.map_or(0, |f| f.next_free), CACHE_BYTES)?;
        let entry1_at_open = fat.raw_entry(&store, 1)?;
        let durable = device.is_block_device();
        Ok(Volume {
            device,
            boot,
            boot_raw: sector,
            entry1_at_open,
            writing: false,
            unfinished: false,
            layout,
            fat,
            fsinfo_raw,
            fsinfo_on_disk: fsinfo,
            dirs: RefCell::new(DirectoryCache::default()),
            copy_buffer: Vec::new(),
            durable,
        })
    }

    /// Whether a write that publishes new state waits for everything it
    /// points at to reach the device first: a directory entry for its data
    /// and FAT chain, the FAT freeing clusters for the directory that no
    /// longer names them. The order of the writes alone holds only while
    /// the device keeps it; a volatile write cache does not, and then only
    /// a flush at these points makes a crash leave the old or the new file
    /// and never an entry pointing at stale clusters. On by default for
    /// block devices, off for image files, which are synced once at the
    /// end. Each flush costs what fdatasync costs on the device.
    pub fn set_durable(&mut self, durable: bool) {
        self.durable = durable;
    }

    /// Whether writes that publish new state are preceded by a flush.
    pub fn durable(&self) -> bool {
        self.durable
    }

    /// Marks the volume as being written, once per session. Linux and
    /// Windows decide from bit 0 of byte 0x41 in the boot sector whether a
    /// volume was cleanly unmounted, EDK2 and the specification from bit 27
    /// of FAT entry 1, and a crash in the middle of our work has to leave
    /// those marks behind. The FSInfo counts become "unknown" at the same
    /// time, so that no reader trusts a count a crash left stale. close()
    /// and sync() put the original values back.
    fn begin_write(&mut self) -> Result<()> {
        if self.writing {
            return Ok(());
        }
        self.writing = true;
        let dirty = self.entry1_at_open & !ENTRY1_CLEAN_SHUTDOWN;
        let (fat, store) = self.fat_mut();
        fat.set_entry1(&store, dirty)?;
        self.flush()?;
        let mut sector = self.boot_raw;
        sector[boot::field::NT_FLAGS] |= NT_FLAG_DIRTY;
        self.device.write_at(0, &sector)
    }

    /// Ends a writing session: the marks go back to what they were and
    /// FSInfo gets the real counts.
    fn end_write(&mut self) -> Result<()> {
        if !self.writing {
            return Ok(());
        }
        self.writing = false;
        let clean = self.entry1_at_open;
        let (fat, store) = self.fat_mut();
        fat.set_entry1(&store, clean)?;
        self.flush()?;
        self.device.write_at(0, &self.boot_raw)
    }

    /// The FAT copies on the device, for the FAT cache.
    fn store(&self) -> DeviceStore<'_> {
        DeviceStore {
            device: &self.device,
            layout: self.layout,
        }
    }

    /// The FAT and its store, borrowed apart so that the FAT can change.
    fn fat_mut(&mut self) -> (&mut Fat, DeviceStore<'_>) {
        (
            &mut self.fat,
            DeviceStore {
                device: &self.device,
                layout: self.layout,
            },
        )
    }

    /// What the FAT says about `cluster`.
    pub(crate) fn fat_entry(&self, cluster: u32) -> Result<Entry> {
        self.fat.get(&self.store(), cluster)
    }

    /// The length of the intact chain starting at `first`.
    pub(crate) fn chain_len(&self, first: u32) -> Result<u32> {
        self.fat.chain_len(&self.store(), first)
    }

    /// Allocates up to `max` contiguous clusters, see [`Fat::allocate`].
    pub(crate) fn allocate(&mut self, max: u32) -> Result<Extent> {
        let (fat, store) = self.fat_mut();
        fat.allocate(&store, max)
    }

    /// Makes `cluster` point at `next`.
    pub(crate) fn link(&mut self, cluster: u32, next: u32) -> Result<()> {
        let (fat, store) = self.fat_mut();
        fat.link(&store, cluster, next)
    }

    /// Frees the intact chain starting at `first`.
    pub(crate) fn free_chain(&mut self, first: u32) -> Result<u32> {
        let (fat, store) = self.fat_mut();
        fat.free_chain(&store, first)
    }

    /// The flush before a write that publishes what came before it.
    fn commit_barrier(&self) -> Result<()> {
        if self.durable {
            self.device.sync_data()?;
        }
        Ok(())
    }

    /// The volume geometry.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// The boot sector.
    pub fn boot_sector(&self) -> &BootSector {
        &self.boot
    }

    /// The underlying device.
    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Number of free clusters.
    pub fn free_clusters(&self) -> u32 {
        self.fat.free_count()
    }

    /// Free space in bytes.
    pub fn free_bytes(&self) -> u64 {
        u64::from(self.fat.free_count()) * u64::from(self.layout.cluster_size())
    }

    /// The volume label, from the root directory entry or else from the
    /// boot sector. None when the volume has no label: `NO NAME` and a
    /// blank label mean none, to us as to blkid and mtools.
    pub fn label(&self) -> Result<Option<String>> {
        Ok(self.label_bytes()?.map(|raw| crate::format::decode_label(&raw)))
    }

    /// The volume label as stored on disk, eleven space padded bytes in the
    /// OEM code page: the root directory's label entry if there is one, else
    /// the boot sector's. None when that says `NO NAME` or is blank, which
    /// is how a volume without a label is written.
    pub fn label_bytes(&self) -> Result<Option<[u8; 11]>> {
        let label = match self.label_entry()? {
            Some(e) => e.short.name,
            None => self.boot.volume_label,
        };
        Ok(Some(label).filter(|l| !is_no_name(l)))
    }

    /// The root directory's volume label entry, if there is one.
    fn label_entry(&self) -> Result<Option<DirEntry>> {
        self.with_directory(self.boot.root_cluster, |root| {
            Ok(root.iter().find(|e| e.short.is_volume_label()).cloned())
        })
    }

    /// The root directory's time: the volume label entry's modification
    /// time, when there is such an entry. FAT keeps no times for the root
    /// directory itself; its label entry is where mkfs.fat stamps the
    /// format time and where [`Volume::set_root_time`] puts one.
    pub fn root_time(&self) -> Result<Option<SystemTime>> {
        Ok(self.label_entry()?.map(|e| e.short.write_timestamp().to_system_time()))
    }

    /// The label a root label entry made here carries: the boot sector's
    /// label field, which is what format writes alongside its entry, and
    /// `NO NAME` when that field is blank or zeroed. A field starting with
    /// a zero byte can never go into an entry, where it would read as the
    /// end of the directory.
    fn label_for_entry(&self) -> [u8; 11] {
        let mut label = self.boot.volume_label;
        if label[0] == ENTRY_END || label.iter().all(|&b| b == b' ') {
            return NO_NAME;
        }
        if label[0] == ENTRY_DELETED {
            label[0] = ENTRY_E5_ESCAPE;
        }
        label
    }

    /// Sets the root directory's time on the volume label entry, creating
    /// the entry when there is none. A new entry carries the boot sector's
    /// label, `NO NAME` when the volume has none, so the label the volume
    /// reports stays what it was, see [`Volume::label`]. The time is stored
    /// as on any entry: the modification time in two second steps, the
    /// creation time in hundredths. The entry is one slot written in place,
    /// so a crash leaves the old time or the new one.
    pub fn set_root_time(&mut self, time: SystemTime) -> Result<()> {
        self.begin_write()?;
        let t = FatTimestamp::from_system_time(time);
        self.with_directory_mut(self.boot.root_cluster, |vol, root| {
            writable(root)?;
            let label = root.iter().find(|e| e.short.is_volume_label()).cloned();
            match label {
                Some(label) => {
                    let mut raw = label.short;
                    raw.set_times(t);
                    root.set_slot(label.slot, &raw.to_bytes());
                }
                None => {
                    let mut entry = RawDirEntry {
                        name: vol.label_for_entry(),
                        attr: ATTR_VOLUME_ID,
                        ..RawDirEntry::default()
                    };
                    entry.set_times(t);
                    let start = vol.free_run(root, 1)?;
                    root.write_entry(start, &[], &entry);
                    // A grown root has its new cluster linked in the FAT;
                    // the link goes to disk before the entry that sits in it.
                    vol.flush()?;
                }
            }
            vol.save_directory(root)
        })
    }

    /// Reads a directory from disk, past the cache. Operations go through
    /// [`Volume::take_directory`]; this is for looking at what is on disk.
    pub(crate) fn load_directory(&self, first_cluster: u32) -> Result<Directory> {
        let cs = self.layout.cluster_size() as usize;
        // A directory has at most MAX_SLOTS entries. A longer chain is damage
        // and must not make us read the volume into memory.
        let max_clusters = MAX_SLOTS * DIR_ENTRY_SIZE / cs;
        let Some(chain) = self.fat.chain_bounded(&self.store(), first_cluster, max_clusters)? else {
            bail!(
                EUCLEAN,
                "directory at cluster {} spans more than the {} clusters a directory can have",
                first_cluster,
                max_clusters
            );
        };
        let mut data = vec![0u8; chain.len() * cs];
        for (i, &c) in chain.iter().enumerate() {
            self.device
                .read_at(self.layout.cluster_offset(c)?, &mut data[i * cs..(i + 1) * cs])?;
        }
        Directory::new(chain, data, cs)
    }

    /// The directory starting at `first_cluster`, out of the cache or from
    /// disk, with the slots reserved for files being written in it.
    fn take_directory(&self, first_cluster: u32) -> Result<Directory> {
        if let Some(dir) = self.dirs.borrow_mut().take(first_cluster) {
            return Ok(dir);
        }
        let mut dir = self.load_directory(first_cluster)?;
        #[cfg(test)]
        {
            self.dirs.borrow_mut().loads += 1;
        }
        if let Some(runs) = self.dirs.borrow().reserved.get(&first_cluster) {
            for (&start, &count) in runs {
                // Slots taken meanwhile fail the file's finish, which checks
                // its reservation.
                dir.reserve(start, count);
            }
        }
        Ok(dir)
    }

    /// Keeps a directory that matches the disk for the operations to come.
    fn keep_directory(&self, dir: Directory) {
        self.dirs.borrow_mut().keep(dir);
    }

    /// Runs `f` on the directory starting at `first_cluster`, out of the
    /// cache or from disk. The directory goes back into the cache afterwards
    /// unless it holds changes that did not reach the disk, which a failed
    /// operation leaves behind: then the next one reads the disk again.
    fn with_directory<R>(&self, first_cluster: u32, f: impl FnOnce(&mut Directory) -> Result<R>) -> Result<R> {
        let mut dir = self.take_directory(first_cluster)?;
        let result = f(&mut dir);
        if !dir.has_dirty_clusters() {
            self.keep_directory(dir);
        }
        result
    }

    /// [`Volume::with_directory`] for an operation that changes the volume
    /// around the directory as well: allocates, grows or flushes.
    fn with_directory_mut<R>(
        &mut self,
        first_cluster: u32,
        f: impl FnOnce(&mut Self, &mut Directory) -> Result<R>,
    ) -> Result<R> {
        let mut dir = self.take_directory(first_cluster)?;
        let result = f(self, &mut dir);
        if !dir.has_dirty_clusters() {
            self.keep_directory(dir);
        }
        result
    }

    /// Drops the cached copy of a directory whose clusters are freed.
    fn forget_directory(&self, first_cluster: u32) {
        self.dirs.borrow_mut().take(first_cluster);
    }

    /// Reserves `count` slots at `start` of `dir` for a file being written,
    /// in the directory and in the record the cache keeps of them. False if
    /// the slots are not free.
    fn reserve_slots(&self, dir: &mut Directory, start: usize, count: usize) -> bool {
        if !dir.reserve(start, count) {
            return false;
        }
        self.dirs
            .borrow_mut()
            .add_reservation(dir.first_cluster(), start, count);
        true
    }

    /// Gives back the slots reserved at `start` of `dir`.
    fn release_slots(&self, dir: &mut Directory, start: usize) {
        dir.release_reservation(start);
        self.dirs.borrow_mut().release(dir.first_cluster(), start);
    }

    /// Writes the changed clusters of a directory.
    fn save_directory(&self, dir: &mut Directory) -> Result<()> {
        for i in 0..dir.chain().len() {
            if dir.is_dirty(i) {
                self.device
                    .write_at(self.layout.cluster_offset(dir.chain()[i])?, dir.cluster_data(i))?;
                dir.mark_clean(i);
            }
        }
        Ok(())
    }

    /// Finds `name` in `dir`, ignoring the dot entries and the volume label.
    fn find(dir: &Directory, name: &str) -> Option<DirEntry> {
        dir.find_name(&fold_str(name))
    }

    /// Descends from the root along `comps`, which must all be directories,
    /// and returns the first cluster of the directory reached.
    fn walk(&self, comps: &[&str]) -> Result<u32> {
        let mut cluster = self.boot.root_cluster;
        for (i, name) in comps.iter().enumerate() {
            cluster = match self.with_directory(cluster, |dir| Ok(Self::find(dir, name)))? {
                Some(e) if e.short.is_directory() => e.short.first_cluster,
                Some(_) => {
                    let p = format!("/{}", comps[..=i].join("/"));
                    bail!(ENOTDIR, Detail::Path(p.clone()), "'{}' is not a directory", p);
                }
                None => {
                    let p = format!("/{}", comps[..=i].join("/"));
                    bail!(ENOENT, Detail::Path(p.clone()), "'{}' does not exist", p);
                }
            };
        }
        Ok(cluster)
    }

    fn locate(&self, path: &str) -> Result<Located> {
        let comps = components(path)?;
        let Some((last, parents)) = comps.split_last() else {
            return Ok(Located::Root);
        };
        let parent = self.walk(parents)?;
        match self.with_directory(parent, |dir| Ok(Self::find(dir, last)))? {
            Some(entry) => Ok(Located::Entry { parent, entry }),
            None => bail!(ENOENT, Detail::Path(path.to_string()), "'{}' does not exist", path),
        }
    }

    /// The first cluster of the directory a path refers to.
    fn directory_at(&self, path: &str) -> Result<u32> {
        self.walk(&components(path)?)
    }

    /// The first cluster of the directory that would hold `path`, and the
    /// validated final component.
    fn locate_parent(&self, path: &str) -> Result<(u32, LongName)> {
        let comps = components(path)?;
        let Some((last, parents)) = comps.split_last() else {
            bail!(EEXIST, Detail::Path("/".into()), "the root directory exists");
        };
        let name = LongName::new(last)?;
        Ok((self.walk(parents)?, name))
    }

    fn metadata_of(entry: &DirEntry) -> Metadata {
        Metadata {
            name: entry.name(),
            short_name: short_name_to_string(&entry.short),
            is_dir: entry.short.is_directory(),
            size: if entry.short.is_directory() {
                0
            } else {
                u64::from(entry.short.size)
            },
            modified: entry.short.write_timestamp().to_system_time(),
            created: entry.short.create_timestamp().to_system_time(),
            attributes: entry.short.attr,
            first_cluster: entry.short.first_cluster,
        }
    }

    /// Returns what is known about `path`.
    pub fn metadata(&self, path: &str) -> Result<Metadata> {
        match self.locate(path)? {
            Located::Root => Ok(Metadata {
                name: String::new(),
                short_name: String::new(),
                is_dir: true,
                size: 0,
                modified: FatTimestamp::EPOCH.to_system_time(),
                created: FatTimestamp::EPOCH.to_system_time(),
                attributes: ATTR_DIRECTORY,
                first_cluster: self.boot.root_cluster,
            }),
            Located::Entry { entry, .. } => Ok(Self::metadata_of(&entry)),
        }
    }

    /// Lists the directory at `path`, in on-disk order, without the dot
    /// entries and the volume label.
    pub fn read_dir(&self, path: &str) -> Result<Vec<Metadata>> {
        self.with_directory(self.directory_at(path)?, |dir| {
            Ok(dir
                .iter()
                .filter(|e| !e.is_dot() && !e.short.is_volume_label())
                .map(Self::metadata_of)
                .collect())
        })
    }

    /// Adds a zeroed cluster to a directory. The cluster is written out right
    /// away: an all-zero tail is always a valid extension, so whatever
    /// happens to the caller afterwards the directory stays consistent once
    /// the FAT is flushed.
    fn grow_directory(&mut self, dir: &mut Directory) -> Result<()> {
        let per_cluster = self.layout.cluster_size() as usize / DIR_ENTRY_SIZE;
        if dir.slots() + per_cluster > MAX_SLOTS {
            bail!(
                ENOSPC,
                Detail::NoSpace {
                    reason: NoSpaceReason::DirectoryEntries,
                    path: None,
                },
                "directory is full, it cannot hold more than {} entries",
                MAX_SLOTS
            );
        }
        let cluster = self.allocate(1)?.first;
        let zeros = vec![0u8; self.layout.cluster_size() as usize];
        // The zeros reach the device before the FAT links the cluster into
        // the chain, else a crash could leave the directory running into
        // whatever the cluster held before.
        let written = self
            .device
            .write_at(self.layout.cluster_offset(cluster)?, &zeros)
            .and_then(|()| self.commit_barrier());
        if let Err(e) = written {
            let _ = self.free_chain(cluster);
            return Err(e);
        }
        let last = *dir.chain().last().expect("directories have a cluster");
        self.link(last, cluster)?;
        dir.append_cluster(cluster);
        dir.mark_clean(dir.chain().len() - 1);
        Ok(())
    }

    /// Finds the first run of `count` free slots in `dir`, growing it as
    /// needed. Nothing is written to the slots.
    fn free_run(&mut self, dir: &mut Directory, count: usize) -> Result<usize> {
        loop {
            if let Some(start) = dir.find_free_run(count) {
                return Ok(start);
            }
            self.grow_directory(dir)?;
        }
    }

    /// Picks the short name for `name`, builds its long name entries and
    /// finds room for them in `dir`, growing it as needed. `replacing` is an
    /// entry about to be replaced, whose names do not count as taken.
    /// Nothing is written yet.
    fn place_entry(&mut self, dir: &mut Directory, name: &LongName, replacing: Option<&DirEntry>) -> Result<Placement> {
        writable(dir)?;
        if dir.name_taken(&name.folded(), replacing) {
            bail!(EEXIST, "'{}' exists", name.as_str());
        }
        let alias = Alias::of(name);
        let (short, long) = if alias.needs_long_name {
            let short = if alias.lossy {
                dir.short_name_for(&alias, replacing).ok_or_else(|| {
                    err!(
                        ENOSPC,
                        Detail::NoSpace {
                            reason: NoSpaceReason::ShortNames,
                            path: None,
                        },
                        "no free short name for '{}'",
                        name.as_str()
                    )
                })?
            } else {
                alias.name
            };
            (short, long_name_entries(name, short_name_checksum(&short)))
        } else {
            (alias.name, Vec::new())
        };
        let start = self.free_run(dir, long.len() + 1)?;
        Ok(Placement {
            start,
            name: short,
            case_flags: alias.case_flags,
            long,
        })
    }

    fn write_placed(dir: &mut Directory, p: &Placement, mut short: RawDirEntry) -> usize {
        short.name = p.name;
        short.nt_flags = p.case_flags;
        dir.write_entry(p.start, &p.long, &short);
        p.start + p.long.len()
    }

    /// Deletes an entry from `dir`, writes the directory, then frees the
    /// entry's clusters. In that order a crash costs at most a leaked chain,
    /// never a directory entry pointing at free clusters.
    fn remove_entry(&mut self, dir: &mut Directory, entry: &DirEntry) -> Result<()> {
        writable(dir)?;
        dir.delete(entry);
        self.save_directory(dir)?;
        if entry.short.first_cluster != 0 {
            // The entry is gone before its clusters are free for reuse.
            self.commit_barrier()?;
            self.free_chain(entry.short.first_cluster)?;
        }
        Ok(())
    }

    /// Creates the directory `name` in `parent`, writes both and returns the
    /// new directory, which matches the disk. On failure `parent` may hold
    /// an entry that was never written, which keeps it out of the cache.
    fn make_directory(&mut self, parent: &mut Directory, name: &LongName, time: SystemTime) -> Result<Directory> {
        let t = FatTimestamp::from_system_time(time);
        // The new directory's cluster is allocated before anything else is
        // touched, so that running out of space changes nothing.
        let cluster = self.allocate(1)?.first;
        let result = (|| {
            let cs = self.layout.cluster_size() as usize;
            let mut data = vec![0u8; cs];
            let mut dot = RawDirEntry {
                name: DOT_NAME,
                attr: ATTR_DIRECTORY,
                first_cluster: cluster,
                ..RawDirEntry::default()
            };
            dot.set_times(t);
            let mut dotdot = dot;
            dotdot.name = DOTDOT_NAME;
            // ".." of a directory in the root points at cluster 0, not at
            // the root's real cluster.
            dotdot.first_cluster = if parent.first_cluster() == self.boot.root_cluster {
                0
            } else {
                parent.first_cluster()
            };
            data[..DIR_ENTRY_SIZE].copy_from_slice(&dot.to_bytes());
            data[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE].copy_from_slice(&dotdot.to_bytes());
            self.device.write_at(self.layout.cluster_offset(cluster)?, &data)?;
            let placement = self.place_entry(parent, name, None)?;
            let mut entry = RawDirEntry {
                attr: ATTR_DIRECTORY,
                first_cluster: cluster,
                ..RawDirEntry::default()
            };
            entry.set_times(t);
            Self::write_placed(parent, &placement, entry);
            // FAT first, directory entry second: a crash in between leaks
            // a cluster instead of leaving an entry on free space.
            self.flush()?;
            self.commit_barrier()?;
            self.save_directory(parent)?;
            self.flush()?;
            Directory::new(vec![cluster], data, cs)
        })();
        if result.is_err() {
            let _ = self.free_chain(cluster);
            let _ = self.flush();
        }
        result
    }

    /// Creates a directory. Its parent must exist.
    pub fn create_dir(&mut self, path: &str, time: SystemTime) -> Result<()> {
        self.begin_write()?;
        let (parent, name) = self.locate_parent(path)?;
        let child = self.with_directory_mut(parent, |vol, parent| {
            if Self::find(parent, name.as_str()).is_some() {
                bail!(EEXIST, Detail::Path(path.to_string()), "'{}' exists", path);
            }
            vol.make_directory(parent, &name, time).map_err(|e| e.at_path(path))
        })?;
        self.keep_directory(child);
        Ok(())
    }

    /// Creates a directory and any missing parents. Existing directories
    /// along the way are fine.
    pub fn create_dir_all(&mut self, path: &str, time: SystemTime) -> Result<()> {
        self.begin_write()?;
        let comps = components(path)?;
        let mut cluster = self.boot.root_cluster;
        for (i, c) in comps.iter().enumerate() {
            cluster = self.with_directory_mut(cluster, |vol, dir| match Self::find(dir, c) {
                Some(e) if e.short.is_directory() => Ok(e.short.first_cluster),
                Some(_) => {
                    let p = format!("/{}", comps[..=i].join("/"));
                    bail!(
                        ENOTDIR,
                        Detail::Path(p.clone()),
                        "'{}' exists and is not a directory",
                        p
                    );
                }
                None => {
                    let name = LongName::new(c)?;
                    let child = vol
                        .make_directory(dir, &name, time)
                        .map_err(|e| e.at_path(&format!("/{}", comps[..=i].join("/"))))?;
                    let first = child.first_cluster();
                    vol.keep_directory(child);
                    Ok(first)
                }
            })?;
        }
        Ok(())
    }

    /// Sets the modification and creation time of a file or directory. A
    /// directory's "." and ".." entries follow along.
    pub fn set_times(&mut self, path: &str, time: SystemTime) -> Result<()> {
        self.begin_write()?;
        let Located::Entry { parent, entry } = self.locate(path)? else {
            bail!(EINVAL, "the root directory has no timestamps");
        };
        let t = FatTimestamp::from_system_time(time);
        let mut raw = entry.short;
        raw.set_times(t);
        self.with_directory(parent, |parent| {
            writable(parent)?;
            parent.set_slot(entry.slot, &raw.to_bytes());
            self.save_directory(parent)
        })?;
        if raw.is_directory() {
            self.with_directory(raw.first_cluster, |dir| {
                writable(dir)?;
                let dots: Vec<DirEntry> = dir.iter().filter(|e| e.is_dot()).cloned().collect();
                for dot in dots {
                    let mut d = dot.short;
                    d.set_times(t);
                    dir.set_slot(dot.slot, &d.to_bytes());
                }
                self.save_directory(dir)
            })?;
        }
        Ok(())
    }

    /// Sets the read-only, hidden, system and archive attributes of the
    /// entry at `path`, leaving the other bits alone: `attributes` replaces
    /// those four bits, so a file loses its archive bit unless it is given
    /// again. Any other bit is refused with EINVAL. Works for files and
    /// directories; the root has no entry and is refused. The entry is
    /// rewritten in place, so a crash leaves the old attributes or the new.
    pub fn set_attributes(&mut self, path: &str, attributes: u8) -> Result<()> {
        check_attributes(attributes)?;
        self.begin_write()?;
        let Located::Entry { parent, entry } = self.locate(path)? else {
            bail!(
                EINVAL,
                Detail::InvalidOption("path"),
                "the root directory has no attributes"
            );
        };
        let mut raw = entry.short;
        raw.attr = (raw.attr & !SETTABLE_ATTRIBUTES) | attributes;
        self.with_directory(parent, |parent| {
            writable(parent)?;
            parent.set_slot(entry.slot, &raw.to_bytes());
            self.save_directory(parent)
        })
    }

    /// Removes an empty directory.
    pub fn remove_dir(&mut self, path: &str) -> Result<()> {
        self.begin_write()?;
        let Located::Entry { parent, entry } = self.locate(path)? else {
            bail!(EBUSY, "the root directory cannot be removed");
        };
        if !entry.short.is_directory() {
            bail!(ENOTDIR, Detail::Path(path.to_string()), "'{}' is not a directory", path);
        }
        let child = entry.short.first_cluster;
        if !self.with_directory(child, |dir| Ok(dir.is_empty()))? {
            bail!(ENOTEMPTY, Detail::Path(path.to_string()), "'{}' is not empty", path);
        }
        // The directory goes with its clusters, and so does its cached copy.
        self.forget_directory(child);
        self.with_directory_mut(parent, |vol, parent| vol.remove_entry(parent, &entry))?;
        self.flush()
    }

    /// Removes a file.
    pub fn remove_file(&mut self, path: &str) -> Result<()> {
        self.begin_write()?;
        let Located::Entry { parent, entry } = self.locate(path)? else {
            bail!(EISDIR, Detail::Path("/".into()), "the root directory is not a file");
        };
        if entry.short.is_directory() {
            bail!(EISDIR, Detail::Path(path.to_string()), "'{}' is a directory", path);
        }
        self.with_directory_mut(parent, |vol, parent| vol.remove_entry(parent, &entry))?;
        self.flush()
    }

    /// Writes changed FAT sectors and the FSInfo sector.
    pub fn flush(&mut self) -> Result<()> {
        // Every FAT copy gets the same runs of changed sectors.
        let ss = u64::from(self.layout.sector_size);
        for (sector, bytes) in self.fat.take_dirty_runs() {
            for copy in 0..self.layout.fats {
                self.device
                    .write_at(self.layout.fat_offset(copy) + sector as u64 * ss, &bytes)?;
            }
        }
        // While a session writes, the counts on disk say "unknown"; the
        // real ones go out when it ends.
        let current = if self.writing {
            FsInfo {
                free_clusters: FSINFO_UNKNOWN,
                next_free: FSINFO_UNKNOWN,
            }
        } else {
            FsInfo {
                free_clusters: self.fat.free_count(),
                next_free: self.fat.cursor(),
            }
        };
        if self.fsinfo_on_disk != Some(current) {
            let off = u64::from(self.boot.fsinfo_sector) * u64::from(self.layout.sector_size);
            // The counters go into the structure as it is: the bytes around
            // them are reserved and some boot loaders keep their own data
            // there. A structure whose signatures are gone is replaced
            // wholesale.
            if FsInfo::parse(&self.fsinfo_raw).is_some() {
                current.patch(&mut self.fsinfo_raw);
            } else {
                self.fsinfo_raw = current.to_bytes();
            }
            self.device.write_at(off, &self.fsinfo_raw)?;
            self.fsinfo_on_disk = Some(current);
        }
        Ok(())
    }

    /// Ends the writing session, flushes and makes everything reach stable
    /// storage. The volume is clean after this until the next write.
    pub fn sync(&mut self) -> Result<()> {
        self.end_write()?;
        self.flush()?;
        self.device.sync()
    }

    /// Syncs and closes the volume.
    pub fn close(mut self) -> Result<()> {
        self.sync()
    }

    /// Closes a volume whose contents are not complete, such as one an
    /// assembly failed to fill. Everything written reaches stable storage,
    /// but the volume keeps the marks it carries while it is written, even
    /// when nothing was written since open(). Linux, EDK2 and fsck then
    /// see a volume that was not cleanly unmounted, as after a crash.
    pub fn close_unfinished(mut self) -> Result<()> {
        self.unfinished = true;
        self.begin_write()?;
        self.flush()?;
        self.device.sync()
    }
}

impl Drop for Volume {
    fn drop(&mut self) {
        // While unwinding from a panic the in-memory state is not to be
        // trusted; the dirty marks stay so that fsck looks at the volume.
        // A volume closed unfinished keeps them as well.
        if std::thread::panicking() || self.unfinished {
            return;
        }
        // Best effort: callers that care about errors use close().
        let _ = self.end_write();
        let _ = self.flush();
    }
}
