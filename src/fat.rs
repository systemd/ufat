// SPDX-License-Identifier: LGPL-2.1-or-later
//! The file allocation table, read and written through a cache of bounded
//! size.
//!
//! The FAT of a volume can be large: a byte per cluster for the first copy
//! alone would be 1 GiB at the FAT32 maximum, and the size is whatever the
//! boot sector claims. So the table is never held in memory as a whole.
//! Entries are read and written through a direct-mapped cache of FAT
//! sectors, [`CACHE_BYTES`] large by default, the way EDK2's FAT driver
//! does it. A dirty sector that is evicted is written to every FAT copy
//! first, so a sector that reached the device reached all copies at every
//! moment; the sectors still dirty in the cache are handed out as runs by
//! [`Fat::take_dirty_runs`] for the volume to write at a flush.
//!
//! When a volume is opened the first copy is scanned once, front to back,
//! for the free cluster count and for which FAT sectors hold a free entry
//! at all. Nothing of that scan is kept but the count and one bit per
//! sector. A chain is followed cluster by cluster with [`Fat::walk`] and
//! [`Fat::step`]; nothing holds a chain as a list except a directory,
//! whose length is bounded.
//!
//! Allocation follows mtools and the kernel: a cursor remembers the last
//! allocated cluster and the search for free clusters starts right after
//! it, so files written one after another on a fresh volume are laid out
//! contiguously in order. FAT sectors known to hold no free entry are
//! skipped without being read.
//!
//! The FAT copies themselves live behind [`FatStore`], which a device
//! implements in the volume and a vector in the tests and proofs.

use std::cell::RefCell;

use crate::bytes::le32;
use crate::errno::*;
use crate::layout::Layout;
use crate::Result;
use crate::{CorruptPlace, Detail, NoSpaceReason};

/// The detail of a chain that is damaged at `cluster`.
fn broken_chain(cluster: u32) -> Detail {
    Detail::Corrupt {
        place: CorruptPlace::Chain,
        field: None,
        path: None,
        cluster: Some(cluster),
    }
}

/// The bits of a FAT32 entry that carry the cluster number. The top four
/// bits are reserved and preserved when writing.
pub const ENTRY_MASK: u32 = 0x0FFF_FFFF;
/// Entries at or above this value mark the end of a chain.
pub const END_OF_CHAIN_MIN: u32 = 0x0FFF_FFF8;
/// The end of chain marker this crate writes.
pub const END_OF_CHAIN: u32 = 0x0FFF_FFFF;
/// Bit of FAT entry 1 that is set while the volume is cleanly unmounted.
pub const ENTRY1_CLEAN_SHUTDOWN: u32 = 1 << 27;
/// Marks a bad cluster.
pub const BAD_CLUSTER: u32 = 0x0FFF_FFF7;
/// A free cluster.
pub const FREE: u32 = 0;

/// Size of the sector cache unless a caller asks for another, in bytes.
/// The whole FAT of a 4 GiB volume with 4 KiB clusters fits.
pub const CACHE_BYTES: usize = 4 << 20;

/// Longest run of changed sectors handed out at once, in bytes.
const MAX_RUN: usize = 1 << 20;

/// How much of the FAT the scan at open reads at once, in bytes.
const SCAN_CHUNK: usize = 1 << 20;

/// A cache slot that holds no sector.
const EMPTY: usize = usize::MAX;

/// What a FAT entry says about its cluster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// The cluster is free.
    Free,
    /// The cluster is in use and the chain continues at this cluster.
    Next(u32),
    /// The cluster is the last one of its chain.
    End,
    /// The cluster is marked bad.
    Bad,
    /// The entry holds a value that is not a valid cluster number.
    Invalid(u32),
}

/// Where the FAT copies are. `sector` counts from the start of a copy and
/// a buffer covers as many consecutive sectors as it has bytes for.
pub trait FatStore {
    /// Reads sectors of FAT copy `copy`.
    fn read_fat(&self, copy: u32, sector: u64, buf: &mut [u8]) -> Result<()>;
    /// Writes sectors of FAT copy `copy`.
    fn write_fat(&self, copy: u32, sector: u64, buf: &[u8]) -> Result<()>;
}

/// The sectors held in memory. Direct mapped: a sector has one slot it can
/// be in, found by masking its number, so that an access is O(1) and there
/// is nothing to keep ordered.
#[derive(Debug)]
struct Cache {
    /// The sector in each slot, [`EMPTY`] when none.
    tags: Vec<usize>,
    /// Per slot: changed since it was read or last written.
    dirty: Vec<bool>,
    /// The sectors' bytes, slot after slot.
    data: Vec<u8>,
    /// Sectors that became dirty since the last [`Fat::take_dirty_runs`],
    /// in the order it happened. A sector evicted meanwhile is still
    /// listed and skipped then.
    changed: Vec<usize>,
    sector_size: usize,
    /// Sectors read from and written to the store, for the tests.
    reads: u64,
    writes: u64,
}

impl Cache {
    fn new(slots: usize, sector_size: usize) -> Cache {
        Cache {
            tags: vec![EMPTY; slots],
            dirty: vec![false; slots],
            data: vec![0u8; slots * sector_size],
            changed: Vec::new(),
            sector_size,
            reads: 0,
            writes: 0,
        }
    }

    fn slot_of(&self, sector: usize) -> usize {
        sector & (self.tags.len() - 1)
    }

    fn range(&self, slot: usize) -> std::ops::Range<usize> {
        slot * self.sector_size..(slot + 1) * self.sector_size
    }
}

/// FAT entry 0 of a volume with the media descriptor `media`: the
/// descriptor in the low byte, all other bits set.
pub fn media_entry(media: u8) -> u32 {
    0x0FFF_FF00 | u32::from(media)
}

/// The FAT, as far as it is in memory: a sector cache, the free count and
/// the allocation cursor.
#[derive(Debug)]
pub struct Fat {
    layout: Layout,
    /// FAT sectors that hold entries of existing clusters; the rest of a
    /// FAT is never read or written.
    sectors: usize,
    cache: RefCell<Cache>,
    /// One bit per FAT sector: set if it may hold a free entry, clear once
    /// a search found none. A sector gets its bit back when an entry in it
    /// is freed.
    may_have_free: BitSet,
    free: u32,
    cursor: u32,
}

/// A set of the numbers below a bound, one bit each.
#[derive(Debug)]
pub(crate) struct BitSet(Vec<u64>);

impl BitSet {
    /// An empty set for the numbers below `len`.
    pub(crate) fn new(len: usize) -> BitSet {
        BitSet(vec![0; len.div_ceil(64)])
    }

    pub(crate) fn contains(&self, n: usize) -> bool {
        self.0[n / 64] & (1 << (n % 64)) != 0
    }

    pub(crate) fn insert(&mut self, n: usize) {
        self.0[n / 64] |= 1 << (n % 64);
    }

    pub(crate) fn remove(&mut self, n: usize) {
        self.0[n / 64] &= !(1 << (n % 64));
    }
}

/// Contiguous clusters [`Fat::allocate`] handed out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent {
    /// The first cluster.
    pub first: u32,
    /// The number of clusters, at least one.
    pub count: u32,
}

/// A chain being followed, see [`Fat::walk`].
#[derive(Debug)]
pub struct Walk {
    first: u32,
    next: Option<u32>,
    steps: u64,
}

impl Fat {
    /// Number of FAT sectors that hold entries for existing clusters. A FAT
    /// may be larger than that; the rest is never read or written.
    pub fn used_sectors(layout: &Layout) -> usize {
        let needed = (u64::from(layout.fat_entries()) * 4).div_ceil(u64::from(layout.sector_size));
        needed.min(u64::from(layout.fat_sectors)) as usize
    }

    /// The first sector of the FAT of a freshly formatted volume: the two
    /// reserved entries, the root directory's end marker, zeros.
    pub fn first_sector(layout: &Layout, media: u8) -> Vec<u8> {
        let mut sector = vec![0u8; layout.sector_size as usize];
        for (i, value) in [media_entry(media), END_OF_CHAIN, END_OF_CHAIN_MIN].iter().enumerate() {
            sector[i * 4..i * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        sector
    }

    /// Opens the FAT in `store`: scans the first copy once for the free
    /// count and sets up a cache of about `cache_bytes`. `hint` is the
    /// FSInfo next-free value, used to seed the allocation cursor when it
    /// is plausible.
    pub fn open(layout: &Layout, store: &dyn FatStore, hint: u32, cache_bytes: usize) -> Result<Fat> {
        let ss = layout.sector_size as usize;
        let sectors = Self::used_sectors(layout);
        if sectors == 0 {
            bail!(
                EUCLEAN,
                Detail::Corrupt {
                    place: CorruptPlace::Fat,
                    field: Some("fatSectors"),
                    path: None,
                    cluster: None,
                },
                "the FAT has no sectors"
            );
        }
        // Slots are a power of two for the masking; no more than the FAT
        // has sectors, no fewer than one.
        let slots = (cache_bytes / ss)
            .max(1)
            .min(sectors.next_power_of_two())
            .next_power_of_two();
        let per_sector = ss / 4;
        let max = layout.max_cluster() as usize;
        let mut free = 0u32;
        let mut may_have_free = BitSet::new(sectors);
        let mut buf = vec![0u8; SCAN_CHUNK.min(sectors * ss).max(ss) / ss * ss];
        let mut sector = 0;
        while sector < sectors {
            let n = (sectors - sector).min(buf.len() / ss);
            store.read_fat(0, sector as u64, &mut buf[..n * ss])?;
            for s in 0..n {
                let first_cluster = (sector + s) * per_sector;
                let mut any = false;
                for (i, e) in buf[s * ss..(s + 1) * ss].chunks_exact(4).enumerate() {
                    let cluster = first_cluster + i;
                    if cluster < 2 || cluster > max {
                        continue;
                    }
                    if le32(e, 0) & ENTRY_MASK == FREE {
                        free += 1;
                        any = true;
                    }
                }
                if any {
                    may_have_free.insert(sector + s);
                }
            }
            sector += n;
        }
        Ok(Fat {
            layout: *layout,
            sectors,
            cache: RefCell::new(Cache::new(slots, ss)),
            may_have_free,
            free,
            cursor: if layout.valid_cluster(hint) { hint } else { 1 },
        })
    }

    /// The volume layout.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    /// Number of free clusters.
    pub fn free_count(&self) -> u32 {
        self.free
    }

    /// The last allocated cluster, stored in the FSInfo sector as the hint
    /// where to continue searching.
    pub fn cursor(&self) -> u32 {
        self.cursor
    }

    /// Sectors read from and written to the store so far.
    #[cfg(test)]
    pub(crate) fn io_counts(&self) -> (u64, u64) {
        let cache = self.cache.borrow();
        (cache.reads, cache.writes)
    }

    /// The same for the proofs.
    #[cfg(kani)]
    fn io_counts_kani(&self) -> (u64, u64) {
        let cache = self.cache.borrow();
        (cache.reads, cache.writes)
    }

    /// FAT sector and byte offset of a cluster's entry.
    fn locate(&self, cluster: u32) -> (usize, usize) {
        let offset = cluster as usize * 4;
        let ss = self.layout.sector_size as usize;
        (offset / ss, offset % ss)
    }

    /// Brings `sector` into the cache and returns its slot. A dirty sector
    /// in the way goes to every FAT copy first.
    fn load(&self, store: &dyn FatStore, sector: usize) -> Result<usize> {
        debug_assert!(sector < self.sectors);
        let mut cache = self.cache.borrow_mut();
        let slot = cache.slot_of(sector);
        if cache.tags[slot] == sector {
            return Ok(slot);
        }
        let range = cache.range(slot);
        if cache.tags[slot] != EMPTY && cache.dirty[slot] {
            let old = cache.tags[slot];
            for copy in 0..self.layout.fats {
                store.write_fat(copy, old as u64, &cache.data[range.clone()])?;
                cache.writes += 1;
            }
            cache.dirty[slot] = false;
        }
        // Nothing valid in the slot while the read is in flight.
        cache.tags[slot] = EMPTY;
        store.read_fat(0, sector as u64, &mut cache.data[range])?;
        cache.reads += 1;
        cache.tags[slot] = sector;
        Ok(slot)
    }

    /// The whole FAT entry, reserved high nibble included.
    pub(crate) fn raw_entry(&self, store: &dyn FatStore, cluster: u32) -> Result<u32> {
        let (sector, offset) = self.locate(cluster);
        let slot = self.load(store, sector)?;
        let cache = self.cache.borrow();
        let at = cache.range(slot).start + offset;
        Ok(le32(&cache.data, at))
    }

    /// The masked value of a FAT entry.
    pub(crate) fn raw(&self, store: &dyn FatStore, cluster: u32) -> Result<u32> {
        Ok(self.raw_entry(store, cluster)? & ENTRY_MASK)
    }

    /// Interprets the entry of `cluster`, which must be a valid cluster.
    pub fn get(&self, store: &dyn FatStore, cluster: u32) -> Result<Entry> {
        Ok(match self.raw(store, cluster)? {
            FREE => Entry::Free,
            BAD_CLUSTER => Entry::Bad,
            v if v >= END_OF_CHAIN_MIN => Entry::End,
            v if self.layout.valid_cluster(v) => Entry::Next(v),
            v => Entry::Invalid(v),
        })
    }

    /// Writes an entry: the whole of it when `whole`, else the cluster
    /// bits with the reserved nibble kept.
    fn write(&mut self, store: &dyn FatStore, cluster: u32, value: u32, whole: bool) -> Result<()> {
        let (sector, offset) = self.locate(cluster);
        let slot = self.load(store, sector)?;
        let mut cache = self.cache.borrow_mut();
        let at = cache.range(slot).start + offset;
        let old = le32(&cache.data, at);
        let new = if whole {
            value
        } else {
            (old & !ENTRY_MASK) | (value & ENTRY_MASK)
        };
        cache.data[at..at + 4].copy_from_slice(&new.to_le_bytes());
        if !cache.dirty[slot] {
            cache.dirty[slot] = true;
            cache.changed.push(sector);
        }
        if new & ENTRY_MASK == FREE {
            self.may_have_free.insert(sector);
        }
        Ok(())
    }

    fn set(&mut self, store: &dyn FatStore, cluster: u32, value: u32) -> Result<()> {
        debug_assert!(self.layout.valid_cluster(cluster));
        self.write(store, cluster, value, false)
    }

    /// Sets reserved entry 1 as a whole. Its top bits carry the dirty flag
    /// (bit 27 clear) and the hardware error flag (bit 26 clear) that EDK2
    /// and the specification use.
    pub(crate) fn set_entry1(&mut self, store: &dyn FatStore, value: u32) -> Result<()> {
        self.write(store, 1, value, true)
    }

    /// Starts following the chain at `first`. [`Fat::step`] yields its
    /// clusters one by one.
    pub fn walk(&self, first: u32) -> Result<Walk> {
        if !self.layout.valid_cluster(first) {
            bail!(
                EUCLEAN,
                broken_chain(first),
                "chain starts at invalid cluster {}",
                first
            );
        }
        Ok(Walk {
            first,
            next: Some(first),
            steps: 0,
        })
    }

    /// The next cluster of a chain, None after its last one. A chain that
    /// runs into a free, bad or invalid entry, or that loops, is EUCLEAN.
    pub fn step(&self, store: &dyn FatStore, walk: &mut Walk) -> Result<Option<u32>> {
        let Some(cluster) = walk.next else { return Ok(None) };
        walk.steps += 1;
        match self.get(store, cluster)? {
            Entry::End => walk.next = None,
            Entry::Next(next) => {
                if walk.steps > u64::from(self.layout.clusters) {
                    bail!(
                        EUCLEAN,
                        broken_chain(cluster),
                        "cluster chain starting at {} loops",
                        walk.first
                    );
                }
                walk.next = Some(next);
            }
            Entry::Free => bail!(
                EUCLEAN,
                broken_chain(cluster),
                "cluster chain starting at {} runs into free cluster {}",
                walk.first,
                cluster
            ),
            Entry::Bad => bail!(
                EUCLEAN,
                broken_chain(cluster),
                "cluster chain starting at {} runs into bad cluster {}",
                walk.first,
                cluster
            ),
            Entry::Invalid(v) => bail!(
                EUCLEAN,
                broken_chain(cluster),
                "cluster {} in chain starting at {} holds invalid entry 0x{:08x}",
                cluster,
                walk.first,
                v
            ),
        }
        Ok(Some(cluster))
    }

    /// The number of clusters of an intact chain. Nothing is kept.
    pub fn chain_len(&self, store: &dyn FatStore, first: u32) -> Result<u32> {
        let mut walk = self.walk(first)?;
        let mut len = 0;
        while self.step(store, &mut walk)?.is_some() {
            len += 1;
        }
        Ok(len)
    }

    /// The clusters of a chain that is at most `max` long, or `None` for a
    /// longer one, found before more than `max` clusters are held.
    pub fn chain_bounded(&self, store: &dyn FatStore, first: u32, max: usize) -> Result<Option<Vec<u32>>> {
        let mut walk = self.walk(first)?;
        let mut chain = Vec::new();
        while let Some(c) = self.step(store, &mut walk)? {
            if chain.len() == max {
                return Ok(None);
            }
            chain.push(c);
        }
        Ok(Some(chain))
    }

    fn may_have_free(&self, sector: usize) -> bool {
        self.may_have_free.contains(sector)
    }

    /// The first free cluster in `lo..=hi`, skipping the FAT sectors known
    /// to be full and remembering the ones found full on the way.
    fn find_free(&mut self, store: &dyn FatStore, lo: u32, hi: u32) -> Result<Option<u32>> {
        let per_sector = self.layout.sector_size as usize / 4;
        let mut c = lo as usize;
        while c <= hi as usize {
            let sector = c / per_sector;
            let sector_end = (sector + 1) * per_sector - 1;
            if !self.may_have_free(sector) {
                c = sector_end + 1;
                continue;
            }
            let end = sector_end.min(hi as usize);
            let slot = self.load(store, sector)?;
            let found = {
                let cache = self.cache.borrow();
                let base = cache.range(slot).start;
                (c..=end).find(|&x| le32(&cache.data, base + (x % per_sector) * 4) & ENTRY_MASK == FREE)
            };
            if let Some(x) = found {
                return Ok(Some(x as u32));
            }
            // Every cluster of the sector was looked at and none is free.
            // The first sector starts at cluster 2 and the last one ends at
            // the last cluster.
            let whole =
                c == (sector * per_sector).max(2) && (end == sector_end || end == self.layout.max_cluster() as usize);
            if whole {
                self.may_have_free.remove(sector);
            }
            c = end + 1;
        }
        Ok(None)
    }

    /// Allocates up to `max` contiguous clusters as a chain of its own,
    /// terminated with an end marker. The caller links the run to any
    /// preceding chain.
    pub fn allocate(&mut self, store: &dyn FatStore, max: u32) -> Result<Extent> {
        if max == 0 {
            bail!(EINVAL, "allocation of zero clusters");
        }
        if self.free == 0 {
            bail!(
                ENOSPC,
                Detail::NoSpace {
                    reason: NoSpaceReason::Clusters,
                    path: None,
                },
                "no free clusters left"
            );
        }
        let max_cluster = self.layout.max_cluster();
        let first = match self.find_free(store, self.cursor + 1, max_cluster)? {
            Some(c) => c,
            None => self.find_free(store, 2, self.cursor.min(max_cluster))?.ok_or_else(|| {
                err!(
                    EUCLEAN,
                    "free cluster count {} is wrong, no free cluster found",
                    self.free
                )
            })?,
        };
        let mut count = 1;
        while count < max && first + count <= max_cluster && self.raw(store, first + count)? == FREE {
            count += 1;
        }
        for c in first..first + count - 1 {
            self.set(store, c, c + 1)?;
        }
        self.set(store, first + count - 1, END_OF_CHAIN)?;
        self.free -= count;
        self.cursor = first + count - 1;
        Ok(Extent { first, count })
    }

    /// Makes `cluster` point at `next`.
    pub fn link(&mut self, store: &dyn FatStore, cluster: u32, next: u32) -> Result<()> {
        self.set(store, cluster, next)
    }

    /// Frees the chain starting at `first`. Nothing is freed if the chain
    /// is not intact: it is walked once to check and once to free.
    pub fn free_chain(&mut self, store: &dyn FatStore, first: u32) -> Result<u32> {
        let len = self.chain_len(store, first)?;
        let mut walk = self.walk(first)?;
        // step() reads the entry before it is overwritten here.
        while let Some(c) = self.step(store, &mut walk)? {
            self.set(store, c, FREE)?;
        }
        self.free += len;
        Ok(len)
    }

    /// Hands out the sectors changed since the last call that are still in
    /// the cache, as runs of consecutive sectors in ascending order, each
    /// with its bytes and at most [`MAX_RUN`] long, and marks them clean.
    /// The caller writes every run to every FAT copy; see `Volume::flush`.
    /// A changed sector evicted meanwhile has been written already. The
    /// cost is that of the changed sectors, not of the FAT.
    pub fn take_dirty_runs(&mut self) -> Vec<(usize, Vec<u8>)> {
        let mut cache = self.cache.borrow_mut();
        let ss = cache.sector_size;
        let mut changed = std::mem::take(&mut cache.changed);
        changed.sort_unstable();
        changed.dedup();
        let mut runs: Vec<(usize, Vec<u8>)> = Vec::new();
        for sector in changed {
            let slot = cache.slot_of(sector);
            if cache.tags[slot] != sector || !cache.dirty[slot] {
                continue;
            }
            cache.dirty[slot] = false;
            let bytes = &cache.data[cache.range(slot)];
            match runs.last_mut() {
                Some((start, data)) if *start + data.len() / ss == sector && data.len() < MAX_RUN => {
                    data.extend_from_slice(bytes)
                }
                _ => runs.push((sector, bytes.to_vec())),
            }
        }
        runs
    }
}

/// FAT copies in memory, for the tests and the proofs.
#[cfg(any(test, kani))]
pub(crate) struct VecStore {
    pub(crate) bytes: RefCell<Vec<u8>>,
    copy_bytes: usize,
    sector_size: usize,
}

#[cfg(any(test, kani))]
impl VecStore {
    /// Zeroed FAT copies of the size the layout says.
    pub(crate) fn new(layout: &Layout) -> VecStore {
        let copy_bytes = layout.fat_sectors as usize * layout.sector_size as usize;
        VecStore {
            bytes: RefCell::new(vec![0u8; copy_bytes * layout.fats as usize]),
            copy_bytes,
            sector_size: layout.sector_size as usize,
        }
    }

    /// Copies of a freshly formatted volume.
    pub(crate) fn fresh(layout: &Layout, media: u8) -> VecStore {
        let store = VecStore::new(layout);
        let first = Fat::first_sector(layout, media);
        for copy in 0..layout.fats {
            store.write_fat(copy, 0, &first).unwrap();
        }
        store
    }

    /// Writes one entry into every copy, as it is.
    pub(crate) fn poke(&self, cluster: u32, value: u32) {
        let mut bytes = self.bytes.borrow_mut();
        let copies = bytes.len() / self.copy_bytes;
        for copy in 0..copies {
            let at = copy * self.copy_bytes + cluster as usize * 4;
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
    }

    /// One entry of one copy.
    pub(crate) fn peek(&self, copy: u32, cluster: u32) -> u32 {
        let bytes = self.bytes.borrow();
        let at = copy as usize * self.copy_bytes + cluster as usize * 4;
        le32(&bytes, at)
    }
}

#[cfg(any(test, kani))]
impl FatStore for VecStore {
    fn read_fat(&self, copy: u32, sector: u64, buf: &mut [u8]) -> Result<()> {
        let at = copy as usize * self.copy_bytes + sector as usize * self.sector_size;
        buf.copy_from_slice(&self.bytes.borrow()[at..at + buf.len()]);
        Ok(())
    }

    fn write_fat(&self, copy: u32, sector: u64, buf: &[u8]) -> Result<()> {
        let at = copy as usize * self.copy_bytes + sector as usize * self.sector_size;
        self.bytes.borrow_mut()[at..at + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(fat_sectors: u32, clusters: u32) -> Layout {
        Layout {
            sector_size: 512,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            fat_sectors,
            total_sectors: 32 + 2 * fat_sectors + clusters,
            clusters,
        }
    }

    /// A fresh FAT of 100 clusters in one sector, with its store.
    fn fat() -> (VecStore, Fat) {
        let l = layout(1, 100);
        let store = VecStore::fresh(&l, 0xF8);
        let fat = Fat::open(&l, &store, 0, CACHE_BYTES).unwrap();
        (store, fat)
    }

    /// What Volume::flush does with the runs.
    fn flush(fat: &mut Fat, store: &VecStore) {
        for (sector, bytes) in fat.take_dirty_runs() {
            for copy in 0..fat.layout().fats {
                store.write_fat(copy, sector as u64, &bytes).unwrap();
            }
        }
    }

    #[test]
    fn fresh_state() {
        let (s, f) = fat();
        assert_eq!(f.raw(&s, 0).unwrap(), 0x0FFF_FFF8);
        assert_eq!(f.raw(&s, 1).unwrap(), END_OF_CHAIN);
        assert_eq!(f.get(&s, 2).unwrap(), Entry::End);
        assert_eq!(f.get(&s, 3).unwrap(), Entry::Free);
        assert_eq!(f.free_count(), 99);
        assert_eq!(f.chain_len(&s, 2).unwrap(), 1);
        assert_eq!(f.chain_bounded(&s, 2, 1).unwrap(), Some(vec![2]));
        assert_eq!(f.cursor(), 1);
        assert_eq!(Fat::first_sector(&layout(1, 100), 0xF8).len(), 512);
    }

    #[test]
    fn allocation_is_contiguous_and_wraps() {
        let (s, mut f) = fat();
        let Extent { first, count } = f.allocate(&s, 10).unwrap();
        assert_eq!((first, count), (3, 10));
        assert_eq!(f.chain_bounded(&s, 3, 10).unwrap(), Some((3..13).collect::<Vec<_>>()));
        assert_eq!(f.chain_bounded(&s, 3, 9).unwrap(), None);
        assert_eq!(f.free_count(), 89);
        let Extent { first, count } = f.allocate(&s, 1000).unwrap();
        assert_eq!((first, count), (13, 89));
        assert_eq!(f.free_count(), 0);
        assert_eq!(f.allocate(&s, 1).unwrap_err().errno(), ENOSPC);
        assert_eq!(f.free_chain(&s, 3).unwrap(), 10);
        assert_eq!(f.free_count(), 10);
        // The cursor is at the end, so the search wraps to the freed run.
        let Extent { first, count } = f.allocate(&s, 4).unwrap();
        assert_eq!((first, count), (3, 4));
        f.link(&s, 6, 7).unwrap();
        let Extent { first, count } = f.allocate(&s, 100).unwrap();
        assert_eq!((first, count), (7, 6));
        assert_eq!(f.chain_len(&s, 3).unwrap(), 10);
        // The store sees all of it once flushed, in both copies.
        flush(&mut f, &s);
        for copy in 0..2 {
            assert_eq!(s.peek(copy, 6), 7);
            assert_eq!(s.peek(copy, 12), END_OF_CHAIN);
            assert_eq!(s.peek(copy, 13), 14);
        }
    }

    #[test]
    fn broken_chains() {
        let (s, mut f) = fat();
        f.set(&s, 5, 6).unwrap();
        f.set(&s, 6, 5).unwrap();
        assert_eq!(f.chain_len(&s, 5).unwrap_err().errno(), EUCLEAN);
        f.set(&s, 7, 8).unwrap();
        assert!(f.chain_len(&s, 7).unwrap_err().message().contains("free cluster"));
        f.set(&s, 9, 0x0FFF_FFF0).unwrap();
        assert_eq!(f.get(&s, 9).unwrap(), Entry::Invalid(0x0FFF_FFF0));
        assert!(f.chain_len(&s, 9).is_err());
        assert!(f.walk(0).is_err());
        assert!(f.walk(102).is_err());
        f.set(&s, 10, 11).unwrap();
        f.set(&s, 11, BAD_CLUSTER).unwrap();
        assert_eq!(f.get(&s, 11).unwrap(), Entry::Bad);
        assert!(f.chain_len(&s, 10).is_err());
        // Nothing of a broken chain is freed.
        let free = f.free_count();
        assert!(f.free_chain(&s, 7).is_err());
        assert_eq!(f.free_count(), free);
        assert_eq!(f.get(&s, 7).unwrap(), Entry::Next(8));
    }

    #[test]
    fn high_nibble_is_preserved() {
        let l = layout(1, 100);
        let s = VecStore::fresh(&l, 0xF8);
        s.poke(20, 0xA000_0000);
        let mut f = Fat::open(&l, &s, 0, CACHE_BYTES).unwrap();
        f.set(&s, 20, END_OF_CHAIN).unwrap();
        assert_eq!(f.raw_entry(&s, 20).unwrap(), 0xAFFF_FFFF);
        assert_eq!(f.get(&s, 20).unwrap(), Entry::End);
        flush(&mut f, &s);
        assert_eq!(s.peek(1, 20), 0xAFFF_FFFF);
    }

    #[test]
    fn dirty_runs_come_out_sorted_and_once() {
        // Four sectors of 128 entries each.
        let l = layout(4, 500);
        let s = VecStore::fresh(&l, 0xF8);
        let mut f = Fat::open(&l, &s, 0, CACHE_BYTES).unwrap();
        assert!(f.take_dirty_runs().is_empty());
        // Changes out of order, twice in one sector: one run per group of
        // consecutive sectors, ascending, each sector once.
        f.set(&s, 400, END_OF_CHAIN).unwrap();
        f.set(&s, 5, END_OF_CHAIN).unwrap();
        f.set(&s, 130, END_OF_CHAIN).unwrap();
        f.set(&s, 6, END_OF_CHAIN).unwrap();
        let runs = f.take_dirty_runs();
        assert_eq!(
            runs.iter().map(|(s, d)| (*s, d.len())).collect::<Vec<_>>(),
            vec![(0, 1024), (3, 512)]
        );
        assert_eq!(&runs[0].1[5 * 4..6 * 4], &END_OF_CHAIN.to_le_bytes());
        assert!(f.take_dirty_runs().is_empty());
        assert!(!f.cache.borrow().dirty.iter().any(|&d| d));
    }

    #[test]
    fn long_runs_are_split() {
        // A FAT of 3000 sectors changed throughout comes out in 1 MiB runs.
        let l = layout(3000, 383_000);
        let s = VecStore::fresh(&l, 0xF8);
        let mut f = Fat::open(&l, &s, 0, CACHE_BYTES).unwrap();
        let used = Fat::used_sectors(&l);
        assert_eq!(used, 2993, "the last seven sectors hold no cluster");
        for sector in 0..used as u32 {
            f.set(&s, sector * 128 + 3, END_OF_CHAIN).unwrap();
        }
        let runs = f.take_dirty_runs();
        assert_eq!(
            runs.iter().map(|(s, d)| (*s, d.len())).collect::<Vec<_>>(),
            vec![(0, MAX_RUN), (2048, (used - 2048) * 512)]
        );
    }

    #[test]
    fn eviction_writes_back_to_every_copy() {
        // Four FAT sectors, a cache of two slots: sectors 0 and 2 share a
        // slot, as do 1 and 3.
        let l = layout(4, 500);
        let s = VecStore::fresh(&l, 0xF8);
        let mut f = Fat::open(&l, &s, 0, 1024).unwrap();
        assert_eq!(f.cache.borrow().tags.len(), 2);
        let (reads, writes) = f.io_counts();
        f.set(&s, 5, END_OF_CHAIN).unwrap(); // sector 0, dirty
        f.set(&s, 300, END_OF_CHAIN).unwrap(); // sector 2 evicts 0: written to both copies
        assert_eq!(f.io_counts(), (reads + 2, writes + 2));
        assert_eq!(s.peek(0, 5), END_OF_CHAIN);
        assert_eq!(s.peek(1, 5), END_OF_CHAIN);
        assert_eq!(s.peek(0, 300), FREE, "sector 2 is dirty in the cache only");
        // What was evicted is not handed out again.
        let runs = f.take_dirty_runs();
        assert_eq!(runs.iter().map(|(s, _)| *s).collect::<Vec<_>>(), vec![2]);
        for (sector, bytes) in runs {
            for copy in 0..2 {
                s.write_fat(copy, sector as u64, &bytes).unwrap();
            }
        }
        assert_eq!(s.peek(1, 300), END_OF_CHAIN);
        // Reading sector 0 back gives the written value.
        assert_eq!(f.get(&s, 5).unwrap(), Entry::End);
        // A clean eviction writes nothing.
        let (_, writes) = f.io_counts();
        f.get(&s, 300).unwrap();
        assert_eq!(f.io_counts().1, writes);
    }

    #[test]
    fn full_sectors_are_skipped_and_come_back() {
        // Four sectors; fill the first three completely, then allocate.
        let l = layout(4, 500);
        let s = VecStore::fresh(&l, 0xF8);
        for c in 3..384 {
            s.poke(c, END_OF_CHAIN);
        }
        let mut f = Fat::open(&l, &s, 0, CACHE_BYTES).unwrap();
        assert_eq!(f.free_count(), 500 - 382);
        // The scan at open knows which sectors hold a free entry.
        assert!(!f.may_have_free(0) && !f.may_have_free(1) && !f.may_have_free(2) && f.may_have_free(3));
        let (reads, _) = f.io_counts();
        let Extent { first, count } = f.allocate(&s, 1).unwrap();
        assert_eq!((first, count), (384, 1));
        // Only sector 3 was read for that.
        assert_eq!(f.io_counts().0, reads + 1);
        // Freeing an entry brings its sector back.
        f.free_chain(&s, 200).unwrap();
        assert!(f.may_have_free(1));
        let first = f.allocate(&s, 1).unwrap().first;
        assert_eq!(first, 385, "the cursor comes first");
        f.cursor = l.max_cluster();
        let first = f.allocate(&s, 1).unwrap().first;
        assert_eq!(first, 200, "the wrap finds the freed entry");
        // Sectors found full while searching are marked so, the first and
        // the last one included, and the mark goes when something in them
        // is freed.
        for c in 385..=l.max_cluster() {
            f.set(&s, c, END_OF_CHAIN).unwrap();
        }
        f.free = 0;
        assert_eq!(f.allocate(&s, 1).unwrap_err().errno(), ENOSPC);
        f.free = 1;
        assert_eq!(f.allocate(&s, 1).unwrap_err().errno(), EUCLEAN, "a wrong count");
        // Sector 1 was searched in two halves, from the cursor and after
        // the wrap, so it keeps its bit; the others were seen whole.
        assert!(!f.may_have_free(0) && !f.may_have_free(2) && !f.may_have_free(3));
        f.set(&s, 450, FREE).unwrap();
        assert!(f.may_have_free(3) && !f.may_have_free(2));
        assert_eq!(f.allocate(&s, 1).unwrap(), Extent { first: 450, count: 1 });
        // The store is only touched at a flush or an eviction.
        assert_eq!(s.peek(0, 384), FREE);
        flush(&mut f, &s);
        assert_eq!(s.peek(0, 384), END_OF_CHAIN);
        assert_eq!(s.peek(1, 385), END_OF_CHAIN);
        assert_eq!(s.peek(1, 450), END_OF_CHAIN);
    }
}

/// Bounded model checking harnesses for Kani, on a FAT of
/// six clusters in two sectors of four entries. The chain and nibble
/// harnesses have fully symbolic entries; the write-back harness too, and
/// it reads through one slot so that its second write, to a fixed cluster
/// in the other sector, evicts the first sector and writes it to every
/// copy. Allocation is proven on a FAT whose entries are each free or in
/// use with the pattern symbolic, through a cache holding both sectors,
/// and freeing on a fresh FAT with a chain of symbolic length: the two
/// together as one harness with fully symbolic entries, or a symbolic
/// cursor, did not finish in half an hour on 512 cores, and a twelve
/// cluster FAT in four sectors through two slots did not either.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn no_format(_: std::fmt::Arguments<'_>) -> String {
        String::new()
    }

    const CLUSTERS: u32 = 6;

    fn any_layout() -> Layout {
        Layout {
            sector_size: 16,
            sectors_per_cluster: 1,
            reserved_sectors: 32,
            fats: 2,
            fat_sectors: 2,
            total_sectors: 32 + 4 + CLUSTERS,
            clusters: CLUSTERS,
        }
    }

    /// A FAT with symbolic entries behind a cache of `slots` sectors.
    fn any_fat(slots: usize) -> (VecStore, Fat) {
        let layout = any_layout();
        let store = VecStore::fresh(&layout, 0xF8);
        for c in 2..=layout.max_cluster() {
            store.poke(c, kani::any());
        }
        let fat = Fat::open(&layout, &store, kani::any(), slots * 16).unwrap();
        (store, fat)
    }

    /// Following a chain ends or fails for every FAT content and start
    /// cluster, and never visits more clusters than there are.
    #[kani::proof]
    #[kani::unwind(12)]
    #[kani::stub(std::fmt::format, no_format)]
    fn chain_terminates_for_any_fat_content() {
        let (store, fat) = any_fat(2);
        let first: u32 = kani::any();
        if let Ok(mut walk) = fat.walk(first) {
            let mut len = 0;
            while let Ok(Some(c)) = fat.step(&store, &mut walk) {
                assert!(fat.layout.valid_cluster(c));
                len += 1;
                assert!(len <= CLUSTERS);
            }
        }
    }

    /// A FAT whose clusters are each free or in use (an end of chain), with
    /// the pattern symbolic: everything allocation looks at. The values
    /// behind in-use entries do not matter to it.
    fn any_pattern_fat(slots: usize, hint: u32) -> (VecStore, Fat) {
        let layout = any_layout();
        let store = VecStore::fresh(&layout, 0xF8);
        for c in 2..=layout.max_cluster() {
            let used: bool = kani::any();
            store.poke(c, if used { END_OF_CHAIN } else { FREE });
        }
        let fat = Fat::open(&layout, &store, hint, slots * 16).unwrap();
        (store, fat)
    }

    /// allocate() hands out clusters that were free, as a terminated chain
    /// of the length it reports, and lowers the free count by that much.
    #[kani::proof]
    #[kani::unwind(12)]
    #[kani::stub(std::fmt::format, no_format)]
    fn allocate_hands_out_free_clusters() {
        let (store, mut fat) = any_pattern_fat(2, 0);
        let before = fat.free_count();
        let max: u32 = kani::any_where(|m: &u32| *m >= 1 && *m <= CLUSTERS);
        if let Ok(Extent { first, count }) = fat.allocate(&store, max) {
            assert!(count >= 1 && count <= max);
            assert!(fat.free_count() == before - count);
            assert!(fat.chain_len(&store, first).unwrap() == count);
            for c in first..first + count {
                // The store still holds the entries as they were before.
                assert!(store.peek(0, c) & ENTRY_MASK == FREE);
            }
        } else {
            assert!(before == 0);
        }
    }

    /// free_chain() gives an intact chain back and raises the free count
    /// by its length.
    #[kani::proof]
    #[kani::unwind(12)]
    #[kani::stub(std::fmt::format, no_format)]
    fn free_chain_restores_the_free_count() {
        let layout = any_layout();
        let store = VecStore::fresh(&layout, 0xF8);
        let mut fat = Fat::open(&layout, &store, 0, 32).unwrap();
        let len: u32 = kani::any_where(|n: &u32| *n >= 1 && *n <= 3);
        for c in 2..2 + len {
            let next = if c + 1 < 2 + len { c + 1 } else { END_OF_CHAIN };
            fat.set(&store, c, next).unwrap();
        }
        let before = fat.free_count();
        assert!(fat.free_chain(&store, 2).unwrap() == len);
        assert!(fat.free_count() == before + len);
        for c in 2..2 + len {
            assert!(fat.get(&store, c).unwrap() == Entry::Free);
        }
    }

    /// The reserved high nibble of an entry survives every write.
    #[kani::proof]
    #[kani::unwind(12)]
    #[kani::stub(std::fmt::format, no_format)]
    fn high_nibble_is_preserved() {
        let (store, mut fat) = any_fat(1);
        let cluster: u32 = kani::any_where(|c: &u32| *c >= 2 && *c <= CLUSTERS + 1);
        let value: u32 = kani::any();
        let before = fat.raw_entry(&store, cluster).unwrap() & !ENTRY_MASK;
        fat.set(&store, cluster, value).unwrap();
        assert!(fat.raw_entry(&store, cluster).unwrap() & !ENTRY_MASK == before);
        assert!(fat.raw(&store, cluster).unwrap() == value & ENTRY_MASK);
    }

    /// Whatever was written, after the dirty runs went out every FAT copy
    /// holds the same bytes and they are what the cache says. The second
    /// write goes to the other sector, so with one slot it evicts the first
    /// one and writes it back on the way.
    #[kani::proof]
    #[kani::unwind(12)]
    #[kani::stub(std::fmt::format, no_format)]
    fn every_copy_holds_what_was_written() {
        let (store, mut fat) = any_fat(1);
        // Cluster 2 is in the first sector, cluster 6 in the second.
        let (a, b) = (2, 6);
        let va: u32 = kani::any();
        let vb: u32 = kani::any();
        fat.set(&store, a, va).unwrap();
        fat.set(&store, b, vb).unwrap();
        assert!(
            fat.io_counts_kani().1 == 2,
            "the first sector was written back to both copies"
        );
        assert!(store.peek(0, a) & ENTRY_MASK == va & ENTRY_MASK);
        assert!(store.peek(1, a) & ENTRY_MASK == va & ENTRY_MASK);
        for (sector, bytes) in fat.take_dirty_runs() {
            for copy in 0..2 {
                store.write_fat(copy, sector as u64, &bytes).unwrap();
            }
        }
        for c in 0..=CLUSTERS + 1 {
            let v0 = store.peek(0, c);
            assert!(v0 == store.peek(1, c));
            assert!(v0 == fat.raw_entry(&store, c).unwrap());
        }
        assert!(fat.raw(&store, b).unwrap() == vb & ENTRY_MASK);
    }
}
