// SPDX-License-Identifier: LGPL-2.1-or-later
//! Directory contents: parsing entries, matching names, placing new entries.
//!
//! A [`Directory`] is the in-memory image of a directory's clusters. The
//! volume loads it, operates on it and writes the changed clusters back.
//! Three invariants are maintained:
//!
//! - After the first unused (0x00) slot every slot is zero. A directory
//!   that violates this is read up to the marker, as Linux (since 7.2) reads
//!   it, but not written to: Linux refuses to create entries over the data
//!   behind the marker and so do we, with EUCLEAN.
//! - Deleted (0xE5) slots and orphaned long name entries are reused first
//!   fit. Deleted slots at the end of the directory are zeroed, so deleting
//!   an entry and creating it again leaves the same bytes as creating it
//!   once.
//! - A set of long name entries always immediately precedes its short entry.
//!
//! The directory keeps an index of itself: the entries by slot, the slots
//! answering to each folded name, the free runs, where the end marker is
//! and which numeric alias tails are known to be taken. Every change keeps
//! the index current, so a lookup, a placement or the choice of an alias
//! never rescans the directory: loading costs O(n) for n slots and every
//! operation after that O(log n) at most.

#[cfg(not(kani))]
use std::collections::HashMap;
use std::collections::{BTreeMap, BTreeSet};

use crate::dirent::{
    self, short_name_checksum, RawDirEntry, ATTR_LONG_NAME, ATTR_VOLUME_ID, DIR_ENTRY_SIZE, DOTDOT_NAME, DOT_NAME,
    ENTRY_DELETED, ENTRY_END,
};
use crate::errno::*;
use crate::name::{
    fold_str, join_long_name, parse_long_name_entry, short_name_to_string, valid_short_char, Alias, LongNameEntry,
};
use crate::Result;

/// Largest number of slots a directory may have: 2 MiB of entries. Linux
/// refuses to create entries beyond that and EDK2 addresses slots with 16
/// bits.
pub(crate) const MAX_SLOTS: usize = 65_536;

/// The maps of the index: hash maps with a random key, since what they hold
/// comes from the medium. Under Kani they are association lists with the
/// same interface, see [`proofs::AssocMap`].
#[cfg(not(kani))]
type Map<K, V> = HashMap<K, V>;
#[cfg(kani)]
type Map<K, V> = proofs::AssocMap<K, V>;

/// A directory entry as parsed from a directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DirEntry {
    /// The long name, if the entry has long name entries.
    pub(crate) long_name: Option<String>,
    /// The short entry.
    pub(crate) short: RawDirEntry,
    /// Slot index of the short entry.
    pub(crate) slot: usize,
    /// Number of long name slots preceding the short entry.
    pub(crate) long_slots: usize,
}

impl DirEntry {
    /// The entry's name: the long name, or the short name as text.
    pub(crate) fn name(&self) -> String {
        match &self.long_name {
            Some(n) => n.clone(),
            None => short_name_to_string(&self.short),
        }
    }

    /// Index of the first slot the entry occupies.
    pub(crate) fn first_slot(&self) -> usize {
        self.slot - self.long_slots
    }

    /// Number of slots the entry occupies.
    pub(crate) fn slot_count(&self) -> usize {
        self.long_slots + 1
    }

    /// Whether this is the "." or ".." entry of a subdirectory.
    pub(crate) fn is_dot(&self) -> bool {
        self.long_name.is_none() && (self.short.name == DOT_NAME || self.short.name == DOTDOT_NAME)
    }

    /// Whether the entry's names count when a name is looked up or placed:
    /// the dot entries and the volume label do not.
    fn is_named(&self) -> bool {
        !self.is_dot() && !self.short.is_volume_label()
    }

    /// The folded names the entry answers to: the long name if there is one,
    /// then the short name.
    fn folded_names(&self) -> Vec<Vec<u16>> {
        let mut names = Vec::with_capacity(2);
        if let Some(n) = &self.long_name {
            names.push(fold_str(n));
        }
        names.push(fold_str(&short_name_to_string(&self.short)));
        names
    }
}

/// The candidates `PREFIX~N.EXT` for all N with one number of digits: the
/// form a lossy alias takes once it gets a numeric tail. Every long name
/// whose alias has the same prefix, digit count and extension competes for
/// the same candidates, so this is what the index remembers taken tails by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TailShape {
    prefix: Vec<u8>,
    digits: u8,
    ext: Vec<u8>,
}

impl TailShape {
    /// The shape `alias` takes with a tail of `digits` digits, as
    /// [`Alias::with_tail`] builds it.
    fn of(alias: &Alias, digits: u8) -> TailShape {
        let keep = alias.base_len.min(8 - 1 - digits as usize);
        let ext_end = alias.name[8..].iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
        TailShape {
            prefix: alias.name[..keep].to_vec(),
            digits,
            ext: alias.name[8..8 + ext_end].to_vec(),
        }
    }

    /// The smallest and the largest tail with this many digits.
    fn range(&self) -> (u32, u32) {
        let min = 10u32.pow(u32::from(self.digits) - 1);
        (min, (min * 10 - 1).min(Alias::MAX_TAIL))
    }

    /// The folded name of the candidate with tail `n`, as
    /// [`short_name_to_string`] followed by [`fold_str`] renders it.
    fn candidate(&self, n: u32) -> Vec<u16> {
        let mut out: Vec<u16> = self.prefix.iter().map(|&b| u16::from(b)).collect();
        out.push(u16::from(b'~'));
        let mut digits = [0u8; 10];
        let mut count = 0;
        let mut rest = n;
        while rest > 0 {
            digits[count] = b'0' + (rest % 10) as u8;
            rest /= 10;
            count += 1;
        }
        out.extend(digits[..count].iter().rev().map(|&b| u16::from(b)));
        if !self.ext.is_empty() {
            out.push(u16::from(b'.'));
            out.extend(self.ext.iter().map(|&b| u16::from(b)));
        }
        out
    }

    /// Reads a folded name as a candidate, if it has that form.
    fn parse(folded: &[u16]) -> Option<(TailShape, u32)> {
        let bytes: Vec<u8> = folded
            .iter()
            .map(|&u| if u < 0x80 { Some(u as u8) } else { None })
            .collect::<Option<_>>()?;
        let (base, ext) = match bytes.iter().rposition(|&b| b == b'.') {
            Some(i) => (&bytes[..i], &bytes[i + 1..]),
            None => (&bytes[..], &bytes[bytes.len()..]),
        };
        if base.len() > 8 || ext.len() > 3 {
            return None;
        }
        let tilde = base.iter().rposition(|&b| b == b'~')?;
        let digits = &base[tilde + 1..];
        if digits.is_empty() || digits.len() > 6 || digits[0] == b'0' || !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let prefix = &base[..tilde];
        if !prefix.iter().chain(ext).all(|&b| valid_short_char(b)) {
            return None;
        }
        let n = digits.iter().fold(0u32, |acc, &d| acc * 10 + u32::from(d - b'0'));
        Some((
            TailShape {
                prefix: prefix.to_vec(),
                digits: digits.len() as u8,
                ext: ext.to_vec(),
            },
            n,
        ))
    }
}

/// What a directory knows about itself beyond its bytes. Built by
/// [`Directory::scan`] when the directory is loaded and kept current by
/// every change.
#[derive(Debug, Default)]
struct Index {
    /// The entries, by the slot of the short entry.
    entries: BTreeMap<usize, DirEntry>,
    /// Entries other than the dot entries.
    plain: usize,
    /// The slots, ascending, of the entries answering to a folded name, long
    /// or short. Dot entries and the volume label are left out.
    names: Map<Vec<u16>, Vec<usize>>,
    /// The free runs, by first slot: start to length. No two touch.
    holes: BTreeMap<usize, usize>,
    /// The free runs by length, then start, for first fit placement.
    by_length: BTreeMap<usize, BTreeSet<usize>>,
    /// One past the last slot whose first byte marks it in use: where the
    /// end marker is or would be.
    raw_end: usize,
    /// For each tail shape, a tail below which every candidate is taken.
    tails: Map<TailShape, u32>,
    /// A tail picked by [`Directory::short_name_for`] but not written yet,
    /// with the hint to record once it is.
    pending_tail: Option<(TailShape, u32)>,
    /// Runs set aside for entries not written yet, start to length: out of
    /// the free runs, nothing on disk. See [`Directory::reserve`].
    reserved: BTreeMap<usize, usize>,
}

impl Index {
    fn build(entries: Vec<DirEntry>, free: &[bool], raw_end: usize) -> Index {
        let mut index = Index {
            raw_end,
            ..Index::default()
        };
        let mut start = 0;
        for run in free.chunk_by(|a, b| a == b) {
            if run[0] {
                index.add_hole(start, run.len());
            }
            start += run.len();
        }
        for e in entries {
            index.insert(e);
        }
        index
    }

    fn insert(&mut self, e: DirEntry) {
        if e.is_named() {
            for n in e.folded_names() {
                let slots = self.names.entry(n).or_default();
                if let Err(at) = slots.binary_search(&e.slot) {
                    slots.insert(at, e.slot);
                }
            }
        }
        if !e.is_dot() {
            self.plain += 1;
        }
        self.entries.insert(e.slot, e);
    }

    fn remove(&mut self, slot: usize) -> Option<DirEntry> {
        let e = self.entries.remove(&slot)?;
        if e.is_named() {
            for n in e.folded_names() {
                if let Some(slots) = self.names.get_mut(&n) {
                    slots.retain(|&s| s != slot);
                    if slots.is_empty() {
                        self.names.remove(&n);
                    }
                }
                // A name that goes away may free a tail below the hint.
                if let Some((shape, tail)) = TailShape::parse(&n) {
                    if let Some(hint) = self.tails.get_mut(&shape) {
                        *hint = (*hint).min(tail);
                    }
                }
            }
        }
        if !e.is_dot() {
            self.plain -= 1;
        }
        self.pending_tail = None;
        Some(e)
    }

    fn add_hole(&mut self, start: usize, len: usize) {
        self.holes.insert(start, len);
        self.by_length.entry(len).or_default().insert(start);
    }

    fn remove_hole(&mut self, start: usize) -> usize {
        let len = self.holes.remove(&start).expect("a known hole");
        let starts = self.by_length.get_mut(&len).expect("every hole is listed by length");
        starts.remove(&start);
        if starts.is_empty() {
            self.by_length.remove(&len);
        }
        len
    }

    /// Takes `count` slots at `start` out of the free runs. False if they
    /// do not lie inside one run.
    fn occupy(&mut self, start: usize, count: usize) -> bool {
        let Some((&hs, &hl)) = self.holes.range(..=start).next_back() else {
            return false;
        };
        if hs + hl < start + count {
            return false;
        }
        self.remove_hole(hs);
        if hs < start {
            self.add_hole(hs, start - hs);
        }
        if start + count < hs + hl {
            self.add_hole(start + count, hs + hl - start - count);
        }
        true
    }

    /// Gives `count` slots at `start` back to the free runs, merging with
    /// the runs next to them.
    fn release(&mut self, mut start: usize, mut count: usize) {
        if let Some((&ps, &pl)) = self.holes.range(..start).next_back() {
            if ps + pl == start {
                self.remove_hole(ps);
                start = ps;
                count += pl;
            }
        }
        if self.holes.contains_key(&(start + count)) {
            count += self.remove_hole(start + count);
        }
        self.add_hole(start, count);
    }

    /// The first run of at least `count` free slots.
    fn first_fit(&self, count: usize) -> Option<usize> {
        self.by_length
            .range(count..)
            .filter_map(|(_, starts)| starts.first().copied())
            .min()
    }
}

/// The in-memory image of a directory.
#[derive(Debug)]
pub(crate) struct Directory {
    first_cluster: u32,
    chain: Vec<u32>,
    data: Vec<u8>,
    dirty: Vec<bool>,
    cluster_size: usize,
    damaged: bool,
    index: Index,
}

impl Directory {
    /// Wraps the clusters `chain` and their contents. Data after the first
    /// end marker is damage: it is left alone, the directory can be read up
    /// to the marker and is refused for writing, see
    /// [`Directory::is_damaged`]. Silently zeroing what might be entries is
    /// not this crate's call to make.
    pub(crate) fn new(chain: Vec<u32>, data: Vec<u8>, cluster_size: usize) -> Result<Directory> {
        if chain.is_empty() || data.len() != chain.len() * cluster_size {
            bail!(EINVAL, "directory data does not match its chain");
        }
        let damaged = match data
            .chunks_exact(DIR_ENTRY_SIZE)
            .position(|s| s[dirent::field::MARKER] == ENTRY_END)
        {
            Some(end) => data[(end + 1) * DIR_ENTRY_SIZE..].iter().any(|&b| b != 0),
            None => false,
        };
        let mut dir = Directory {
            dirty: vec![false; chain.len()],
            first_cluster: chain[0],
            chain,
            data,
            cluster_size,
            damaged,
            index: Index::default(),
        };
        dir.rebuild_index();
        Ok(dir)
    }

    /// Whether the directory holds data after its end marker. Such a
    /// directory can be read but must not be written to.
    pub(crate) fn is_damaged(&self) -> bool {
        self.damaged
    }

    /// First cluster of the directory.
    pub(crate) fn first_cluster(&self) -> u32 {
        self.first_cluster
    }

    /// The clusters of the directory, in order.
    pub(crate) fn chain(&self) -> &[u32] {
        &self.chain
    }

    /// Number of slots.
    pub(crate) fn slots(&self) -> usize {
        self.data.len() / DIR_ENTRY_SIZE
    }

    /// Size of the directory data in bytes.
    pub(crate) fn data_len(&self) -> usize {
        self.data.len()
    }

    /// The raw bytes of slot `i`.
    ///
    /// # Panics
    ///
    /// If `i` is not a slot of the directory, see [`Directory::slots`].
    pub(crate) fn slot(&self, i: usize) -> &[u8; DIR_ENTRY_SIZE] {
        self.data[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE]
            .try_into()
            .expect("slot size")
    }

    /// Whether the first byte of slot `i` marks it as in use.
    fn in_use(&self, i: usize) -> bool {
        let b = self.slot(i)[dirent::field::MARKER];
        b != ENTRY_END && b != ENTRY_DELETED
    }

    /// Writes slot `i` and keeps the end position current; the caller keeps
    /// the rest of the index current.
    fn set_slot_raw(&mut self, i: usize, bytes: &[u8; DIR_ENTRY_SIZE]) {
        let off = i * DIR_ENTRY_SIZE;
        if &self.data[off..off + DIR_ENTRY_SIZE] == bytes {
            return;
        }
        self.data[off..off + DIR_ENTRY_SIZE].copy_from_slice(bytes);
        self.dirty[off / self.cluster_size] = true;
        if self.in_use(i) {
            self.index.raw_end = self.index.raw_end.max(i + 1);
        } else if i + 1 == self.index.raw_end {
            self.index.raw_end = (0..i).rev().find(|&j| self.in_use(j)).map_or(0, |j| j + 1);
        }
    }

    /// Overwrites slot `i`. A change to the short entry of a known entry
    /// that keeps its name, as when a file gets its size or its times, is
    /// taken into the index; any other change rebuilds it.
    pub(crate) fn set_slot(&mut self, i: usize, bytes: &[u8; DIR_ENTRY_SIZE]) {
        let old = self.slot(i);
        if old == bytes {
            return;
        }
        let same_name = old[dirent::field::NAME] == bytes[dirent::field::NAME]
            && (old[dirent::field::ATTR] ^ bytes[dirent::field::ATTR]) & ATTR_VOLUME_ID == 0
            && self.index.entries.contains_key(&i);
        self.set_slot_raw(i, bytes);
        if same_name {
            self.index.entries.get_mut(&i).expect("checked above").short = RawDirEntry::from_bytes(bytes);
        } else {
            self.rebuild_index();
        }
    }

    /// The contents of cluster `index` of the chain.
    pub(crate) fn cluster_data(&self, index: usize) -> &[u8] {
        &self.data[index * self.cluster_size..(index + 1) * self.cluster_size]
    }

    /// Whether cluster `index` has unwritten changes.
    pub(crate) fn is_dirty(&self, index: usize) -> bool {
        self.dirty[index]
    }

    /// Whether any cluster has unwritten changes.
    pub(crate) fn has_dirty_clusters(&self) -> bool {
        self.dirty.iter().any(|&d| d)
    }

    /// Marks cluster `index` as written.
    pub(crate) fn mark_clean(&mut self, index: usize) {
        self.dirty[index] = false;
    }

    /// Appends a freshly allocated, zeroed cluster.
    pub(crate) fn append_cluster(&mut self, cluster: u32) {
        let old = self.slots();
        self.chain.push(cluster);
        self.data.resize(self.data.len() + self.cluster_size, 0);
        self.dirty.push(true);
        self.index.release(old, self.slots() - old);
        #[cfg(any(test, kani))]
        self.check_index();
    }

    /// Parses the directory into its entries and a map of free slots.
    fn scan(&self) -> (Vec<DirEntry>, Vec<bool>) {
        let n = self.slots();
        let mut entries = Vec::new();
        let mut free = vec![false; n];
        let mut pending: Vec<(usize, LongNameEntry)> = Vec::new();
        let orphan = |pending: &mut Vec<(usize, LongNameEntry)>, free: &mut Vec<bool>| {
            for (i, _) in pending.drain(..) {
                free[i] = true;
            }
        };
        let mut i = 0;
        while i < n {
            let raw = self.slot(i);
            if raw[dirent::field::MARKER] == ENTRY_END {
                break;
            }
            if raw[dirent::field::MARKER] == ENTRY_DELETED {
                orphan(&mut pending, &mut free);
                free[i] = true;
                i += 1;
                continue;
            }
            if let Some(l) = parse_long_name_entry(raw) {
                // Like the kernel (fs/fat/dir.c, fat_parse_long()): a slot
                // continues the set when its number and checksum fit; the
                // "last" bit on a later slot is ignored, not a break.
                let continues = match pending.last() {
                    Some((_, prev)) => l.sequence + 1 == prev.sequence && l.checksum == prev.checksum,
                    None => false,
                };
                if !continues {
                    orphan(&mut pending, &mut free);
                }
                if continues || l.last {
                    pending.push((i, l));
                } else {
                    free[i] = true;
                }
                i += 1;
                continue;
            }
            if raw[dirent::field::ATTR] == ATTR_LONG_NAME {
                // A long name slot whose sequence byte is out of range. The
                // kernel skips it (fat_parse_long() returns PARSE_INVALID);
                // it is never read as a short entry.
                orphan(&mut pending, &mut free);
                free[i] = true;
                i += 1;
                continue;
            }
            let short = RawDirEntry::from_bytes(raw);
            let mut long_name = None;
            let mut long_slots = 0;
            if let Some((_, last)) = pending.last() {
                if last.sequence == 1 && pending[0].1.checksum == short_name_checksum(&short.name) {
                    let units: Vec<LongNameEntry> = pending.iter().rev().map(|(_, l)| *l).collect();
                    long_name = Some(String::from_utf16_lossy(&join_long_name(&units)));
                    long_slots = pending.len();
                    pending.clear();
                }
            }
            orphan(&mut pending, &mut free);
            entries.push(DirEntry {
                long_name,
                short,
                slot: i,
                long_slots,
            });
            i += 1;
        }
        orphan(&mut pending, &mut free);
        for f in &mut free[i..] {
            *f = true;
        }
        (entries, free)
    }

    /// Builds the index from the bytes. Reservations survive, as long as
    /// their slots are still free.
    fn rebuild_index(&mut self) {
        let (entries, free) = self.scan();
        let raw_end = (0..self.slots()).rev().find(|&i| self.in_use(i)).map_or(0, |i| i + 1);
        let reserved = std::mem::take(&mut self.index.reserved);
        self.index = Index::build(entries, &free, raw_end);
        for (start, count) in reserved {
            if self.index.occupy(start, count) {
                self.index.reserved.insert(start, count);
            }
        }
    }

    /// Sets `count` free slots at `start` aside for an entry to be written
    /// later with [`Directory::write_entry`]: they are no longer free for
    /// placement, and nothing is written to them, so the directory on disk
    /// stays as it is until the entry is complete. False if the slots are
    /// not free.
    pub(crate) fn reserve(&mut self, start: usize, count: usize) -> bool {
        if count == 0 || !self.index.occupy(start, count) {
            return false;
        }
        self.index.reserved.insert(start, count);
        #[cfg(any(test, kani))]
        self.check_index();
        true
    }

    /// Gives a reservation back. False if there is none at `start`.
    pub(crate) fn release_reservation(&mut self, start: usize) -> bool {
        match self.index.reserved.remove(&start) {
            Some(count) => {
                self.index.release(start, count);
                #[cfg(any(test, kani))]
                self.check_index();
                true
            }
            None => false,
        }
    }

    /// Whether `count` slots at `start` are reserved.
    pub(crate) fn is_reserved(&self, start: usize, count: usize) -> bool {
        self.index.reserved.get(&start) == Some(&count)
    }

    /// Whether any slots are reserved for entries not written yet.
    #[cfg(test)]
    pub(crate) fn has_reservations(&self) -> bool {
        !self.index.reserved.is_empty()
    }

    /// The entries of the directory, in slot order. Deleted entries and
    /// orphaned long name entries are skipped.
    #[cfg(any(test, kani))]
    pub(crate) fn entries(&self) -> Vec<DirEntry> {
        self.index.entries.values().cloned().collect()
    }

    /// The entries, in slot order, without copying them.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &DirEntry> {
        self.index.entries.values()
    }

    /// The entry whose short entry is in slot `slot`.
    pub(crate) fn entry_at(&self, slot: usize) -> Option<&DirEntry> {
        self.index.entries.get(&slot)
    }

    /// The first entry, in slot order, whose long or short name folds to
    /// `folded`. The dot entries and the volume label are not considered.
    pub(crate) fn find_name(&self, folded: &[u16]) -> Option<DirEntry> {
        let slot = *self.index.names.get(folded)?.first()?;
        self.index.entries.get(&slot).cloned()
    }

    /// Whether an entry other than `except` answers to `folded`.
    pub(crate) fn name_taken(&self, folded: &[u16], except: Option<&DirEntry>) -> bool {
        self.index
            .names
            .get(folded)
            .is_some_and(|slots| slots.iter().any(|&s| except.is_none_or(|e| e.slot != s)))
    }

    /// Finds the first run of `count` free slots.
    pub(crate) fn find_free_run(&self, count: usize) -> Option<usize> {
        self.index.first_fit(count)
    }

    /// Chooses the short name for an alias that needs a numeric tail: the
    /// candidate with the smallest tail no entry answers to, as mtools and
    /// Windows choose it. Candidates below a remembered hint are known to be
    /// taken and are not tried again; the hint moves up when the entry is
    /// written and down when a name goes away. `except` is an entry about to
    /// be replaced: its names do not count, so its own tail, if it has one
    /// of this shape, is the lowest candidate worth trying below the hint.
    /// None if every tail is taken.
    pub(crate) fn short_name_for(&mut self, alias: &Alias, except: Option<&DirEntry>) -> Option<[u8; 11]> {
        let own_tail = |shape: &TailShape| {
            let e = except?;
            let (own, tail) = TailShape::parse(&fold_str(&short_name_to_string(&e.short)))?;
            (own == *shape).then_some(tail)
        };
        for digits in 1..=6u8 {
            let shape = TailShape::of(alias, digits);
            let (min, max) = shape.range();
            let mut n = min;
            if let Some(&hint) = self.index.tails.get(&shape) {
                n = n.max(own_tail(&shape).map_or(hint, |tail| hint.min(tail)));
            }
            while n <= max {
                if !self.name_taken(&shape.candidate(n), except) {
                    if except.is_none() {
                        self.index.tails.insert(shape.clone(), n);
                        self.index.pending_tail = Some((shape, n + 1));
                    }
                    return Some(alias.with_tail(n));
                }
                n += 1;
            }
            if except.is_none() {
                self.index.tails.insert(shape, max + 1);
            }
        }
        None
    }

    /// Writes an entry: its long name slots followed by the short entry,
    /// starting at `start`. The caller has found the free run.
    pub(crate) fn write_entry(&mut self, start: usize, long: &[[u8; DIR_ENTRY_SIZE]], short: &RawDirEntry) {
        // The long name entries were made for this short entry; read them
        // back the way scan() will.
        let checksum = short_name_checksum(&short.name);
        let mut units: Vec<LongNameEntry> = Vec::with_capacity(long.len());
        let mut well_formed = true;
        for (i, raw) in long.iter().enumerate() {
            match parse_long_name_entry(raw) {
                Some(l) if l.sequence as usize == long.len() - i && l.checksum == checksum && (i > 0 || l.last) => {
                    units.push(l)
                }
                _ => well_formed = false,
            }
        }
        let count = long.len() + 1;
        let placed = well_formed
            && if self.index.reserved.get(&start) == Some(&count) {
                self.index.reserved.remove(&start);
                true
            } else {
                self.index.occupy(start, count)
            };
        // Slots in front of the entry that still read as the end of the
        // directory would hide it: a run reserved for an entry not written
        // yet. Mark them deleted; the entry they wait for overwrites them.
        for i in self.index.raw_end..start {
            if self.slot(i)[dirent::field::MARKER] == ENTRY_END {
                let mut raw = *self.slot(i);
                raw[dirent::field::MARKER] = ENTRY_DELETED;
                self.set_slot_raw(i, &raw);
            }
        }
        for (i, slot) in long.iter().enumerate() {
            self.set_slot_raw(start + i, slot);
        }
        self.set_slot_raw(start + long.len(), &short.to_bytes());
        if !placed {
            self.rebuild_index();
            return;
        }
        units.reverse();
        let long_name = (!long.is_empty()).then(|| String::from_utf16_lossy(&join_long_name(&units)));
        if let Some((shape, next)) = self.index.pending_tail.take() {
            if fold_str(&short_name_to_string(short)) == shape.candidate(next - 1) {
                self.index.tails.insert(shape, next);
            }
        }
        self.index.insert(DirEntry {
            long_name,
            short: *short,
            slot: start + long.len(),
            long_slots: long.len(),
        });
        #[cfg(any(test, kani))]
        self.check_index();
    }

    /// Deletes an entry and all of its long name slots. Deleted slots at the
    /// end of the directory are zeroed.
    pub(crate) fn delete(&mut self, entry: &DirEntry) {
        for i in entry.first_slot()..=entry.slot {
            let mut raw = *self.slot(i);
            raw[dirent::field::MARKER] = ENTRY_DELETED;
            self.set_slot_raw(i, &raw);
        }
        match self.index.remove(entry.slot) {
            Some(e) if e.first_slot() == entry.first_slot() => {
                self.index.release(entry.first_slot(), entry.slot_count())
            }
            _ => self.rebuild_index(),
        }
        for i in self.index.raw_end..self.slots() {
            if self.slot(i)[dirent::field::MARKER] == ENTRY_END {
                break;
            }
            self.set_slot_raw(i, &[0u8; DIR_ENTRY_SIZE]);
        }
        #[cfg(any(test, kani))]
        self.check_index();
    }

    /// One past the last slot in use: where the end marker is or would be.
    /// Deleted slots right before it count as free.
    pub(crate) fn end(&self) -> usize {
        self.index.raw_end
    }

    /// Whether the directory holds anything besides "." and "..", counting
    /// the entries being written as well.
    pub(crate) fn is_empty(&self) -> bool {
        self.index.plain == 0 && self.index.reserved.is_empty()
    }

    /// Compares the index with a fresh scan.
    #[cfg(any(test, kani))]
    fn check_index(&self) {
        let (entries, free) = self.scan();
        let kept: Vec<DirEntry> = self.index.entries.values().cloned().collect();
        assert_eq!(kept, entries, "the entries diverged from the bytes");
        let mut holes = vec![false; self.slots()];
        let mut listed = 0;
        let mut previous_end = None;
        for (&start, &len) in &self.index.holes {
            assert!(
                len > 0 && previous_end.is_none_or(|end| end < start),
                "holes touch or are empty"
            );
            previous_end = Some(start + len);
            for f in &mut holes[start..start + len] {
                *f = true;
            }
            assert!(self.index.by_length[&len].contains(&start));
            listed += 1;
        }
        for (&start, &len) in &self.index.reserved {
            for f in &mut holes[start..start + len] {
                assert!(!*f, "a reservation overlaps a free run");
                *f = true;
            }
        }
        assert_eq!(holes, free, "the free runs and reservations diverged from the bytes");
        assert_eq!(self.index.by_length.values().map(BTreeSet::len).sum::<usize>(), listed);
        let raw_end = (0..self.slots()).rev().find(|&i| self.in_use(i)).map_or(0, |i| i + 1);
        assert_eq!(self.index.raw_end, raw_end, "the end position diverged");
        assert_eq!(self.index.plain, entries.iter().filter(|e| !e.is_dot()).count());
        let mut names: Map<Vec<u16>, Vec<usize>> = Map::new();
        for e in entries.iter().filter(|e| e.is_named()) {
            for n in e.folded_names() {
                let slots = names.entry(n).or_default();
                if !slots.contains(&e.slot) {
                    slots.push(e.slot);
                }
            }
        }
        assert_eq!(self.index.names, names, "the name table diverged");
        for (shape, &hint) in &self.index.tails {
            let (min, _) = shape.range();
            for n in min..hint {
                assert!(
                    names.contains_key(&shape.candidate(n)),
                    "tail {} of {:?} is below the hint but free",
                    n,
                    shape
                );
            }
        }
    }
}

#[cfg(kani)]
mod proofs {
    //! The Kani harness for the index and what it needs, see
    //! HACKING.md.
    use super::*;
    use crate::dirent::ATTR_ARCHIVE;
    use std::borrow::Borrow;

    /// A map as an association list, in place of the index's hash maps.
    /// `RandomState` seeds itself from getrandom(2), which the model checker
    /// cannot call, so a harness never gets past constructing a `HashMap`;
    /// one with a fixed hasher did not solve a single insert and two lookups
    /// within five minutes. A linear search over a handful of pairs is what
    /// the solver digests, and the index logic on top is the same.
    #[derive(Debug)]
    pub(super) struct AssocMap<K, V>(Vec<(K, V)>);

    impl<K, V> Default for AssocMap<K, V> {
        fn default() -> Self {
            AssocMap(Vec::new())
        }
    }

    impl<K: Eq, V> AssocMap<K, V> {
        pub(super) fn new() -> Self {
            Self::default()
        }

        fn position<Q: ?Sized + Eq>(&self, k: &Q) -> Option<usize>
        where
            K: Borrow<Q>,
        {
            self.0.iter().position(|(key, _)| key.borrow() == k)
        }

        pub(super) fn get<Q: ?Sized + Eq>(&self, k: &Q) -> Option<&V>
        where
            K: Borrow<Q>,
        {
            self.position(k).map(|i| &self.0[i].1)
        }

        pub(super) fn get_mut<Q: ?Sized + Eq>(&mut self, k: &Q) -> Option<&mut V>
        where
            K: Borrow<Q>,
        {
            self.position(k).map(|i| &mut self.0[i].1)
        }

        pub(super) fn contains_key<Q: ?Sized + Eq>(&self, k: &Q) -> bool
        where
            K: Borrow<Q>,
        {
            self.position(k).is_some()
        }

        pub(super) fn insert(&mut self, k: K, v: V) -> Option<V> {
            match self.position(&k) {
                Some(i) => Some(std::mem::replace(&mut self.0[i].1, v)),
                None => {
                    self.0.push((k, v));
                    None
                }
            }
        }

        pub(super) fn remove<Q: ?Sized + Eq>(&mut self, k: &Q) -> Option<V>
        where
            K: Borrow<Q>,
        {
            self.position(k).map(|i| self.0.swap_remove(i).1)
        }

        pub(super) fn entry(&mut self, key: K) -> Entry<'_, K, V> {
            Entry { map: self, key }
        }
    }

    pub(super) struct Entry<'a, K, V> {
        map: &'a mut AssocMap<K, V>,
        key: K,
    }

    impl<'a, K: Eq, V: Default> Entry<'a, K, V> {
        pub(super) fn or_default(self) -> &'a mut V {
            let i = match self.map.position(&self.key) {
                Some(i) => i,
                None => {
                    self.map.0.push((self.key, V::default()));
                    self.map.0.len() - 1
                }
            };
            &mut self.map.0[i].1
        }
    }

    impl<K: Eq, V: PartialEq> PartialEq for AssocMap<K, V> {
        fn eq(&self, other: &Self) -> bool {
            self.0.len() == other.0.len() && self.0.iter().all(|(k, v)| other.get(k) == Some(v))
        }
    }

    fn pair<K, V>(p: &(K, V)) -> (&K, &V) {
        (&p.0, &p.1)
    }

    impl<'a, K, V> IntoIterator for &'a AssocMap<K, V> {
        type Item = (&'a K, &'a V);
        type IntoIter = std::iter::Map<std::slice::Iter<'a, (K, V)>, fn(&'a (K, V)) -> (&'a K, &'a V)>;
        fn into_iter(self) -> Self::IntoIter {
            self.0.iter().map(pair as fn(&'a (K, V)) -> (&'a K, &'a V))
        }
    }

    /// ASCII case folding in place of `name::fold_str`: the Unicode tables
    /// are what the solver cannot digest. Every name the harness builds is
    /// ASCII, and on ASCII this is `fold_str`.
    fn ascii_fold(s: &str) -> Vec<u16> {
        s.chars().map(|c| c.to_ascii_uppercase() as u16).collect()
    }

    /// `String::from_utf16_lossy` for units below 0x80, '?' for the rest.
    fn narrow_lossy(units: &[u16]) -> String {
        units
            .iter()
            .map(|&u| if u < 0x80 { u as u8 as char } else { '?' })
            .collect()
    }

    const SLOTS: usize = 4;

    /// A directory of four slots in one cluster, with concrete slot kinds
    /// and symbolic contents: a long name slot, a short entry, a slot that
    /// is a second short entry or deleted, and the end marker. The long
    /// name slot's sequence byte and checksum are symbolic too, so it is
    /// the start of a set, an orphan or the slot the kernel skips.
    fn shaped_directory() -> Directory {
        let mut data = vec![0u8; SLOTS * DIR_ENTRY_SIZE];
        let lfn: [u8; DIR_ENTRY_SIZE] = kani::any();
        kani::assume(lfn[dirent::field::MARKER] != ENTRY_END && lfn[dirent::field::MARKER] != ENTRY_DELETED);
        data[..DIR_ENTRY_SIZE].copy_from_slice(&lfn);
        data[11] = ATTR_LONG_NAME;
        let short: [u8; DIR_ENTRY_SIZE] = kani::any();
        kani::assume(
            short[dirent::field::MARKER] != ENTRY_END
                && short[dirent::field::MARKER] != ENTRY_DELETED
                && short[dirent::field::ATTR] != ATTR_LONG_NAME,
        );
        data[DIR_ENTRY_SIZE..2 * DIR_ENTRY_SIZE].copy_from_slice(&short);
        let third: [u8; DIR_ENTRY_SIZE] = kani::any();
        kani::assume(third[dirent::field::MARKER] != ENTRY_END && third[dirent::field::ATTR] != ATTR_LONG_NAME);
        data[2 * DIR_ENTRY_SIZE..3 * DIR_ENTRY_SIZE].copy_from_slice(&third);
        Directory::new(vec![2], data, SLOTS * DIR_ENTRY_SIZE).unwrap()
    }

    /// A legal 8.3 name with symbolic letters.
    fn any_short_name() -> [u8; 11] {
        let name: [u8; 11] = kani::any();
        kani::assume(
            name.iter()
                .all(|&b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' '),
        );
        kani::assume(name[0] != b' ');
        name
    }

    /// The index agrees with the bytes after loading the shaped directory,
    /// after writing a short entry into the first fit, after deleting an
    /// entry chosen symbolically and after writing into the slots that
    /// freed: write_entry() and delete() check it themselves under Kani.
    /// The unwind bound covers the longest loops, the 13 units of a long
    /// name slot and the 16 byte table of `valid_short_char`. The solver
    /// did not finish this within the time verify/run.sh gives it, so it
    /// runs with `DIR=1 verify/run.sh` only; see HACKING.md.
    #[cfg(dir_proofs)]
    #[kani::proof]
    #[kani::unwind(20)]
    #[kani::stub(crate::name::fold_str, ascii_fold)]
    #[kani::stub(std::string::String::from_utf16_lossy, narrow_lossy)]
    fn index_follows_writes_and_deletes() {
        let mut d = shaped_directory();
        d.check_index();
        let short = RawDirEntry {
            name: any_short_name(),
            attr: ATTR_ARCHIVE,
            ..RawDirEntry::default()
        };
        if let Some(start) = d.find_free_run(1) {
            d.write_entry(start, &[], &short);
            assert!(d.entry_at(start).is_some_and(|e| e.short.name == short.name));
            kani::cover!(true, "an entry was written");
        }
        let entries = d.entries();
        if !entries.is_empty() {
            let which: usize = kani::any();
            kani::assume(which < entries.len());
            d.delete(&entries[which]);
            assert!(d.entry_at(entries[which].slot).is_none());
            kani::cover!(true, "an entry was deleted");
            if let Some(start) = d.find_free_run(1) {
                d.write_entry(start, &[], &short);
                kani::cover!(true, "the freed slots were written");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirent::{ATTR_ARCHIVE, ATTR_DIRECTORY};
    use crate::name::{long_name_entries, LongName};

    fn dir() -> Directory {
        Directory::new(vec![2], vec![0u8; 512], 512).unwrap()
    }

    fn find(d: &Directory, name: &str) -> Option<DirEntry> {
        d.find_name(&fold_str(name))
    }

    fn short(name: &[u8; 11], attr: u8) -> RawDirEntry {
        RawDirEntry {
            name: *name,
            attr,
            ..RawDirEntry::default()
        }
    }

    /// Places `name` the way the volume does and returns its short name.
    fn create(d: &mut Directory, name: &str) -> [u8; 11] {
        let long_name = LongName::new(name).unwrap();
        assert!(!d.name_taken(&long_name.folded(), None), "{} exists", name);
        let alias = Alias::of(&long_name);
        let short_name = if alias.lossy {
            d.short_name_for(&alias, None).unwrap()
        } else {
            alias.name
        };
        let lfn = if alias.needs_long_name {
            long_name_entries(&long_name, short_name_checksum(&short_name))
        } else {
            Vec::new()
        };
        let start = loop {
            match d.find_free_run(lfn.len() + 1) {
                Some(s) => break s,
                None => {
                    let next = d.chain().last().unwrap() + 1;
                    d.append_cluster(next);
                }
            }
        };
        let mut s = short(&short_name, ATTR_ARCHIVE);
        s.nt_flags = alias.case_flags;
        d.write_entry(start, &lfn, &s);
        short_name
    }

    #[test]
    fn insert_find_delete() {
        let mut d = dir();
        assert_eq!(d.slots(), 16);
        assert_eq!(d.find_free_run(3), Some(0));
        let name = LongName::new("Readme.txt").unwrap();
        let s = short(b"README  TXT", ATTR_ARCHIVE);
        let lfn = long_name_entries(&name, short_name_checksum(&s.name));
        d.write_entry(0, &lfn, &s);
        d.write_entry(2, &[], &short(b"BOOT       ", ATTR_DIRECTORY));
        assert!(d.is_dirty(0));
        let e = d.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].name(), "Readme.txt");
        assert_eq!((e[0].slot, e[0].long_slots), (1, 1));
        assert_eq!(e[1].name(), "BOOT");
        assert!(find(&d, "readme.TXT").is_some());
        assert!(find(&d, "README.TXT").is_some());
        assert!(find(&d, "boot").is_some());
        assert!(find(&d, "other").is_none());
        assert_eq!(d.entry_at(2).map(DirEntry::name), Some("BOOT".to_string()));
        assert!(d.entry_at(1).is_some() && d.entry_at(0).is_none());
        assert_eq!(d.find_free_run(1), Some(3));
        assert_eq!(d.find_free_run(14), None);

        // Deleting the first entry leaves 0xE5 slots that are reused first.
        d.delete(&e[0]);
        assert_eq!(d.slot(0)[dirent::field::MARKER], ENTRY_DELETED);
        assert!(find(&d, "readme.txt").is_none());
        assert_eq!(d.find_free_run(2), Some(0));
        assert_eq!(d.find_free_run(3), Some(3));
        // Deleting the last entry zeroes everything up to the end marker.
        d.delete(&e[1]);
        assert!(d.data.iter().all(|&b| b == 0));
        assert!(d.is_empty());
    }

    #[test]
    fn garbage_after_end_marker_is_remembered() {
        let mut data = vec![0u8; 1024];
        data[..DIR_ENTRY_SIZE].copy_from_slice(&short(b"A          ", ATTR_ARCHIVE).to_bytes());
        data[700] = 1;
        let d = Directory::new(vec![2, 3], data.clone(), 512).unwrap();
        assert!(d.is_damaged());
        assert_eq!(d.entries().len(), 1);
        data[700] = 0;
        assert!(!Directory::new(vec![2, 3], data, 512).unwrap().is_damaged());
    }

    #[test]
    fn labels_and_dots_do_not_block_names() {
        let mut d = dir();
        d.write_entry(0, &[], &short(b"ESP        ", ATTR_VOLUME_ID));
        d.write_entry(1, &[], &short(b".          ", ATTR_DIRECTORY));
        d.write_entry(2, &[], &short(b"FILE       ", ATTR_ARCHIVE));
        assert!(d.name_taken(&fold_str("file"), None));
        assert!(!d.name_taken(&fold_str("file"), Some(&d.entries()[2])));
        assert!(!d.name_taken(&fold_str("esp"), None));
        assert!(find(&d, "esp").is_none() && find(&d, ".").is_none());
        assert!(!d.is_empty());
    }

    #[test]
    fn orphaned_long_entries_are_free() {
        let mut d = dir();
        let name = LongName::new("Some Long Name.txt").unwrap();
        let s = short(b"SOMELO~1TXT", ATTR_ARCHIVE);
        let lfn = long_name_entries(&name, short_name_checksum(&s.name));
        assert_eq!(lfn.len(), 2);
        d.write_entry(0, &lfn, &s);
        assert_eq!(d.entries()[0].long_slots, 2);
        // Corrupt the checksum: the long name is dropped, its slots are free.
        let mut s2 = s;
        s2.name = *b"OTHER   TXT";
        d.set_slot(2, &s2.to_bytes());
        let e = d.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].long_name, None);
        assert_eq!(e[0].name(), "OTHER.TXT");
        assert!(find(&d, "some long name.txt").is_none() && find(&d, "other.txt").is_some());
        assert_eq!(d.find_free_run(2), Some(0));
        // A lone long name entry that is not the last of its set is free as
        // well, and so is a deleted slot between it and the short entry.
        d.set_slot(0, &lfn[1]);
        let mut deleted = lfn[0];
        deleted[dirent::field::MARKER] = ENTRY_DELETED;
        d.set_slot(1, &deleted);
        let e = d.entries();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].long_slots, 0);
        assert_eq!(d.find_free_run(2), Some(0));
        d.check_index();
    }

    #[test]
    fn a_long_name_slot_with_a_bad_sequence_byte_is_an_orphan() {
        let mut d = dir();
        let name = LongName::new("Some Long Name.txt").unwrap();
        let s = short(b"SOMELO~1TXT", ATTR_ARCHIVE);
        let lfn = long_name_entries(&name, short_name_checksum(&s.name));
        d.write_entry(0, &lfn, &s);
        d.write_entry(3, &[], &short(b"OTHER   TXT", ATTR_ARCHIVE));
        // Sequence 31 with the last bit, a set 0x80 bit and sequence 0:
        // none of them is a long name entry, none of them a short one.
        for bad in [0x40 | 31, 0x81, 0x40] {
            let mut slot = lfn[0];
            slot[0] = bad;
            d.set_slot(0, &slot);
            let e = d.entries();
            assert_eq!(e.len(), 2, "{:#x}: {:?}", bad, e);
            assert_eq!(e[0].long_name, None);
            assert_eq!(e[0].name(), "SOMELO~1.TXT");
            assert_eq!(e[1].name(), "OTHER.TXT");
            assert_eq!(d.find_free_run(2), Some(0));
            assert!(d.iter().all(|e| !e.short.is_long_name()));
            d.check_index();
        }
        // The same byte in the slot right before the short entry.
        d.set_slot(0, &lfn[0]);
        let mut slot = lfn[1];
        slot[0] = 0x81;
        d.set_slot(1, &slot);
        let e = d.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].long_name, None);
        assert_eq!(d.find_free_run(2), Some(0));
        d.check_index();
    }

    #[test]
    fn dot_entries() {
        let mut d = dir();
        d.write_entry(0, &[], &short(b".          ", ATTR_DIRECTORY));
        d.write_entry(1, &[], &short(b"..         ", ATTR_DIRECTORY));
        let e = d.entries();
        assert!(e[0].is_dot() && e[1].is_dot());
        assert!(d.is_empty());
        d.write_entry(2, &[], &short(b"X          ", ATTR_ARCHIVE));
        assert!(!d.is_empty());
    }

    #[test]
    fn size_and_times_keep_the_index() {
        let mut d = dir();
        create(&mut d, "Readme.txt");
        let e = d.entries().remove(0);
        let mut raw = e.short;
        raw.size = 1234;
        raw.first_cluster = 7;
        d.set_slot(e.slot, &raw.to_bytes());
        let e = d.entries().remove(0);
        assert_eq!(
            (e.short.size, e.short.first_cluster, e.name().as_str()),
            (1234, 7, "Readme.txt")
        );
        d.check_index();
    }

    #[test]
    fn first_fit_reuses_the_smallest_hole_first() {
        let mut d = Directory::new(vec![2, 3], vec![0u8; 1024], 512).unwrap();
        for i in 0..6 {
            create(&mut d, &format!("plain{}", i));
        }
        let e = d.entries();
        d.delete(&e[1]);
        d.delete(&e[3]);
        d.delete(&e[4]);
        // Holes: slot 1 (one slot) and slots 3-4 (two slots), then the tail.
        assert_eq!(d.find_free_run(1), Some(1));
        assert_eq!(d.find_free_run(2), Some(3));
        assert_eq!(d.find_free_run(3), Some(6));
        create(&mut d, "A Long.txt");
        assert_eq!(find(&d, "a long.txt").unwrap().first_slot(), 3);
        assert_eq!(d.find_free_run(1), Some(1));
        assert_eq!(d.find_free_run(2), Some(6));
        // A hole merges with the tail when the entry before it goes.
        d.delete(&find(&d, "plain5").unwrap());
        assert_eq!(d.find_free_run(27), Some(5));
        assert!(d.find_free_run(28).is_none());
        d.append_cluster(4);
        assert_eq!(d.find_free_run(43), Some(5));
    }

    #[test]
    fn tails_count_up_and_come_back() {
        let mut d = Directory::new(vec![2, 3, 4, 5], vec![0u8; 2048], 512).unwrap();
        for n in 1..=12 {
            let s = create(&mut d, &format!("linux-6.12.{}-200.fc41.x86_64.efi", n));
            let text = short_name_to_string(&RawDirEntry {
                name: s,
                ..RawDirEntry::default()
            });
            // The base gives way to the tail: six characters fit before
            // "~1", five before "~10".
            let expected = if n < 10 {
                format!("LINUX-~{}.EFI", n)
            } else {
                format!("LINUX~{}.EFI", n)
            };
            assert_eq!(text, expected);
        }
        // Freeing a tail in the middle hands it out again first.
        let fourth = find(&d, "linux-6.12.4-200.fc41.x86_64.efi").unwrap();
        d.delete(&fourth);
        let s = create(&mut d, "linux-6.13.0-100.fc42.x86_64.efi");
        assert_eq!(&s[..8], b"LINUX-~4");
        // A plain name that looks like a candidate takes that tail.
        create(&mut d, "linux~13.efi");
        let s = create(&mut d, "linux-6.14.0-100.fc42.x86_64.efi");
        assert_eq!(&s[..8], b"LINUX~14");
        // A name of another shape is not affected.
        let s = create(&mut d, "linux-6.14.0-100.fc42.x86_64.conf");
        assert_eq!(&s[..8], b"LINUX-~1");
        d.check_index();
    }

    #[test]
    fn replacing_an_entry_may_reuse_its_tail() {
        let mut d = dir();
        create(&mut d, "Some Long Name.txt");
        create(&mut d, "Some Long Name 2.txt");
        let first = find(&d, "some long name.txt").unwrap();
        let alias = Alias::of(&LongName::new("Some Long Name.txt").unwrap());
        assert_eq!(&d.short_name_for(&alias, Some(&first)).unwrap()[..8], b"SOMELO~1");
        assert_eq!(&d.short_name_for(&alias, None).unwrap()[..8], b"SOMELO~3");
        // The pick is not written, so the next pick is the same.
        assert_eq!(&d.short_name_for(&alias, None).unwrap()[..8], b"SOMELO~3");
        d.check_index();
        // With many tails taken the hint says where to start, also for a
        // replacement: the smallest tail nobody else has, not always its own.
        for i in 3..60 {
            create(&mut d, &format!("Some Long Name {}.txt", i));
        }
        let fortieth = find(&d, "some long name 40.txt").unwrap();
        assert_eq!(&fortieth.short.name[..8], b"SOMEL~40");
        assert_eq!(&d.short_name_for(&alias, Some(&fortieth)).unwrap()[..8], b"SOMEL~40");
        d.delete(&find(&d, "some long name 7.txt").unwrap());
        assert_eq!(&d.short_name_for(&alias, Some(&fortieth)).unwrap()[..8], b"SOMELO~7");
        assert_eq!(&d.short_name_for(&alias, None).unwrap()[..8], b"SOMELO~7");
        d.check_index();
    }

    #[test]
    fn tail_shapes() {
        let (shape, n) = TailShape::parse(&fold_str("LONGF~12.TXT")).unwrap();
        assert_eq!(
            (shape.prefix.as_slice(), shape.digits, shape.ext.as_slice(), n),
            (&b"LONGF"[..], 2, &b"TXT"[..], 12)
        );
        assert_eq!(shape.candidate(12), fold_str("LONGF~12.TXT"));
        assert_eq!(shape.range(), (10, 99));
        let (shape, n) = TailShape::parse(&fold_str("A~1")).unwrap();
        assert_eq!((shape.prefix.as_slice(), n), (&b"A"[..], 1));
        assert_eq!(shape.candidate(1), fold_str("A~1"));
        for bad in [
            "LONGFILE.TXT",
            "LONG~01.TXT",
            "LONGFI~1.TEXT",
            "LONGFILE~1.TXT",
            "L~1234567",
            "a~1.tx+",
            "Ü~1",
        ] {
            assert!(TailShape::parse(&fold_str(bad)).is_none(), "{}", bad);
        }
        let alias = Alias::of(&LongName::new("linux-6.12.1-200.fc41.x86_64.efi").unwrap());
        assert_eq!(TailShape::of(&alias, 1).candidate(1), fold_str("LINUX-~1.EFI"));
        assert_eq!(TailShape::of(&alias, 3).candidate(100), fold_str("LINU~100.EFI"));
    }

    #[test]
    fn reservations_hold_slots_without_writing() {
        let mut d = dir();
        create(&mut d, "first");
        d.mark_clean(0);
        let before = d.data.clone();
        assert!(d.reserve(1, 3));
        assert!(!d.reserve(2, 1), "the slots are taken");
        assert!(d.is_reserved(1, 3) && !d.is_reserved(1, 2));
        assert_eq!(d.find_free_run(1), Some(4));
        assert_eq!(d.data, before, "a reservation writes nothing");
        assert!(!d.is_dirty(0), "a reservation dirties nothing");
        assert!(!d.is_empty());
        // The entry lands in its reserved slots.
        let name = LongName::new("Some Long Name.txt").unwrap();
        let s = short(b"SOMELO~1TXT", ATTR_ARCHIVE);
        let lfn = long_name_entries(&name, short_name_checksum(&s.name));
        assert_eq!(lfn.len(), 2);
        d.write_entry(1, &lfn, &s);
        assert!(!d.is_reserved(1, 3) && !d.has_reservations());
        assert_eq!(find(&d, "some long name.txt").unwrap().first_slot(), 1);
        // A reservation given back is free again, and a rebuild keeps the
        // ones that are not.
        assert!(d.reserve(4, 2));
        assert!(d.reserve(6, 1));
        d.set_slot(0, &short(b"OTHER      ", ATTR_ARCHIVE).to_bytes());
        assert!(d.is_reserved(4, 2) && d.is_reserved(6, 1));
        assert!(d.release_reservation(4));
        assert!(!d.release_reservation(4));
        assert_eq!(d.find_free_run(2), Some(4));
        assert_eq!(d.find_free_run(3), Some(7));
    }

    #[test]
    fn many_entries_stay_consistent() {
        let mut d = Directory::new(vec![2], vec![0u8; 4096], 4096).unwrap();
        for i in 0..300 {
            create(&mut d, &format!("Entry number {}.conf", i));
        }
        assert_eq!(d.entries().len(), 300);
        for i in (0..300).step_by(3) {
            let e = find(&d, &format!("entry number {}.conf", i)).unwrap();
            d.delete(&e);
        }
        assert_eq!(d.entries().len(), 200);
        for i in 0..100 {
            create(&mut d, &format!("Entry number {}.conf", 300 + i));
        }
        assert_eq!(d.entries().len(), 300);
        assert!(find(&d, "ENTRY NUMBER 3.CONF").is_none());
        assert!(find(&d, "entry number 4.conf").is_some());
        assert!(find(&d, "entry number 399.conf").is_some());
    }
}
