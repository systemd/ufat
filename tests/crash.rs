// SPDX-License-Identifier: LGPL-2.1-or-later
//! Crash consistency of the volume's write sequence. A scenario runs
//! against a traced device with durable mode on; the trace is then replayed
//! into every state a crash can leave behind under the three storage models
//! described in HACKING.md, and each state is checked: `fsck` finds
//! nothing a crash does not explain, every file is old, new or absent and
//! never damaged, directories hold the expected names only, and no cluster
//! is lost that no file ever owned.
//!
//! The generators follow ALICE: every prefix of the trace (model A), every
//! prefix with its last write torn at a sector boundary (model B), and
//! within one fsync epoch every pair dropped and every subset (model C).
//! Runs with `meson test` against a library built with `--cfg ufat_trace`.

mod common;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::ops::Range;
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::Temp;
use ufat::boot::BootSector;
use ufat::device::{Access, Device};
use ufat::dirent::{short_name_checksum, RawDirEntry, ATTR_ARCHIVE, DIR_ENTRY_SIZE, ENTRY_DELETED, ENTRY_END};
use ufat::fat::{Entry, Fat, BAD_CLUSTER, END_OF_CHAIN_MIN, ENTRY_MASK, FREE};
use ufat::format::{self, FormatOptions};
use ufat::fsck::{self, ProblemKind, Severity};
use ufat::layout::Layout;
use ufat::name::{join_long_name, parse_long_name_entry, short_name_to_string, LongNameEntry};
use ufat::sha256;
use ufat::time::FatTimestamp;
use ufat::volume::Volume;

/// Subsets enumerated per epoch before the generator samples instead.
/// UFAT_CRASH_FULL=1 lifts the cap.
const SUBSET_CAP: usize = 4096;
/// The seed of the sampling and of the file contents; printed with the
/// summary so that a run can be repeated.
const SEED: u64 = 20261107;
/// The time every entry is stamped with.
const TIME: u64 = 1_700_000_000;
/// Failures of one kind shown in the summary, at most.
const SHOWN_PER_KIND: usize = 3;

fn fixed_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(TIME)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// splitmix64, for file contents and for sampling.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&self.next().to_le_bytes());
        }
        out.truncate(n);
        out
    }
}

// ---------------------------------------------------------------------
// The trace
// ---------------------------------------------------------------------

/// One record of the device trace; see `Device::trace_to`.
#[derive(Clone, Debug)]
enum Record {
    Write { offset: u64, data: Vec<u8> },
    Zero { offset: u64, len: u64 },
    Barrier,
    Sync,
    Note(String),
}

fn read_trace(path: &Path) -> Vec<Record> {
    let bytes = std::fs::read(path).unwrap();
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let tag = bytes[pos];
        let offset = u64::from_le_bytes(bytes[pos + 1..pos + 9].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[pos + 9..pos + 17].try_into().unwrap());
        pos += 17;
        let payload = |pos: &mut usize| {
            let data = bytes[*pos..*pos + len as usize].to_vec();
            *pos += len as usize;
            data
        };
        records.push(match tag {
            b'W' => Record::Write {
                offset,
                data: payload(&mut pos),
            },
            b'Z' => Record::Zero { offset, len },
            b'F' => Record::Barrier,
            b'S' => Record::Sync,
            b'N' => Record::Note(String::from_utf8_lossy(&payload(&mut pos)).into_owned()),
            other => panic!("unknown trace record tag {:#x}", other),
        });
    }
    records
}

// ---------------------------------------------------------------------
// The scenario
// ---------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Op {
    /// `create_dir_all`.
    Mkdir(String),
    /// A file written `chunk` bytes per write call, replacing an existing
    /// file of that name or not.
    Write {
        path: String,
        data: Vec<u8>,
        replace: bool,
        chunk: usize,
    },
    Remove(String),
    /// `close`: the marks go back, FSInfo gets its counts, fsync.
    Close,
}

impl Op {
    fn describe(&self) -> String {
        match self {
            Op::Mkdir(p) => format!("mkdir {}", p),
            Op::Write {
                path,
                data,
                replace,
                chunk,
            } => format!(
                "{} {} ({} bytes, {} per write)",
                if *replace { "replace" } else { "write" },
                path,
                data.len(),
                chunk
            ),
            Op::Remove(p) => format!("remove {}", p),
            Op::Close => "close".to_string(),
        }
    }

    fn replaces(&self) -> Option<&str> {
        match self {
            Op::Write {
                path, replace: true, ..
            } => Some(path),
            _ => None,
        }
    }
}

/// A tree with long names, files replaced within one directory cluster and
/// across two, a directory grown past its first cluster, a removed file
/// whose slots are reused, nested directories. The big file is written in
/// small pieces so that its epoch holds many writes; the kernel names take
/// four slots each.
fn scenario(slots_per_cluster: usize) -> Vec<Op> {
    let mut rng = Rng(SEED);
    let mut ops: Vec<Op> = Vec::new();
    let whole = 1 << 20;
    let mut file = |ops: &mut Vec<Op>, path: &str, len: usize, replace: bool, chunk: usize| {
        ops.push(Op::Write {
            path: path.to_string(),
            data: rng.bytes(len),
            replace,
            chunk,
        });
    };
    let kernel = |n: usize| format!("/EFI/Linux/linux-6.12.{}-200.fc41.x86_64+3.efi", n);
    ops.push(Op::Mkdir("/EFI/BOOT".into()));
    file(&mut ops, "/EFI/BOOT/BOOTX64.EFI", 70_000, false, 4096);
    ops.push(Op::Mkdir("/EFI/Linux".into()));
    // Enough long names to grow the directory past its first cluster.
    let kernels = slots_per_cluster / 4 + 2;
    for i in 0..kernels {
        file(&mut ops, &kernel(i + 1), 1500 + 700 * i, false, whole);
    }
    ops.push(Op::Mkdir("/loader/entries".into()));
    file(&mut ops, "/loader/entries/fedora.conf", 300, false, whole);
    file(&mut ops, "/loader/loader.conf", 40, false, whole);
    file(&mut ops, "/loader/random-seed", 32, false, whole);
    file(&mut ops, "/loader/entries.srel", 5, false, whole);
    file(&mut ops, "/EFI/BOOT/BOOTX64.EFI", 72_000, true, 4096);
    ops.push(Op::Remove(kernel(4)));
    file(&mut ops, "/loader/loader.conf", 60, true, whole);
    // The new entry goes into the slots the removed kernel left, which
    // straddle a sector boundary with 512 byte sectors.
    file(&mut ops, &kernel(3), 5000, true, whole);
    ops.push(Op::Mkdir("/EFI/systemd/drop-ins/deep".into()));
    file(&mut ops, "/EFI/systemd/systemd-bootx64.efi", 9000, false, whole);
    file(&mut ops, &kernel(kernels + 1), 2048, false, whole);
    // Now the only room is in the directory's second cluster: the old
    // entry's deletion and the new entry are two cluster writes.
    file(&mut ops, &kernel(2), 4000, true, whole);
    ops.push(Op::Close);
    ops
}

/// What the free clusters hold before the scenario starts: stale entries
/// of an earlier life of the partition, so that a directory chain running
/// into an unwritten cluster shows, as it would on a reused ESP.
fn stale_slot() -> [u8; DIR_ENTRY_SIZE] {
    let mut e = RawDirEntry {
        name: *b"STALE   OLD",
        attr: ATTR_ARCHIVE,
        first_cluster: 3,
        size: 100,
        ..RawDirEntry::default()
    };
    e.set_times(FatTimestamp::from_system_time(fixed_time()));
    e.to_bytes()
}

/// A file or directory as the oracle sees it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Node {
    Dir,
    File { size: u64, hash: [u8; 32] },
}

/// Every path of a volume, the root left out.
type Tree = BTreeMap<String, Node>;

fn parent_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &path[..i],
    }
}

fn join(dir: &str, name: &str) -> String {
    if dir == "/" {
        format!("/{}", name)
    } else {
        format!("{}/{}", dir, name)
    }
}

fn hash_of(data: &[u8]) -> [u8; 32] {
    sha256::digest(data)
}

/// The tree the scenario means to leave after `ops`.
fn simulate(ops: &[Op]) -> Tree {
    let mut tree = Tree::new();
    for op in ops {
        match op {
            Op::Mkdir(path) => {
                let mut cur = String::new();
                for comp in path.split('/').filter(|c| !c.is_empty()) {
                    cur.push('/');
                    cur.push_str(comp);
                    tree.insert(cur.clone(), Node::Dir);
                }
            }
            Op::Write { path, data, .. } => {
                tree.insert(
                    path.clone(),
                    Node::File {
                        size: data.len() as u64,
                        hash: hash_of(data),
                    },
                );
            }
            Op::Remove(path) => {
                tree.remove(path);
            }
            Op::Close => {}
        }
    }
    tree
}

fn show_node(node: Option<&Node>) -> String {
    match node {
        None => "absent".into(),
        Some(Node::Dir) => "directory".into(),
        Some(Node::File { size, hash }) => format!("{} bytes {}", size, &sha256::to_hex(hash)[..12]),
    }
}

// ---------------------------------------------------------------------
// Reading a volume
// ---------------------------------------------------------------------

/// The tree as the library reads it, with each file's short name.
fn read_tree(v: &Volume) -> Result<(Tree, BTreeMap<String, String>), String> {
    let mut tree = Tree::new();
    let mut shorts = BTreeMap::new();
    let mut dirs = vec!["/".to_string()];
    while let Some(dir) = dirs.pop() {
        let listing = v.read_dir(&dir).map_err(|e| format!("{}: {}", dir, e))?;
        for md in listing {
            let path = join(&dir, &md.name);
            shorts.insert(path.clone(), md.short_name.clone());
            if md.is_dir {
                tree.insert(path.clone(), Node::Dir);
                dirs.push(path);
            } else {
                let mut data = Vec::new();
                v.open_file(&path)
                    .and_then(|mut f| f.read_to_end(&mut data).map_err(ufat::Error::from))
                    .map_err(|e| format!("{}: {}", path, e))?;
                if data.len() as u64 != md.size {
                    return Err(format!("{}: {} bytes read, {} in the entry", path, data.len(), md.size));
                }
                tree.insert(
                    path,
                    Node::File {
                        size: md.size,
                        hash: hash_of(&data),
                    },
                );
            }
        }
    }
    Ok((tree, shorts))
}

/// A directory entry as a second, independent reader sees it: slots are
/// read up to the first end marker, as Linux (since 7.2) and the library
/// read them, and chains are followed through the first FAT copy.
#[derive(Clone, Debug)]
struct RawEntry {
    path: String,
    is_dir: bool,
    size: u32,
    chain: Vec<u32>,
    /// The chain ran into a free, bad or invalid entry, or loops.
    broken: bool,
}

struct RawImage {
    layout: Layout,
    /// The first FAT copy as read; decoded here, not by the library.
    table: Vec<u8>,
    entries: Vec<RawEntry>,
}

impl RawImage {
    fn read(dev: &Device) -> Result<RawImage, String> {
        let mut sector = [0u8; 512];
        dev.read_at(0, &mut sector).map_err(|e| e.to_string())?;
        let boot = BootSector::parse(&sector).map_err(|e| e.to_string())?;
        let layout = boot.layout().map_err(|e| e.to_string())?;
        let mut table = vec![0u8; Fat::used_sectors(&layout) * layout.sector_size as usize];
        dev.read_at(layout.fat_offset(0), &mut table)
            .map_err(|e| e.to_string())?;
        let mut image = RawImage {
            layout,
            table,
            entries: Vec::new(),
        };
        let (chain, broken) = image.follow(boot.root_cluster);
        image.entries.push(RawEntry {
            path: "/".into(),
            is_dir: true,
            size: 0,
            chain,
            broken,
        });
        let mut next = 0;
        while next < image.entries.len() {
            if image.entries[next].is_dir && !image.entries[next].broken {
                let dir = image.entries[next].clone();
                image.read_dir(dev, &dir)?;
            }
            next += 1;
        }
        Ok(image)
    }

    /// The FAT entry of `c`, decoded from the bytes of the first copy.
    fn fat_get(&self, c: u32) -> Entry {
        let at = c as usize * 4;
        let raw = u32::from_le_bytes(self.table[at..at + 4].try_into().unwrap()) & ENTRY_MASK;
        match raw {
            FREE => Entry::Free,
            BAD_CLUSTER => Entry::Bad,
            v if v >= END_OF_CHAIN_MIN => Entry::End,
            v if self.layout.valid_cluster(v) => Entry::Next(v),
            v => Entry::Invalid(v),
        }
    }

    fn follow(&self, first: u32) -> (Vec<u32>, bool) {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut c = first;
        loop {
            if !self.layout.valid_cluster(c) || !seen.insert(c) {
                return (chain, true);
            }
            chain.push(c);
            match self.fat_get(c) {
                Entry::End => return (chain, false),
                Entry::Next(n) => c = n,
                _ => return (chain, true),
            }
        }
    }

    fn cluster(&self, dev: &Device, c: u32) -> Result<Vec<u8>, String> {
        let mut data = vec![0u8; self.layout.cluster_size() as usize];
        dev.read_at(self.layout.cluster_offset(c).map_err(|e| e.to_string())?, &mut data)
            .map_err(|e| e.to_string())?;
        Ok(data)
    }

    fn read_dir(&mut self, dev: &Device, dir: &RawEntry) -> Result<(), String> {
        let mut pending: Vec<LongNameEntry> = Vec::new();
        'clusters: for &c in &dir.chain {
            let data = self.cluster(dev, c)?;
            for raw in data.chunks_exact(DIR_ENTRY_SIZE) {
                let raw: &[u8; DIR_ENTRY_SIZE] = raw.try_into().unwrap();
                if raw[0] == ENTRY_END {
                    break 'clusters;
                }
                if raw[0] == ENTRY_DELETED {
                    pending.clear();
                    continue;
                }
                if let Some(l) = parse_long_name_entry(raw) {
                    pending.push(l);
                    continue;
                }
                let short = RawDirEntry::from_bytes(raw);
                let mut name = None;
                if let Some(last) = pending.last() {
                    if last.sequence == 1 && pending[0].last && pending[0].checksum == short_name_checksum(&short.name)
                    {
                        let ordered: Vec<LongNameEntry> = pending.iter().rev().copied().collect();
                        name = Some(String::from_utf16_lossy(&join_long_name(&ordered)));
                    }
                }
                pending.clear();
                if short.is_volume_label() || short.name[0] == b'.' {
                    continue;
                }
                let name = name.unwrap_or_else(|| short_name_to_string(&short));
                let (chain, broken) = if short.first_cluster == 0 {
                    (Vec::new(), false)
                } else {
                    self.follow(short.first_cluster)
                };
                self.entries.push(RawEntry {
                    path: join(&dir.path, &name),
                    is_dir: short.is_directory(),
                    size: short.size,
                    chain,
                    broken,
                });
            }
        }
        Ok(())
    }

    /// Every cluster some entry's chain claims.
    fn referenced(&self) -> HashSet<u32> {
        self.entries.iter().flat_map(|e| e.chain.iter().copied()).collect()
    }

    /// Every cluster the FAT has in use.
    fn allocated(&self) -> HashSet<u32> {
        (2..=self.layout.max_cluster())
            .filter(|&c| !matches!(self.fat_get(c), Entry::Free | Entry::Bad))
            .collect()
    }

    /// The bytes of an entry through its own chain.
    fn contents(&self, dev: &Device, e: &RawEntry) -> Result<Vec<u8>, String> {
        let mut data = Vec::new();
        for &c in &e.chain {
            data.extend(self.cluster(dev, c)?);
        }
        data.truncate(e.size as usize);
        Ok(data)
    }
}

// ---------------------------------------------------------------------
// The recorded scenario
// ---------------------------------------------------------------------

struct Config {
    sector_size: u32,
    cluster_size: u32,
    image_size: u64,
}

/// One write of the session, after the format.
struct Wr {
    offset: u64,
    data: Vec<u8>,
    /// The scenario op that issued it.
    op: usize,
}

/// What one op boundary looks like: the volume after the ops before it.
struct Boundary {
    tree: Tree,
    shorts: BTreeMap<String, String>,
    /// Which path owns a cluster.
    owners: HashMap<u32, (String, bool)>,
}

struct Harness {
    cfg: Config,
    layout: Layout,
    ss: u64,
    base: Vec<u8>,
    writes: Vec<Wr>,
    epochs: Vec<Range<usize>>,
    ops: Vec<Op>,
    op_writes: Vec<Range<usize>>,
    /// Boundary j is the volume after ops 0..j; boundary 0 is the
    /// formatted volume.
    boundaries: Vec<Boundary>,
    /// Every cluster that belonged to some file or directory at some
    /// boundary: the clusters a crash may legitimately leak.
    legit: HashSet<u32>,
    /// For each epoch and each of its writes, the earlier writes of the
    /// epoch that share a sector with it.
    conflicts: Vec<Vec<Vec<usize>>>,
}

/// The sectors a write covers.
fn sectors_of(w: &Wr, ss: u64) -> Range<u64> {
    w.offset / ss..(w.offset + w.data.len() as u64).div_ceil(ss)
}

fn sector_count(w: &Wr, ss: u64) -> u32 {
    let s = sectors_of(w, ss);
    (s.end - s.start) as u32
}

fn apply(image: &mut [u8], w: &Wr) {
    let off = w.offset as usize;
    image[off..off + w.data.len()].copy_from_slice(&w.data);
}

fn write_image(path: &Path, image: &[u8]) {
    File::create(path).unwrap().write_all_at(image, 0).unwrap();
}

impl Harness {
    /// Runs the scenario on a traced device and digests the trace.
    fn record(cfg: Config) -> Harness {
        let img = Temp::image(cfg.image_size);
        let stale = stale_slot();
        let fill: Vec<u8> = stale.iter().copied().cycle().take(1 << 20).collect();
        {
            let f = File::options().write(true).open(img.path()).unwrap();
            let mut pos = 0;
            while pos < cfg.image_size {
                let n = (cfg.image_size - pos).min(fill.len() as u64) as usize;
                f.write_all_at(&fill[..n], pos).unwrap();
                pos += n as u64;
            }
        }
        let trace = Temp::new(".trace");
        let mut dev = Device::open(img.path(), Access::ReadWrite).unwrap();
        dev.trace_to(File::create(trace.path()).unwrap());
        dev.trace_note("format").unwrap();
        let options = FormatOptions {
            sector_size: Some(cfg.sector_size),
            cluster_size: Some(cfg.cluster_size),
            volume_id: 0x4352_5348,
            label: Some("ESP".into()),
            timestamp: Some(fixed_time()),
            allow_small: true,
            ..FormatOptions::default()
        };
        let layout = format::format(&dev, &options).unwrap();
        let base = std::fs::read(img.path()).unwrap();
        let ops = scenario(cfg.cluster_size as usize / DIR_ENTRY_SIZE);
        let mut v = Volume::open(dev).unwrap();
        v.set_durable(true);
        for op in &ops {
            v.device().trace_note(&op.describe()).unwrap();
            match op {
                Op::Mkdir(path) => v.create_dir_all(path, fixed_time()).unwrap(),
                Op::Write {
                    path,
                    data,
                    replace,
                    chunk,
                } => {
                    let mut w = v.create_file(path, fixed_time(), *replace).unwrap();
                    for piece in data.chunks(*chunk) {
                        w.write_all(piece).unwrap();
                    }
                    w.finish().unwrap();
                }
                Op::Remove(path) => v.remove_file(path).unwrap(),
                Op::Close => {}
            }
        }
        v.close().unwrap();
        let final_image = std::fs::read(img.path()).unwrap();
        let records = read_trace(trace.path());

        // The format is the pre-state: its records must turn the stale
        // image into the base and nothing else happens in it.
        let mut replayed = fill
            .iter()
            .copied()
            .cycle()
            .take(cfg.image_size as usize)
            .collect::<Vec<u8>>();
        let mut rest = records.iter();
        assert!(matches!(rest.next(), Some(Record::Note(n)) if n == "format"));
        loop {
            match rest.next().expect("the format ends with a sync") {
                Record::Write { offset, data } => {
                    replayed[*offset as usize..*offset as usize + data.len()].copy_from_slice(data)
                }
                Record::Zero { offset, len } => replayed[*offset as usize..(*offset + *len) as usize].fill(0),
                Record::Sync => break,
                other => panic!("unexpected {:?} in the format", other),
            }
        }
        assert!(
            replayed == base,
            "replaying the format does not give the formatted image"
        );

        // The session: writes, epochs cut at every barrier, op ranges cut
        // at every note.
        let mut writes: Vec<Wr> = Vec::new();
        let mut epochs: Vec<Range<usize>> = Vec::new();
        let mut op_writes: Vec<Range<usize>> = Vec::new();
        let mut epoch_start = 0;
        let mut op = 0;
        for r in rest {
            match r {
                Record::Write { offset, data } => writes.push(Wr {
                    offset: *offset,
                    data: data.clone(),
                    op,
                }),
                Record::Zero { .. } => panic!("the session is not expected to punch holes"),
                Record::Barrier | Record::Sync => {
                    epochs.push(epoch_start..writes.len());
                    epoch_start = writes.len();
                }
                Record::Note(_) => {
                    if !op_writes.is_empty() || op > 0 {
                        op += 1;
                    }
                    op_writes.push(writes.len()..writes.len());
                }
            }
        }
        assert_eq!(epoch_start, writes.len(), "the session ends with a sync");
        assert_eq!(op_writes.len(), ops.len());
        for k in 0..ops.len() {
            let end = op_writes.get(k + 1).map_or(writes.len(), |r| r.start);
            op_writes[k] = op_writes[k].start..end;
        }
        for (k, r) in op_writes.iter().enumerate() {
            assert!(!r.is_empty(), "op {} '{}' wrote nothing", k, ops[k].describe());
        }
        let mut replayed = base.clone();
        for w in &writes {
            apply(&mut replayed, w);
        }
        assert!(
            replayed == final_image,
            "replaying the session does not give the final image"
        );

        let ss = u64::from(layout.sector_size);
        let conflicts = epochs
            .iter()
            .map(|e| {
                let ws: Vec<Range<u64>> = writes[e.clone()].iter().map(|w| sectors_of(w, ss)).collect();
                (0..ws.len())
                    .map(|i| {
                        (0..i)
                            .filter(|&j| ws[j].start < ws[i].end && ws[i].start < ws[j].end)
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut h = Harness {
            cfg,
            layout,
            ss,
            base,
            writes,
            epochs,
            ops,
            op_writes,
            boundaries: Vec::new(),
            legit: HashSet::new(),
            conflicts,
        };
        h.read_boundaries();
        h
    }

    /// Reads and checks the volume at every op boundary; those states are
    /// no crash and have to be perfect.
    fn read_boundaries(&mut self) {
        let scratch = Temp::new(".img");
        let mut image = self.base.clone();
        let mut done = 0;
        for j in 0..=self.ops.len() {
            if j > 0 {
                for w in &self.writes[done..self.op_writes[j - 1].end] {
                    apply(&mut image, w);
                }
                done = self.op_writes[j - 1].end;
            }
            write_image(scratch.path(), &image);
            let dev = Device::open(scratch.path(), Access::ReadOnly).unwrap();
            let report = fsck::check(&dev).unwrap();
            let closed = j == self.ops.len();
            for p in &report.problems {
                let fine = p.severity == Severity::Warning
                    && (p.kind == ProblemKind::BelowMinimumClusters
                        || (!closed && j > 0 && matches!(p.kind, ProblemKind::DirtyFlag | ProblemKind::FatDirtyFlag)));
                assert!(fine, "boundary {} (after {}): {:?}", j, self.boundary_name(j), p);
            }
            assert_eq!(report.lost_clusters, 0, "boundary {} leaks clusters", j);
            let raw = RawImage::read(&dev).unwrap();
            let v = Volume::open(Device::open(scratch.path(), Access::ReadOnly).unwrap()).unwrap();
            let (tree, shorts) = read_tree(&v).unwrap();
            let expected = simulate(&self.ops[..j]);
            assert!(
                tree == expected,
                "boundary {} (after {}) does not hold what the scenario wrote:\n got {:#?}\n expected {:#?}",
                j,
                self.boundary_name(j),
                tree,
                expected
            );
            let mut owners = HashMap::new();
            for e in &raw.entries {
                assert!(!e.broken, "{}: broken chain at boundary {}", e.path, j);
                for &c in &e.chain {
                    owners.insert(c, (e.path.clone(), e.is_dir));
                }
            }
            self.legit.extend(raw.referenced());
            self.boundaries.push(Boundary { tree, shorts, owners });
        }
    }

    fn boundary_name(&self, j: usize) -> String {
        if j == 0 {
            "format".into()
        } else {
            self.ops[j - 1].describe()
        }
    }

    /// Describes a write for the summary: region and owner.
    fn describe(&self, i: usize) -> String {
        let w = &self.writes[i];
        let l = &self.layout;
        let sectors = sector_count(w, self.ss);
        let span = if sectors == 1 {
            String::new()
        } else {
            format!(" ({} sectors)", sectors)
        };
        let region = if w.offset < l.fat_offset(0) {
            if w.offset == 0 {
                "boot sector".to_string()
            } else {
                format!("reserved sector {}", w.offset / self.ss)
            }
        } else if w.offset < l.data_start() {
            let copy = ((w.offset - l.fat_offset(0)) / l.fat_size()) as u32;
            let first = (w.offset - l.fat_offset(copy)) / self.ss;
            format!("FAT{} sector {}{}", copy, first, span)
        } else {
            let cs = u64::from(l.cluster_size());
            let first = ((w.offset - l.data_start()) / cs) as u32 + 2;
            let count = (w.data.len() as u64).div_ceil(cs) as u32;
            let owner = self.owner_of(first, w.op);
            let what = match &owner {
                Some((path, true)) => format!("directory {}", path),
                Some((path, false)) => format!("data of {}", path),
                None => "unowned".to_string(),
            };
            if count == 1 {
                format!("cluster {} ({})", first, what)
            } else {
                format!("clusters {}-{} ({})", first, first + count - 1, what)
            }
        };
        format!("#{} {}", i, region)
    }

    /// Who owns a cluster around op `op`: after it, or else before it.
    fn owner_of(&self, cluster: u32, op: usize) -> Option<(String, bool)> {
        self.boundaries[op + 1]
            .owners
            .get(&cluster)
            .or_else(|| self.boundaries[op].owners.get(&cluster))
            .cloned()
    }

    /// The directory a write belongs to, when it writes directory
    /// clusters.
    fn directory_of(&self, i: usize) -> Option<String> {
        let w = &self.writes[i];
        let l = &self.layout;
        if w.offset < l.data_start() {
            return None;
        }
        let first = ((w.offset - l.data_start()) / u64::from(l.cluster_size())) as u32 + 2;
        match self.owner_of(first, w.op) {
            Some((path, true)) => Some(path),
            _ => None,
        }
    }

    /// The directories an op of the state has written only in part: of
    /// the directory clusters the op writes, some are there and some are
    /// not, or one is torn.
    fn partial_directories(&self, pieces: &[Piece]) -> Vec<String> {
        let mut state: HashMap<usize, u8> = HashMap::new();
        for p in pieces {
            let whole = p.from == 0 && p.to == self.whole(p.w).to;
            state.insert(p.w, if whole { 1 } else { 2 });
        }
        let mut groups: BTreeMap<(usize, String), (bool, bool)> = BTreeMap::new();
        for (i, w) in self.writes.iter().enumerate() {
            if let Some(dir) = self.directory_of(i) {
                let s = state.get(&i).copied().unwrap_or(0);
                let g = groups.entry((w.op, dir)).or_insert((false, false));
                g.0 |= s != 0;
                g.1 |= s != 1;
            }
        }
        groups
            .into_iter()
            .filter(|(_, (some, missing))| *some && *missing)
            .map(|((_, dir), _)| dir)
            .collect()
    }
}

// ---------------------------------------------------------------------
// Crash states
// ---------------------------------------------------------------------

/// How a crash state is built from the trace.
#[derive(Clone, Debug)]
enum Recipe {
    /// Writes 0..n, whole.
    Prefix { n: usize },
    /// Writes 0..w whole, then sectors from..to of write w.
    Torn { w: usize, from: u32, to: u32 },
    /// Everything before the epoch, then its writes up to and including
    /// `upto`, except `dropped` (ALICE's pairwise reordering).
    Reorder { epoch: usize, dropped: usize, upto: usize },
    /// Everything before the epoch, then the writes whose bit is set.
    Subset { epoch: usize, mask: u128 },
}

impl Recipe {
    fn generator(&self) -> usize {
        match self {
            Recipe::Prefix { .. } => 0,
            Recipe::Torn { .. } => 1,
            Recipe::Reorder { .. } => 2,
            Recipe::Subset { .. } => 3,
        }
    }
}

const GENERATORS: [&str; 4] = ["G1 prefixes", "G2 torn writes", "G3 pairwise", "G4 subsets"];

/// A piece of a write to apply: whole, or the sectors from..to of it.
#[derive(Clone, Copy, Debug)]
struct Piece {
    w: usize,
    from: u32,
    to: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Untouched,
    InFlight,
    Committed,
}

struct Failure {
    recipe: String,
    complaints: Vec<String>,
}

/// What the oracle let pass in a state, by the rule that allowed it; the
/// summary counts how often each rule was needed.
const ACCEPT_DIRTY: &str = "the dirty marks of a session in progress";
const ACCEPT_FAT_COPIES: &str = "the FAT copies differing";
const ACCEPT_LOST: &str = "lost clusters of an operation in flight";
const ACCEPT_FSINFO: &str = "a stale FSInfo free count";
const ACCEPT_ORPHANS: &str = "orphaned long name slots in a partly written directory";
const ACCEPT_BEHIND_MARKER: &str = "a short entry behind the end marker of a partly written directory";
const ACCEPT_DUPLICATE: &str = "both versions of a replaced file in a partly written directory";
const ACCEPT_ALIAS: &str = "a file listed under its alias in a partly written directory";
const ACCEPT_REPLACED_ABSENT: &str = "a replaced file absent";

struct Verdict {
    failure: Option<Failure>,
    accepted: BTreeSet<&'static str>,
}

impl Harness {
    fn whole(&self, w: usize) -> Piece {
        Piece {
            w,
            from: 0,
            to: sector_count(&self.writes[w], self.ss),
        }
    }

    fn pieces(&self, recipe: &Recipe) -> Vec<Piece> {
        match recipe {
            Recipe::Prefix { n } => (0..*n).map(|w| self.whole(w)).collect(),
            Recipe::Torn { w, from, to } => {
                let mut p: Vec<Piece> = (0..*w).map(|w| self.whole(w)).collect();
                p.push(Piece {
                    w: *w,
                    from: *from,
                    to: *to,
                });
                p
            }
            Recipe::Reorder { epoch, dropped, upto } => {
                let e = &self.epochs[*epoch];
                (0..e.start)
                    .chain((e.start..=e.start + upto).filter(|&w| w != e.start + dropped))
                    .map(|w| self.whole(w))
                    .collect()
            }
            Recipe::Subset { epoch, mask } => {
                let e = &self.epochs[*epoch];
                (0..e.start)
                    .chain(e.clone().filter(|&w| mask >> (w - e.start) & 1 == 1))
                    .map(|w| self.whole(w))
                    .collect()
            }
        }
    }

    fn statuses(&self, pieces: &[Piece]) -> Vec<Status> {
        // 0 absent, 1 whole, 2 partial.
        let mut state = vec![0u8; self.writes.len()];
        for p in pieces {
            state[p.w] = if p.from == 0 && p.to == self.whole(p.w).to {
                1
            } else {
                2
            };
        }
        self.op_writes
            .iter()
            .map(|r| {
                let s = &state[r.clone()];
                if s.iter().all(|&x| x == 1) {
                    Status::Committed
                } else if s.iter().all(|&x| x == 0) {
                    Status::Untouched
                } else {
                    Status::InFlight
                }
            })
            .collect()
    }

    fn describe_recipe(&self, recipe: &Recipe) -> String {
        let op_of = |w: usize| format!("op {} '{}'", self.writes[w].op, self.ops[self.writes[w].op].describe());
        match recipe {
            Recipe::Prefix { n } if *n == 0 => "G1: nothing of the session applied".into(),
            Recipe::Prefix { n } => format!(
                "G1: writes 0..={} applied, the last being {} of {}",
                n - 1,
                self.describe(n - 1),
                op_of(n - 1)
            ),
            Recipe::Torn { w, from, to } => format!(
                "G2: writes 0..{} applied, then {} of {} torn: {} of its {} sectors",
                w,
                self.describe(*w),
                op_of(*w),
                if to - from == 1 {
                    format!("only sector {}", from)
                } else {
                    format!("sectors {}-{}", from, to - 1)
                },
                self.whole(*w).to
            ),
            Recipe::Reorder { epoch, dropped, upto } => {
                let e = &self.epochs[*epoch];
                format!(
                    "G3 epoch {} (writes {}..{}): writes up to {} applied without {}",
                    epoch,
                    e.start,
                    e.end - 1,
                    self.describe(e.start + upto),
                    self.describe(e.start + dropped)
                )
            }
            Recipe::Subset { epoch, mask } => {
                let e = &self.epochs[*epoch];
                let (mut applied, mut dropped) = (Vec::new(), Vec::new());
                for w in e.clone() {
                    if mask >> (w - e.start) & 1 == 1 {
                        applied.push(self.describe(w));
                    } else {
                        dropped.push(self.describe(w));
                    }
                }
                format!(
                    "G4 epoch {} (writes {}..{}): applied [{}], dropped [{}]",
                    epoch,
                    e.start,
                    e.end - 1,
                    applied.join(", "),
                    dropped.join(", ")
                )
            }
        }
    }

    /// Whether a subset of an epoch respects the same-sector rule: a
    /// sector's durable content is one version of its own write sequence,
    /// never a newer one before an older.
    fn valid_subset(&self, epoch: usize, mask: u128) -> bool {
        self.conflicts[epoch]
            .iter()
            .enumerate()
            .all(|(i, earlier)| mask >> i & 1 == 0 || earlier.iter().all(|&j| mask >> j & 1 == 1))
    }

    fn generate(&self, full: bool, cap: usize) -> (Vec<Recipe>, [usize; 4]) {
        let mut recipes = Vec::new();
        let mut skipped = [0usize; 4];
        for n in 0..=self.writes.len() {
            recipes.push(Recipe::Prefix { n });
        }
        for w in 0..self.writes.len() {
            let sectors = self.whole(w).to;
            for p in 1..sectors {
                recipes.push(Recipe::Torn { w, from: 0, to: p });
            }
            for q in 1..sectors {
                recipes.push(Recipe::Torn { w, from: q, to: q + 1 });
            }
        }
        for (epoch, e) in self.epochs.iter().enumerate() {
            let n = e.len();
            for dropped in 0..n {
                for upto in dropped + 1..n {
                    let valid = (dropped + 1..=upto).all(|k| !self.conflicts[epoch][k].contains(&dropped));
                    if valid {
                        recipes.push(Recipe::Reorder { epoch, dropped, upto });
                    } else {
                        skipped[2] += 1;
                    }
                }
            }
        }
        let mut rng = Rng(SEED);
        for (epoch, e) in self.epochs.iter().enumerate() {
            let n = e.len();
            assert!(
                n <= 128,
                "epoch {} has {} writes, more than the subset mask holds",
                epoch,
                n
            );
            let count = 1u128 << n;
            if full || count <= cap as u128 {
                for mask in 0..count {
                    if self.valid_subset(epoch, mask) {
                        recipes.push(Recipe::Subset { epoch, mask });
                    } else {
                        skipped[3] += 1;
                    }
                }
            } else {
                for _ in 0..cap {
                    let mask = (u128::from(rng.next()) << 64 | u128::from(rng.next())) & (count - 1);
                    if self.valid_subset(epoch, mask) {
                        recipes.push(Recipe::Subset { epoch, mask });
                    } else {
                        skipped[3] += 1;
                    }
                }
            }
        }
        (recipes, skipped)
    }
}

// ---------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------

/// Checks crash states one after another on its own copy of the image.
struct Worker<'a> {
    h: &'a Harness,
    /// Removes the image when the worker is done.
    _scratch: Temp,
    file: File,
    /// The same file read-only, for the devices the checks open: a
    /// volume opened on it cannot write anything back when it is dropped.
    readonly: File,
}

impl<'a> Worker<'a> {
    fn new(h: &'a Harness) -> Worker<'a> {
        let scratch = Temp::new(".img");
        write_image(scratch.path(), &h.base);
        let file = File::options().write(true).open(scratch.path()).unwrap();
        let readonly = File::open(scratch.path()).unwrap();
        Worker {
            h,
            _scratch: scratch,
            file,
            readonly,
        }
    }

    fn device(&self) -> Device {
        Device::from_fd(self.readonly.as_fd()).unwrap()
    }

    fn check(&mut self, recipe: &Recipe) -> Verdict {
        let pieces = self.h.pieces(recipe);
        let ss = self.h.ss as usize;
        for p in &pieces {
            let w = &self.h.writes[p.w];
            let (from, to) = (p.from as usize * ss, (p.to as usize * ss).min(w.data.len()));
            self.file
                .write_all_at(&w.data[from..to], w.offset + from as u64)
                .unwrap();
        }
        let (complaints, accepted) = self.oracle(&pieces);
        for p in &pieces {
            let w = &self.h.writes[p.w];
            let (from, to) = (p.from as usize * ss, (p.to as usize * ss).min(w.data.len()));
            let off = w.offset as usize + from;
            self.file
                .write_all_at(&self.h.base[off..off + to - from], off as u64)
                .unwrap();
        }
        let failure = if complaints.is_empty() {
            None
        } else {
            Some(Failure {
                recipe: self.h.describe_recipe(recipe),
                complaints,
            })
        };
        Verdict { failure, accepted }
    }

    fn oracle(&self, pieces: &[Piece]) -> (Vec<String>, BTreeSet<&'static str>) {
        let h = self.h;
        let mut bad: Vec<String> = Vec::new();
        let mut accepted: BTreeSet<&'static str> = BTreeSet::new();
        let status = h.statuses(pieces);
        let final_state = status.iter().all(|&s| s == Status::Committed);
        // The boundaries whose trees a path may show: from the last one
        // every earlier op had reached to the last one any op has touched.
        let lo = status
            .iter()
            .position(|&s| s != Status::Committed)
            .unwrap_or(h.ops.len());
        let hi = status
            .iter()
            .rposition(|&s| s != Status::Untouched)
            .map_or(lo, |k| (k + 1).max(lo));
        let in_flight: Vec<&Op> = (lo..hi)
            .filter(|&k| status[k] == Status::InFlight)
            .map(|k| &h.ops[k])
            .collect();
        // A directory whose update is not all there, because a write of it
        // was torn or because the entry straddles two clusters and only
        // one of the two writes made it, may show a short entry without
        // its long name slots, orphan long name slots, a short entry
        // behind the end marker, or both versions of a replaced file. The
        // models accept that, so the oracle does, in that directory only.
        let partial_dirs = h.partial_directories(pieces);
        let torn_dir = |dir: &str| partial_dirs.iter().any(|d| d == dir);
        let replaced: BTreeSet<&str> = in_flight.iter().filter_map(|op| op.replaces()).collect();
        let versions_of = |path: &str| -> BTreeSet<Option<Node>> {
            (lo..=hi).map(|j| h.boundaries[j].tree.get(path).cloned()).collect()
        };
        let allowed = |path: &str| -> BTreeSet<Option<Node>> {
            let mut set = versions_of(path);
            if replaced.contains(path) {
                set.insert(None);
            }
            set
        };
        // Whether a finding is about `dir` itself or an entry directly in it.
        let in_dir = |path: &str, dir: &str| {
            let prefix = if dir == "/" {
                "/".to_string()
            } else {
                format!("{}/", dir)
            };
            path == dir || (path.starts_with(&prefix) && !path[prefix.len()..].contains('/'))
        };

        // 1. fsck.
        let dev = self.device();
        let report = match fsck::check(&dev) {
            Ok(r) => r,
            Err(e) => {
                bad.push(format!("fsck could not check the volume: {}", e));
                return (bad, accepted);
            }
        };
        for p in &report.problems {
            let msg = p.to_string();
            let path = p.path.as_deref().unwrap_or("");
            let partly_written = partial_dirs.iter().any(|d| in_dir(path, d));
            // The test volume is small, which is worth a warning of its own.
            if p.kind == ProblemKind::BelowMinimumClusters {
                continue;
            }
            let rule = match p.severity {
                Severity::Error if p.kind == ProblemKind::EntryAfterEnd && partly_written => Some(ACCEPT_BEHIND_MARKER),
                Severity::Error
                    if p.kind == ProblemKind::DuplicateName
                        && replaced.iter().any(|f| {
                            partial_dirs.iter().any(|d| d == parent_of(f))
                                && (path == *f
                                    || (lo..=hi).any(|j| {
                                        h.boundaries[j]
                                            .shorts
                                            .get(*f)
                                            .is_some_and(|short| path == join(parent_of(f), short))
                                    }))
                        }) =>
                {
                    Some(ACCEPT_DUPLICATE)
                }
                Severity::Error => None,
                Severity::Warning if p.kind == ProblemKind::OrphanedLongName && partly_written => Some(ACCEPT_ORPHANS),
                // Mid-run the marks are set, a FAT copy may be a write
                // behind, clusters of the operation in flight may be
                // unreferenced and the count may predate an allocation.
                Severity::Warning if final_state => None,
                Severity::Warning if matches!(p.kind, ProblemKind::DirtyFlag | ProblemKind::FatDirtyFlag) => {
                    Some(ACCEPT_DIRTY)
                }
                Severity::Warning if p.kind == ProblemKind::FatCopyDiffers => Some(ACCEPT_FAT_COPIES),
                Severity::Warning if p.kind == ProblemKind::LostClusters => Some(ACCEPT_LOST),
                Severity::Warning if p.kind == ProblemKind::FsinfoFreeCount => Some(ACCEPT_FSINFO),
                Severity::Warning => None,
            };
            match rule {
                Some(r) => {
                    accepted.insert(r);
                }
                None => bad.push(format!(
                    "fsck {}: {}",
                    if p.severity == Severity::Error {
                        "error"
                    } else {
                        "warning"
                    },
                    msg
                )),
            }
        }

        // 2. Clusters: whatever is allocated and unreferenced must have
        // belonged to a file or directory at some point.
        let raw = match RawImage::read(&dev) {
            Ok(r) => r,
            Err(e) => {
                bad.push(format!("the volume cannot be read: {}", e));
                return (bad, accepted);
            }
        };
        let referenced = raw.referenced();
        let mut lost: Vec<u32> = raw.allocated().difference(&referenced).copied().collect();
        lost.sort_unstable();
        if lost.len() as u32 != report.lost_clusters {
            bad.push(format!(
                "fsck counts {} lost clusters, the walk finds {}",
                report.lost_clusters,
                lost.len()
            ));
        }
        let strange: Vec<u32> = lost.iter().copied().filter(|c| !h.legit.contains(c)).collect();
        if !strange.is_empty() {
            bad.push(format!(
                "clusters {:?} are allocated but never belonged to any file or directory",
                strange
            ));
        }
        if final_state && !lost.is_empty() {
            bad.push(format!("{} clusters leaked by the complete run", lost.len()));
        }

        // 3. The tree through the library.
        let v = match Volume::open(self.device()) {
            Ok(v) => v,
            Err(e) => {
                bad.push(format!("the volume does not open: {}", e));
                return (bad, accepted);
            }
        };
        let mut dirs: BTreeSet<String> = ["/".to_string()].into_iter().collect();
        let mut children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for j in lo..=hi {
            for (path, node) in &h.boundaries[j].tree {
                if *node == Node::Dir {
                    dirs.insert(path.clone());
                }
                children
                    .entry(parent_of(path).to_string())
                    .or_default()
                    .insert(path.clone());
            }
        }
        for dir in &dirs {
            let present = dir == "/" || v.metadata(dir).is_ok_and(|md| md.is_dir);
            if !present {
                if !allowed(dir).contains(&None) {
                    bad.push(format!("{}: directory missing", dir));
                }
                continue;
            }
            if dir != "/" && !allowed(dir).contains(&Some(Node::Dir)) {
                bad.push(format!("{}: directory present but expected {}", dir, "absent"));
                continue;
            }
            let listing = match v.read_dir(dir) {
                Ok(l) => l,
                Err(e) => {
                    bad.push(format!("{}: cannot be listed: {}", dir, e));
                    continue;
                }
            };
            let expected = children.get(dir).cloned().unwrap_or_default();
            // Every listed entry stands for an expected path: under its own
            // name, or under its alias when a torn write left a short entry
            // without its long name slots.
            let mut seen: BTreeMap<String, Vec<&ufat::volume::Metadata>> = BTreeMap::new();
            for md in &listing {
                let listed = join(dir, &md.name);
                let path = if expected.contains(&listed) {
                    listed
                } else if torn_dir(dir) {
                    match expected.iter().find(|p| {
                        (lo..=hi).any(|j| {
                            h.boundaries[j]
                                .shorts
                                .get(*p)
                                .is_some_and(|s| s.eq_ignore_ascii_case(&md.name))
                        })
                    }) {
                        Some(p) => {
                            accepted.insert(ACCEPT_ALIAS);
                            p.clone()
                        }
                        None => {
                            bad.push(format!("{}: unexpected entry '{}'", dir, md.name));
                            continue;
                        }
                    }
                } else {
                    bad.push(format!("{}: unexpected entry '{}'", dir, md.name));
                    continue;
                };
                seen.entry(path).or_default().push(md);
            }
            for (path, entries) in &seen {
                let versions = allowed(path);
                let complain = |bad: &mut Vec<String>, observed: Option<Node>| {
                    if !versions.contains(&observed) {
                        bad.push(format!(
                            "{}: is {}, expected one of [{}]",
                            path,
                            show_node(observed.as_ref()),
                            versions
                                .iter()
                                .map(|n| show_node(n.as_ref()))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                };
                if entries.len() == 1 {
                    let md = entries[0];
                    if md.is_dir {
                        complain(&mut bad, Some(Node::Dir));
                        continue;
                    }
                    let mut data = Vec::new();
                    match v
                        .open_file(&join(dir, &md.name))
                        .and_then(|mut f| f.read_to_end(&mut data).map_err(ufat::Error::from))
                    {
                        Ok(_) => complain(
                            &mut bad,
                            Some(Node::File {
                                size: md.size,
                                hash: hash_of(&data),
                            }),
                        ),
                        Err(e) => bad.push(format!("{}: cannot be read: {}", path, e)),
                    }
                    continue;
                }
                // Two entries of one name: only a torn replace may leave
                // them, one under its alias perhaps, and each must be a
                // version of the file. The library's lookup would find the
                // first, so each is read through its own chain.
                if !(torn_dir(dir) && replaced.contains(path.as_str())) {
                    bad.push(format!("{}: {} entries of that name", path, entries.len()));
                    continue;
                }
                accepted.insert(ACCEPT_DUPLICATE);
                let names: Vec<String> = entries.iter().map(|md| join(dir, &md.name)).collect();
                for e in raw.entries.iter().filter(|e| names.contains(&e.path)) {
                    match raw.contents(&dev, e) {
                        Ok(data) if !e.broken && !e.is_dir => complain(
                            &mut bad,
                            Some(Node::File {
                                size: u64::from(e.size),
                                hash: hash_of(&data),
                            }),
                        ),
                        _ => bad.push(format!("{}: a duplicate entry cannot be read", path)),
                    }
                }
            }
            for path in &expected {
                if seen.contains_key(path) || versions_of(path).contains(&None) {
                    continue;
                }
                if replaced.contains(path.as_str()) {
                    accepted.insert(ACCEPT_REPLACED_ABSENT);
                } else {
                    bad.push(format!("{}: missing", path));
                }
            }
        }
        (bad, accepted)
    }
}

// ---------------------------------------------------------------------
// Running it
// ---------------------------------------------------------------------

/// Open files a worker holds at most: the image twice, a device for the
/// checks and one more for the volume.
const FILES_PER_WORKER: usize = 4;

/// The soft limit on open files, from /proc/self/limits.
fn open_files_limit() -> Option<usize> {
    let limits = std::fs::read_to_string("/proc/self/limits").ok()?;
    let line = limits.lines().find(|l| l.starts_with("Max open files"))?;
    line.split_whitespace().nth(3)?.parse().ok()
}

fn threads() -> usize {
    if let Ok(n) = std::env::var("UFAT_CRASH_THREADS") {
        if let Ok(n) = n.parse::<usize>() {
            return n.max(1);
        }
    }
    let cores = std::thread::available_parallelism().map_or(4, std::num::NonZero::get);
    // A 512 core machine with the usual limit of 1024 open files cannot
    // run a worker per core.
    match open_files_limit() {
        Some(limit) => cores.min((limit.saturating_sub(64) / FILES_PER_WORKER).max(1)),
        None => cores,
    }
}

fn run(cfg: Config) {
    let started = Instant::now();
    let full = env_flag("UFAT_CRASH_FULL");
    let cap = std::env::var("UFAT_CRASH_CAP")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(SUBSET_CAP);
    let h = Harness::record(cfg);
    let recorded = started.elapsed();
    let (recipes, skipped) = h.generate(full, cap);
    let mut per_generator = [0usize; 4];
    for r in &recipes {
        per_generator[r.generator()] += 1;
    }
    println!(
        "crash: {} byte sectors, {} byte clusters, {} MiB image, {} ops, {} writes in {} epochs (largest {}), {} boundaries read in {:.1?}",
        h.cfg.sector_size,
        h.cfg.cluster_size,
        h.cfg.image_size >> 20,
        h.ops.len(),
        h.writes.len(),
        h.epochs.len(),
        h.epochs.iter().map(ExactSizeIterator::len).max().unwrap_or(0),
        h.boundaries.len(),
        recorded
    );
    println!(
        "crash: {} states, subsets {} per epoch, seed {}, {} threads",
        recipes.len(),
        if full {
            "complete".to_string()
        } else {
            format!("capped at {}", cap)
        },
        SEED,
        threads()
    );

    let next = AtomicUsize::new(0);
    let failures: Mutex<Vec<(usize, Failure)>> = Mutex::new(Vec::new());
    let accepted: Mutex<BTreeMap<&'static str, usize>> = Mutex::new(BTreeMap::new());
    let checking = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..threads().min(recipes.len().max(1)) {
            s.spawn(|| {
                let mut worker = Worker::new(&h);
                let mut mine = Vec::new();
                let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= recipes.len() {
                        break;
                    }
                    let verdict = worker.check(&recipes[i]);
                    if let Some(f) = verdict.failure {
                        mine.push((i, f));
                    }
                    for rule in verdict.accepted {
                        *tally.entry(rule).or_default() += 1;
                    }
                }
                failures.lock().unwrap().extend(mine);
                let mut total = accepted.lock().unwrap();
                for (rule, n) in tally {
                    *total.entry(rule).or_default() += n;
                }
            });
        }
    });
    let mut failures = failures.into_inner().unwrap();
    failures.sort_by_key(|(i, _)| *i);
    let accepted = accepted.into_inner().unwrap();
    let elapsed = checking.elapsed();

    let mut failed = [0usize; 4];
    for (i, _) in &failures {
        failed[recipes[*i].generator()] += 1;
    }
    for g in 0..4 {
        println!(
            "crash: {:<15} {:>8} states {:>6} failed{}",
            GENERATORS[g],
            per_generator[g],
            failed[g],
            if skipped[g] > 0 {
                format!(" ({} subsets forbidden by the same-sector rule)", skipped[g])
            } else {
                String::new()
            }
        );
    }
    println!(
        "crash: {} states checked in {:.1?} ({:.2} ms per state per thread)",
        recipes.len(),
        elapsed,
        elapsed.as_secs_f64() * 1000.0 * threads() as f64 / recipes.len().max(1) as f64
    );
    println!("crash: states the oracle accepted because the models allow what it saw:");
    for (rule, n) in &accepted {
        println!("crash: {:>8} with {}", n, rule);
    }

    // Group the failures by what the oracle said, digits aside, and show a
    // few recipes of each kind.
    let mut kinds: BTreeMap<String, Vec<&Failure>> = BTreeMap::new();
    for (_, f) in &failures {
        let key: String = f
            .complaints
            .iter()
            .map(|c| {
                c.chars()
                    .map(|ch| if ch.is_ascii_digit() { '#' } else { ch })
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join(" | ");
        kinds.entry(key).or_default().push(f);
    }
    for (kind, fs) in &kinds {
        println!("\ncrash: {} states failed like this:", fs.len());
        for line in kind.split(" | ") {
            println!("    {}", line);
        }
        for f in fs.iter().take(SHOWN_PER_KIND) {
            println!("  {}", f.recipe);
            for c in &f.complaints {
                println!("    {}", c);
            }
        }
        if fs.len() > SHOWN_PER_KIND {
            println!("  ... and {} more", fs.len() - SHOWN_PER_KIND);
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} crash states fail the oracle, see above",
        failures.len(),
        recipes.len()
    );
}

/// 512 byte sectors with two sectors per cluster: directory writes can
/// tear between their long name slots and the short entry.
#[test]
fn sectors_512_clusters_1024() {
    run(Config {
        sector_size: 512,
        cluster_size: 1024,
        image_size: 4 << 20,
    });
}

/// 4096 byte sectors, as on a 4Kn disk: a cluster is a sector, the FAT
/// fits one sector, and a directory grows only after 32 long names.
#[test]
fn sectors_4096_clusters_4096() {
    run(Config {
        sector_size: 4096,
        cluster_size: 4096,
        image_size: 4 << 20,
    });
}
