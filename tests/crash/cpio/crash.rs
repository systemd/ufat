// SPDX-License-Identifier: LGPL-2.1-or-later
//! Crash consistency of writing an archive and of adding to one.
//!
//! A scenario writes an archive, or adds entries to one, on a traced
//! device. The trace is then replayed into every state a crash can leave
//! behind under the three storage models described in HACKING.md.
//!
//! While an archive is added to, each state has to be one of four, which
//! is all `cpio::image::SpliceSink` promises:
//!
//! - the archive as it was;
//! - the archive as it was, stopped where its trailer was. The kernel
//!   unpacks what it held and says that unpacking failed;
//! - all of what was added, stopped at the new trailer. The kernel unpacks
//!   everything and says that unpacking failed;
//! - the archive with all that was added.
//!
//! While an archive is written, each state has to be one of three, which
//! is all `cpio::image::StoppedSink` promises:
//!
//! - what the image held;
//! - something that is stopped at its first byte. The kernel unpacks
//!   nothing of it and says that unpacking failed;
//! - the archive.
//!
//! What the kernel does with a stopped archive is not taken on trust: the
//! `made-populate-cut` and `made-assemble-cut` fixtures are such states,
//! booted, see tests/cpio_kernel.rs. Runs with `cargo test` against the
//! library of the cpio-trace package, which sits on the shared crate
//! built with `--cfg ufat_trace`.

extern crate cpio_trace as cpio;

#[path = "../../common/temp.rs"]
mod common;

use std::fs::{self, File};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use common::Temp;
use cpio::device::{Access, Device};
use cpio::errno::ESTALE;
use cpio::header::{Format, Kind, STOPPER};
use cpio::host::open_dir;
use cpio::name::Name;
use cpio::plan::{Plan, TreeOptions};
use cpio::populate;
use cpio::read::{Damage, End, Foreign, Source};
use cpio::times::TimePolicy;
use cpio::tree::Tree;
use cpio::write::{self, Attributes};

const SECTOR: usize = 512;

/// The name `bytes` are. The tests know them to be one.
fn named(bytes: &[u8]) -> Name<'_> {
    Name::new(bytes).unwrap()
}
/// Subsets of the writes between two flushes that are tried, at most.
const SUBSET_CAP: usize = 1 << 12;

/// One record of the device trace; see `Device::trace_to`.
#[derive(Clone, Debug)]
enum Record {
    Write { offset: u64, data: Vec<u8> },
    Zero { offset: u64, len: u64 },
    Length(u64),
    Barrier,
}

fn read_trace(path: &Path) -> Vec<Record> {
    let bytes = fs::read(path).unwrap();
    let mut records = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let tag = bytes[pos];
        let offset = u64::from_le_bytes(bytes[pos + 1..pos + 9].try_into().unwrap());
        let len = u64::from_le_bytes(bytes[pos + 9..pos + 17].try_into().unwrap());
        pos += 17;
        match tag {
            b'W' => {
                records.push(Record::Write {
                    offset,
                    data: bytes[pos..pos + len as usize].to_vec(),
                });
                pos += len as usize;
            }
            b'Z' => records.push(Record::Zero { offset, len }),
            b'L' => records.push(Record::Length(offset)),
            b'F' | b'S' => records.push(Record::Barrier),
            other => panic!("unknown trace record tag {:#x}", other),
        }
    }
    records
}

fn apply(image: &mut Vec<u8>, record: &Record) {
    match record {
        Record::Write { offset, data } => {
            let end = *offset as usize + data.len();
            if image.len() < end {
                image.resize(end, 0);
            }
            image[*offset as usize..end].copy_from_slice(data);
        }
        Record::Zero { offset, len } => image[*offset as usize..(*offset + *len) as usize].fill(0),
        Record::Length(len) => image.resize(*len as usize, 0),
        Record::Barrier => {}
    }
}

/// How often the device was told to put what was written on it for good.
fn barriers(records: &[Record]) -> usize {
    records
        .iter()
        .filter(|record| matches!(record, Record::Barrier))
        .count()
}

/// What an archive unpacks to, to tell two of them apart.
type Unpacked = Vec<(Vec<u8>, Kind, [u32; 7], Vec<u8>)>;

fn unpacked(tree: &Tree, image: &[u8]) -> Unpacked {
    tree.entries()
        .map(|(name, inode)| {
            let data = &image[inode.data_offset as usize..][..inode.size as usize];
            let numbers = [
                inode.mode,
                inode.uid,
                inode.gid,
                inode.mtime,
                inode.nlink,
                inode.rdev.major,
                inode.rdev.minor,
            ];
            (name, inode.kind, numbers, data.to_vec())
        })
        .collect()
}

/// What an image is to its readers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum State {
    /// The archive as it was.
    Old,
    /// The archive as it was, with something behind its trailer that is
    /// no archive. That is what is there while a failed call puts the
    /// archive back: the kernel says that unpacking failed, and readers
    /// that stop at the trailer see the archive as it was.
    OldFollowed,
    /// The archive as it was, stopped where its trailer was.
    Stopped,
    /// All that was added, stopped at the new trailer.
    Late,
    /// The archive with all that was added.
    New,
}

struct Scenario {
    before: Vec<u8>,
    after: Vec<u8>,
    old: Unpacked,
    new: Unpacked,
    old_trailer: u64,
    new_trailer: u64,
}

impl Scenario {
    fn new(before: Vec<u8>, after: Vec<u8>) -> Scenario {
        let old_tree = Tree::open(&before[..]).unwrap();
        let new_tree = Tree::open(&after[..]).unwrap();
        Scenario {
            old: unpacked(&old_tree, &before),
            new: unpacked(&new_tree, &after),
            old_trailer: old_tree.trailer_offset().unwrap(),
            new_trailer: new_tree.trailer_offset().unwrap(),
            before,
            after,
        }
    }

    fn classify(&self, image: &[u8]) -> Result<State, String> {
        let (tree, damage) = Tree::replay(image, &mut |_| {}).map_err(|e| format!("the image is not read: {}", e))?;
        let found = unpacked(&tree, image);
        let which = if found == self.old {
            Some(false)
        } else if found == self.new {
            Some(true)
        } else {
            None
        };
        match (damage, which) {
            (None, Some(new)) => {
                let follows = match tree.end() {
                    End::Trailer(end) => image.first_nonzero(end).unwrap().is_some(),
                    End::NoTrailer => false,
                };
                match (new, follows) {
                    (false, false) => Ok(State::Old),
                    (false, true) => Ok(State::OldFollowed),
                    (true, false) => Ok(State::New),
                    (true, true) => Err("something follows the new trailer".into()),
                }
            }
            (Some(Damage::Magic { offset, .. }), Some(new)) if image[offset as usize] == STOPPER => {
                if !new && offset == self.old_trailer {
                    Ok(State::Stopped)
                } else if new && offset == self.new_trailer {
                    Ok(State::Late)
                } else {
                    Err(format!(
                        "stopped at offset {} with the {} entries",
                        offset,
                        if new { "new" } else { "old" }
                    ))
                }
            }
            (damage, which) => Err(format!(
                "damage {:?}, and it unpacks to {}",
                damage,
                match which {
                    Some(false) => "the old archive",
                    Some(true) => "the new archive",
                    None => "neither the old nor the new archive",
                }
            )),
        }
    }

    /// Replays the trace into every state the three models allow, and
    /// returns the states that came up while the writes landed in order.
    /// A state that is none of `allowed` is a failure.
    fn check(&self, records: &[Record], allowed: &[State]) -> Vec<State> {
        let mut failures = Vec::new();
        let mut in_order = Vec::new();
        let seen = every_state(
            &self.before,
            &self.after,
            records,
            &mut |what, image, ordered| match self.classify(image) {
                Ok(state) if allowed.contains(&state) => {
                    if ordered {
                        in_order.push(state);
                    }
                }
                Ok(state) => failures.push(format!("{}: {:?}", what, state)),
                Err(e) => failures.push(format!("{}: {}", what, e)),
            },
        );
        assert!(
            failures.is_empty(),
            "{} of {} states:\n{}",
            failures.len(),
            seen,
            failures.join("\n")
        );
        eprintln!("{} states checked", seen);
        in_order
    }
}

/// Replays `records` on the image `before` into every state the three
/// models allow and shows each of them to `see`, with a word on how it
/// comes to be and whether it is one of the writes landing whole and in
/// order. The trace has to lead to `after`. Returns how many states there
/// were.
fn every_state(before: &[u8], after: &[u8], records: &[Record], see: &mut dyn FnMut(&str, &[u8], bool)) -> usize {
    let mut seen = 0usize;
    let mut show = |what: String, image: &[u8], ordered: bool| {
        seen += 1;
        see(&what, image, ordered);
    };
    // Every write lands whole, in order.
    let mut image = before.to_vec();
    show("before the first write".into(), &image, true);
    for (index, record) in records.iter().enumerate() {
        // A write of several sectors stops at a sector boundary.
        if let Record::Write { offset, data } = record {
            let first = SECTOR - *offset as usize % SECTOR;
            let boundaries: Vec<usize> = (first..data.len()).step_by(SECTOR).collect();
            for (nth, &cut) in boundaries.iter().enumerate() {
                // All boundaries near the ends of a write, a sample of
                // the ones between.
                if nth >= 16 && nth + 16 < boundaries.len() && nth % 61 != 0 {
                    continue;
                }
                let mut torn = image.clone();
                apply(
                    &mut torn,
                    &Record::Write {
                        offset: *offset,
                        data: data[..cut].to_vec(),
                    },
                );
                show(format!("record {} torn after {} bytes", index, cut), &torn, false);
            }
        }
        apply(&mut image, record);
        show(format!("after record {}", index), &image, true);
    }
    assert!(image == after, "the trace does not lead to the image that was written");
    // Between two flushes the device keeps any subset of the writes.
    let mut image = before.to_vec();
    for epoch in records.split(|record| matches!(record, Record::Barrier)) {
        let subsets = 1usize << epoch.len().min(usize::BITS as usize - 1);
        let step = subsets.div_ceil(SUBSET_CAP);
        for subset in (0..subsets).step_by(step) {
            let mut kept = image.clone();
            for (bit, record) in epoch.iter().enumerate() {
                if (subset >> bit) & 1 == 1 {
                    apply(&mut kept, record);
                }
            }
            show(
                format!("an epoch of {} records with the subset {:#x}", epoch.len(), subset),
                &kept,
                false,
            );
        }
        for record in epoch {
            apply(&mut image, record);
        }
    }
    seen
}

const T: u64 = 1_577_934_245;

fn fixed() -> TreeOptions {
    TreeOptions {
        times: TimePolicy::Fixed(UNIX_EPOCH + Duration::from_secs(T)),
        uid: Some(0),
        gid: Some(0),
        replace: true,
    }
}

const DIRECTORY: Attributes = Attributes {
    mode: 0o755,
    uid: 0,
    gid: 0,
    mtime: T as u32,
};

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// An archive of a small tree.
fn first(layout: &write::Options) -> Vec<u8> {
    let tree = Temp::dir();
    fs::create_dir_all(tree.path().join("etc")).unwrap();
    fs::write(tree.path().join("etc/conf"), b"old").unwrap();
    fs::write(tree.path().join("init"), b"#!/bin/sh\n").unwrap();
    fs::write(tree.path().join("a"), pattern(3000, 1)).unwrap();
    fs::hard_link(tree.path().join("a"), tree.path().join("b")).unwrap();
    let mut plan = Plan::new();
    plan.add_directory(named(b"."), DIRECTORY).unwrap();
    plan.add_tree(open_dir(tree.path()).unwrap().as_fd(), named(b"."), &fixed())
        .unwrap();
    let measure = plan.measure(layout, 0, &|_| false).unwrap();
    let image = Temp::new(".cpio");
    let window = measure
        .make_room(Device::create(image.path()).unwrap(), 0, None)
        .unwrap();
    plan.assemble(&window, layout, &measure, &mut |_| {}).unwrap();
    fs::read(image.path()).unwrap()
}

/// A tree to add: more than the writer collects before it writes, so that
/// what is added reaches the device in several writes.
fn second() -> Temp {
    let tree = Temp::dir();
    fs::create_dir_all(tree.path().join("etc")).unwrap();
    fs::write(tree.path().join("etc/conf"), b"new and longer").unwrap();
    fs::create_dir_all(tree.path().join("lib")).unwrap();
    fs::write(tree.path().join("lib/big"), pattern(1_300_000, 2)).unwrap();
    fs::write(tree.path().join("lib/more"), pattern(900_000, 3)).unwrap();
    fs::hard_link(tree.path().join("lib/more"), tree.path().join("lib/more-link")).unwrap();
    fs::write(tree.path().join("small"), b"small").unwrap();
    tree
}

/// Adds `tree` to the archive `before` on a traced device. Returns the
/// trace, the image that is left, and what the call returned.
fn add(before: &[u8], tree: &Path, spoil: bool) -> (Vec<Record>, Vec<u8>, cpio::Result<()>) {
    let image = Temp::new(".cpio");
    fs::write(image.path(), before).unwrap();
    let trace = Temp::new(".trace");
    let mut plan = Plan::new();
    plan.add_tree(open_dir(tree).unwrap().as_fd(), named(b"."), &fixed())
        .unwrap();
    if spoil {
        // The last file to be read is not the one that was planned.
        fs::write(tree.join("small"), b"another one").unwrap();
    }
    let mut device = Device::open(image.path(), Access::ReadWrite).unwrap();
    device.trace_to(File::create(trace.path()).unwrap());
    let result = plan
        .populate(&mut device, 0, None, &populate::Options::default(), &mut |_| {})
        .map(|_| ());
    drop(device);
    (read_trace(trace.path()), fs::read(image.path()).unwrap(), result)
}

#[test]
fn adding_is_old_or_new_or_stopped_at_every_point() {
    let _serial = common::serial();
    let layouts = [
        write::Options::default(),
        // With checksums, which are written into the headers afterwards.
        write::Options {
            format: Format::Crc,
            end_alignment: 4096,
            data_alignment: 4096,
        },
    ];
    for layout in layouts {
        let packed = first(&layout);
        // An image the archive fills, one with room behind it, and an
        // archive without its trailer.
        let mut roomy = packed.clone();
        roomy.resize(4 << 20, 0);
        let trailer = Tree::open(&packed[..]).unwrap().trailer_offset().unwrap() as usize;
        for before in [packed.clone(), roomy, packed[..trailer].to_vec()] {
            let tree = second();
            let (records, after, result) = add(&before, tree.path(), false);
            result.unwrap();
            let writes = records
                .iter()
                .filter(|record| matches!(record, Record::Write { .. }))
                .count();
            assert!(writes >= 5, "only {} writes", writes);
            // The stop, what is added, its first byte and the first byte
            // of its trailer: each is on the device for good before the
            // next one is written.
            assert_eq!(barriers(&records), 4);
            let mut scenario = Scenario::new(before, after);
            if scenario.old_trailer as usize == scenario.before.len() {
                // Without a trailer the archive is not stopped at one, but
                // at its end.
                scenario.old_trailer = trailer as u64;
            }
            let in_order = scenario.check(&records, &[State::Old, State::Stopped, State::Late, State::New]);
            // From old to new, through both stops, and never back.
            assert!(in_order.windows(2).all(|pair| pair[0] <= pair[1]), "{:?}", in_order);
            for state in [State::Old, State::Stopped, State::Late, State::New] {
                assert!(in_order.contains(&state), "{:?} never came up: {:?}", state, in_order);
            }
        }
    }
}

/// A call that fails puts the archive back, through states that are the
/// old archive to every reader, with or without a complaint.
#[test]
fn a_failed_call_goes_back_to_old_at_every_point() {
    let _serial = common::serial();
    let packed = first(&write::Options::default());
    let mut roomy = packed.clone();
    roomy.resize(4 << 20, 0);
    for before in [packed, roomy] {
        let tree = second();
        let (records, after, result) = add(&before, tree.path(), true);
        assert_eq!(result.unwrap_err().errno(), ESTALE);
        assert!(after == before, "the archive is not as it was");
        // The new archive never comes to be: there is none to hold the
        // states against, so the old one stands in.
        let scenario = Scenario::new(before.clone(), before);
        let in_order = scenario.check(&records, &[State::Old, State::OldFollowed, State::Stopped]);
        assert!(in_order.contains(&State::Stopped), "{:?}", in_order);
        assert_eq!(in_order.last(), Some(&State::Old));
    }
}

/// What an image is to the kernel while an archive is written into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Written {
    /// What the image held, with or without the room that was made for
    /// the archive.
    Before,
    /// Something that is stopped at its first byte: nothing of it is
    /// unpacked.
    Stopped,
    /// The archive.
    Whole,
}

/// An archive that is written to `size` bytes at `offset` of an image, or
/// to all there is from `offset` on.
struct Writing {
    before: Vec<u8>,
    /// The image with the archive in it. None when the call fails.
    whole: Option<Vec<u8>>,
    offset: usize,
    size: Option<usize>,
}

impl Writing {
    fn classify(&self, image: &[u8]) -> Result<Written, String> {
        let end = self.size.map_or(image.len(), |size| self.offset + size);
        // What is in front of the archive and behind the room it has is
        // never touched.
        let front = self.offset.min(self.before.len());
        if image.len() < front || image[..front] != self.before[..front] {
            return Err("what is in front of the archive changed".into());
        }
        if self.size.is_some() && image.get(end..) != self.before.get(end..) {
            return Err("what is behind the room of the archive changed".into());
        }
        let archive = image.get(self.offset..end.min(image.len())).unwrap_or(&[]);
        if archive.first() == Some(&STOPPER) {
            // The reader, which is held against kernels, has nothing of
            // it unpacked and the kernel failing at the first byte.
            return match Tree::replay(archive, &mut |_| {}) {
                Ok((tree, Some(Damage::Magic { offset: 0, .. }))) if tree.records() == 0 => Ok(Written::Stopped),
                Ok((tree, damage)) => Err(format!(
                    "stopped at the first byte, with {} entries read and damage {:?}",
                    tree.records(),
                    damage
                )),
                Err(e) => Err(format!("the image is not read: {}", e)),
            };
        }
        if self.whole.as_deref() == Some(image) {
            return Ok(Written::Whole);
        }
        // Room that was made is NUL bytes behind what was there.
        let kept = self.before.len().min(image.len());
        if image[..kept] == self.before[..kept]
            && image.len() >= self.before.len()
            && image[kept..].iter().all(|&b| b == 0)
        {
            return Ok(Written::Before);
        }
        Err("it is neither what the image held, nor stopped, nor the archive".into())
    }

    /// Replays the trace into every state the three models allow, and
    /// returns the states that came up while the writes landed in order.
    fn check(&self, records: &[Record], after: &[u8]) -> Vec<Written> {
        let mut failures = Vec::new();
        let mut in_order = Vec::new();
        let seen = every_state(
            &self.before,
            after,
            records,
            &mut |what, image, ordered| match self.classify(image) {
                Ok(state) => {
                    if ordered {
                        in_order.push(state);
                    }
                }
                Err(e) => failures.push(format!("{}: {}", what, e)),
            },
        );
        assert!(
            failures.is_empty(),
            "{} of {} states:\n{}",
            failures.len(),
            seen,
            failures.join("\n")
        );
        eprintln!("{} states checked", seen);
        in_order
    }
}

/// Writes the archive of `tree` to `size` bytes at `offset` of the image
/// `before`, on a traced device. Returns the trace, the image that is
/// left, and what the call returned.
fn write(
    before: &[u8],
    offset: u64,
    size: Option<u64>,
    tree: &Path,
    layout: &write::Options,
    spoil: bool,
) -> (Vec<Record>, Vec<u8>, cpio::Result<()>) {
    let image = Temp::new(".cpio");
    fs::write(image.path(), before).unwrap();
    let trace = Temp::new(".trace");
    let mut plan = Plan::new();
    plan.add_directory(named(b"."), DIRECTORY).unwrap();
    plan.add_tree(open_dir(tree).unwrap().as_fd(), named(b"."), &fixed())
        .unwrap();
    let measure = plan.measure(layout, 0, &|_| false).unwrap();
    if spoil {
        // The last file to be read is not the one that was planned.
        fs::write(tree.join("small"), b"another one").unwrap();
    }
    let mut device = Device::open(image.path(), Access::ReadWrite).unwrap();
    device.trace_to(File::create(trace.path()).unwrap());
    let window = measure.make_room(device, offset, size).unwrap();
    let result = plan.assemble(&window, layout, &measure, &mut |_| {}).map(|_| ());
    drop(window);
    (read_trace(trace.path()), fs::read(image.path()).unwrap(), result)
}

/// The images an archive is written into: an empty one, one that holds a
/// smaller archive, one that holds more than the archive needs, and room
/// of a size in the middle of an image, at an offset that is no multiple
/// of anything.
fn images(layout: &write::Options) -> Vec<(Vec<u8>, u64, Option<u64>)> {
    let small = first(layout);
    let mut large = small.clone();
    large.resize(4 << 20, 0);
    // Entries that the kernel would take, far behind the start.
    large[3 << 20..][..small.len()].copy_from_slice(&small);
    let mut middle = vec![0x55u8; 510];
    middle.extend_from_slice(&large);
    middle.extend_from_slice(&[0x66u8; 4096]);
    vec![
        (Vec::new(), 0, None),
        (small, 0, None),
        (large.clone(), 0, None),
        (middle, 510, Some(large.len() as u64)),
    ]
}

#[test]
fn writing_is_before_or_stopped_or_whole_at_every_point() {
    let _serial = common::serial();
    let layouts = [
        write::Options::default(),
        // With checksums, which are written into the headers afterwards.
        write::Options {
            format: Format::Crc,
            end_alignment: 4096,
            data_alignment: 4096,
        },
    ];
    for layout in layouts {
        for (before, offset, size) in images(&layout) {
            let tree = second();
            let (records, after, result) = write(&before, offset, size, tree.path(), &layout, false);
            result.unwrap();
            let writes = records
                .iter()
                .filter(|record| matches!(record, Record::Write { .. }))
                .count();
            assert!(writes >= 4, "only {} writes", writes);
            // The stop, the archive and its first byte: each is on the
            // device for good before the next one is written.
            assert_eq!(barriers(&records), 3);
            let writing = Writing {
                before,
                whole: Some(after.clone()),
                offset: offset as usize,
                size: size.map(|size| size as usize),
            };
            let in_order = writing.check(&records, &after);
            // From what was there to the archive, through the stop, and
            // never back.
            assert!(in_order.windows(2).all(|pair| pair[0] <= pair[1]), "{:?}", in_order);
            for state in [Written::Before, Written::Stopped, Written::Whole] {
                assert!(in_order.contains(&state), "{:?} never came up: {:?}", state, in_order);
            }
            // The archive is one, and it is all there is in its room.
            let end = size.map_or(after.len(), |size| (offset + size) as usize);
            let archive = &after[offset as usize..end];
            let whole = Tree::open(archive).unwrap();
            assert!(whole.get(b"lib/more-link").is_some());
            let End::Trailer(trailer) = whole.end() else {
                panic!("no trailer");
            };
            assert_eq!(archive.first_nonzero(trailer).unwrap(), None);
        }
    }
}

/// A call that fails leaves the image stopped, and it is stopped from the
/// first write on.
#[test]
fn a_failed_call_leaves_the_image_stopped() {
    let _serial = common::serial();
    let layout = write::Options::default();
    for (before, offset, size) in images(&layout) {
        let tree = second();
        let (records, after, result) = write(&before, offset, size, tree.path(), &layout, true);
        assert_eq!(result.unwrap_err().errno(), ESTALE);
        // Only the stop was put on the device for good.
        assert_eq!(barriers(&records), 1);
        let writing = Writing {
            before,
            whole: None,
            offset: offset as usize,
            size: size.map(|size| size as usize),
        };
        let in_order = writing.check(&records, &after);
        assert!(in_order.windows(2).all(|pair| pair[0] <= pair[1]), "{:?}", in_order);
        assert_eq!(in_order.first(), Some(&Written::Before));
        assert_eq!(in_order.last(), Some(&Written::Stopped));
        // A check calls what is left an archive that was not finished.
        let end = size.map_or(after.len(), |size| (offset + size) as usize);
        let report = cpio::check::check(&after[offset as usize..end]).unwrap();
        assert_eq!((report.records, report.errors()), (0, 1));
        assert_eq!(report.problems[0].found, Some(Foreign::Unfinished));
    }
}
