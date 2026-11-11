// SPDX-License-Identifier: LGPL-2.1-or-later
//! What ucpio writes, against archives a kernel unpacked.
//!
//! The `made-*` archives in tests/fixtures/cpio are ucpio's own. This test
//! builds each of them again from a tree it makes and holds the result
//! against the file, byte for byte. tests/cpio_kernel.rs holds the tree of
//! the same file against what a kernel unpacked it to. Together they say
//! that what is written here is unpacked by a kernel the way ucpio says.
//!
//! When the bytes change on purpose, write the files again with
//! UCPIO_BLESS=1 set and record what a kernel makes of them with
//! tests/fixtures/cpio/make-fixtures.py.

mod common;

use std::fs::{self, File, Permissions};
use std::os::fd::AsFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use common::Temp;
use cpio::check::{self, ProblemKind};
use cpio::device::{Access, Device};
use cpio::header::Format;
use cpio::header::STOPPER;
use cpio::host::open_dir;
use cpio::name::Name;
use cpio::plan::{Plan, TreeOptions};
use cpio::populate;
use cpio::times::TimePolicy;
use cpio::tree::Tree;
use cpio::write::{self, Attributes};

/// The name `bytes` are. The tests know them to be one.
fn named(bytes: &[u8]) -> Name<'_> {
    Name::new(bytes).unwrap()
}

/// 2020-01-02T03:04:05Z.
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

fn dir(path: PathBuf, mode: u32) {
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
}

fn put(path: PathBuf, contents: &[u8], mode: u32) {
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
}

/// Contents that are not the same anywhere.
fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The tree the archives are assembled from.
fn first_tree(root: &Path) {
    dir(root.join("bin"), 0o755);
    put(root.join("bin/tool"), b"#!/bin/sh\nexit 0\n", 0o755);
    put(root.join("bin/setuid"), b"s", 0o4755);
    dir(root.join("etc"), 0o755);
    put(root.join("etc/conf"), b"old\n", 0o644);
    put(root.join("etc/keep"), b"keep\n", 0o600);
    put(root.join("etc/empty"), b"", 0o644);
    dir(root.join("lib"), 0o755);
    put(root.join("lib/a.so"), &pattern(5000, 1), 0o644);
    fs::hard_link(root.join("lib/a.so"), root.join("lib/b.so")).unwrap();
    fs::hard_link(root.join("lib/a.so"), root.join("etc/a-link")).unwrap();
    put(root.join("big"), &pattern(9000, 2), 0o644);
    symlink("etc/conf", root.join("link")).unwrap();
    symlink("bin", root.join("sbin")).unwrap();
    symlink("nowhere", root.join("dangling")).unwrap();
    dir(root.join("empty"), 0o700);
    dir(root.join("tmp"), 0o1777);
    dir(root.join("run"), 0o755);
    drop(UnixListener::bind(root.join("run/sock")).unwrap());
    fs::set_permissions(root.join("run/sock"), Permissions::from_mode(0o600)).unwrap();
}

/// The tree that is added.
fn second_tree(root: &Path) {
    dir(root.join("etc"), 0o700);
    put(root.join("etc/conf"), b"new and longer\n", 0o640);
    put(root.join("etc/added"), b"added\n", 0o644);
    dir(root.join("usr"), 0o755);
    dir(root.join("usr/share"), 0o755);
    dir(root.join("usr/share/doc"), 0o755);
    put(root.join("usr/share/doc/readme"), b"read me\n", 0o444);
    dir(root.join("lib"), 0o755);
    put(root.join("lib/c.so"), &pattern(4500, 3), 0o644);
    fs::hard_link(root.join("lib/c.so"), root.join("lib/d.so")).unwrap();
    symlink("bin/tool", root.join("link2")).unwrap();
    dir(root.join("empty"), 0o755);
    put(root.join("empty/now-filled"), b"x", 0o644);
    // A file where a symbolic link is.
    put(root.join("link"), b"a file where a link was\n", 0o644);
}

fn assembled(tree: &Path, layout: &write::Options) -> Temp {
    let mut plan = Plan::new();
    plan.add_directory(named(b"."), DIRECTORY).unwrap();
    plan.add_tree(open_dir(tree).unwrap().as_fd(), named(b"."), &fixed())
        .unwrap();
    let measure = plan.measure(layout, 0, &|_| false).unwrap();
    let image = Temp::new(".cpio");
    let window = measure
        .make_room(Device::create(image.path()).unwrap(), 0, None)
        .unwrap();
    let report = plan.assemble(&window, layout, &measure, &mut |_| {}).unwrap();
    assert_eq!(report.len, fs::metadata(image.path()).unwrap().len());
    image
}

fn added(image: &Temp, plan: &mut Plan, options: &populate::Options) {
    let mut device = Device::open(image.path(), Access::ReadWrite).unwrap();
    let report = plan.populate(&mut device, 0, None, options, &mut |_| {}).unwrap();
    drop(device);
    assert_eq!(report.len, fs::metadata(image.path()).unwrap().len());
}

fn aligned() -> write::Options {
    write::Options {
        format: Format::Crc,
        end_alignment: 4096,
        data_alignment: 4096,
    }
}

/// Every archive with its name among the fixtures.
fn made() -> Vec<(&'static str, Vec<u8>)> {
    let first = Temp::dir();
    first_tree(first.path());
    let second = Temp::dir();
    second_tree(second.path());
    let mut archives = Vec::new();
    let keep = |archives: &mut Vec<_>, name, image: &Temp| archives.push((name, fs::read(image.path()).unwrap()));

    let plain = assembled(first.path(), &write::Options::default());
    keep(&mut archives, "made-assemble", &plain);
    let before = fs::read(plain.path()).unwrap();
    let checked = assembled(first.path(), &aligned());
    keep(&mut archives, "made-assemble-aligned", &checked);
    // What is in the image when writing an archive is cut off or fails,
    // see cpio::image::StoppedSink: the image is stopped at its first
    // byte, with nothing of the archive behind the stopped magic at first
    // and all of it but its first byte in the end.
    // tests/crash/cpio/crash.rs has that these are the states that come
    // up.
    let mut cut = vec![0u8; before.len()];
    cut[..6].copy_from_slice(&Format::Newc.stopped_magic());
    archives.push(("made-assemble-cut-early", cut));
    let mut cut = before.clone();
    cut[0] = STOPPER;
    archives.push(("made-assemble-cut", cut));

    // A tree over the root of what is there.
    let over = |image: &Temp, options: &populate::Options| {
        let mut plan = Plan::new();
        plan.add_tree(open_dir(second.path()).unwrap().as_fd(), named(b"."), &fixed())
            .unwrap();
        added(image, &mut plan, options);
    };
    over(&plain, &populate::Options::default());
    keep(&mut archives, "made-populate", &plain);
    // What is in the image when adding to it is cut off, see
    // cpio::image::SpliceSink: the archive is stopped where its trailer
    // was, with the beginning of what is added behind the stopper or all
    // of it, and at the end it is stopped at the new trailer only.
    // tests/crash/cpio/crash.rs has that these are the states that come
    // up.
    let after = fs::read(plain.path()).unwrap();
    let old_trailer = Tree::open(&before[..]).unwrap().trailer_offset().unwrap() as usize;
    let new_trailer = Tree::open(&after[..]).unwrap().trailer_offset().unwrap() as usize;
    let mut cut = before.clone();
    cut.resize(after.len(), 0);
    cut[old_trailer] = STOPPER;
    cut[old_trailer + 1..old_trailer + 3001].copy_from_slice(&after[old_trailer + 1..old_trailer + 3001]);
    archives.push(("made-populate-cut-early", cut));
    let mut cut = after.clone();
    cut[old_trailer] = STOPPER;
    cut[new_trailer] = STOPPER;
    archives.push(("made-populate-cut", cut.clone()));
    cut[old_trailer] = after[old_trailer];
    archives.push(("made-populate-cut-late", cut));
    let options = populate::Options {
        end_alignment: 4096,
        data_alignment: 4096,
        replace: true,
    };
    over(&checked, &options);
    keep(&mut archives, "made-populate-aligned", &checked);

    // A tree below a new directory and one file, added to what was added.
    let mut plan = Plan::new();
    plan.add_directory(named(b"opt"), DIRECTORY).unwrap();
    plan.add_directory(named(b"opt/pkg"), DIRECTORY).unwrap();
    plan.add_tree(open_dir(second.path()).unwrap().as_fd(), named(b"opt/pkg"), &fixed())
        .unwrap();
    plan.add_file(
        named(b"etc/motd"),
        File::open(second.path().join("usr/share/doc/readme")).unwrap(),
        &fixed(),
    )
    .unwrap();
    added(&plain, &mut plan, &populate::Options::default());
    keep(&mut archives, "made-populate-twice", &plain);
    archives
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cpio")
        .join(format!("{}.cpio", name))
}

#[test]
fn what_is_written_is_what_a_kernel_unpacked() {
    let _serial = common::serial();
    let bless = std::env::var_os("UCPIO_BLESS").is_some();
    for (name, bytes) in made() {
        let path = fixture(name);
        if bless {
            fs::write(&path, &bytes).unwrap();
            continue;
        }
        let kept = fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
        let differs = kept.iter().zip(&bytes).position(|(a, b)| a != b);
        assert!(
            kept == bytes,
            "{} is {} bytes and is written as {} bytes now, the first difference is at {:?}: \
             no kernel has unpacked these bytes, see the top of tests/cpio_made.rs",
            path.display(),
            kept.len(),
            bytes.len(),
            differs
        );
    }
}

/// A second run writes the same bytes, and a check has nothing to say
/// about them but that a later entry takes the place of an earlier one.
#[test]
fn what_is_written_is_sound_and_the_same_every_time() {
    let _serial = common::serial();
    let first = made();
    let second = made();
    assert_eq!(first.len(), second.len());
    for ((name, bytes), (_, again)) in first.iter().zip(&second) {
        assert!(bytes == again, "{} is not written the same twice", name);
        let report = check::check(&bytes[..]).unwrap();
        let kinds: Vec<ProblemKind> = report.problems.iter().map(|p| p.kind).collect();
        if name.starts_with("made-populate-cut") || name.starts_with("made-assemble-cut") {
            // The check says what the kernel says: no entry where the
            // archive is stopped.
            assert_eq!(kinds.last(), Some(&ProblemKind::NoMagic), "{}", name);
            if name.starts_with("made-assemble-cut") {
                // Stopped at its first byte, it has nothing unpacked.
                assert_eq!((report.records, kinds.len()), (0, 1), "{}", name);
            }
            assert!(kinds
                .iter()
                .all(|kind| matches!(kind, ProblemKind::NoMagic | ProblemKind::Replaced)));
            continue;
        }
        if name.starts_with("made-assemble") {
            assert_eq!(kinds, [], "{}", name);
        } else {
            assert!(!kinds.is_empty(), "{}", name);
            assert!(
                kinds.iter().all(|kind| *kind == ProblemKind::Replaced),
                "{}: {:?}",
                name,
                kinds
            );
        }
        assert_eq!(report.errors(), 0, "{}", name);
    }
}
