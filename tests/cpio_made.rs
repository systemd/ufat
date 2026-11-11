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

use std::fs::{self, Permissions};
use std::os::fd::AsFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use common::Temp;
use cpio::check::{self, ProblemKind};
use cpio::device::Device;
use cpio::header::Format;
use cpio::header::STOPPER;
use cpio::host::open_dir;
use cpio::name::Name;
use cpio::plan::{Plan, TreeOptions};
use cpio::times::TimePolicy;
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
    let mut cut = vec![0u8; before.len()];
    cut[..6].copy_from_slice(&Format::Newc.stopped_magic());
    archives.push(("made-assemble-cut-early", cut));
    let mut cut = before.clone();
    cut[0] = STOPPER;
    archives.push(("made-assemble-cut", cut));
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
/// about them.
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
        if name.starts_with("made-assemble-cut") {
            // The check says what the kernel says: no entry where the
            // archive is stopped. Stopped at its first byte, it has
            // nothing unpacked.
            assert_eq!(kinds, [ProblemKind::NoMagic], "{}", name);
            assert_eq!(report.records, 0, "{}", name);
            continue;
        }
        assert_eq!(kinds, [], "{}", name);
    }
}
