// SPDX-License-Identifier: LGPL-2.1-or-later
//! How many descriptors copying a tree holds open, counted in
//! /proc/self/fd.
//!
//! This test is the only one in its binary, so it has a process of its
//! own. Listing /proc/self/fd and reading its links takes a reference on
//! every open file of the process for a moment. When another thread closes
//! its last descriptor of a file in that moment, the file is only released
//! once the listing thread has dropped its reference and returned to user
//! space, and so is the BSD lock that file holds. A test in another thread
//! that opens the same image again right away then finds it locked
//! (EBUSY). Keep other tests out of this file.

mod common;

use std::fs;
use std::os::fd::AsFd;
use std::path::Path;

use common::Temp;
use fat::device::{Access, Device};
use fat::format::{self, FormatOptions};
use fat::host;
use fat::populate::CopyOptions;
use fat::volume::Volume;

/// The number of files in the directory the test copies, more than the
/// usual soft limit of 1024 descriptors.
const FILES: u64 = 1500;

/// The size of the image the tree is copied to.
const IMAGE_SIZE: u64 = 64 << 20;

/// The descriptors of this process that refer to something below `root`.
fn descriptors_below(root: &Path) -> usize {
    fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter(|e| match fs::read_link(e.as_ref().unwrap().path()) {
            Ok(target) => target.starts_with(root),
            Err(_) => false,
        })
        .count()
}

/// The walk pins one entry at a time and holds one directory per level,
/// so copying a large directory never needs more than a handful of
/// descriptors, and none is left open afterwards.
#[test]
fn a_large_directory_costs_no_descriptors() {
    let tree = Temp::dir();
    let root = tree.path();
    fs::create_dir(root.join("big")).unwrap();
    for i in 0..FILES {
        fs::write(root.join(format!("big/f{:04}", i)), b"x").unwrap();
    }
    let image = Temp::image(IMAGE_SIZE);
    format::format(
        &Device::open(image.path(), Access::ReadWrite).unwrap(),
        &FormatOptions::default(),
    )
    .unwrap();
    let mut v = Volume::open(Device::open(image.path(), Access::ReadWrite).unwrap()).unwrap();
    let fd = host::open_dir(root).unwrap();
    let mut most = 0;
    let report = v
        .copy_tree_with_progress(fd.as_fd(), "/", &CopyOptions::default(), &mut |_| {
            most = most.max(descriptors_below(root));
        })
        .unwrap();
    assert_eq!((report.directories, report.files, report.bytes), (1, FILES, FILES));
    // The test's own root descriptor, the walk's dup of it, the pinned
    // "big", the pinned entry being copied and the file opened from it.
    assert!(most <= 5, "{} descriptors open below the root", most);
    assert_eq!(descriptors_below(root), 1);
}
