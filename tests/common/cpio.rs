// SPDX-License-Identifier: LGPL-2.1-or-later
//! The trees the `made-*` archives of tests/fixtures/cpio are made of.
//! Everything about them is set here, down to the mode of every
//! directory, so that an archive of them is the same wherever it is made.
#![allow(dead_code, unreachable_pub)]

use std::fs::{self, Permissions};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

/// 2020-01-02T03:04:05Z, the time of everything in the archives.
pub const T: u64 = 1_577_934_245;

pub fn dir(path: PathBuf, mode: u32) {
    fs::create_dir_all(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
}

pub fn put(path: PathBuf, contents: &[u8], mode: u32) {
    fs::write(&path, contents).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
}

/// Contents that are not the same anywhere.
pub fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// The tree the archives are assembled from.
pub fn first_tree(root: &Path) {
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
pub fn second_tree(root: &Path) {
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
