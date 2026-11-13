// SPDX-License-Identifier: LGPL-2.1-or-later
//! Temporary images, directories and volumes for the tests.
use crate::device::{Access, Device};
use crate::format::{self, FormatOptions};
use crate::volume::Volume;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A path in the temporary directory that no other test of this process
/// uses.
fn unique(name: &str) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("ufat-test-{}-{}-{}", std::process::id(), n, name))
}

/// A temporary image file, removed on drop.
pub(crate) struct TempImage(PathBuf);

impl TempImage {
    /// A sparse image of `size` bytes.
    pub(crate) fn new(size: u64) -> TempImage {
        let path = unique("img");
        fs::File::create(&path).unwrap().set_len(size).unwrap();
        TempImage(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    /// The image, opened for writing.
    pub(crate) fn device(&self) -> Device {
        Device::open(&self.0, Access::ReadWrite).unwrap()
    }
}

impl Drop for TempImage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// A temporary directory, removed with everything in it on drop.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new(name: &str) -> TempDir {
        let path = unique(name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The options [`volume`] formats with.
pub(crate) fn format_options(sector_size: u32, cluster_size: u32) -> FormatOptions {
    FormatOptions {
        sector_size: Some(sector_size),
        cluster_size: Some(cluster_size),
        allow_small: true,
        volume_id: 0x1234_abcd,
        label: Some("TEST".into()),
        ..FormatOptions::default()
    }
}

/// A freshly formatted volume of `size` bytes in a temporary image.
pub(crate) fn volume(size: u64, sector_size: u32, cluster_size: u32) -> (TempImage, Volume) {
    let img = TempImage::new(size);
    format::format(&img.device(), &format_options(sector_size, cluster_size)).unwrap();
    let vol = Volume::open(img.device()).unwrap();
    (img, vol)
}
