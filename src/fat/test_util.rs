// SPDX-License-Identifier: LGPL-2.1-or-later
//! Temporary images, directories and volumes for the tests.
use crate::format::{self, FormatOptions};
use crate::volume::Volume;

// The images and directories are the ones the shared crate tests with.
#[path = "../shared/test_util.rs"]
mod host_side;
pub(crate) use host_side::{TempDir, TempImage};

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
