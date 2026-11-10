// SPDX-License-Identifier: LGPL-2.1-or-later
//! Formats the small FAT32 images the mutation harness starts from. The
//! command line tool makes no volume below the 65525 cluster floor, and the
//! harness wants images of a few megabytes it can read whole, so the seeds
//! come from the library with `allow_small` set, the way the test fixtures
//! do. tests/fuzz/seeds.sh runs this and fills the image with `ufat
//! populate`.
//!
//!     fuzz-seeds IMAGE SIZE SECTOR_SIZE CLUSTER_SIZE LABEL
//!
//! IMAGE is created or truncated to SIZE bytes (K, M and G suffixes), the
//! two sizes are in bytes. The time stamp is $SOURCE_DATE_EPOCH or the
//! epoch and the volume id is derived from the geometry, so the same
//! arguments give the same image.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use ufat::device::{Access, Device};
use ufat::format::{self, FormatOptions};

fn size(s: &str) -> Option<u64> {
    let (digits, factor) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1u64 << 10),
        b'M' | b'm' => (&s[..s.len() - 1], 1 << 20),
        b'G' | b'g' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(factor)
}

fn run(args: &[String]) -> Result<(), String> {
    let path = Path::new(&args[1]);
    let bytes = size(&args[2]).ok_or_else(|| format!("{} is not a size", args[2]))?;
    let sector_size: u32 = args[3]
        .parse()
        .map_err(|_| format!("{} is not a sector size", args[3]))?;
    let cluster_size: u32 = args[4]
        .parse()
        .map_err(|_| format!("{} is not a cluster size", args[4]))?;
    let epoch: u64 = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(v) => v
            .parse()
            .map_err(|_| format!("SOURCE_DATE_EPOCH={} is not a number", v))?,
        Err(_) => 0,
    };
    std::fs::File::create(path)
        .and_then(|f| f.set_len(bytes))
        .map_err(|e| format!("{}: {}", path.display(), e))?;
    let device = Device::open(path, Access::ReadWrite).map_err(|e| e.to_string())?;
    let options = FormatOptions {
        sector_size: Some(sector_size),
        cluster_size: Some(cluster_size),
        label: Some(args[5].clone()),
        timestamp: Some(UNIX_EPOCH + Duration::from_secs(epoch)),
        volume_id: 0x5EED_0000
            | ((bytes >> 20) as u32 & 0xff)
            | (sector_size.trailing_zeros() << 8)
            | (cluster_size.trailing_zeros() << 12),
        allow_small: true,
        ..FormatOptions::default()
    };
    format::format(&device, &options).map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 6 {
        eprintln!("usage: fuzz-seeds IMAGE SIZE SECTOR_SIZE CLUSTER_SIZE LABEL");
        std::process::exit(2);
    }
    if let Err(e) = run(&args) {
        eprintln!("fuzz-seeds: {}", e);
        std::process::exit(1);
    }
}
