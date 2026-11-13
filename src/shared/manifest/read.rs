// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading a manifest into memory.

use std::io::Read;

use crate::{errno, Result};

/// The largest manifest read into memory. A record is at most 4 MiB and a
/// tree of a hundred thousand files describes itself in some tens of MiB,
/// so anything above this is not a manifest, an image given by mistake for
/// one, and is refused before it is read into memory.
pub const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;

/// Reads an open file to its end, refusing one of more than `limit` bytes
/// (EFBIG) instead of holding it in memory.
pub fn read_all(file: std::fs::File, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        bail!(errno::EFBIG, "more than {} bytes", limit);
    }
    Ok(data)
}
