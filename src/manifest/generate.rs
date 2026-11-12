// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing a manifest for a host tree, the way `systemd-manifest make`
//! writes it.

use std::io::{self, Write};
use std::os::fd::BorrowedFd;
use std::time::{SystemTime, UNIX_EPOCH};

use json::{Object, Value};

use super::{valid_name, MEDIA_TYPE, RECORD_SEPARATOR, TRAILER_MEDIA_TYPE};
use crate::host::Case;
use crate::sha256::{self, Sha256};
use crate::sys;
use crate::Result;

/// Writes one record of the JSON text sequence: the record separator, the
/// object with its keys sorted and without whitespace, a newline. The host
/// tree generator and the volume writer frame their records here, so both
/// write what `systemd-manifest` writes. Each record goes out in one write.
pub(crate) fn write_record(out: &mut dyn Write, mut o: Object) -> io::Result<()> {
    o.sort();
    let record = format!("{}{}\n", char::from(RECORD_SEPARATOR), Value::Object(o));
    out.write_all(record.as_bytes())
}

/// A time as `mTimeNSec` carries it: nanoseconds since the epoch. None for
/// a time the field cannot express, before the epoch or after the year
/// 2554.
pub(crate) fn time_nsec(time: SystemTime) -> Option<u64> {
    let since = time.duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since.as_nanos()).ok()
}

/// Builds a manifest for the host tree below the open directory `root` the
/// way `systemd-manifest make --field=size,hash,mtime` would, for tests and
/// for the command line tool. The descriptor is what the caller resolved
/// its path to, with [`crate::host::open_dir`] when it has a path, and may
/// be O_PATH; everything below it is reached by descriptor. Only regular
/// files and directories are listed, and a manifest stored in the tree's
/// top level is left out since its name is reserved. Names that differ
/// only in case are listed as they are, the way the host has them.
pub fn generate(root: BorrowedFd<'_>) -> Result<Vec<u8>> {
    fn mtime_nsec(md: &std::fs::Metadata) -> Option<u64> {
        md.modified().ok().and_then(time_nsec)
    }
    let mut out = Vec::new();
    // The leading object carries the tree's own time, as systemd's does.
    let mut top = Object::new();
    if let Some(m) = mtime_nsec(&sys::fstat(root)?) {
        top.insert("mTimeNSec", m);
    }
    top.insert("mediaType", MEDIA_TYPE);
    write_record(&mut out, top)?;
    let mut buf = vec![0u8; 1024 * 1024];
    crate::host::walk_tree(root, "", false, Case::Kept, &mut |target, entry| {
        let md = &entry.metadata;
        // walk_tree joins with a leading slash; manifests want none.
        let path = &target[1..];
        if md.is_file() && !valid_name(path) {
            return Ok(false);
        }
        let mtime = mtime_nsec(md);
        let mut o = Object::new();
        if md.is_dir() {
            if let Some(m) = mtime {
                o.insert("mTimeNSec", m);
            }
            o.insert("name", path);
            o.insert("type", "dir");
            write_record(&mut out, o)?;
        } else if md.is_file() {
            let mut file = entry.open_file()?;
            let mut hasher = Sha256::new();
            loop {
                let n = crate::host::read_some(&mut file, &mut buf)?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            if let Some(m) = mtime {
                o.insert("mTimeNSec", m);
            }
            o.insert("name", path);
            o.insert("sha256", sha256::to_hex(&hasher.finalize()));
            o.insert("size", md.len());
            write_record(&mut out, o)?;
        }
        Ok(md.is_dir())
    })?;
    write_record(&mut out, json::object! { "mediaType" => TRAILER_MEDIA_TYPE })?;
    Ok(out)
}
