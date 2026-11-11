// SPDX-License-Identifier: LGPL-2.1-or-later
//! Entries put together by hand for the tests, without the writer: with
//! every field as a test wants it, well formed or not.

// The temporary images and directories are the ones the shared crate
// tests with.
#[path = "../shared/test_util.rs"]
mod host_side;
#[allow(unused_imports)]
pub(crate) use host_side::{TempDir, TempImage};

use crate::header::DeviceNumber;
use crate::name::Name;

/// The name `bytes` are, for a test that knows them to be one.
pub(crate) fn named(bytes: &[u8]) -> Name<'_> {
    Name::new(bytes).unwrap()
}

/// One entry as it is stored.
#[derive(Clone, Debug)]
pub(crate) struct Raw {
    pub(crate) magic: [u8; 6],
    pub(crate) ino: u32,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) nlink: u32,
    pub(crate) mtime: u32,
    pub(crate) rdev: DeviceNumber,
    /// The name as it is stored, with its NUL where it has one.
    pub(crate) name: Vec<u8>,
    pub(crate) data: Vec<u8>,
}

impl Raw {
    /// An entry with the mode `mode`, named `name` with a NUL behind it.
    pub(crate) fn new(mode: u32, name: &[u8]) -> Raw {
        let mut stored = name.to_vec();
        stored.push(0);
        Raw {
            magic: *b"070701",
            ino: 0,
            mode,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            rdev: DeviceNumber::NONE,
            name: stored,
            data: Vec::new(),
        }
    }

    /// The trailer.
    pub(crate) fn trailer() -> Raw {
        Raw::new(0, b"TRAILER!!!")
    }

    pub(crate) fn data(mut self, data: &[u8]) -> Raw {
        self.data = data.to_vec();
        self
    }

    /// The inode number and how many names the file has.
    pub(crate) fn inode(mut self, ino: u32, nlink: u32) -> Raw {
        self.ino = ino;
        self.nlink = nlink;
        self
    }

    pub(crate) fn owner(mut self, uid: u32, gid: u32) -> Raw {
        self.uid = uid;
        self.gid = gid;
        self
    }

    pub(crate) fn mtime(mut self, mtime: u32) -> Raw {
        self.mtime = mtime;
        self
    }

    pub(crate) fn rdev(mut self, major: u32, minor: u32) -> Raw {
        self.rdev = DeviceNumber::new(major, minor);
        self
    }

    pub(crate) fn magic(mut self, magic: &[u8; 6]) -> Raw {
        self.magic = *magic;
        self
    }

    /// The bytes of the entry, upper case digits in the header.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut out = self.magic.to_vec();
        let fields = [
            self.ino,
            self.mode,
            self.uid,
            self.gid,
            self.nlink,
            self.mtime,
            self.data.len() as u32,
            0,
            0,
            self.rdev.major,
            self.rdev.minor,
            self.name.len() as u32,
            0,
        ];
        for field in fields {
            out.extend_from_slice(format!("{:08X}", field).as_bytes());
        }
        out.extend_from_slice(&self.name);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&self.data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }
}

/// An archive of `entries`, with the trailer behind them.
pub(crate) fn archive(entries: &[Raw]) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        out.extend(entry.bytes());
    }
    out.extend(Raw::trailer().bytes());
    out
}
