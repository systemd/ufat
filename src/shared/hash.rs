// SPDX-License-Identifier: LGPL-2.1-or-later
//! The hash of an image, with the algorithm the caller names.

use crate::device::Device;
use crate::progress::Progress;
use crate::sha256::{self, Sha256};
use crate::sha512::{self, Sha512};
use crate::Result;

/// Bytes read at a time when the image is hashed.
const HASH_STEP: usize = 1 << 20;

/// The hash of a file system as it is in its image, as `imageHash` asks
/// for it.
pub enum Hash {
    /// SHA-256.
    Sha256(Sha256),
    /// SHA-512.
    Sha512(Sha512),
}

impl Hash {
    /// The hash that `algorithm` names, `sha256` or `sha512`. None for any
    /// other name.
    pub fn new(algorithm: &str) -> Option<Hash> {
        match algorithm {
            "sha256" => Some(Hash::Sha256(Sha256::new())),
            "sha512" => Some(Hash::Sha512(Sha512::new())),
            _ => None,
        }
    }

    /// Reads all of `device` back and returns the hash in lowercase hex,
    /// telling `progress` how many bytes it read so far after every read.
    pub fn of(mut self, device: &Device, progress: &mut dyn FnMut(&Progress)) -> Result<String> {
        let mut buf = vec![0u8; HASH_STEP];
        let mut offset = 0;
        while offset < device.len() {
            let n = (device.len() - offset).min(HASH_STEP as u64) as usize;
            device.read_at(offset, &mut buf[..n])?;
            match &mut self {
                Hash::Sha256(h) => h.update(&buf[..n]),
                Hash::Sha512(h) => h.update(&buf[..n]),
            }
            offset += n as u64;
            progress(&Progress {
                bytes: offset,
                ..Progress::default()
            });
        }
        Ok(match self {
            Hash::Sha256(h) => sha256::to_hex(&h.finalize()),
            Hash::Sha512(h) => sha512::to_hex(&h.finalize()),
        })
    }
}
