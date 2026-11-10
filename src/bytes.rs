// SPDX-License-Identifier: LGPL-2.1-or-later
//! Little-endian fields of on-disk structures.

/// The little-endian `u16` at `off` in `b`.
pub(crate) fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// The little-endian `u32` at `off` in `b`.
pub(crate) fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
