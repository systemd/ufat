// SPDX-License-Identifier: LGPL-2.1-or-later
//! Little-endian fields of on-disk structures.

use std::ops::Range;

/// The little-endian `u16` at `off` in `b`.
pub(crate) fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

/// The little-endian `u32` at `off` in `b`.
pub(crate) fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// The little-endian `u16` in the two bytes `field` of `b`.
pub(crate) fn le16_at(b: &[u8], field: Range<usize>) -> u16 {
    u16::from_le_bytes(b[field].try_into().expect("a field of two bytes"))
}

/// The little-endian `u32` in the four bytes `field` of `b`.
pub(crate) fn le32_at(b: &[u8], field: Range<usize>) -> u32 {
    u32::from_le_bytes(b[field].try_into().expect("a field of four bytes"))
}

/// The bytes `field` of `b`, as an array of the size of the field.
pub(crate) fn bytes_at<const N: usize>(b: &[u8], field: Range<usize>) -> [u8; N] {
    b[field].try_into().expect("an array of the size of the field")
}

/// The number of bytes in `field`.
pub(crate) const fn size(field: Range<usize>) -> usize {
    field.end - field.start
}
