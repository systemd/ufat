// SPDX-License-Identifier: LGPL-2.1-or-later
//! The values of the kernel interface that the libc crate lacks, from the
//! uapi headers of Linux.

use std::ffi::{c_int, c_ulong};

/// Linux 7.2: `openat(fd, "", flags | O_EMPTYPATH)` opens what `fd` refers
/// to, which is how an O_PATH descriptor becomes a real one without procfs.
/// include/uapi/asm-generic/fcntl.h; no architecture overrides it.
pub(crate) const O_EMPTYPATH: c_int = 1 << 26;

// The kernel gives every open flag a bit of its own, so O_EMPTYPATH must
// not collide with a flag libc knows for this target.
const _: () = {
    let known = libc::O_ACCMODE
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_NOCTTY
        | libc::O_TRUNC
        | libc::O_APPEND
        | libc::O_NONBLOCK
        | libc::O_DSYNC
        | libc::O_ASYNC
        | libc::O_DIRECT
        | libc::O_DIRECTORY
        | libc::O_NOFOLLOW
        | libc::O_NOATIME
        | libc::O_CLOEXEC
        | libc::O_SYNC
        | libc::O_PATH
        | libc::O_TMPFILE;
    assert!(O_EMPTYPATH & known == 0);
};

/// BLKGETSIZE64, `_IOR(0x12, 114, size_t)`: the size of a block device in
/// bytes. include/uapi/linux/fs.h.
pub(super) const BLKGETSIZE64: c_ulong = libc::_IOR::<libc::size_t>(0x12, 114);
/// BLKZEROOUT, `_IO(0x12, 127)`: zero a range of a block device, with a
/// write zeroes command where the device has one (block/ioctl.c).
/// include/uapi/linux/fs.h.
pub(super) const BLKZEROOUT: c_ulong = libc::_IO(0x12, 127);
