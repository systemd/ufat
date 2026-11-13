// SPDX-License-Identifier: LGPL-2.1-or-later
//! The values of the kernel interface that the libc crate lacks, or has
//! with glibc's value instead of the kernel's, from the uapi headers of
//! Linux. Each architecture ufat supports is listed; the build fails on
//! any other.

use std::ffi::c_int;

/// Linux 7.2: `openat(fd, "", flags | O_EMPTYPATH)` opens what `fd` refers
/// to, which is how an O_PATH descriptor becomes a real one without procfs.
/// include/uapi/asm-generic/fcntl.h; no architecture overrides it.
pub(crate) const O_EMPTYPATH: c_int = 1 << 26;

/// Set by the kernel on every descriptor a 64-bit process opens
/// (force_o_largefile()), and by glibc's openat64() on 32-bit targets.
/// F_GETFL reports it. glibc, and libc with it, say 0 on 64-bit targets.
// include/uapi/asm-generic/fcntl.h
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "loongarch64",
    target_arch = "riscv64",
    target_arch = "s390x"
))]
pub(crate) const O_LARGEFILE: c_int = 0o100000;
// arch/arm/include/uapi/asm/fcntl.h and arch/arm64/include/uapi/asm/fcntl.h
#[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
pub(crate) const O_LARGEFILE: c_int = 0o400000;
// arch/powerpc/include/uapi/asm/fcntl.h
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
pub(crate) const O_LARGEFILE: c_int = 0o200000;
// arch/sparc/include/uapi/asm/fcntl.h
#[cfg(target_arch = "sparc64")]
pub(crate) const O_LARGEFILE: c_int = 0x40000;
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "loongarch64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "sparc64"
)))]
compile_error!("src/fat/sys/uapi.rs has no O_LARGEFILE for this architecture");

// On 32-bit targets glibc has the kernel's value.
#[cfg(target_pointer_width = "32")]
const _: () = assert!(O_LARGEFILE == libc::O_LARGEFILE);

// The kernel gives every open flag a bit of its own, so neither value may
// collide with a flag libc knows for this target.
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
    assert!(O_LARGEFILE & known == 0 && O_EMPTYPATH & known == 0 && O_LARGEFILE != O_EMPTYPATH);
};

/// BLKGETSIZE64, `_IOR(0x12, 114, size_t)`: the size of a block device in
/// bytes. include/uapi/linux/fs.h.
pub(super) const BLKGETSIZE64: libc::Ioctl = libc::_IOR::<libc::size_t>(0x12, 114);
/// BLKZEROOUT, `_IO(0x12, 127)`: zero a range of a block device, with a
/// write zeroes command where the device has one (block/ioctl.c).
/// include/uapi/linux/fs.h.
pub(super) const BLKZEROOUT: libc::Ioctl = libc::_IO(0x12, 127);
