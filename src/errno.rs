// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Linux errno values this crate reports.
//!
//! Errors carry a positive errno, which the tool reports by name and the
//! Varlink service passes on as `errno` and `errnoName`, the way systemd
//! does it.

#[cfg(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "sparc",
    target_arch = "sparc64"
))]
compile_error!("the errno table below is for the generic Linux layout only");

/// `EPERM`
pub const EPERM: i32 = 1;
/// `ENOENT`
pub const ENOENT: i32 = 2;
/// `EINTR`
pub const EINTR: i32 = 4;
/// `EIO`
pub const EIO: i32 = 5;
/// `ENXIO`
pub const ENXIO: i32 = 6;
/// `E2BIG`
pub const E2BIG: i32 = 7;
/// `EBADF`
pub const EBADF: i32 = 9;
/// `EAGAIN`
pub const EAGAIN: i32 = 11;
/// `ENOMEM`
pub const ENOMEM: i32 = 12;
/// `EBUSY`
pub const EBUSY: i32 = 16;
/// `EEXIST`
pub const EEXIST: i32 = 17;
/// `ENODEV`
pub const ENODEV: i32 = 19;
/// `ENOTDIR`
pub const ENOTDIR: i32 = 20;
/// `EISDIR`
pub const EISDIR: i32 = 21;
/// `EINVAL`
pub const EINVAL: i32 = 22;
/// `ENOTTY`
pub const ENOTTY: i32 = 25;
/// `EFBIG`
pub const EFBIG: i32 = 27;
/// `ENOSPC`
pub const ENOSPC: i32 = 28;
/// `EROFS`
pub const EROFS: i32 = 30;
/// `ERANGE`
pub const ERANGE: i32 = 34;
/// `ENAMETOOLONG`
pub const ENAMETOOLONG: i32 = 36;
/// `ENOSYS`
pub const ENOSYS: i32 = 38;
/// `ENOTEMPTY`
pub const ENOTEMPTY: i32 = 39;
/// `ELOOP`
pub const ELOOP: i32 = 40;
/// `ENODATA`
pub const ENODATA: i32 = 61;
/// `EBADMSG`
pub const EBADMSG: i32 = 74;
/// `EOVERFLOW`
pub const EOVERFLOW: i32 = 75;
/// `EBADFD`: a descriptor that is open but not usable for what it was
/// handed over for, systemd's choice for a passed descriptor of the wrong
/// kind.
pub const EBADFD: i32 = 77;
/// `EOPNOTSUPP`
pub const EOPNOTSUPP: i32 = 95;
/// `EUCLEAN`
pub const EUCLEAN: i32 = 117;
/// `ENOMEDIUM`
pub const ENOMEDIUM: i32 = 123;
/// `EMEDIUMTYPE`
pub const EMEDIUMTYPE: i32 = 124;
/// `EKEYEXPIRED`
pub const EKEYEXPIRED: i32 = 127;
/// `EKEYREVOKED`
pub const EKEYREVOKED: i32 = 128;
