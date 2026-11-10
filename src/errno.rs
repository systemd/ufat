// SPDX-License-Identifier: LGPL-2.1-or-later
//! The Linux errno values this crate reports.
//!
//! Errors carry a positive errno, which the tool reports by name and the
//! Varlink service passes on as `errno` and `errnoName`, the way systemd
//! does it.

/// `EPERM`
pub const EPERM: i32 = libc::EPERM;
/// `ENOENT`
pub const ENOENT: i32 = libc::ENOENT;
/// `EINTR`
pub const EINTR: i32 = libc::EINTR;
/// `EIO`
pub const EIO: i32 = libc::EIO;
/// `ENXIO`
pub const ENXIO: i32 = libc::ENXIO;
/// `E2BIG`
pub const E2BIG: i32 = libc::E2BIG;
/// `EBADF`
pub const EBADF: i32 = libc::EBADF;
/// `EAGAIN`
pub const EAGAIN: i32 = libc::EAGAIN;
/// `ENOMEM`
pub const ENOMEM: i32 = libc::ENOMEM;
/// `EBUSY`
pub const EBUSY: i32 = libc::EBUSY;
/// `EEXIST`
pub const EEXIST: i32 = libc::EEXIST;
/// `ENODEV`
pub const ENODEV: i32 = libc::ENODEV;
/// `ENOTDIR`
pub const ENOTDIR: i32 = libc::ENOTDIR;
/// `EISDIR`
pub const EISDIR: i32 = libc::EISDIR;
/// `EINVAL`
pub const EINVAL: i32 = libc::EINVAL;
/// `ENOTTY`
pub const ENOTTY: i32 = libc::ENOTTY;
/// `EFBIG`
pub const EFBIG: i32 = libc::EFBIG;
/// `ENOSPC`
pub const ENOSPC: i32 = libc::ENOSPC;
/// `EROFS`
pub const EROFS: i32 = libc::EROFS;
/// `ERANGE`
pub const ERANGE: i32 = libc::ERANGE;
/// `ENAMETOOLONG`
pub const ENAMETOOLONG: i32 = libc::ENAMETOOLONG;
/// `ENOSYS`
pub const ENOSYS: i32 = libc::ENOSYS;
/// `ENOTEMPTY`
pub const ENOTEMPTY: i32 = libc::ENOTEMPTY;
/// `ELOOP`
pub const ELOOP: i32 = libc::ELOOP;
/// `ENODATA`
pub const ENODATA: i32 = libc::ENODATA;
/// `EBADMSG`
pub const EBADMSG: i32 = libc::EBADMSG;
/// `EOVERFLOW`
pub const EOVERFLOW: i32 = libc::EOVERFLOW;
/// `EBADFD`: a descriptor that is open but not usable for what it was
/// handed over for, systemd's choice for a passed descriptor of the wrong
/// kind.
pub const EBADFD: i32 = libc::EBADFD;
/// `EOPNOTSUPP`
pub const EOPNOTSUPP: i32 = libc::EOPNOTSUPP;
/// `EUCLEAN`
pub const EUCLEAN: i32 = libc::EUCLEAN;
/// `ENOMEDIUM`
pub const ENOMEDIUM: i32 = libc::ENOMEDIUM;
/// `EMEDIUMTYPE`
pub const EMEDIUMTYPE: i32 = libc::EMEDIUMTYPE;
/// `EKEYEXPIRED`
pub const EKEYEXPIRED: i32 = libc::EKEYEXPIRED;
/// `EKEYREVOKED`
pub const EKEYREVOKED: i32 = libc::EKEYREVOKED;
