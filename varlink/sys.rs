// SPDX-License-Identifier: LGPL-2.1-or-later
//! The raw system interfaces std does not cover. The only unsafe code of the
//! crate lives here.
#![allow(unsafe_code)]

#[cfg(any(
    target_arch = "mips",
    target_arch = "mips32r6",
    target_arch = "mips64",
    target_arch = "mips64r6",
    target_arch = "sparc",
    target_arch = "sparc64"
))]
compile_error!(
    "the socket option and errno numbers in this crate follow the generic Linux layout; mips and sparc differ"
);

use std::ffi::{c_int, c_long, c_short, c_ulong, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;

extern "C" {
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32) -> c_int;
    fn setsockopt(fd: c_int, level: c_int, name: c_int, value: *const c_void, len: u32) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    fn poll(fds: *mut PollFd, nfds: c_ulong, timeout: c_int) -> c_int;
    fn geteuid() -> u32;
    fn getpid() -> c_int;
    fn syscall(number: c_long, ...) -> c_long;
    fn pthread_sigmask(how: c_int, set: *const SigSet, old: *mut SigSet) -> c_int;
    fn recvmsg(fd: c_int, msg: *mut MsgHdr, flags: c_int) -> isize;
    fn sendmsg(fd: c_int, msg: *const MsgHdr, flags: c_int) -> isize;
}

/// glibc's sigset_t: 1024 bits.
#[repr(C)]
struct SigSet([u64; 16]);

const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIGTERM: c_int = 15;

fn change_sigterm(how: c_int) -> io::Result<()> {
    let mut set = SigSet([0; 16]);
    set.0[0] = 1 << (SIGTERM - 1);
    // SAFETY: the set is a valid sigset_t for the duration of the call; the
    // old mask is not requested. pthread_sigmask() returns the error number
    // instead of setting errno.
    let r = unsafe { pthread_sigmask(how, &set, std::ptr::null_mut()) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }
    Ok(())
}

/// Blocks SIGTERM for the calling thread. A pending SIGTERM takes effect
/// when [`unblock_sigterm`] runs.
pub(crate) fn block_sigterm() -> io::Result<()> {
    change_sigterm(SIG_BLOCK)
}

/// Unblocks SIGTERM for the calling thread.
pub(crate) fn unblock_sigterm() -> io::Result<()> {
    change_sigterm(SIG_UNBLOCK)
}

// Socket option numbers as in include/uapi/asm-generic/socket.h. powerpc
// numbers the first few differently (arch/powerpc/include/uapi/asm/socket.h);
// alpha, mips, parisc and sparc differ further and are refused below.
const SOL_SOCKET: c_int = 1;
#[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))]
const SO_PEERCRED: c_int = 21;
#[cfg(not(any(target_arch = "powerpc", target_arch = "powerpc64")))]
const SO_PEERCRED: c_int = 17;
const SO_ACCEPTCONN: c_int = 30;
/// Linux 6.16; older kernels reject it, which is fine.
const SO_PASSRIGHTS: c_int = 83;
// Message flags, include/linux/socket.h, and the one ancillary message
// type we deal in.
const MSG_PEEK: c_int = 2;
const MSG_CTRUNC: c_int = 8;
const MSG_NOSIGNAL: c_int = 0x4000;
const MSG_CMSG_CLOEXEC: c_int = 0x4000_0000;
const SCM_RIGHTS: c_int = 1;
/// SCM_MAX_FD (include/net/scm.h): the kernel passes at most this many
/// descriptors in one message, and we make room for exactly that.
pub(crate) const MAX_FDS: usize = 253;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const POLLIN: c_short = 1;
const SYS_PIDFD_OPEN: c_long = 434;
const SYS_SIGNALFD4: c_long = 289;
const SFD_CLOEXEC: c_int = 0o2000000;
const SFD_NONBLOCK: c_int = 0o4000;
// errno values, include/uapi/asm-generic/errno-base.h and errno.h.
pub(crate) const ENXIO: c_int = 6;
pub(crate) const EBADF: c_int = 9;
pub(crate) const ENOTSOCK: c_int = 88;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

/// struct iovec.
#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

/// struct msghdr as glibc lays it out: the padding after `namelen` on
/// 64-bit targets falls out of repr(C).
#[repr(C)]
struct MsgHdr {
    name: *mut c_void,
    namelen: u32,
    iov: *mut IoVec,
    iovlen: usize,
    control: *mut c_void,
    controllen: usize,
    flags: c_int,
}

/// struct cmsghdr; the data follows, aligned like a size_t.
#[repr(C)]
struct CmsgHdr {
    len: usize,
    level: c_int,
    type_: c_int,
}

/// Makes a system call until no signal interrupts it, and turns a negative
/// return into the error in errno.
fn retry(mut call: impl FnMut() -> isize) -> io::Result<usize> {
    loop {
        if let Ok(n) = usize::try_from(call()) {
            return Ok(n);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// CMSG_ALIGN, CMSG_LEN and CMSG_SPACE of the C headers.
const fn cmsg_align(n: usize) -> usize {
    (n + size_of::<usize>() - 1) & !(size_of::<usize>() - 1)
}
const fn cmsg_len(data: usize) -> usize {
    cmsg_align(size_of::<CmsgHdr>()) + data
}
const fn cmsg_space(data: usize) -> usize {
    cmsg_align(size_of::<CmsgHdr>()) + cmsg_align(data)
}
/// A control buffer with room for MAX_FDS descriptors, as size_t words so
/// that it is aligned for the headers.
const CONTROL_WORDS: usize = cmsg_space(MAX_FDS * size_of::<c_int>()) / size_of::<usize>() + 1;

/// What one recvmsg() delivered.
pub(crate) struct Received {
    /// Bytes read into the caller's buffer; 0 at the end of the stream.
    pub(crate) bytes: usize,
    /// The descriptors sent along with those bytes, FD_CLOEXEC set.
    pub(crate) fds: Vec<OwnedFd>,
    /// The kernel had to drop descriptors because the control buffer was
    /// too small for them (MSG_CTRUNC).
    pub(crate) truncated: bool,
}

/// Looks at what waits to be read without taking it (MSG_PEEK), up to
/// `buf.len()` bytes. Returns 0 at the end of the stream. No control
/// buffer is passed, so the kernel installs no descriptors for a peek.
pub(crate) fn peek(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    let mut iov = IoVec {
        base: buf.as_mut_ptr().cast(),
        len: buf.len(),
    };
    let mut msg = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: std::ptr::null_mut(),
        controllen: 0,
        flags: 0,
    };
    retry(|| {
        // SAFETY: the header points at one iovec over the caller's buffer,
        // both alive for the call; no control buffer is passed.
        unsafe { recvmsg(fd.as_raw_fd(), &mut msg, MSG_PEEK) }
    })
}

/// Reads up to `buf.len()` bytes and takes the descriptors that were sent
/// along with them (SCM_RIGHTS), FD_CLOEXEC set on arrival so that none of
/// them leaks into a child. The caller decides what they belong to.
pub(crate) fn recv_with_fds(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Received> {
    let mut control = [0usize; CONTROL_WORDS];
    let mut iov = IoVec {
        base: buf.as_mut_ptr().cast(),
        len: buf.len(),
    };
    let mut msg = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: control.as_mut_ptr().cast(),
        controllen: size_of::<[usize; CONTROL_WORDS]>(),
        flags: 0,
    };
    let n = retry(|| {
        // SAFETY: the header points at one iovec over the caller's buffer
        // and at a control buffer of the stated size, all alive for the
        // call.
        unsafe { recvmsg(fd.as_raw_fd(), &mut msg, MSG_CMSG_CLOEXEC) }
    })?;
    // Walk the control messages the kernel filled in. Anything that is not
    // SCM_RIGHTS (credentials, for one) is skipped.
    let mut fds = Vec::new();
    let base = control.as_ptr().cast::<u8>();
    let header = cmsg_align(size_of::<CmsgHdr>());
    let mut offset = 0;
    while offset + size_of::<CmsgHdr>() <= msg.controllen {
        // SAFETY: the kernel wrote a cmsghdr at every offset it reports
        // within controllen; reading it unaligned is always sound.
        let hdr = unsafe { std::ptr::read_unaligned(base.add(offset).cast::<CmsgHdr>()) };
        if hdr.len < header || offset + hdr.len > msg.controllen {
            break;
        }
        if hdr.level == SOL_SOCKET && hdr.type_ == SCM_RIGHTS {
            let count = (hdr.len - header) / size_of::<c_int>();
            for i in 0..count {
                let at = offset + header + i * size_of::<c_int>();
                // SAFETY: the data of an SCM_RIGHTS message is `count` ints
                // within the `hdr.len` bytes checked above, read unaligned.
                let raw = unsafe { std::ptr::read_unaligned(base.add(at).cast::<c_int>()) };
                // SAFETY: the kernel installed each of them as a descriptor
                // that we now own.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        offset += cmsg_align(hdr.len);
    }
    Ok(Received {
        bytes: n,
        fds,
        truncated: msg.flags & MSG_CTRUNC != 0,
    })
}

/// Sends `data` with `fds` attached as one SCM_RIGHTS message. Returns how
/// many bytes went out; the descriptors travel with the first of them, so
/// the rest can follow with plain writes. MSG_NOSIGNAL makes a peer that
/// went away an error rather than a SIGPIPE.
pub(crate) fn send_with_fds(fd: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<usize> {
    if fds.len() > MAX_FDS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} descriptors in one message, at most {} go", fds.len(), MAX_FDS),
        ));
    }
    let mut control = [0usize; CONTROL_WORDS];
    let header = cmsg_align(size_of::<CmsgHdr>());
    let data_len = fds.len() * size_of::<c_int>();
    if !fds.is_empty() {
        let hdr = CmsgHdr {
            len: cmsg_len(data_len),
            level: SOL_SOCKET,
            type_: SCM_RIGHTS,
        };
        let base = control.as_mut_ptr().cast::<u8>();
        // SAFETY: the control buffer has room for the header and MAX_FDS
        // ints, written unaligned.
        unsafe { std::ptr::write_unaligned(base.cast::<CmsgHdr>(), hdr) };
        for (i, f) in fds.iter().enumerate() {
            let at = header + i * size_of::<c_int>();
            // SAFETY: as above; there are at most MAX_FDS of them.
            unsafe { std::ptr::write_unaligned(base.add(at).cast::<c_int>(), f.as_raw_fd()) };
        }
    }
    // sendmsg() only reads through the iovec.
    let mut iov = IoVec {
        base: data.as_ptr().cast_mut().cast(),
        len: data.len(),
    };
    let msg = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: if fds.is_empty() {
            std::ptr::null_mut()
        } else {
            control.as_mut_ptr().cast()
        },
        controllen: if fds.is_empty() { 0 } else { cmsg_space(data_len) },
        flags: 0,
    };
    retry(|| {
        // SAFETY: the header points at one iovec over `data` and at the
        // control buffer filled above, both alive for the call.
        unsafe { sendmsg(fd.as_raw_fd(), &msg, MSG_NOSIGNAL) }
    })
}

fn sockopt_int(fd: BorrowedFd<'_>, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>() as u32;
    // SAFETY: the option stores an int through the pointer; both pointers are
    // valid for the duration of the call.
    let r = unsafe { getsockopt(fd.as_raw_fd(), SOL_SOCKET, name, (&raw mut value).cast(), &mut len) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Whether the socket is in listening state.
pub(crate) fn is_listening(fd: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(sockopt_int(fd, SO_ACCEPTCONN)? != 0)
}

/// The credentials of the peer of a connected AF_UNIX socket: (pid, uid,
/// gid).
pub(crate) fn peer_credentials(fd: BorrowedFd<'_>) -> io::Result<(i32, u32, u32)> {
    let mut cred = UCred { pid: 0, uid: 0, gid: 0 };
    let mut len = size_of::<UCred>() as u32;
    // SAFETY: SO_PEERCRED fills a struct ucred of exactly this layout.
    let r = unsafe {
        getsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // A wrong option number must never read as credentials.
    if len as usize != size_of::<UCred>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SO_PEERCRED returned an unexpected size",
        ));
    }
    Ok((cred.pid, cred.uid, cred.gid))
}

/// Lets file descriptors arrive with SCM_RIGHTS on this socket. That is
/// the kernel's default; saying so explicitly (SO_PASSRIGHTS, Linux 6.16)
/// undoes a stricter setting inherited from whoever made the socket, and
/// on a listening socket it is inherited by every accepted connection, so
/// no client can race us. Older kernels refuse the option, which is fine.
pub(crate) fn allow_passed_fds(fd: BorrowedFd<'_>) {
    let on: c_int = 1;
    // SAFETY: the option takes an int; the pointer is valid for the call.
    unsafe {
        setsockopt(
            fd.as_raw_fd(),
            SOL_SOCKET,
            SO_PASSRIGHTS,
            (&raw const on).cast(),
            size_of::<c_int>() as u32,
        );
    }
}

/// Sets FD_CLOEXEC on a descriptor.
pub(crate) fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_SETFD with an int argument is a plain fcntl call.
    if unsafe { fcntl(fd.as_raw_fd(), F_SETFD, FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits until one of `fds` is readable, or `timeout_ms` passed (None waits
/// forever), and says which of them are: none after a timeout.
pub(crate) fn wait_readable<const N: usize>(
    fds: [BorrowedFd<'_>; N],
    timeout_ms: Option<u32>,
) -> io::Result<[bool; N]> {
    let mut polled = fds.map(|fd| PollFd {
        fd: fd.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    });
    let timeout = timeout_ms.map_or(-1, |t| c_int::try_from(t).unwrap_or(c_int::MAX));
    retry(|| {
        // SAFETY: N pollfds, valid for the call.
        unsafe { poll(polled.as_mut_ptr(), N as c_ulong, timeout) as isize }
    })?;
    Ok(polled.map(|p| p.revents != 0))
}

/// The effective user id of this process.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { geteuid() }
}

/// The inode number of this process's pidfd, which is what LISTEN_PIDFDID
/// carries. None if the kernel has no pidfd_open().
pub(crate) fn own_pidfd_inode() -> Option<u64> {
    // SAFETY: getpid() has no preconditions.
    let pid = unsafe { getpid() };
    // SAFETY: pidfd_open(pid, 0) takes no pointers.
    let fd = unsafe { syscall(SYS_PIDFD_OPEN, c_long::from(pid), 0 as c_long) };
    let fd = RawFd::try_from(fd).ok().filter(|&fd| fd >= 0)?;
    // SAFETY: the system call returned a fresh descriptor that we now own.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    Some(file.metadata().ok()?.ino())
}

/// Takes ownership of a file descriptor the service manager passed in.
///
/// # Safety
/// The caller guarantees that `fd` is open and not owned by anything else,
/// which holds for the descriptors announced through `LISTEN_FDS`.
pub(crate) unsafe fn take_fd(fd: RawFd) -> OwnedFd {
    // SAFETY: the caller's guarantee is what from_raw_fd() asks for.
    unsafe { OwnedFd::from_raw_fd(fd) }
}

/// A descriptor that becomes readable when a SIGTERM is pending for the
/// process. SIGTERM must be blocked in every thread for the signal to wait
/// there instead of killing the process.
pub(crate) fn sigterm_fd() -> io::Result<OwnedFd> {
    let mut set = SigSet([0; 16]);
    set.0[0] = 1 << (SIGTERM - 1);
    // The kernel's sigset_t is 64 bits, not glibc's 1024: the size passed
    // must be the kernel's, and the first word of the set holds SIGTERM.
    // glibc reads every argument after the number as a long.
    // SAFETY: a valid set of that size, read for the duration of the call.
    let fd = unsafe {
        syscall(
            SYS_SIGNALFD4,
            -1 as c_long,
            set.0.as_ptr(),
            size_of::<u64>() as c_long,
            c_long::from(SFD_CLOEXEC | SFD_NONBLOCK),
        )
    };
    let fd = RawFd::try_from(fd)
        .ok()
        .filter(|&fd| fd >= 0)
        .ok_or_else(io::Error::last_os_error)?;
    // SAFETY: the system call returned a fresh descriptor that we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
