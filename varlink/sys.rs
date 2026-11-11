// SPDX-License-Identifier: LGPL-2.1-or-later
//! The raw system interfaces std does not cover. The only unsafe code of the
//! crate lives here.
#![allow(unsafe_code)]

use std::ffi::{c_int, c_long, c_uint};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;

/// A signal set with SIGTERM alone.
fn sigterm_set() -> libc::sigset_t {
    let mut set = MaybeUninit::<libc::sigset_t>::uninit();
    // SAFETY: sigemptyset() initializes the set, and sigaddset() adds a
    // valid signal to it; neither fails for these arguments.
    unsafe {
        libc::sigemptyset(set.as_mut_ptr());
        libc::sigaddset(set.as_mut_ptr(), libc::SIGTERM);
        set.assume_init()
    }
}

fn change_sigterm(how: c_int) -> io::Result<()> {
    let set = sigterm_set();
    // SAFETY: the set is a valid sigset_t for the duration of the call; the
    // old mask is not requested. pthread_sigmask() returns the error number
    // instead of setting errno.
    let r = unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
    if r != 0 {
        return Err(io::Error::from_raw_os_error(r));
    }
    Ok(())
}

/// Blocks SIGTERM for the calling thread. A pending SIGTERM takes effect
/// when [`unblock_sigterm`] runs.
pub(crate) fn block_sigterm() -> io::Result<()> {
    change_sigterm(libc::SIG_BLOCK)
}

/// Unblocks SIGTERM for the calling thread.
pub(crate) fn unblock_sigterm() -> io::Result<()> {
    change_sigterm(libc::SIG_UNBLOCK)
}

/// SO_PASSRIGHTS, Linux 6.16. Older kernels reject it, which is fine. The
/// libc crate has it for sparc only. The other architectures take it from
/// include/uapi/asm-generic/socket.h, powerpc included.
#[cfg(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "loongarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x"
))]
const SO_PASSRIGHTS: c_int = 83;
// arch/sparc/include/uapi/asm/socket.h
#[cfg(target_arch = "sparc64")]
const SO_PASSRIGHTS: c_int = 0x5c;
#[cfg(target_arch = "sparc64")]
const _: () = assert!(SO_PASSRIGHTS == libc::SO_PASSRIGHTS);
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "loongarch64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64"
)))]
compile_error!("varlink/sys.rs has no SO_PASSRIGHTS for this architecture");

/// SCM_MAX_FD (include/net/scm.h): the kernel passes at most this many
/// descriptors in one message, and we make room for exactly that.
pub(crate) const MAX_FDS: usize = 253;

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

/// The bytes `count` descriptors take in a control message.
const fn fds_size(count: usize) -> c_uint {
    (count * size_of::<c_int>()) as c_uint
}

/// A control buffer with room for MAX_FDS descriptors, as size_t words so
/// that it is aligned for the headers.
// SAFETY: CMSG_SPACE() computes a size and touches no memory.
const CONTROL_WORDS: usize = unsafe { libc::CMSG_SPACE(fds_size(MAX_FDS)) } as usize / size_of::<usize>() + 1;

/// A message header for the one buffer `iov`, without an address, a
/// control buffer or flags.
fn message(iov: &mut libc::iovec) -> libc::msghdr {
    // SAFETY: msghdr is pointers and integers, for which all zeros is a
    // valid value.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg
}

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
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg = message(&mut iov);
    retry(|| {
        // SAFETY: the header points at one iovec over the caller's buffer,
        // both alive for the call; no control buffer is passed.
        unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_PEEK) }
    })
}

/// Reads up to `buf.len()` bytes and takes the descriptors that were sent
/// along with them (SCM_RIGHTS), FD_CLOEXEC set on arrival so that none of
/// them leaks into a child. The caller decides what they belong to.
pub(crate) fn recv_with_fds(fd: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<Received> {
    let mut control = [0usize; CONTROL_WORDS];
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut msg = message(&mut iov);
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of_val(&control);
    let n = retry(|| {
        // SAFETY: the header points at one iovec over the caller's buffer
        // and at a control buffer of the stated size, all alive for the
        // call.
        unsafe { libc::recvmsg(fd.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) }
    })?;
    // Walk the control messages the kernel filled in. Anything that is not
    // SCM_RIGHTS (credentials, for one) is skipped.
    let mut fds = Vec::new();
    // SAFETY: CMSG_LEN() computes a size and touches no memory.
    let header = unsafe { libc::CMSG_LEN(0) } as usize;
    let end = msg.msg_control.addr() + msg.msg_controllen;
    // SAFETY: the header describes the control buffer, which the kernel
    // filled in up to msg_controllen.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        // SAFETY: CMSG_FIRSTHDR() and CMSG_NXTHDR() return a header only
        // where one fits before the end of the buffer, at an offset the
        // kernel aligned for it in a buffer aligned for it.
        let hdr = unsafe { &*cmsg };
        // They do not check that the data fits as well.
        if hdr.cmsg_len < header || hdr.cmsg_len > end - cmsg.addr() {
            break;
        }
        if hdr.cmsg_level == libc::SOL_SOCKET && hdr.cmsg_type == libc::SCM_RIGHTS {
            // SAFETY: the data follows the header.
            let data = unsafe { libc::CMSG_DATA(cmsg) };
            for i in 0..(hdr.cmsg_len - header) / size_of::<c_int>() {
                // SAFETY: the data of an SCM_RIGHTS message is ints within
                // the cmsg_len bytes checked above, read unaligned.
                let raw = unsafe { data.add(i * size_of::<c_int>()).cast::<c_int>().read_unaligned() };
                // SAFETY: the kernel installed each of them as a descriptor
                // that we now own.
                fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
            }
        }
        // SAFETY: as for CMSG_FIRSTHDR(); null after the last header.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(Received {
        bytes: n,
        fds,
        truncated: msg.msg_flags & libc::MSG_CTRUNC != 0,
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
    // sendmsg() only reads through the iovec.
    let mut iov = libc::iovec {
        iov_base: data.as_ptr().cast_mut().cast(),
        iov_len: data.len(),
    };
    let mut msg = message(&mut iov);
    if !fds.is_empty() {
        let size = fds_size(fds.len());
        msg.msg_control = control.as_mut_ptr().cast();
        // SAFETY: CMSG_SPACE() computes a size and touches no memory.
        msg.msg_controllen = unsafe { libc::CMSG_SPACE(size) } as usize;
        // SAFETY: the control buffer is aligned for the header and has
        // room for it and for MAX_FDS ints, and msg_controllen covers
        // them, so CMSG_FIRSTHDR() returns its start. The ints are
        // written unaligned.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_len = libc::CMSG_LEN(size) as usize;
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            let data = libc::CMSG_DATA(cmsg);
            for (i, f) in fds.iter().enumerate() {
                data.add(i * size_of::<c_int>())
                    .cast::<c_int>()
                    .write_unaligned(f.as_raw_fd());
            }
        }
    }
    retry(|| {
        // SAFETY: the header points at one iovec over `data` and at the
        // control buffer filled above, both alive for the call.
        unsafe { libc::sendmsg(fd.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) }
    })
}

fn sockopt_int(fd: BorrowedFd<'_>, name: c_int) -> io::Result<c_int> {
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>() as libc::socklen_t;
    // SAFETY: the option stores an int through the pointer; both pointers are
    // valid for the duration of the call.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            name,
            (&raw mut value).cast(),
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Whether the socket is in listening state.
pub(crate) fn is_listening(fd: BorrowedFd<'_>) -> io::Result<bool> {
    Ok(sockopt_int(fd, libc::SO_ACCEPTCONN)? != 0)
}

/// The credentials of the peer of a connected AF_UNIX socket: (pid, uid,
/// gid).
pub(crate) fn peer_credentials(fd: BorrowedFd<'_>) -> io::Result<(i32, u32, u32)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a struct ucred of exactly this layout.
    let r = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    // A wrong option number must never read as credentials.
    if len as usize != size_of::<libc::ucred>() {
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
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            SO_PASSRIGHTS,
            (&raw const on).cast(),
            size_of::<c_int>() as libc::socklen_t,
        );
    }
}

/// Sets FD_CLOEXEC on a descriptor.
pub(crate) fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_SETFD with an int argument is a plain fcntl call.
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
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
    let mut polled = fds.map(|fd| libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    });
    let timeout = timeout_ms.map_or(-1, |t| c_int::try_from(t).unwrap_or(c_int::MAX));
    retry(|| {
        // SAFETY: N pollfds, valid for the call.
        unsafe { libc::poll(polled.as_mut_ptr(), N as libc::nfds_t, timeout) as isize }
    })?;
    Ok(polled.map(|p| p.revents != 0))
}

/// The effective user id of this process.
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// A pidfd for the process `pid`. None if the kernel has no pidfd_open().
fn pidfd_open(pid: libc::pid_t) -> Option<OwnedFd> {
    // SAFETY: pidfd_open(pid, 0) takes no pointers. glibc reads every
    // argument after the number as a long.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, c_long::from(pid), 0 as c_long) };
    let fd = RawFd::try_from(fd).ok().filter(|&fd| fd >= 0)?;
    // SAFETY: the system call returned a fresh descriptor that we now own.
    Some(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The inode number of this process's pidfd, which is what LISTEN_PIDFDID
/// carries. None if the kernel has no pidfd_open().
pub(crate) fn own_pidfd_inode() -> Option<u64> {
    // SAFETY: getpid() has no preconditions.
    let pid = unsafe { libc::getpid() };
    let file = std::fs::File::from(pidfd_open(pid)?);
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
    let set = sigterm_set();
    // SAFETY: a valid set, read for the duration of the call.
    let fd = unsafe { libc::signalfd(-1, &set, libc::SFD_CLOEXEC | libc::SFD_NONBLOCK) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: signalfd() returned a fresh descriptor that we now own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};

    /// Whether the running kernel is at least `major.minor`.
    fn kernel_at_least(major: u32, minor: u32) -> bool {
        let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
            return false;
        };
        let mut numbers = release.split(|c: char| !c.is_ascii_digit()).map(str::parse::<u32>);
        match (numbers.next(), numbers.next()) {
            (Some(Ok(a)), Some(Ok(b))) => (a, b) >= (major, minor),
            _ => false,
        }
    }

    /// A SIGTERM for this thread, which blocks it, makes the descriptor
    /// readable and reads back as SIGTERM. pthread_kill() keeps the signal
    /// away from the other threads of the test.
    #[test]
    fn sigterm_fd_reports_a_blocked_sigterm() {
        block_sigterm().unwrap();
        let fd = sigterm_fd().unwrap();
        assert_eq!(wait_readable([fd.as_fd()], Some(0)).unwrap(), [false]);
        // SAFETY: the signal goes to the calling thread, which blocks it,
        // so it stays pending until the descriptor takes it.
        assert_eq!(unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) }, 0);
        assert_eq!(wait_readable([fd.as_fd()], Some(10_000)).unwrap(), [true]);
        let mut info = [0u8; size_of::<libc::signalfd_siginfo>()];
        assert_eq!(std::fs::File::from(fd).read(&mut info).unwrap(), info.len());
        // ssi_signo comes first.
        assert_eq!(u32::from_ne_bytes(info[..4].try_into().unwrap()), libc::SIGTERM as u32);
        unblock_sigterm().unwrap();
    }

    /// SO_PEERCRED has the number of this architecture: the peer of a
    /// socket pair is this process.
    #[test]
    fn peer_credentials_of_a_socket_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getpid() and getegid() have no preconditions.
        let (pid, gid) = unsafe { (libc::getpid(), libc::getegid()) };
        assert_eq!(peer_credentials(a.as_fd()).unwrap(), (pid, effective_uid(), gid));
    }

    /// SO_ACCEPTCONN has the number of this architecture: a listening
    /// socket says so, a connected one does not.
    #[test]
    fn listening_sockets_are_told_apart() {
        let name = format!("ufat-varlink-sys-test-{}", std::process::id());
        let listener = UnixListener::bind_addr(&SocketAddr::from_abstract_name(name).unwrap()).unwrap();
        assert!(is_listening(listener.as_fd()).unwrap());
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(!is_listening(a.as_fd()).unwrap());
    }

    /// SO_PASSRIGHTS has the kernel's number: turned off on the receiving
    /// end, descriptors sent there are refused (EPERM, Linux 6.16), and
    /// allow_passed_fds() lets them through again.
    #[test]
    fn so_passrights_turns_passed_descriptors_off_and_on() {
        let (a, b) = UnixStream::pair().unwrap();
        let off: c_int = 0;
        // SAFETY: the option takes an int; the pointer is valid for the call.
        let r = unsafe {
            libc::setsockopt(
                b.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PASSRIGHTS,
                (&raw const off).cast(),
                size_of::<c_int>() as libc::socklen_t,
            )
        };
        if r != 0 {
            let e = io::Error::last_os_error();
            assert_eq!(e.raw_os_error(), Some(libc::ENOPROTOOPT));
            assert!(!kernel_at_least(6, 16), "SO_PASSRIGHTS refused: {}", e);
            return eprintln!("skipping: SO_PASSRIGHTS needs Linux 6.16");
        }
        let e = send_with_fds(a.as_fd(), b"x", &[a.as_fd()]).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EPERM));
        allow_passed_fds(b.as_fd());
        assert_eq!(send_with_fds(a.as_fd(), b"x", &[a.as_fd()]).unwrap(), 1);
        let mut buf = [0u8; 1];
        let received = recv_with_fds(b.as_fd(), &mut buf).unwrap();
        assert_eq!((received.bytes, received.fds.len(), received.truncated), (1, 1, false));
    }

    /// pidfd_open() has the number of this architecture: the kernel shows
    /// our pid for the descriptor.
    #[test]
    fn pidfd_open_opens_a_pidfd() {
        // SAFETY: getpid() has no preconditions.
        let pid = unsafe { libc::getpid() };
        let fd = pidfd_open(pid).expect("pidfd_open() failed");
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        assert!(info.lines().any(|l| l == format!("Pid:\t{}", pid)), "{}", info);
        assert!(own_pidfd_inode().is_some());
    }
}
