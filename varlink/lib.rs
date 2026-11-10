// SPDX-License-Identifier: LGPL-2.1-or-later
//! A Varlink server for tools, done the way systemd's tools do it.
//!
//! The service manager (or `varlinkctl call exec:...`) passes one socket as
//! file descriptor 3, announced through `LISTEN_FDS=1`,
//! `LISTEN_PID=<pid>` and `LISTEN_FDNAMES=varlink`. [`activation`] detects
//! that, [`Server::run`] serves the connection until the peer hangs up, and
//! the process exits. `SYSTEMD_VARLINK_LISTEN` takes the same addresses as
//! sd-varlink: `-` for stdin/stdout, an absolute path or `@name` for a
//! socket to listen on.
//!
//! The wire protocol follows the UAPI group's Varlink specification as
//! sd-varlink implements it: NUL terminated JSON objects, `method`,
//! `parameters`, `oneway`, `more` and `upgrade` in calls, `parameters`,
//! `error` and `continues` in replies, malformed messages end the
//! connection, and parameters are validated against the interface
//! description before a method sees them.
//!
//! On a listening socket, connections are served concurrently and only
//! peers running as root or as the server's own user are accepted, like
//! sd-varlink's `ROOT_ONLY|MYSELF_ONLY`. The server exits once the last
//! connection is gone.
//!
//! A client that gives up on a call closes the connection and, over the
//! `exec:` transport, sends SIGTERM. So that this cannot cut a write short,
//! SIGTERM is blocked on the serving thread while a call is being handled
//! and acted on between calls.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod idl;
mod sys;

use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::linux::net::SocketAddrExt;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

pub use json::{Object, Value};

/// Largest message accepted, the same limit sd-varlink uses.
pub const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

/// How long a peer may take to deliver the rest of a message it has
/// started, and how long it may take to accept a reply. A connection that
/// is idle between messages has no limit.
pub const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Connections served at once unless [`Server::set_max_connections`] says
/// otherwise. Beyond that accepting pauses and the kernel queues peers in
/// the listen backlog until a connection finishes.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Stack of a thread serving a connection. The handlers recurse at most as
/// deep as a JSON document, which the parser bounds, and as deep as a path,
/// which has a limit of its own; 8 MiB leaves room and costs address space
/// only.
const SERVE_STACK: usize = 8 << 20;

/// Interface descriptions every server carries.
pub const ORG_VARLINK_SERVICE: &str = include_str!("org.varlink.service.varlink");
/// The `io.systemd` interface, home of the generic `io.systemd.System`
/// errno error.
pub const IO_SYSTEMD: &str = include_str!("io.systemd.varlink");
/// The most file descriptors one message carries, the kernel's SCM_MAX_FD.
pub const MAX_FDS: usize = sys::MAX_FDS;

/// A bidirectional byte stream carrying a connection.
pub trait Stream: Read + Write + Send {
    /// The socket under the stream, when there is one. File descriptors
    /// can only travel over an AF_UNIX socket, so a stream without one
    /// never carries any, in either direction.
    fn socket(&self) -> Option<BorrowedFd<'_>> {
        None
    }
}

impl Stream for UnixStream {
    fn socket(&self) -> Option<BorrowedFd<'_>> {
        Some(self.as_fd())
    }
}

/// A method call as received.
#[derive(Clone, Debug, PartialEq)]
pub struct Call {
    /// Fully qualified method name.
    pub method: String,
    /// The parameters, `{}` when absent or null.
    pub parameters: Object,
    /// The client does not want a reply.
    pub oneway: bool,
    /// The client accepts multiple replies.
    pub more: bool,
    /// The client asks to take over the connection after the reply.
    pub upgrade: bool,
}

/// An error reply.
#[derive(Clone, Debug, PartialEq)]
pub struct Error {
    /// Fully qualified error name.
    pub name: String,
    /// Error parameters.
    pub parameters: Object,
}

impl Error {
    /// An error with parameters.
    pub fn new(name: impl Into<String>, parameters: Object) -> Error {
        Error {
            name: name.into(),
            parameters,
        }
    }

    /// `org.varlink.service.InterfaceNotFound`
    pub fn interface_not_found(interface: &str) -> Error {
        Error::new(
            "org.varlink.service.InterfaceNotFound",
            json::object! { "interface" => interface },
        )
    }

    /// `org.varlink.service.MethodNotFound`
    pub fn method_not_found(method: &str) -> Error {
        Error::new(
            "org.varlink.service.MethodNotFound",
            json::object! { "method" => method },
        )
    }

    /// `org.varlink.service.MethodNotImplemented`
    pub fn method_not_implemented(method: &str) -> Error {
        Error::new(
            "org.varlink.service.MethodNotImplemented",
            json::object! { "method" => method },
        )
    }

    /// `org.varlink.service.InvalidParameter`
    pub fn invalid_parameter(parameter: &str) -> Error {
        Error::new(
            "org.varlink.service.InvalidParameter",
            json::object! { "parameter" => parameter },
        )
    }

    /// `org.varlink.service.PermissionDenied`
    pub fn permission_denied() -> Error {
        Error::new("org.varlink.service.PermissionDenied", Object::new())
    }

    /// `org.varlink.service.ExpectedMore`
    pub fn expected_more() -> Error {
        Error::new("org.varlink.service.ExpectedMore", Object::new())
    }

    /// `org.varlink.service.ExpectedUpgrade`
    pub fn expected_upgrade() -> Error {
        Error::new("org.varlink.service.ExpectedUpgrade", Object::new())
    }

    /// `io.systemd.System`, the generic errno error systemd tools use.
    pub fn system(errno: i32) -> Error {
        let errno = i32::try_from(errno.unsigned_abs()).unwrap_or(i32::MAX);
        let mut p = json::object! { "origin" => "linux", "errno" => errno };
        if let Some(name) = errno_name(errno) {
            p.insert("errnoName", name);
        }
        Error::new("io.systemd.System", p)
    }
}

// The names of systemd's errno list, which leaves out the aliases
// EWOULDBLOCK, EDEADLOCK, ENOTSUP, ECANCELLED and EREFUSED. The numbers
// come from libc, so they are this architecture's.
macro_rules! errno_names {
    ($($name:ident)*) => {
        /// The name of an errno value, as systemd's errno_to_name() has it.
        fn errno_name(errno: i32) -> Option<&'static str> {
            match errno {
                $(libc::$name => Some(stringify!($name)),)*
                _ => None,
            }
        }

        /// Every name with its number.
        #[cfg(test)]
        const ERRNO_NAMES: &[(&str, i32)] = &[$((stringify!($name), libc::$name)),*];
    };
}

errno_names! {
    EPERM ENOENT ESRCH EINTR EIO ENXIO E2BIG ENOEXEC EBADF ECHILD EAGAIN ENOMEM EACCES EFAULT ENOTBLK EBUSY EEXIST
    EXDEV ENODEV ENOTDIR EISDIR EINVAL ENFILE EMFILE ENOTTY ETXTBSY EFBIG ENOSPC ESPIPE EROFS EMLINK EPIPE EDOM
    ERANGE EDEADLK ENAMETOOLONG ENOLCK ENOSYS ENOTEMPTY ELOOP ENOMSG EIDRM ECHRNG EL2NSYNC EL3HLT EL3RST ELNRNG
    EUNATCH ENOCSI EL2HLT EBADE EBADR EXFULL ENOANO EBADRQC EBADSLT EBFONT ENOSTR ENODATA ETIME ENOSR ENONET ENOPKG
    EREMOTE ENOLINK EADV ESRMNT ECOMM EPROTO EMULTIHOP EDOTDOT EBADMSG EOVERFLOW ENOTUNIQ EBADFD EREMCHG ELIBACC
    ELIBBAD ELIBSCN ELIBMAX ELIBEXEC EILSEQ ERESTART ESTRPIPE EUSERS ENOTSOCK EDESTADDRREQ EMSGSIZE EPROTOTYPE
    ENOPROTOOPT EPROTONOSUPPORT ESOCKTNOSUPPORT EOPNOTSUPP EPFNOSUPPORT EAFNOSUPPORT EADDRINUSE EADDRNOTAVAIL
    ENETDOWN ENETUNREACH ENETRESET ECONNABORTED ECONNRESET ENOBUFS EISCONN ENOTCONN ESHUTDOWN ETOOMANYREFS ETIMEDOUT
    ECONNREFUSED EHOSTDOWN EHOSTUNREACH EALREADY EINPROGRESS ESTALE EUCLEAN ENOTNAM ENAVAIL EISNAM EREMOTEIO EDQUOT
    ENOMEDIUM EMEDIUMTYPE ECANCELED ENOKEY EKEYEXPIRED EKEYREVOKED EKEYREJECTED EOWNERDEAD ENOTRECOVERABLE ERFKILL
    EHWPOISON
}

/// What a method handler returns.
#[derive(Debug)]
pub enum Reply {
    /// The call succeeded with these output parameters.
    Final(Object),
    /// The call failed.
    Error(Error),
    /// The handler confirmed an upgrade with [`Connection::upgrade`] and now
    /// owns the stream; the server stops serving this connection.
    Upgraded,
}

/// The raw stream after a confirmed upgrade.
pub struct Upgraded {
    /// The connection's stream.
    pub stream: Box<dyn Stream>,
    /// Bytes already read from the stream after the upgrading call. They
    /// belong to the upgraded protocol.
    pub buffered: Vec<u8>,
}

impl fmt::Debug for Upgraded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgraded")
            .field("buffered", &self.buffered.len())
            .finish_non_exhaustive()
    }
}

/// Why a connection ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disconnect {
    /// The peer closed the connection, or the write side broke.
    Closed,
    /// The peer sent something that is not Varlink; the connection was
    /// dropped without a reply, as sd-varlink does.
    Protocol(&'static str),
    /// A handler took the stream over.
    Upgraded,
}

/// A connection with a client.
pub struct Connection {
    stream: Option<Box<dyn Stream>>,
    buffer: Vec<u8>,
    /// How far the buffer has been scanned for a NUL.
    scanned: usize,
    /// Flags of the call being handled.
    more: bool,
    upgrade: bool,
    /// The descriptors that arrived with the message being handled, in
    /// the order sent; None once a handler took one. Whatever is left is
    /// closed when the call is answered.
    fds: Vec<Option<OwnedFd>>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("upgraded", &self.stream.is_none())
            .field("buffered", &self.buffer.len())
            .field("more", &self.more)
            .field("upgrade", &self.upgrade)
            .field("fds", &self.fds)
            .finish_non_exhaustive()
    }
}

enum Message {
    Data(Vec<u8>),
    End(Disconnect),
}

/// Whether an I/O error means the peer went away.
fn peer_gone(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}

/// What one attempt to read from the peer came to.
enum ReadOutcome {
    /// Try again.
    Retry,
    /// This many bytes arrived (0: end of stream).
    Bytes(usize),
    /// The connection is over.
    End(Disconnect),
}

/// Sorts a read's result the same way for every kind of stream: a signal
/// means try again, a timeout is fine between messages but not inside one,
/// a peer that went away reads as the end of the stream.
fn classify(result: io::Result<usize>, mid_message: bool) -> io::Result<ReadOutcome> {
    Ok(match result {
        Ok(n) => ReadOutcome::Bytes(n),
        Err(e) if e.kind() == io::ErrorKind::Interrupted => ReadOutcome::Retry,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
            if mid_message {
                ReadOutcome::End(Disconnect::Protocol("message not completed in time"))
            } else {
                // Idle between messages: the peer may take its time.
                ReadOutcome::Retry
            }
        }
        Err(e) if peer_gone(&e) => ReadOutcome::Bytes(0),
        Err(e) => return Err(e),
    })
}

impl Connection {
    fn new(stream: Box<dyn Stream>) -> Connection {
        Connection {
            stream: Some(stream),
            buffer: Vec::new(),
            scanned: 0,
            more: false,
            upgrade: false,
            fds: Vec::new(),
        }
    }

    /// Reads the next NUL terminated message.
    ///
    /// On a socket the read is bounded to the next NUL, the way sd-varlink
    /// bounds it: the descriptors a client sends with a call travel with
    /// the call's first byte, and the kernel may hand them out together
    /// with the tail of whatever came before, so a message is never read
    /// past its end and a read never straddles two messages. Descriptors
    /// that arrive once part of a message is in hand belong to nothing
    /// and end the connection, as they do there.
    fn read_message(&mut self) -> io::Result<Message> {
        loop {
            if let Some(pos) = self.buffer[self.scanned..].iter().position(|&b| b == 0) {
                let end = self.scanned + pos;
                let message = self.buffer[..end].to_vec();
                self.buffer.drain(..=end);
                self.scanned = 0;
                return Ok(Message::Data(message));
            }
            self.scanned = self.buffer.len();
            // Including the terminating NUL a message may be at most
            // MAX_MESSAGE_SIZE bytes, so never read past that.
            let room = MAX_MESSAGE_SIZE.saturating_sub(self.buffer.len());
            if room == 0 {
                return Ok(Message::End(Disconnect::Protocol("message too large")));
            }
            let Some(stream) = self.stream.as_mut() else {
                return Ok(Message::End(Disconnect::Upgraded));
            };
            let mid_message = !self.buffer.is_empty();
            let mut chunk = vec![0u8; room.min(65536)];
            let n = match stream.socket() {
                Some(fd) => {
                    let peeked = match classify(sys::peek(fd, &mut chunk), mid_message)? {
                        ReadOutcome::Retry => continue,
                        ReadOutcome::End(why) => return Ok(Message::End(why)),
                        ReadOutcome::Bytes(n) => n,
                    };
                    if peeked == 0 {
                        0
                    } else {
                        let want = chunk[..peeked].iter().position(|&b| b == 0).map_or(peeked, |p| p + 1);
                        let received = match sys::recv_with_fds(fd, &mut chunk[..want]) {
                            Ok(r) => r,
                            Err(e) => match classify(Err(e), mid_message)? {
                                ReadOutcome::Retry => continue,
                                ReadOutcome::End(why) => return Ok(Message::End(why)),
                                ReadOutcome::Bytes(n) => {
                                    debug_assert_eq!(n, 0);
                                    sys::Received {
                                        bytes: 0,
                                        fds: Vec::new(),
                                        truncated: false,
                                    }
                                }
                            },
                        };
                        if !received.fds.is_empty() {
                            if mid_message {
                                return Ok(Message::End(Disconnect::Protocol(
                                    "file descriptors arrived in the middle of a message",
                                )));
                            }
                            // Dropped ones (MSG_CTRUNC) are simply missing:
                            // a handler that asks for their index is told so.
                            if received.truncated {
                                eprintln!("varlink: the kernel dropped file descriptors sent with a call");
                            }
                            self.fds = received.fds.into_iter().map(Some).collect();
                        }
                        received.bytes
                    }
                }
                None => match classify(stream.read(&mut chunk), mid_message)? {
                    ReadOutcome::Retry => continue,
                    ReadOutcome::End(why) => return Ok(Message::End(why)),
                    ReadOutcome::Bytes(n) => n,
                },
            };
            if n == 0 {
                self.fds.clear();
                return Ok(Message::End(if self.buffer.is_empty() {
                    Disconnect::Closed
                } else {
                    Disconnect::Protocol("connection closed inside a message")
                }));
            }
            self.buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// How many file descriptors came with the call being handled.
    pub fn fd_count(&self) -> usize {
        self.fds.len()
    }

    /// Takes ownership of the `index`th descriptor sent with the call being
    /// handled, counting from 0 in the order the client passed them: the
    /// number an `...FileDescriptor` parameter carries. ENXIO when no such
    /// descriptor came, EBADF when it was taken already; the same errors
    /// sd_varlink_take_fd() gives. Whatever is not taken is closed when the
    /// call is answered.
    pub fn take_fd(&mut self, index: usize) -> io::Result<OwnedFd> {
        match self.fds.get_mut(index) {
            None => Err(io::Error::from_raw_os_error(libc::ENXIO)),
            Some(slot) => slot.take().ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF)),
        }
    }

    fn send(&mut self, message: &Object) -> io::Result<()> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection was upgraded"))?;
        let mut text = message.to_string().into_bytes();
        text.push(0);
        stream.write_all(&text)?;
        stream.flush()
    }

    /// Sends an intermediate reply. Only valid while handling a call made
    /// with the `more` flag.
    pub fn notify(&mut self, parameters: Object) -> io::Result<()> {
        if !self.more {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the call was made without the more flag",
            ));
        }
        let mut m = Object::new();
        if !parameters.is_empty() {
            m.insert("parameters", parameters);
        }
        m.insert("continues", true);
        self.send(&m)
    }

    /// Confirms an upgrade request with a final reply and hands the raw
    /// stream over. Only valid while handling a call made with the `upgrade`
    /// flag. The handler must then return [`Reply::Upgraded`].
    pub fn upgrade(&mut self, parameters: Object) -> io::Result<Upgraded> {
        if !self.upgrade {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the call was made without the upgrade flag",
            ));
        }
        let mut m = Object::new();
        if !parameters.is_empty() {
            m.insert("parameters", parameters);
        }
        self.send(&m)?;
        let stream = self
            .stream
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection was upgraded"))?;
        Ok(Upgraded {
            stream,
            buffered: std::mem::take(&mut self.buffer),
        })
    }
}

/// Service meta information for `org.varlink.service.GetInfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    /// Vendor name.
    pub vendor: String,
    /// Product name.
    pub product: String,
    /// Version string.
    pub version: String,
    /// URL with more information.
    pub url: String,
}

/// Implements the methods of one or more interfaces. Connections of a
/// listening socket are served on separate threads, hence `Sync`.
pub trait Service: Sync {
    /// Handles a call whose parameters already passed validation against
    /// the interface description. Streaming replies go through
    /// [`Connection::notify`], upgrades through [`Connection::upgrade`].
    fn call(&self, call: &Call, connection: &mut Connection) -> Reply;
}

/// Serves interfaces.
#[derive(Debug)]
pub struct Server {
    info: Info,
    interfaces: BTreeMap<String, idl::Interface>,
    any_peer: bool,
    defer_sigterm: bool,
    max_connections: usize,
}

/// Blocks SIGTERM on the current thread until dropped.
struct DeferSigterm(bool);

impl DeferSigterm {
    fn new(active: bool) -> DeferSigterm {
        DeferSigterm(active && sys::block_sigterm().is_ok())
    }
}

impl Drop for DeferSigterm {
    fn drop(&mut self) {
        if self.0 {
            // A SIGTERM that arrived meanwhile terminates the process here,
            // after the reply went out.
            let _ = sys::unblock_sigterm();
        }
    }
}

impl Server {
    /// A server carrying `org.varlink.service` and `io.systemd`.
    pub fn new(info: Info) -> Server {
        let mut s = Server {
            info,
            interfaces: BTreeMap::new(),
            any_peer: false,
            defer_sigterm: true,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        };
        s.add_interface(ORG_VARLINK_SERVICE).expect("built-in interface parses");
        s.add_interface(IO_SYSTEMD).expect("built-in interface parses");
        s
    }

    /// How many connections a listening socket serves at once; at least
    /// one. Further peers wait in the backlog.
    pub fn set_max_connections(&mut self, count: usize) {
        self.max_connections = count.max(1);
    }

    /// Registers an interface by its description.
    pub fn add_interface(&mut self, description: &str) -> Result<(), idl::Error> {
        let iface = idl::parse(description)?;
        self.interfaces.insert(iface.name.clone(), iface);
        Ok(())
    }

    /// Accepts connections from any user on listening sockets. By default
    /// only root and the server's own user are served.
    pub fn set_allow_any_peer(&mut self, allow: bool) {
        self.any_peer = allow;
    }

    /// Whether SIGTERM is deferred while a call is handled, on by default.
    pub fn set_defer_sigterm(&mut self, defer: bool) {
        self.defer_sigterm = defer;
    }

    /// The registered interfaces.
    pub fn interfaces(&self) -> impl Iterator<Item = &idl::Interface> {
        self.interfaces.values()
    }

    /// Parses and checks a request. Err means the connection must be closed.
    fn parse_call(&self, message: &[u8]) -> Result<Call, &'static str> {
        let text = std::str::from_utf8(message).map_err(|_| "message is not UTF-8")?;
        let value = json::parse(text).map_err(|_| "message is not valid JSON")?;
        let Value::Object(mut object) = value else {
            return Err("message is not a JSON object");
        };
        // The parameters are taken out of the message, not copied: they can
        // be most of a message of MAX_MESSAGE_SIZE bytes.
        let parameters = match object.remove("parameters") {
            None | Some(Value::Null) => Object::new(),
            Some(Value::Object(o)) => o,
            Some(_) => return Err("parameters is not an object"),
        };
        let mut call = Call {
            method: String::new(),
            parameters,
            oneway: false,
            more: false,
            upgrade: false,
        };
        let mut has_method = false;
        let mut flags = 0;
        for (key, value) in object.iter() {
            match key {
                "method" => {
                    call.method = value.as_str().ok_or("method is not a string")?.to_string();
                    has_method = true;
                }
                "oneway" | "more" | "upgrade" => {
                    let b = value.as_bool().ok_or("flag is not a boolean")?;
                    if b {
                        flags += 1;
                    }
                    match key {
                        "oneway" => call.oneway = b,
                        "more" => call.more = b,
                        _ => call.upgrade = b,
                    }
                }
                // Vendor extensions live under reverse domain keys and are
                // ignored, as the specification asks; anything else is a
                // protocol error.
                k if k.contains('.') => {}
                _ => return Err("unknown field in call"),
            }
        }
        if !has_method {
            return Err("call without method");
        }
        if flags > 1 {
            return Err("more than one of oneway, more and upgrade set");
        }
        Ok(call)
    }

    fn get_info(&self) -> Object {
        json::object! {
            "vendor" => self.info.vendor.as_str(),
            "product" => self.info.product.as_str(),
            "version" => self.info.version.as_str(),
            "url" => self.info.url.as_str(),
            "interfaces" => self.interfaces.keys().cloned().collect::<Vec<_>>(),
        }
    }

    /// Dispatches one call: the built-in methods, or the service after
    /// validating the parameters.
    fn dispatch(&self, call: &Call, connection: &mut Connection, service: &dyn Service) -> Reply {
        let Some((interface, method)) = call.method.rsplit_once('.') else {
            return Reply::Error(Error::method_not_found(&call.method));
        };
        match (interface, method) {
            ("org.varlink.service", "GetInfo") => {
                if let Some(key) = call.parameters.keys().next() {
                    return Reply::Error(Error::invalid_parameter(key));
                }
                Reply::Final(self.get_info())
            }
            ("org.varlink.service", "GetInterfaceDescription") => {
                let service_iface = &self.interfaces["org.varlink.service"];
                let input = &service_iface.methods["GetInterfaceDescription"].input;
                if let Err(p) = service_iface.validate(input, &call.parameters) {
                    return Reply::Error(Error::invalid_parameter(p));
                }
                let name = call.parameters.get("interface").and_then(Value::as_str).unwrap_or("");
                match self.interfaces.get(name) {
                    Some(i) => Reply::Final(json::object! { "description" => i.text.as_str() }),
                    None => Reply::Error(Error::interface_not_found(name)),
                }
            }
            _ => {
                let Some(iface) = self.interfaces.get(interface) else {
                    return Reply::Error(Error::method_not_found(&call.method));
                };
                let Some(m) = iface.methods.get(method) else {
                    return Reply::Error(Error::method_not_found(&call.method));
                };
                if let Err(p) = iface.validate(&m.input, &call.parameters) {
                    return Reply::Error(Error::invalid_parameter(p));
                }
                if m.requires_more && !call.more {
                    return Reply::Error(Error::expected_more());
                }
                if m.requires_upgrade && !call.upgrade {
                    return Reply::Error(Error::expected_upgrade());
                }
                service.call(call, connection)
            }
        }
    }

    /// Serves one connection until it ends.
    pub fn serve(&self, stream: Box<dyn Stream>, service: &dyn Service) -> io::Result<Disconnect> {
        self.serve_with(stream, service, self.defer_sigterm)
    }

    /// `serve` with an explicit decision on blocking SIGTERM per call. The
    /// listener's threads have it blocked for good and pass false.
    fn serve_with(
        &self,
        stream: Box<dyn Stream>,
        service: &dyn Service,
        defer_sigterm: bool,
    ) -> io::Result<Disconnect> {
        let mut connection = Connection::new(stream);
        loop {
            let message = match connection.read_message()? {
                Message::Data(m) => m,
                Message::End(why) => return Ok(why),
            };
            let call = match self.parse_call(&message) {
                Ok(c) => c,
                Err(why) => return Ok(Disconnect::Protocol(why)),
            };
            connection.more = call.more;
            connection.upgrade = call.upgrade;
            let deferred = DeferSigterm::new(defer_sigterm);
            let reply = self.dispatch(&call, &mut connection, service);
            // The call is answered now: descriptors it came with that no
            // handler took go, as they do in sd-varlink.
            connection.fds.clear();
            let message = match reply {
                Reply::Upgraded => {
                    drop(deferred);
                    return Ok(Disconnect::Upgraded);
                }
                _ if call.oneway => {
                    drop(deferred);
                    continue;
                }
                Reply::Final(parameters) => {
                    let mut m = Object::new();
                    if !parameters.is_empty() {
                        m.insert("parameters", parameters);
                    }
                    m
                }
                Reply::Error(e) => {
                    let mut m = json::object! { "error" => e.name.as_str() };
                    if !e.parameters.is_empty() {
                        m.insert("parameters", e.parameters);
                    }
                    m
                }
            };
            let sent = connection.send(&message);
            drop(deferred);
            match sent {
                Ok(()) => {}
                Err(e) if peer_gone(&e) => return Ok(Disconnect::Closed),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    return Ok(Disconnect::Protocol("reply not accepted in time"))
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Whether a connection from this peer is served.
    fn peer_allowed(&self, stream: &UnixStream) -> bool {
        if self.any_peer {
            return true;
        }
        match sys::peer_credentials(stream.as_fd()) {
            Ok((_, uid, _)) => uid == 0 || uid == sys::effective_uid(),
            Err(_) => false,
        }
    }

    /// Accepts and serves connections concurrently, and returns once the
    /// first connection has come and gone and none is left, or once a
    /// SIGTERM arrived and the connections in flight have finished.
    fn listen(&self, listener: UnixListener, service: &dyn Service) -> io::Result<()> {
        listener.set_nonblocking(true)?;
        // Set on the listening socket, before anything is accepted, so
        // that every connection inherits it and no client can race us.
        sys::allow_passed_fds(listener.as_fd());
        // SIGTERM is blocked in this thread, and so in every serving thread
        // spawned below, for the whole run: it arrives through a descriptor
        // instead and means "stop accepting, finish what is in flight, exit".
        // Blocking it per call in the serving threads would not do: the
        // kernel delivers a process-directed signal to any thread that has
        // it unblocked at the time, and that kills the whole process while
        // another thread may be half way through a write.
        let term = if self.defer_sigterm {
            sys::block_sigterm()?;
            Some(sys::sigterm_fd()?)
        } else {
            None
        };
        let live = AtomicUsize::new(0);
        let mut served_any = false;
        let mut stopping = false;
        std::thread::scope(|scope| -> io::Result<()> {
            loop {
                if stopping {
                    if live.load(Ordering::SeqCst) == 0 {
                        return Ok(());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                if live.load(Ordering::SeqCst) >= self.max_connections {
                    // Full: new peers wait in the backlog. SIGTERM is still
                    // acted on.
                    match &term {
                        Some(fd) => {
                            let [terminated] = sys::wait_readable([fd.as_fd()], Some(50))?;
                            if terminated {
                                stopping = true;
                            }
                        }
                        None => std::thread::sleep(std::time::Duration::from_millis(50)),
                    }
                    continue;
                }
                // Block for the first client; afterwards look for more work
                // now and then and leave once idle, like exit-on-idle.
                let timeout = if served_any { Some(100) } else { None };
                let [readable, terminated] = match &term {
                    Some(fd) => sys::wait_readable([listener.as_fd(), fd.as_fd()], timeout)?,
                    None => {
                        let [readable] = sys::wait_readable([listener.as_fd()], timeout)?;
                        [readable, false]
                    }
                };
                if terminated {
                    stopping = true;
                    continue;
                }
                if !readable {
                    if live.load(Ordering::SeqCst) == 0 {
                        return Ok(());
                    }
                    continue;
                }
                let stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if !self.peer_allowed(&stream) {
                    continue;
                }
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                served_any = true;
                live.fetch_add(1, Ordering::SeqCst);
                let live = &live;
                let spawned = std::thread::Builder::new()
                    .name("varlink-connection".into())
                    .stack_size(SERVE_STACK)
                    .spawn_scoped(scope, move || {
                        match self.serve_with(Box::new(stream), service, false) {
                            Ok(Disconnect::Protocol(why)) => eprintln!("varlink: dropped a connection: {}", why),
                            Ok(_) => {}
                            Err(e) => eprintln!("varlink: connection failed: {}", e),
                        }
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                if let Err(e) = spawned {
                    // The connection went with the closure that was not run.
                    live.fetch_sub(1, Ordering::SeqCst);
                    eprintln!("varlink: could not start a thread for a connection: {}", e);
                }
            }
        })
    }

    /// Serves whatever the environment handed over, and returns when the
    /// last connection is gone. A peer that violates the protocol gets its
    /// connection dropped with a note on stderr, not an error.
    pub fn run(&self, activation: Activation, service: &dyn Service) -> io::Result<()> {
        match activation {
            Activation::Stdio => self.serve_one(Box::new(StdioStream), service),
            Activation::Connection(stream) => {
                // A connected socket comes from whoever could connect to the
                // socket a unit with Accept=yes listens on, so the peer is
                // checked like one accepted here. sd-varlink does the same.
                if !self.peer_allowed(&stream) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "the peer is neither root nor the user this service runs as",
                    ));
                }
                stream.set_read_timeout(Some(IO_TIMEOUT))?;
                stream.set_write_timeout(Some(IO_TIMEOUT))?;
                self.serve_one(Box::new(stream), service)
            }
            Activation::Listener(listener) => self.listen(listener, service),
        }
    }

    fn serve_one(&self, stream: Box<dyn Stream>, service: &dyn Service) -> io::Result<()> {
        if let Disconnect::Protocol(why) = self.serve(stream, service)? {
            eprintln!("varlink: dropped the connection: {}", why);
        }
        Ok(())
    }
}

/// How the process was handed its Varlink socket.
#[derive(Debug)]
pub enum Activation {
    /// One connected socket to serve, for a peer that passes the same check
    /// as an accepted connection.
    Connection(UnixStream),
    /// Standard input and output as the connection
    /// (`SYSTEMD_VARLINK_LISTEN=-`). No peer to check.
    Stdio,
    /// A listening socket to accept connections on.
    Listener(UnixListener),
}

/// stdin and stdout as one stream.
struct StdioStream;

impl Read for StdioStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::stdin().lock().read(buf)
    }
}

impl Write for StdioStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stdout().lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().lock().flush()
    }
}

impl Stream for StdioStream {}

/// Binds a listening socket for a `SYSTEMD_VARLINK_LISTEN` address: an
/// absolute path (0644, a stale socket file is replaced) or `@name` for
/// the abstract namespace. `unix:` in front is accepted for convenience.
fn bind(address: &str) -> io::Result<UnixListener> {
    let address = address.strip_prefix("unix:").unwrap_or(address);
    if let Some(name) = address.strip_prefix('@') {
        let addr = SocketAddr::from_abstract_name(name)?;
        return UnixListener::bind_addr(&addr);
    }
    if !address.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Varlink listen address '{}' is not an absolute path, @name or -",
                address
            ),
        ));
    }
    let path = Path::new(address);
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))?;
    Ok(listener)
}

/// Detects a Varlink invocation. Returns Ok(None) when the process was
/// started normally.
///
/// `SYSTEMD_VARLINK_LISTEN` wins: `-` serves stdin/stdout, anything else is
/// bound as a listening socket (see [`bind`]). Otherwise a single
/// descriptor passed as fd 3 with `LISTEN_PID` matching, `LISTEN_FDS=1`
/// and `LISTEN_FDNAMES=varlink` is taken, `LISTEN_PIDFDID` is checked when
/// present, and `SO_ACCEPTCONN` decides whether to accept on the socket or
/// to serve it.
///
/// The `LISTEN_*` variables are removed from the environment, so that no
/// child inherits them. Changing the environment is not thread safe: call
/// this before the process starts any thread.
pub fn activation() -> io::Result<Option<Activation>> {
    if let Ok(listen) = std::env::var("SYSTEMD_VARLINK_LISTEN") {
        if listen == "-" {
            return Ok(Some(Activation::Stdio));
        }
        return Ok(Some(Activation::Listener(bind(&listen)?)));
    }
    let Some(pid) = std::env::var("LISTEN_PID").ok().and_then(|p| p.parse::<u32>().ok()) else {
        return Ok(None);
    };
    if pid != std::process::id() {
        return Ok(None);
    }
    let Some(fds) = std::env::var("LISTEN_FDS").ok().and_then(|p| p.parse::<u32>().ok()) else {
        return Ok(None);
    };
    let names = std::env::var("LISTEN_FDNAMES").unwrap_or_default();
    let pidfd_id = std::env::var("LISTEN_PIDFDID").ok().and_then(|p| p.parse::<u64>().ok());
    for key in ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PIDFDID"] {
        std::env::remove_var(key);
    }
    if let (Some(id), Some(own)) = (pidfd_id, sys::own_pidfd_inode()) {
        // The variables were meant for an earlier process with our pid.
        if id != own {
            return Ok(None);
        }
    }
    if fds == 0 {
        return Ok(None);
    }
    if fds != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} file descriptors passed, expected one", fds),
        ));
    }
    if names != "varlink" {
        return Ok(None);
    }
    // SAFETY: the service manager promised fd 3 to us and nothing else in
    // this process has claimed it.
    #[allow(unsafe_code)]
    let fd = unsafe { sys::take_fd(3) };
    sys::set_cloexec(fd.as_fd())?;
    if sys::is_listening(fd.as_fd())? {
        Ok(Some(Activation::Listener(UnixListener::from(fd))))
    } else {
        let stream = UnixStream::from(fd);
        stream.set_nonblocking(false)?;
        sys::allow_passed_fds(stream.as_fd());
        Ok(Some(Activation::Connection(stream)))
    }
}

/// How a call wants to be answered: the flags of the Varlink protocol, of
/// which a call carries one at most.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CallMode {
    /// With one reply.
    #[default]
    Plain,
    /// With no reply at all (`oneway`).
    Oneway,
    /// With replies until one that does not continue (`more`).
    More,
    /// With one reply, after which the connection carries another protocol
    /// (`upgrade`).
    Upgrade,
}

/// A minimal client, for tests and for driving other services.
#[derive(Debug)]
pub struct Client {
    connection: Connection,
}

/// What a call returned.
#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    /// A reply, final unless `continues` is true.
    Reply {
        /// The output parameters.
        parameters: Object,
        /// Whether more replies follow.
        continues: bool,
    },
    /// An error.
    Error(Error),
}

fn protocol_error(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.to_string())
}

impl Client {
    /// Wraps a connected stream.
    pub fn new(stream: Box<dyn Stream>) -> Client {
        Client {
            connection: Connection::new(stream),
        }
    }

    /// Sends a call, to be answered the way `mode` asks.
    pub fn send(&mut self, method: &str, parameters: Object, mode: CallMode) -> io::Result<()> {
        let mut m = json::object! { "method" => method };
        if !parameters.is_empty() {
            m.insert("parameters", parameters);
        }
        let flag = match mode {
            CallMode::Plain => None,
            CallMode::Oneway => Some("oneway"),
            CallMode::More => Some("more"),
            CallMode::Upgrade => Some("upgrade"),
        };
        if let Some(flag) = flag {
            m.insert(flag, true);
        }
        self.connection.more = mode == CallMode::More;
        self.connection.send(&m)
    }

    /// Sends a call with file descriptors attached, the way
    /// sd_varlink_push_fd() plus a call does: one message, the descriptors
    /// travelling with its first byte, index `i` in the parameters naming
    /// `fds[i]`. The stream has to be a socket (ENOTSOCK otherwise), at
    /// most [`MAX_FDS`] descriptors go in one call.
    pub fn send_with_fds(&mut self, method: &str, parameters: Object, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.send_fds(method, parameters, fds, false)
    }

    /// [`Client::send_with_fds`] with the `more` flag set, for a method
    /// that answers with several replies; [`Client::receive`] then takes
    /// the replies that continue until the one that does not.
    pub fn send_more_with_fds(&mut self, method: &str, parameters: Object, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        self.send_fds(method, parameters, fds, true)
    }

    fn send_fds(&mut self, method: &str, parameters: Object, fds: &[BorrowedFd<'_>], more: bool) -> io::Result<()> {
        let mut m = json::object! { "method" => method };
        if !parameters.is_empty() {
            m.insert("parameters", parameters);
        }
        if more {
            m.insert("more", true);
        }
        self.connection.more = more;
        let stream = self
            .connection
            .stream
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "connection was upgraded"))?;
        let socket = stream
            .socket()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOTSOCK))?;
        let mut text = m.to_string().into_bytes();
        text.push(0);
        let sent = sys::send_with_fds(socket, &text, fds)?;
        stream.write_all(&text[sent..])?;
        stream.flush()
    }

    /// Calls a method with file descriptors attached and waits for its
    /// single reply.
    pub fn call_with_fds(&mut self, method: &str, parameters: Object, fds: &[BorrowedFd<'_>]) -> io::Result<Response> {
        self.send_with_fds(method, parameters, fds)?;
        self.receive()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed without a reply"))
    }

    /// Reads the next reply, checking its shape the way sd-varlink does.
    /// Ok(None) means the server closed the connection.
    pub fn receive(&mut self) -> io::Result<Option<Response>> {
        let message = match self.connection.read_message()? {
            Message::Data(m) => m,
            Message::End(Disconnect::Protocol(why)) => return Err(protocol_error(why)),
            Message::End(_) => return Ok(None),
        };
        let text = std::str::from_utf8(&message).map_err(|_| protocol_error("reply is not UTF-8"))?;
        let value = json::parse(text).map_err(|_| protocol_error("reply is not JSON"))?;
        let Value::Object(mut object) = value else {
            return Err(protocol_error("reply is not an object"));
        };
        let parameters = match object.remove("parameters") {
            None | Some(Value::Null) => Object::new(),
            Some(Value::Object(o)) => o,
            Some(_) => return Err(protocol_error("unexpected field in reply")),
        };
        let mut error = None;
        let mut continues = false;
        for (key, value) in object.iter() {
            match (key, value) {
                ("error", Value::String(name)) => error = Some(name.clone()),
                ("continues", Value::Bool(b)) => continues = *b,
                (k, _) if k.contains('.') => {}
                _ => return Err(protocol_error("unexpected field in reply")),
            }
        }
        if let Some(name) = error {
            if continues {
                return Err(protocol_error("error reply with continues"));
            }
            return Ok(Some(Response::Error(Error::new(name, parameters))));
        }
        if continues && !self.connection.more {
            return Err(protocol_error("continues without more"));
        }
        Ok(Some(Response::Reply { parameters, continues }))
    }

    /// Calls a method and waits for its single reply.
    pub fn call(&mut self, method: &str, parameters: Object) -> io::Result<Response> {
        self.send(method, parameters, CallMode::Plain)?;
        self.receive()?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "connection closed without a reply"))
    }

    /// Takes the raw stream after a confirmed upgrade.
    pub fn into_upgraded(self) -> Upgraded {
        let mut c = self.connection;
        Upgraded {
            // Only a server's connection is ever upgraded in place; a
            // client's stream is there until it is taken here.
            stream: c.stream.take().expect("client stream present"),
            buffered: c.buffer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IDL: &str = "\
interface io.test.Echo

method Echo(text: string, times: ?int) -> (text: string)

# [Requires 'more' flag]
method Count(upto: int) -> (n: int)

# [Requires 'upgrade' flag]
method Take() -> (bytes: int)

method Read(fileDescriptor: int) -> (text: string)

error Boom(reason: string)
";

    struct Echo;

    impl Service for Echo {
        fn call(&self, call: &Call, connection: &mut Connection) -> Reply {
            match call.method.as_str() {
                "io.test.Echo.Echo" => {
                    let text = call.parameters.get("text").and_then(Value::as_str).unwrap();
                    let times = call.parameters.get("times").and_then(Value::as_u64).unwrap_or(1);
                    if text == "boom" {
                        return Reply::Error(Error::new(
                            "io.test.Echo.Boom",
                            json::object! { "reason" => "asked for it" },
                        ));
                    }
                    Reply::Final(json::object! { "text" => text.repeat(times as usize) })
                }
                "io.test.Echo.Count" => {
                    let upto = call.parameters.get("upto").and_then(Value::as_u64).unwrap();
                    for n in 0..upto {
                        connection.notify(json::object! { "n" => n }).unwrap();
                    }
                    Reply::Final(json::object! { "n" => upto })
                }
                "io.test.Echo.Read" => {
                    let index = call.parameters.get("fileDescriptor").and_then(Value::as_u64).unwrap() as usize;
                    match connection.take_fd(index) {
                        Ok(fd) => {
                            let mut text = String::new();
                            std::fs::File::from(fd).read_to_string(&mut text).unwrap();
                            Reply::Final(json::object! { "text" => text })
                        }
                        Err(_) => Reply::Error(Error::invalid_parameter("fileDescriptor")),
                    }
                }
                "io.test.Echo.Take" => {
                    let mut up = connection.upgrade(json::object! { "bytes" => 5u32 }).unwrap();
                    let mut data = up.buffered;
                    let mut rest = vec![0u8; 5 - data.len()];
                    up.stream.read_exact(&mut rest).unwrap();
                    data.extend(rest);
                    up.stream
                        .write_all(&data.iter().rev().copied().collect::<Vec<_>>())
                        .unwrap();
                    Reply::Upgraded
                }
                _ => Reply::Error(Error::method_not_implemented(&call.method)),
            }
        }
    }

    fn server() -> Server {
        let mut s = Server::new(Info {
            vendor: "test".into(),
            product: "echo".into(),
            version: "1".into(),
            url: "https://example.org".into(),
        });
        s.add_interface(TEST_IDL).unwrap();
        s
    }

    /// Runs the server on one end of a socket pair and returns a client on
    /// the other.
    fn pair() -> (Client, std::thread::JoinHandle<io::Result<Disconnect>>) {
        let (a, b) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || server().serve(Box::new(b), &Echo));
        (Client::new(Box::new(a)), handle)
    }

    /// A file holding `text`, open for reading from its start.
    fn file_with(name: &str, text: &str) -> std::fs::File {
        let path = std::env::temp_dir().join(format!("varlink-fd-{}-{}", std::process::id(), name));
        std::fs::write(&path, text).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }

    fn text_of(r: Response) -> String {
        match r {
            Response::Reply { parameters, .. } => parameters.get("text").unwrap().as_str().unwrap().to_string(),
            other => panic!("expected a reply, got {:?}", other),
        }
    }

    fn error_name(r: Response) -> String {
        match r {
            Response::Error(e) => e.name,
            other => panic!("expected an error, got {:?}", other),
        }
    }

    /// Descriptors sent with a call reach the handler of that call and no
    /// other: the ones a handler does not take are gone with the reply, a
    /// call without descriptors right behind one with them sees none, a
    /// bad index is told apart, and descriptors arriving inside a message
    /// end the connection, as they do with sd-varlink.
    #[test]
    fn descriptors_travel_with_their_call() {
        let (a, b) = UnixStream::pair().unwrap();
        let raw = a.try_clone().unwrap();
        let handle = std::thread::spawn(move || server().serve(Box::new(b), &Echo));
        let mut client = Client::new(Box::new(a));
        let one = file_with("one", "one");
        let two = file_with("two", "two");
        let r = client
            .call_with_fds(
                "io.test.Echo.Read",
                params(r#"{"fileDescriptor":1}"#),
                &[one.as_fd(), two.as_fd()],
            )
            .unwrap();
        assert_eq!(text_of(r), "two");
        // Nothing is left over for the next call.
        let r = client
            .call("io.test.Echo.Read", params(r#"{"fileDescriptor":0}"#))
            .unwrap();
        assert_eq!(error_name(r), "org.varlink.service.InvalidParameter");
        // Out of range.
        let one = file_with("one", "one");
        let r = client
            .call_with_fds("io.test.Echo.Read", params(r#"{"fileDescriptor":1}"#), &[one.as_fd()])
            .unwrap();
        assert_eq!(error_name(r), "org.varlink.service.InvalidParameter");
        // Two calls in flight: the descriptors belong to the second one.
        let one = file_with("one", "one");
        client
            .send("io.test.Echo.Read", params(r#"{"fileDescriptor":0}"#), CallMode::Plain)
            .unwrap();
        client
            .send_with_fds("io.test.Echo.Read", params(r#"{"fileDescriptor":0}"#), &[one.as_fd()])
            .unwrap();
        assert_eq!(
            error_name(client.receive().unwrap().unwrap()),
            "org.varlink.service.InvalidParameter"
        );
        assert_eq!(text_of(client.receive().unwrap().unwrap()), "one");
        // Half a message, then, once the server has that half, the rest
        // with descriptors attached: the connection is dropped without a
        // reply. (Sent in one go, the kernel would deliver the descriptors
        // with the whole message and they would simply belong to it.)
        let one = file_with("one", "one");
        let message = br#"{"method":"io.test.Echo.Read","parameters":{"fileDescriptor":0}}"#;
        (&raw).write_all(&message[..20]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let rest = [&message[20..], &[0u8][..]].concat();
        sys::send_with_fds(raw.as_fd(), &rest, &[one.as_fd()]).unwrap();
        assert!(client.receive().unwrap().is_none());
        assert_eq!(
            handle.join().unwrap().unwrap(),
            Disconnect::Protocol("file descriptors arrived in the middle of a message")
        );
    }

    fn params(text: &str) -> Object {
        json::parse(text).unwrap().as_object().unwrap().clone()
    }

    #[test]
    fn calls_and_errors() {
        let (mut c, h) = pair();
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"text":"ab","times":2}"#))
                .unwrap(),
            Response::Reply {
                parameters: params(r#"{"text":"abab"}"#),
                continues: false
            }
        );
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"text":"boom"}"#)).unwrap(),
            Response::Error(Error::new("io.test.Echo.Boom", params(r#"{"reason":"asked for it"}"#)))
        );
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"text":5}"#)).unwrap(),
            Response::Error(Error::invalid_parameter("text"))
        );
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"text":"a","bogus":1}"#))
                .unwrap(),
            Response::Error(Error::invalid_parameter("bogus"))
        );
        // Declared fields are checked before unknown keys, like sd-varlink.
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"bogus":1}"#)).unwrap(),
            Response::Error(Error::invalid_parameter("text"))
        );
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{}"#)).unwrap(),
            Response::Error(Error::invalid_parameter("text"))
        );
        assert_eq!(
            c.call("io.test.Echo.Nope", Object::new()).unwrap(),
            Response::Error(Error::method_not_found("io.test.Echo.Nope"))
        );
        assert_eq!(
            c.call("io.nope.X.Y", Object::new()).unwrap(),
            Response::Error(Error::method_not_found("io.nope.X.Y"))
        );
        assert_eq!(
            c.call("", Object::new()).unwrap(),
            Response::Error(Error::method_not_found(""))
        );
        assert_eq!(
            c.call("io.test.Echo.Count", params(r#"{"upto":3}"#)).unwrap(),
            Response::Error(Error::expected_more())
        );
        assert_eq!(
            c.call("io.test.Echo.Take", Object::new()).unwrap(),
            Response::Error(Error::expected_upgrade())
        );
        match c.call("org.varlink.service.GetInfo", Object::new()).unwrap() {
            Response::Reply { parameters, .. } => {
                assert_eq!(parameters.get("vendor").unwrap().as_str(), Some("test"));
                let ifaces: Vec<&str> = parameters
                    .get("interfaces")
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_str().unwrap())
                    .collect();
                assert_eq!(ifaces, vec!["io.systemd", "io.test.Echo", "org.varlink.service"]);
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(
            c.call("org.varlink.service.GetInfo", params(r#"{"x":1}"#)).unwrap(),
            Response::Error(Error::invalid_parameter("x"))
        );
        match c
            .call(
                "org.varlink.service.GetInterfaceDescription",
                params(r#"{"interface":"io.test.Echo"}"#),
            )
            .unwrap()
        {
            Response::Reply { parameters, .. } => {
                assert_eq!(parameters.get("description").unwrap().as_str(), Some(TEST_IDL))
            }
            other => panic!("{:?}", other),
        }
        assert_eq!(
            c.call(
                "org.varlink.service.GetInterfaceDescription",
                params(r#"{"interface":"io.nope"}"#)
            )
            .unwrap(),
            Response::Error(Error::interface_not_found("io.nope"))
        );
        assert_eq!(
            c.call("org.varlink.service.GetInterfaceDescription", params(r#"{}"#))
                .unwrap(),
            Response::Error(Error::invalid_parameter("interface"))
        );
        drop(c);
        assert_eq!(h.join().unwrap().unwrap(), Disconnect::Closed);
    }

    #[test]
    fn more_and_oneway() {
        let (mut c, h) = pair();
        c.send("io.test.Echo.Count", params(r#"{"upto":2}"#), CallMode::More)
            .unwrap();
        assert_eq!(
            c.receive().unwrap().unwrap(),
            Response::Reply {
                parameters: params(r#"{"n":0}"#),
                continues: true
            }
        );
        assert_eq!(
            c.receive().unwrap().unwrap(),
            Response::Reply {
                parameters: params(r#"{"n":1}"#),
                continues: true
            }
        );
        assert_eq!(
            c.receive().unwrap().unwrap(),
            Response::Reply {
                parameters: params(r#"{"n":2}"#),
                continues: false
            }
        );
        // A oneway call gets no reply, not even for an error; the next
        // call's reply follows directly.
        c.send("io.test.Echo.Echo", params(r#"{"text":"boom"}"#), CallMode::Oneway)
            .unwrap();
        assert_eq!(
            c.call("io.test.Echo.Echo", params(r#"{"text":"x"}"#)).unwrap(),
            Response::Reply {
                parameters: params(r#"{"text":"x"}"#),
                continues: false
            }
        );
        drop(c);
        h.join().unwrap().unwrap();
    }

    #[test]
    fn upgrade_hands_over_the_stream() {
        let (mut c, h) = pair();
        // Pipeline part of the payload right behind the call to make sure
        // the server hands over what it read past the NUL.
        c.send("io.test.Echo.Take", Object::new(), CallMode::Upgrade).unwrap();
        c.connection.stream.as_mut().unwrap().write_all(b"ab").unwrap();
        assert_eq!(
            c.receive().unwrap().unwrap(),
            Response::Reply {
                parameters: params(r#"{"bytes":5}"#),
                continues: false
            }
        );
        let mut up = c.into_upgraded();
        up.stream.write_all(b"cde").unwrap();
        let mut back = [0u8; 5];
        up.stream.read_exact(&mut back).unwrap();
        assert_eq!(&back, b"edcba");
        assert_eq!(h.join().unwrap().unwrap(), Disconnect::Upgraded);
    }

    #[test]
    fn protocol_errors_drop_the_connection() {
        for bad in [
            "{\"method\":\"org.varlink.service.GetInfo\",\"bogus\":1}",
            "not json",
            "[1]",
            "{\"parameters\":{}}",
            "{\"method\":\"a.b.C\",\"more\":true,\"oneway\":true}",
            "{\"method\":\"a.b.C\",\"more\":1}",
            "{\"method\":\"a.b.C\",\"parameters\":[]}",
            "{\"method\":5}",
        ] {
            let (mut a, b) = UnixStream::pair().unwrap();
            let h = std::thread::spawn(move || server().serve(Box::new(b), &Echo));
            a.write_all(bad.as_bytes()).unwrap();
            a.write_all(&[0]).unwrap();
            assert!(
                matches!(h.join().unwrap().unwrap(), Disconnect::Protocol(_)),
                "{:?} accepted",
                bad
            );
            let mut buf = [0u8; 16];
            assert_eq!(a.read(&mut buf).unwrap(), 0, "{:?} got a reply", bad);
        }
        // A vendor extension key is fine.
        let (mut c, h) = pair();
        c.connection
            .stream
            .as_mut()
            .unwrap()
            .write_all(b"{\"method\":\"org.varlink.service.GetInfo\",\"org.example\":{\"x\":1}}\0")
            .unwrap();
        assert!(matches!(c.receive().unwrap().unwrap(), Response::Reply { .. }));
        drop(c);
        h.join().unwrap().unwrap();
        // EOF inside a message is a protocol end too, but a clean EOF is not.
        let (mut a, b) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || server().serve(Box::new(b), &Echo));
        a.write_all(b"{\"method\":").unwrap();
        drop(a);
        assert!(matches!(h.join().unwrap().unwrap(), Disconnect::Protocol(_)));
    }

    #[test]
    fn oversized_messages_are_refused() {
        let (mut a, b) = UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || server().serve(Box::new(b), &Echo));
        let writer = std::thread::spawn(move || {
            let chunk = vec![b' '; 1 << 20];
            for _ in 0..17 {
                if a.write_all(&chunk).is_err() {
                    break;
                }
            }
        });
        assert_eq!(h.join().unwrap().unwrap(), Disconnect::Protocol("message too large"));
        writer.join().unwrap();
    }

    /// A socket path, removed on drop.
    struct SocketPath(std::path::PathBuf);

    impl Drop for SocketPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn listener_serves_concurrently_and_exits_when_idle() {
        let sock = SocketPath(std::env::temp_dir().join(format!("ufat-varlink-{}", std::process::id())));
        let dir = sock.0.clone();
        let _ = std::fs::remove_file(&dir);
        let listener = bind(dir.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o644);
        let path = dir.clone();
        let server_thread = std::thread::spawn(move || server().listen(listener, &Echo));
        let mut first = Client::new(Box::new(UnixStream::connect(&path).unwrap()));
        let mut second = Client::new(Box::new(UnixStream::connect(&path).unwrap()));
        // The second client is served while the first one is still open.
        assert!(matches!(
            second.call("io.test.Echo.Echo", params(r#"{"text":"b"}"#)).unwrap(),
            Response::Reply { .. }
        ));
        assert!(matches!(
            first.call("io.test.Echo.Echo", params(r#"{"text":"a"}"#)).unwrap(),
            Response::Reply { .. }
        ));
        drop(second);
        drop(first);
        server_thread.join().unwrap().unwrap();
        use std::os::unix::fs::PermissionsExt as _;
    }

    /// A stream that answers reads from a script.
    struct Scripted(std::collections::VecDeque<io::Result<Vec<u8>>>);

    impl Stream for Scripted {}

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                Some(Ok(bytes)) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Some(Err(e)) => Err(e),
                None => Ok(0),
            }
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_stalled_message_ends_the_connection_but_an_idle_peer_may_wait() {
        let timeout = || io::Error::from(io::ErrorKind::TimedOut);
        let script = |items: Vec<io::Result<Vec<u8>>>| Box::new(Scripted(items.into_iter().collect()));
        // Nothing of a message yet: not the peer's fault, keep reading.
        let mut c = Connection::new(script(vec![Err(timeout()), Ok(b"{\"method\":\"x\"}\0".to_vec())]));
        assert!(matches!(c.read_message().unwrap(), Message::Data(m) if m == b"{\"method\":\"x\"}"));
        // Half a message and then silence: the connection is dropped.
        let mut c = Connection::new(script(vec![Ok(b"{\"meth".to_vec()), Err(timeout())]));
        assert!(matches!(
            c.read_message().unwrap(),
            Message::End(Disconnect::Protocol(why)) if why.contains("in time")
        ));
    }

    #[test]
    fn connections_beyond_the_limit_wait_for_a_free_slot() {
        let sock = SocketPath(std::env::temp_dir().join(format!("ufat-varlink-cap-{}", std::process::id())));
        let path = sock.0.clone();
        let _ = std::fs::remove_file(&path);
        let listener = bind(path.to_str().unwrap()).unwrap();
        let mut s = server();
        s.set_max_connections(1);
        let server_thread = std::thread::spawn(move || s.listen(listener, &Echo));
        let mut first = Client::new(Box::new(UnixStream::connect(&path).unwrap()));
        assert!(matches!(
            first.call("io.test.Echo.Echo", params(r#"{"text":"a"}"#)).unwrap(),
            Response::Reply { .. }
        ));
        let (tx, rx) = std::sync::mpsc::channel();
        let second_path = path.clone();
        std::thread::spawn(move || {
            let mut second = Client::new(Box::new(UnixStream::connect(&second_path).unwrap()));
            let served = matches!(
                second.call("io.test.Echo.Echo", params(r#"{"text":"b"}"#)).unwrap(),
                Response::Reply { .. }
            );
            tx.send(served).unwrap();
        });
        // The second peer is accepted by the kernel but not served while
        // the first one holds the only slot.
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300)).is_err(),
            "served beyond the limit"
        );
        drop(first);
        assert!(rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap());
        server_thread.join().unwrap().unwrap();
    }

    #[test]
    fn abstract_and_bad_addresses() {
        let name = format!("ufat-varlink-test-{}", std::process::id());
        let listener = bind(&format!("@{}", name)).unwrap();
        drop(listener);
        assert!(bind("relative/path").is_err());
        assert!(bind("tcp:127.0.0.1:1").is_err());
    }

    #[test]
    fn system_error() {
        let e = Error::system(-2);
        assert_eq!(e.name, "io.systemd.System");
        assert_eq!(e.parameters.get("errno").unwrap().as_i64(), Some(2));
        assert_eq!(e.parameters.get("errnoName").unwrap().as_str(), Some("ENOENT"));
        assert_eq!(
            Error::system(libc::EHWPOISON)
                .parameters
                .get("errnoName")
                .unwrap()
                .as_str(),
            Some("EHWPOISON")
        );
        assert_eq!(
            Error::system(libc::EMEDIUMTYPE)
                .parameters
                .get("errnoName")
                .unwrap()
                .as_str(),
            Some("EMEDIUMTYPE")
        );
        assert!(!Error::system(9999).parameters.contains_key("errnoName"));
    }

    /// Every name maps to its number and back, and the aliases have the
    /// name of what they alias, as in systemd.
    #[test]
    fn errno_names() {
        assert_eq!(ERRNO_NAMES.len(), 131);
        for &(name, errno) in ERRNO_NAMES {
            assert_eq!(errno_name(errno), Some(name));
        }
        assert_eq!(errno_name(libc::EWOULDBLOCK), Some("EAGAIN"));
        assert_eq!(errno_name(libc::ENOTSUP), Some("EOPNOTSUPP"));
        if libc::EDEADLOCK != libc::EDEADLK {
            assert_eq!(errno_name(libc::EDEADLOCK), None);
        }
        assert_eq!(errno_name(0), None);
        assert_eq!(errno_name(9999), None);
    }
}
