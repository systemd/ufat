// SPDX-License-Identifier: LGPL-2.1-or-later
//! A client of the org.uapi-group.FileSystem interface for the tests of
//! the services: starting a tool as a service, calling it with
//! descriptors, and holding every reply and error against the interface
//! description.
#![allow(dead_code, unreachable_pub)]

use std::ffi::c_int;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Duration;

use varlink::{Client, Object, Response, Stream, Value};

use crate::common::Temp;

pub const INTERFACE: &str = include_str!("../../docs/org.uapi-group.FileSystem.varlink");
pub const IFACE: &str = "org.uapi-group.FileSystem";
pub const IMG: &str = r#"{"image":{"fileDescriptor":0}}"#;

/// Makes `fd` the child's fd 3, open across exec: dup2 clears FD_CLOEXEC
/// on the new descriptor, but not when `fd` is 3 already, so the flag is
/// cleared explicitly (F_SETFD).
///
/// # Safety
/// Runs in the forked child before exec; dup2 and fcntl are
/// async-signal-safe and take no pointers.
pub unsafe fn install_fd3(fd: c_int) -> std::io::Result<()> {
    if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A child's stdin and stdout as one stream: no socket, so no descriptors.
pub struct ChildStream {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: ChildStdout,
}

impl Read for ChildStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stdout.read(buf)
    }
}

impl Write for ChildStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stdin.as_mut().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdin.as_mut().unwrap().flush()
    }
}

impl Stream for ChildStream {}

impl Drop for ChildStream {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

/// Starts the tool serving stdin/stdout.
pub fn connect_stdio(ufat: &PathBuf) -> Client {
    let mut child = Command::new(ufat)
        .env("SYSTEMD_VARLINK_LISTEN", "-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    Client::new(Box::new(ChildStream {
        child,
        stdin: Some(stdin),
        stdout,
    }))
}

/// A connected socket plus the child serving its other end.
pub struct SocketStream {
    stream: UnixStream,
    child: Child,
}

impl Read for SocketStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for SocketStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

impl Stream for SocketStream {
    fn socket(&self) -> Option<BorrowedFd<'_>> {
        Some(self.stream.as_fd())
    }
}

impl Drop for SocketStream {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        let _ = self.child.wait();
    }
}

/// Starts the tool with a connected socket as fd 3, announced through the
/// LISTEN_FDS protocol like sd_varlink_connect_exec() does.
pub fn connect_fd3(ufat: &PathBuf) -> Client {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let theirs_fd = theirs.into_raw_fd();
    // LISTEN_PID has to be the service's own pid. A shell puts its pid into
    // the environment and execs ufat in place, which keeps the pid; nothing
    // has to allocate or take locks in the forked child.
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("LISTEN_PID=$$ exec \"$0\"")
        .arg(ufat)
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "varlink");
    // SAFETY: dup2 and fcntl are async-signal-safe and the only things the
    // child does before exec.
    unsafe {
        command.pre_exec(move || install_fd3(theirs_fd));
    }
    let child = command.spawn().unwrap();
    // SAFETY: we own theirs_fd and the child has its own copy now.
    drop(unsafe { OwnedFd::from_raw_fd(theirs_fd) });
    Client::new(Box::new(SocketStream { stream: ours, child }))
}

/// Starts the tool listening on a socket of its own and connects to it.
pub fn connect_listening(ufat: &Path) -> (Child, Temp, Client) {
    let sock = Temp::new(".sock");
    let child = Command::new(ufat)
        .env("SYSTEMD_VARLINK_LISTEN", sock.path())
        .spawn()
        .unwrap();
    // The socket appears once the service is up.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let stream = loop {
        match UnixStream::connect(sock.path()) {
            Ok(s) => break s,
            Err(e) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the service did not come up: {}",
                    e
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    (child, sock, Client::new(Box::new(stream)))
}

pub fn params(text: &str) -> Object {
    json::parse(text).unwrap().as_object().unwrap().clone()
}

pub fn reply(r: Response) -> Object {
    match r {
        Response::Reply { parameters, continues } => {
            assert!(!continues);
            parameters
        }
        Response::Error(e) => panic!("unexpected error {} {}", e.name, Value::Object(e.parameters)),
    }
}

pub fn error(r: Response) -> varlink::Error {
    match r {
        Response::Error(e) => e,
        other => panic!("expected an error, got {:?}", other),
    }
}

/// The interface the service serves, parsed once: every reply and every
/// error is held to what it declares.
pub fn interface() -> &'static varlink::idl::Interface {
    static INTERFACE_PARSED: std::sync::OnceLock<varlink::idl::Interface> = std::sync::OnceLock::new();
    INTERFACE_PARSED.get_or_init(|| varlink::idl::parse(INTERFACE).unwrap())
}

/// A reply, intermediate or final, or an error of `method` has the fields
/// the description lists, of the types it gives, and no others: in
/// particular no text, since the words are the client's to choose.
pub fn conforms(method: &str, r: &Response) {
    let iface = interface();
    match r {
        Response::Reply { parameters, .. } => {
            let m = iface
                .methods
                .get(method)
                .unwrap_or_else(|| panic!("undeclared method {}", method));
            assert_eq!(
                iface.validate(&m.output, parameters),
                Ok(()),
                "{} replied {}",
                method,
                Value::Object(parameters.clone())
            );
        }
        Response::Error(e) => {
            if let Some(name) = e.name.strip_prefix(&format!("{}.", IFACE)) {
                let fields = iface
                    .errors
                    .get(name)
                    .unwrap_or_else(|| panic!("undeclared error {}", e.name));
                assert_eq!(
                    iface.validate(fields, &e.parameters),
                    Ok(()),
                    "{} {}",
                    e.name,
                    Value::Object(e.parameters.clone())
                );
            }
            assert!(
                e.parameters.get("message").is_none(),
                "{} carries text: {}",
                e.name,
                Value::Object(e.parameters.clone())
            );
        }
    }
}

pub fn method(name: &str) -> String {
    format!("{}.{}", IFACE, name)
}

/// Calls `method` with the descriptors passed along, index i naming fds[i],
/// and expects one reply.
pub fn call(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> Response {
    let r = if fds.is_empty() {
        c.call(&method(name), params(p)).unwrap()
    } else {
        c.call_with_fds(&method(name), params(p), fds).unwrap()
    };
    conforms(name, &r);
    r
}

pub fn error_of(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> varlink::Error {
    error(call(c, name, p, fds))
}

/// Calls `method` with the more flag and returns every reply in order,
/// the final one last.
pub fn call_more(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> Vec<Object> {
    c.send_more_with_fds(&method(name), params(p), fds).unwrap();
    let mut replies = Vec::new();
    loop {
        let r = c.receive().unwrap().expect("the connection closed without a reply");
        conforms(name, &r);
        match r {
            Response::Reply { parameters, continues } => {
                replies.push(parameters);
                if !continues {
                    return replies;
                }
            }
            Response::Error(e) => panic!("unexpected error {} {}", e.name, Value::Object(e.parameters)),
        }
    }
}

/// The phases the intermediate replies of a streamed call announced.
pub fn phases(replies: &[Object]) -> Vec<&str> {
    replies
        .iter()
        .filter_map(|r| r.get("phase").and_then(Value::as_str))
        .collect()
}

pub fn u64_of(o: &Object, key: &str) -> u64 {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_u64()
        .unwrap()
}

pub fn str_of<'a>(o: &'a Object, key: &str) -> &'a str {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_str()
        .unwrap()
}

pub fn bool_of(o: &Object, key: &str) -> bool {
    o.get(key).unwrap().as_bool().unwrap()
}

pub fn object_of<'a>(o: &'a Object, key: &str) -> &'a Object {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_object()
        .unwrap()
}

pub fn strings_of<'a>(o: &'a Object, key: &str) -> Vec<&'a str> {
    o.get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

/// The image open read-write, as a client that wants it written passes it.
pub fn rw(path: &Path) -> File {
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}

/// Open read-only: how a source, a manifest or an image to look at is passed.
pub fn ro(path: &Path) -> File {
    File::open(path).unwrap()
}

/// A fresh, empty image file open read-write: an Assemble with content grows
/// it to the fit.
pub fn fresh_image() -> (Temp, File) {
    let t = Temp::new(".img");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(t.path())
        .unwrap();
    (t, f)
}

/// A file to receive a manifest, open for writing as a sink is passed.
pub fn sink(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap()
}

/// Writes `data` to a fresh file and returns it open read-only.
pub fn file_with(dir: &Path, name: &str, data: &[u8]) -> File {
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    ro(&path)
}

/// Names the entries a listing with the more flag returned, one per reply.
pub fn names(replies: &[Object]) -> Vec<&str> {
    replies.iter().map(|r| str_of(object_of(r, "entry"), "name")).collect()
}
