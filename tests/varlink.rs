// SPDX-License-Identifier: LGPL-2.1-or-later
//! Drives the ufat binary over Varlink the way systemd and varlinkctl do:
//! through a socket passed as fd 3, through stdin/stdout and through a
//! listening socket, with every file the service touches passed as a
//! descriptor along with the call. Every reply and every error is held to
//! the org.uapi-group.FileSystem interface description the binary serves.

mod common;

use std::ffi::c_int;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, UNIX_EPOCH};

use common::{build_tree, find_program, first_difference, ufat, Temp};
use ufat::device::{Access, Device};
use ufat::volume::Volume;
use varlink::{Client, Object, Response, Stream, Value};

const INTERFACE: &str = include_str!("../docs/org.uapi-group.FileSystem.varlink");
const IFACE: &str = "org.uapi-group.FileSystem";
const IMG: &str = r#"{"image":{"fileDescriptor":0}}"#;
/// A FAT time with a day: 2023-11-14 22:13:20 UTC.
const T0: u64 = 1_700_000_000_000_000;

/// Makes `fd` the child's fd 3, open across exec: dup2 clears FD_CLOEXEC
/// on the new descriptor, but not when `fd` is 3 already, so the flag is
/// cleared explicitly (F_SETFD).
///
/// # Safety
/// Runs in the forked child before exec; dup2 and fcntl are
/// async-signal-safe and take no pointers.
unsafe fn install_fd3(fd: c_int) -> std::io::Result<()> {
    if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// A child's stdin and stdout as one stream: no socket, so no descriptors.
struct ChildStream {
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

/// Starts ufat serving stdin/stdout.
fn connect_stdio(ufat: &PathBuf) -> Client {
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
struct SocketStream {
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

/// Starts ufat with a connected socket as fd 3, announced through the
/// LISTEN_FDS protocol like sd_varlink_connect_exec() does.
fn connect_fd3(ufat: &PathBuf) -> Client {
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

/// Starts ufat listening on a socket of its own and connects to it.
fn connect_listening(ufat: &Path) -> (Child, Temp, Client) {
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

fn params(text: &str) -> Object {
    json::parse(text).unwrap().as_object().unwrap().clone()
}

fn reply(r: Response) -> Object {
    match r {
        Response::Reply { parameters, continues } => {
            assert!(!continues);
            parameters
        }
        Response::Error(e) => panic!("unexpected error {} {}", e.name, Value::Object(e.parameters)),
    }
}

fn error(r: Response) -> varlink::Error {
    match r {
        Response::Error(e) => e,
        other => panic!("expected an error, got {:?}", other),
    }
}

/// The interface the service serves, parsed once: every reply and every
/// error is held to what it declares.
fn interface() -> &'static varlink::idl::Interface {
    static INTERFACE_PARSED: std::sync::OnceLock<varlink::idl::Interface> = std::sync::OnceLock::new();
    INTERFACE_PARSED.get_or_init(|| varlink::idl::parse(INTERFACE).unwrap())
}

/// A reply, intermediate or final, or an error of `method` has the fields
/// the description lists, of the types it gives, and no others: in
/// particular no text, since the words are the client's to choose.
fn conforms(method: &str, r: &Response) {
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

fn method(name: &str) -> String {
    format!("{}.{}", IFACE, name)
}

/// Calls `method` with the descriptors passed along, index i naming fds[i],
/// and expects one reply.
fn call(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> Response {
    let r = if fds.is_empty() {
        c.call(&method(name), params(p)).unwrap()
    } else {
        c.call_with_fds(&method(name), params(p), fds).unwrap()
    };
    conforms(name, &r);
    r
}

fn error_of(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> varlink::Error {
    error(call(c, name, p, fds))
}

/// Calls `method` with the more flag and returns every reply in order,
/// the final one last.
fn call_more(c: &mut Client, name: &str, p: &str, fds: &[BorrowedFd<'_>]) -> Vec<Object> {
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
fn phases(replies: &[Object]) -> Vec<&str> {
    replies
        .iter()
        .filter_map(|r| r.get("phase").and_then(Value::as_str))
        .collect()
}

fn u64_of(o: &Object, key: &str) -> u64 {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_u64()
        .unwrap()
}

fn str_of<'a>(o: &'a Object, key: &str) -> &'a str {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_str()
        .unwrap()
}

fn bool_of(o: &Object, key: &str) -> bool {
    o.get(key).unwrap().as_bool().unwrap()
}

fn object_of<'a>(o: &'a Object, key: &str) -> &'a Object {
    o.get(key)
        .unwrap_or_else(|| panic!("no {} in {}", key, Value::Object(o.clone())))
        .as_object()
        .unwrap()
}

fn strings_of<'a>(o: &'a Object, key: &str) -> Vec<&'a str> {
    o.get(key)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

/// The image open read-write, as a client that wants it written passes it.
fn rw(path: &Path) -> File {
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}

/// Open read-only: how a source, a manifest or an image to look at is passed.
fn ro(path: &Path) -> File {
    File::open(path).unwrap()
}

/// A fresh, empty image file open read-write: an Assemble with content grows
/// it to the fit.
fn fresh_image() -> (Temp, File) {
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
fn sink(path: &Path) -> File {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .unwrap()
}

/// A small tree as an ESP has it: two files in three directories.
fn esp_tree() -> Temp {
    let tree = Temp::dir();
    build_tree(
        tree.path(),
        &[
            ("EFI/BOOT/BOOTX64.EFI", &[1u8; 5000]),
            ("loader/loader.conf", b"timeout 5\n"),
        ],
    );
    tree
}

/// A manifest of the tree and the contents of its streamed files in
/// manifest order.
fn manifest_and_blob(tree: &Path) -> (Vec<u8>, Vec<u8>) {
    let bytes = ufat::manifest::generate(ufat::host::open_dir(tree).unwrap().as_fd()).unwrap();
    let m = ufat::manifest::parse(&bytes).unwrap();
    let mut blob = Vec::new();
    for e in &m.entries {
        if e.is_streamed() {
            blob.extend(std::fs::read(tree.join(e.name.as_ref().unwrap())).unwrap());
        }
    }
    (bytes, blob)
}

/// Writes `data` to a fresh file and returns it open read-only.
fn file_with(dir: &Path, name: &str, data: &[u8]) -> File {
    let path = dir.join(name);
    std::fs::write(&path, data).unwrap();
    ro(&path)
}

fn sha256_hex(data: &[u8]) -> String {
    ufat::sha256::to_hex(&ufat::sha256::digest(data))
}

fn sha512_hex(data: &[u8]) -> String {
    ufat::sha512::to_hex(&ufat::sha512::digest(data))
}

/// Names the entries a listing with the more flag returned, one per reply.
fn names(replies: &[Object]) -> Vec<&str> {
    replies.iter().map(|r| str_of(object_of(r, "entry"), "name")).collect()
}

/// Opens the volume in `image` through the library, to look at what the
/// service did.
fn volume(image: &Path, access: Access) -> Volume {
    Volume::open(Device::open(image, access).unwrap()).unwrap()
}

/// Damages the FAT32 volume in `image`: every file entry of the root
/// directory gets a modification time with hour 31 and a date with month
/// 0, two findings each for a check. Returns how many entries were hit.
fn damage_root_entries(image: &Path) -> usize {
    let f = rw(image);
    let mut sector = [0u8; 512];
    f.read_exact_at(&mut sector, 0).unwrap();
    let boot = ufat::boot::BootSector::parse(&sector).unwrap();
    let layout = boot.layout().unwrap();
    let mut cluster = boot.root_cluster;
    let mut buf = vec![0u8; layout.cluster_size() as usize];
    let mut damaged = 0;
    loop {
        let offset = layout.cluster_offset(cluster).unwrap();
        f.read_exact_at(&mut buf, offset).unwrap();
        for slot in buf.chunks_mut(32) {
            // An entry in use with the plain file attribute, no long name
            // part, no label, no directory.
            if slot[0] != 0xE5 && slot[0] != 0x00 && slot[11] == 0x20 {
                slot[22..24].copy_from_slice(&0xFFFFu16.to_le_bytes());
                slot[24..26].copy_from_slice(&0u16.to_le_bytes());
                damaged += 1;
            }
        }
        f.write_all_at(&buf, offset).unwrap();
        let mut entry = [0u8; 4];
        f.read_exact_at(&mut entry, layout.fat_offset(0) + u64::from(cluster) * 4)
            .unwrap();
        let next = u32::from_le_bytes(entry) & 0x0FFF_FFFF;
        if next >= 0x0FFF_FFF8 || !layout.valid_cluster(next) {
            break;
        }
        cluster = next;
    }
    damaged
}

#[test]
fn info_and_description_over_fd3() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let mut c = connect_fd3(&ufat);
    let info = reply(c.call("org.varlink.service.GetInfo", Object::new()).unwrap());
    assert_eq!(
        strings_of(&info, "interfaces"),
        vec!["io.systemd", IFACE, "org.varlink.service"]
    );
    assert_eq!(info.get("product").unwrap().as_str(), Some("ufat"));
    let d = reply(
        c.call(
            "org.varlink.service.GetInterfaceDescription",
            params(&format!(r#"{{"interface":"{}"}}"#, IFACE)),
        )
        .unwrap(),
    );
    assert_eq!(d.get("description").unwrap().as_str(), Some(INTERFACE));
    let e = error(c.call(&method("Nope"), Object::new()).unwrap());
    assert_eq!(e.name, "org.varlink.service.MethodNotFound");
    let e = error(c.call(&method("Describe"), params(r#"{"image":5}"#)).unwrap());
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(e.parameters.get("parameter").unwrap().as_str(), Some("image"));
    // An index that names no descriptor is as wrong as a missing one.
    let e = error(c.call(&method("Describe"), params(IMG)).unwrap());
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(e.parameters.get("parameter").unwrap().as_str(), Some("image"));
    let e = error(c.call(&method("Assemble"), params(r#"{"mode":"assemble"}"#)).unwrap());
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(e.parameters.get("parameter").unwrap().as_str(), Some("image"));
}

/// stdin and stdout carry no descriptors, so every method that takes an
/// image is out of reach there; the introspection and the capabilities
/// still work.
#[test]
fn stdio_carries_no_descriptors() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let mut c = connect_stdio(&ufat);
    reply(c.call("org.varlink.service.GetInfo", Object::new()).unwrap());
    let caps = reply(call(&mut c, "GetCapabilities", "{}", &[]));
    assert_eq!(str_of(object_of(&caps, "capabilities"), "fileSystemType"), "vfat");
    let e = error_of(&mut c, "Describe", IMG, &[]);
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(e.parameters.get("parameter").unwrap().as_str(), Some("image"));
}

/// What the service says it can do, and that it serves vfat alone.
#[test]
fn capabilities_describe_vfat() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let mut c = connect_fd3(&ufat);
    let r = reply(call(&mut c, "GetCapabilities", r#"{"fileSystemType":"vfat"}"#, &[]));
    let caps = object_of(&r, "capabilities");
    assert_eq!(str_of(caps, "fileSystemType"), "vfat");
    assert_eq!(str_of(caps, "implementation"), "ufat");
    assert!(!str_of(caps, "version").is_empty());
    assert!(!bool_of(caps, "readOnly"));
    assert_eq!(
        strings_of(caps, "operations"),
        vec![
            "plan",
            "assembleWithContent",
            "populate",
            "remove",
            "list",
            "check",
            "label",
            "identifier",
            "reproducible",
            "manifest",
            "writeManifest"
        ]
    );
    assert_eq!(str_of(caps, "sizeToFit"), "exact");
    // The smallest volume: 65525 clusters of one 512 byte sector, two
    // FATs of 512 sectors and 32 reserved sectors.
    let mut params = ufat::layout::LayoutParams::new(512);
    params.sectors_per_cluster = Some(1);
    let minimal = ufat::layout::minimal(&params, ufat::layout::MIN_CLUSTERS)
        .unwrap()
        .size();
    assert_eq!(u64_of(caps, "minimalSizeBytes"), minimal);
    assert_eq!(u64_of(caps, "minimalSizeBytes"), (32 + 2 * 512 + 65525) * 512);
    assert_eq!(u64_of(caps, "maximalSizeBytes"), 0xFFFF_FFFF * 512);
    assert_eq!(u64_of(caps, "sizeGranularityBytes"), 512);
    let ints = |key: &str| -> Vec<u64> {
        caps.get(key)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect()
    };
    assert_eq!(ints("sectorSizes"), vec![512, 1024, 2048, 4096]);
    assert_eq!(ints("blockSizes"), vec![512, 1024, 2048, 4096, 8192, 16384, 32768]);
    let label = object_of(caps, "label");
    assert_eq!(u64_of(label, "lengthMax"), 11);
    assert_eq!(str_of(label, "unit"), "bytes");
    assert_eq!(str_of(label, "charset"), "fat");
    assert_eq!(str_of(caps, "identifier"), "serial");
    assert_eq!(strings_of(caps, "preserves"), vec!["dosAttributes"]);
    assert!(caps.get("inodeFlags").is_none());
    let times = object_of(caps, "times");
    assert_eq!(u64_of(times, "resolutionNSec"), 2_000_000_000);
    assert_eq!(u64_of(times, "minUSec"), 315_532_800_000_000);
    assert_eq!(u64_of(times, "maxUSec"), 4_354_819_199_000_000);
    assert!(bool_of(times, "created"));
    assert!(bool_of(times, "accessed"));
    assert!(!bool_of(times, "changed"));
    assert!(bool_of(times, "utc"));
    assert!(!bool_of(caps, "caseSensitive"));
    assert_eq!(u64_of(caps, "nameLengthMax"), 255);
    assert_eq!(str_of(caps, "nameUnit"), "utf16Units");
    assert_eq!(u64_of(caps, "fileSizeMaxBytes"), 4_294_967_295);
    assert!(caps.get("features").is_none());
    // Any other type is not served, by any method.
    let e = error_of(&mut c, "GetCapabilities", r#"{"fileSystemType":"ext4"}"#, &[]);
    assert_eq!(e.name, format!("{}.FileSystemTypeNotSupported", IFACE));
    assert_eq!(str_of(&e.parameters, "fileSystemType"), "ext4");
    let e = error_of(&mut c, "Assemble", r#"{"fileSystemType":"xfs","mode":"plan"}"#, &[]);
    assert_eq!(e.name, format!("{}.FileSystemTypeNotSupported", IFACE));
}

/// Assemble with mode plan: the size the content needs, from a tree or from
/// its manifest alike, and what Assemble then makes.
#[test]
fn assemble_plans_from_a_tree_and_a_manifest() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let (manifest, _) = manifest_and_blob(tree.path());
    let scratch = Temp::dir();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let a = reply(call(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","options":{"label":"esp","identifier":"1234-abcd"},"content":{"sourceFileDescriptor":0}}"#,
        &[source.as_fd()],
    ));
    assert!(bool_of(&a, "exact"));
    assert_eq!(u64_of(&a, "files"), 2);
    assert_eq!(u64_of(&a, "directories"), 3);
    assert_eq!(u64_of(&a, "bytes"), 5010);
    let d = object_of(&a, "description");
    assert_eq!(str_of(d, "fileSystemType"), "vfat");
    // The label and identifier as they would be stored.
    assert_eq!(str_of(d, "label"), "esp");
    assert_eq!(str_of(d, "identifier"), "1234-ABCD");
    assert_eq!(u64_of(d, "sectorSize"), 512);
    assert_eq!(u64_of(d, "sizeBytes"), u64_of(d, "minimalSizeBytes"));
    assert!(u64_of(d, "sizeBytes") >= 65525 * 512);
    assert!(u64_of(d, "blockSize") >= 512);
    assert!(d.get("freeBytes").is_none());
    // The manifest describes the same tree, so it plans the same size.
    let manifest_file = file_with(scratch.path(), "manifest", &manifest);
    let b = reply(call(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","options":{"label":"esp"},"content":{"manifest":{"fileDescriptor":0}}}"#,
        &[manifest_file.as_fd()],
    ));
    let bd = object_of(&b, "description");
    assert_eq!(u64_of(bd, "sizeBytes"), u64_of(d, "sizeBytes"));
    assert_eq!(u64_of(&b, "files"), 2);
    assert_eq!(u64_of(&b, "directories"), 3);
    assert_eq!(u64_of(&b, "bytes"), 5010);
    // With the directory beside the manifest the source is verified first.
    let manifest_file = ro(&scratch.path().join("manifest"));
    let empty = Temp::dir();
    let empty_dir = ro(empty.path());
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","content":{"manifest":{"fileDescriptor":0},"sourceFileDescriptor":1}}"#,
        &[manifest_file.as_fd(), empty_dir.as_fd()],
    );
    assert_eq!(e.name, format!("{}.SourceMismatch", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "missing");
    // No content: the smallest volume there is, with 4 KiB sectors too.
    let m = reply(call(&mut c, "Assemble", r#"{"mode":"plan"}"#, &[]));
    let md = object_of(&m, "description");
    assert_eq!(u64_of(md, "sizeBytes"), (32 + 2 * 512 + 65525) * 512);
    assert_eq!(u64_of(&m, "files"), 0);
    let m = reply(call(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","options":{"sectorSize":4096}}"#,
        &[],
    ));
    assert_eq!(u64_of(object_of(&m, "description"), "sectorSize"), 4096);
    // The format makes exactly what the plan said.
    let (image, img) = fresh_image();
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"label":"esp","identifier":"1234-abcd"},"content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    let rd = object_of(&r, "description");
    assert_eq!(u64_of(rd, "sizeBytes"), u64_of(d, "sizeBytes"));
    assert_eq!(u64_of(rd, "blockSize"), u64_of(d, "blockSize"));
    assert_eq!(std::fs::metadata(image.path()).unwrap().len(), u64_of(d, "sizeBytes"));
    // With more, the plan announces itself.
    let replies = call_more(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","content":{"sourceFileDescriptor":0}}"#,
        &[source.as_fd()],
    );
    assert_eq!(phases(&replies), vec!["planning"]);
    assert!(bool_of(replies.last().unwrap(), "exact"));
}

/// Assemble with a tree: the image sized to fit, the root stamped with the
/// time given, the description as stored, and Describe, List and Check
/// agreeing with it.
#[test]
fn assemble_with_a_tree() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let (image, img) = fresh_image();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let r = reply(call(
        &mut c,
        "Assemble",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"options":{{"label":"ESP","identifier":"1234-ABCD","timestampUSec":{}}},"content":{{"sourceFileDescriptor":1,"times":"clamp"}}}}"#,
            T0
        ),
        &[img.as_fd(), source.as_fd()],
    ));
    assert!(bool_of(&r, "exact"));
    assert_eq!(u64_of(&r, "files"), 2);
    assert_eq!(u64_of(&r, "directories"), 3);
    assert_eq!(u64_of(&r, "bytes"), 5010);
    assert_eq!(u64_of(&r, "skipped"), 0);
    assert!(r.get("omitted").is_none());
    assert!(r.get("imageHash").is_none());
    let d = object_of(&r, "description");
    assert_eq!(str_of(d, "fileSystemType"), "vfat");
    assert_eq!(str_of(d, "label"), "ESP");
    assert_eq!(str_of(d, "identifier"), "1234-ABCD");
    assert_eq!(u64_of(d, "sectorSize"), 512);
    assert_eq!(u64_of(d, "sizeBytes"), std::fs::metadata(image.path()).unwrap().len());
    assert!(u64_of(d, "freeBytes") < u64_of(d, "sizeBytes"));
    assert!(d.get("minimalSizeBytes").is_none());
    // Looking only needs a read-only descriptor, and sees the same.
    let img_ro = ro(image.path());
    let described = reply(call(&mut c, "Describe", IMG, &[img_ro.as_fd()]));
    assert_eq!(object_of(&described, "description"), d);
    assert!(described.get("files").is_none());
    let listed = call_more(&mut c, "List", IMG, &[img_ro.as_fd()]);
    assert_eq!(names(&listed), vec!["EFI", "loader"]);
    let ck = reply(call(&mut c, "Check", IMG, &[img_ro.as_fd()]));
    assert_eq!(u64_of(&ck, "errors"), 0, "{}", Value::Object(ck.clone()));
    assert!(bool_of(&ck, "clean"));
    assert_eq!(u64_of(&ck, "repaired"), 0);
    assert_eq!(u64_of(&ck, "dropped"), 0);
    // What is in it, and the root's time.
    let v = volume(image.path(), Access::ReadOnly);
    let mut data = Vec::new();
    v.open_file("/EFI/BOOT/BOOTX64.EFI")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, vec![1u8; 5000]);
    assert_eq!(v.root_time().unwrap(), Some(UNIX_EPOCH + Duration::from_micros(T0)));
    drop(v);
    // Without a timestamp the root takes the source directory's time,
    // which build_tree fixed.
    let (image2, img2) = fresh_image();
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[img2.as_fd(), source.as_fd()],
    ));
    let v = volume(image2.path(), Access::ReadOnly);
    assert_eq!(
        v.root_time().unwrap(),
        Some(UNIX_EPOCH + Duration::from_secs(1_699_999_000))
    );
    assert_eq!(v.label().unwrap(), None);
}

/// Assemble without content: the window as given, grown for a size on a
/// regular file, and nothing to go on for an empty one.
#[test]
fn assemble_without_content() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let mut c = connect_fd3(&ufat);
    // 4 KiB clusters need a volume of 65525 of them; 40 MiB would not do.
    let small = Temp::image(40 << 20);
    let small_img = rw(small.path());
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"blockSize":4096}}"#,
        &[small_img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSpaceLeft", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "volume");
    let image = Temp::image(320 << 20);
    let img = rw(image.path());
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"label":"ESP","blockSize":4096,"vfat":{"oemName":"ufat","fats":1}}}"#,
        &[img.as_fd()],
    ));
    assert!(!bool_of(&r, "exact"));
    assert!(r.get("files").is_none());
    let d = object_of(&r, "description");
    assert_eq!(u64_of(d, "sizeBytes"), 320 << 20);
    assert_eq!(u64_of(d, "blockSize"), 4096);
    assert_eq!(str_of(d, "label"), "ESP");
    let v = volume(image.path(), Access::ReadOnly);
    assert_eq!(v.layout().fats, 1);
    assert_eq!(&v.boot_sector().oem_name, b"ufat    ");
    drop(v);
    // A window inside the image, sized; the rest of the file is left alone.
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0,"offset":1048576,"size":35651584}}"#,
        &[img.as_fd()],
    ));
    assert_eq!(u64_of(object_of(&r, "description"), "sizeBytes"), 34 << 20);
    assert_eq!(std::fs::metadata(image.path()).unwrap().len(), 320 << 20);
    let img_ro = ro(image.path());
    let r = reply(call(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0,"offset":1048576}}"#,
        &[img_ro.as_fd()],
    ));
    assert_eq!(u64_of(object_of(&r, "description"), "sizeBytes"), 34 << 20);
    // An empty file with a size is grown to it.
    let (fresh, fresh_img) = fresh_image();
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0,"size":41943040}}"#,
        &[fresh_img.as_fd()],
    ));
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 40 << 20);
    // An empty file without a size and without content has no size to take.
    let (_fresh2, fresh_img2) = fresh_image();
    let e = error_of(&mut c, "Assemble", IMG, &[fresh_img2.as_fd()]);
    assert_eq!(e.name, format!("{}.SizeRequired", IFACE));
    // Options the library refuses are named as the interface spells them.
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"blockSize":3000}}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "blockSize");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"sectorSize":256}}"#,
        &[img.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "sectorSize");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"vfat":{"fats":9}}}"#,
        &[img.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "fats");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"vfat":{"oemName":"nine chars"}}}"#,
        &[img.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "oemName");
}

/// Assemble with a manifest beside the directory it describes: links are
/// followed inside the source and the directory is verified before the
/// image is touched.
#[test]
fn assemble_with_a_manifest_and_a_directory() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let base = Temp::dir();
    let tree = base.path().join("tree");
    build_tree(
        &tree,
        &[
            ("EFI/BOOT/BOOTX64.EFI", &[1u8; 5000]),
            ("loader/loader.conf", b"timeout 5\n"),
        ],
    );
    std::os::unix::fs::symlink("loader/loader.conf", tree.join("conf.lnk")).unwrap();
    std::os::unix::fs::symlink("tree", base.path().join("via-link")).unwrap();
    let (manifest, _) = manifest_and_blob(&tree);
    let manifest_file = file_with(base.path(), "manifest", &manifest);
    let mut c = connect_fd3(&ufat);
    // Through a symbolic link to the directory, which the client's open
    // resolved. The manifest is what decides what goes in: the link inside
    // the tree is not in it, so it is not copied.
    let source = ro(&base.path().join("via-link"));
    let (image, img) = fresh_image();
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"label":"ESP"},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    ));
    assert_eq!(u64_of(&r, "files"), 2);
    assert_eq!(u64_of(&r, "directories"), 3);
    assert_eq!(u64_of(&r, "skipped"), 0);
    let v = volume(image.path(), Access::ReadOnly);
    assert_eq!(v.metadata("/loader/loader.conf").unwrap().size, 10);
    assert!(v.metadata("/conf.lnk").is_err());
    drop(v);
    // The tree itself, copied, has the link's target as one more file.
    let (image2, img2) = fresh_image();
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[img2.as_fd(), source.as_fd()],
    ));
    assert_eq!(u64_of(&r, "files"), 3);
    assert_eq!(
        volume(image2.path(), Access::ReadOnly)
            .metadata("/conf.lnk")
            .unwrap()
            .size,
        10
    );
    // A directory that does not hold what the manifest names fails before
    // the image is touched: the file the client created stays empty.
    let manifest_file = ro(&base.path().join("manifest"));
    let empty = Temp::dir();
    let empty_dir = ro(empty.path());
    let (fresh, fresh_img) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[fresh_img.as_fd(), manifest_file.as_fd(), empty_dir.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.SourceMismatch", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "missing");
    // The file as the manifest names it, not as a path in the volume.
    assert_eq!(str_of(&e.parameters, "name"), "EFI/BOOT/BOOTX64.EFI");
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    // So does a file that grew since the manifest was written. The manifest
    // takes it whole, so it has to have the manifest's size.
    std::fs::write(tree.join("loader/loader.conf"), b"timeout 5\nconsole-mode max\n").unwrap();
    let manifest_file = ro(&base.path().join("manifest"));
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[fresh_img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.SourceMismatch", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "size");
    assert_eq!(str_of(&e.parameters, "name"), "loader/loader.conf");
    assert_eq!(u64_of(&e.parameters, "sizeBytes"), 27);
    assert_eq!(u64_of(&e.parameters, "expectedSizeBytes"), 10);
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    std::fs::write(tree.join("loader/loader.conf"), b"timeout 5\n").unwrap();
    // A broken manifest is InvalidManifest, with nothing written either.
    let garbage = file_with(base.path(), "garbage", b"garbage");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[fresh_img.as_fd(), garbage.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.InvalidManifest", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "recordSeparator");
    let bad = file_with(base.path(), "bad",
        b"\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n\x1e{\"name\":\"x\"}\n\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
    );
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","content":{"manifest":{"fileDescriptor":0}}}"#,
        &[bad.as_fd()],
    );
    assert_eq!(e.name, format!("{}.InvalidManifest", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "noSize");
    assert_eq!(str_of(&e.parameters, "name"), "/x");
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    // A manifest needs a source, a stream needs a manifest, a file is no
    // content for Assemble.
    let manifest_file = ro(&base.path().join("manifest"));
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1}}}"#,
        &[fresh_img.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "content");
    let conf = ro(&tree.join("loader/loader.conf"));
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[fresh_img.as_fd(), conf.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "content");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{}}"#,
        &[fresh_img.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "content");
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
}

/// Assemble with a manifest and the contents of its files in a stream.
#[test]
fn assemble_with_a_manifest_and_a_stream() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let Some(mkfifo) = find_program("mkfifo") else {
        return eprintln!("skipping: mkfifo not found");
    };
    let tree = Temp::dir();
    build_tree(
        tree.path(),
        &[
            ("EFI/BOOT/BOOTX64.EFI", &[0xAAu8; 70_000]),
            ("EFI/Linux/linux-6.12.efi", &[0x55u8; 123_456]),
            ("loader/entries/linux.conf", b"title Linux\n"),
            ("empty", b""),
        ],
    );
    let (manifest, blob) = manifest_and_blob(tree.path());
    let scratch = Temp::dir();
    let manifest_file = file_with(scratch.path(), "manifest", &manifest);
    let mut c = connect_fd3(&ufat);
    // The contents come through a pipe, in manifest order.
    let (image, img) = fresh_image();
    let fifo = scratch.path().join("fifo");
    assert!(Command::new(&mkfifo).arg(&fifo).status().unwrap().success());
    let writer = {
        let fifo = fifo.clone();
        let blob = blob.clone();
        std::thread::spawn(move || {
            let mut w = OpenOptions::new().write(true).open(fifo).unwrap();
            w.write_all(&blob).unwrap();
        })
    };
    let reader = ro(&fifo);
    let r = reply(call(
        &mut c,
        "Assemble",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"options":{{"label":"ESP","identifier":"00000001","timestampUSec":{}}},"content":{{"manifest":{{"fileDescriptor":1}},"sourceFileDescriptor":2}}}}"#,
            T0
        ),
        &[img.as_fd(), manifest_file.as_fd(), reader.as_fd()],
    ));
    writer.join().unwrap();
    assert_eq!(u64_of(&r, "files"), 4);
    assert_eq!(u64_of(&r, "bytes"), blob.len() as u64);
    assert_eq!(str_of(object_of(&r, "description"), "identifier"), "0000-0001");
    drop(reader);
    // The content is small, so the image got the FAT32 minimum of 65525
    // clusters, which EDK2 boots from: it is clean and holds the data.
    let report = ufat::fsck::check(&Device::open(image.path(), Access::ReadOnly).unwrap()).unwrap();
    assert_eq!(report.errors(), 0, "{:?}", report.problems);
    assert!(
        !report
            .problems
            .iter()
            .any(|p| p.kind == ufat::fsck::ProblemKind::BelowMinimumClusters),
        "{:?}",
        report.problems
    );
    let v = volume(image.path(), Access::ReadOnly);
    assert!(v.layout().clusters >= ufat::layout::MIN_CLUSTERS);
    let mut data = Vec::new();
    v.open_file("/EFI/Linux/linux-6.12.efi")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, vec![0x55u8; 123_456]);
    assert_eq!(v.metadata("/empty").unwrap().size, 0);
    drop(v);
    // A short stream, from a file this time, is a ContentMismatch.
    let (_image2, img2) = fresh_image();
    let short = file_with(scratch.path(), "short", &blob[..1000]);
    let manifest_file = ro(&scratch.path().join("manifest"));
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[img2.as_fd(), manifest_file.as_fd(), short.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.ContentMismatch", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "streamEnded");
    assert_eq!(str_of(&e.parameters, "name"), "EFI/BOOT/BOOTX64.EFI");
    // So is a stream that goes on after the last file: that file got more
    // than the manifest says, by how much is not known.
    let last = ufat::manifest::parse(&manifest)
        .unwrap()
        .entries
        .into_iter()
        .rfind(|e| e.is_streamed())
        .unwrap();
    let (_image3, img3) = fresh_image();
    let long = file_with(scratch.path(), "long", &[&blob[..], b"more"].concat());
    let manifest_file = ro(&scratch.path().join("manifest"));
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[img3.as_fd(), manifest_file.as_fd(), long.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.ContentMismatch", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "size");
    assert_eq!(Some(str_of(&e.parameters, "name")), last.name.as_deref());
    assert_eq!(u64_of(&e.parameters, "expectedSizeBytes"), last.size.unwrap());
    assert!(e.parameters.get("sizeBytes").is_none());
}

/// The kinds of the problems Check finds in `image`, which has no errors.
fn warnings(c: &mut Client, image: &Path) -> Vec<String> {
    let img = ro(image);
    let ck = reply(call(c, "Check", IMG, &[img.as_fd()]));
    assert_eq!(u64_of(&ck, "errors"), 0, "{}", Value::Object(ck.clone()));
    let mut kinds: Vec<String> = ck
        .get("problems")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|p| str_of(p.as_object().unwrap(), "kind").to_string())
        .collect();
    kinds.sort();
    kinds
}

/// An Assemble that fails after the format leaves the file system as after
/// a crash: with the files that were complete, and marked as not cleanly
/// unmounted, which Check reports. It is marked when it fails before the
/// first file as well. Assembling again makes a clean file system.
#[test]
fn a_failed_assemble_leaves_the_file_system_unfinished() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let base = Temp::dir();
    let tree = base.path().join("tree");
    build_tree(
        &tree,
        &[
            ("EFI/BOOT/BOOTX64.EFI", &[1u8; 5000]),
            ("loader/loader.conf", b"timeout 5\n"),
        ],
    );
    let (manifest, _) = manifest_and_blob(&tree);
    let manifest_file = file_with(base.path(), "manifest", &manifest);
    // loader.conf keeps its size and changes its contents after the
    // manifest was written: it passes the check of the source before the
    // format and fails while it is copied, after BOOTX64.EFI.
    std::fs::write(tree.join("loader/loader.conf"), b"timeout 9\n").unwrap();
    let mut c = connect_fd3(&ufat);
    let source = ro(&tree);
    let (image, img) = fresh_image();
    let assemble =
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#;
    let e = error_of(
        &mut c,
        "Assemble",
        assemble,
        &[img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.ContentMismatch", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "hash");
    assert_eq!(warnings(&mut c, image.path()), ["dirtyFlag", "fatDirtyFlag"]);
    let v = volume(image.path(), Access::ReadOnly);
    assert_eq!(v.metadata("/EFI/BOOT/BOOTX64.EFI").unwrap().size, 5000);
    assert!(v.metadata("/loader/loader.conf").is_err());
    drop(v);
    // A manifest that expired fails before anything is copied.
    let (expired, expired_img) = fresh_image();
    let old = file_with(
        base.path(),
        "expired",
        b"\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"validUntilUSec\":1}\n\x1e{\"name\":\"x\",\"size\":0}\n\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
    );
    let empty = file_with(base.path(), "empty", b"");
    let e = error_of(
        &mut c,
        "Assemble",
        assemble,
        &[expired_img.as_fd(), old.as_fd(), empty.as_fd()],
    );
    assert_eq!(e.name, format!("{}.EntryNotValid", IFACE));
    assert_eq!(warnings(&mut c, expired.path()), ["dirtyFlag", "fatDirtyFlag"]);
    // Assembling again starts over with a clean file system.
    std::fs::write(tree.join("loader/loader.conf"), b"timeout 5\n").unwrap();
    let manifest_file = ro(&base.path().join("manifest"));
    reply(call(
        &mut c,
        "Assemble",
        assemble,
        &[img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    ));
    assert!(warnings(&mut c, image.path()).is_empty());
}

/// imageHash: the hash of the whole image window as the call leaves it,
/// which for a fresh file sized to fit is the hash of the file.
#[test]
fn assemble_hashes_the_image() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    for (algorithm, hex) in [
        ("sha256", sha256_hex as fn(&[u8]) -> String),
        ("sha512", sha512_hex as fn(&[u8]) -> String),
    ] {
        let (image, img) = fresh_image();
        let r = reply(call(
            &mut c,
            "Assemble",
            &format!(
                r#"{{"image":{{"fileDescriptor":0}},"content":{{"sourceFileDescriptor":1}},"imageHash":"{}"}}"#,
                algorithm
            ),
            &[img.as_fd(), source.as_fd()],
        ));
        let data = std::fs::read(image.path()).unwrap();
        assert_eq!(data.len() as u64, u64_of(object_of(&r, "description"), "sizeBytes"));
        assert_eq!(str_of(&r, "imageHash"), hex(&data), "{}", algorithm);
    }
    // Without content the window is the whole 40 MiB file.
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"imageHash":"sha256"}"#,
        &[img.as_fd()],
    ));
    assert_eq!(
        str_of(&r, "imageHash"),
        sha256_hex(&std::fs::read(image.path()).unwrap())
    );
}

/// A manifest of what was written, through manifestSink: the names, the
/// sizes and the hashes of the tree, and the root's time.
#[test]
fn assemble_writes_a_manifest() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let scratch = Temp::dir();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let (_image, img) = fresh_image();
    let out = scratch.path().join("out.manifest");
    let out_file = sink(&out);
    let r = reply(call(
        &mut c,
        "Assemble",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"options":{{"timestampUSec":{}}},"content":{{"sourceFileDescriptor":1,"manifestSink":{{"fileDescriptor":2,"fields":["size","hash","mtime"]}}}}}}"#,
            T0
        ),
        &[img.as_fd(), source.as_fd(), out_file.as_fd()],
    ));
    assert_eq!(u64_of(&r, "files"), 2);
    assert_eq!(u64_of(&r, "omitted"), 0);
    drop(out_file);
    let m = ufat::manifest::parse(&std::fs::read(&out).unwrap()).unwrap();
    let mut listed: Vec<&str> = m.entries.iter().map(|e| e.name.as_deref().unwrap()).collect();
    listed.sort_unstable();
    assert_eq!(
        listed,
        vec![
            "EFI",
            "EFI/BOOT",
            "EFI/BOOT/BOOTX64.EFI",
            "loader",
            "loader/loader.conf"
        ]
    );
    assert_eq!(m.root.mtime_nsec, Some(T0 * 1000));
    for e in &m.entries {
        if e.inode_type == ufat::manifest::InodeType::Regular {
            let data = std::fs::read(tree.path().join(e.name.as_deref().unwrap())).unwrap();
            assert_eq!(e.size, Some(data.len() as u64));
            assert_eq!(e.sha256, Some(ufat::sha256::digest(&data)), "{:?}", e.name);
            assert!(e.mtime_nsec.is_some());
        }
    }
    // A sink that cannot be written to is refused before anything happens.
    let (fresh, fresh_img) = fresh_image();
    let readable = ro(&out);
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1,"manifestSink":{"fileDescriptor":2}}}"#,
        &[fresh_img.as_fd(), source.as_fd(), readable.as_fd()],
    );
    assert_eq!(e.name, format!("{}.BadFileDescriptor", IFACE));
    assert_eq!(str_of(&e.parameters, "parameter"), "manifestSink");
    assert_eq!(str_of(&e.parameters, "reason"), "notWritable");
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
}

/// With the more flag Assemble tells which step it is in, in order.
#[test]
fn assemble_reports_its_phases() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let scratch = Temp::dir();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let (_image, img) = fresh_image();
    let out_file = sink(&scratch.path().join("out.manifest"));
    let replies = call_more(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1,"manifestSink":{"fileDescriptor":2}},"imageHash":"sha256"}"#,
        &[img.as_fd(), source.as_fd(), out_file.as_fd()],
    );
    // A phase that lasts repeats itself; the order is what counts, and the
    // manifest and the hash announce their reading each.
    let mut seen = phases(&replies);
    let readings = seen.iter().filter(|&&p| p == "reading").count();
    seen.dedup();
    assert_eq!(seen, vec!["planning", "formatting", "populating", "reading"]);
    assert!(readings >= 2, "{:?}", replies);
    let last = replies.last().unwrap();
    assert!(last.get("phase").is_none());
    assert!(last.get("imageHash").is_some());
    assert_eq!(u64_of(last, "files"), 2);
    // Without content there is nothing to plan or populate.
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    let replies = call_more(&mut c, "Assemble", IMG, &[img.as_fd()]);
    assert_eq!(phases(&replies), vec!["formatting"]);
}

/// A phase that lasts repeats itself about once a second with the counts
/// so far. The contents of the second file arrive after a pause longer
/// than that, so the caller hears how far the copy got before the call
/// ends.
#[test]
fn long_phases_report_progress() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let Some(mkfifo) = find_program("mkfifo") else {
        return eprintln!("skipping: mkfifo not found");
    };
    let tree = Temp::dir();
    build_tree(
        tree.path(),
        &[("a.bin", &[0x11u8; 100_000]), ("b.bin", &[0x22u8; 100_000])],
    );
    let (manifest, blob) = manifest_and_blob(tree.path());
    let scratch = Temp::dir();
    let manifest_file = file_with(scratch.path(), "manifest", &manifest);
    let mut c = connect_fd3(&ufat);
    let (_image, img) = fresh_image();
    let fifo = scratch.path().join("fifo");
    assert!(Command::new(&mkfifo).arg(&fifo).status().unwrap().success());
    let writer = {
        let fifo = fifo.clone();
        let blob = blob.clone();
        std::thread::spawn(move || {
            let mut w = OpenOptions::new().write(true).open(fifo).unwrap();
            w.write_all(&blob[..100_000]).unwrap();
            std::thread::sleep(Duration::from_millis(1500));
            w.write_all(&blob[100_000..]).unwrap();
        })
    };
    let reader = ro(&fifo);
    let replies = call_more(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[img.as_fd(), manifest_file.as_fd(), reader.as_fd()],
    );
    writer.join().unwrap();
    let progress: Vec<&Object> = replies
        .iter()
        .filter(|r| r.get("phase").and_then(Value::as_str) == Some("populating") && r.get("bytes").is_some())
        .collect();
    assert!(!progress.is_empty(), "{:?}", replies);
    assert_eq!(u64_of(progress[0], "files"), 1);
    assert!(u64_of(progress[0], "bytes") > 100_000);
    let last = replies.last().unwrap();
    assert_eq!((u64_of(last, "files"), u64_of(last, "bytes")), (2, 200_000));
}

/// reproducible: refused without the identifier and timestamp it needs,
/// and with them two formats of the same tree give the same bytes.
#[test]
fn reproducible_images_are_identical() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let (_image, img) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"options":{{"reproducible":true,"timestampUSec":{}}},"content":{{"sourceFileDescriptor":1}}}}"#,
            T0
        ),
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NotReproducible", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "identifierRequired");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"reproducible":true,"identifier":"1234-ABCD"},"content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NotReproducible", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "timestampRequired");
    let options = format!(
        r#"{{"image":{{"fileDescriptor":0}},"options":{{"reproducible":true,"identifier":"1234-ABCD","timestampUSec":{},"label":"ESP"}},"content":{{"sourceFileDescriptor":1,"times":"clamp"}}}}"#,
        T0
    );
    let (a, a_img) = fresh_image();
    let (b, b_img) = fresh_image();
    reply(call(&mut c, "Assemble", &options, &[a_img.as_fd(), source.as_fd()]));
    reply(call(&mut c, "Assemble", &options, &[b_img.as_fd(), source.as_fd()]));
    assert!(std::fs::metadata(a.path()).unwrap().len() > 0);
    assert_eq!(first_difference(a.path(), b.path()).unwrap(), None);
}

/// Describe: what is there, and the manifest of it when asked for.
#[test]
fn describe_with_and_without_a_manifest() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let scratch = Temp::dir();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    let (image, img) = fresh_image();
    reply(call(
        &mut c,
        "Assemble",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"options":{{"label":"ESP","identifier":"1234-ABCD","timestampUSec":{}}},"content":{{"sourceFileDescriptor":1}}}}"#,
            T0
        ),
        &[img.as_fd(), source.as_fd()],
    ));
    let img_ro = ro(image.path());
    let r = reply(call(&mut c, "Describe", IMG, &[img_ro.as_fd()]));
    let d = object_of(&r, "description");
    assert_eq!(str_of(d, "label"), "ESP");
    assert_eq!(str_of(d, "identifier"), "1234-ABCD");
    assert_eq!(u64_of(d, "sizeBytes"), std::fs::metadata(image.path()).unwrap().len());
    assert!(u64_of(d, "freeBytes") > 0);
    assert!(r.get("files").is_none());
    // With a sink: the default field set, which has no mtime, and the
    // phase announced when asked.
    let out = scratch.path().join("described.manifest");
    let out_file = sink(&out);
    let replies = call_more(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0},"manifestSink":{"fileDescriptor":1}}"#,
        &[img_ro.as_fd(), out_file.as_fd()],
    );
    assert_eq!(phases(&replies), vec!["reading"]);
    let last = replies.last().unwrap();
    assert_eq!(u64_of(last, "files"), 2);
    assert_eq!(u64_of(last, "directories"), 3);
    assert_eq!(u64_of(last, "bytes"), 5010);
    assert_eq!(u64_of(last, "omitted"), 0);
    drop(out_file);
    let m = ufat::manifest::parse(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(m.entries.len(), 5);
    assert!(m.root.mtime_nsec.is_none());
    assert!(m.entries.iter().all(|e| e.mtime_nsec.is_none()));
    let conf = m
        .entries
        .iter()
        .find(|e| e.name.as_deref() == Some("loader/loader.conf"))
        .unwrap();
    assert_eq!(conf.sha256, Some(ufat::sha256::digest(b"timeout 5\n")));
    // Images that hold no FAT32 volume say why.
    let blank = Temp::image(40 << 20);
    let blank_ro = ro(blank.path());
    let e = error_of(&mut c, "Describe", IMG, &[blank_ro.as_fd()]);
    assert_eq!(e.name, format!("{}.NotFileSystem", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "blank");
    let mut bytes = vec![0x55u8; 1 << 20];
    let garbage = file_with(scratch.path(), "garbage", &bytes);
    let e = error_of(&mut c, "Describe", IMG, &[garbage.as_fd()]);
    assert_eq!(e.name, format!("{}.NotFileSystem", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "sectorSize");
    assert_eq!(u64_of(&e.parameters, "sectorSize"), 0x5555);
    // A plausible sector size and a FAT16 style FAT size: something else.
    bytes[11..13].copy_from_slice(&512u16.to_le_bytes());
    let other = file_with(scratch.path(), "other", &bytes);
    let e = error_of(&mut c, "Describe", IMG, &[other.as_fd()]);
    assert_eq!(e.name, format!("{}.NotFileSystem", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "otherFileSystem");
    let tiny = file_with(scratch.path(), "tiny", b"tiny");
    let e = error_of(&mut c, "Describe", IMG, &[tiny.as_fd()]);
    assert_eq!(str_of(&e.parameters, "reason"), "tooSmall");
    let e = error_of(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0,"offset":512}}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NotFileSystem", IFACE));
    let e = error_of(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0,"offset":-1}}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "image");
}

/// Populate: a tree, one file, a manifest's tree, and a directory alone;
/// the source's type decides.
#[test]
fn populate_puts_content_into_a_volume() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let (manifest, _) = manifest_and_blob(tree.path());
    let scratch = Temp::dir();
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    let mut c = connect_fd3(&ufat);
    reply(call(&mut c, "Assemble", IMG, &[img.as_fd()]));
    // A tree below a directory that is made for it.
    let source = ro(tree.path());
    let replies = call_more(
        &mut c,
        "Populate",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"path":"/sub","content":{{"sourceFileDescriptor":1,"times":"clamp"}},"timestampUSec":{}}}"#,
            T0
        ),
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(phases(&replies), vec!["populating"]);
    let r = replies.last().unwrap();
    assert_eq!(u64_of(r, "files"), 2);
    assert_eq!(u64_of(r, "directories"), 3);
    assert_eq!(u64_of(r, "bytes"), 5010);
    assert_eq!(u64_of(r, "skipped"), 0);
    assert!(r.get("omitted").is_none());
    let img_ro = ro(image.path());
    assert_eq!(
        names(&call_more(
            &mut c,
            "List",
            r#"{"image":{"fileDescriptor":0},"path":"/sub"}"#,
            &[img_ro.as_fd()]
        )),
        vec!["EFI", "loader"]
    );
    // One file, with its parents made.
    let conf = ro(&tree.path().join("loader/loader.conf"));
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/a/b/c.conf","content":{"sourceFileDescriptor":1},"parents":true}"#,
        &[img.as_fd(), conf.as_fd()],
    ));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "bytes")), (1, 10));
    let listed = reply(call(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/a/b/c.conf"}"#,
        &[img_ro.as_fd()],
    ));
    assert_eq!(str_of(object_of(&listed, "entry"), "type"), "reg");
    // Without parents the parent has to be there.
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/nowhere/c.conf","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), conf.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    // An existing file is replaced unless replace says otherwise.
    reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/a/b/c.conf","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), conf.as_fd()],
    ));
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/a/b/c.conf","content":{"sourceFileDescriptor":1,"replace":false}}"#,
        &[img.as_fd(), conf.as_fd()],
    );
    assert_eq!(e.name, format!("{}.FileExists", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/a/b/c.conf");
    // A manifest names its paths from the root and goes nowhere else.
    let manifest_file = file_with(scratch.path(), "manifest", &manifest);
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/m","content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "path");
    let e = error_of(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/m"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    // A manifest's tree, with the manifest of the whole volume written
    // afterwards.
    let manifest_file = ro(&scratch.path().join("manifest"));
    let out = scratch.path().join("out.manifest");
    let out_file = sink(&out);
    let replies = call_more(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2,"manifestSink":{"fileDescriptor":3}}}"#,
        &[img.as_fd(), manifest_file.as_fd(), source.as_fd(), out_file.as_fd()],
    );
    assert_eq!(phases(&replies), vec!["populating", "reading"]);
    let r = replies.last().unwrap();
    assert_eq!(u64_of(r, "files"), 2);
    assert_eq!(u64_of(r, "omitted"), 0);
    drop(out_file);
    let m = ufat::manifest::parse(&std::fs::read(&out).unwrap()).unwrap();
    assert!(m
        .entries
        .iter()
        .any(|e| e.name.as_deref() == Some("EFI/BOOT/BOOTX64.EFI")));
    assert!(m.entries.iter().any(|e| e.name.as_deref() == Some("a/b/c.conf")));
    assert_eq!(
        names(&call_more(
            &mut c,
            "List",
            r#"{"image":{"fileDescriptor":0},"path":"/EFI/BOOT"}"#,
            &[img_ro.as_fd()]
        )),
        vec!["BOOTX64.EFI"]
    );
    // No content: a directory, once.
    let r = reply(call(
        &mut c,
        "Populate",
        &format!(
            r#"{{"image":{{"fileDescriptor":0}},"path":"/d","timestampUSec":{}}}"#,
            T0
        ),
        &[img.as_fd()],
    ));
    assert_eq!(u64_of(&r, "directories"), 1);
    assert_eq!(u64_of(&r, "files"), 0);
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/d"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.FileExists", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/d");
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/d","parents":true}"#,
        &[img.as_fd()],
    ));
    assert_eq!(u64_of(&r, "directories"), 0);
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/x/y/z","parents":true,"content":{}}"#,
        &[img.as_fd()],
    ));
    assert_eq!(u64_of(&r, "directories"), 1);
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/p/q"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    let v = volume(image.path(), Access::ReadOnly);
    assert_eq!(
        v.metadata("/d").unwrap().modified,
        UNIX_EPOCH + Duration::from_micros(T0)
    );
    assert!(v.metadata("/x/y/z").unwrap().is_dir);
    drop(v);
    // A manifest without a source is no content.
    let manifest_file = ro(&scratch.path().join("manifest"));
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"manifest":{"fileDescriptor":1}}}"#,
        &[img.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "content");
    // A tree into the root of a volume that has things already.
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    assert_eq!(u64_of(&r, "files"), 2);
}

/// Remove: a file, an empty directory, a directory with everything below
/// it, and never the root.
#[test]
fn remove_files_and_directories() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let (image, img) = fresh_image();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/empty"}"#,
        &[img.as_fd()],
    ));
    let r = reply(call(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/loader/loader.conf"}"#,
        &[img.as_fd()],
    ));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "directories")), (1, 0));
    let r = reply(call(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/empty"}"#,
        &[img.as_fd()],
    ));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "directories")), (0, 1));
    let e = error_of(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/EFI"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.DirectoryNotEmpty", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/EFI");
    let replies = call_more(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/EFI","recursive":true}"#,
        &[img.as_fd()],
    );
    assert_eq!(phases(&replies), vec!["removing"]);
    let r = replies.last().unwrap();
    assert_eq!((u64_of(r, "files"), u64_of(r, "directories")), (1, 2));
    let e = error_of(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/EFI"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/EFI");
    for p in [
        r#"{"image":{"fileDescriptor":0},"path":"/"}"#,
        r#"{"image":{"fileDescriptor":0},"path":"/","recursive":true}"#,
    ] {
        let e = error_of(&mut c, "Remove", p, &[img.as_fd()]);
        assert_eq!(e.name, "org.varlink.service.InvalidParameter");
        assert_eq!(str_of(&e.parameters, "parameter"), "path");
    }
    let img_ro = ro(image.path());
    assert_eq!(
        names(&call_more(&mut c, "List", IMG, &[img_ro.as_fd()])),
        vec!["loader"]
    );
    let ck = reply(call(&mut c, "Check", IMG, &[img_ro.as_fd()]));
    assert_eq!(u64_of(&ck, "errors"), 0, "{}", Value::Object(ck.clone()));
}

/// List: one entry per reply with the more flag, a single reply for a
/// file, and ExpectedMore for a directory without it.
#[test]
fn list_streams_entries() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let tree = esp_tree();
    let (image, img) = fresh_image();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/empty"}"#,
        &[img.as_fd()],
    ));
    {
        let mut v = volume(image.path(), Access::ReadWrite);
        v.set_attributes("/loader/loader.conf", ufat::dirent::ATTR_READ_ONLY)
            .unwrap();
        v.close().unwrap();
    }
    let img_ro = ro(image.path());
    let replies = call_more(&mut c, "List", IMG, &[img_ro.as_fd()]);
    assert_eq!(replies.len(), 3);
    assert_eq!(names(&replies), vec!["EFI", "loader", "empty"]);
    let efi = object_of(&replies[0], "entry");
    assert_eq!(str_of(efi, "type"), "dir");
    assert_eq!(u64_of(efi, "sizeBytes"), 0);
    assert_eq!(str_of(efi, "alternateName"), "EFI");
    assert!(efi.get("modifiedUSec").is_some() && efi.get("createdUSec").is_some());
    assert!(efi.get("mode").is_none() && efi.get("uid").is_none() && efi.get("target").is_none());
    let replies = call_more(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/loader"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(replies.len(), 1);
    let conf = object_of(&replies[0], "entry");
    assert_eq!(str_of(conf, "name"), "loader.conf");
    assert_eq!(str_of(conf, "type"), "reg");
    assert_eq!(u64_of(conf, "sizeBytes"), 10);
    assert_eq!(strings_of(conf, "dosAttributes"), vec!["readOnly"]);
    assert_eq!(u64_of(conf, "modifiedUSec"), 1_700_000_002_000_000);
    // A new file carries the archive attribute, as DOS sets it.
    let boot = call_more(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/EFI/BOOT"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(
        strings_of(object_of(&boot[0], "entry"), "dosAttributes"),
        vec!["archive"]
    );
    assert_eq!(str_of(object_of(&boot[0], "entry"), "alternateName"), "BOOTX64.EFI");
    // An empty directory: one reply, no entry.
    let replies = call_more(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/empty"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(replies.len(), 1);
    assert!(replies[0].get("entry").is_none());
    // A file: its entry, in one reply, more or not.
    let r = reply(call(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/loader/loader.conf"}"#,
        &[img_ro.as_fd()],
    ));
    assert_eq!(str_of(object_of(&r, "entry"), "name"), "loader.conf");
    let replies = call_more(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/loader/loader.conf"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(replies.len(), 1);
    // A directory needs the more flag.
    let e = error_of(&mut c, "List", IMG, &[img_ro.as_fd()]);
    assert_eq!(e.name, "org.varlink.service.ExpectedMore");
    let e = error_of(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/missing"}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/missing");
}

/// Check: clean on a fresh volume; findings with class, kind and facts on
/// a damaged one, streamed in batches with the more flag.
#[test]
fn check_finds_damage() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    // Enough files in the root for more findings than one batch holds.
    let tree = Temp::dir();
    let names_: Vec<String> = (0..120).map(|i| format!("f{:03}.txt", i)).collect();
    let files: Vec<(&str, &[u8])> = names_.iter().map(|n| (n.as_str(), b"x" as &[u8])).collect();
    build_tree(tree.path(), &files);
    let (image, img) = fresh_image();
    let mut c = connect_fd3(&ufat);
    let source = ro(tree.path());
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    let img_ro = ro(image.path());
    let ck = reply(call(&mut c, "Check", IMG, &[img_ro.as_fd()]));
    assert_eq!(u64_of(&ck, "errors"), 0, "{}", Value::Object(ck.clone()));
    assert!(bool_of(&ck, "clean"));
    assert!(ck.get("problems").unwrap().as_array().unwrap().is_empty());
    let replies = call_more(&mut c, "Check", IMG, &[img_ro.as_fd()]);
    assert_eq!(phases(&replies), vec!["checking"]);
    assert_eq!(replies.len(), 2);
    assert!(bool_of(&replies[1], "clean"));
    // Repair is not on offer.
    let e = error_of(
        &mut c,
        "Check",
        r#"{"image":{"fileDescriptor":0},"repair":"preen"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.OperationNotSupported", IFACE));
    assert_eq!(str_of(&e.parameters, "operation"), "repair");
    let damaged = damage_root_entries(image.path());
    assert_eq!(damaged, 120);
    let ck = reply(call(&mut c, "Check", IMG, &[img_ro.as_fd()]));
    let total = u64_of(&ck, "errors") + u64_of(&ck, "warnings");
    assert!(total >= 2 * damaged as u64, "{}", Value::Object(ck.clone()));
    assert_eq!(bool_of(&ck, "clean"), u64_of(&ck, "errors") == 0);
    assert_eq!(u64_of(&ck, "dropped"), 0);
    let problems = ck.get("problems").unwrap().as_array().unwrap();
    assert_eq!(problems.len() as u64, total);
    for p in problems {
        let p = p.as_object().unwrap();
        assert_eq!(str_of(p, "class"), "timestamp", "{}", Value::Object(p.clone()));
        assert!(matches!(str_of(p, "kind"), "dateInvalid" | "timeInvalid"));
        assert!(str_of(p, "path").starts_with("/f"));
        assert!(matches!(str_of(p, "severity"), "error" | "warning"));
        assert!(p.get("value").is_some() && p.get("field").is_some());
        assert!(p.get("repaired").is_none());
    }
    // Streamed: the phase, then batches of at most 100, then the counts
    // without the list.
    let replies = call_more(&mut c, "Check", IMG, &[img_ro.as_fd()]);
    assert_eq!(phases(&replies), vec!["checking"]);
    let batches: Vec<usize> = replies
        .iter()
        .filter_map(|r| r.get("problems").and_then(Value::as_array))
        .map(<[Value]>::len)
        .collect();
    assert!(batches.len() >= 2, "{} batches", batches.len());
    assert!(batches.iter().all(|&b| b <= 100));
    assert_eq!(batches.iter().map(|&b| b as u64).sum::<u64>(), total);
    let last = replies.last().unwrap();
    assert!(last.get("problems").is_none());
    assert_eq!(u64_of(last, "errors") + u64_of(last, "warnings"), total);
}

/// Every descriptor is vetted before it is used: not O_PATH, nothing beyond
/// the access mode, read-only where the service reads, read-write without
/// O_APPEND where it writes, open for writing for a sink, and of the type
/// the parameter names.
#[test]
fn passed_descriptors_are_vetted() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let image = Temp::image(40 << 20);
    let tree = Temp::dir();
    build_tree(tree.path(), &[("hello.txt", b"hello\n")]);
    let mut c = connect_fd3(&ufat);
    let bad_fd = |c: &mut Client, method: &str, p: &str, fds: &[BorrowedFd<'_>], parameter: &str| {
        let e = error_of(c, method, p, fds);
        assert_eq!(
            e.name,
            format!("{}.BadFileDescriptor", IFACE),
            "{}",
            Value::Object(e.parameters.clone())
        );
        assert_eq!(str_of(&e.parameters, "parameter"), parameter);
        str_of(&e.parameters, "reason").to_string()
    };
    let img_ro = ro(image.path());
    let img = rw(image.path());
    // Writing needs a read-write image; O_APPEND would make every write
    // land at the end.
    let m = bad_fd(&mut c, "Assemble", IMG, &[img_ro.as_fd()], "image");
    assert_eq!(m, "notReadWrite");
    let append = OpenOptions::new().read(true).append(true).open(image.path()).unwrap();
    let m = bad_fd(&mut c, "Assemble", IMG, &[append.as_fd()], "image");
    assert_eq!(m, "flags");
    let wronly = OpenOptions::new().write(true).open(image.path()).unwrap();
    let m = bad_fd(&mut c, "Assemble", IMG, &[wronly.as_fd()], "image");
    assert_eq!(m, "writeOnly");
    // O_PATH cannot be read or written and is refused everywhere.
    let pinned = ufat::host::open_dir(tree.path()).unwrap();
    let m = bad_fd(&mut c, "Describe", IMG, &[pinned.as_fd()], "image");
    assert_eq!(m, "oPath");
    reply(call(&mut c, "Assemble", IMG, &[img.as_fd()]));
    bad_fd(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), pinned.as_fd()],
        "sourceFileDescriptor",
    );
    // Sources have to be read-only.
    let hello_rw = rw(&tree.path().join("hello.txt"));
    let m = bad_fd(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/h","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), hello_rw.as_fd()],
        "sourceFileDescriptor",
    );
    assert_eq!(m, "notReadOnly");
    let dir = ro(tree.path());
    let hello = ro(&tree.path().join("hello.txt"));
    // A manifest is a stream: not a directory, not a pipe that would not
    // wait.
    let m = bad_fd(
        &mut c,
        "Assemble",
        r#"{"mode":"plan","content":{"manifest":{"fileDescriptor":0}}}"#,
        &[dir.as_fd()],
        "manifest",
    );
    assert_eq!(m, "wrongType");
    let nonblock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(tree.path().join("hello.txt"))
        .unwrap();
    let m = bad_fd(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/h","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), nonblock.as_fd()],
        "sourceFileDescriptor",
    );
    assert_eq!(m, "flags");
    // A directory as the image.
    let m = bad_fd(&mut c, "Describe", IMG, &[dir.as_fd()], "image");
    assert_eq!(m, "wrongType");
    // A sink has to be writable and a file or pipe.
    let m = bad_fd(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0},"manifestSink":{"fileDescriptor":1}}"#,
        &[img_ro.as_fd(), hello.as_fd()],
        "manifestSink",
    );
    assert_eq!(m, "notWritable");
    let m = bad_fd(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0},"manifestSink":{"fileDescriptor":1}}"#,
        &[img_ro.as_fd(), dir.as_fd()],
        "manifestSink",
    );
    assert_eq!(m, "notWritable");
    // Right the way round, the same descriptors work.
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/h","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), hello.as_fd()],
    ));
    assert_eq!(u64_of(&r, "bytes"), 6);
    // Indexes that name nothing, or the same descriptor twice.
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":5}}"#,
        &[img.as_fd(), dir.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "sourceFileDescriptor");
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":0}}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    let e = error_of(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0},"manifestSink":{"fileDescriptor":3}}"#,
        &[img_ro.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "parameter"), "manifestSink");
}

/// The errors the options and the paths can provoke, each the typed one
/// the interface declares.
#[test]
fn errors_are_typed() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    let mut c = connect_fd3(&ufat);
    let format_error = |c: &mut Client, options: &str| {
        error_of(
            c,
            "Assemble",
            &format!(r#"{{"image":{{"fileDescriptor":0}},"options":{}}}"#, options),
            &[img.as_fd()],
        )
    };
    let e = format_error(&mut c, r#"{"label":"A.B"}"#);
    assert_eq!(e.name, format!("{}.InvalidLabel", IFACE));
    assert_eq!(str_of(&e.parameters, "label"), "A.B");
    assert_eq!(str_of(&e.parameters, "reason"), "invalidCharacter");
    let e = format_error(&mut c, r#"{"label":"TWELVE CHARS"}"#);
    assert_eq!(e.name, format!("{}.InvalidLabel", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "tooLong");
    let e = format_error(&mut c, r#"{"identifier":"xyz"}"#);
    assert_eq!(e.name, format!("{}.InvalidIdentifier", IFACE));
    assert_eq!(str_of(&e.parameters, "identifier"), "xyz");
    assert_eq!(str_of(&e.parameters, "reason"), "malformed");
    let e = format_error(&mut c, r#"{"identifier":"8e3f0b2a-1b1c-4c2d-9e0f-123456789abc"}"#);
    assert_eq!(e.name, format!("{}.InvalidIdentifier", IFACE));
    // Options of other file systems are not part of the interface.
    let e = format_error(&mut c, r#"{"ext4":{"inodeSize":256}}"#);
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "options");
    // What FAT has no notion of.
    for (options, operation) in [
        (r#"{"discard":true}"#, "discard"),
        (r#"{"enableFeatures":["casefold"]}"#, "features"),
        (r#"{"disableFeatures":["x"]}"#, "features"),
    ] {
        let e = format_error(&mut c, options);
        assert_eq!(e.name, format!("{}.OperationNotSupported", IFACE), "{}", options);
        assert_eq!(str_of(&e.parameters, "operation"), operation);
    }
    // discard off is fine; so are the ownership switches FAT ignores.
    reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"discard":false,"zero":false,"enableFeatures":[]}}"#,
        &[img.as_fd()],
    ));
    let tree = Temp::dir();
    build_tree(tree.path(), &[("hello.txt", b"hello\n")]);
    let source = ro(tree.path());
    reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1,"extendedAttributes":true,"uid":0,"gid":0,"unsupported":"fail"}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    // Paths.
    let e = error_of(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/missing"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NoSuchFile", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/missing");
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/hello.txt/below","parents":true}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NotADirectory", IFACE));
    assert_eq!(str_of(&e.parameters, "path"), "/hello.txt");
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/hello.txt","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.NotADirectory", IFACE));
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/bad:name"}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, format!("{}.InvalidName", IFACE));
    assert_eq!(str_of(&e.parameters, "reason"), "invalidCharacter");
    // A socket in a tree is nothing FAT can hold: skipped and counted, or
    // refused when the caller wants to know.
    let _socket = std::os::unix::net::UnixListener::bind(tree.path().join("sock")).unwrap();
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    ));
    assert_eq!(u64_of(&r, "skipped"), 1);
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1,"unsupported":"fail"}}"#,
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.ContentNotSupported", IFACE));
    assert_eq!(str_of(&e.parameters, "what"), "inodeType");
    assert_eq!(str_of(&e.parameters, "name"), "sock");
    let (fresh, fresh_img) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1,"unsupported":"fail"}}"#,
        &[fresh_img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.ContentNotSupported", IFACE));
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    // There is no switch for following links, and no unknown parameter.
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1,"followSymlinks":true}}"#,
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "content");
    let e = error_of(
        &mut c,
        "Check",
        r#"{"image":{"fileDescriptor":0},"fix":true}"#,
        &[img.as_fd()],
    );
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "fix");
}

#[test]
fn varlinkctl_can_drive_us() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let Some(varlinkctl) = find_program("varlinkctl") else {
        return eprintln!("skipping: varlinkctl not found");
    };
    let image = Temp::image(40 << 20);
    // varlinkctl opens a --push-fd=PATH read-only; a writable image goes in
    // as a descriptor the shell opened, here fd 3.
    let img = rw(image.path());
    let img_fd = img.into_raw_fd();
    let mut command = Command::new(&varlinkctl);
    command.args([
        "call",
        "--push-fd=3",
        ufat.to_str().unwrap(),
        &method("Assemble"),
        r#"{"image":{"fileDescriptor":0},"options":{"label":"CTL"}}"#,
    ]);
    // SAFETY: dup2 and fcntl are async-signal-safe and the only things the
    // child does before exec.
    unsafe {
        command.pre_exec(move || install_fd3(img_fd));
    }
    let out = command.output().unwrap();
    // SAFETY: img_fd is ours to close; the child had its own copy.
    drop(unsafe { OwnedFd::from_raw_fd(img_fd) });
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = Command::new(&varlinkctl)
        .args([
            "call",
            &format!("--push-fd={}", image.path().display()),
            ufat.to_str().unwrap(),
            &method("Describe"),
            IMG,
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v = json::parse(String::from_utf8_lossy(&out.stdout).trim()).unwrap();
    assert_eq!(
        v.get("description").unwrap().get("label").unwrap().as_str(),
        Some("CTL")
    );
    let out = Command::new(&varlinkctl)
        .args(["introspect", ufat.to_str().unwrap(), IFACE])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("method Assemble(")
            && text.contains("method GetCapabilities(")
            && !text.contains("method Format("),
        "{}",
        text
    );
}

#[test]
fn a_listening_service_finishes_its_connections_after_sigterm() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let (mut child, sock, mut client) = connect_listening(&ufat);
    reply(client.call("org.varlink.service.GetInfo", Object::new()).unwrap());
    let kill = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(kill.success());
    // Had the service not blocked SIGTERM, the signal would have killed it
    // as it was sent. Instead, the open connection is still served, and
    // descriptors pass over it as over any socket.
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    reply(call(&mut client, "Assemble", IMG, &[img.as_fd()]));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the service died while a connection was open"
    );
    // A new connection is never accepted. The service is gone soon after
    // the last connection it serves, with a clean exit, although this one
    // still waits.
    let _late = UnixStream::connect(sock.path()).unwrap();
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the service did not exit after SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{:?}", status);
}

/// A volume too small for what goes into it: a copy that runs out of
/// clusters says which file did not fit and leaves the earlier files in a
/// consistent file system, and an image window too small for the content
/// is refused before anything is written.
#[test]
fn too_small_images_are_reported() {
    let _serial = common::serial();
    let Some(ufat) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let base = Temp::dir();
    let tree = base.path().join("tree");
    // The smallest volume the service makes has 65525 clusters, 32 MiB of
    // data with 512 byte clusters; a 40 MiB image holds that, and the file
    // that does not fit is larger still.
    let big = vec![0x5au8; 48 << 20];
    build_tree(
        &tree,
        &[
            ("a.txt", b"first\n"),
            ("big.bin", big.as_slice()),
            ("sub/c.txt", b"last\n"),
        ],
    );
    let image = Temp::image(40 << 20);
    let img = rw(image.path());
    let mut c = connect_fd3(&ufat);
    reply(call(&mut c, "Assemble", IMG, &[img.as_fd()]));
    let source = ro(&tree);
    let e = error_of(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}"#,
        &[img.as_fd(), source.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.NoSpaceLeft", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(str_of(&e.parameters, "reason"), "blocks");
    assert_eq!(str_of(&e.parameters, "path"), "/big.bin");
    let ck = reply(call(&mut c, "Check", IMG, &[img.as_fd()]));
    assert_eq!(u64_of(&ck, "errors"), 0);
    assert!(bool_of(&ck, "clean"));
    let replies = call_more(&mut c, "List", IMG, &[img.as_fd()]);
    let listed = names(&replies);
    assert!(
        listed.contains(&"a.txt") && !listed.contains(&"big.bin"),
        "{:?}",
        listed
    );
    // Sized into a window of 1 MiB the content does not fit: TooSmall, and
    // the fresh file the client made is still empty.
    let (manifest, _) = manifest_and_blob(&tree);
    let manifest_file = file_with(base.path(), "manifest", &manifest);
    let (fresh, fresh_img) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0,"size":1048576},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[fresh_img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    );
    assert_eq!(
        e.name,
        format!("{}.TooSmall", IFACE),
        "{}",
        Value::Object(e.parameters.clone())
    );
    assert_eq!(u64_of(&e.parameters, "sizeBytes"), 1 << 20);
    assert!(u64_of(&e.parameters, "minimalSizeBytes") > 48 << 20);
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0,"size":1048576},"content":{"sourceFileDescriptor":1}}"#,
        &[fresh_img.as_fd(), source.as_fd()],
    );
    assert_eq!(e.name, format!("{}.TooSmall", IFACE));
    assert_eq!(std::fs::metadata(fresh.path()).unwrap().len(), 0);
    // Without a size the file is grown to the fit and the same call
    // succeeds; the size was not the exact minimum when it was given.
    let manifest_file = ro(&base.path().join("manifest"));
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"content":{"manifest":{"fileDescriptor":1},"sourceFileDescriptor":2}}"#,
        &[fresh_img.as_fd(), manifest_file.as_fd(), source.as_fd()],
    ));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "directories")), (3, 1));
    assert!(bool_of(&r, "exact"));
    assert!(std::fs::metadata(fresh.path()).unwrap().len() > 48 << 20);
    let (big_image, big_img) = fresh_image();
    let r = reply(call(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0,"size":67108864},"content":{"sourceFileDescriptor":1}}"#,
        &[big_img.as_fd(), source.as_fd()],
    ));
    assert!(!bool_of(&r, "exact"));
    assert_eq!(u64_of(object_of(&r, "description"), "sizeBytes"), 64 << 20);
    assert_eq!(std::fs::metadata(big_image.path()).unwrap().len(), 64 << 20);
}
