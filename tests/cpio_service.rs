// SPDX-License-Identifier: LGPL-2.1-or-later
//! The ucpio service of the org.uapi-group.FileSystem interface.
//!
//! Every reply and every error is held against the interface description
//! by the client of the tests. What the service writes for the trees and
//! the manifests of the fixtures is held against the `made-*` archives of
//! tests/fixtures/cpio, the archives a kernel unpacked.

#[path = "common/client.rs"]
mod client;
mod common;
#[path = "common/cpio.rs"]
mod trees;

use std::fs::{self, Permissions};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use client::*;
use common::Temp;
use cpio::manifest;
use trees::{first_tree, second_tree, T};
use varlink::Client;

const USEC: u64 = T * 1_000_000;
/// The content of a call that gives every entry one time and one owner,
/// as the fixtures have them.
const FIXED: &str = r#""times":"fixed","uid":0,"gid":0"#;

fn ucpio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ucpio"))
}

fn service() -> Client {
    connect_fd3(&ucpio())
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = fixtures().join("cpio").join(format!("{}.cpio", name));
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))
}

fn copy_of(name: &str) -> Temp {
    let image = Temp::new(".cpio");
    fs::write(image.path(), fixture(name)).unwrap();
    image
}

fn assert_is(image: &Path, name: &str) {
    let written = fs::read(image).unwrap();
    let kept = fixture(name);
    assert!(
        written == kept,
        "the service wrote {} bytes that are not {}.cpio ({} bytes), the first difference is at {:?}",
        written.len(),
        name,
        kept.len(),
        written.iter().zip(&kept).position(|(a, b)| a != b)
    );
}

fn first() -> Temp {
    let tree = Temp::dir();
    first_tree(tree.path());
    fs::set_permissions(tree.path(), Permissions::from_mode(0o755)).unwrap();
    tree
}

fn error_name(e: &varlink::Error) -> &str {
    e.name.rsplit('.').next().unwrap()
}

#[test]
fn capabilities_and_what_an_archive_has_no_notion_of() {
    let _serial = common::serial();
    let mut c = service();
    let r = reply(call(&mut c, "GetCapabilities", "{}", &[]));
    let capabilities = object_of(&r, "capabilities");
    assert_eq!(str_of(capabilities, "fileSystemType"), "cpio");
    assert_eq!(str_of(capabilities, "implementation"), "ucpio");
    let operations = strings_of(capabilities, "operations");
    for operation in [
        "plan",
        "populate",
        "list",
        "check",
        "manifest",
        "writeManifest",
        "reproducible",
    ] {
        assert!(operations.contains(&operation), "{}", operation);
    }
    for operation in ["remove", "repair", "label", "identifier"] {
        assert!(!operations.contains(&operation), "{}", operation);
    }
    assert_eq!(
        strings_of(capabilities, "preserves"),
        ["ownership", "modes", "hardlinks", "symlinks", "specialFiles"]
    );
    reply(call(&mut c, "GetCapabilities", r#"{"fileSystemType":"cpio"}"#, &[]));
    let e = error_of(&mut c, "GetCapabilities", r#"{"fileSystemType":"vfat"}"#, &[]);
    assert_eq!(error_name(&e), "FileSystemTypeNotSupported");
    assert_eq!(str_of(&e.parameters, "fileSystemType"), "vfat");

    // What the interface has and an archive has not.
    let (_image, file) = fresh_image();
    let fds = [file.as_fd()];
    for (options, operation) in [
        (r#"{"label":"x"}"#, "label"),
        (r#"{"identifier":"1234-5678"}"#, "identifier"),
        (r#"{"discard":true}"#, "discard"),
        (r#"{"enableFeatures":["x"]}"#, "features"),
    ] {
        let p = format!(r#"{{"image":{{"fileDescriptor":0}},"options":{}}}"#, options);
        let e = error_of(&mut c, "Assemble", &p, &fds);
        assert_eq!(error_name(&e), "OperationNotSupported", "{}", options);
        assert_eq!(str_of(&e.parameters, "operation"), operation);
    }
    for (options, parameter) in [
        (r#"{"vfat":{}}"#, "vfat"),
        (r#"{"sectorSize":512}"#, "sectorSize"),
        (r#"{"blockSize":4096}"#, "blockSize"),
        (r#"{"cpio":{"endAlignment":6}}"#, "cpio"),
        (r#"{"cpio":{"dataAlignment":3}}"#, "cpio"),
    ] {
        let p = format!(r#"{{"image":{{"fileDescriptor":0}},"options":{}}}"#, options);
        let e = error_of(&mut c, "Assemble", &p, &fds);
        assert_eq!(e.name, "org.varlink.service.InvalidParameter", "{}", options);
        assert_eq!(str_of(&e.parameters, "parameter"), parameter);
    }
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"options":{"reproducible":true}}"#,
        &fds,
    );
    assert_eq!(error_name(&e), "NotReproducible");
    assert_eq!(str_of(&e.parameters, "reason"), "timestampRequired");
    let e = error_of(
        &mut c,
        "Assemble",
        r#"{"image":{"fileDescriptor":0},"fileSystemType":"ext4"}"#,
        &fds,
    );
    assert_eq!(error_name(&e), "FileSystemTypeNotSupported");
    // Nothing is taken out of an archive, and none is repaired.
    let image = copy_of("made-assemble");
    let file = rw(image.path());
    let e = error_of(
        &mut c,
        "Remove",
        r#"{"image":{"fileDescriptor":0},"path":"/etc"}"#,
        &[file.as_fd()],
    );
    assert_eq!(error_name(&e), "OperationNotSupported");
    assert_eq!(str_of(&e.parameters, "operation"), "remove");
    let e = error_of(
        &mut c,
        "Check",
        r#"{"image":{"fileDescriptor":0},"repair":"preen"}"#,
        &[file.as_fd()],
    );
    assert_eq!(str_of(&e.parameters, "operation"), "repair");
    assert!(fs::read(image.path()).unwrap() == fixture("made-assemble"));
}

#[test]
fn assemble_writes_the_archives_a_kernel_unpacked() {
    let _serial = common::serial();
    let mut c = service();
    let tree = first();
    let dir = ro(tree.path());
    let expected = fixture("made-assemble");
    let content = format!(r#""content":{{"sourceFileDescriptor":1,{}}}"#, FIXED);

    let (image, file) = fresh_image();
    let p = format!(
        r#"{{"image":{{"fileDescriptor":0}},"options":{{"timestampUSec":{},"reproducible":true}},{},"imageHash":"sha256"}}"#,
        USEC, content
    );
    let r = reply(call(&mut c, "Assemble", &p, &[file.as_fd(), dir.as_fd()]));
    assert_is(image.path(), "made-assemble");
    let description = object_of(&r, "description");
    assert_eq!(str_of(description, "fileSystemType"), "cpio");
    assert_eq!(u64_of(description, "sizeBytes"), expected.len() as u64);
    assert_eq!(u64_of(description, "minimalSizeBytes"), expected.len() as u64);
    assert!(bool_of(&r, "exact"));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "skipped")), (7, 0));
    assert_eq!(
        str_of(&r, "imageHash"),
        cpio::sha256::to_hex(&cpio::sha256::digest(&expected))
    );

    // A plan says the size and writes nothing.
    let p = format!(
        r#"{{"mode":"plan","options":{{"timestampUSec":{}}},"content":{{"sourceFileDescriptor":0,{}}}}}"#,
        USEC, FIXED
    );
    let r = reply(call(&mut c, "Assemble", &p, &[dir.as_fd()]));
    assert_eq!(u64_of(object_of(&r, "description"), "sizeBytes"), expected.len() as u64);
    assert!(bool_of(&r, "exact"));

    // The form with checksums and aligned contents, with the steps told.
    let (image, file) = fresh_image();
    let p = format!(
        r#"{{"image":{{"fileDescriptor":0}},"options":{{"timestampUSec":{},"cpio":{{"endAlignment":4096,"dataAlignment":4096,"checksums":true}}}},{}}}"#,
        USEC, content
    );
    let replies = call_more(&mut c, "Assemble", &p, &[file.as_fd(), dir.as_fd()]);
    assert_is(image.path(), "made-assemble-aligned");
    assert_eq!(phases(&replies), ["planning", "populating"]);

    // Room that is too small for the archive.
    let (image, file) = fresh_image();
    file.set_len(4096).unwrap();
    let p = format!(
        r#"{{"image":{{"fileDescriptor":0,"size":4096}},"options":{{"timestampUSec":{}}},{}}}"#,
        USEC, content
    );
    let e = error_of(&mut c, "Assemble", &p, &[file.as_fd(), dir.as_fd()]);
    assert_eq!(error_name(&e), "TooSmall");
    assert_eq!(u64_of(&e.parameters, "minimalSizeBytes"), expected.len() as u64);
    assert_eq!(u64_of(&e.parameters, "sizeBytes"), 4096);
    assert!(fs::read(image.path()).unwrap() == vec![0u8; 4096]);

    // Without content and without an entry for the root the archive is
    // its trailer.
    let (image, file) = fresh_image();
    let p = format!(
        r#"{{"image":{{"fileDescriptor":0}},"options":{{"timestampUSec":{},"cpio":{{"rootEntry":false,"endAlignment":4}}}}}}"#,
        USEC
    );
    let r = reply(call(&mut c, "Assemble", &p, &[file.as_fd()]));
    assert_eq!(u64_of(object_of(&r, "description"), "sizeBytes"), 124);
    assert_eq!(fs::metadata(image.path()).unwrap().len(), 124);
}

#[test]
fn populate_adds_what_a_kernel_unpacked() {
    let _serial = common::serial();
    let mut c = service();
    let second = Temp::dir();
    second_tree(second.path());
    let dir = ro(second.path());

    let image = copy_of("made-assemble");
    let file = rw(image.path());
    let p = format!(
        r#"{{"image":{{"fileDescriptor":0}},"path":"/","content":{{"sourceFileDescriptor":1,{}}},"timestampUSec":{}}}"#,
        FIXED, USEC
    );
    let replies = call_more(&mut c, "Populate", &p, &[file.as_fd(), dir.as_fd()]);
    assert_is(image.path(), "made-populate");
    assert_eq!(phases(&replies), ["populating"]);
    let last = replies.last().unwrap();
    // Six files: the two names of the hard-linked one are one file.
    assert_eq!((u64_of(last, "files"), u64_of(last, "skipped")), (6, 0));

    // What a manifest of systemd's describes, below a new directory.
    let image = copy_of("made-assemble");
    let file = rw(image.path());
    let special = fixtures().join("special");
    let (tree, manifest) = (ro(&special.join("tree")), ro(&special.join("Uapi16Manifest")));
    let p = r#"{"image":{"fileDescriptor":0},"path":"/srv/special","content":{"sourceFileDescriptor":1,"manifest":{"fileDescriptor":2}},"timestampUSec":0}"#;
    reply(call(
        &mut c,
        "Populate",
        p,
        &[file.as_fd(), tree.as_fd(), manifest.as_fd()],
    ));
    assert_is(image.path(), "made-populate-manifest");
}

#[test]
fn what_cannot_be_added_is_an_error_of_the_interface() {
    let _serial = common::serial();
    let mut c = service();
    let image = copy_of("made-assemble");
    let before = fixture("made-assemble");
    let dir = Temp::dir();
    let source = file_with(dir.path(), "file", b"contents");
    let mut refused = |path: &str, rest: &str, with_source: bool| {
        let file = rw(image.path());
        let content = if with_source {
            format!(r#","content":{{"sourceFileDescriptor":1{}}}"#, rest)
        } else {
            rest.to_string()
        };
        let p = format!(r#"{{"image":{{"fileDescriptor":0}},"path":"{}"{}}}"#, path, content);
        let fds = if with_source {
            vec![file.as_fd(), source.as_fd()]
        } else {
            vec![file.as_fd()]
        };
        let e = error_of(&mut c, "Populate", &p, &fds);
        assert!(
            fs::read(image.path()).unwrap() == before,
            "{} changed the archive",
            path
        );
        e
    };
    let named = |e: &varlink::Error, name: &str, path: &str| {
        assert_eq!(error_name(e), name);
        assert_eq!(str_of(&e.parameters, "path"), path);
    };
    // A file where a directory is, under a name of a hard-linked file,
    // below what is not there and below what is no directory.
    named(&refused("/etc", "", true), "IsADirectory", "/etc");
    named(&refused("/lib/a.so", "", true), "FileExists", "/lib/a.so");
    named(&refused("/nowhere/file", "", true), "NoSuchFile", "/nowhere");
    named(&refused("/big/file", "", true), "NotADirectory", "/big");
    named(&refused("/", "", true), "IsADirectory", "/");
    // A file that is there, when it is not to be replaced.
    named(
        &refused("/etc/conf", r#","replace":false"#, true),
        "FileExists",
        "/etc/conf",
    );
    // A directory that is there, without leave to take it for the one to
    // make.
    named(&refused("/etc", "", false), "FileExists", "/etc");
    // A path that does not start at the root, and a name the format keeps
    // for itself.
    let e = refused("etc/x", "", true);
    assert_eq!(e.name, "org.varlink.service.InvalidParameter");
    assert_eq!(str_of(&e.parameters, "parameter"), "path");
    let e = refused("/TRAILER!!!", "", true);
    assert_eq!(error_name(&e), "InvalidName");
    assert_eq!(str_of(&e.parameters, "reason"), "reserved");

    // With leave the directory is taken, and nothing is added.
    let file = rw(image.path());
    let r = reply(call(
        &mut c,
        "Populate",
        r#"{"image":{"fileDescriptor":0},"path":"/etc","parents":true}"#,
        &[file.as_fd()],
    ));
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "directories")), (0, 0));
    assert!(fs::read(image.path()).unwrap() == before);
}

#[test]
fn manifests_as_content_and_as_what_was_written() {
    let _serial = common::serial();
    let mut c = service();
    let special = fixtures().join("special");
    let (tree, manifest_file) = (ro(&special.join("tree")), ro(&special.join("Uapi16Manifest")));
    let out = Temp::new(".manifest");
    let written = sink(out.path());

    // From the files next to the manifest, with the manifest of what was
    // written asked for.
    let (image, file) = fresh_image();
    let p = r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1,"manifest":{"fileDescriptor":2},"manifestSink":{"fileDescriptor":3,"fields":["mode","uid","gid","size","hash","symlink","device","hardlink","mtime","userXattr"]}}}"#;
    let r = reply(call(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), tree.as_fd(), manifest_file.as_fd(), written.as_fd()],
    ));
    assert_is(image.path(), "made-manifest-special");
    assert_eq!(u64_of(&r, "omitted"), 0);
    let mut ours = manifest::Manifest::parse(&fs::read(out.path()).unwrap()).unwrap();
    let mut theirs = manifest::Manifest::parse(&fs::read(special.join("Uapi16Manifest")).unwrap()).unwrap();
    // An archive has no extended attributes, which its manifest says, and
    // no names of users and groups.
    for manifest in [&mut ours, &mut theirs] {
        for object in std::iter::once(&mut manifest.root).chain(&mut manifest.objects) {
            (object.user_xattrs, object.user_name, object.group_name) = (None, None, None);
        }
    }
    assert_eq!(ours, theirs);

    // From a stream that has the contents in the order of the manifest.
    let esp = fixtures().join("esp");
    let text = fs::read(esp.join("Uapi16Manifest")).unwrap();
    let mut contents = Vec::new();
    for entry in manifest::Manifest::parse(&text)
        .unwrap()
        .objects
        .iter()
        .filter(|e| e.is_streamed())
    {
        contents.extend(fs::read(esp.join("tree").join(entry.name.as_str())).unwrap());
    }
    let dir = Temp::dir();
    let stream = file_with(dir.path(), "contents", &contents);
    let manifest_file = ro(&esp.join("Uapi16Manifest"));
    let (image, file) = fresh_image();
    let p = r#"{"image":{"fileDescriptor":0},"content":{"sourceFileDescriptor":1,"manifest":{"fileDescriptor":2}}}"#;
    reply(call(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), stream.as_fd(), manifest_file.as_fd()],
    ));
    assert_is(image.path(), "made-manifest-esp-stream");

    // A stream that ends early, and files that are not what the manifest
    // says.
    let short = file_with(dir.path(), "short", &contents[..contents.len() - 1]);
    let manifest_file = ro(&esp.join("Uapi16Manifest"));
    let (_image, file) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), short.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(error_name(&e), "ContentMismatch");
    assert_eq!(str_of(&e.parameters, "reason"), "streamEnded");
    let copy = Temp::dir();
    common::run(
        Path::new("cp"),
        &[
            "-r",
            special.join("tree").to_str().unwrap(),
            copy.path().join("tree").to_str().unwrap(),
        ],
        &[],
    );
    fs::write(copy.path().join("tree/a.txt"), b"FIRST\n").unwrap();
    let (tree, manifest_file) = (ro(&copy.path().join("tree")), ro(&special.join("Uapi16Manifest")));
    let (image, file) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), tree.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(error_name(&e), "ContentMismatch");
    assert_eq!(
        (str_of(&e.parameters, "name"), str_of(&e.parameters, "reason")),
        ("a.txt", "hash")
    );
    // The call failed while it wrote the archive, and what it leaves is
    // stopped: no call takes it for an archive, and a check says why.
    assert!(fs::read(image.path()).unwrap().starts_with(b"X70701"));
    let unfinished = ro(image.path());
    let e = error_of(&mut c, "Describe", IMG, &[unfinished.as_fd()]);
    assert_eq!(error_name(&e), "Corrupt");
    assert_eq!(str_of(&e.parameters, "field"), "c_magic");
    let r = reply(call(&mut c, "Check", IMG, &[unfinished.as_fd()]));
    assert!(!bool_of(&r, "clean"));
    assert_eq!((u64_of(&r, "errors"), u64_of(&r, "warnings")), (1, 0));
    let problems = r.get("problems").and_then(json::Value::as_array).unwrap();
    let problem = problems[0].as_object().unwrap();
    assert_eq!(
        (str_of(problem, "kind"), str_of(problem, "name")),
        ("noMagic", "cpio-unfinished")
    );
    // A file that grew since the manifest was written is not cut short.
    fs::write(copy.path().join("tree/a.txt"), b"first\nand more\n").unwrap();
    let (tree, manifest_file) = (ro(&copy.path().join("tree")), ro(&special.join("Uapi16Manifest")));
    let (image, file) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), tree.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(error_name(&e), "SourceMismatch");
    assert_eq!(
        (str_of(&e.parameters, "name"), str_of(&e.parameters, "reason")),
        ("a.txt", "size")
    );
    assert_eq!(fs::metadata(image.path()).unwrap().len(), 0);
    fs::remove_file(copy.path().join("tree/a.txt")).unwrap();
    let (tree, manifest_file) = (ro(&copy.path().join("tree")), ro(&special.join("Uapi16Manifest")));
    let (image, file) = fresh_image();
    let e = error_of(
        &mut c,
        "Assemble",
        p,
        &[file.as_fd(), tree.as_fd(), manifest_file.as_fd()],
    );
    assert_eq!(error_name(&e), "SourceMismatch");
    assert_eq!(
        (str_of(&e.parameters, "name"), str_of(&e.parameters, "reason")),
        ("a.txt", "missing")
    );
    // Found before anything was written.
    assert_eq!(fs::metadata(image.path()).unwrap().len(), 0);

    // The manifest of an archive that is there.
    let image = copy_of("made-populate");
    let file = ro(image.path());
    let written = sink(out.path());
    let r = reply(call(
        &mut c,
        "Describe",
        r#"{"image":{"fileDescriptor":0},"manifestSink":{"fileDescriptor":1}}"#,
        &[file.as_fd(), written.as_fd()],
    ));
    assert_eq!(
        u64_of(object_of(&r, "description"), "sizeBytes"),
        fixture("made-populate").len() as u64
    );
    // Every name of a regular file is an object of the manifest.
    assert_eq!((u64_of(&r, "files"), u64_of(&r, "omitted")), (15, 0));
    let m = manifest::Manifest::parse(&fs::read(out.path()).unwrap()).unwrap();
    let conf = m.objects.iter().find(|e| e.name == "etc/conf").unwrap();
    assert_eq!(conf.sha256, Some(manifest::Sha256::of(b"new and longer\n")));
}

#[test]
fn an_archive_is_listed_checked_and_described() {
    let _serial = common::serial();
    let mut c = service();
    let image = copy_of("made-populate");
    let file = ro(image.path());
    let fds = [file.as_fd()];
    const IMAGE: &str = r#"{"image":{"fileDescriptor":0}}"#;

    // The names in the root are the ones a kernel unpacked there.
    let listing = fs::read_to_string(fixtures().join("cpio/made-populate.unpacked")).unwrap();
    let unpacked: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|name| *name != "." && !name.contains('/'))
        .collect();
    let replies = call_more(&mut c, "List", IMAGE, &fds);
    assert_eq!(names(&replies), unpacked);
    let e = error_of(&mut c, "List", IMAGE, &fds);
    assert_eq!(e.name, "org.varlink.service.ExpectedMore");
    // A file answers with itself, without the more flag.
    let r = reply(call(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/etc/conf"}"#,
        &fds,
    ));
    let entry = object_of(&r, "entry");
    assert_eq!((str_of(entry, "name"), str_of(entry, "type")), ("conf", "reg"));
    assert_eq!((u64_of(entry, "sizeBytes"), u64_of(entry, "mode")), (15, 0o640));
    assert_eq!(u64_of(entry, "modifiedUSec"), USEC);
    let r = reply(call(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/sbin"}"#,
        &fds,
    ));
    let entry = object_of(&r, "entry");
    assert_eq!((str_of(entry, "type"), str_of(entry, "target")), ("lnk", "bin"));
    let replies = call_more(&mut c, "List", r#"{"image":{"fileDescriptor":0},"path":"/run"}"#, &fds);
    assert_eq!(names(&replies), ["sock"]);
    assert_eq!(str_of(object_of(&replies[0], "entry"), "type"), "sock");
    let e = error_of(
        &mut c,
        "List",
        r#"{"image":{"fileDescriptor":0},"path":"/nowhere"}"#,
        &fds,
    );
    assert_eq!(error_name(&e), "NoSuchFile");
    assert_eq!(str_of(&e.parameters, "path"), "/nowhere");

    // A check of it, and of an archive the kernel loses entries of.
    let r = reply(call(&mut c, "Check", IMAGE, &fds));
    assert!(bool_of(&r, "clean"));
    assert_eq!((u64_of(&r, "errors"), u64_of(&r, "warnings")), (0, 2));
    let lost = copy_of("names");
    let lost_file = ro(lost.path());
    let replies = call_more(&mut c, "Check", IMAGE, &[lost_file.as_fd()]);
    assert_eq!(phases(&replies), ["checking"]);
    let last = replies.last().unwrap();
    assert!(!bool_of(last, "clean"));
    assert!(u64_of(last, "errors") > 0);
    let kinds: Vec<&str> = replies
        .iter()
        .filter_map(|r| r.get("problems").and_then(json::Value::as_array))
        .flatten()
        .filter_map(|p| p.as_object())
        .map(|p| str_of(p, "kind"))
        .collect();
    for kind in ["missingParent", "parentNotDirectory", "trailingSlash", "unusableName"] {
        assert!(kinds.contains(&kind), "{}: {:?}", kind, kinds);
    }

    let r = reply(call(&mut c, "Describe", IMAGE, &fds));
    let description = object_of(&r, "description");
    assert_eq!(str_of(description, "fileSystemType"), "cpio");
    assert_eq!(u64_of(description, "sizeBytes"), fixture("made-populate").len() as u64);

    // What is no archive.
    let dir = Temp::dir();
    for (bytes, reason) in [
        (&b""[..], "blank"),
        (&[0u8; 2048][..], "blank"),
        (b"\x1f\x8b\x08 compressed", "foreignImageType"),
        (b"something else entirely", "unknown"),
    ] {
        let other = file_with(dir.path(), "other", bytes);
        for method in ["Describe", "Check"] {
            let e = error_of(&mut c, method, IMAGE, &[other.as_fd()]);
            assert_eq!(error_name(&e), "NotFileSystem", "{}", reason);
            assert_eq!(str_of(&e.parameters, "reason"), reason);
        }
    }
    // An archive that is damaged where it has to be read.
    let cut = file_with(dir.path(), "cut", &fixture("made-assemble")[..300]);
    let e = error_of(&mut c, "Describe", IMAGE, &[cut.as_fd()]);
    assert_eq!(error_name(&e), "Corrupt");
}
