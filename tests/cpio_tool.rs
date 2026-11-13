// SPDX-License-Identifier: LGPL-2.1-or-later
//! The ucpio command line.
//!
//! What the tool writes for the trees and the manifests of the fixtures is
//! held against the `made-*` archives of tests/fixtures/cpio, byte for
//! byte. Those are the archives a kernel unpacked, see
//! tests/cpio_made.rs and tests/cpio_kernel.rs: so what the command line
//! writes is what a kernel was seen to take.

mod common;
#[path = "common/cpio.rs"]
mod trees;

use std::ffi::OsStr;
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use common::Temp;
use cpio::manifest;
use trees::{first_tree, second_tree, T};

fn ucpio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ucpio"))
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn fixture(name: &str) -> Vec<u8> {
    let path = fixtures().join("cpio").join(format!("{}.cpio", name));
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))
}

/// A copy of a fixture to work on.
fn copy_of(name: &str) -> Temp {
    let image = Temp::new(".cpio");
    fs::write(image.path(), fixture(name)).unwrap();
    image
}

/// Runs the tool with `args` and `input` on its standard input. The time
/// of the build is not in its environment.
fn run_with(args: &[&OsStr], input: &[u8]) -> Output {
    let mut child = Command::new(ucpio())
        .args(args)
        .env_remove("SOURCE_DATE_EPOCH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn run(args: &[&OsStr]) -> Output {
    run_with(args, b"")
}

/// Runs the tool, which has to succeed, and returns what it printed.
fn ok(args: &[&OsStr]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "ucpio {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Runs the tool, which has to fail with the exit status `code`, and
/// returns what it said.
fn fails(args: &[&OsStr], code: i32) -> String {
    let out = run(args);
    assert_eq!(out.status.code(), Some(code), "ucpio {:?}", args);
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn os(text: &str) -> &OsStr {
    OsStr::new(text)
}

/// The options that make what the tool writes the same wherever it runs:
/// one time and one owner for everything.
fn fixed() -> Vec<String> {
    [
        "--timestamp",
        &T.to_string(),
        "--times",
        "fixed",
        "--uid",
        "0",
        "--gid",
        "0",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn args<'a>(command: &'a str, options: &'a [String], rest: &[&'a Path]) -> Vec<&'a OsStr> {
    let mut args = vec![os(command)];
    args.extend(options.iter().map(|option| os(option)));
    args.extend(rest.iter().map(|path| path.as_os_str()));
    args
}

fn assert_is(image: &Path, name: &str) {
    let written = fs::read(image).unwrap();
    let kept = fixture(name);
    assert!(
        written == kept,
        "the tool wrote {} bytes that are not {}.cpio ({} bytes), the first difference is at {:?}",
        written.len(),
        name,
        kept.len(),
        written.iter().zip(&kept).position(|(a, b)| a != b)
    );
}

/// The first tree of the fixtures, with the mode its root has in them.
fn first() -> Temp {
    let tree = Temp::dir();
    first_tree(tree.path());
    fs::set_permissions(tree.path(), Permissions::from_mode(0o755)).unwrap();
    tree
}

#[test]
fn the_tool_writes_the_archives_a_kernel_unpacked() {
    let _serial = common::serial();
    let first = first();
    let second = Temp::dir();
    second_tree(second.path());
    let fixed = fixed();

    // A tree, and a tree added to it.
    let image = Temp::new(".cpio");
    let _ = fs::remove_file(image.path());
    ok(&args("assemble", &fixed, &[image.path(), first.path()]));
    assert_is(image.path(), "made-assemble");
    // The size is what a plan says.
    let planned = ok(&args(
        "assemble",
        &[fixed.clone(), vec!["--plan".to_string()]].concat(),
        &[first.path()],
    ));
    assert_eq!(planned.trim(), fs::metadata(image.path()).unwrap().len().to_string());
    ok(&args("populate", &fixed, &[image.path(), second.path()]));
    assert_is(image.path(), "made-populate");

    // The same with checksums and aligned contents.
    let aligned: Vec<String> = ["--end-alignment", "4096", "--data-alignment", "4096"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let options = [fixed.clone(), aligned.clone(), vec!["--checksums".to_string()]].concat();
    ok(&args("assemble", &options, &[image.path(), first.path()]));
    assert_is(image.path(), "made-assemble-aligned");
    ok(&args(
        "populate",
        &[fixed.clone(), aligned].concat(),
        &[image.path(), second.path()],
    ));
    assert_is(image.path(), "made-populate-aligned");

    // What a manifest of systemd's describes, from the files next to it.
    let special = fixtures().join("special");
    let manifest = vec![
        "--manifest".to_string(),
        special.join("Uapi16Manifest").to_str().unwrap().to_string(),
    ];
    let _ = fs::remove_file(image.path());
    ok(&args("assemble", &manifest, &[image.path(), &special.join("tree")]));
    assert_is(image.path(), "made-manifest-special");

    // And added to an archive, below a directory that is not there yet.
    // The time of the directories that are made is the one given.
    ok(&args("assemble", &fixed, &[image.path(), first.path()]));
    let below: Vec<String> = ["--path", "/srv/special", "--timestamp", "0", "--times", "preserve"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    ok(&args(
        "populate",
        &[manifest, below].concat(),
        &[image.path(), &special.join("tree")],
    ));
    assert_is(image.path(), "made-populate-manifest");

    // A manifest with the contents of its files on standard input.
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
    let _ = fs::remove_file(image.path());
    let manifest_path = esp.join("Uapi16Manifest");
    let out = run_with(
        &[
            os("assemble"),
            os("--manifest"),
            manifest_path.as_os_str(),
            image.path().as_os_str(),
            os("-"),
        ],
        &contents,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_is(image.path(), "made-manifest-esp-stream");

    // A stream that goes on after the last file is not the one the
    // manifest describes.
    let _ = fs::remove_file(image.path());
    let long = [&contents[..], b"more"].concat();
    let out = run_with(
        &[
            os("assemble"),
            os("--manifest"),
            manifest_path.as_os_str(),
            image.path().as_os_str(),
            os("-"),
        ],
        &long,
    );
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("goes on after the last file"), "{}", said);
}

#[test]
fn an_archive_is_listed_described_and_read() {
    let _serial = common::serial();
    let image = copy_of("made-populate");
    // The names in the root are the ones a kernel unpacked there.
    let listing = fs::read_to_string(fixtures().join("cpio/made-populate.unpacked")).unwrap();
    let unpacked: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.split(' ').next())
        .filter(|name| *name != "." && !name.contains('/'))
        .collect();
    let listed = ok(&[os("list"), image.path().as_os_str()]);
    assert_eq!(listed.lines().collect::<Vec<_>>(), unpacked);
    // A directory, with and without the slash in front, and a file.
    let lib = ok(&[os("list"), image.path().as_os_str(), os("/lib")]);
    assert_eq!(lib.lines().collect::<Vec<_>>(), ["a.so", "b.so", "c.so", "d.so"]);
    assert_eq!(ok(&[os("list"), image.path().as_os_str(), os("lib")]), lib);
    assert_eq!(ok(&[os("list"), image.path().as_os_str(), os("/etc/conf")]), "conf\n");
    let long = ok(&[os("list"), os("-l"), image.path().as_os_str()]);
    let line = |name: &str| {
        long.lines()
            .find(|line| line.split(' ').any(|word| word.trim_end_matches('/') == name))
            .unwrap_or_else(|| panic!("no line for {} in {}", name, long))
    };
    assert!(line("bin").starts_with("d0755  -     0     0          0 2020-01-02 03:04:05 bin/"));
    assert!(line("big").starts_with("-0644  1     0     0       9000 2020-01-02 03:04:05 big"));
    assert!(line("sbin").ends_with("sbin -> bin"), "{}", line("sbin"));
    let etc = ok(&[os("list"), os("-l"), image.path().as_os_str(), os("/etc")]);
    assert!(
        etc.lines().any(|l| l.starts_with("-0644  3") && l.ends_with("a-link")),
        "{}",
        etc
    );
    // What is not there.
    fails(&[os("list"), image.path().as_os_str(), os("/nowhere")], 1);

    assert_eq!(
        run(&[os("cat"), image.path().as_os_str(), os("/etc/conf")]).stdout,
        b"new and longer\n"
    );
    let big = run(&[os("cat"), image.path().as_os_str(), os("big")]).stdout;
    assert_eq!(big.len(), 9000);
    fails(&[os("cat"), image.path().as_os_str(), os("/etc")], 1);
    fails(&[os("cat"), image.path().as_os_str(), os("/sbin")], 1);
    fails(&[os("cat"), image.path().as_os_str(), os("/nowhere")], 1);

    let described = ok(&[os("describe"), image.path().as_os_str()]);
    assert!(described.contains("format:        070701"), "{}", described);
    assert!(described.contains(&format!("size:          {}", fixture("made-populate").len())));
    assert!(
        described.contains("root:          mode 0755, owner 0:0"),
        "{}",
        described
    );
    let checked = copy_of("made-assemble-aligned");
    assert!(ok(&[os("describe"), checked.path().as_os_str()]).contains("format:        070702"));
}

#[test]
fn a_check_exits_like_fsck() {
    let _serial = common::serial();
    // Sound, and sound with something to say.
    let image = copy_of("made-assemble");
    let out = ok(&[os("check"), image.path().as_os_str()]);
    assert!(out.contains("0 errors, 0 warnings"), "{}", out);
    let image = copy_of("made-populate");
    let out = ok(&[os("check"), image.path().as_os_str()]);
    assert!(
        out.contains("warning: 'etc/conf' replaces an earlier entry of the same name"),
        "{}",
        out
    );
    assert!(out.contains("0 errors, 2 warnings"), "{}", out);
    // Entries the kernel loses, an archive that was cut off while
    // entries were added to it, and one that was cut off while it was
    // written.
    for name in [
        "names",
        "made-populate-cut",
        "made-assemble-cut",
        "made-assemble-cut-early",
    ] {
        let image = copy_of(name);
        let out = run(&[os("check"), image.path().as_os_str()]);
        assert_eq!(out.status.code(), Some(4), "{}", name);
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(said.contains("error: "), "{}", name);
        assert_eq!(
            said.contains("was not finished"),
            name.contains("-cut"),
            "{}: {}",
            name,
            said
        );
    }
    // No archive at all.
    let empty = Temp::new(".cpio");
    fs::write(empty.path(), b"").unwrap();
    fails(&[os("check"), empty.path().as_os_str()], 8);
    fs::write(empty.path(), b"\x1f\x8b\x08 not what we read").unwrap();
    let said = fails(&[os("check"), empty.path().as_os_str()], 8);
    assert!(said.contains("gzip"), "{}", said);
    fails(&[os("check"), os("/nonexistent/image")], 8);
}

#[test]
fn what_cannot_be_added_leaves_the_archive_as_it_was() {
    let _serial = common::serial();
    let image = copy_of("made-assemble");
    let before = fixture("made-assemble");
    let dir = Temp::dir();
    let file = dir.path().join("file");
    fs::write(&file, b"contents").unwrap();
    let populate = |rest: &[&OsStr]| {
        let mut args = vec![os("populate"), image.path().as_os_str()];
        args.extend(rest);
        let said = fails(&args, 1);
        assert!(
            fs::read(image.path()).unwrap() == before,
            "{:?} changed the archive",
            rest
        );
        said
    };
    // A file where a directory is, under a name of a hard-linked file,
    // and below what is not there or no directory.
    assert!(populate(&[file.as_os_str(), os("--path"), os("/etc")]).contains("is a directory"));
    assert!(populate(&[file.as_os_str(), os("--path"), os("/lib/a.so")]).contains("hard-linked"));
    populate(&[file.as_os_str(), os("--path"), os("/nowhere/file")]);
    populate(&[file.as_os_str(), os("--path"), os("/big/file")]);
    populate(&[file.as_os_str(), os("--path"), os("/")]);
    // A file that is there, when it is not to be replaced.
    assert!(populate(&[file.as_os_str(), os("--path"), os("/etc/conf"), os("--no-replace")]).contains("etc/conf"));
    // A directory that is there, without leave to take it for the one to
    // make.
    populate(&[os("--path"), os("/etc")]);
    // Options that are none.
    populate(&[os("--label"), os("x")]);
    populate(&[os("--end-alignment"), os("6"), file.as_os_str(), os("--path"), os("/f")]);
    // With leave the directory is taken, and nothing is added.
    ok(&[
        os("populate"),
        image.path().as_os_str(),
        os("--path"),
        os("/etc"),
        os("-p"),
    ]);
    assert!(fs::read(image.path()).unwrap() == before);
    // A new directory with the ones that lead to it.
    ok(&[
        os("populate"),
        image.path().as_os_str(),
        os("--path"),
        os("/var/lib/thing"),
        os("--parents"),
    ]);
    let listed = ok(&[os("list"), image.path().as_os_str(), os("/var/lib")]);
    assert_eq!(listed, "thing\n");
}

#[test]
fn the_manifest_and_the_hash_of_what_was_written() {
    let _serial = common::serial();
    let first = first();
    let image = Temp::new(".cpio");
    let _ = fs::remove_file(image.path());
    let out = Temp::new(".manifest");
    let options = [
        fixed(),
        vec![
            "--hash".to_string(),
            "sha256".to_string(),
            "--write-manifest".to_string(),
            out.path().to_str().unwrap().to_string(),
        ],
    ]
    .concat();
    let printed = ok(&args("assemble", &options, &[image.path(), first.path()]));
    let written = fs::read(image.path()).unwrap();
    assert_eq!(printed.trim(), cpio::sha256::to_hex(&cpio::sha256::digest(&written)));
    // The manifest describes the tree: every file with its hash.
    let m = manifest::Manifest::parse(&fs::read(out.path()).unwrap()).unwrap();
    let conf = m.objects.iter().find(|e| e.name == "etc/conf").unwrap();
    assert_eq!(conf.sha256, Some(manifest::Sha256::of(b"old\n")));
    assert_eq!(
        (conf.mode.map(|mode| mode.bits()), conf.uid, conf.gid),
        (Some(0o644), Some(0), Some(0))
    );
    // The manifest of an archive made from one of systemd's is that one,
    // without the times, which are not among the fields by default.
    let special = copy_of("made-manifest-special");
    ok(&[
        os("describe"),
        os("--write-manifest"),
        out.path().as_os_str(),
        special.path().as_os_str(),
    ]);
    let mut ours = manifest::Manifest::parse(&fs::read(out.path()).unwrap()).unwrap();
    let mut theirs = manifest::Manifest::parse(&fs::read(fixtures().join("special/Uapi16Manifest")).unwrap()).unwrap();
    // An archive has no extended attributes, which its manifest says, and
    // no names of users and groups.
    for manifest in [&mut ours, &mut theirs] {
        for object in std::iter::once(&mut manifest.root).chain(&mut manifest.objects) {
            (object.user_xattrs, object.user_name, object.group_name) = (None, None, None);
        }
    }
    for object in std::iter::once(&mut theirs.root).chain(&mut theirs.objects) {
        object.mtime_nsec = None;
    }
    assert_eq!(ours, theirs);
}

/// A command that fails after it began to write an archive leaves it
/// stopped: nothing takes what is in the image for an archive, and
/// writing it again makes it one.
#[test]
fn an_archive_that_was_not_finished_is_not_taken_for_one() {
    let _serial = common::serial();
    let tree = first();
    let image = Temp::new(".cpio");
    let stopped = |image: &Path| fs::read(image).unwrap().starts_with(b"X70701");
    let refused = |image: &Path| {
        for command in ["describe", "list", "populate"] {
            let said = fails(&[os(command), image.as_os_str()], 1);
            assert!(said.contains("was not finished"), "{}: {}", command, said);
        }
        let said = fails(&[os("cat"), image.as_os_str(), os("/etc/conf")], 1);
        assert!(said.contains("was not finished"), "{}", said);
        let out = run(&[os("check"), image.as_os_str()]);
        assert_eq!(out.status.code(), Some(4));
        assert!(String::from_utf8_lossy(&out.stdout).contains("was not finished"));
    };

    // The manifest of the archive cannot be written where it is asked
    // for. The archive is all there by then, and it stays stopped.
    let scratch = Temp::dir();
    let nowhere = scratch.path().join("no-such-directory/manifest");
    let mut options = fixed();
    options.extend(["--write-manifest".to_string(), nowhere.to_str().unwrap().to_string()]);
    let _ = fs::remove_file(image.path());
    let said = fails(&args("assemble", &options, &[image.path(), tree.path()]), 1);
    assert!(said.contains("cannot create"), "{}", said);
    assert!(stopped(image.path()));
    let mut whole = fs::read(image.path()).unwrap();
    whole[0] = b'0';
    assert!(whole == fixture("made-assemble"));
    refused(image.path());

    // A file of a manifest that is not what the manifest says, found
    // while the archive is written over the one that was not finished.
    let special = fixtures().join("special");
    let copy = Temp::dir();
    let out = Command::new("cp")
        .arg("-a")
        .arg(special.join("tree"))
        .arg(copy.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    fs::write(copy.path().join("tree/a.txt"), b"FIRST\n").unwrap();
    let manifest_path = special.join("Uapi16Manifest");
    let said = fails(
        &[
            os("assemble"),
            os("--manifest"),
            manifest_path.as_os_str(),
            image.path().as_os_str(),
            copy.path().join("tree").as_os_str(),
        ],
        1,
    );
    assert!(said.contains("does not match the hash"), "{}", said);
    assert!(stopped(image.path()));
    refused(image.path());

    // Written again, it is the archive.
    ok(&args("assemble", &fixed(), &[image.path(), tree.path()]));
    assert_is(image.path(), "made-assemble");
    ok(&[os("check"), image.path().as_os_str()]);
}

/// After `--`, and as the value of an option, -h is an argument like any
/// other.
#[test]
fn help_after_the_options_is_an_argument() {
    let _serial = common::serial();
    let dir = Temp::dir();
    let root = dir.path();
    fs::create_dir(root.join("-h")).unwrap();
    fs::write(root.join("-h/x"), b"x").unwrap();
    let source = root.join("-h");
    let expected = ok(&[os("assemble"), os("--plan"), source.as_os_str()]);
    let out = Command::new(ucpio())
        .args(["assemble", "--plan", "--", "-h"])
        .current_dir(root)
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    let said = fails(
        &[os("assemble"), os("--plan"), os("--size"), os("-h"), source.as_os_str()],
        1,
    );
    assert!(said.contains("unknown size suffix in '-h'"), "{}", said);
}

/// Output into a pipe whose reader is gone ends ucpio with SIGPIPE, as it
/// ends other command line tools, without a panic.
#[test]
fn a_closed_pipe_ends_ucpio_quietly() {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;

    let _serial = common::serial();
    let image = copy_of("made-assemble");
    for args in [
        &[os("describe"), image.path().as_os_str()][..],
        &[os("list"), os("-l"), image.path().as_os_str()],
        &[os("capabilities")],
        &[os("--help")],
        &[os("list"), os("-h")],
    ] {
        let mut fds = [0; 2];
        // SAFETY: pipe2() stores two new descriptors in the array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both descriptors were just created and nothing else owns
        // them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // The reader is gone before ucpio starts, so its first write fails.
        drop(read);
        let out = Command::new(ucpio())
            .args(args)
            .stdout(Stdio::from(write))
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGPIPE),
            "ucpio {:?}: {:?}",
            args,
            out.status
        );
        assert!(
            out.stderr.is_empty(),
            "ucpio {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn usage_and_capabilities() {
    let _serial = common::serial();
    assert!(ok(&[os("--help")]).starts_with("Usage: ucpio COMMAND"));
    assert!(ok(&[os("assemble"), os("--help")]).starts_with("Usage: ucpio COMMAND"));
    fails(&[], 1);
    fails(&[os("frobnicate")], 1);
    fails(&[os("assemble")], 1);
    fails(&[os("capabilities"), os("more")], 1);
    let capabilities = json::parse(&ok(&[os("capabilities")])).unwrap();
    let capabilities = capabilities.as_object().unwrap();
    assert_eq!(
        capabilities.get("fileSystemType").and_then(json::Value::as_str),
        Some("cpio")
    );
}
