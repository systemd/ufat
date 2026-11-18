// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line: assemble makes a file system and fills it, populate
//! fills an existing one, both take a directory tree, or with --manifest the
//! tree a UAPI.16 manifest describes. The commands are the methods of the
//! Varlink interface.

mod common;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{ufat, Temp};

/// The exit statuses of check, as fsck has them: errors are left in the
/// file system, and the check could not be done.
const FSCK_ERRORS_LEFT_UNCORRECTED: i32 = 4;
const FSCK_OPERATIONAL_ERROR: i32 = 8;

fn run(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("ufat runs")
}

/// Runs ufat with `stdin` fed to its standard input. ufat may exit before
/// it reads its input, for one when it refuses an argument first or its
/// SOURCE is a tree.
fn run_in(bin: &Path, args: &[&str], stdin: &[u8]) -> Output {
    use std::io::{ErrorKind, Write};
    use std::process::Stdio;
    let mut child = Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ufat runs");
    if let Err(e) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(e.kind(), ErrorKind::BrokenPipe, "{}", e);
    }
    child.wait_with_output().expect("ufat runs")
}

/// Runs ufat with the file at `path` as its standard input.
fn run_from(bin: &Path, args: &[&str], path: &Path) -> Output {
    Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .stdin(fs::File::open(path).unwrap())
        .output()
        .expect("ufat runs")
}

/// Runs ufat with a pipe that holds `stdin` as its standard input, the
/// writing end closed. Returns what ufat left in the pipe as well. `stdin`
/// has to fit into the pipe.
fn run_from_pipe(bin: &Path, args: &[&str], stdin: &[u8]) -> (Output, Vec<u8>) {
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    let mut fds = [0; 2];
    // SAFETY: pipe2() fills in two descriptors, which are owned here.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both are open and owned by nothing else.
    let (mut reader, mut writer) = unsafe { (fs::File::from_raw_fd(fds[0]), fs::File::from_raw_fd(fds[1])) };
    writer.write_all(stdin).unwrap();
    drop(writer);
    let out = Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .stdin(reader.try_clone().unwrap())
        .output()
        .expect("ufat runs");
    let mut left = Vec::new();
    reader.read_to_end(&mut left).unwrap();
    (out, left)
}

fn ok(bin: &Path, args: &[&str]) -> String {
    let out = run(bin, args);
    assert!(
        out.status.success(),
        "ufat {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(bin: &Path, args: &[&str], with: &str) {
    let out = run(bin, args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "ufat {:?}: {}", args, stderr);
    assert!(
        stderr.contains(with),
        "ufat {:?}: expected '{}' in '{}'",
        args,
        with,
        stderr
    );
}

fn tree(root: &Path) {
    fs::create_dir_all(root.join("EFI/Linux")).unwrap();
    fs::create_dir_all(root.join("loader/entries")).unwrap();
    fs::write(root.join("EFI/Linux/linux.efi"), b"kernel").unwrap();
    fs::write(root.join("loader/entries/x.conf"), b"title x\n").unwrap();
}

/// -h and --help print the usage and exit 0 wherever they are among the
/// options, alone or in a bundle of short options, whatever else is on the
/// command line. Every other short option in a bundle is either applied or
/// refused.
#[test]
fn help_and_short_options() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let usage = ok(&bin, &["list", "-h"]);
    assert!(usage.starts_with("Usage: ufat COMMAND"), "{}", usage);
    // assemble's --verbose is described once, with what it reports, and so
    // is the one of remove.
    let verbose: Vec<&str> = usage
        .lines()
        .filter(|l| l.trim_start().starts_with("--verbose"))
        .collect();
    assert_eq!(
        verbose,
        [
            "  --verbose             Report the geometry chosen and what was written",
            "  --verbose             Report what was removed"
        ]
    );
    for args in [
        &["list", "-hl", "x.img"][..],
        &["list", "-lh", "x.img"],
        &["list", "x.img", "-lh"],
        &["remove", "-rh", "x.img", "/a"],
        &["populate", "-ph", "x.img"],
        &["check", "-rh", "x.img"],
        &["list", "--bogus", "-hl", "x.img"],
        &["describe", "--help", "x.img"],
    ] {
        assert_eq!(ok(&bin, args), usage, "ufat {:?}", args);
    }
    fails(&bin, &["list", "-lr", "x.img"], "unknown option -r");
    fails(&bin, &["list", "-rl", "x.img"], "unknown option -r");
    fails(&bin, &["remove", "-rl", "x.img", "/a"], "unknown option -l");
    fails(&bin, &["check", "-p", "x.img"], "unknown option -p");
    fails(&bin, &["list", "-lx", "x.img"], "unknown option -x");
    fails(&bin, &["list", "-l=1", "x.img"], "option -l takes no value");
}

/// After `--`, and as the value of an option, -h is an argument like any
/// other.
#[test]
fn help_after_the_options_is_an_argument() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    fs::create_dir(root.join("-h")).unwrap();
    fs::write(root.join("-h/x"), b"x").unwrap();
    let source = root.join("-h");
    let source = source.to_str().unwrap();
    let expected = ok(&bin, &["manifest", source]);
    let out = Command::new(&bin)
        .args(["manifest", "--", "-h"])
        .current_dir(root)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("ufat runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    fails(
        &bin,
        &["assemble", "--plan", "--size", "-h", source],
        "unknown size suffix in '-h'",
    );
}

/// Output into a pipe whose reader is gone ends ufat with SIGPIPE, as it
/// ends other command line tools, without a panic.
#[test]
fn a_closed_pipe_ends_ufat_quietly() {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let image = dir.path().join("a.img");
    let image = image.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", image]);
    for args in [
        &["describe", image][..],
        &["capabilities"],
        &["--help"],
        &["list", "-h"],
    ] {
        let mut fds = [0; 2];
        // SAFETY: pipe2() stores two new descriptors in the array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both descriptors were just created and nothing else owns
        // them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // The reader is gone before ufat starts, so its first write fails.
        drop(read);
        let out = Command::new(&bin)
            .args(args)
            .stdout(Stdio::from(write))
            .stderr(Stdio::piped())
            .output()
            .expect("ufat runs");
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGPIPE),
            "ufat {:?}: {:?}",
            args,
            out.status
        );
        assert!(
            out.stderr.is_empty(),
            "ufat {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// --version, and version like help, print the version of the package.
#[test]
fn version() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let version = format!("ufat {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(ok(&bin, &["--version"]), version);
    assert_eq!(ok(&bin, &["version"]), version);
}

/// The owner, with its NUL, and the type of a dlopen note, as the ELF
/// dlopen metadata specification has them.
const DLOPEN_NOTE_OWNER: &[u8] = b"FDO\0";
const DLOPEN_NOTE_TYPE: u32 = 0x407c_0c0a;

/// The bytes of a section as `readelf --hex-dump` prints them. A line
/// holds the address, then up to 16 bytes as hex digits in groups of 4
/// bytes, which take 36 columns, then the bytes as text.
fn hex_dump(dump: &str) -> Vec<u8> {
    const HEX_COLUMNS: usize = 36;
    let mut bytes = Vec::new();
    for line in dump.lines() {
        let Some((_, hex)) = line.trim_start().strip_prefix("0x").and_then(|l| l.split_once(' ')) else {
            continue;
        };
        let digits: Vec<u8> = hex
            .bytes()
            .take(HEX_COLUMNS)
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        for pair in digits.chunks(2) {
            bytes.push(u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap());
        }
    }
    bytes
}

/// The notes in the bytes of a note section, in the byte order of the
/// target: the name with its NUL, the type and the description of each.
/// A note is the sizes of the name and of the description and the type,
/// 32 bits each, then the name and the description, each padded to 4
/// bytes.
fn elf_notes(mut section: &[u8]) -> Vec<(Vec<u8>, u32, Vec<u8>)> {
    const WORD: usize = 4;
    const HEADER_SIZE: usize = 3 * WORD;
    let mut notes = Vec::new();
    while section.len() >= HEADER_SIZE {
        let word = |at: usize| u32::from_ne_bytes(section[at..at + WORD].try_into().unwrap());
        let namesz = word(0) as usize;
        let descsz = word(WORD) as usize;
        let kind = word(2 * WORD);
        let desc = HEADER_SIZE + namesz.next_multiple_of(WORD);
        notes.push((
            section[HEADER_SIZE..HEADER_SIZE + namesz].to_vec(),
            kind,
            section[desc..desc + descsz].to_vec(),
        ));
        section = &section[(desc + descsz).next_multiple_of(WORD).min(section.len())..];
    }
    notes
}

/// The binary carries the `.note.dlopen` ELF note that names libblkid,
/// which ufat loads with dlopen(): owner FDO, type 0x407c0c0a and the JSON
/// of the ELF dlopen metadata specification.
#[test]
fn the_binary_names_libblkid_in_a_dlopen_note() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let Some(readelf) = common::find_program("readelf") else {
        return eprintln!("skipping readelf: not found");
    };
    let readelf = |args: &[&str]| {
        let out = Command::new(&readelf)
            .args(args)
            .arg(&bin)
            .output()
            .expect("readelf runs");
        assert!(
            out.status.success(),
            "readelf {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    };
    // Only a note section is listed with --notes.
    assert!(readelf(&["--wide", "--notes"]).contains("Displaying notes found in: .note.dlopen"));
    let json = concat!(
        r#"[{"feature":"blkid","#,
        r#""description":"Identification of file systems and partition tables in images","#,
        r#""priority":"recommended","#,
        r#""soname":["libblkid.so.1"]}]"#,
        "\0"
    );
    let notes = elf_notes(&hex_dump(&readelf(&["--hex-dump=.note.dlopen"])));
    let note = (DLOPEN_NOTE_OWNER.to_vec(), DLOPEN_NOTE_TYPE, json.as_bytes().to_vec());
    assert_eq!(notes, [note]);
}

/// describe and check say what an image holds when it holds no FAT32 file
/// system, for the images the tools of other file systems make. With
/// libblkid they name it. Without it they say that the image is not
/// blank, except for NTFS, whose boot sector reads like a damaged FAT32
/// one. Only an image of zeros is blank.
#[test]
fn describe_and_check_say_what_an_image_holds() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let blkid = fat::probe::Prober::new().has_libblkid();
    let dir = Temp::dir();
    for (i, maker) in common::MAKERS.iter().enumerate() {
        let image = dir.path().join(format!("{}-{}.img", i, maker.program));
        if !maker.make(&image) {
            eprintln!("skipping {}: not found", maker.program);
            continue;
        }
        let image = image.to_str().unwrap();
        if !blkid && maker.found == "ntfs" {
            fails(&bin, &["describe", image], "invalid reserved sector count 0");
            let out = run(&bin, &["check", image]);
            assert_eq!(out.status.code(), Some(FSCK_ERRORS_LEFT_UNCORRECTED), "{}", maker.found);
            assert!(String::from_utf8_lossy(&out.stdout).contains("the reservedSectors field is invalid"));
            continue;
        }
        let expected = if blkid {
            format!("no FAT32 file system found, the image holds {}", maker.what)
        } else {
            "no FAT32 file system found, the image is not blank and libblkid is not available".to_string()
        };
        fails(&bin, &["describe", image], &expected);
        let out = run(&bin, &["check", image]);
        assert_eq!(out.status.code(), Some(FSCK_OPERATIONAL_ERROR), "{}", maker.found);
        assert!(
            String::from_utf8_lossy(&out.stderr).contains(&expected),
            "{}: {}",
            maker.found,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let blank = dir.path().join("blank.img");
    fs::File::create(&blank).unwrap().set_len(64 << 20).unwrap();
    fails(
        &bin,
        &["describe", blank.to_str().unwrap()],
        "no file system found, the image is blank",
    );
}

/// assemble formats a new, an empty and a blank image, and refuses one
/// that holds a file system unless --force or -f is given: one that it
/// made itself, and one of another file system. Without libblkid it
/// refuses anything that is not blank. Only the part of the image that
/// --offset and --size select counts.
#[test]
fn assemble_refuses_to_format_over_what_is_there() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let blkid = fat::probe::Prober::new().has_libblkid();
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--minimize", a, t]);
    let refused = "the image holds a FAT file system, use --force to format it anyway";
    fails(&bin, &["assemble", a, t], refused);
    fails(&bin, &["assemble", "--create", "--size", "40M", a], refused);
    fails(&bin, &["assemble", "--fit", t, a], refused);
    ok(&bin, &["assemble", "--force", "--label", "AGAIN", a, t]);
    ok(&bin, &["assemble", "-f", "--create", "--size", "40M", a]);
    assert!(run(&bin, &["check", a]).status.success());
    assert_eq!(ok(&bin, &["list", a]), "");
    // Empty and zeros.
    let empty = root.join("empty.img");
    fs::File::create(&empty).unwrap();
    ok(&bin, &["assemble", "--minimize", empty.to_str().unwrap(), t]);
    let zeros = root.join("zeros.img");
    fs::File::create(&zeros).unwrap().set_len(40 << 20).unwrap();
    ok(&bin, &["assemble", zeros.to_str().unwrap()]);
    // A file system 60 MiB into a disk image: the 40 MiB before it are
    // blank, the 40 MiB at it are not.
    let disk = root.join("disk.img");
    let d = disk.to_str().unwrap();
    fs::File::create(&disk).unwrap().set_len(100 << 20).unwrap();
    ok(&bin, &["assemble", "--offset", "60M", "--size", "40M", d]);
    ok(&bin, &["assemble", "--size", "40M", d]);
    fails(&bin, &["assemble", "--offset", "60M", d], refused);
    fails(&bin, &["assemble", "--offset", "60M", "--size", "40M", d, t], refused);
    // An offset beyond the end of the image leaves no size to take. One at
    // its end leaves 0 bytes, too few for any file system, like a size of 0.
    fails(
        &bin,
        &["assemble", "--offset", "200M", d],
        "offset 209715200 is beyond the end of the device (104857600 bytes)",
    );
    let no_room = "0 sectors are not enough for the 32 reserved sectors";
    fails(&bin, &["assemble", "--offset", "100M", d], no_room);
    fails(&bin, &["assemble", "--size", "0", d], no_room);
    // Another file system, which libblkid names.
    let ext4 = root.join("ext4.img");
    let mkfs_ext4 = common::Maker::of("ext4");
    if !mkfs_ext4.make(&ext4) {
        return eprintln!("skipping {}: not found", mkfs_ext4.program);
    }
    let e = ext4.to_str().unwrap();
    let held = if blkid {
        "the image holds a file system of type ext4, use --force"
    } else {
        "the image is not blank and libblkid is not available, use --force"
    };
    fails(&bin, &["assemble", e, t], held);
    fails(&bin, &["assemble", "--size", "40M", e], held);
    ok(&bin, &["assemble", "--force", e, t]);
    assert!(run(&bin, &["check", e]).status.success());
    assert_eq!(ok(&bin, &["cat", e, "/EFI/Linux/linux.efi"]), "kernel");
}

#[test]
fn assemble_and_populate_take_trees_and_manifests() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree_arg = root.join("tree");
    let tree_arg = tree_arg.to_str().unwrap();
    let image = |name: &str| root.join(name).to_str().unwrap().to_string();
    let a = image("a.img");
    let a = a.as_str();
    // A tree: created, formatted and filled in one command. The size is
    // given so that the replacements below have room: a replacement holds
    // the old file until the new one is complete, and a volume sized to fit
    // exactly has no cluster to spare for that.
    ok(&bin, &["assemble", "--create", "--size", "40M", a, tree_arg]);
    assert_eq!(ok(&bin, &["list", a, "/EFI/Linux"]), "linux.efi\n");
    assert!(run(&bin, &["check", a]).status.success());
    let tree_size = ok(&bin, &["assemble", "--plan", tree_arg]);
    // A manifest of the tree, kept outside it, builds the same content; the
    // one SOURCE says where the files are. --minimize reads it twice.
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", tree_arg])).unwrap();
    let m = manifest.to_str().unwrap();
    let b = image("b.img");
    let b = b.as_str();
    ok(
        &bin,
        &["assemble", "--create", "--minimize", "--manifest", m, b, tree_arg],
    );
    assert_eq!(ok(&bin, &["list", b, "/loader/entries"]), "x.conf\n");
    assert_eq!(ok(&bin, &["cat", b, "/EFI/Linux/linux.efi"]), "kernel");
    assert_eq!(fs::metadata(b).unwrap().len().to_string() + "\n", tree_size);
    // The planner sees the same size from the manifest, which needs no
    // SOURCE to be sized.
    assert_eq!(tree_size, ok(&bin, &["assemble", "--plan", "--manifest", m]));
    // populate fills an existing volume, from a manifest too. A file the
    // volume holds already it replaces only with --replace.
    fails(
        &bin,
        &["populate", "--manifest", m, a, tree_arg],
        "'/EFI/Linux/linux.efi' exists",
    );
    ok(&bin, &["populate", "--replace", "--manifest", m, a, tree_arg]);
    ok(&bin, &["populate", "--path", "/second", a, tree_arg]);
    assert_eq!(ok(&bin, &["list", a, "/second/EFI/Linux"]), "linux.efi\n");
    assert!(run(&bin, &["check", a]).status.success());
    // "-" takes the file contents from standard input, back to back in
    // manifest order: linux.efi sorts before x.conf.
    let out = run_in(
        &bin,
        &["populate", "--replace", "--manifest", m, a, "-"],
        b"kerneltitle x\n",
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(ok(&bin, &["cat", a, "/loader/entries/x.conf"]), "title x\n");
    let out = run_in(&bin, &["populate", "--replace", "--manifest", m, a, "-"], b"kern");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ended"));
    let out = run_in(
        &bin,
        &["populate", "--replace", "--manifest", m, a, "-"],
        b"kerneltitle x\nmore",
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("goes on after the last file"));
    // A populate that fails partway leaves the file system marked as not
    // cleanly unmounted, with what was complete.
    assert!(ok(&bin, &["check", a]).contains("not cleanly unmounted"));
    // One whose manifest is refused at its first object, before anything
    // was written, leaves the file system as it was: an object that has
    // expired, one that comes before its directory, one FAT cannot store
    // under --unsupported fail, a file the stream cannot have without a
    // size or at an offset, one that is missing below the SOURCE, one where
    // the file system has a directory, a name FAT cannot store or one too
    // long, and a name the file system holds already.
    let clean = image("clean.img");
    let clean = clean.as_str();
    ok(&bin, &["assemble", "--create", "--size", "40M", clean]);
    let old = root.join("old.txt");
    fs::write(&old, b"old").unwrap();
    ok(&bin, &["populate", "--path", "/d", clean]);
    ok(&bin, &["populate", "--path", "/f", clean, old.to_str().unwrap()]);
    let long = format!(r#"{{"name":"{}","size":0}}"#, "x".repeat(256));
    for (object, options, source, message) in [
        (
            r#"{"name":"x","size":0,"validUntilUSec":1}"#,
            &[][..],
            tree_arg,
            "has expired",
        ),
        (r#"{"name":"d/x","size":0}"#, &[], tree_arg, "does not come right after"),
        (
            r#"{"name":"x","type":"fifo"}"#,
            &["--unsupported", "fail"],
            tree_arg,
            "which FAT cannot store",
        ),
        (r#"{"name":"x"}"#, &[], "-", "cannot be streamed"),
        (
            r#"{"contents":[{"file":"x","offset":1}],"name":"x","size":1}"#,
            &[],
            "-",
            "offset cannot be used",
        ),
        (r#"{"name":"x","size":1}"#, &[], tree_arg, "failed to open x"),
        (r#"{"name":"d","size":0}"#, &[], "-", "'/d' is a directory"),
        (
            r#"{"name":"a:b","size":0}"#,
            &[],
            "-",
            "contains the invalid character ':'",
        ),
        (long.as_str(), &[], "-", "is longer than 255 UTF-16 units"),
        (r#"{"name":"f","size":0}"#, &[], "-", "'/f' exists"),
    ] {
        let refused = root.join("refused.manifest");
        fs::write(
            &refused,
            format!(
                "\x1e{{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}}\n\x1e{}\n\x1e{{\"mediaType\":\"application/vnd.uapi.16.trailer\"}}\n",
                object
            ),
        )
        .unwrap();
        let refused = refused.to_str().unwrap();
        let mut args = vec!["populate"];
        args.extend_from_slice(options);
        args.extend_from_slice(&["--manifest", refused, clean, source]);
        let out = run_in(&bin, &args, b"x");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}: {}", object, stderr);
        assert!(stderr.contains(message), "{}: {}", object, stderr);
        let report = ok(&bin, &["check", clean]);
        assert!(report.ends_with("; 0 errors, 0 warnings\n"), "{}: {}", object, report);
    }
    assert_eq!(ok(&bin, &["cat", clean, "/f"]), "old");
    let out = run_in(&bin, &["populate", "--manifest", m, clean, "-"], b"kern");
    assert_eq!(out.status.code(), Some(1));
    assert!(ok(&bin, &["check", clean]).contains("not cleanly unmounted"));
    // --manifest - reads the manifest from standard input, which then
    // cannot carry the file contents as well. A pipe is read once.
    // assemble --minimize with a SOURCE plans the content before it writes
    // it, so it refuses one before it reads anything of it: all of it is
    // left in the pipe. assemble --plan, assemble without a SOURCE and
    // assemble with a size given read the manifest once and take one.
    // assemble --plan takes standard input that is the file itself as well.
    let manifest_bytes = fs::read(&manifest).unwrap();
    let not_a_file = "standard input is not a regular file: --minimize with a SOURCE needs the manifest in one";
    let piped = image("piped.img");
    let piped = piped.as_str();
    let minimized = ["assemble", "--create", "--minimize", "--manifest", "-", piped, tree_arg];
    let (out, left) = run_from_pipe(&bin, &minimized, &manifest_bytes);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains(not_a_file));
    assert_eq!(left, manifest_bytes);
    assert!(!Path::new(piped).exists());
    let (out, left) = run_from_pipe(
        &bin,
        &["assemble", "--create", "--manifest", "-", piped],
        &manifest_bytes,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(left.is_empty(), "{} bytes left", left.len());
    assert_eq!(fs::metadata(piped).unwrap().len().to_string() + "\n", tree_size);
    assert!(run(&bin, &["check", piped]).status.success());
    fs::remove_file(piped).unwrap();
    let (out, left) = run_from_pipe(&bin, &["assemble", "--plan", "--manifest", "-"], &manifest_bytes);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), tree_size);
    assert!(left.is_empty(), "{} bytes left", left.len());
    let out = run_from(&bin, &["assemble", "--plan", "--manifest", "-"], &manifest);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), tree_size);
    let out = run_in(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "40M",
            "--manifest",
            "-",
            piped,
            tree_arg,
        ],
        &manifest_bytes,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(ok(&bin, &["cat", piped, "/loader/entries/x.conf"]), "title x\n");
    let out = run_in(
        &bin,
        &["populate", "--replace", "--manifest", "-", a, tree_arg],
        &manifest_bytes,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = run_in(&bin, &["populate", "--manifest", "-", a, "-"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot both read standard input"));
    fs::write(root.join("not-a-manifest"), b"not a manifest").unwrap();
    let out = run_from(
        &bin,
        &["assemble", "--plan", "--manifest", "-"],
        &root.join("not-a-manifest"),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("standard input is not a UAPI.16 manifest"));
    let out = run_in(&bin, &["populate", "--manifest", "-", a, tree_arg], b"not a manifest");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("standard input is not a UAPI.16 manifest"));
    // A SOURCE is a directory, or for populate one file that needs --path;
    // a manifest is named by --manifest. A manifest given as a SOURCE next
    // to a tree fails on the count of trees, which says so too. Nothing is
    // created then.
    let untouched = root.join("untouched.img");
    let untouched = untouched.to_str().unwrap();
    fails(&bin, &["populate", a, m], "needs --path");
    fails(&bin, &["assemble", "--plan", m], "a SOURCE is a directory tree");
    fails(&bin, &["populate", a, m, tree_arg], "--manifest PATH names a manifest");
    fails(
        &bin,
        &["assemble", "--create", untouched, m, tree_arg],
        "--manifest PATH names a manifest",
    );
    assert!(!Path::new(untouched).exists());
    fs::write(root.join("garbage"), b"not a manifest").unwrap();
    fails(
        &bin,
        &[
            "populate",
            "--manifest",
            root.join("garbage").to_str().unwrap(),
            a,
            tree_arg,
        ],
        "is not a UAPI.16 manifest",
    );
    // A manifest whose objects are out of order is refused when the object
    // that breaks the order comes.
    let unsorted = root.join("unsorted.manifest");
    let text = String::from_utf8(manifest_bytes.clone()).unwrap();
    let records: Vec<&str> = text.split_inclusive('\n').collect();
    let mut swapped = records.clone();
    swapped.swap(1, records.len() - 2);
    fs::write(&unsorted, swapped.concat()).unwrap();
    fails(
        &bin,
        &["populate", "--manifest", unsorted.to_str().unwrap(), a, tree_arg],
        &format!("{}: manifest object 1 (loader/entries/x.conf):", unsorted.display()),
    );
    // A manifest takes exactly one SOURCE and no --path.
    let nowhere = root.join("nowhere");
    let nowhere = nowhere.to_str().unwrap();
    fails(
        &bin,
        &["populate", "--manifest", nowhere, a, tree_arg, tree_arg],
        "exactly one SOURCE",
    );
    fails(&bin, &["populate", "--manifest", nowhere, a], "exactly one SOURCE");
    fails(
        &bin,
        &["populate", "--manifest", nowhere, "--path", "/x", a, tree_arg],
        "--path applies to directory trees",
    );
    // The switches and commands of the earlier command line are gone.
    fails(&bin, &["populate", "--format", "tree", a, tree_arg], "unknown option");
    fails(&bin, &["populate", "--into", "/x", a, tree_arg], "unknown option");
    for old in ["mkfs", "size", "info", "cp", "mkdir", "rmdir", "rm", "ls", "fsck"] {
        fails(&bin, &[old, a], "unknown command");
    }
    fails(
        &bin,
        &["assemble", "--create", "--source", tree_arg, b, m],
        "unknown option",
    );
    fails(&bin, &["assemble", "--create", "--stream", b, m], "unknown option");
    fails(
        &bin,
        &["assemble", "--no-replace", "--create", b, tree_arg],
        "unknown option",
    );
    // The files a manifest names are found below the SOURCE when they are
    // copied, and the messages about them name the SOURCE. A SOURCE that is
    // not there leaves nothing behind. A file that is missing, or changed
    // since the manifest was written, fails the copy. An image made for the
    // file system is not kept then. One that was there holds what was
    // complete before the failure, marked as not cleanly unmounted, the way
    // a crash would leave it. A file that grew still has the data the
    // manifest describes at its start, and that is what is copied.
    let d = image("d.img");
    let d = d.as_str();
    fails(
        &bin,
        &["assemble", "--create", "--minimize", "--manifest", m, d, nowhere],
        "nowhere",
    );
    assert!(!Path::new(d).exists());
    let empty = root.join("empty");
    let empty = empty.to_str().unwrap();
    fs::create_dir(empty).unwrap();
    let missing = format!(
        "ufat: {}: EFI/Linux/linux.efi: failed to open EFI/Linux/linux.efi",
        empty
    );
    fails(
        &bin,
        &["assemble", "--create", "--minimize", "--manifest", m, d, empty],
        &missing,
    );
    assert!(!Path::new(d).exists());
    fs::write(d, b"").unwrap();
    fails(&bin, &["assemble", "--minimize", "--manifest", m, d, empty], &missing);
    assert_eq!(ok(&bin, &["list", d, "/EFI/Linux"]), "");
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernel and more").unwrap();
    ok(&bin, &["assemble", "--force", "--manifest", m, d, tree_arg]);
    assert_eq!(ok(&bin, &["cat", d, "/EFI/Linux/linux.efi"]), "kernel");
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernal").unwrap();
    fails(
        &bin,
        &["assemble", "--force", "--manifest", m, d, tree_arg],
        &format!(
            "ufat: {}: 'EFI/Linux/linux.efi' does not match the hash in the manifest",
            tree_arg
        ),
    );
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernel").unwrap();
    fs::write(root.join("tree/loader/entries/x.conf"), b"title y\n").unwrap();
    fails(
        &bin,
        &["assemble", "--force", "--manifest", m, d, tree_arg],
        "'loader/entries/x.conf' does not match the hash",
    );
    assert_eq!(ok(&bin, &["cat", d, "/EFI/Linux/linux.efi"]), "kernel");
    let report = ok(&bin, &["check", d]);
    assert!(report.contains("marked dirty"), "{}", report);
    assert!(report.ends_with("; 0 errors, 2 warnings\n"), "{}", report);
    fs::write(root.join("tree/loader/entries/x.conf"), b"title x\n").unwrap();
    // Without a SOURCE assemble makes an empty file system, sized for a
    // manifest as well, and takes no --fit with it.
    let c = image("c.img");
    let c = c.as_str();
    ok(&bin, &["assemble", "--create", "--manifest", m, c]);
    assert_eq!(fs::metadata(c).unwrap().len().to_string() + "\n", tree_size);
    ok(&bin, &["populate", "--manifest", m, c, tree_arg]);
    assert!(run(&bin, &["check", c]).status.success());
    // Populating it with the same manifest once more fails at its first
    // file, which is there, before anything is written, with the contents
    // from the SOURCE and from standard input. So does the tree. The image
    // stays as it was, byte for byte.
    let image_before = fs::read(c).unwrap();
    for (args, stdin) in [
        (&["populate", "--manifest", m, c, tree_arg][..], &b""[..]),
        (&["populate", "--manifest", m, c, "-"], b"kerneltitle x\n"),
        (&["populate", c, tree_arg], b""),
    ] {
        let out = run_in(&bin, args, stdin);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{:?}: {}", args, stderr);
        assert!(
            stderr.contains("'/EFI/Linux/linux.efi' exists"),
            "{:?}: {}",
            args,
            stderr
        );
        assert!(fs::read(c).unwrap() == image_before, "{:?} changed the image", args);
    }
    // With --size it takes that size, which the --fit directory or what the
    // manifest describes has to fit. A size no file system fits in is
    // refused as it is without them.
    let e = image("e.img");
    let e = e.as_str();
    for sized in [["--fit", tree_arg], ["--manifest", m]] {
        ok(
            &bin,
            &[&["assemble", "--create", "--size", "64M", e][..], &sized].concat(),
        );
        assert_eq!(fs::metadata(e).unwrap().len(), 64 << 20);
        fs::remove_file(e).unwrap();
        fails(
            &bin,
            &[&["assemble", "--create", "--size", "1M", e][..], &sized].concat(),
            "FAT32 needs at least 65525",
        );
        assert!(!Path::new(e).exists());
    }
    fails(
        &bin,
        &["assemble", "--create", "--fit", tree_arg, "--manifest", nowhere, c],
        "carries the sizes",
    );
    fails(&bin, &["assemble", "--plan"], "a SOURCE or --manifest");
    fails(
        &bin,
        &["assemble", "--create", "--fit", tree_arg, c, tree_arg],
        "--fit sizes an empty file system",
    );
    // One tree is taken, as by mkfs tools. The trees are counted before
    // anything is opened, so a tree that is not there is not what fails.
    // The same goes for a manifest: the checks above of its SOURCE, --path
    // and --fit come before it is read.
    for args in [
        &["assemble", "--create", c, nowhere, tree_arg][..],
        &["assemble", "--plan", nowhere, tree_arg],
        &["populate", a, nowhere, tree_arg],
        &["assemble", "--create", "--fit", nowhere, "--fit", tree_arg, c],
    ] {
        fails(&bin, args, "only one directory tree can be given");
    }
    // Bad values of --unsupported and --times fail right after the command
    // line is parsed, whatever the command does: before a tree, a file or a
    // manifest is opened, an image is created, or anything is put into one.
    let unsupported = "unknown policy 'bogus' for --unsupported";
    let times = "unknown time policy 'bogus'";
    fails(&bin, &["populate", "--unsupported", "bogus", a, nowhere], unsupported);
    fails(
        &bin,
        &["populate", "--manifest", nowhere, "--unsupported", "bogus", a, tree_arg],
        unsupported,
    );
    fails(
        &bin,
        &["assemble", "--create", "--times", "bogus", untouched, tree_arg],
        times,
    );
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "34M",
            "--unsupported",
            "bogus",
            untouched,
        ],
        unsupported,
    );
    assert!(!Path::new(untouched).exists());
    let file = root.join("tree/loader/entries/x.conf");
    let file = file.to_str().unwrap();
    fails(
        &bin,
        &["populate", "--times", "bogus", "--path", "/new", a, tree_arg],
        times,
    );
    fails(&bin, &["populate", "--times", "bogus", "--path", "/newdir", a], times);
    fails(
        &bin,
        &["populate", "--unsupported", "bogus", "--path", "/new.txt", a, file],
        unsupported,
    );
    let listed = ok(&bin, &["list", a, "/"]);
    for name in ["new/", "newdir/", "new.txt"] {
        assert!(!listed.lines().any(|l| l == name), "{}", listed);
    }
}

/// A manifest has to declare the code point order. One that does not is
/// refused before anything is written, also when its objects are sorted,
/// from a file and from standard input.
#[test]
fn manifests_have_to_declare_their_order() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let declared = ok(&bin, &["manifest", t]);
    let undeclared = declared.replacen(r#","order":"codepoint""#, "", 1);
    assert_ne!(undeclared, declared);
    let manifest = root.join("undeclared.manifest");
    fs::write(&manifest, &undeclared).unwrap();
    let m = manifest.to_str().unwrap();
    let refused = "the manifest does not declare \"order\": \"codepoint\" in its root file object";
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--size", "40M", "--manifest", m, a, t],
        &format!("ufat: {}: {}", m, refused),
    );
    assert!(!image.exists());
    let out = run_in(
        &bin,
        &["assemble", "--create", "--size", "40M", "--manifest", "-", a, t],
        undeclared.as_bytes(),
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!("ufat: standard input: {}", refused)),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!image.exists());
    fails(&bin, &["assemble", "--plan", "--manifest", m], refused);
    fails(&bin, &["assemble", "--create", "--manifest", m, a], refused);
    assert!(!image.exists());
    ok(&bin, &["assemble", "--create", "--size", "40M", a]);
    fails(&bin, &["populate", "--manifest", m, a, t], refused);
    assert_eq!(ok(&bin, &["list", a]), "");
    // With the declaration it is taken.
    fs::write(&manifest, &declared).unwrap();
    ok(&bin, &["populate", "--manifest", m, a, t]);
    assert_eq!(ok(&bin, &["list", a]), "EFI/\nloader/\n");
}

/// The serial number and the label `describe` shows for `image`.
fn described_identity(bin: &Path, image: &str) -> (String, String) {
    let described = ok(bin, &["describe", image]);
    let field = |name: &str| {
        described
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap()
            .trim()
            .to_string()
    };
    (field("volume id:"), field("volume label:"))
}

/// The root object of a manifest names the file system: assemble gives it
/// the serial number and the label, --identifier and --label have to agree,
/// and populate checks them. Without a serial number from the manifest or
/// --identifier, it is the one derived from the manifest's bytes, the same
/// from a file, from standard input and with --minimize. A manifest that
/// lists fs-label without fsLabel is for a file system without a label. A
/// label that FAT cannot store, or would report as another one or as none,
/// is refused. The manifests ufat writes of a file system name it, those of
/// a tree do not.
#[test]
fn manifests_name_the_file_system() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let image = |name: &str| root.join(name).to_str().unwrap().to_string();
    let manifest = ok(&bin, &["manifest", t]);
    // A tree describes no file system.
    assert!(!manifest.contains("fatSerial") && !manifest.contains("fsLabel"));
    let plain = root.join("plain.manifest");
    fs::write(&plain, &manifest).unwrap();
    let p = plain.to_str().unwrap();
    // The serial number derived from the manifest, whichever way it comes:
    // the first eight hex digits sha256sum prints for it.
    let derived = common::derived_serial(manifest.as_bytes());
    match common::find_program("sha256sum") {
        Some(sha256sum) => {
            let out = Command::new(sha256sum).arg(&plain).output().unwrap();
            let printed = String::from_utf8(out.stdout).unwrap().to_uppercase();
            assert_eq!(format!("{}-{}", &printed[..4], &printed[4..8]), derived);
        }
        None => eprintln!("not comparing with sha256sum: not found"),
    }
    let (a, b, c, d) = (image("a.img"), image("b.img"), image("c.img"), image("d.img"));
    ok(&bin, &["assemble", "--create", "--size", "40M", "--manifest", p, &a, t]);
    let out = run_in(
        &bin,
        &["assemble", "--create", "--size", "40M", "--manifest", "-", &b, t],
        manifest.as_bytes(),
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    ok(&bin, &["assemble", "--create", "--minimize", "--manifest", p, &c, t]);
    ok(&bin, &["assemble", "--create", "--manifest", p, &d]);
    for img in [&a, &b, &c, &d] {
        assert_eq!(
            described_identity(&bin, img),
            (derived.clone(), String::new()),
            "{}",
            img
        );
    }
    // The image is the same whether the manifest came from a file and was
    // read twice for --minimize, or from standard input with the size and
    // the cluster size that --minimize chose.
    let size = fs::metadata(&c).unwrap().len().to_string();
    let cluster = ok(&bin, &["describe", &c])
        .lines()
        .find_map(|line| line.strip_prefix("cluster size:").map(|v| v.trim().to_string()))
        .unwrap();
    let e = image("e.img");
    let out = run_in(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            &size,
            "--cluster-size",
            &cluster,
            "--manifest",
            "-",
            &e,
            t,
        ],
        manifest.as_bytes(),
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(fs::read(&c).unwrap() == fs::read(&e).unwrap(), "the images differ");
    // --identifier and --label are used where the manifest names nothing.
    let f = image("f.img");
    ok(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "40M",
            "--identifier",
            "1111-2222",
            "--label",
            "MINE",
            "--manifest",
            p,
            &f,
            t,
        ],
    );
    assert_eq!(
        described_identity(&bin, &f),
        ("1111-2222".to_string(), "MINE".to_string())
    );
    // A manifest that names the file system gives it its serial number and
    // label, from fatSerial, or else from the start of fsUUID.
    let named = |name: &str, features: &[&str], fields: &str| {
        let path = root.join(format!("{}.manifest", name));
        fs::write(&path, common::with_root_fields(manifest.as_bytes(), features, fields)).unwrap();
        path.to_str().unwrap().to_string()
    };
    let esp = named(
        "esp",
        &["fat-serial", "fs-label", "fs-uuid"],
        r#""fatSerial":"1234-abcd","fsLabel":"ESP","fsUUID":"9999aaaa-0000-4000-8000-000000000000""#,
    );
    let uuid = named(
        "uuid",
        &["fs-uuid"],
        r#""fsUUID":"5678abcd-0000-4000-8000-000000000000""#,
    );
    let g = image("g.img");
    ok(&bin, &["assemble", "--create", "--manifest", &esp, &g]);
    assert_eq!(
        described_identity(&bin, &g),
        ("1234-ABCD".to_string(), "ESP".to_string())
    );
    let h = image("h.img");
    ok(
        &bin,
        &["assemble", "--create", "--size", "40M", "--manifest", &uuid, &h, t],
    );
    assert_eq!(described_identity(&bin, &h), ("5678-ABCD".to_string(), String::new()));
    // The options have to agree with what the manifest names: the same
    // values are fine, others are refused before an image is made.
    let i = image("i.img");
    ok(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "40M",
            "--identifier",
            "1234ABCD",
            "--label",
            "ESP",
            "--manifest",
            &esp,
            &i,
            t,
        ],
    );
    let j = image("j.img");
    for (option, value, message) in [
        (
            "--identifier",
            "1234-0000",
            "the identifier 1234-0000 differs from the serial number 1234-ABCD the manifest gives in fatSerial",
        ),
        (
            "--label",
            "esp",
            "the label 'esp' differs from the label 'ESP' the manifest gives in fsLabel",
        ),
    ] {
        fails(
            &bin,
            &[
                "assemble",
                "--create",
                "--size",
                "40M",
                option,
                value,
                "--manifest",
                &esp,
                &j,
                t,
            ],
            &format!("ufat: {}: {}", esp, message),
        );
        assert!(!Path::new(&j).exists());
    }
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "40M",
            "--identifier",
            "00000001",
            "--manifest",
            &uuid,
            &j,
            t,
        ],
        "the identifier 0000-0001 differs from the serial number 5678-ABCD the manifest gives in fsUUID",
    );
    // A manifest that lists fs-label without fsLabel is for a file system
    // without a label, and a --label is one too many.
    let unlabeled = named("unlabeled", &["fs-label"], "");
    let k = image("k.img");
    ok(
        &bin,
        &["assemble", "--create", "--size", "40M", "--manifest", &unlabeled, &k, t],
    );
    assert_eq!(described_identity(&bin, &k).1, "");
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "40M",
            "--label",
            "MINE",
            "--manifest",
            &unlabeled,
            &j,
            t,
        ],
        "the label 'MINE' differs from the manifest, which gives the file system no label (fsLabel)",
    );
    assert!(!Path::new(&j).exists());
    // A label FAT cannot store is refused, and so is one it would report
    // as another label or as none: blkid shows a FAT label without the
    // spaces at its end, and nothing for the blank label and NO NAME.
    let mut refused = Vec::new();
    for (name, label, message) in [
        (
            "long",
            "much too long",
            "label 'much too long' is longer than 11 characters",
        ),
        (
            "trailing",
            "ESP ",
            "label 'ESP ' ends with a space, which FAT does not keep",
        ),
        ("blank", "   ", "label '   ' is what FAT stores for no label"),
        ("no-name", "NO NAME", "label 'NO NAME' is what FAT stores for no label"),
    ] {
        let m = named(name, &["fs-label"], &format!(r#""fsLabel":"{}""#, label));
        fails(
            &bin,
            &["assemble", "--create", "--size", "40M", "--manifest", &m, &j, t],
            message,
        );
        fails(&bin, &["assemble", "--plan", "--manifest", &m], message);
        assert!(!Path::new(&j).exists());
        refused.push((m, message));
    }
    // populate checks the file system against what the manifest names, and
    // writes nothing into another one. Its errors name the image, or the
    // manifest for a label it refuses. A manifest that names nothing goes
    // anywhere.
    ok(&bin, &["populate", "--manifest", &esp, &g, t]);
    ok(&bin, &["populate", "--replace", "--manifest", p, &g, t]);
    ok(&bin, &["populate", "--replace", "--manifest", &unlabeled, &a, t]);
    let other = named("other", &["fs-label"], r#""fsLabel":"OTHER""#);
    let (before_a, before_g) = (fs::read(&a).unwrap(), fs::read(&g).unwrap());
    for (img, m, message) in [
        (
            &a,
            &esp,
            format!(
                "the file system has the serial number {}, the manifest is for 1234-ABCD (fatSerial)",
                derived
            ),
        ),
        (
            &g,
            &other,
            "the file system has the label 'ESP', the manifest is for 'OTHER' (fsLabel)".to_string(),
        ),
        (
            &a,
            &other,
            "the file system has no label, the manifest is for 'OTHER' (fsLabel)".to_string(),
        ),
        (
            &g,
            &unlabeled,
            "the file system has the label 'ESP', the manifest is for one without a label (fsLabel)".to_string(),
        ),
    ] {
        fails(
            &bin,
            &["populate", "--replace", "--manifest", m, img, t],
            &format!("ufat: {}: {}", img, message),
        );
    }
    for (m, message) in &refused {
        fails(
            &bin,
            &["populate", "--replace", "--manifest", m, &g, t],
            &format!("ufat: {}: {}", m, message),
        );
    }
    assert!(fs::read(&a).unwrap() == before_a, "a.img changed");
    assert!(fs::read(&g).unwrap() == before_g, "g.img changed");
    // What ufat writes of a file system names it, so it makes the same
    // serial number and label again and goes into that file system.
    let written = root.join("written.manifest");
    ok(&bin, &["describe", "--write-manifest", written.to_str().unwrap(), &g]);
    let text = fs::read_to_string(&written).unwrap();
    assert!(
        text.starts_with(concat!(
            "\u{1e}{\"fatSerial\":\"1234-ABCD\",",
            "\"features\":[\"device\",\"fat-serial\",\"fs-label\",\"hardlink\",\"read-only\",\"sha256\",\"size\",\"symlink\"],",
            "\"fsLabel\":\"ESP\","
        )),
        "{}",
        text
    );
    let l = image("l.img");
    ok(
        &bin,
        &[
            "assemble",
            "--create",
            "--minimize",
            "--manifest",
            written.to_str().unwrap(),
            &l,
            t,
        ],
    );
    assert_eq!(
        described_identity(&bin, &l),
        ("1234-ABCD".to_string(), "ESP".to_string())
    );
    ok(
        &bin,
        &["populate", "--replace", "--manifest", written.to_str().unwrap(), &g, t],
    );
    // So does what ufat writes of a file system without a label, which
    // lists fs-label and has no fsLabel.
    ok(&bin, &["describe", "--write-manifest", written.to_str().unwrap(), &a]);
    let text = fs::read_to_string(&written).unwrap();
    assert!(!text.contains("fsLabel") && text.contains("\"fs-label\""), "{}", text);
    let m = image("m.img");
    ok(
        &bin,
        &["assemble", "--create", "--manifest", written.to_str().unwrap(), &m],
    );
    assert_eq!(described_identity(&bin, &m), (derived.clone(), String::new()));
    fails(
        &bin,
        &["populate", "--replace", "--manifest", written.to_str().unwrap(), &g, t],
        &format!("ufat: {}: the file system has the serial number 1234-ABCD", g),
    );
    // The label a manifest names takes an entry in the root directory,
    // which a plan counts: sixteen files fill a cluster of 512 bytes, the
    // label entry is a seventeenth. A manifest that names no label takes
    // none.
    let mut sixteen =
        String::from("\u{1e}{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n");
    for i in 0..16 {
        sixteen.push_str(&format!("\u{1e}{{\"name\":\"f{:02}\",\"size\":0}}\n", i));
    }
    sixteen.push_str("\u{1e}{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n");
    for (fields, clusters) in [
        ("", "1 cluster"),
        (r#""features":["fs-label","size"],"fsLabel":"ESP","#, "2 clusters"),
        (r#""features":["fs-label","size"],"#, "1 cluster"),
    ] {
        let path = root.join("sixteen.manifest");
        fs::write(&path, sixteen.replacen("\u{1e}{", &format!("\u{1e}{{{}", fields), 1)).unwrap();
        let out = run(
            &bin,
            &[
                "assemble",
                "--plan",
                "--verbose",
                "--cluster-size",
                "512",
                "--manifest",
                path.to_str().unwrap(),
            ],
        );
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(&format!("16 files, 0 directories, 0 bytes: {} of 512 bytes", clusters)),
            "{}: {}",
            fields,
            stderr
        );
    }
}

/// Names FAT does not tell apart are one name: assemble and populate refuse
/// a second one, in a manifest as well as in a tree, a directory's as well
/// as a file's, unless --replace says to take it as the first. A tree is
/// copied in the order of the bytes of its names, as a manifest has them.
#[test]
fn names_fat_does_not_tell_apart() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    let both = root.join("both");
    fs::create_dir_all(&both).unwrap();
    fs::write(both.join("README.TXT"), "upper\n").unwrap();
    fs::write(both.join("readme.txt"), "lower\n").unwrap();
    let path = |name: &str| root.join(name).to_str().unwrap().to_string();
    let both = path("both");
    let manifest = root.join("both.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", &both])).unwrap();
    let m = manifest.to_str().unwrap();
    let a = path("a.img");
    fails(
        &bin,
        &["assemble", "--create", "--size", "40M", &a, &both],
        "'/readme.txt' and '/README.TXT' are names FAT cannot tell apart",
    );
    assert!(!Path::new(&a).exists(), "a failed assemble left its image behind");
    ok(&bin, &["assemble", "--create", "--size", "40M", "--replace", &a, &both]);
    assert_eq!(ok(&bin, &["list", &a]), "readme.txt\n");
    assert_eq!(ok(&bin, &["cat", &a, "/README.TXT"]), "lower\n");
    fails(
        &bin,
        &["assemble", "--force", "--manifest", m, &a, &both],
        "'/readme.txt' and '/README.TXT' are names FAT cannot tell apart",
    );
    ok(&bin, &["assemble", "--force", "--replace", "--manifest", m, &a, &both]);
    assert_eq!(ok(&bin, &["list", &a]), "readme.txt\n");
    fails(
        &bin,
        &["populate", "--manifest", m, &a, &both],
        "'/README.TXT' and '/readme.txt' are names FAT cannot tell apart",
    );
    ok(&bin, &["populate", "--replace", "--manifest", m, &a, &both]);
    // A tree's efi is its EFI only with --replace, and takes the entries of
    // the EFI then.
    for name in ["EFI/a", "efi/b"] {
        let file = root.join("dirs").join(name);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, "x\n").unwrap();
    }
    let (dirs, d) = (path("dirs"), path("d.img"));
    fails(
        &bin,
        &["assemble", "--create", "--size", "40M", &d, &dirs],
        "'/efi' and '/EFI' are names FAT cannot tell apart",
    );
    ok(&bin, &["assemble", "--create", "--size", "40M", "--replace", &d, &dirs]);
    assert_eq!(ok(&bin, &["list", &d, "/EFI"]), "a\nb\n");
    // A trailing slash means nothing, also to the message, which spells the
    // path that is there the way the file system does.
    fails(
        &bin,
        &["populate", "--path", "/efi/", &d, &path("dirs/EFI/a")],
        "'/efi/' and '/EFI' are names FAT cannot tell apart",
    );
    fails(
        &bin,
        &["populate", "--path", "/efi/A", &d, &path("dirs/EFI/a")],
        "'/efi/A' and '/EFI/a' are names FAT cannot tell apart",
    );
    // A file whose name FAT does not tell apart from a directory's is that
    // as well, before anything else, and with --replace it cannot take the
    // directory's place.
    let mixed = root.join("mixed");
    fs::create_dir_all(mixed.join("EFI")).unwrap();
    fs::write(mixed.join("efi"), "x\n").unwrap();
    let (mixed, e) = (path("mixed"), path("e.img"));
    fails(
        &bin,
        &["assemble", "--create", "--size", "40M", &e, &mixed],
        "'/efi' and '/EFI' are names FAT cannot tell apart",
    );
    fails(
        &bin,
        &["assemble", "--create", "--size", "40M", "--replace", &e, &mixed],
        "'/efi' is a directory",
    );
    assert!(!Path::new(&e).exists(), "a failed assemble left its image behind");
}

/// A volume too small for what goes into it. A copy that runs out of
/// clusters says which file did not fit and leaves what came before it in
/// a consistent file system. `assemble --minimize` with a `--size` the
/// content does not fit says so before it sizes or formats anything:
/// nothing is left of a file `--create` made, and an existing file is as
/// it was. So do `--fit` and `--manifest` without a SOURCE, and a size of
/// 0, which no file system fits in. Without `--minimize` content that does
/// not fit is found while it is written: nothing is left of a file
/// `--create` made then either, and an existing file keeps what was
/// written, marked as not cleanly unmounted. With `--minimize` and without
/// a size an existing file is grown to the fit and never shrunk. Without
/// `--minimize` the file system takes the size given or the whole file.
#[test]
fn too_small_volumes_fail_cleanly() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("a.txt"), b"first\n").unwrap();
    fs::write(tree.join("big.bin"), vec![0x5au8; 36 << 20]).unwrap();
    fs::write(tree.join("sub/c.txt"), b"last\n").unwrap();
    let t = tree.to_str().unwrap();

    let small = root.join("small.img");
    let s = small.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "34M", s]);
    fails(&bin, &["populate", s, t], "copying big.bin: no free clusters left");
    assert!(run(&bin, &["check", s]).status.success());
    assert_eq!(ok(&bin, &["cat", s, "/a.txt"]), "first\n");
    assert!(!ok(&bin, &["list", s, "/"]).contains("big.bin"));

    let new = root.join("new.img");
    let n = new.to_str().unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--minimize", "--size", "1M", n, t],
        "holds 1048576 bytes but the content needs",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    fails(
        &bin,
        &["assemble", "--create", n, t],
        "is empty: give --size, or --minimize",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    fails(
        &bin,
        &["assemble", "--create", "--size", "1M", n, t],
        "FAT32 needs at least 65525",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    fails(
        &bin,
        &["assemble", "--create", "--size", "0", n, t],
        "0 sectors are not enough for the 32 reserved sectors",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    // An empty file system that the tree or its manifest has to fit is
    // refused the same way, in the clusters --size 34M gets.
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", t])).unwrap();
    let m = manifest.to_str().unwrap();
    for content in [["--fit", t], ["--manifest", m]] {
        fails(
            &bin,
            &[&["assemble", "--create", "--size", "34M", n][..], &content].concat(),
            "a file system of 35651584 bytes holds 68528 clusters of 512 bytes, the content needs 73732",
        );
        assert!(!new.exists(), "a failed assemble left its image behind");
    }
    // Without --minimize content that does not fit is found while it is
    // written. The image made for it is not kept then either, and neither
    // is it when the manifest of what was written or its hash cannot be
    // written.
    fails(
        &bin,
        &["assemble", "--create", "--size", "34M", n, t],
        "copying big.bin: no free clusters left",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    fails(
        &bin,
        &["assemble", "--create", "--size", "34M", "--manifest", m, n, t],
        "copying big.bin: no free clusters left",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    let nowhere = root.join("missing/m.json");
    let nowhere = nowhere.to_str().unwrap();
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "64M",
            "--write-manifest",
            nowhere,
            n,
            t,
        ],
        "cannot create",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--size",
            "64M",
            "--hash",
            "sha256",
            "--write-hash",
            nowhere,
            n,
            t,
        ],
        "cannot write",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    let existing = root.join("existing.img");
    let e = existing.to_str().unwrap();
    fs::write(&existing, b"").unwrap();
    fails(
        &bin,
        &["assemble", "--minimize", "--size", "1M", e, t],
        "holds 1048576 bytes but the content needs",
    );
    assert_eq!(fs::metadata(&existing).unwrap().len(), 0);
    // An image that was there keeps what was written, marked as not
    // cleanly unmounted.
    fails(
        &bin,
        &["assemble", "--size", "34M", e, t],
        "copying big.bin: no free clusters left",
    );
    assert_eq!(fs::metadata(&existing).unwrap().len(), 34 << 20);
    assert!(ok(&bin, &["check", e]).contains("marked dirty"));

    let size: u64 = ok(&bin, &["assemble", "--plan", t]).trim().parse().unwrap();
    // A plan against a size says whether the tree fits it, the way
    // assemble with the same options would: 1M is too small for any file
    // system, and too small for the smallest one --minimize makes.
    fails(
        &bin,
        &["assemble", "--plan", "--size", "1M", t],
        "FAT32 needs at least 65525",
    );
    fails(
        &bin,
        &["assemble", "--plan", "--minimize", "--size", "1M", t],
        "more than --size",
    );
    assert_eq!(
        ok(&bin, &["assemble", "--plan", "--size", "64M", t]),
        format!("{}\n", size)
    );
    fs::File::create(&existing).unwrap().set_len(4096).unwrap();
    ok(&bin, &["assemble", "--minimize", e, t]);
    assert_eq!(fs::metadata(&existing).unwrap().len(), size);
    assert_eq!(ok(&bin, &["cat", e, "/sub/c.txt"]), "last\n");
    let large = root.join("large.img");
    let l = large.to_str().unwrap();
    fs::File::create(&large).unwrap().set_len(64 << 20).unwrap();
    ok(&bin, &["assemble", "--minimize", l, t]);
    assert_eq!(fs::metadata(&large).unwrap().len(), 64 << 20);
    assert!(ok(&bin, &["describe", l]).contains(&format!("size:             {}\n", size)));
    assert!(run(&bin, &["check", l]).status.success());
    assert_eq!(ok(&bin, &["cat", l, "/sub/c.txt"]), "last\n");
    ok(&bin, &["assemble", "--force", l, t]);
    assert!(ok(&bin, &["describe", l]).contains(&format!("size:             {}\n", 64 << 20)));
    assert_eq!(ok(&bin, &["cat", l, "/sub/c.txt"]), "last\n");
    // Without --minimize nothing is planned: what does not fit fails while
    // it is written, and leaves the file system unfinished.
    fs::File::create(&large).unwrap().set_len(36 << 20).unwrap();
    fails(&bin, &["assemble", l, t], "copying big.bin: no free clusters left");
    assert!(ok(&bin, &["check", l]).contains("marked dirty"));
}

/// A file system of the size given gets the cluster size that size gets,
/// also where `--fit` or `--manifest` without a SOURCE plans what it has to
/// hold. A plan of a small tree picks 512 byte clusters, and 200 GiB of
/// them are more than FAT32 can count. The images are sparse.
#[test]
fn a_size_given_keeps_its_cluster_size() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", t])).unwrap();
    let m = manifest.to_str().unwrap();
    let sized = ["assemble", "--create", "--size", "200G", "--identifier", "1234abcd"];
    let alone = root.join("alone.img");
    let alone = alone.to_str().unwrap();
    ok(&bin, &[&sized[..], &[alone]].concat());
    let geometry = ok(&bin, &["describe", alone]);
    assert!(geometry.contains("cluster size:     32768\n"), "{}", geometry);
    let image = root.join("sized.img");
    let i = image.to_str().unwrap();
    for content in [["--fit", t], ["--manifest", m]] {
        ok(&bin, &[&sized[..], &content, &[i]].concat());
        assert_eq!(fs::metadata(&image).unwrap().len(), 200 << 30);
        assert_eq!(ok(&bin, &["describe", i]), geometry);
        assert!(run(&bin, &["check", i]).status.success());
        fs::remove_file(&image).unwrap();
    }
}

/// Whether the content fits a size given is counted in clusters. One
/// sector more can take one more sector for each FAT and hold one cluster
/// less: with 512 byte clusters a file system of 66590 sectors holds 65534
/// clusters, one of 66591 sectors 65533. A tree that takes 65534 clusters
/// fills the smaller one to the last cluster. Its plan, the smallest file
/// system for it, has 66590 sectors, fewer than 66591, so comparing sizes
/// would let `--fit` and `--manifest` pass there and the copy run out of
/// clusters. The images are sparse.
#[test]
fn one_sector_more_can_hold_one_cluster_less() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    // A cluster for the root directory and 65533 for the file.
    let tree = root.join("tree");
    fs::create_dir(&tree).unwrap();
    fs::File::create(tree.join("big"))
        .unwrap()
        .set_len(65533 * 512)
        .unwrap();
    let t = tree.to_str().unwrap();
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", t])).unwrap();
    let m = manifest.to_str().unwrap();
    let sectors = |n: u64| (n * 512).to_string();
    let clusters = |free: u64, clusters: u64| format!("clusters:         {} ({} free)", clusters, free);
    assert_eq!(ok(&bin, &["assemble", "--plan", t]), sectors(66590) + "\n");
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    for (n, held) in [(66590, 65534), (66591, 65533), (66592, 65534)] {
        ok(&bin, &["assemble", "--create", "--size", &sectors(n), a]);
        assert!(ok(&bin, &["describe", a]).contains(&clusters(held - 1, held)));
        fs::remove_file(&image).unwrap();
    }
    for content in [["--fit", t], ["--manifest", m]] {
        for n in [66590, 66592] {
            ok(
                &bin,
                &[&["assemble", "--create", "--size", &sectors(n), a][..], &content].concat(),
            );
            fs::remove_file(&image).unwrap();
        }
        fails(
            &bin,
            &[&["assemble", "--create", "--size", &sectors(66591), a][..], &content].concat(),
            "a file system of 34094592 bytes holds 65533 clusters of 512 bytes, the content needs 65534",
        );
        assert!(!image.exists(), "a failed assemble left its image behind");
    }
    // The copy agrees: the tree fills 66590 sectors to the last cluster and
    // does not go into 66591.
    ok(
        &bin,
        &["assemble", "--create", "--size", &sectors(66590), "--fit", t, a],
    );
    ok(&bin, &["populate", a, t]);
    assert!(ok(&bin, &["describe", a]).contains(&clusters(0, 65534)));
    fs::remove_file(&image).unwrap();
    ok(&bin, &["assemble", "--create", "--size", &sectors(66591), a]);
    fails(&bin, &["populate", a, t], "copying big: no free clusters left");
}

/// `assemble --plan --size` answers for `assemble` with the same options.
/// Without `--minimize` that is a file system of the size given, with the
/// cluster size the formatter picks for it: 80000 files of one byte fit 512
/// byte clusters in about 44 MB, but take 80000 of the 4 KiB clusters that
/// 300 MiB gets, and it has fewer. With `--minimize` the smallest file
/// system, with 512 byte clusters, has to fit in `--size`. The files come
/// from standard input, after a manifest.
#[test]
fn a_plan_against_a_size_answers_for_assemble() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    // 100 directories of 800 files, which keeps every directory below the
    // 65536 entries FAT allows.
    let mut text = String::from(
        "\x1e{\"features\":[\"size\"],\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
    );
    for d in 0..100 {
        text.push_str(&format!("\x1e{{\"name\":\"d{:02}\",\"type\":\"dir\"}}\n", d));
        for f in 0..800 {
            text.push_str(&format!("\x1e{{\"name\":\"d{:02}/f{:03}\",\"size\":1}}\n", d, f));
        }
    }
    text.push_str("\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n");
    let manifest = root.join("small.manifest");
    fs::write(&manifest, text).unwrap();
    let m = manifest.to_str().unwrap();
    let contents = vec![b'x'; 80_000];
    let smallest: u64 = ok(&bin, &["assemble", "--plan", "--manifest", m])
        .trim()
        .parse()
        .unwrap();
    assert!(smallest < 300 << 20, "{}", smallest);
    ok(
        &bin,
        &["assemble", "--plan", "--minimize", "--size", "300M", "--manifest", m],
    );
    fails(
        &bin,
        &["assemble", "--plan", "--size", "300M", "--manifest", m],
        "a file system of 314572800 bytes holds 76646 clusters of 4096 bytes, the content needs 80701",
    );
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    let out = run_in(
        &bin,
        &["assemble", "--create", "--size", "300M", "--manifest", m, a, "-"],
        &contents,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    assert!(stderr.contains("no free clusters left"), "{}", stderr);
    assert!(!image.exists(), "a failed assemble left its image behind");
    // 400 MiB holds them, and the plan says so.
    ok(&bin, &["assemble", "--plan", "--size", "400M", "--manifest", m]);
    let out = run_in(
        &bin,
        &["assemble", "--create", "--size", "400M", "--manifest", m, a, "-"],
        &contents,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(ok(&bin, &["cat", a, "/d99/f799"]), "x");
}

/// A plan does not compare names. With --replace the entries of a
/// directory under two names that FAT does not tell apart go into one
/// directory. The plan holds the entries under each name to the 65536
/// entries of a FAT directory on their own, and only the write sees them
/// all in one directory. In two runs of 1600 names of 255 characters,
/// which take 21 entries each, the plan passes and `assemble --replace`
/// fails. Without --replace the second name fails before. In one run the
/// plan fails.
#[test]
fn directories_under_two_names_fill_up_when_written() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    let manifest = |runs: &[(&str, std::ops::Range<usize>)]| {
        let mut text = String::from(
            "\x1e{\"features\":[\"size\"],\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
        );
        for (name, files) in runs {
            text.push_str(&format!("\x1e{{\"name\":\"{}\",\"type\":\"dir\"}}\n", name));
            for i in files.clone() {
                text.push_str(&format!("\x1e{{\"name\":\"{}/{:0>255}\",\"size\":0}}\n", name, i));
            }
        }
        text.push_str("\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n");
        text
    };
    let split = root.join("split.manifest");
    fs::write(&split, manifest(&[("EFI", 0..1600), ("efi", 1600..3200)])).unwrap();
    let s = split.to_str().unwrap();
    ok(&bin, &["assemble", "--plan", "--manifest", s]);
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--minimize",
            "--replace",
            "--manifest",
            s,
            a,
            "-",
        ],
        "directory is full",
    );
    assert!(!image.exists(), "a failed assemble left its image behind");
    let image = root.join("b.img");
    let b = image.to_str().unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--minimize", "--manifest", s, b, "-"],
        "'/efi' and '/EFI' are names FAT cannot tell apart",
    );
    assert!(!image.exists(), "a failed assemble left its image behind");
    let whole = root.join("whole.manifest");
    fs::write(&whole, manifest(&[("EFI", 0..3200)])).unwrap();
    fails(
        &bin,
        &["assemble", "--plan", "--manifest", whole.to_str().unwrap()],
        "'/EFI' needs more than the 65536 entry slots a FAT32 directory holds",
    );
}

/// The names in `dir` that a new file waits under where O_TMPFILE is
/// refused: `.#`, its name and 16 hex digits.
fn temporary_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(".#"))
        .collect();
    names.sort();
    names
}

/// Whether the file system of `dir` makes a file without a name
/// (O_TMPFILE), as ufat tries first.
fn makes_unnamed_files(dir: &Path) -> bool {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    let dir = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
    // SAFETY: a NUL terminated path and plain flags.
    let fd = unsafe { libc::open(dir.as_ptr(), libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return false;
    }
    // SAFETY: a descriptor the kernel just handed out, owned by nothing
    // else.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
    true
}

/// Runs `command` with its standard output a pipe whose reader is gone, so
/// that its first write there fails, and returns how it ended.
fn with_a_closed_pipe(mut command: Command) -> Output {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::process::Stdio;
    let mut fds = [0; 2];
    // SAFETY: pipe2() stores two new descriptors in the array.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: both descriptors were just created and nothing else owns
    // them.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    drop(read);
    command
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .stdout(Stdio::from(write))
        .stderr(Stdio::piped())
        .output()
        .expect("ufat runs")
}

/// assemble gives the image it makes its name only once everything else
/// succeeded, the hash included, and the files it writes next to the
/// image, the manifest and the hash, theirs after the image. A failure
/// before leaves none of them behind: what was at their paths stays as it
/// was, also where the manifest was written before the hash failed. On
/// success they replace what is there, and what is not a regular file,
/// such as /dev/stdout, is written to as the command goes.
#[test]
fn assemble_names_what_it_made_at_the_end() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let t = tree.to_str().unwrap();
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    let manifest = root.join("a.manifest");
    let m = manifest.to_str().unwrap();
    let hash = root.join("a.sha256");
    let h = hash.to_str().unwrap();
    fs::write(&manifest, b"old manifest\n").unwrap();
    fs::write(&hash, b"old hash\n").unwrap();
    let nowhere = root.join("missing/a.sha256");
    let nowhere = nowhere.to_str().unwrap();
    let assemble = |hash| {
        let args = ["assemble", "--create", "--size", "40M", "--write-manifest", m];
        [&args[..], &["--hash", "sha256", "--write-hash", hash, a, t]].concat()
    };
    fails(&bin, &assemble(nowhere), &format!("cannot write {}", nowhere));
    assert!(!image.exists(), "a failed assemble left its image behind");
    assert_eq!(fs::read(&manifest).unwrap(), b"old manifest\n");
    assert_eq!(fs::read(&hash).unwrap(), b"old hash\n");
    assert_eq!(temporary_names(root), Vec::<String>::new());
    ok(&bin, &assemble(h));
    let digest = fat::manifest::Sha256::digest(&fs::read(&image).unwrap());
    assert_eq!(fs::read_to_string(&hash).unwrap(), format!("{}\n", digest));
    let described = ok(&bin, &["describe", "--write-manifest", "-", a]);
    assert_eq!(fs::read_to_string(&manifest).unwrap(), described);
    assert!(ok(&bin, &["check", a]).ends_with("; 0 errors, 0 warnings\n"));
    assert_eq!(temporary_names(root), Vec::<String>::new());
    // The name is taken now, and what is there is formatted anew.
    fails(&bin, &assemble(h), "use --force to format it anyway");
    let written = ok(&bin, &["assemble", "--force", "--write-manifest", "/dev/stdout", a, t]);
    assert_eq!(written, ok(&bin, &["describe", "--write-manifest", "-", a]));
    assert_eq!(temporary_names(root), Vec::<String>::new());
}

/// A manifest on standard output is written before the image gets its
/// name. SIGPIPE ends assemble when the reader of the pipe is gone, and no
/// image is left. A hash is printed once the image has its name, so there
/// SIGPIPE leaves the image complete.
#[test]
fn a_killed_assemble_leaves_no_image() {
    use std::os::unix::process::ExitStatusExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let image = root.join("a.img");
    let mut command = Command::new(&bin);
    command
        .args(["assemble", "--create", "--size", "40M", "--write-manifest", "-"])
        .args([&image, &tree]);
    let out = with_a_closed_pipe(command);
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{:?}", out);
    assert!(!image.exists(), "a killed assemble left its image behind");
    if makes_unnamed_files(root) {
        assert_eq!(temporary_names(root), Vec::<String>::new());
    }
    let mut command = Command::new(&bin);
    command
        .args(["assemble", "--create", "--size", "40M", "--hash", "sha256"])
        .args([&image, &tree]);
    let out = with_a_closed_pipe(command);
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{:?}", out);
    assert!(ok(&bin, &["check", image.to_str().unwrap()]).ends_with("; 0 errors, 0 warnings\n"));
}

/// Where ufat, running as `pid`, makes an image in `dir`: its descriptor of
/// the file without a name, /proc/PID/fd/N, or where O_TMPFILE is refused
/// the temporary name of the file. Only once the image has its size, which
/// comes after the probe that can rename the file, so that its name holds.
fn image_in_the_making(pid: u32, dir: &Path) -> Option<PathBuf> {
    let unnamed = format!("{}/#", fs::canonicalize(dir).unwrap().display());
    let open = fs::read_dir(format!("/proc/{}/fd", pid)).ok().and_then(|fds| {
        fds.flatten()
            .map(|fd| fd.path())
            .find(|fd| fs::read_link(fd).is_ok_and(|target| target.to_string_lossy().starts_with(&unnamed)))
    });
    open.or_else(|| temporary_names(dir).first().map(|name| dir.join(name)))
        .filter(|image| fs::metadata(image).is_ok_and(|metadata| metadata.len() > 0))
}

/// Runs `command`, ufat assembling with `--manifest -` an image in `dir`,
/// with the manifest `text` on its standard input. The root object goes
/// first: assemble reads it before it makes the image, and the record
/// separator of the next object ends it. Once the image is in the making,
/// `meanwhile` gets where it is, and the rest of the manifest goes in.
fn assemble_meanwhile(mut command: Command, dir: &Path, text: &str, meanwhile: impl FnOnce(&Path)) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let (first, rest) = text.split_at(text[1..].find('\x1e').unwrap() + 2);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ufat runs");
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(first.as_bytes()).unwrap();
    let started = Instant::now();
    let image = loop {
        if let Some(image) = image_in_the_making(child.id(), dir) {
            break image;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("ufat ended before it made the image: {}", status);
        }
        assert!(started.elapsed() < Duration::from_secs(60), "ufat made no image");
        std::thread::sleep(Duration::from_millis(10));
    };
    meanwhile(&image);
    // ufat may fail before it read all of it.
    let _ = stdin.write_all(rest.as_bytes());
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// Gives the file at `from` the name `to` as well. `from` can be one of
/// the /proc/PID/fd/N of ufat, which is followed to the file, also to one
/// without a name.
fn hard_link(from: &Path, to: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let (from, to) = (
        std::ffi::CString::new(from.as_os_str().as_bytes()).unwrap(),
        std::ffi::CString::new(to.as_os_str().as_bytes()).unwrap(),
    );
    // SAFETY: NUL terminated paths and plain flags.
    let linked = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    assert_eq!(linked, 0, "{}", std::io::Error::last_os_error());
}

/// A name that something else takes while assemble makes the image stays
/// as it is: the image does not get it, and nothing is left of the image
/// or of the manifest written next to it.
#[test]
fn a_name_taken_meanwhile_stays_as_it_is() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let text = ok(&bin, &["manifest", tree.to_str().unwrap()]);
    let image = root.join("a.img");
    let manifest = root.join("a.manifest");
    fs::write(&manifest, b"old\n").unwrap();
    let mut command = Command::new(&bin);
    command
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .args([
            "assemble",
            "--create",
            "--size",
            "40M",
            "--manifest",
            "-",
            "--write-manifest",
        ])
        .args([&manifest, &image, &tree]);
    let out = assemble_meanwhile(command, root, &text, |_| fs::write(&image, b"theirs").unwrap());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    let taken = format!(
        "failed to create {}: {}",
        image.display(),
        std::io::Error::from_raw_os_error(libc::EEXIST)
    );
    assert!(stderr.contains(&taken), "{}", stderr);
    assert_eq!(fs::read(&image).unwrap(), b"theirs");
    assert_eq!(fs::read(&manifest).unwrap(), b"old\n");
    assert_eq!(temporary_names(root), Vec::<String>::new());
}

/// An image assemble gives up after it wrote part of the content is not
/// written to anymore. So a file system that got another name while it was
/// made, a hard link through ufat's descriptor or through the temporary
/// name where O_TMPFILE is refused, keeps the marks of one that is being
/// written and is never taken for a finished one.
#[test]
fn a_given_up_image_keeps_its_marks() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let text = ok(&bin, &["manifest", tree.to_str().unwrap()]);
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    let image = root.join("a.img");
    let kept = root.join("kept.img");
    let unnamed = Command::new(&bin);
    for command in [Some(unnamed), refusing(&bin, &[Refused::TMPFILE])]
        .into_iter()
        .flatten()
    {
        let mut command = command;
        command
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .args(["assemble", "--create", "--size", "40M", "--manifest", "-"])
            .args([&image, &empty]);
        let out = assemble_meanwhile(command, root, &text, |made| hard_link(made, &kept));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}", stderr);
        assert!(stderr.contains("failed to open EFI/Linux/linux.efi"), "{}", stderr);
        assert!(!image.exists(), "a failed assemble left its image behind");
        assert_eq!(temporary_names(root), Vec::<String>::new());
        let report = ok(&bin, &["check", kept.to_str().unwrap()]);
        assert!(report.contains("marked dirty"), "{}", report);
        fs::remove_file(&kept).unwrap();
    }
}

/// A system call that fails with `errno` under a seccomp filter on ufat,
/// where its argument at the index of `flag` has that flag set, or always
/// without a `flag`. ufat runs then the way it runs where the kernel or the
/// file system refuses what the call asks for.
#[derive(Clone, Copy, Debug)]
struct Refused {
    call: libc::c_long,
    flag: Option<(usize, u32)>,
    errno: i32,
}

/// The flags of include/uapi/linux/audit.h that make an AUDIT_ARCH of a
/// machine of elf.h, the architecture a seccomp filter compares with.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
#[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
const AUDIT_ARCH_LE: u32 = 0x4000_0000;

/// The AUDIT_ARCH of the system calls of ufat, where the filters know it.
/// Each of these is little endian, so the low 32 bits of an argument come
/// first.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: Option<u32> = Some(libc::EM_X86_64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE);
#[cfg(target_arch = "x86")]
const AUDIT_ARCH: Option<u32> = Some(libc::EM_386 as u32 | AUDIT_ARCH_LE);
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: Option<u32> = Some(libc::EM_AARCH64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE);
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
const AUDIT_ARCH: Option<u32> = None;

impl Refused {
    /// O_TMPFILE, refused as a file system without it refuses it.
    const TMPFILE: Refused = Refused {
        call: libc::SYS_openat,
        flag: Some((2, (libc::O_TMPFILE & !libc::O_DIRECTORY) as u32)),
        errno: libc::EOPNOTSUPP,
    };
    /// linkat() with AT_EMPTY_PATH, refused as without CAP_DAC_READ_SEARCH
    /// before Linux 6.10.
    const EMPTY_PATH_LINK: Refused = Refused {
        call: libc::SYS_linkat,
        flag: Some((4, libc::AT_EMPTY_PATH as u32)),
        errno: libc::ENOENT,
    };
    /// renameat2() with RENAME_NOREPLACE, refused as NFS refuses it.
    const NOREPLACE: Refused = Refused {
        call: libc::SYS_renameat2,
        flag: Some((4, libc::RENAME_NOREPLACE)),
        errno: libc::EINVAL,
    };
    /// Every linkat(), refused as a file system without hard links refuses
    /// it (vfs_link()).
    const LINK: Refused = Refused {
        call: libc::SYS_linkat,
        flag: None,
        errno: libc::EPERM,
    };
    /// Every flock(), refused as where another process holds the lock.
    const FLOCK: Refused = Refused {
        call: libc::SYS_flock,
        flag: None,
        errno: libc::EWOULDBLOCK,
    };
    /// Every flock(), refused as NFS without its lock manager refuses it.
    const NO_LOCKS: Refused = Refused {
        call: libc::SYS_flock,
        flag: None,
        errno: libc::ENOLCK,
    };
    /// Every linkat(), failing for another reason than hard links being
    /// refused.
    const LINK_FAILS: Refused = Refused {
        call: libc::SYS_linkat,
        flag: None,
        errno: libc::EIO,
    };
    /// Every renameat(), a rename that may replace, failing. glibc renames
    /// with it on x86_64 and x86, where it is a system call of its own.
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    const RENAME: Refused = Refused {
        call: libc::SYS_renameat,
        flag: None,
        errno: libc::EIO,
    };

    /// The seccomp filter: another architecture, another system call or
    /// the call without the flag is allowed.
    fn filter(self, arch: u32) -> Vec<libc::sock_filter> {
        use std::mem::offset_of;
        let load = |offset: usize| libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: offset as u32,
        };
        let jump = |code: u32, k: u32| libc::sock_filter {
            code: (libc::BPF_JMP | code | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k,
        };
        let give = |action: u32| libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: action,
        };
        let mut filter = vec![
            load(offset_of!(libc::seccomp_data, arch)),
            jump(libc::BPF_JEQ, arch),
            load(offset_of!(libc::seccomp_data, nr)),
            jump(libc::BPF_JEQ, self.call as u32),
        ];
        if let Some((arg, flag)) = self.flag {
            filter.push(load(offset_of!(libc::seccomp_data, args) + arg * size_of::<u64>()));
            filter.push(jump(libc::BPF_JSET, flag));
        }
        filter.push(give(libc::SECCOMP_RET_ERRNO | self.errno as u32));
        filter.push(give(libc::SECCOMP_RET_ALLOW));
        // Every test that fails jumps to the last instruction, which allows
        // the call.
        let last = filter.len() - 1;
        for (at, instruction) in filter.iter_mut().enumerate() {
            if instruction.code == (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16
                || instruction.code == (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16
            {
                instruction.jf = (last - at - 1) as u8;
            }
        }
        filter
    }
}

/// ufat with the system calls of `refused` refused, or None where seccomp
/// filters cannot be had: on an architecture the filters do not know, or
/// under qemu-user, which does not pass them on.
fn refusing(bin: &Path, refused: &[Refused]) -> Option<Command> {
    static USABLE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    let arch = AUDIT_ARCH?;
    let usable = *USABLE.get_or_init(|| {
        let mut probe = filtered(bin, arch, &[Refused::TMPFILE]);
        probe.arg("--version").output().is_ok_and(|out| out.status.success())
    });
    usable.then(|| filtered(bin, arch, refused))
}

/// ufat with the system calls of `refused` refused on the architecture
/// `arch`.
fn filtered(bin: &Path, arch: u32, refused: &[Refused]) -> Command {
    use std::os::unix::process::CommandExt;
    let filters: Vec<Vec<libc::sock_filter>> = refused.iter().map(|r| r.filter(arch)).collect();
    let mut command = Command::new(bin);
    command.env("SOURCE_DATE_EPOCH", "1700000000");
    // SAFETY: between fork and exec the closure makes prctl() calls only,
    // with filters made before the fork.
    unsafe {
        command.pre_exec(move || {
            let (on, unused): (libc::c_ulong, libc::c_ulong) = (1, 0);
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, on, unused, unused, unused) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for filter in &filters {
                let program = libc::sock_fprog {
                    len: filter.len() as u16,
                    filter: filter.as_ptr().cast_mut(),
                };
                let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
                if libc::prctl(libc::PR_SET_SECCOMP, mode, std::ptr::from_ref(&program)) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}

/// Where O_TMPFILE is refused, the image waits under a temporary name in
/// its directory, `.#`, its name and 16 hex digits, and so do the files
/// written next to it. Success renames them, with RENAME_NOREPLACE for the
/// image, and where that is refused too with a link and the removal of the
/// temporary name. A failure, also one after part of the content was
/// written, removes them. A kill leaves the temporary name of the image.
/// Where a link with AT_EMPTY_PATH is refused, the files are linked through
/// /proc/self/fd. seccomp filters on ufat do the refusing; qemu-user does
/// not pass them on, and an architecture the filters do not know skips
/// the test.
#[test]
fn assemble_where_o_tmpfile_or_more_is_refused() {
    use std::os::unix::process::ExitStatusExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let refused = |refused: &[Refused], args: &[&str]| {
        let mut command = refusing(&bin, refused)?;
        command.args(args);
        command.output().ok()
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let t = tree.to_str().unwrap();
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    let image = root.join("a.img");
    let a = image.to_str().unwrap();
    let manifest = root.join("a.manifest");
    let m = manifest.to_str().unwrap();
    fs::write(&manifest, ok(&bin, &["manifest", t])).unwrap();
    let written = root.join("written.manifest");
    let w = written.to_str().unwrap();
    fs::write(&written, b"old\n").unwrap();
    let creates = ["assemble", "--create", "--size", "40M", "--write-manifest", w];
    let tmpfile = &[Refused::TMPFILE][..];
    // A file missing below the SOURCE, after the directories were written.
    let out = refused(
        tmpfile,
        &[&creates[..], &["--manifest", m, a, empty.to_str().unwrap()]].concat(),
    )
    .unwrap();
    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to open EFI/Linux/linux.efi"));
    assert!(!image.exists(), "a failed assemble left its image behind");
    assert_eq!(fs::read(&written).unwrap(), b"old\n");
    assert_eq!(temporary_names(root), Vec::<String>::new());
    // A hash that cannot be written, after the manifest was.
    let nowhere = root.join("missing/a.sha256");
    let hashed = ["--hash", "sha256", "--write-hash", nowhere.to_str().unwrap(), a, t];
    let out = refused(tmpfile, &[&creates[..], &hashed].concat()).unwrap();
    assert_eq!(out.status.code(), Some(1), "{:?}", out);
    assert!(!image.exists(), "a failed assemble left its image behind");
    assert_eq!(fs::read(&written).unwrap(), b"old\n");
    assert_eq!(temporary_names(root), Vec::<String>::new());
    for refusals in [
        tmpfile,
        &[Refused::TMPFILE, Refused::NOREPLACE],
        &[Refused::EMPTY_PATH_LINK],
    ] {
        let out = refused(refusals, &[&creates[..], &[a, t]].concat()).unwrap();
        assert!(out.status.success(), "{:?}: {:?}", refusals, out);
        assert!(ok(&bin, &["check", a]).ends_with("; 0 errors, 0 warnings\n"));
        assert_eq!(
            fs::read_to_string(&written).unwrap(),
            ok(&bin, &["describe", "--write-manifest", "-", a])
        );
        assert_eq!(temporary_names(root), Vec::<String>::new());
        fs::remove_file(&image).unwrap();
        fs::write(&written, b"old\n").unwrap();
    }
    let mut command = refusing(&bin, tmpfile).unwrap();
    command.args(["assemble", "--create", "--size", "40M", "--write-manifest", "-", a, t]);
    let out = with_a_closed_pipe(command);
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{:?}", out);
    assert!(!image.exists(), "a killed assemble left its image behind");
    let left = temporary_names(root);
    assert_eq!(left.len(), 1, "{:?}", left);
    let digits = left[0].strip_prefix(".#a.img").unwrap();
    assert!(
        digits.len() == 16 && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "{:?}",
        left
    );
}

/// Where a file system has neither O_TMPFILE nor RENAME_NOREPLACE nor hard
/// links, as vboxsf and orangefs have none of them, assemble finds that out
/// when it makes the image and takes the image's name right away, as it
/// always did. A failure removes the image by that name again. The files
/// next to the image get their names by a plain rename, which replaces.
#[test]
fn assemble_where_only_a_plain_rename_works() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    let image = root.join("a.img");
    let manifest = root.join("a.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", tree.to_str().unwrap()])).unwrap();
    let written = root.join("written.manifest");
    fs::write(&written, b"old\n").unwrap();
    let assemble = || {
        let mut command = refusing(&bin, &[Refused::TMPFILE, Refused::NOREPLACE, Refused::LINK]).unwrap();
        command.args(["assemble", "--create", "--size", "40M", "--write-manifest"]);
        command.args([&written, &image]);
        command
    };
    let out = assemble()
        .arg("--manifest")
        .arg(&manifest)
        .arg(&empty)
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    assert!(stderr.contains("failed to open EFI/Linux/linux.efi"), "{}", stderr);
    assert!(!image.exists(), "a failed assemble left its image behind");
    assert_eq!(fs::read(&written).unwrap(), b"old\n");
    assert_eq!(temporary_names(root), Vec::<String>::new());
    let out = assemble().arg(&tree).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let a = image.to_str().unwrap();
    assert!(ok(&bin, &["check", a]).ends_with("; 0 errors, 0 warnings\n"));
    assert_eq!(
        fs::read_to_string(&written).unwrap(),
        ok(&bin, &["describe", "--write-manifest", "-", a])
    );
    assert_eq!(temporary_names(root), Vec::<String>::new());
}

/// A file that takes the temporary name of the image while assemble makes
/// it is left where it is. Before the image gets its name, by a rename of
/// the temporary name with RENAME_NOREPLACE or, where the flag is refused,
/// by a link of its descriptor, assemble checks that the temporary name
/// still refers to the image. It fails then, and says that the other file
/// is left alone.
#[test]
fn a_temporary_name_taken_meanwhile_is_left_alone() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let text = ok(&bin, &["manifest", tree.to_str().unwrap()]);
    let image = root.join("a.img");
    let theirs = root.join("theirs");
    for refusals in [&[Refused::TMPFILE][..], &[Refused::TMPFILE, Refused::NOREPLACE]] {
        let mut command = refusing(&bin, refusals).unwrap();
        command
            .args(["assemble", "--create", "--size", "40M", "--manifest", "-"])
            .args([&image, &tree]);
        let mut taken = PathBuf::new();
        let out = assemble_meanwhile(command, root, &text, |made| {
            fs::write(&theirs, b"theirs").unwrap();
            fs::rename(&theirs, made).unwrap();
            taken = made.to_path_buf();
        });
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{:?}: {}", refusals, stderr);
        let failed = format!(
            "failed to create {}: {} refers to another file now",
            image.display(),
            taken.display()
        );
        assert!(stderr.contains(&failed), "{:?}: {}", refusals, stderr);
        let left_alone = format!("{} refers to another file now, which is left alone", taken.display());
        assert!(stderr.contains(&left_alone), "{:?}: {}", refusals, stderr);
        assert!(!image.exists(), "{:?}: {}", refusals, stderr);
        assert_eq!(fs::read(&taken).unwrap(), b"theirs");
        fs::remove_file(&taken).unwrap();
        assert_eq!(temporary_names(root), Vec::<String>::new());
    }
}

/// Where the lock of a new image is refused, another process holds the
/// file: assemble fails and leaves it its name, which it says. Where the
/// lock cannot be had at all, as NFS without its lock manager refuses it
/// with ENOLCK, assemble fails with that and leaves nothing.
#[test]
fn a_new_image_locked_by_another_process_keeps_its_name() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let image = root.join("a.img");
    let assemble = |refusals: &[Refused]| {
        let mut command = refusing(&bin, refusals).unwrap();
        command
            .args(["assemble", "--create", "--size", "40M"])
            .args([&image, &root.join("tree")]);
        command.output().unwrap()
    };
    let out = assemble(&[Refused::TMPFILE, Refused::FLOCK]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    assert!(!image.exists());
    let left = temporary_names(root);
    assert_eq!(left.len(), 1, "{:?}", left);
    let used = format!("{} is being used by another process", root.join(&left[0]).display());
    assert!(stderr.contains(&used), "{}", stderr);
    fs::remove_file(root.join(&left[0])).unwrap();
    for refusals in [&[Refused::TMPFILE, Refused::NO_LOCKS][..], &[Refused::NO_LOCKS]] {
        let out = assemble(refusals);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{:?}: {}", refusals, stderr);
        let failed = format!("failed to create {}: failed to lock ", image.display());
        assert!(stderr.contains(&failed), "{:?}: {}", refusals, stderr);
        let unlocked = std::io::Error::from_raw_os_error(libc::ENOLCK).to_string();
        assert!(stderr.contains(&unlocked), "{:?}: {}", refusals, stderr);
        assert!(!image.exists());
        assert_eq!(temporary_names(root), Vec::<String>::new());
    }
}

/// Where the file system makes files without a name but refuses to link
/// them, assemble says so at its end, and nothing is left. A link that
/// fails for another reason says only that.
#[test]
fn a_file_system_that_cannot_name_the_image() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    if !makes_unnamed_files(root) {
        return eprintln!("skipping: no O_TMPFILE here");
    }
    let image = root.join("a.img");
    let refused = format!(
        "failed to create {}: the file system made the file but refuses to give it its name",
        image.display()
    );
    // In the words of the C library, which musl and glibc put differently.
    let failed = format!(
        "failed to create {}: {}",
        image.display(),
        std::io::Error::from_raw_os_error(libc::EIO)
    );
    for (refusal, says) in [(Refused::LINK, &refused), (Refused::LINK_FAILS, &failed)] {
        let mut command = refusing(&bin, &[refusal]).unwrap();
        command
            .args(["assemble", "--create", "--size", "40M"])
            .args([&image, &root.join("tree")]);
        let out = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}", stderr);
        assert!(stderr.contains(says.as_str()), "{}", stderr);
        assert!(!image.exists());
        assert_eq!(temporary_names(root), Vec::<String>::new());
    }
}

/// assemble makes an image in a directory it may search and write to but
/// not read, as one of mode 0300. The image and the manifest written next
/// to it get their names, and the directory, which cannot be opened to
/// sync it, is left as it is.
#[test]
fn assemble_in_a_directory_it_cannot_read() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let images = root.join("images");
    fs::create_dir(&images).unwrap();
    let (image, written) = (images.join("a.img"), images.join("a.manifest"));
    let (a, w) = (image.to_str().unwrap(), written.to_str().unwrap());
    let assemble = ["assemble", "--create", "--size", "40M", "--write-manifest", w, a];
    fs::set_permissions(&images, fs::Permissions::from_mode(0o300)).unwrap();
    let unreadable = fs::read_dir(&images).is_err();
    let out = run(&bin, &[&assemble[..], &[root.join("tree").to_str().unwrap()]].concat());
    fs::set_permissions(&images, fs::Permissions::from_mode(0o755)).unwrap();
    if !unreadable {
        eprintln!("the directory can be read here, so it was synced");
    }
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(ok(&bin, &["check", a]).ends_with("; 0 errors, 0 warnings\n"));
    assert_eq!(
        fs::read_to_string(&written).unwrap(),
        ok(&bin, &["describe", "--write-manifest", "-", a])
    );
}

/// A file written next to the image that cannot get its name, where the
/// name exists and the rename onto it fails, takes its temporary name with
/// it, also with O_TMPFILE. The image keeps its name.
#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
#[test]
fn an_output_that_cannot_replace_leaves_no_temporary_name() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    if !makes_unnamed_files(root) {
        return eprintln!("skipping: no O_TMPFILE here");
    }
    let image = root.join("a.img");
    let written = root.join("written.manifest");
    fs::write(&written, b"old\n").unwrap();
    let mut command = refusing(&bin, &[Refused::RENAME]).unwrap();
    command
        .args(["assemble", "--create", "--size", "40M", "--write-manifest"])
        .args([&written, &image, &root.join("tree")]);
    let out = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    assert!(
        stderr.contains(&format!("cannot write {}", written.display())),
        "{}",
        stderr
    );
    assert_eq!(fs::read(&written).unwrap(), b"old\n");
    assert!(ok(&bin, &["check", image.to_str().unwrap()]).ends_with("; 0 errors, 0 warnings\n"));
    assert_eq!(temporary_names(root), Vec::<String>::new());
}

/// Where O_TMPFILE is refused and the temporary name of an image assemble
/// gives up cannot be removed, a line of its own names the image that
/// stays. Where another file took the temporary name meanwhile, that file
/// stays, and a line says so.
#[test]
fn what_stays_of_a_given_up_image_is_reported() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    if refusing(&bin, &[]).is_none() {
        return eprintln!("skipping: no seccomp filters here");
    }
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree = root.join("tree");
    let text = ok(&bin, &["manifest", tree.to_str().unwrap()]);
    let empty = root.join("empty");
    fs::create_dir(&empty).unwrap();
    let image = root.join("a.img");
    let assemble = || {
        let mut command = refusing(&bin, &[Refused::TMPFILE]).unwrap();
        command
            .args(["assemble", "--create", "--size", "40M", "--manifest", "-"])
            .args([&image, &empty]);
        command
    };
    let chmod = |mode| fs::set_permissions(root, fs::Permissions::from_mode(mode)).unwrap();
    // SAFETY: geteuid() reads the effective user id and nothing else.
    if unsafe { libc::geteuid() } != 0 {
        let out = assemble_meanwhile(assemble(), root, &text, |_| chmod(0o555));
        chmod(0o755);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{}", stderr);
        let stays = format!(
            "ufat: the unfinished {} stays: failed to remove {}",
            image.display(),
            root.join(".#a.img").display()
        );
        // What failed comes first, then what that left behind.
        let failed = stderr.find("failed to open EFI/Linux/linux.efi");
        assert!(
            failed.is_some_and(|failed| stderr.find(&stays).is_some_and(|stays| failed < stays)),
            "{}",
            stderr
        );
        let left = temporary_names(root);
        assert_eq!(left.len(), 1, "{:?}", left);
        fs::remove_file(root.join(&left[0])).unwrap();
    }
    let theirs = root.join("theirs");
    let mut taken = PathBuf::new();
    let out = assemble_meanwhile(assemble(), root, &text, |made| {
        fs::write(&theirs, b"theirs").unwrap();
        fs::rename(&theirs, made).unwrap();
        taken = made.to_path_buf();
    });
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    let left_alone = format!("{} refers to another file now, which is left alone", taken.display());
    assert!(stderr.contains(&left_alone), "{}", stderr);
    assert_eq!(fs::read(&taken).unwrap(), b"theirs");
    assert!(!image.exists(), "a failed assemble left its image behind");
}

/// Paths on the host are taken as the bytes they are, UTF-8 or not. Paths
/// inside the volume are Unicode, and one that is not UTF-8 is refused.
#[test]
fn host_paths_need_not_be_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let tree_dir = dir.path().join(OsStr::from_bytes(b"tree-\xfe"));
    tree(&tree_dir);
    let image = dir.path().join(OsStr::from_bytes(b"esp-\xff.img"));
    let manifest = dir.path().join(OsStr::from_bytes(b"m-\xfd.json"));
    let ufat = |args: &[&OsStr]| {
        Command::new(&bin)
            .args(args)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .expect("ufat runs")
    };
    let out = ufat(&[
        "assemble".as_ref(),
        "--create".as_ref(),
        "--minimize".as_ref(),
        image.as_ref(),
        tree_dir.as_ref(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = ufat(&["cat".as_ref(), image.as_ref(), "/EFI/Linux/linux.efi".as_ref()]);
    assert_eq!(out.stdout, b"kernel");
    let out = ufat(&["manifest".as_ref(), tree_dir.as_ref()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    fs::write(&manifest, &out.stdout).unwrap();
    let mut with_manifest = OsString::from("--manifest=");
    with_manifest.push(&manifest);
    let out = ufat(&["assemble".as_ref(), "--plan".as_ref(), &with_manifest]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = ufat(&["list".as_ref(), image.as_ref(), OsStr::from_bytes(b"/EFI/\xff")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not valid UTF-8"));
    let out = ufat(&["assemble".as_ref(), OsStr::from_bytes(b"--label=\xff"), image.as_ref()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not valid UTF-8"));
}

/// populate puts a tree below --path, one file at --path, and makes the
/// directory --path when there is no SOURCE; remove takes files, empty
/// directories and with --recursive whole trees, never the root. What FAT
/// cannot store is left out, or with --unsupported fail refused before
/// anything is written.
#[test]
fn populate_and_remove_work_on_paths() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let img = root.join("a.img");
    let a = img.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", a]);
    // One file, at the path it is given, with its parents on request.
    let file = root.join("bootx64.efi");
    fs::write(&file, b"loader").unwrap();
    let f = file.to_str().unwrap();
    fails(
        &bin,
        &["populate", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
        "does not exist",
    );
    ok(
        &bin,
        &["populate", "--parents", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
    );
    assert_eq!(ok(&bin, &["cat", a, "/EFI/BOOT/BOOTX64.EFI"]), "loader");
    fails(&bin, &["populate", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f], "exists");
    ok(
        &bin,
        &["populate", "--replace", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
    );
    // No SOURCE: the directory --path, which may exist only with --parents.
    ok(&bin, &["populate", "--path", "/loader", a]);
    fails(&bin, &["populate", "--path", "/loader", a], "exists");
    ok(&bin, &["populate", "--parents", "--path", "/loader/entries", a]);
    ok(&bin, &["populate", "--parents", "--path", "/loader", a]);
    fails(&bin, &["populate", a], "--path for the directory to create");
    // A tree goes below --path, which is made when missing.
    ok(&bin, &["populate", "--path", "/copy", a, t]);
    assert_eq!(ok(&bin, &["list", a, "/copy/EFI/Linux"]), "linux.efi\n");
    // remove: a file, an empty directory, a tree only with --recursive.
    // --verbose says what each PATH took with it, the directory itself
    // counted.
    let out = run(
        &bin,
        &["remove", "--verbose", a, "/EFI/BOOT/BOOTX64.EFI", "/loader/entries"],
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "/EFI/BOOT/BOOTX64.EFI: 1 file, 0 directories\n/loader/entries: 0 files, 1 directory\n"
    );
    assert_eq!(ok(&bin, &["list", a, "/loader"]), "");
    fails(&bin, &["remove", a, "/copy"], "not empty");
    let out = run(&bin, &["remove", "-r", "--verbose", a, "/copy"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stderr), "/copy: 2 files, 5 directories\n");
    ok(&bin, &["remove", "--recursive", a, "/EFI"]);
    assert_eq!(ok(&bin, &["list", a, "/"]), "loader/\n");
    fails(&bin, &["remove", "--recursive", a, "/"], "root directory");
    assert!(run(&bin, &["check", a]).status.success());
    // A FIFO cannot go on FAT: left out by default, refused on request.
    sys_mkfifo(&root.join("tree/fifo"));
    let out = run(&bin, &["populate", "--path", "/fifo-skip", a, t]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("skipped"));
    fails(
        &bin,
        &["populate", "--unsupported", "fail", "--path", "/fifo-fail", a, t],
        "cannot be stored on FAT",
    );
    assert!(!ok(&bin, &["list", a, "/"]).contains("fifo-fail"));
    fails(&bin, &["populate", "--unsupported", "maybe", a, t], "skip or fail");
    // A plan refuses it too, from a tree or a manifest, and so does
    // --minimize before the image is touched.
    fails(
        &bin,
        &["assemble", "--plan", "--unsupported", "fail", t],
        "cannot be stored on FAT",
    );
    let manifest = root.join("fifo.manifest");
    fs::write(
        &manifest,
        concat!(
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
            "\x1e{\"name\":\"a\",\"size\":0}\n",
            "\x1e{\"name\":\"f\",\"type\":\"fifo\"}\n",
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
        ),
    )
    .unwrap();
    let m = manifest.to_str().unwrap();
    let fifo = "'/f' is a fifo, which FAT cannot store";
    fails(
        &bin,
        &["assemble", "--plan", "--unsupported", "fail", "--manifest", m],
        fifo,
    );
    let blank = root.join("blank.img");
    fs::File::create(&blank).unwrap().set_len(40 << 20).unwrap();
    fails(
        &bin,
        &[
            "assemble",
            "--minimize",
            "--unsupported",
            "fail",
            "--manifest",
            m,
            blank.to_str().unwrap(),
            t,
        ],
        fifo,
    );
    assert!(fs::read(&blank).unwrap().iter().all(|&b| b == 0));
}

/// Creates a FIFO without spawning mkfifo(1).
fn sys_mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL terminated path; mkfifo touches nothing else.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

/// assemble, populate and describe write the UAPI.16 manifest of what the
/// file system holds on request, one that builds the same content again.
#[test]
fn manifests_of_what_was_written() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    let written = root.join("written.manifest");
    let w = written.to_str().unwrap();
    ok(
        &bin,
        &["assemble", "--create", "--minimize", "--write-manifest", w, a, t],
    );
    let described = root.join("described.manifest");
    let d = described.to_str().unwrap();
    ok(&bin, &["describe", "--write-manifest", d, a]);
    assert_eq!(fs::read(&written).unwrap(), fs::read(&described).unwrap());
    let text = String::from_utf8_lossy(&fs::read(&written).unwrap()).into_owned();
    assert!(text.contains("\"EFI/Linux/linux.efi\""), "{}", text);
    // The manifest builds the same files from the tree.
    let b = root.join("b.img");
    let b = b.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--minimize", "--manifest", w, b, t]);
    assert_eq!(ok(&bin, &["cat", b, "/EFI/Linux/linux.efi"]), "kernel");
    let populated = root.join("populated.manifest");
    let p = populated.to_str().unwrap();
    ok(&bin, &["populate", "--path", "/more", "--write-manifest", p, b, t]);
    assert!(String::from_utf8_lossy(&fs::read(&populated).unwrap()).contains("\"more/EFI/Linux/linux.efi\""));

    // "-" is standard output. What the command prints there otherwise, the
    // description or the hash, goes to standard error then. Nothing named
    // "-" is created.
    let run_here = |args: &[&str]| {
        let out = Command::new(&bin)
            .args(args)
            .current_dir(root)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .expect("ufat runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "ufat {:?} failed: {}", args, stderr);
        (out.stdout, stderr)
    };
    let (stdout, stderr) = run_here(&["describe", "--write-manifest", "-", a]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    assert!(stderr.contains("volume id:"), "{}", stderr);
    let c = root.join("c.img");
    let c = c.to_str().unwrap();
    let (stdout, stderr) = run_here(&[
        "assemble",
        "--create",
        "--minimize",
        "--hash",
        "sha256",
        "--write-manifest",
        "-",
        c,
        t,
    ]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    // What --hash sha256 prints for an image sized to fit.
    let sha256_line = |image: &str| format!("{}\n", fat::manifest::Sha256::digest(&fs::read(image).unwrap()));
    assert_eq!(stderr, sha256_line(c));
    // --write-hash writes the hash to a file of its own, or for "-" to
    // standard output, which the manifest then cannot have as well.
    let e = root.join("e.img");
    let e = e.to_str().unwrap();
    let hash_file = root.join("e.sha256");
    let (stdout, stderr) = run_here(&[
        "assemble",
        "--create",
        "--minimize",
        "--hash",
        "sha256",
        "--write-hash",
        hash_file.to_str().unwrap(),
        "--write-manifest",
        "-",
        e,
        t,
    ]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    assert!(stderr.is_empty(), "{}", stderr);
    assert_eq!(fs::read_to_string(&hash_file).unwrap(), sha256_line(e));
    let f = root.join("f.img");
    let f = f.to_str().unwrap();
    let (stdout, _) = run_here(&[
        "assemble",
        "--create",
        "--minimize",
        "--hash",
        "sha256",
        "--write-hash",
        "-",
        f,
        t,
    ]);
    assert_eq!(String::from_utf8_lossy(&stdout), sha256_line(f));
    fails(
        &bin,
        &["assemble", "--create", "--write-hash", "-", c, t],
        "--write-hash needs --hash",
    );
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--hash",
            "sha256",
            "--write-hash",
            "-",
            "--write-manifest",
            "-",
            c,
            t,
        ],
        "cannot both write to standard output",
    );
    let (stdout, _) = run_here(&["populate", "--path", "/more", "--write-manifest", "-", c, t]);
    assert_eq!(stdout, fs::read(&populated).unwrap());
    assert!(!root.join("-").exists());
}

/// A count of one is said in the singular: in the summary of check, in
/// what --verbose reports and in the note about entries a manifest leaves
/// out.
#[test]
fn counts_of_one() {
    use std::os::unix::fs::FileExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    fs::create_dir_all(root.join("tree/d")).unwrap();
    fs::write(root.join("tree/d/f"), b"x").unwrap();
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    let out = run(
        &bin,
        &["assemble", "--create", "--minimize", "--verbose", "--fats", "1", a, t],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert!(
        stderr.contains(": 1 file and 1 directory in 1 byte need a "),
        "{}",
        stderr
    );
    assert!(
        stderr.contains(&format!("{}: 1 file, 1 directory, 1 byte\n", t)),
        "{}",
        stderr
    );
    assert!(stderr.contains(" reserved sectors, 1 FAT of "), "{}", stderr);
    // A plan says what it found, the clusters it needs and the sectors.
    let out = run(&bin, &["assemble", "--plan", "--verbose", t]);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "1 file, 1 directory, 1 byte: 3 clusters of 512 bytes, 512 byte sectors\n"
    );
    let out = run(&bin, &["assemble", "--plan", "--verbose", "--sector-size", "4096", t]);
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "1 file, 1 directory, 1 byte: 3 clusters of 4096 bytes, 4096 byte sectors\n"
    );

    // FAT entry 0 without the media byte in the first of two FATs is one
    // error, and the one byte the second FAT differs in is one warning.
    let b = root.join("b.img");
    ok(&bin, &["assemble", "--create", "--minimize", b.to_str().unwrap(), t]);
    let image = fs::OpenOptions::new().read(true).write(true).open(&b).unwrap();
    let mut sector = [0u8; 512];
    image.read_exact_at(&mut sector, 0).unwrap();
    let layout = fat::boot::BootSector::parse(&sector).unwrap().layout().unwrap();
    image.write_all_at(&[0xf0], layout.fat_offset(0)).unwrap();
    drop(image);
    let out = run(&bin, &["check", b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(FSCK_ERRORS_LEFT_UNCORRECTED));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let summary = stdout.lines().last().unwrap();
    assert!(
        summary.starts_with(&format!("{}: 1 file, 1 directory, 3 clusters used, ", b.display())),
        "{}",
        stdout
    );
    assert!(summary.ends_with(" free, 0 lost; 1 error, 1 warning"), "{}", stdout);

    // An empty volume uses the one cluster of its root directory. A name
    // with the noncharacter U+FDD0 fits FAT but no manifest.
    let e = root.join("e.img");
    let e = e.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", e]);
    let summary = ok(&bin, &["check", e]);
    assert!(
        summary.contains(": 0 files, 0 directories, 1 cluster used, "),
        "{}",
        summary
    );
    let device = fat::device::Device::open(Path::new(e), fat::device::Access::ReadWrite).unwrap();
    let mut v = fat::volume::Volume::open(device).unwrap();
    let odd = "a\u{fdd0}";
    v.create_dir(&format!("/{}", odd), std::time::SystemTime::now())
        .unwrap();
    v.close().unwrap();
    let m = root.join("e.manifest");
    let out = run(&bin, &["describe", "--write-manifest", m.to_str().unwrap(), e]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert!(
        stderr.contains(": its name cannot be written in a manifest"),
        "{}",
        stderr
    );
    assert!(stderr.starts_with("ufat: 1 entry is not in "), "{}", stderr);
}

/// A label that a file system made from the manifest would not get, which
/// only other tools write, is not in the manifest of a volume, and describe
/// names it, apart from the entries it leaves out.
#[test]
fn a_label_the_manifest_leaves_out_is_named() {
    use std::os::unix::fs::FileExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let root = Temp::dir();
    let img = root.path().join("l.img");
    let img = img.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", "--label", "ESP", img]);
    // The label entry of the root directory as another tool writes it: A+B,
    // which a file system made from the manifest would not get.
    let device = fat::device::Device::open(Path::new(img), fat::device::Access::ReadOnly).unwrap();
    let v = fat::volume::Volume::open(device).unwrap();
    let offset = v.layout().cluster_offset(v.boot_sector().root_cluster).unwrap();
    let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
    drop(v);
    let file = fs::OpenOptions::new().read(true).write(true).open(img).unwrap();
    file.read_exact_at(&mut cluster, offset).unwrap();
    let slot = cluster
        .chunks(fat::dirent::DIR_ENTRY_SIZE)
        .position(|e| e[fat::dirent::field::ATTR] == fat::dirent::ATTR_VOLUME_ID)
        .unwrap();
    let name = slot * fat::dirent::DIR_ENTRY_SIZE + fat::dirent::field::NAME.start;
    file.write_all_at(b"A+B        ", offset + name as u64).unwrap();
    let m = root.path().join("l.manifest");
    let out = run(&bin, &["describe", "--write-manifest", m.to_str().unwrap(), img]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert_eq!(
        stderr,
        format!(
            "ufat: the label 'A+B' is not in {}: a file system made from it would not get that label\n",
            m.display()
        )
    );
    let manifest = fs::read_to_string(&m).unwrap();
    assert!(!manifest.contains("fsLabel"), "{}", manifest);
}

/// `ufat manifest` prints the manifest while it walks the tree. It leaves
/// out what a manifest cannot name and says how many entries it left out.
/// What it printed of a tree it cannot walk to its end has no trailer.
#[test]
fn manifest_of_a_tree_as_far_as_it_goes() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let t = dir.path().join("tree");
    // A noncharacter, a control character and a name that is not UTF-8, a
    // directory with what is in it counting as one entry, and the name of
    // the manifest, which is no omission.
    fs::create_dir_all(t.join("d\u{fdd0}")).unwrap();
    fs::write(t.join("d\u{fdd0}/inside"), b"x").unwrap();
    fs::write(t.join("a.txt"), b"a").unwrap();
    fs::write(t.join("b\u{1}.txt"), b"b").unwrap();
    fs::write(t.join(OsStr::from_bytes(b"z\xff")), b"z").unwrap();
    fs::write(t.join("Uapi16Manifest"), b"old").unwrap();
    let records = |stdout: &[u8]| {
        let text = String::from_utf8(stdout.to_vec()).unwrap();
        text.split('\u{1e}').skip(1).map(str::to_string).collect::<Vec<_>>()
    };
    let out = run(&bin, &["manifest", t.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert_eq!(
        stderr,
        "ufat: 3 entries are not in the manifest on standard output: their names cannot be written in a manifest\n"
    );
    let printed = records(&out.stdout);
    assert_eq!(printed.len(), 3, "{:?}", printed);
    assert!(printed[1].contains(r#""name":"a.txt""#), "{:?}", printed);
    assert_eq!(printed[2], "{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n");

    // A file that cannot be opened stops the walk where it comes. Where its
    // mode keeps nobody out, as for root, there is nothing to try.
    let locked = t.join("c.txt");
    fs::write(&locked, b"c").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        return eprintln!("skipping the file that cannot be opened: it opens");
    }
    let out = run(&bin, &["manifest", t.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", stderr);
    assert!(stderr.contains("failed to open"), "{}", stderr);
    let printed = records(&out.stdout);
    assert_eq!(printed.len(), 2, "{:?}", printed);
    assert!(printed[1].contains(r#""name":"a.txt""#), "{:?}", printed);
}

/// assemble prints the hash of the file system it wrote on request, and
/// capabilities prints what GetCapabilities answers.
#[test]
fn hashes_and_capabilities() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    let hash = ok(&bin, &["assemble", "--create", "--minimize", "--hash", "sha256", a, t]);
    assert_eq!(
        hash,
        format!("{}\n", fat::manifest::Sha256::digest(&fs::read(a).unwrap()))
    );
    let hash = ok(&bin, &["assemble", "--force", "--hash", "sha512", a, t]);
    assert_eq!(hash.trim().len(), 128);
    // The hash is of the file system written, also where --size is only
    // the most --minimize may take, and when the image is larger.
    let size: usize = ok(&bin, &["assemble", "--plan", t]).trim().parse().unwrap();
    let b = root.join("b.img");
    let b = b.to_str().unwrap();
    let minimized = ["assemble", "--minimize", "--size", "50M", "--hash", "sha256"];
    let hash = ok(&bin, &[&minimized[..], &["--create", b, t]].concat());
    assert_eq!(
        hash,
        format!("{}\n", fat::manifest::Sha256::digest(&fs::read(b).unwrap()))
    );
    fs::File::options()
        .write(true)
        .open(b)
        .unwrap()
        .set_len(100 << 20)
        .unwrap();
    let hash = ok(&bin, &[&minimized[..], &["--force", b, t]].concat());
    assert_eq!(
        hash,
        format!("{}\n", fat::manifest::Sha256::digest(&fs::read(b).unwrap()[..size]))
    );
    fails(&bin, &["assemble", "--hash", "md5", a, t], "sha256 or sha512");
    let caps = ok(&bin, &["capabilities"]);
    assert!(
        caps.starts_with('{') && caps.contains("\"fileSystemType\":\"vfat\""),
        "{}",
        caps
    );
    fails(&bin, &["capabilities", a], "takes no arguments");
}
