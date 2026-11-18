// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line: assemble makes a file system and fills it, populate
//! fills an existing one, both take a directory tree, or with --manifest the
//! tree a UAPI.16 manifest describes. The commands are the methods of the
//! Varlink interface.

mod common;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
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
    ok(&bin, &["assemble", "--create", a, t]);
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
    ok(&bin, &["assemble", empty.to_str().unwrap(), t]);
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
    // one SOURCE says where the files are. assemble reads it twice.
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", tree_arg])).unwrap();
    let m = manifest.to_str().unwrap();
    let b = image("b.img");
    let b = b.as_str();
    ok(&bin, &["assemble", "--create", "--manifest", m, b, tree_arg]);
    assert_eq!(ok(&bin, &["list", b, "/loader/entries"]), "x.conf\n");
    assert_eq!(ok(&bin, &["cat", b, "/EFI/Linux/linux.efi"]), "kernel");
    assert_eq!(fs::metadata(b).unwrap().len().to_string() + "\n", tree_size);
    // The planner sees the same size from the manifest, which needs no
    // SOURCE to be sized.
    assert_eq!(tree_size, ok(&bin, &["assemble", "--plan", "--manifest", m]));
    // populate fills an existing volume, from a manifest too, replacing.
    ok(&bin, &["populate", "--manifest", m, a, tree_arg]);
    ok(&bin, &["populate", "--path", "/second", a, tree_arg]);
    assert_eq!(ok(&bin, &["list", a, "/second/EFI/Linux"]), "linux.efi\n");
    assert!(run(&bin, &["check", a]).status.success());
    // "-" takes the file contents from standard input, back to back in
    // manifest order: linux.efi sorts before x.conf.
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kerneltitle x\n");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(ok(&bin, &["cat", a, "/loader/entries/x.conf"]), "title x\n");
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kern");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ended"));
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kerneltitle x\nmore");
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
    // long, and a name the file system holds with --no-replace.
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
        (r#"{"name":"f","size":0}"#, &["--no-replace"], "-", "'/f' exists"),
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
    // assemble with a SOURCE plans the content before it writes it, so it
    // refuses one before it reads anything of it: all of it is left in the
    // pipe. assemble --plan and assemble without a SOURCE read the
    // manifest once and take one. assemble --plan takes standard input
    // that is the file itself as well.
    let manifest_bytes = fs::read(&manifest).unwrap();
    let not_a_file = "standard input is not a regular file: assemble with a SOURCE needs the manifest in one";
    let piped = image("piped.img");
    let piped = piped.as_str();
    for args in [
        &["assemble", "--create", "--manifest", "-", piped, tree_arg][..],
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
    ] {
        let (out, left) = run_from_pipe(&bin, args, &manifest_bytes);
        assert_eq!(out.status.code(), Some(1), "{:?}", args);
        assert!(String::from_utf8_lossy(&out.stderr).contains(not_a_file), "{:?}", args);
        assert_eq!(left, manifest_bytes, "{:?}", args);
        assert!(!Path::new(piped).exists());
    }
    let (out, left) = run_from_pipe(
        &bin,
        &["assemble", "--create", "--manifest", "-", piped],
        &manifest_bytes,
    );
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(left.is_empty(), "{} bytes left", left.len());
    assert_eq!(fs::metadata(piped).unwrap().len().to_string() + "\n", tree_size);
    assert!(run(&bin, &["check", piped]).status.success());
    let (out, left) = run_from_pipe(&bin, &["assemble", "--plan", "--manifest", "-"], &manifest_bytes);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), tree_size);
    assert!(left.is_empty(), "{} bytes left", left.len());
    let out = run_from(&bin, &["assemble", "--plan", "--manifest", "-"], &manifest);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), tree_size);
    let out = run_in(&bin, &["populate", "--manifest", "-", a, tree_arg], &manifest_bytes);
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
    // The files a manifest names are found below the SOURCE when they are
    // copied, and the messages about them name the SOURCE. A SOURCE that is
    // not there leaves nothing behind. A file that is missing, or changed
    // since the manifest was written, fails the copy, and the file system
    // holds what was complete before it, marked as not cleanly unmounted,
    // the way a crash would leave it. A file that grew still has the data
    // the manifest describes at its start, and that is what is copied.
    let d = image("d.img");
    let d = d.as_str();
    fails(&bin, &["assemble", "--create", "--manifest", m, d, nowhere], "nowhere");
    assert!(!Path::new(d).exists());
    let empty = root.join("empty");
    let empty = empty.to_str().unwrap();
    fs::create_dir(empty).unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--manifest", m, d, empty],
        &format!(
            "ufat: {}: EFI/Linux/linux.efi: failed to open EFI/Linux/linux.efi",
            empty
        ),
    );
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
    fails(&bin, &["assemble", "--plan", "--manifest", m], refused);
    fails(&bin, &["assemble", "--create", "--manifest", m, a], refused);
    assert!(!image.exists());
    ok(&bin, &["assemble", "--create", "--size", "40M", a]);
    fails(&bin, &["populate", "--manifest", m, a, t], refused);
    let out = run_in(&bin, &["populate", "--manifest", "-", a, t], undeclared.as_bytes());
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains(&format!("ufat: standard input: {}", refused)),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ok(&bin, &["list", a]), "");
    // With the declaration it is taken.
    fs::write(&manifest, &declared).unwrap();
    ok(&bin, &["populate", "--manifest", m, a, t]);
    assert_eq!(ok(&bin, &["list", a]), "EFI/\nloader/\n");
}

/// A volume too small for what goes into it. A copy that runs out of
/// clusters says which file did not fit and leaves what came before it in
/// a consistent file system. `assemble` with a `--size` the content does
/// not fit says so before it sizes or formats anything: a file `--create`
/// made is gone again and an existing file is as it was. Without a size an
/// existing file is grown to the fit and never shrunk.
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
        &["assemble", "--create", "--size", "1M", n, t],
        "holds 1048576 bytes but the content needs",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    let existing = root.join("existing.img");
    let e = existing.to_str().unwrap();
    fs::write(&existing, b"").unwrap();
    fails(
        &bin,
        &["assemble", "--size", "1M", e, t],
        "holds 1048576 bytes but the content needs",
    );
    assert_eq!(fs::metadata(&existing).unwrap().len(), 0);

    let size: u64 = ok(&bin, &["assemble", "--plan", t]).trim().parse().unwrap();
    // A plan against a size says whether the tree fits it.
    fails(&bin, &["assemble", "--plan", "--size", "1M", t], "more than --size");
    assert_eq!(
        ok(&bin, &["assemble", "--plan", "--size", "64M", t]),
        format!("{}\n", size)
    );
    fs::File::create(&existing).unwrap().set_len(4096).unwrap();
    ok(&bin, &["assemble", e, t]);
    assert_eq!(fs::metadata(&existing).unwrap().len(), size);
    assert_eq!(ok(&bin, &["cat", e, "/sub/c.txt"]), "last\n");
    let large = root.join("large.img");
    let l = large.to_str().unwrap();
    fs::File::create(&large).unwrap().set_len(64 << 20).unwrap();
    ok(&bin, &["assemble", l, t]);
    assert_eq!(fs::metadata(&large).unwrap().len(), 64 << 20);
    assert!(run(&bin, &["check", l]).status.success());
    assert_eq!(ok(&bin, &["cat", l, "/sub/c.txt"]), "last\n");
}

/// A plan does not compare names. The entries of a directory under two
/// names that FAT does not tell apart go into one directory. The plan holds
/// the entries under each name to the 65536 entries of a FAT directory on
/// their own, and only the write sees them all in one directory. In two
/// runs of 1600 names of 255 characters, which take 21 entries each, the
/// plan passes and `assemble` fails. In one run the plan fails.
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
        &["assemble", "--create", "--manifest", s, a, "-"],
        "directory is full",
    );
    let whole = root.join("whole.manifest");
    fs::write(&whole, manifest(&[("EFI", 0..3200)])).unwrap();
    fails(
        &bin,
        &["assemble", "--plan", "--manifest", whole.to_str().unwrap()],
        "'/EFI' needs more than the 65536 entry slots a FAT32 directory holds",
    );
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
    fails(
        &bin,
        &["populate", "--no-replace", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
        "exists",
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
    // assemble, which plans first, before the image is touched.
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
    ok(&bin, &["assemble", "--create", "--write-manifest", w, a, t]);
    let described = root.join("described.manifest");
    let d = described.to_str().unwrap();
    ok(&bin, &["describe", "--write-manifest", d, a]);
    assert_eq!(fs::read(&written).unwrap(), fs::read(&described).unwrap());
    let text = String::from_utf8_lossy(&fs::read(&written).unwrap()).into_owned();
    assert!(text.contains("\"EFI/Linux/linux.efi\""), "{}", text);
    // The manifest builds the same files from the tree.
    let b = root.join("b.img");
    let b = b.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--manifest", w, b, t]);
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
    let (stdout, _) = run_here(&["assemble", "--create", "--hash", "sha256", "--write-hash", "-", f, t]);
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
    let out = run(&bin, &["assemble", "--create", "--verbose", "--fats", "1", a, t]);
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
    ok(&bin, &["assemble", "--create", b.to_str().unwrap(), t]);
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
    let hash = ok(&bin, &["assemble", "--create", "--hash", "sha256", a, t]);
    assert_eq!(
        hash,
        format!("{}\n", fat::manifest::Sha256::digest(&fs::read(a).unwrap()))
    );
    let hash = ok(&bin, &["assemble", "--force", "--hash", "sha512", a, t]);
    assert_eq!(hash.trim().len(), 128);
    fails(&bin, &["assemble", "--hash", "md5", a, t], "sha256 or sha512");
    let caps = ok(&bin, &["capabilities"]);
    assert!(
        caps.starts_with('{') && caps.contains("\"fileSystemType\":\"vfat\""),
        "{}",
        caps
    );
    fails(&bin, &["capabilities", a], "takes no arguments");
}
