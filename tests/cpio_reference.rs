// SPDX-License-Identifier: LGPL-2.1-or-later
//! What ucpio writes, read by the other tools: GNU cpio, bsdcpio and
//! busybox. Tests whose tool is missing are skipped with a note.
//!
//! The archives are the `made-*` fixtures, which tests/cpio_made.rs holds
//! against what ucpio writes, and the reference is what a kernel unpacked
//! them to, which is recorded next to them.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::fs::{self, File};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::{find_program, Temp};
use cpio::read::{Scanner, Standing};

/// The readers, each with what makes it unpack an archive into the
/// current directory, times included, and replace what is there.
const READERS: [(&str, &[&str]); 3] = [
    ("cpio", &["-idmu", "--quiet"]),
    ("bsdcpio", &["-idmu", "--quiet"]),
    ("busybox", &["cpio", "-idmu"]),
];

fn skip(tool: &str) {
    eprintln!("skipping: {} not found", tool);
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpio")
}

/// The fixtures ucpio wrote whose names start with `prefix`, by name.
fn fixtures_named(prefix: &str) -> BTreeMap<String, PathBuf> {
    let mut found = BTreeMap::new();
    for entry in fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_stem().unwrap().to_str().unwrap().to_string();
        if name.starts_with(prefix) && path.extension().is_some_and(|e| e == "cpio") {
            found.insert(name, path);
        }
    }
    found
}

/// The archives ucpio wrote, by name.
fn made() -> BTreeMap<String, PathBuf> {
    let mut made = fixtures_named("made-");
    made.retain(|name, _| !name.starts_with(STOPPED));
    assert!(made.len() >= 2, "only {} archives found", made.len());
    made
}

/// The archives that are what a crash or a failure leaves of one that was
/// being written: stopped at their first byte.
const STOPPED: &str = "made-assemble-cut";
/// Runs a reader on `archive` in `dir`. Returns what it wrote to its
/// standard output and error.
fn read_with(program: &Path, args: &[&str], archive: &Path, dir: &Path) -> (String, String) {
    let out = Command::new(program)
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::from(File::open(archive).unwrap()))
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", program.display(), e));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "{} {:?} failed on {}: {}",
        program.display(),
        args,
        archive.display(),
        stderr
    );
    (String::from_utf8_lossy(&out.stdout).into_owned(), stderr)
}

fn escaped(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b <= 0x20 || b >= 0x7f || b == b'\\' {
            write!(out, "\\x{:02x}", b).unwrap();
        } else {
            out.push(b as char);
        }
    }
    out
}

/// A directory in the lines of a fixture listing, without the owners: a
/// reader that is not root cannot set them.
fn list(root: &Path) -> Vec<String> {
    fn entry(path: &Path, name: &str, first: &mut HashMap<u64, String>, lines: &mut Vec<String>) -> bool {
        let md = fs::symlink_metadata(path).unwrap();
        let kind = md.mode() & 0o170000;
        let letter = match kind {
            0o040000 => 'd',
            0o100000 => 'f',
            0o120000 => 'l',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '?',
        };
        let mut line = format!("{} {}", name, letter);
        if letter != 'l' {
            write!(line, " mode={:04o}", md.mode() & 0o7777).unwrap();
        }
        write!(line, " mtime={}", md.mtime()).unwrap();
        if letter != 'd' {
            write!(line, " nlink={}", md.nlink()).unwrap();
            if md.nlink() > 1 {
                match first.get(&md.ino()) {
                    Some(first) => write!(line, " link={}", first).unwrap(),
                    None => {
                        first.insert(md.ino(), name.to_string());
                    }
                }
            }
        }
        if letter == 'f' {
            let data = fs::read(path).unwrap();
            let sum = data.iter().fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
            write!(line, " size={} sum={:08x}", data.len(), sum).unwrap();
        } else if letter == 'l' {
            write!(
                line,
                " target={}",
                escaped(fs::read_link(path).unwrap().as_os_str().as_bytes())
            )
            .unwrap();
        }
        lines.push(line);
        letter == 'd'
    }
    fn walk(path: &Path, name: &str, first: &mut HashMap<u64, String>, lines: &mut Vec<String>) {
        let mut names: Vec<Vec<u8>> = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().file_name().as_bytes().to_vec())
            .collect();
        names.sort();
        for child in names {
            let below = path.join(std::ffi::OsStr::from_bytes(&child));
            let full = if name.is_empty() {
                escaped(&child)
            } else {
                format!("{}/{}", name, escaped(&child))
            };
            if entry(&below, &full, first, lines) {
                walk(&below, &full, first, lines);
            }
        }
    }
    let mut first = HashMap::new();
    let mut lines = Vec::new();
    entry(root, ".", &mut first, &mut lines);
    walk(root, "", &mut first, &mut lines);
    lines
}

/// What of a line every reader gets right when it is not root: the names,
/// the permissions, times, links and contents of regular files, the
/// targets of symbolic links, the permissions of directories. Left out are
/// - the owners, which need root;
/// - the set-user-ID bit, which bsdcpio drops;
/// - the times of directories and symbolic links, which GNU cpio and
///   busybox do not set, and the mode of the directory unpacked into;
/// - what a socket becomes: bsdcpio makes a regular file of it.
fn common_ground(line: &str, nodes: &HashSet<String>) -> String {
    let mut words = line.split(' ');
    let name = words.next().unwrap();
    let kind = words.next().unwrap();
    let field = |key: &str| {
        line.split(' ')
            .find_map(|word| word.strip_prefix(key))
            .unwrap_or("")
            .to_string()
    };
    if nodes.contains(name) {
        return format!("{} node", name);
    }
    match kind {
        "f" => {
            let mode = u32::from_str_radix(&field("mode="), 8).unwrap() & 0o777;
            format!(
                "{} f mode={:03o} mtime={} nlink={} link={} size={} sum={}",
                name,
                mode,
                field("mtime="),
                field("nlink="),
                field("link="),
                field("size="),
                field("sum=")
            )
        }
        "l" => format!("{} l target={}", name, field("target=")),
        "d" if name == "." => ". d".to_string(),
        "d" => format!("{} d mode={}", name, field("mode=")),
        _ => format!("{} node", name),
    }
}

fn kernel_listing(archive: &Path) -> Vec<String> {
    let listing = fs::read_to_string(archive.with_extension("unpacked")).unwrap();
    assert!(
        !listing.lines().any(|line| line.starts_with("! ")),
        "{}",
        archive.display()
    );
    listing.lines().map(str::to_string).collect()
}

/// Every reader unpacks what the kernel unpacks.
#[test]
fn readers_unpack_what_the_kernel_unpacks() {
    let _serial = common::serial();
    for (reader, args) in READERS {
        let Some(program) = find_program(reader) else {
            skip(reader);
            continue;
        };
        for (name, archive) in made() {
            let kernel = kernel_listing(&archive);
            let nodes: HashSet<String> = kernel
                .iter()
                .filter(|line| matches!(line.split(' ').nth(1), Some("s" | "p" | "c" | "b")))
                .map(|line| line.split(' ').next().unwrap().to_string())
                .collect();
            let dir = Temp::dir();
            read_with(&program, args, &archive, dir.path());
            let unpacked: Vec<String> = list(dir.path())
                .iter()
                .map(|line| common_ground(line, &nodes))
                .collect();
            let expected: Vec<String> = kernel.iter().map(|line| common_ground(line, &nodes)).collect();
            assert_eq!(unpacked, expected, "{} on {}", reader, name);
        }
    }
}

/// The names of the entries of an archive as they are stored, in order.
fn stored_names(archive: &Path) -> Vec<String> {
    let bytes = fs::read(archive).unwrap();
    Scanner::new(&bytes[..])
        .map(|entry| entry.unwrap().unwrap())
        .filter(|record| record.standing != Standing::Trailer)
        .map(|record| String::from_utf8(record.name).unwrap())
        .collect()
}

/// GNU cpio and bsdcpio list every entry, in the order of the archive.
#[test]
fn readers_list_every_entry() {
    let _serial = common::serial();
    for reader in ["cpio", "bsdcpio"] {
        let Some(program) = find_program(reader) else {
            skip(reader);
            continue;
        };
        for (name, archive) in made() {
            let dir = Temp::dir();
            let (listed, _) = read_with(&program, &["-t", "--quiet"], &archive, dir.path());
            let listed: Vec<&str> = listed.lines().collect();
            assert_eq!(listed, stored_names(&archive), "{} on {}", reader, name);
        }
    }
}

/// GNU cpio verifies the checksums of the `070702` form.
#[test]
fn gnu_cpio_finds_the_checksums_right() {
    let _serial = common::serial();
    let Some(cpio) = find_program("cpio") else {
        return skip("cpio");
    };
    let name = "made-assemble-aligned";
    let dir = Temp::dir();
    let (_, stderr) = read_with(
        &cpio,
        &["-i", "--only-verify-crc", "--quiet"],
        &made()[name],
        dir.path(),
    );
    assert_eq!(stderr, "", "{}", name);
    // And it does look: the fixture with a wrong one.
    let dir = Temp::dir();
    let out = Command::new(&cpio)
        .args(["-i", "--only-verify-crc", "--quiet"])
        .current_dir(dir.path())
        .stdin(Stdio::from(File::open(fixtures().join("crc-wrong.cpio")).unwrap()))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("checksum error"));
}

/// An archive that was not finished is stopped at its first byte. The
/// kernel unpacks nothing of it. bsdcpio and busybox do not either, and
/// they fail. GNU cpio goes on to look for entries behind what it does
/// not know, so what it does depends on what is there. It never reads
/// such an archive without a complaint.
#[test]
fn readers_do_not_take_an_archive_that_was_not_finished() {
    let _serial = common::serial();
    let stopped = fixtures_named(STOPPED);
    assert_eq!(stopped.len(), 2);
    for (reader, list, unpack) in [
        ("cpio", &["-t", "--quiet"][..], &["-idmu", "--quiet"][..]),
        ("bsdcpio", &["-t", "--quiet"], &["-idmu", "--quiet"]),
        ("busybox", &["cpio", "-t"], &["cpio", "-idmu"]),
    ] {
        let Some(program) = find_program(reader) else {
            skip(reader);
            continue;
        };
        for (name, archive) in &stopped {
            for args in [list, unpack] {
                let dir = Temp::dir();
                let out = Command::new(&program)
                    .args(args)
                    .current_dir(dir.path())
                    .stdin(Stdio::from(File::open(archive).unwrap()))
                    .output()
                    .unwrap();
                assert!(
                    !out.stderr.is_empty(),
                    "{} {:?} read {} without a complaint",
                    reader,
                    args,
                    name
                );
                if reader == "cpio" {
                    continue;
                }
                assert!(
                    !out.status.success(),
                    "{} {:?} took {} for a whole archive",
                    reader,
                    args,
                    name
                );
                assert!(
                    out.stdout.is_empty(),
                    "{} {:?} listed entries of {}",
                    reader,
                    args,
                    name
                );
                assert_eq!(
                    fs::read_dir(dir.path()).unwrap().count(),
                    0,
                    "{} {:?} unpacked entries of {}",
                    reader,
                    args,
                    name
                );
            }
        }
    }
}
