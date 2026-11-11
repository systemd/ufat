// SPDX-License-Identifier: LGPL-2.1-or-later
//! What ucpio says an archive unpacks to, against what a kernel unpacked.
//!
//! tests/fixtures/cpio holds archives and, for each of them, the listing
//! of the root file system a kernel made of it. Nothing here is written by
//! hand: make-fixtures.py there boots every archive and records the
//! result. So the rules of `cpio::tree` are held against the kernel
//! itself, not against a reading of its source.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use cpio::check::{self, ProblemKind};
use cpio::header::Kind;
use cpio::read::{Damage, End, Skip, Source};
use cpio::tree::{FindingKind, Replay, RootStated, Tree};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cpio")
}

/// The cases: every archive with the listing recorded for it.
fn cases() -> BTreeMap<String, (Vec<u8>, Vec<String>)> {
    let mut cases = BTreeMap::new();
    for entry in fs::read_dir(fixtures()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "cpio") {
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            let listing = fs::read_to_string(path.with_extension("unpacked"))
                .unwrap_or_else(|e| panic!("{}: no listing: {}", name, e));
            let lines = listing.lines().map(str::to_string).collect();
            cases.insert(name, (fs::read(&path).unwrap(), lines));
        }
    }
    assert!(cases.len() >= 40, "only {} fixtures found", cases.len());
    cases
}

/// A name or a target as init.c writes it.
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

/// The tree in the lines of a listing.
fn render(tree: &Tree, archive: &[u8]) -> Vec<String> {
    let mut first: HashMap<u32, String> = HashMap::new();
    let mut lines = Vec::new();
    for (name, inode) in tree.entries() {
        let shown = escaped(&name);
        let letter = match inode.kind {
            Kind::Directory => 'd',
            Kind::Regular => 'f',
            Kind::Symlink => 'l',
            Kind::CharDevice => 'c',
            Kind::BlockDevice => 'b',
            Kind::Fifo => 'p',
            Kind::Socket => 's',
        };
        let mut line = format!("{} {}", shown, letter);
        if name == b"." {
            // What the archive does not set is what the kernel gives the
            // root of the tmpfs it unpacks into.
            let stated = tree.root_stated();
            let mode = if stated.contains(RootStated::MODE) {
                inode.mode
            } else {
                0o1777
            };
            let (uid, gid) = if stated.contains(RootStated::OWNER) {
                (inode.uid, inode.gid)
            } else {
                (0, 0)
            };
            write!(line, " mode={:04o} uid={} gid={}", mode, uid, gid).unwrap();
            if stated.contains(RootStated::TIME) {
                write!(line, " mtime={}", inode.mtime).unwrap();
            } else {
                line.push_str(" mtime=boot");
            }
        } else {
            if inode.kind != Kind::Symlink {
                write!(line, " mode={:04o}", inode.mode).unwrap();
            }
            write!(line, " uid={} gid={} mtime={}", inode.uid, inode.gid, inode.mtime).unwrap();
        }
        if inode.kind != Kind::Directory {
            write!(line, " nlink={}", inode.nlink).unwrap();
            if inode.nlink > 1 {
                let id = tree.inode_id(&name).unwrap();
                match first.get(&id) {
                    Some(first) => write!(line, " link={}", first).unwrap(),
                    None => {
                        first.insert(id, shown.clone());
                    }
                }
            }
        }
        let data = &archive[inode.data_offset as usize..][..inode.size as usize];
        match inode.kind {
            Kind::Regular => {
                let sum = data.iter().fold(0u32, |sum, &b| sum.wrapping_add(u32::from(b)));
                write!(line, " size={} sum={:08x}", inode.size, sum).unwrap();
                if !data.is_empty() {
                    line.push_str(" head=");
                    for b in &data[..data.len().min(16)] {
                        write!(line, "{:02x}", b).unwrap();
                    }
                }
            }
            Kind::Symlink => write!(line, " target={}", escaped(data)).unwrap(),
            Kind::CharDevice | Kind::BlockDevice => write!(line, " rdev={}", inode.rdev).unwrap(),
            _ => {}
        }
        lines.push(line);
    }
    lines
}

/// How far the tree goes with the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fit {
    /// The tree is what the kernel unpacked.
    Whole,
    /// Everything in the tree is what the kernel unpacked, and the kernel
    /// unpacked more: the tree stops where this crate stops reading, or
    /// leaves out what it does not follow.
    Part,
    /// The kernel stopped at a checksum that does not hold. The tree does
    /// not read contents: it is what the kernel unpacked when it is made
    /// of the archive up to the end of that entry.
    Checksum,
}

/// What is expected of a case beyond the listing.
struct Expected {
    fit: Fit,
    /// The damage the reader finds, by its name.
    damage: Option<&'static str>,
    /// Whether something that is no padding follows the trailer.
    followed: bool,
    /// Whether the tree says it does not follow everything.
    approximate: bool,
    /// Names the tree has otherwise than the kernel, changed by what the
    /// tree does not follow.
    differ: &'static [&'static str],
}

const WHOLE: Expected = Expected {
    fit: Fit::Whole,
    damage: None,
    followed: false,
    approximate: false,
    differ: &[],
};

fn expected(case: &str) -> Expected {
    let followed = Expected {
        fit: Fit::Part,
        followed: true,
        ..WHOLE
    };
    let approximate = Expected {
        fit: Fit::Part,
        approximate: true,
        ..WHOLE
    };
    let damaged = |damage| Expected {
        damage: Some(damage),
        ..WHOLE
    };
    match case {
        // A trailer in the middle: the kernel reads on behind it.
        "trailer-plain"
        | "trailer-file"
        | "trailer-file-data"
        | "trailer-directory"
        | "trailer-node"
        | "trailer-padded-name" => followed,
        // The archive behind the trailer has a file of the first one again.
        "end-second-archive" => Expected {
            differ: &["e/over"],
            ..followed
        },
        // A compressed archive behind the trailer is unpacked too.
        "end-follower-compressed" => followed,
        // What follows the trailer is nothing the kernel takes: no
        // archive, one in the old format, one that starts off a multiple
        // of four, or the mere start of an entry. Nothing of it is
        // unpacked.
        "end-junk"
        | "end-junk-padded"
        | "end-follower-old"
        | "end-follower-misaligned"
        | "end-follower-short"
        | "end-follower-zero"
        | "end-follower-compressed-misaligned" => Expected {
            fit: Fit::Whole,
            ..followed
        },
        // An entry for 'n/sub/..' sets the mode of 'n'.
        "names-dotdot" => Expected {
            differ: &["n"],
            ..approximate
        },
        "names-symlink" => approximate,
        // An entry without a type for a symbolic link with a slash at its
        // end: the lookup goes through the link, and nothing comes of it.
        "names-directory" => Expected {
            fit: Fit::Whole,
            ..approximate
        },
        // The kernel has /dev and /root before it unpacks anything.
        "builtin" => Expected {
            fit: Fit::Part,
            ..WHOLE
        },
        "crc-wrong" | "crc-wrong-link" => Expected {
            fit: Fit::Checksum,
            ..WHOLE
        },
        "end-gap-misaligned" => damaged("Misaligned"),
        "end-magic-old" | "end-magic-none" | "end-stopper" => damaged("Magic"),
        "end-field" => damaged("Field"),
        "end-unterminated" | "end-unterminated-symlink" => damaged("Unterminated"),
        "end-cut-header" | "end-cut-name" => damaged("Truncated"),
        // The kernel leaves a file of the full size behind, zeros where
        // the archive ends.
        "end-cut-data" => Expected {
            fit: Fit::Part,
            ..damaged("Truncated")
        },
        _ => WHOLE,
    }
}

fn damage_name(damage: &Damage) -> &'static str {
    match damage {
        Damage::Magic { .. } => "Magic",
        Damage::Field { .. } => "Field",
        Damage::Unterminated { .. } => "Unterminated",
        Damage::Misaligned { .. } => "Misaligned",
        Damage::Truncated { .. } => "Truncated",
    }
}

/// What the kernel logs for a kind of damage.
fn kernel_says(damage: &str) -> &'static [&'static str] {
    match damage {
        "Magic" => &[
            "no cpio magic",
            "incorrect cpio method used: use -H newc option",
            "invalid magic at start of compressed archive",
        ],
        "Field" => &["damaged header"],
        "Unterminated" => &["malformed archive"],
        "Misaligned" => &["broken padding"],
        _ => &[],
    }
}

/// Where the first entry with a wrong checksum ends.
fn end_of_wrong_checksum(archive: &[u8]) -> Option<u64> {
    let report = check::check(archive).unwrap();
    let wrong = report
        .problems
        .iter()
        .find(|p| p.kind == ProblemKind::Checksum)?
        .offset?;
    Replay::new(archive)
        .map(|entry| entry.unwrap().record)
        .find(|record| record.offset == wrong)
        .map(|record| record.end())
}

#[test]
fn the_tree_is_what_the_kernel_unpacks() {
    let mut failures = Vec::new();
    for (case, (archive, listing)) in cases() {
        let expected = expected(&case);
        let (messages, unpacked): (Vec<&String>, Vec<&String>) =
            listing.iter().partition(|line| line.starts_with("! "));
        let mut fail = |what: String| failures.push(format!("{}: {}", case, what));
        let read = match expected.fit {
            Fit::Checksum => match end_of_wrong_checksum(&archive) {
                Some(end) => &archive[..end as usize],
                None => {
                    fail("the check finds no wrong checksum".into());
                    continue;
                }
            },
            _ => &archive[..],
        };
        let (tree, damage) = match Tree::replay(read, &mut |_| {}) {
            Ok(result) => result,
            Err(e) => {
                fail(format!("the archive is not read: {}", e));
                continue;
            }
        };
        let lines = render(&tree, &archive);
        match expected.fit {
            Fit::Whole | Fit::Checksum => {
                if lines.iter().ne(unpacked.iter().copied()) {
                    let mut diff = String::from("the tree is not what the kernel unpacked");
                    for line in &lines {
                        if !unpacked.contains(&line) {
                            write!(diff, "\n    only the tree:   {}", line).unwrap();
                        }
                    }
                    for line in &unpacked {
                        if !lines.contains(line) {
                            write!(diff, "\n    only the kernel: {}", line).unwrap();
                        }
                    }
                    fail(diff);
                }
            }
            Fit::Part => {
                for line in &lines {
                    let name = line.split(' ').next().unwrap();
                    if !unpacked.contains(&line) && !expected.differ.contains(&name) {
                        fail(format!("the kernel did not unpack: {}", line));
                    }
                }
                if lines.len() >= unpacked.len() && expected.differ.is_empty() {
                    fail("the kernel was expected to unpack more than the tree has".into());
                }
            }
        }
        for name in expected.differ {
            if !lines.iter().any(|line| line.split(' ').next() == Some(name)) {
                fail(format!("'{}' is not in the tree", name));
            }
        }
        let found = damage.as_ref().map(damage_name);
        if found != expected.damage {
            fail(format!("damage {:?}, expected {:?}", found, expected.damage));
        }
        // The kernel reports what the reader calls damage, but not an
        // archive that is cut short.
        if let Some(damage) = expected.damage {
            let failed: Vec<&str> = messages
                .iter()
                .filter_map(|line| line.strip_prefix("! Initramfs unpacking failed: "))
                .collect();
            let says = kernel_says(damage);
            let agrees = match failed[..] {
                [] => says.is_empty(),
                [said] => says.contains(&said),
                _ => false,
            };
            if !agrees {
                fail(format!("the kernel said {:?}, expected one of {:?}", failed, says));
            }
        }
        if tree.approximate() != expected.approximate {
            fail(format!("approximate is {}", tree.approximate()));
        }
        let follows = match tree.end() {
            End::Trailer(end) => read.first_nonzero(end).unwrap().is_some(),
            End::NoTrailer => false,
        };
        if follows != expected.followed {
            fail(format!("something follows the trailer: {}", follows));
        }
    }
    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

/// The kernel says that it failed to unpack an archive exactly when a
/// check finds one of the things it stops at.
#[test]
fn a_check_reports_what_the_kernel_reports() {
    let stops = [
        ProblemKind::NoMagic,
        ProblemKind::HeaderField,
        ProblemKind::UnterminatedName,
        ProblemKind::MisalignedEntry,
        ProblemKind::Checksum,
        ProblemKind::JunkAfterTrailer,
    ];
    let mut failures = Vec::new();
    for (case, (archive, listing)) in cases() {
        let kernel_failed = listing
            .iter()
            .any(|line| line.starts_with("! Initramfs unpacking failed: "));
        let report = check::check(&archive[..]).unwrap();
        let found: Vec<ProblemKind> = report
            .problems
            .iter()
            .map(|p| p.kind)
            .filter(|kind| stops.contains(kind))
            .collect();
        if kernel_failed == found.is_empty() {
            failures.push(format!(
                "{}: the kernel {} and the check found {:?}",
                case,
                if kernel_failed { "failed" } else { "did not fail" },
                found
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}\n", failures.join("\n"));
}

/// The checksums of the `070702` form are the kernel's to verify, and it
/// stops at the first that is wrong.
#[test]
fn a_wrong_checksum_is_found() {
    let cases = cases();
    for case in ["crc-wrong", "crc-wrong-link"] {
        let (archive, listing) = &cases[case];
        assert!(listing.contains(&"! Initramfs unpacking failed: bad data checksum".to_string()));
        let report = check::check(&archive[..]).unwrap();
        assert!(
            report.problems.iter().any(|p| p.kind == ProblemKind::Checksum),
            "{}: {:?}",
            case,
            report.problems
        );
    }
    let (archive, listing) = &cases["crc"];
    assert!(!listing.iter().any(|line| line.starts_with("! ")));
    let report = check::check(&archive[..]).unwrap();
    assert!(!report.problems.iter().any(|p| p.kind == ProblemKind::Checksum));
}

/// What the tree leaves out it says so: every entry of a case that the
/// kernel lost has a finding.
#[test]
fn findings_name_what_the_kernel_drops() {
    let cases = cases();
    let findings = |case: &str| {
        let mut found = Vec::new();
        Tree::replay(&cases[case].0[..], &mut |finding| {
            found.push((finding.kind, finding.name))
        })
        .unwrap();
        found
    };
    let has = |found: &[(FindingKind, Vec<u8>)], kind: FindingKind, name: &[u8]| {
        found.iter().any(|(k, n)| *k == kind && n == name)
    };
    let names = findings("names");
    assert!(has(&names, FindingKind::MissingParent, b"n/missing/child"));
    assert!(has(&names, FindingKind::ParentNotDirectory, b"n/notdir/child"));
    assert!(has(&names, FindingKind::TrailingSlash, b"n/file-slash/"));
    assert!(has(&names, FindingKind::UnusableName, b""));
    let links = findings("links");
    assert!(has(&links, FindingKind::BrokenLink, b"l/gone-2"));
    assert!(has(&links, FindingKind::BrokenLink, b"l/turned-2"));
    assert!(has(&links, FindingKind::BrokenLink, b"l/found"));
    let replace = findings("replace");
    assert!(has(&replace, FindingKind::DirectoryInTheWay, b"r/full-file"));
    assert!(has(&replace, FindingKind::Replaced, b"r/file-file"));
    let lost = findings("links-lost-first");
    for name in [
        &b"l/second"[..],
        b"l/third",
        b"l/after-long",
        b"l/after-slash",
        b"l/after-full",
        b"l/after-chr",
    ] {
        assert!(has(&lost, FindingKind::BrokenLink, name), "{:?}", name);
    }
    let directory = findings("names-directory");
    assert!(has(&directory, FindingKind::TrailingSlash, b"d/slash-empty-file/"));
    assert!(has(&directory, FindingKind::TrailingSlash, b"d/dot-empty-file/."));
    assert!(has(&directory, FindingKind::MissingParent, b"d/dot-missing/."));
    assert!(has(&directory, FindingKind::ParentNotDirectory, b"d/dot-file-dir/."));
    assert!(has(&directory, FindingKind::ParentIsSymlink, b"d/slash-sym-typeless/"));
    let targets = findings("symlink-targets");
    assert!(has(&targets, FindingKind::LongTarget, b"s/long-over-file"));
    assert!(has(&targets, FindingKind::Skipped(Skip::TargetSize), b"s/nul-4097"));
    let numbers = findings("device-numbers");
    assert!(has(&numbers, FindingKind::DeviceNumber, b"d/major-4096"));
    assert!(has(&numbers, FindingKind::DeviceNumber, b"d/minor-2-20"));
    assert!(!has(&numbers, FindingKind::DeviceNumber, b"d/file-rdev"));
    assert!(!has(&findings("types"), FindingKind::DeviceNumber, b"d/bigdev"));
}
