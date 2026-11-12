// SPDX-License-Identifier: LGPL-2.1-or-later
//! Manifests written by systemd's own tool, fed through the reader, the
//! planner, the assembler, the generator and the volume's manifest writer.
//! See tests/fixtures/README.md for where they come from.

mod common;

use std::io::Read;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::Temp;
use ufat::device::{Access, Device};
use ufat::dirent::ATTR_READ_ONLY;
use ufat::errno::{EINVAL, EOPNOTSUPP};
use ufat::format::{self, FormatOptions};
use ufat::host;
use ufat::manifest::volume::Fields;
use ufat::manifest::{self, AssembleOptions, DirectorySource, InodeType, Manifest, StreamSource};
use ufat::plan::{Plan, PlanOptions};
use ufat::volume::Volume;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn load(case: &str, name: &str) -> Manifest {
    let path = fixtures().join(case).join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
    manifest::parse(&bytes).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))
}

fn tree(case: &str) -> PathBuf {
    fixtures().join(case).join("tree")
}

/// The fixture's tree as a content source: the directory resolved once.
fn source(case: &str) -> DirectorySource {
    DirectorySource::new(host::open_dir(&tree(case)).unwrap())
}

fn time(nsec: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(nsec)
}

fn names(m: &Manifest) -> Vec<&str> {
    m.entries.iter().filter_map(|e| e.name.as_deref()).collect()
}

/// Formats an image of exactly the planned size and returns it open.
fn planned_volume(m: &Manifest) -> (Temp, Volume, Vec<String>) {
    let mut plan = Plan::new(PlanOptions {
        allow_small: true,
        ..PlanOptions::new(512)
    });
    let skipped = plan.add_manifest(m).unwrap();
    let estimate = plan.estimate().unwrap();
    let img = Temp::image(estimate.size());
    let mut options = FormatOptions {
        allow_small: true,
        ..FormatOptions::default()
    };
    estimate.apply(&mut options);
    format::format(&Device::open(img.path(), Access::ReadWrite).unwrap(), &options).unwrap();
    let v = Volume::open(Device::open(img.path(), Access::ReadWrite).unwrap()).unwrap();
    (img, v, skipped)
}

fn read_back(v: &Volume, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    v.open_file(path).unwrap().read_to_end(&mut out).unwrap();
    out
}

/// Every regular file of the manifest is in the volume with the tree's
/// contents and the manifest's time; every directory object is there too.
fn check_against_tree(m: &Manifest, v: &Volume, tree: &Path) {
    for e in &m.entries {
        let name = e.name.as_deref().unwrap();
        let path = e.path();
        match e.inode_type {
            InodeType::Regular => {
                let md = v.metadata(&path).unwrap_or_else(|err| panic!("{}: {}", path, err));
                assert!(!md.is_dir, "{}", path);
                let expected = std::fs::read(tree.join(name)).unwrap();
                assert_eq!(read_back(v, &path), expected, "{}", path);
                if let Some(size) = e.size {
                    assert_eq!(md.size, size, "{}", path);
                }
                if let Some(t) = e.mtime_nsec {
                    assert_eq!(md.modified, time(t), "{}", path);
                }
                assert_eq!(md.attributes & ATTR_READ_ONLY != 0, e.is_read_only(), "{}", path);
            }
            InodeType::Directory => {
                let md = v.metadata(&path).unwrap_or_else(|err| panic!("{}: {}", path, err));
                assert!(md.is_dir, "{}", path);
                if let Some(t) = e.mtime_nsec {
                    assert_eq!(md.modified, time(t), "{}", path);
                }
            }
            _ => assert!(v.metadata(&path).is_err(), "{} should not exist", path),
        }
    }
}

fn clean(img: &Temp) {
    let r = ufat::fsck::check(&Device::open(img.path(), Access::ReadOnly).unwrap()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert_eq!(r.lost_clusters, 0);
}

#[test]
fn every_fixture_parses() {
    let esp = load("esp", "Uapi16Manifest");
    assert_eq!(esp.entries.len(), 13);
    assert_eq!(
        esp.entries
            .iter()
            .filter(|e| e.inode_type == InodeType::Directory)
            .count(),
        6
    );
    assert_eq!(esp.root.inode_type, InodeType::Directory);
    assert_eq!(esp.root.mtime_nsec, Some(1_699_999_000_000_000_000));
    assert_eq!(esp.signatures, 0);
    assert_eq!(
        names(&esp),
        vec![
            "EFI",
            "EFI/BOOT",
            "EFI/BOOT/BOOTX64.EFI",
            "EFI/Linux",
            "EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi",
            "EFI/systemd",
            "EFI/systemd/systemd-bootx64.efi",
            "loader",
            "loader/entries",
            "loader/entries/fedora.conf",
            "loader/entries.srel",
            "loader/loader.conf",
            "loader/random-seed",
        ]
    );
    let uki = &esp.entries[4];
    assert_eq!(uki.size, Some(6395));
    assert_eq!(uki.mode, Some(0o664));
    assert_eq!(uki.mtime_nsec, Some(1_700_000_002_000_000_000));
    assert!(!uki.is_read_only());
    assert!(uki.contents.is_empty());

    // The signature does not change the file objects.
    let signed = load("esp", "signed.Uapi16Manifest");
    assert_eq!(signed.signatures, 1);
    assert_eq!(signed.entries, esp.entries);
    assert_eq!(signed.root, esp.root);

    // Fewer fields, same tree.
    let lean = load("esp", "size-hash-mtime.Uapi16Manifest");
    assert_eq!(names(&lean), names(&esp));
    assert!(lean.entries.iter().all(|e| e.mode.is_none()));
    assert!(lean
        .entries
        .iter()
        .zip(&esp.entries)
        .all(|(a, b)| a.size == b.size && a.sha256 == b.sha256 && a.mtime_nsec == b.mtime_nsec));
    let none = load("esp", "none.Uapi16Manifest");
    assert_eq!(names(&none), names(&esp));
    assert!(none
        .entries
        .iter()
        .all(|e| e.size.is_none() && e.sha256.is_none() && e.mtime_nsec.is_none()));

    let special = load("special", "Uapi16Manifest");
    assert_eq!(special.entries.len(), 13);
    let types: Vec<InodeType> = special.entries.iter().map(|e| e.inode_type).collect();
    assert_eq!(types.iter().filter(|&&t| t == InodeType::Symlink).count(), 1);
    assert_eq!(types.iter().filter(|&&t| t == InodeType::Fifo).count(), 1);
    let link = special
        .entries
        .iter()
        .find(|e| e.inode_type == InodeType::Symlink)
        .unwrap();
    assert_eq!(link.contents[0].literal.as_deref(), Some(&b"a.txt"[..]));
    let hardlinks: Vec<&str> = special
        .entries
        .iter()
        .filter(|e| e.inode_token.is_some())
        .filter_map(|e| e.name.as_deref())
        .collect();
    assert_eq!(hardlinks, vec!["sub/hl_a", "sub/hl_b"]);
    let readonly = special
        .entries
        .iter()
        .find(|e| e.name.as_deref() == Some("sub/readonly.bin"))
        .unwrap();
    assert_eq!(readonly.mode, Some(0o444));
    assert!(readonly.is_read_only());
    assert!(names(&special).contains(&"sub/\u{fc}mlaut \u{221e}.txt"));

    let empty = load("empty", "Uapi16Manifest");
    assert!(empty.entries.is_empty());
    assert_eq!(empty.root.mtime_nsec, Some(1_700_000_200_000_000_000));
}

#[test]
fn esp_assembles_from_the_tree_into_the_planned_size() {
    for name in [
        "Uapi16Manifest",
        "size-hash-mtime.Uapi16Manifest",
        "signed.Uapi16Manifest",
    ] {
        let m = load("esp", name);
        let (img, mut v, skipped) = planned_volume(&m);
        assert!(skipped.is_empty());
        let report = v.assemble(&m, &mut source("esp"), &AssembleOptions::default()).unwrap();
        assert_eq!(
            (report.files, report.directories, report.bytes),
            (7, 6, 14718),
            "{}",
            name
        );
        assert!(report.skipped.is_empty());
        assert_eq!(v.free_clusters(), 0, "{}: the plan was not exact", name);
        check_against_tree(&m, &v, &tree("esp"));
        v.close().unwrap();
        clean(&img);
    }
}

#[test]
fn esp_assembles_from_a_stream() {
    let m = load("esp", "Uapi16Manifest");
    let mut blob = Vec::new();
    for e in &m.entries {
        if e.is_streamed() {
            blob.extend(std::fs::read(tree("esp").join(e.name.as_deref().unwrap())).unwrap());
        }
    }
    assert_eq!(m.streamed_bytes().unwrap(), blob.len() as u64);
    let (img, mut v, _) = planned_volume(&m);
    let mut reader: &[u8] = &blob;
    let report = v
        .assemble(&m, &mut StreamSource::new(&mut reader), &AssembleOptions::default())
        .unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (7, 6, 14718));
    assert!(reader.is_empty(), "the stream had bytes left over");
    check_against_tree(&m, &v, &tree("esp"));
    v.close().unwrap();
    clean(&img);

    // One flipped byte in the stream fails the hash check of that file and
    // leaves the earlier files in place.
    let mut bad = blob.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x80;
    let (_img, mut v, _) = planned_volume(&m);
    let mut reader: &[u8] = &bad;
    let e = v
        .assemble(&m, &mut StreamSource::new(&mut reader), &AssembleOptions::default())
        .unwrap_err();
    assert!(e.message().contains("hash"), "{}", e);
    assert!(v.metadata("/loader/random-seed").is_err());
    assert!(v.metadata("/loader/loader.conf").is_ok());
}

#[test]
fn special_skips_what_fat_cannot_hold() {
    let m = load("special", "Uapi16Manifest");
    assert_eq!(m.check_supported().unwrap_err().errno(), EOPNOTSUPP);
    let (img, mut v, skipped) = planned_volume(&m);
    assert_eq!(skipped, vec!["link", "sub/fifo"]);
    let e = v
        .assemble(&m, &mut source("special"), &AssembleOptions::default())
        .unwrap_err();
    assert_eq!(e.errno(), EOPNOTSUPP);
    assert!(e.message().contains("link"), "{}", e);
    let options = AssembleOptions {
        skip_unsupported: true,
        ..AssembleOptions::default()
    };
    let report = v.assemble(&m, &mut source("special"), &options).unwrap();
    assert_eq!(report.skipped, skipped);
    assert_eq!((report.files, report.directories), (8, 3));
    assert_eq!(v.free_clusters(), 0);
    check_against_tree(&m, &v, &tree("special"));
    // Hardlinks become two copies, names fold case, the read-only bit
    // comes from the mode.
    assert_eq!(read_back(&v, "/sub/hl_a"), read_back(&v, "/sub/hl_b"));
    assert_eq!(v.metadata("/mixed case.txt").unwrap().name, "Mixed Case.TXT");
    assert_eq!(
        v.metadata("/sub/readonly.bin").unwrap().attributes & ATTR_READ_ONLY,
        ATTR_READ_ONLY
    );
    assert_eq!(v.metadata("/EMPTY DIR").unwrap().name, "empty dir");
    assert_eq!(read_back(&v, "/sub/\u{fc}mlaut \u{221e}.txt"), b"umlaut\n");
    v.close().unwrap();
    clean(&img);
}

#[test]
fn names_only_manifests_assemble_but_cannot_be_planned() {
    let m = load("esp", "none.Uapi16Manifest");
    let mut plan = Plan::new(PlanOptions {
        allow_small: true,
        ..PlanOptions::new(512)
    });
    assert_eq!(plan.add_manifest(&m).unwrap_err().errno(), EINVAL);
    assert_eq!(m.streamed_bytes().unwrap_err().errno(), EINVAL);

    let img = Temp::image(1 << 20);
    let options = FormatOptions {
        sector_size: Some(512),
        cluster_size: Some(512),
        allow_small: true,
        ..FormatOptions::default()
    };
    format::format(&Device::open(img.path(), Access::ReadWrite).unwrap(), &options).unwrap();
    let mut v = Volume::open(Device::open(img.path(), Access::ReadWrite).unwrap()).unwrap();
    let default_time = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    let report = v
        .assemble(
            &m,
            &mut source("esp"),
            &AssembleOptions {
                default_time,
                ..AssembleOptions::default()
            },
        )
        .unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (7, 6, 14718));
    check_against_tree(&m, &v, &tree("esp"));
    assert_eq!(v.metadata("/EFI/BOOT/BOOTX64.EFI").unwrap().modified, default_time);
    v.close().unwrap();
    clean(&img);
}

#[test]
fn empty_manifest_is_an_empty_volume() {
    let m = load("empty", "Uapi16Manifest");
    let (img, mut v, skipped) = planned_volume(&m);
    assert!(skipped.is_empty());
    // Git keeps no empty directory, so the empty tree is made here; the
    // source is resolved once, before the assembly, like any other.
    let tree = Temp::dir();
    let mut source = DirectorySource::new(host::open_dir(tree.path()).unwrap());
    let report = v.assemble(&m, &mut source, &AssembleOptions::default()).unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (0, 0, 0));
    assert!(v.read_dir("/").unwrap().is_empty());
    v.close().unwrap();
    clean(&img);
}

/// Our generator writes what `systemd-manifest make --field=size,hash,mtime`
/// writes for the same tree, byte for byte.
#[test]
fn generator_agrees_with_systemd_manifest() {
    let m = load("esp", "size-hash-mtime.Uapi16Manifest");
    // Git does not keep modification times, so put the manifest's back onto
    // a copy of the tree, files first and directories deepest first.
    let copy = Temp::dir();
    let src = tree("esp");
    let mut dirs: Vec<(PathBuf, u64)> = Vec::new();
    for e in &m.entries {
        let name = e.name.as_deref().unwrap();
        let dest = copy.path().join(name);
        match e.inode_type {
            InodeType::Directory => {
                std::fs::create_dir_all(&dest).unwrap();
                dirs.push((dest, e.mtime_nsec.unwrap()));
            }
            InodeType::Regular => {
                std::fs::copy(src.join(name), &dest).unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&dest)
                    .unwrap()
                    .set_modified(time(e.mtime_nsec.unwrap()))
                    .unwrap();
            }
            other => panic!("unexpected {:?}", other),
        }
    }
    dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    dirs.push((copy.path().to_path_buf(), m.root.mtime_nsec.unwrap()));
    for (dir, nsec) in dirs {
        std::fs::File::open(&dir).unwrap().set_modified(time(nsec)).unwrap();
    }
    let ours = manifest::generate(host::open_dir(copy.path()).unwrap().as_fd()).unwrap();
    let theirs = std::fs::read(fixtures().join("esp/size-hash-mtime.Uapi16Manifest")).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&ours),
        String::from_utf8_lossy(&theirs),
        "the generator and systemd-manifest disagree"
    );
}

/// The manifest of a volume is what `systemd-manifest make` writes for the
/// tree the volume was filled from, byte for byte, for the fields FAT has
/// a notion of: none at all, and size, hash and mtime.
#[test]
fn volume_manifest_agrees_with_systemd_manifest() {
    let m = load("esp", "size-hash-mtime.Uapi16Manifest");
    let (_img, mut v, _) = planned_volume(&m);
    v.assemble(&m, &mut source("esp"), &AssembleOptions::default()).unwrap();
    for (name, fields) in [
        ("none.Uapi16Manifest", Fields::none()),
        (
            "size-hash-mtime.Uapi16Manifest",
            Fields::from_names(["size", "hash", "mtime"]).unwrap(),
        ),
    ] {
        let mut ours = Vec::new();
        manifest::volume::write(&v, m.root.mtime(), fields, &mut ours).unwrap();
        let theirs = std::fs::read(fixtures().join("esp").join(name)).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(&theirs),
            "the volume's manifest and systemd-manifest's {} disagree",
            name
        );
    }
}
