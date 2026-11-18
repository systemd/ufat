// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;
use crate::populate::CopyOptions;
use crate::progress::Progress;
use crate::test_util::{volume, TempDir, TempImage};
use crate::volume::{NameCollision, Volume};
use crate::{ContentProblem, Error, ManifestProblem, NameProblem, SourceProblem};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use uapi16::{Data, Digest, Mode, MAX_RECORD_SIZE, RECORD_SEPARATOR};

/// A directory resolved once, the way the tool resolves the SOURCE of a
/// manifest.
fn source_dir(path: &Path) -> PinnedDirectory {
    PinnedDirectory::new(crate::host::open_dir(path).unwrap())
}

fn dir_source(path: &Path) -> DirectorySource<PinnedDirectory> {
    DirectorySource::new(source_dir(path))
}

/// The manifest the generator writes for the tree at `path`.
fn generated(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    HostTree::new(crate::host::open_dir(path).unwrap().as_fd())
        .write_manifest(&mut out)
        .unwrap();
    out
}

/// Reads the manifest `bytes` to its end with the reader of the `uapi16`
/// crate, which requires the code point order, and returns its root file
/// object and its file objects. A test can hold a manifest whole.
fn read(bytes: &[u8]) -> Result<(RootObject, Vec<FileObject>)> {
    let reader = Reader::open(bytes)?;
    reader.root().require_order(Order::CodePoint)?;
    let root = reader.root().clone();
    let mut objects = Vec::new();
    for object in reader {
        if let Object::File(object) = object? {
            objects.push(*object);
        }
    }
    Ok((root, objects))
}

/// The file objects of the manifest `bytes`.
fn objects(bytes: &[u8]) -> Vec<FileObject> {
    read(bytes).unwrap().1
}

/// Assembles the manifest `bytes` into `v`.
fn assemble(
    v: &mut Volume,
    bytes: &[u8],
    source: &mut dyn ContentSource,
    options: &AssembleOptions,
) -> Result<AssembleReport> {
    v.assemble(&mut Reader::open(bytes)?, source, options)
}

/// Assembles the manifest `bytes` into `v` with the contents of the files
/// from `stream`.
fn assemble_stream(v: &mut Volume, bytes: &[u8], stream: &[u8], options: &AssembleOptions) -> Result<AssembleReport> {
    let mut stream = stream;
    assemble(v, bytes, &mut StreamSource::new(&mut stream), options)
}

fn seq(records: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.push(RECORD_SEPARATOR);
        out.extend_from_slice(r.as_bytes());
        out.push(b'\n');
    }
    out
}

const ROOT: &str = r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#;
const TRAILER: &str = r#"{"mediaType":"application/vnd.uapi.16.trailer"}"#;
/// A root file object of a manifest that records modification times too.
const ROOT_MTIME: &str = concat!(
    r#"{"features":["device","gid","hardlink","mode","mtime","sha256","size","symlink","uid"],"#,
    r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
);

/// The contents of a file read back from the volume.
fn contents(v: &Volume, path: &str) -> Vec<u8> {
    let mut back = Vec::new();
    v.open_file(path).unwrap().read_to_end(&mut back).unwrap();
    back
}

/// Records what an assembly reports to its observer.
#[derive(Debug, Default)]
struct Recorder {
    progress: Vec<Progress>,
    skipped: Vec<(String, SkipReason)>,
}

impl AssembleObserver for Recorder {
    fn progress(&mut self, progress: &Progress) {
        self.progress.push(*progress);
    }

    fn skipped(&mut self, name: &Name, reason: SkipReason) {
        self.skipped.push((name.to_string(), reason));
    }
}

#[test]
fn assembles_what_a_manifest_describes() {
    let hello = Sha256::digest(b"hello").to_string();
    let m = seq(&[
        ROOT_MTIME,
        r#"{"mode":493,"name":"EFI","type":"dir","uid":0,"gid":0}"#,
        r#"{"name":"EFI/BOOT","type":"dir"}"#,
        &format!(
            r#"{{"mTimeNSec":1700000000000000000,"mode":420,"name":"EFI/BOOT/BOOTX64.EFI","sha256":"{}","size":5}}"#,
            hello
        ),
        r#"{"name":"empty","size":0}"#,
        r#"{"contents":[{"literal":"aGVsbG8="}],"name":"link","type":"lnk"}"#,
        r#"{"contents":[{"literal":"aGVsbG8="}],"name":"literal.txt","mode":420}"#,
        r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AAAA"}"#,
        r#"{"mediaType":"application/x-unknown","whatever":1}"#,
        TRAILER,
    ]);
    let entries = objects(&m);
    assert_eq!(entries.len(), 6);
    assert_eq!(entries[5].inode.mode.map(Mode::bits), Some(0o644));
    let boot = &entries[2];
    assert_eq!(
        boot.inode.mtime(),
        Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000))
    );
    assert!(!boot.inode.is_read_only() && boot.has_external_data());
    assert_eq!(entries[3].sha256, Some(Sha256::EMPTY));
    assert!(!entries[5].has_external_data());
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let options = AssembleOptions {
        flags: AssembleFlags::SKIP_UNSUPPORTED,
        ..AssembleOptions::default()
    };
    let r = assemble_stream(&mut v, &m, b"hello", &options).unwrap();
    assert_eq!((r.files, r.directories, r.bytes, r.skipped), (3, 2, 10, 1));
    assert_eq!(contents(&v, "/EFI/BOOT/BOOTX64.EFI"), b"hello");
    assert_eq!(
        v.metadata("/EFI/BOOT/BOOTX64.EFI").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
    assert_eq!(contents(&v, "/literal.txt"), b"hello");
    assert_eq!(v.metadata("/empty").unwrap().size, 0);
    assert_eq!(v.metadata("/link").unwrap_err().errno(), ENOENT);
}

/// What the reader refuses is for the uapi16 crate to test, in its
/// refused.jsonl. An assembly fails on it before it writes what the record
/// describes, with the problem in the detail.
#[test]
fn rejects_broken_manifests() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let m = seq(&[ROOT, r#"{"name":"x","size":1,"mode":5000}"#, TRAILER]);
    let e = assemble_stream(&mut v, &m, b"x", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EBADMSG);
    assert_eq!(
        e.detail(),
        Some(&Detail::Manifest {
            problem: ManifestProblem::Malformed(Problem::FieldOutOfRange),
            record: Some(1),
            name: Some("x".to_string()),
            field: Some("mode".to_string()),
        })
    );
    assert!(v.read_dir("/").unwrap().is_empty());
    // A record beyond the cap fails with E2BIG.
    let big = format!(r#"{{"name":"x","size":0,"pad":"{}"}}"#, "p".repeat(MAX_RECORD_SIZE));
    let e = assemble_stream(&mut v, &seq(&[ROOT, &big, TRAILER]), b"", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), E2BIG);
    assert!(e.is_manifest(), "{:?}", e);
    assert!(v.read_dir("/").unwrap().is_empty());
    // A manifest that does not declare the code point order is refused
    // before anything is written, also when its objects are in that order.
    for root in [
        r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#,
        r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"bytes"}"#,
    ] {
        let undeclared = seq(&[
            root,
            r#"{"name":"a","type":"dir"}"#,
            r#"{"name":"b","size":0}"#,
            TRAILER,
        ]);
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &undeclared, b"", &AssembleOptions::default()).unwrap_err();
        assert_eq!(e.errno(), EBADMSG);
        assert_eq!(
            e.detail(),
            Some(&Detail::Manifest {
                problem: ManifestProblem::Malformed(Problem::NoOrder),
                record: Some(0),
                name: None,
                field: Some("order".to_string()),
            }),
            "{}",
            root
        );
        assert!(v.read_dir("/").unwrap().is_empty());
    }
    // A manifest does not limit a component on its own. A name too long
    // for FAT is refused when it would be written, and nothing is.
    let long = format!(r#"{{"name":"{}","size":0}}"#, "x".repeat(256));
    assert!(read(&seq(&[ROOT, &long, TRAILER])).is_ok());
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &seq(&[ROOT, &long, TRAILER]), b"", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), ENAMETOOLONG);
    assert!(!v.is_writing());
}

/// What the volume refuses at the first object of a manifest leaves it as
/// it was, not even marked as being written: a file where it has a
/// directory, a name FAT cannot store, as a file and as a directory, and a
/// name it holds when nothing is replaced.
#[test]
fn refusals_at_the_first_object_write_nothing() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let t0 = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    v.create_dir("/d", t0).unwrap();
    v.write_file("/f", &mut &b"old"[..], t0, NameCollision::Fail).unwrap();
    v.sync().unwrap();
    let keep = AssembleOptions {
        flags: AssembleFlags::NONE,
        ..AssembleOptions::default()
    };
    for (object, errno) in [
        (r#"{"name":"d","size":0}"#, EISDIR),
        (r#"{"name":"a:b","size":0}"#, EINVAL),
        (r#"{"name":"a:b","type":"dir"}"#, EINVAL),
        (r#"{"name":"f","size":3}"#, EEXIST),
    ] {
        let e = assemble_stream(&mut v, &seq(&[ROOT, object, TRAILER]), b"new", &keep).unwrap_err();
        assert_eq!(e.errno(), errno, "{}", object);
        assert!(!v.is_writing(), "{}", object);
    }
    assert_eq!(contents(&v, "/f"), b"old");
}

/// A manifest that lists a file before the object of its directory, or
/// its objects out of code point order, is refused when the object comes.
/// What came before it is written.
#[test]
fn misplaced_and_unsorted_manifests_are_refused() {
    for (records, problem, written) in [
        (
            &[
                ROOT,
                r#"{"name":"d/x","size":0}"#,
                r#"{"name":"d","type":"dir","mTimeNSec":1700000000000000000}"#,
                TRAILER,
            ][..],
            ManifestProblem::Malformed(Problem::Misplaced),
            0,
        ),
        (
            &[
                ROOT,
                r#"{"name":"a","type":"dir"}"#,
                r#"{"name":"b","size":0}"#,
                r#"{"name":"a/x","size":0}"#,
                TRAILER,
            ],
            ManifestProblem::Malformed(Problem::Misplaced),
            2,
        ),
        // In tree order, but the names of a directory are not sorted.
        (
            &[ROOT, r#"{"name":"b","size":0}"#, r#"{"name":"a","size":0}"#, TRAILER],
            ManifestProblem::Malformed(Problem::OutOfOrder),
            1,
        ),
        (
            &[
                ROOT,
                r#"{"name":"a-b","size":0}"#,
                r#"{"name":"a","type":"dir"}"#,
                TRAILER,
            ],
            ManifestProblem::Malformed(Problem::OutOfOrder),
            1,
        ),
    ] {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &seq(records), b"", &AssembleOptions::default()).unwrap_err();
        assert_eq!(e.errno(), EBADMSG, "{:?}", records);
        assert!(
            matches!(e.detail(), Some(Detail::Manifest { problem: p, .. }) if *p == problem),
            "{:?}: {:?}",
            records,
            e
        );
        assert_eq!(v.read_dir("/").unwrap().len(), written, "{:?}", records);
    }
}

/// The manifest of a tree, with the contents of its streamed files in
/// manifest order.
fn manifest_with_tree() -> (Vec<u8>, Vec<u8>) {
    let a = b"first file".to_vec();
    let b = vec![7u8; 5000];
    let m = seq(&[
        ROOT_MTIME,
        r#"{"mTimeNSec":1700000000000000000,"name":"EFI","type":"dir"}"#,
        r#"{"name":"EFI/Linux","type":"dir"}"#,
        &format!(
            r#"{{"mode":292,"name":"EFI/Linux/b.efi","sha256":"{}","size":{}}}"#,
            Sha256::digest(&b),
            b.len()
        ),
        &format!(
            r#"{{"mTimeNSec":1700000001000000000,"name":"EFI/a.txt","sha256":"{}","size":{}}}"#,
            Sha256::digest(&a),
            a.len()
        ),
        r#"{"contents":[{"literal":"aGVsbG8="}],"name":"literal.txt","size":5}"#,
        TRAILER,
    ]);
    let mut blob = b;
    blob.extend(a);
    (m, blob)
}

#[test]
fn assembles_from_a_stream() {
    let (m, blob) = manifest_with_tree();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let report = assemble_stream(&mut v, &m, &blob, &AssembleOptions::default()).unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (3, 2, 5015));
    assert_eq!(
        v.metadata("/EFI/a.txt").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
    let b = v.metadata("/EFI/Linux/b.efi").unwrap();
    assert_eq!(b.size, 5000);
    assert_eq!(b.attributes & ATTR_READ_ONLY, ATTR_READ_ONLY);
    // A directory without a time gets the default time, clamped to the FAT
    // epoch.
    assert_eq!(
        v.metadata("/EFI/Linux").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(crate::time::FAT_EPOCH as u64)
    );
    assert_eq!(contents(&v, "/literal.txt"), b"hello");

    // A short stream fails at the file it runs out in and leaves no trace
    // of it. The directories before it are there.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &m, &blob[..100], &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EBADMSG);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Content {
                problem: ContentProblem::StreamEnded,
                ..
            })
        ),
        "{:?}",
        e
    );
    assert!(v.metadata("/EFI/Linux/b.efi").is_err());
    assert!(v.metadata("/EFI/Linux").unwrap().is_dir);

    // A stream that goes on after the last file fails once the manifest
    // ended, naming that file. The files are all there by then.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let long_blob = [&blob[..], b"more"].concat();
    let e = assemble_stream(&mut v, &m, &long_blob, &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EBADMSG);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Content {
                problem: ContentProblem::Size,
                name,
                size: None,
                expected: Some(10),
            }) if name == "EFI/a.txt"
        ),
        "{:?}",
        e
    );
    assert_eq!(v.metadata("/EFI/a.txt").unwrap().size, 10);
    assert_eq!(contents(&v, "/literal.txt"), b"hello");

    // A corrupted stream fails the hash check. The file it was about to
    // replace survives untouched.
    let mut bad = blob.clone();
    bad[0] ^= 1;
    let replace = AssembleOptions {
        flags: AssembleFlags::REPLACE,
        ..AssembleOptions::default()
    };
    let e = assemble_stream(&mut v, &m, &bad, &replace).unwrap_err();
    assert!(e.message().contains("hash"), "{}", e);
    assert_eq!(contents(&v, "/EFI/Linux/b.efi"), vec![7u8; 5000]);

    // On a fresh volume the failed file leaves nothing behind.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assemble_stream(&mut v, &m, &bad, &AssembleOptions::default()).unwrap_err();
    assert!(v.metadata("/EFI/Linux/b.efi").is_err());
    assert!(v.metadata("/EFI/Linux").is_ok());
}

/// A manifest is read once, from its start to its end: from a pipe as
/// well as from a file.
#[test]
fn assembles_while_a_manifest_comes_through_a_pipe() {
    let tmp = TempDir::new("manifest-pipe");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("EFI/Linux")).unwrap();
    std::fs::write(dir.join("EFI/a.txt"), b"first file").unwrap();
    std::fs::write(dir.join("EFI/Linux/b.efi"), vec![7u8; 5000]).unwrap();
    let (m, _) = manifest_with_tree();
    let (mut ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let writer = std::thread::spawn(move || {
        // A record at a time, the way a producer writes them.
        for record in m.split_inclusive(|&b| b == b'\n') {
            theirs.write_all(record).unwrap();
        }
    });
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut reader = Reader::open(&mut ours).unwrap();
    let report = v
        .assemble(&mut reader, &mut dir_source(&dir), &AssembleOptions::default())
        .unwrap();
    writer.join().unwrap();
    assert_eq!((report.files, report.directories, report.bytes), (3, 2, 5015));
    assert_eq!(contents(&v, "/EFI/a.txt"), b"first file");
}

#[test]
fn assembles_from_a_directory() {
    let tmp = TempDir::new("manifest");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("EFI/Linux")).unwrap();
    std::fs::write(dir.join("EFI/a.txt"), b"first file").unwrap();
    std::fs::write(dir.join("EFI/Linux/b.efi"), vec![7u8; 5000]).unwrap();
    let (m, _) = manifest_with_tree();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let report = assemble(&mut v, &m, &mut dir_source(&dir), &AssembleOptions::default()).unwrap();
    assert_eq!(report.files, 3);

    // The generator produces a manifest the reader accepts and the
    // planner and assembler agree on.
    let generated = generated(&dir);
    assert_eq!(
        objects(&generated).iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
        vec!["EFI", "EFI/Linux", "EFI/Linux/b.efi", "EFI/a.txt"]
    );
    let mut plan = crate::plan::Plan::new(crate::plan::PlanOptions {
        allow_small: true,
        cluster_size: Some(512),
        ..crate::plan::PlanOptions::new(512)
    });
    let mut reader = Reader::open(&generated[..]).unwrap();
    assert_eq!(
        plan.add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED).unwrap(),
        0
    );
    let est = plan.estimate().unwrap();
    let img = TempImage::new(est.size());
    let mut o = crate::format::FormatOptions {
        allow_small: true,
        ..Default::default()
    };
    est.apply(&mut o);
    crate::format::format(&img.device(), &o).unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    assemble(&mut v, &generated, &mut dir_source(&dir), &AssembleOptions::default()).unwrap();
    assert_eq!(v.free_clusters(), 0);
}

/// What FAT cannot store is refused, or left out with everything below it
/// and counted. The contents of a file that is left out are read past in
/// a stream, which ends with them all the same.
#[test]
fn unsupported_entries() {
    let hello = Sha256::digest(b"hello").to_string();
    let m = seq(&[
        ROOT,
        r#"{"name":"encoded","size":5,"contents":[{"literal":"H4sIAAAAAAAAA8tIzcnJBwCGphA2BQAAAA==","encoding":"gzip"}]}"#,
        r#"{"name":"link","type":"lnk","contents":[{"literal":"eA=="}]}"#,
        r#"{"name":"ok","size":2}"#,
        r#"{"name":"remote","size":5,"contents":[{"url":"https://example.com/x"}]}"#,
        &format!(r#"{{"name":"sub","type":"dir","sha256":"{}","size":5}}"#, hello),
        r#"{"name":"sub/deeper","type":"dir"}"#,
        r#"{"name":"sub/deeper/x","size":3}"#,
        r#"{"name":"sub/inner","size":0}"#,
        r#"{"name":"z","size":1}"#,
        TRAILER,
    ]);
    let unsupported: Vec<String> = objects(&m)
        .iter()
        .filter(|e| EntryKind::try_from(*e).is_err())
        .map(|e| e.name.to_string())
        .collect();
    assert_eq!(unsupported, vec!["encoded", "link", "remote", "sub"]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &m, b"okxyzZ", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EOPNOTSUPP);
    // Nothing was created for the entry that failed.
    assert_eq!(v.read_dir("/").unwrap().len(), 0);
    let options = AssembleOptions {
        flags: AssembleFlags::SKIP_UNSUPPORTED,
        ..Default::default()
    };
    let mut recorder = Recorder::default();
    let mut stream: &[u8] = b"okxyzZ";
    let r = v
        .assemble_with_observer(
            &mut Reader::open(&m[..]).unwrap(),
            &mut StreamSource::new(&mut stream),
            &options,
            &mut recorder,
        )
        .unwrap();
    assert_eq!((r.files, r.directories, r.bytes, r.skipped), (2, 0, 3, 7));
    use SkipReason::{BelowSkipped as Below, Unsupported as Cannot};
    let skipped: Vec<(&str, SkipReason)> = recorder.skipped.iter().map(|(n, r)| (n.as_str(), *r)).collect();
    assert_eq!(
        skipped,
        [
            ("encoded", Cannot),
            ("link", Cannot),
            ("remote", Cannot),
            ("sub", Cannot),
            ("sub/deeper", Below),
            ("sub/deeper/x", Below),
            ("sub/inner", Below),
        ]
    );
    assert_eq!(contents(&v, "/ok"), b"ok");
    assert_eq!(contents(&v, "/z"), b"Z");
    assert_eq!(v.metadata("/sub").unwrap_err().errno(), ENOENT);
    // The stream had the contents of the file below the directory that
    // was left out, and nothing else.
    for stream in [&b"okxyz"[..], b"okxyzZmore"] {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        assert_eq!(
            assemble_stream(&mut v, &m, stream, &options).unwrap_err().errno(),
            EBADMSG
        );
    }
    // A file larger than a FAT32 file can be is no object to leave out.
    let big = seq(&[ROOT, r#"{"name":"big","size":4294967296}"#, TRAILER]);
    let e = assemble_stream(&mut v, &big, b"", &options).unwrap_err();
    assert_eq!(e.errno(), EFBIG);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::TooLarge {
                path: Some(path),
                size: 4294967296,
                ..
            }) if path == "/big"
        ),
        "{:?}",
        e
    );
    // The planner leaves out the same objects.
    let mut plan = crate::plan::Plan::new(crate::plan::PlanOptions {
        allow_small: true,
        ..crate::plan::PlanOptions::new(512)
    });
    let mut reader = Reader::open(&m[..]).unwrap();
    assert_eq!(
        plan.add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED).unwrap(),
        7
    );
    assert_eq!((plan.estimate().unwrap().files, plan.estimate().unwrap().bytes), (2, 3));
}

/// Directories that are left out one after the other each take what is
/// below them along, and nothing else: a name that only starts like the
/// name of one is not below it. The stream has the contents of the files
/// below them as well.
#[test]
fn directories_left_out_one_after_the_other() {
    let hello = Sha256::digest(b"hello").to_string();
    let sub = |name: &str| format!(r#"{{"name":"{}","sha256":"{}","size":5,"type":"dir"}}"#, name, hello);
    let m = seq(&[
        ROOT,
        &sub("a"),
        r#"{"name":"a/x","size":1}"#,
        r#"{"name":"ab","size":1}"#,
        &sub("b"),
        r#"{"name":"b/y","size":1}"#,
        &sub("c"),
        r#"{"name":"d","size":1}"#,
        TRAILER,
    ]);
    let options = AssembleOptions {
        flags: AssembleFlags::SKIP_UNSUPPORTED,
        ..Default::default()
    };
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let mut recorder = Recorder::default();
    let mut stream: &[u8] = b"xAyD";
    let r = v
        .assemble_with_observer(
            &mut Reader::open(&m[..]).unwrap(),
            &mut StreamSource::new(&mut stream),
            &options,
            &mut recorder,
        )
        .unwrap();
    assert_eq!((r.files, r.skipped), (2, 5));
    use SkipReason::{BelowSkipped as Below, Unsupported as Cannot};
    let skipped: Vec<(&str, SkipReason)> = recorder.skipped.iter().map(|(n, r)| (n.as_str(), *r)).collect();
    assert_eq!(
        skipped,
        [
            ("a", Cannot),
            ("a/x", Below),
            ("b", Cannot),
            ("b/y", Below),
            ("c", Cannot),
        ]
    );
    assert_eq!(contents(&v, "/ab"), b"A");
    assert_eq!(contents(&v, "/d"), b"D");
}

/// A regular file without a size can be neither streamed nor planned, and
/// both say so alike: by its name in the manifest, and the size field. The
/// stream refuses it before anything is written.
#[test]
fn files_without_a_size() {
    let m = seq(&[ROOT, r#"{"name":"x"}"#, TRAILER]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let streamed = assemble_stream(&mut v, &m, b"", &AssembleOptions::default()).unwrap_err();
    assert!(!v.is_writing());
    let mut plan = crate::plan::Plan::new(crate::plan::PlanOptions::new(512));
    let mut reader = Reader::open(&m[..]).unwrap();
    let planned = plan.add_records(&mut reader, AssembleFlags::NONE).unwrap_err();
    for e in [streamed, planned] {
        let Some(Detail::Manifest {
            problem, name, field, ..
        }) = e.detail()
        else {
            panic!("{:?}", e);
        };
        assert_eq!(*problem, ManifestProblem::NoSize);
        assert_eq!((name.as_deref(), field.as_deref()), (Some("x"), Some("size")));
    }
}

/// A directory that refers to a sub-manifest is refused at its object,
/// before the stream is asked for the sub-manifest, with or without a size.
/// Left out instead, it takes its sub-manifest along: the stream has that
/// too, and reads past it as far as the size says. Without a size it
/// cannot.
#[test]
fn sub_manifests_and_a_stream() {
    let hello = Sha256::digest(b"hello").to_string();
    let m = |size: &str| {
        seq(&[
            ROOT,
            &format!(
                r#"{{"contents":[{{"file":"sub.manifest"}}],"name":"sub","sha256":"{}"{},"type":"dir"}}"#,
                hello, size
            ),
            r#"{"name":"z","size":1}"#,
            TRAILER,
        ])
    };
    for size in ["", r#","size":5"#] {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &m(size), b"helloZ", &AssembleOptions::default()).unwrap_err();
        assert_eq!(e.errno(), EOPNOTSUPP, "{:?}", e);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Unsupported {
                    what: UnsupportedKind::SubManifest,
                    ..
                })
            ),
            "{:?}",
            e
        );
        assert!(v.read_dir("/").unwrap().is_empty());
    }
    let skip = AssembleOptions {
        flags: AssembleFlags::SKIP_UNSUPPORTED,
        ..AssembleOptions::default()
    };
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let r = assemble_stream(&mut v, &m(r#","size":5"#), b"helloZ", &skip).unwrap();
    assert_eq!((r.files, r.skipped), (1, 1));
    assert_eq!(contents(&v, "/z"), b"Z");
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &m(""), b"helloZ", &skip).unwrap_err();
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Manifest {
                problem: ManifestProblem::NoSize,
                ..
            })
        ),
        "{:?}",
        e
    );
}

/// Contents at an offset in their file come from a directory, and a stream,
/// which has the contents of each file and nothing else of it, refuses
/// them when the object comes, whether objects FAT cannot store are left
/// out or not, before anything is written. So does a directory whose file
/// is missing.
#[test]
fn offsets_and_a_stream() {
    let tmp = TempDir::new("manifest-offset");
    let dir = tmp.path().to_path_buf();
    std::fs::write(dir.join("a"), b"hello world").unwrap();
    let m = seq(&[
        ROOT,
        r#"{"contents":[{"file":"a","offset":6}],"name":"w","size":5}"#,
        TRAILER,
    ]);
    for flags in [AssembleFlags::NONE, AssembleFlags::SKIP_UNSUPPORTED] {
        let options = AssembleOptions {
            flags,
            ..AssembleOptions::default()
        };
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &m, b"world", &options).unwrap_err();
        assert_eq!(e.errno(), EOPNOTSUPP, "{:?}", e);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Unsupported {
                    what: UnsupportedKind::Offset,
                    ..
                })
            ),
            "{:?}",
            e
        );
        assert!(v.read_dir("/").unwrap().is_empty());
        assert!(!v.is_writing());
        let empty = TempDir::new("manifest-offset-empty");
        let e = assemble(&mut v, &m, &mut dir_source(empty.path()), &options).unwrap_err();
        assert_eq!(e.errno(), ENOENT, "{:?}", e);
        assert!(!v.is_writing());
        let r = assemble(&mut v, &m, &mut dir_source(&dir), &options).unwrap();
        assert_eq!((r.files, r.skipped), (1, 0));
        assert_eq!(contents(&v, "/w"), b"world");
    }
}

/// A file that changes while it is read fails with SourceChanged, without
/// sizes. A file of procfs says it is empty when it is opened and has data
/// when it is read, which is how a file that grew after it was opened looks
/// to the source. Checked against a hash of all of it, it is read past its
/// length.
#[test]
fn files_that_change_while_they_are_read() {
    let hello = Sha256::digest(b"hello").to_string();
    let m = seq(&[
        ROOT,
        &format!(
            r#"{{"contents":[{{"originalSha256":"{}"}}],"name":"version","size":0}}"#,
            hello
        ),
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble(
        &mut v,
        &m,
        &mut dir_source(Path::new("/proc")),
        &AssembleOptions::default(),
    )
    .unwrap_err();
    assert_eq!(e.errno(), EBADMSG);
    assert_eq!(
        e.detail(),
        Some(&Detail::Content {
            name: "version".to_string(),
            problem: ContentProblem::SourceChanged,
            size: None,
            expected: None,
        })
    );
    assert!(v.read_dir("/").unwrap().is_empty());
}

/// Names FAT does not tell apart, the second of which an assembly finds
/// in the volume: refused by default, taken as the same name with REPLACE.
#[test]
fn case_collisions_are_refused_unless_replaced() {
    let m = seq(&[
        ROOT,
        r#"{"name":"A.TXT","size":1}"#,
        r#"{"name":"EFI","type":"dir"}"#,
        r#"{"name":"EFI/x","size":1}"#,
        r#"{"name":"a.txt","size":2}"#,
        r#"{"name":"efi","type":"dir"}"#,
        r#"{"name":"efi/y","size":1}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &m, b"Axyyz", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EEXIST);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Name {
                name,
                problem: NameProblem::CaseCollision,
            }) if name == "/a.txt"
        ),
        "{:?}",
        e
    );
    assert_eq!(e.message(), "'/a.txt' and '/A.TXT' are names FAT cannot tell apart");
    assert_eq!(contents(&v, "/A.TXT"), b"A");
    // A directory collides the same way.
    let dirs = seq(&[
        ROOT,
        r#"{"name":"EFI","type":"dir"}"#,
        r#"{"name":"efi","type":"dir"}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble_stream(&mut v, &dirs, b"", &AssembleOptions::default()).unwrap_err();
    assert!(
        matches!(e.detail(), Some(Detail::Name { name, problem: NameProblem::CaseCollision }) if name == "/efi"),
        "{:?}",
        e
    );
    // With REPLACE a file replaces the one it collides with, under its own
    // name, and a directory takes the entries of the one it collides with.
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let replace = AssembleOptions {
        flags: AssembleFlags::REPLACE,
        ..AssembleOptions::default()
    };
    let r = assemble_stream(&mut v, &m, b"Axyyz", &replace).unwrap();
    assert_eq!((r.files, r.directories, r.bytes), (4, 2, 5));
    let names = |v: &Volume, path: &str| {
        let mut names: Vec<String> = v.read_dir(path).unwrap().into_iter().map(|md| md.name).collect();
        names.sort();
        names
    };
    assert_eq!(names(&v, "/"), ["EFI", "a.txt"]);
    assert_eq!(contents(&v, "/a.txt"), b"yy");
    assert_eq!(names(&v, "/EFI"), ["x", "y"]);
}

/// Directories that the volume holds with the times and the attributes
/// the manifest gives are not written again. So a manifest refused at a
/// file after them, or one of nothing but such directories, leaves the
/// volume as it was.
#[test]
fn directories_that_are_there_with_their_times_write_nothing() {
    let dirs = [
        r#"{"mTimeNSec":1700000000000000000,"name":"EFI","type":"dir"}"#,
        r#"{"mTimeNSec":1700000000000000000,"name":"EFI/BOOT","type":"dir"}"#,
    ];
    let m = seq(&[
        ROOT_MTIME,
        dirs[0],
        dirs[1],
        r#"{"name":"EFI/BOOT/x","size":1}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assemble_stream(&mut v, &m, b"x", &AssembleOptions::default()).unwrap();
    v.sync().unwrap();
    let keep = AssembleOptions {
        flags: AssembleFlags::NONE,
        ..AssembleOptions::default()
    };
    let e = assemble_stream(&mut v, &m, b"x", &keep).unwrap_err();
    assert_eq!(e.errno(), EEXIST);
    assert!(!v.is_writing());
    let r = assemble_stream(&mut v, &seq(&[ROOT_MTIME, dirs[0], dirs[1], TRAILER]), b"", &keep).unwrap();
    assert_eq!(r.directories, 2);
    assert!(!v.is_writing());
    // Other attributes are written, here the read-only attribute that a
    // mode without write permission gives.
    let read_only = seq(&[
        ROOT_MTIME,
        r#"{"mTimeNSec":1700000000000000000,"mode":365,"name":"EFI","type":"dir"}"#,
        TRAILER,
    ]);
    assemble_stream(&mut v, &read_only, b"", &keep).unwrap();
    assert!(v.is_writing());
    assert_eq!(dos_attributes(&v, "/EFI"), ATTR_READ_ONLY);
    v.sync().unwrap();
    // Another time is written.
    let later = seq(&[
        ROOT_MTIME,
        r#"{"mTimeNSec":1800000000000000000,"name":"EFI","type":"dir"}"#,
        TRAILER,
    ]);
    assemble_stream(&mut v, &later, b"", &keep).unwrap();
    assert!(v.is_writing());
    assert_eq!(
        v.metadata("/EFI").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    );
}

/// A directory that is there in a damaged directory, with the time the
/// manifest gives and other attributes, fails before anything is written,
/// so a manifest refused there leaves the volume as it was.
#[test]
fn attributes_in_a_damaged_directory_write_nothing() {
    use crate::dirent::DIR_ENTRY_SIZE;
    let (img, mut v) = volume(8 << 20, 512, 512);
    v.create_dir_all("/d/sub", UNIX_EPOCH + Duration::from_secs(1_700_000_000))
        .unwrap();
    let d = v.metadata("/d").unwrap();
    let layout = *v.layout();
    v.close().unwrap();
    // Garbage behind the end marker of /d, in its slot 5 after ".", ".."
    // and "sub": such a directory is read, but not written.
    img.device()
        .write_at(
            layout.cluster_offset(d.first_cluster).unwrap() + 5 * DIR_ENTRY_SIZE as u64,
            b"X",
        )
        .unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    let bytes = std::fs::read(img.path()).unwrap();
    let m = seq(&[
        concat!(
            r#"{"features":["flag-hidden","mtime"],"#,
            r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
        ),
        r#"{"mTimeNSec":1700000000000000000,"name":"d","type":"dir"}"#,
        r#"{"flagHidden":true,"mTimeNSec":1700000000000000000,"name":"d/sub","type":"dir"}"#,
        TRAILER,
    ]);
    let e = assemble_stream(&mut v, &m, b"", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EUCLEAN);
    // The image is read while the volume is open: closing it would put
    // back marks a refusal set.
    assert!(!v.is_writing());
    assert_eq!(std::fs::read(img.path()).unwrap(), bytes);
}

/// What a volume holds under the same name as an object was there before
/// the assembly: a directory takes the entries, a file is replaced only
/// with REPLACE.
#[test]
fn entries_of_the_same_name_that_are_there() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let t0 = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
    v.create_dir("/EFI", t0).unwrap();
    v.write_file("/EFI/x", &mut &b"old"[..], t0, NameCollision::Fail)
        .unwrap();
    let m = seq(&[
        ROOT_MTIME,
        r#"{"mTimeNSec":1700000000000000000,"name":"EFI","type":"dir"}"#,
        r#"{"name":"EFI/x","size":3}"#,
        r#"{"name":"EFI/y","size":1}"#,
        TRAILER,
    ]);
    let e = assemble_stream(&mut v, &m, b"newy", &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), EEXIST);
    assert_eq!(e.detail(), Some(&Detail::Path("/EFI/x".into())));
    assert_eq!(
        v.metadata("/EFI").unwrap().modified,
        UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    );
    assert_eq!(contents(&v, "/EFI/x"), b"old");
    let replace = AssembleOptions {
        flags: AssembleFlags::REPLACE,
        ..AssembleOptions::default()
    };
    let r = assemble_stream(&mut v, &m, b"newy", &replace).unwrap();
    assert_eq!((r.files, r.directories), (2, 1));
    assert_eq!(contents(&v, "/EFI/x"), b"new");
    // A file where the volume has a directory, and the other way round.
    for (records, errno) in [
        (&[ROOT, r#"{"name":"EFI","size":0}"#, TRAILER][..], EISDIR),
        (
            &[
                ROOT,
                r#"{"name":"EFI","type":"dir"}"#,
                r#"{"name":"EFI/x","type":"dir"}"#,
                TRAILER,
            ],
            ENOTDIR,
        ),
    ] {
        assert_eq!(
            assemble_stream(&mut v, &seq(records), b"", &replace)
                .unwrap_err()
                .errno(),
            errno
        );
    }
}

#[test]
fn contents_are_chosen_by_what_can_be_used() {
    let hello = Sha256::digest(b"hello").to_string();
    let m = seq(&[
        ROOT,
        // A URL first, then an encoded literal, then plain data.
        &format!(
            r#"{{"name":"x","size":5,"sha256":"{}","contents":[{{"url":"https://example.com/x"}},{{"literal":"AAAA","encoding":"gzip"}},{{"literal":"aGVsbG8="}}]}}"#,
            hello
        ),
        // A URL with a file as the alternative is read from the source.
        &format!(
            r#"{{"name":"y","size":5,"sha256":"{}","contents":[{{"url":"https://example.com/y"}},{{"file":"data/y.bin"}}]}}"#,
            hello
        ),
        TRAILER,
    ]);
    let entries = objects(&m);
    assert_eq!(entries[0].data().unwrap(), Data::Literal(b"hello"));
    assert!(!entries[0].has_external_data());
    assert!(matches!(entries[1].data(), Ok(Data::External(reference)) if reference.file == "data/y.bin"));
    assert!(entries[1].has_external_data());
    let tmp = TempDir::new("manifest-contents");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::write(dir.join("data/y.bin"), b"hello").unwrap();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let r = assemble(&mut v, &m, &mut dir_source(&dir), &AssembleOptions::default()).unwrap();
    assert_eq!((r.files, r.bytes), (2, 10));
    for name in ["/x", "/y"] {
        assert_eq!(contents(&v, name), b"hello");
    }
}

/// The data of an object is the part of its file that starts at the offset
/// and is as long as the object says, whatever else the file holds, as the
/// specification has it. A file that grew since the manifest was written is
/// copied as far as the manifest says. The file has to be long enough for
/// the data, and as long as the originalSize the manifest gives for it.
#[test]
fn files_hold_the_data_the_manifest_says() {
    let tmp = TempDir::new("manifest-sizes");
    let dir = tmp.path().to_path_buf();
    std::fs::write(dir.join("a"), b"hello world").unwrap();
    let hello = Sha256::digest(b"hello").to_string();
    let world = Sha256::digest(b"world").to_string();
    // The manifest was written when `a` held "hello". The file is found by
    // the entry's name or through a file reference.
    let m = seq(&[
        ROOT,
        &format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, hello),
        &format!(
            r#"{{"name":"b","size":5,"sha256":"{}","contents":[{{"file":"a"}}]}}"#,
            hello
        ),
        // Parts of `a`, at an offset and out of the originalSize the
        // manifest gives.
        &format!(
            r#"{{"name":"c","size":5,"sha256":"{}","contents":[{{"file":"a","offset":6}}]}}"#,
            world
        ),
        r#"{"name":"d","size":3,"contents":[{"file":"a","offset":2}]}"#,
        &format!(
            r#"{{"name":"e","size":5,"sha256":"{}","contents":[{{"file":"a","originalSize":11}}]}}"#,
            hello
        ),
        r#"{"name":"f","size":11,"contents":[{"file":"a","originalSize":11}]}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assemble(&mut v, &m, &mut dir_source(&dir), &AssembleOptions::default()).unwrap();
    for (name, data) in [
        ("/a", "hello"),
        ("/b", "hello"),
        ("/c", "world"),
        ("/d", "llo"),
        ("/e", "hello"),
        ("/f", "hello world"),
    ] {
        assert_eq!(contents(&v, name), data.as_bytes(), "{}", name);
    }
    // A file too short for the data, at an offset and as a whole, and an
    // originalSize that is not the file's, larger and smaller.
    for (record, expected) in [
        r#"{"name":"g","size":6,"contents":[{"file":"a","offset":6}]}"#,
        r#"{"name":"h","size":12,"contents":[{"file":"a"}]}"#,
        r#"{"name":"i","size":5,"contents":[{"file":"a","originalSize":12}]}"#,
        r#"{"name":"j","size":5,"contents":[{"file":"a","originalSize":5}]}"#,
    ]
    .into_iter()
    .zip([12, 12, 12, 5])
    {
        let m = seq(&[ROOT, record, TRAILER]);
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble(&mut v, &m, &mut dir_source(&dir), &AssembleOptions::default()).unwrap_err();
        assert_eq!(e.errno(), EBADMSG);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Content {
                    problem: ContentProblem::Size,
                    size: Some(11),
                    expected: Some(n),
                    ..
                }) if *n == expected
            ),
            "{}: {:?}",
            record,
            e
        );
        assert!(v.read_dir("/").unwrap().is_empty());
    }
}

/// Source and content mismatches name the file the way its record in the
/// manifest does, not as a path in the volume.
#[test]
fn mismatches_name_the_record() {
    let tmp = TempDir::new("manifest-names");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("loader/entries")).unwrap();
    std::fs::write(dir.join("loader/loader.conf"), b"timeout 3\n").unwrap();
    let conf = Sha256::digest(b"timeout 3\n").to_string();
    let other = Sha256::digest(b"timeout 5\n").to_string();
    // In the detail and in the message.
    let named = |e: Error, name: &str| {
        match e.detail() {
            Some(Detail::Source { name: n, .. } | Detail::Content { name: n, .. }) => assert_eq!(n, name, "{:?}", e),
            _ => panic!("{:?}", e),
        }
        let text = e.to_string();
        assert!(text.contains(name) && !text.contains(&format!("/{}", name)), "{}", text);
    };
    const LOADER: &str = r#"{"name":"loader","type":"dir"}"#;
    // Missing, not a regular file, too short, and the hash of the file and
    // that of the whole source. The last record of each names the file.
    let cases: [(&[&str], &str, String); 5] = [
        (
            &[LOADER, r#"{"name":"loader/entries","type":"dir"}"#],
            "loader/entries/a.conf",
            r#"{"name":"loader/entries/a.conf","size":1}"#.to_string(),
        ),
        (
            &[LOADER, r#"{"name":"x","type":"dir"}"#],
            "x/y",
            r#"{"name":"x/y","size":1,"contents":[{"file":"loader/entries"}]}"#.to_string(),
        ),
        (
            &[LOADER],
            "loader/loader.conf",
            r#"{"name":"loader/loader.conf","size":12}"#.to_string(),
        ),
        (
            &[LOADER],
            "loader/loader.conf",
            format!(r#"{{"name":"loader/loader.conf","size":10,"sha256":"{}"}}"#, other),
        ),
        (
            &[LOADER],
            "loader/loader.conf",
            format!(
                r#"{{"name":"loader/loader.conf","size":5,"contents":[{{"originalSize":10,"originalSha256":"{}"}}]}}"#,
                other
            ),
        ),
    ];
    for (directories, name, record) in &cases {
        let records = [&[ROOT][..], directories, &[record.as_str(), TRAILER]].concat();
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble(
            &mut v,
            &seq(&records),
            &mut dir_source(&dir),
            &AssembleOptions::default(),
        )
        .unwrap_err();
        named(e, name);
    }
    // From a stream that ends early or goes on after the last file.
    let m = seq(&[
        ROOT,
        LOADER,
        &format!(r#"{{"name":"loader/loader.conf","size":10,"sha256":"{}"}}"#, conf),
        TRAILER,
    ]);
    for data in [&b"timeout"[..], &b"timeout 3\nmore"[..]] {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &m, data, &AssembleOptions::default()).unwrap_err();
        named(e, "loader/loader.conf");
    }
    let missing = seq(&[ROOT, r#"{"name":"nowhere","size":1}"#, TRAILER]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let e = assemble(&mut v, &missing, &mut dir_source(&dir), &AssembleOptions::default()).unwrap_err();
    assert_eq!(e.errno(), ENOENT);
    assert!(
        matches!(
            e.detail(),
            Some(Detail::Source {
                problem: SourceProblem::Missing,
                ..
            })
        ),
        "{:?}",
        e
    );
}

#[test]
fn source_files_stay_inside_the_source_directory() {
    let tmp = TempDir::new("manifest-beneath");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("tree/sub")).unwrap();
    std::fs::write(dir.join("outside.txt"), b"outside").unwrap();
    std::fs::write(dir.join("tree/sub/inside.txt"), b"inside").unwrap();
    std::os::unix::fs::symlink("sub/inside.txt", dir.join("tree/in.lnk")).unwrap();
    std::os::unix::fs::symlink("../outside.txt", dir.join("tree/out.lnk")).unwrap();
    std::os::unix::fs::symlink(dir.join("outside.txt"), dir.join("tree/abs.lnk")).unwrap();
    let record =
        |name: &str, file: &str| format!(r#"{{"name":"{}","size":6,"contents":[{{"file":"{}"}}]}}"#, name, file);
    let base = dir.join("tree");
    let options = AssembleOptions::default();
    let (_img, mut v) = volume(8 << 20, 512, 512);
    // Plain files work; a symlink does not until asked for.
    let m = seq(&[ROOT, &record("a", "sub/inside.txt"), TRAILER]);
    assemble(&mut v, &m, &mut dir_source(&base), &options).unwrap();
    let m = seq(&[ROOT, &record("b", "in.lnk"), TRAILER]);
    assert!(assemble(&mut v, &m, &mut dir_source(&base), &options).is_err());
    let mut following = DirectorySource::new(source_dir(&base).follow_symlinks(true));
    assemble(&mut v, &m, &mut following, &options).unwrap();
    // Nothing leads out of the tree, however it is spelled.
    for file in ["out.lnk", "abs.lnk"] {
        let m = seq(&[ROOT, &record("c", file), TRAILER]);
        let mut following = DirectorySource::new(source_dir(&base).follow_symlinks(true));
        assert!(assemble(&mut v, &m, &mut following, &options).is_err(), "{}", file);
    }
    assert_eq!(v.read_dir("/").unwrap().len(), 2);
}

#[test]
fn generator_leaves_the_manifest_out() {
    let tmp = TempDir::new("manifest-generate");
    let dir = tmp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("sub")).unwrap();
    std::fs::write(dir.join("Uapi16Manifest"), b"old").unwrap();
    std::fs::write(dir.join("Uapi16Manifest.sig"), b"old").unwrap();
    std::fs::write(dir.join("Uapi16Manifest2"), b"kept").unwrap();
    std::fs::write(dir.join("sub/Uapi16Manifest"), b"kept").unwrap();
    let entries = objects(&generated(&dir));
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
}

#[test]
fn validity() {
    let revoked = seq(&[ROOT, r#"{"name":"x","size":0,"validity":"revoked"}"#, TRAILER]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let at = |now| AssembleOptions {
        now_usec: Some(now),
        ..Default::default()
    };
    assert_eq!(
        assemble_stream(&mut v, &revoked, b"", &at(1)).unwrap_err().errno(),
        EKEYREVOKED
    );
    let m = seq(&[
        ROOT,
        r#"{"name":"d","type":"dir","validUntilUSec":10}"#,
        r#"{"name":"d/x","size":0}"#,
        TRAILER,
    ]);
    assert_eq!(
        assemble_stream(&mut v, &m, b"", &at(20)).unwrap_err().errno(),
        EKEYEXPIRED
    );
    assert!(v.read_dir("/").unwrap().is_empty());
    assert!(assemble_stream(&mut v, &m, b"", &at(5)).is_ok());
    // So does the root file object, for the whole manifest.
    let expired = seq(&[
        r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint","validUntilUSec":10}"#,
        TRAILER,
    ]);
    assert_eq!(
        assemble_stream(&mut v, &expired, b"", &at(20)).unwrap_err().errno(),
        EKEYEXPIRED
    );
    // An object is checked before it is left out, also one below a
    // directory that is left out. Without the check both are left out.
    let skipping = |now_usec| AssembleOptions {
        flags: AssembleFlags::SKIP_UNSUPPORTED,
        now_usec,
        ..Default::default()
    };
    let hello = Sha256::digest(b"hello").to_string();
    let sub = format!(r#"{{"name":"sub","sha256":"{}","size":5,"type":"dir"}}"#, hello);
    for (m, skipped) in [
        (
            seq(&[
                ROOT,
                r#"{"contents":[{"literal":"eA=="}],"name":"link","type":"lnk","validity":"revoked"}"#,
                TRAILER,
            ]),
            1,
        ),
        (
            seq(&[ROOT, &sub, r#"{"name":"sub/x","size":0,"validity":"revoked"}"#, TRAILER]),
            2,
        ),
    ] {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let e = assemble_stream(&mut v, &m, b"", &skipping(Some(1))).unwrap_err();
        assert_eq!(e.errno(), EKEYREVOKED);
        assert!(v.read_dir("/").unwrap().is_empty());
        assert_eq!(
            assemble_stream(&mut v, &m, b"", &skipping(None)).unwrap().skipped,
            skipped
        );
    }
}

/// Checks the progress a long operation reported: the counts only grow
/// and end at what its report says.
fn reported(seen: &[Progress], last: Progress) {
    assert!(
        seen.windows(2)
            .all(|w| w[0].files <= w[1].files && w[0].directories <= w[1].directories && w[0].bytes <= w[1].bytes),
        "{:?}",
        seen
    );
    assert_eq!(seen.last(), Some(&last));
}

/// The long operations tell their progress callback what they did so far,
/// after every entry and every chunk of a file: a copy, the manifest of
/// what was copied, an assembly from a manifest and a removal.
#[test]
fn long_operations_report_progress() {
    let tmp = TempDir::new("progress");
    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("sub")).unwrap();
    std::fs::write(tree.join("big"), vec![0x5au8; 3 << 20]).unwrap();
    std::fs::write(tree.join("sub/small"), b"small").unwrap();
    let source = crate::host::open_dir(&tree).unwrap();
    let mut seen = Vec::new();

    let (_img, mut v) = volume(64 << 20, 512, 4096);
    let r = v
        .copy_tree_with_progress(source.as_fd(), "/tree", &CopyOptions::default(), &mut |p| seen.push(*p))
        .unwrap();
    // The big file reports its bytes in chunks, before it is done.
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: r.files,
            directories: r.directories,
            bytes: r.bytes,
        },
    );

    seen.clear();
    let w = v
        .write_manifest_with_progress(None, Features::DEFAULT, &mut Vec::new(), &mut |p| seen.push(*p))
        .unwrap();
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: w.files,
            directories: w.directories,
            bytes: w.bytes,
        },
    );

    seen.clear();
    let manifest = generated(&tree);
    let (_img2, mut v2) = volume(64 << 20, 512, 4096);
    let a = v2
        .assemble_with_observer(
            &mut Reader::open(&manifest[..]).unwrap(),
            &mut dir_source(&tree),
            &AssembleOptions::default(),
            &mut |p: &Progress| seen.push(*p),
        )
        .unwrap();
    assert!(seen.iter().any(|p| p.files == 0 && p.bytes > 0), "{:?}", seen);
    reported(
        &seen,
        Progress {
            files: a.files,
            directories: a.directories,
            bytes: a.bytes,
        },
    );

    seen.clear();
    let removed = v.remove_tree_with_progress("/tree", &mut |p| seen.push(*p)).unwrap();
    reported(
        &seen,
        Progress {
            files: removed.files,
            directories: removed.directories,
            bytes: 0,
        },
    );
    assert_eq!((removed.files, removed.directories), (2, 2));
}

#[test]
fn assemble_flags() {
    let both = AssembleFlags::REPLACE | AssembleFlags::SKIP_UNSUPPORTED;
    assert_eq!(AssembleFlags::default(), AssembleFlags::NONE);
    assert_eq!(AssembleOptions::default().flags, AssembleFlags::NONE);
    assert!(both.contains(AssembleFlags::REPLACE) && both.contains(AssembleFlags::SKIP_UNSUPPORTED));
    assert!(both.contains(both) && both.contains(AssembleFlags::NONE));
    assert!(!AssembleFlags::REPLACE.contains(AssembleFlags::SKIP_UNSUPPORTED));
    assert!(!AssembleFlags::NONE.contains(AssembleFlags::REPLACE));
    for (replace, skip) in [(false, false), (false, true), (true, false), (true, true)] {
        let flags = AssembleFlags::NONE
            .with(AssembleFlags::REPLACE, replace)
            .with(AssembleFlags::SKIP_UNSUPPORTED, skip);
        assert_eq!(flags.contains(AssembleFlags::REPLACE), replace);
        assert_eq!(flags.contains(AssembleFlags::SKIP_UNSUPPORTED), skip);
        assert_eq!(
            both.with(AssembleFlags::REPLACE, replace)
                .with(AssembleFlags::SKIP_UNSUPPORTED, skip),
            flags
        );
    }
    let mut flags = AssembleFlags::NONE;
    flags |= AssembleFlags::SKIP_UNSUPPORTED;
    assert_eq!(format!("{:?}", flags), "AssembleFlags(SKIP_UNSUPPORTED)");
    assert_eq!(format!("{:?}", both), "AssembleFlags(REPLACE | SKIP_UNSUPPORTED)");
    assert_eq!(format!("{:?}", AssembleFlags::NONE), "AssembleFlags()");
}

/// The read-only, hidden, system and archive attributes of the entry at
/// `path`.
fn dos_attributes(v: &Volume, path: &str) -> u8 {
    DosAttributes::new(v.metadata(path).unwrap().attributes).settable()
}

/// The error of reading the manifest `bytes` is an UnlistedFeature at
/// record 1, the object `name`, field `field`.
fn assert_unlisted(bytes: &[u8], name: &str, field: &str) {
    let e = read(bytes).unwrap_err();
    assert_eq!(
        e.detail(),
        Some(&Detail::Manifest {
            problem: ManifestProblem::Malformed(Problem::UnlistedFeature),
            record: Some(1),
            name: Some(name.to_string()),
            field: Some(field.to_string()),
        })
    );
}

#[test]
fn applies_the_dos_attributes() {
    // A manifest that records the read-only attribute and the flags of the
    // archive, hidden and system attributes: an object without one of them
    // has the attribute cleared, also the archive attribute a new file has
    // otherwise.
    let root = concat!(
        r#"{"features":["flag-archive","flag-hidden","flag-system","read-only","sha256","size"],"#,
        r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
    );
    let flagged = seq(&[
        root,
        r#"{"flagHidden":true,"flagSystem":true,"name":"d","type":"dir"}"#,
        r#"{"flagArchive":true,"name":"d/a","size":0}"#,
        r#"{"name":"d/b","size":0}"#,
        r#"{"flagHidden":true,"name":"h","readOnly":true,"size":0}"#,
        r#"{"name":"plain","type":"dir"}"#,
        r#"{"name":"ro","readOnly":true,"type":"dir"}"#,
        r#"{"name":"unlocked","readOnly":true,"type":"dir"}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assemble_stream(&mut v, &flagged, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/d"), ATTR_HIDDEN | ATTR_SYSTEM);
    assert_eq!(dos_attributes(&v, "/d/a"), ATTR_ARCHIVE);
    assert_eq!(dos_attributes(&v, "/d/b"), NO_ATTRIBUTES);
    assert_eq!(dos_attributes(&v, "/h"), ATTR_HIDDEN | ATTR_READ_ONLY);
    assert_eq!(dos_attributes(&v, "/plain"), NO_ATTRIBUTES);
    assert_eq!(dos_attributes(&v, "/ro"), ATTR_READ_ONLY);
    assert_eq!(dos_attributes(&v, "/unlocked"), ATTR_READ_ONLY);
    // Without the features nothing is known about the flags: a new file
    // keeps its archive attribute, and a flag that is not listed cannot be
    // given at all, nor can readOnly.
    let unflagged = seq(&[ROOT, r#"{"name":"f","size":0}"#, TRAILER]);
    assemble_stream(&mut v, &unflagged, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/f"), ATTR_ARCHIVE);
    let hidden = seq(&[ROOT, r#"{"flagHidden":true,"name":"g","size":0}"#, TRAILER]);
    assert_unlisted(&hidden, "g", "flagHidden");
    let read_only = seq(&[ROOT, r#"{"name":"g","readOnly":true,"size":0}"#, TRAILER]);
    assert_unlisted(&read_only, "g", "readOnly");
    // A directory that is there takes the attributes of its object as
    // well: the flags the manifest lists, and the read-only attribute,
    // which is cleared where the object does not say it is read-only. The
    // system attribute, which this manifest does not list, stays, and so
    // does everything of a directory the manifest does not name.
    let cleared = seq(&[
        concat!(
            r#"{"features":["flag-hidden"],"#,
            r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
        ),
        r#"{"name":"d","type":"dir"}"#,
        r#"{"name":"unlocked","type":"dir"}"#,
        TRAILER,
    ]);
    assemble_stream(&mut v, &cleared, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/d"), ATTR_SYSTEM);
    assert_eq!(dos_attributes(&v, "/unlocked"), NO_ATTRIBUTES);
    assert_eq!(dos_attributes(&v, "/ro"), ATTR_READ_ONLY);
    // The manifest of the volume says what the volume holds, for files and
    // directories, a read-only one among them. The assembly of it gives the
    // same attributes again, and the manifest of that volume is the same.
    let features = Features::from_names(["flag-archive", "flag-hidden", "flag-system", "size", "sha256"]).unwrap();
    let mut written = Vec::new();
    v.write_manifest(None, features, &mut written).unwrap();
    let (root, objects) = read(&written).unwrap();
    assert!(root.recorded_features().contains(Features::READ_ONLY));
    let object = |name: &str| objects.iter().find(|o| o.name == name).unwrap();
    let d = object("d").dos_flags;
    assert_eq!(
        (
            d.get(DosFlags::HIDDEN),
            d.get(DosFlags::SYSTEM),
            d.get(DosFlags::ARCHIVE)
        ),
        (Some(false), Some(true), Some(false))
    );
    assert_eq!(object("d/a").dos_flags.get(DosFlags::ARCHIVE), Some(true));
    assert_eq!(object("d/b").dos_flags.get(DosFlags::ARCHIVE), Some(false));
    assert_eq!(object("f").dos_flags.get(DosFlags::ARCHIVE), Some(true));
    assert_eq!(object("h").dos_flags.get(DosFlags::HIDDEN), Some(true));
    assert!(object("h").inode.is_read_only());
    assert!(object("ro").inode.is_read_only());
    assert!(!object("unlocked").inode.is_read_only());
    let (_img, mut again) = volume(8 << 20, 512, 512);
    assemble_stream(&mut again, &written, b"", &AssembleOptions::default()).unwrap();
    for path in ["/d", "/d/a", "/d/b", "/f", "/h", "/plain", "/ro", "/unlocked"] {
        assert_eq!(dos_attributes(&again, path), dos_attributes(&v, path), "{}", path);
    }
    let mut rewritten = Vec::new();
    again.write_manifest(None, features, &mut rewritten).unwrap();
    assert_eq!(rewritten, written);
    // Without the features no flag is written.
    let mut written = Vec::new();
    v.write_manifest(None, Features::DEFAULT, &mut written).unwrap();
    assert!(read(&written)
        .unwrap()
        .1
        .iter()
        .all(|o| o.dos_flags == FlagStates::default()));
}

/// A mode that gives nobody write permission stands in for readOnly only
/// where the manifest does not list read-only, for files and directories,
/// new ones and those that are there.
#[test]
fn a_mode_stands_in_for_read_only_where_it_is_not_listed() {
    // The default features have mode and not read-only.
    let unlisted = seq(&[
        ROOT,
        r#"{"mode":365,"name":"locked","type":"dir"}"#,
        r#"{"mode":292,"name":"locked/f","size":0}"#,
        r#"{"mode":420,"name":"locked/g","size":0}"#,
        r#"{"mode":493,"name":"open","type":"dir"}"#,
        TRAILER,
    ]);
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assemble_stream(&mut v, &unlisted, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/locked"), ATTR_READ_ONLY);
    assert_eq!(dos_attributes(&v, "/locked/f"), ATTR_ARCHIVE | ATTR_READ_ONLY);
    assert_eq!(dos_attributes(&v, "/locked/g"), ATTR_ARCHIVE);
    assert_eq!(dos_attributes(&v, "/open"), NO_ATTRIBUTES);
    // Where the manifest lists read-only, an object without readOnly is not
    // read-only, whatever its mode says.
    let listed = seq(&[
        concat!(
            r#"{"features":["mode","read-only","size"],"#,
            r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
        ),
        r#"{"mode":365,"name":"locked","type":"dir"}"#,
        r#"{"mode":292,"name":"locked/h","size":0}"#,
        r#"{"mode":365,"name":"open","type":"dir"}"#,
        TRAILER,
    ]);
    assemble_stream(&mut v, &listed, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/locked"), NO_ATTRIBUTES);
    assert_eq!(dos_attributes(&v, "/locked/h"), ATTR_ARCHIVE);
    assert_eq!(dos_attributes(&v, "/open"), NO_ATTRIBUTES);
    // Without it, the mode decides for a directory that is there too.
    let again = seq(&[ROOT, r#"{"mode":365,"name":"open","type":"dir"}"#, TRAILER]);
    assemble_stream(&mut v, &again, b"", &AssembleOptions::default()).unwrap();
    assert_eq!(dos_attributes(&v, "/open"), ATTR_READ_ONLY);
}

#[test]
fn dos_attributes_and_flags() {
    use crate::dirent::ATTR_DIRECTORY;
    let all = Features::FLAG_HIDDEN | Features::FLAG_SYSTEM | Features::FLAG_ARCHIVE;
    let attributes = DosAttributes::new(ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_READ_ONLY);
    let states = attributes.flag_states(all);
    assert_eq!(states.get(DosFlags::HIDDEN), Some(true));
    assert_eq!(states.get(DosFlags::SYSTEM), Some(false));
    assert_eq!(states.get(DosFlags::ARCHIVE), Some(false));
    // A flag the manifest does not record is not known.
    assert_eq!(
        attributes.flag_states(Features::FLAG_SYSTEM).get(DosFlags::HIDDEN),
        None
    );
    assert_eq!(attributes.settable(), ATTR_HIDDEN | ATTR_READ_ONLY);
    // Setting flags touches what they state and nothing else.
    let mut states = FlagStates::default();
    states.put(DosFlags::HIDDEN, Some(false));
    states.put(DosFlags::ARCHIVE, Some(true));
    let changed = attributes.with_flags(states);
    assert_eq!(
        changed,
        DosAttributes::new(ATTR_DIRECTORY | ATTR_READ_ONLY | ATTR_ARCHIVE)
    );
    assert_eq!(changed.with_flags(FlagStates::default()), changed);
    assert_eq!(
        changed.with_read_only(false),
        DosAttributes::new(ATTR_DIRECTORY | ATTR_ARCHIVE)
    );
    assert_eq!(changed.with_read_only(true), changed);
    // An object gives the read-only attribute as it is read-only or not,
    // and the flags it states: one with neither readOnly nor a mode is not
    // read-only, and a mode without write permission stands in for
    // readOnly.
    let mut object = FileObject::new(Name::new("x").unwrap());
    object.dos_flags = states;
    assert_eq!(
        DosAttributes::NONE.with_object(&object),
        DosAttributes::new(ATTR_ARCHIVE)
    );
    assert_eq!(attributes.with_object(&object), changed.with_read_only(false));
    object.inode.mode = Mode::new(0o444);
    assert_eq!(attributes.with_object(&object), changed);
    object.inode.mode = Mode::new(0o644);
    assert_eq!(attributes.with_object(&object), changed.with_read_only(false));
    object.inode.mode = None;
    object.inode.read_only = Some(true);
    assert_eq!(attributes.with_object(&object), changed);
    // What the attributes of an entry record in its object, an object
    // gives back, for every combination of the four.
    let recorded = all | Features::READ_ONLY;
    for bits in NO_ATTRIBUTES..=SETTABLE_ATTRIBUTES {
        if bits & !SETTABLE_ATTRIBUTES != 0 {
            continue;
        }
        let mut object = FileObject::new(Name::new("x").unwrap());
        DosAttributes::new(ATTR_DIRECTORY | bits).record_in(&mut object, recorded);
        assert_eq!(
            object.inode.read_only,
            Some(bits & ATTR_READ_ONLY != 0),
            "{:#04x}",
            bits
        );
        assert_eq!(
            DosAttributes::NONE.with_object(&object),
            DosAttributes::new(bits),
            "{:#04x}",
            bits
        );
    }
    // Without read-only it records no readOnly.
    let mut object = FileObject::new(Name::new("x").unwrap());
    DosAttributes::new(ATTR_READ_ONLY).record_in(&mut object, all);
    assert_eq!(object.inode.read_only, None);
}
