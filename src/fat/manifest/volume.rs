// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing the manifest of what a volume holds: the UAPI.16 description of
//! every file and directory in it, in the stored form.
//!
//! This is the manifest the Varlink interface's `ManifestSink` receives
//! from Assemble, Populate and Describe, see
//! docs/org.uapi-group.FileSystem.varlink. It says what the volume stores
//! as the volume stores it:
//! times at FAT's 2 s, the read-only attribute as `readOnly`, and no mode,
//! owner, device numbers, hardlinks or extended attributes, since FAT has
//! no notion of them. A field the file system has no notion of is left out
//! and not counted; what FAT keeps and the manifest could not record is
//! counted in the report's `omitted`.
//!
//! The order is the specification's: the root object first, every
//! directory's entries right after it, sorted by the bytes of their names
//! and never in on-disk order, the trailer last. Keys inside an object are
//! sorted and the records carry no whitespace, as `systemd-manifest`
//! writes them. Like `systemd-manifest` and the host tree generator, the
//! writer leaves out the inode type on the root object and on regular
//! files, where the specification implies it. So with the same fields, the
//! manifest of a volume is the one they write for the tree the volume was
//! filled from, apart from what FAT changes on the way: FAT keeps times at
//! 2 s, and a read-only file gets `readOnly`.

use std::collections::HashSet;
use std::io::Write;
use std::time::SystemTime;

use shared::manifest::WriteReport;
use uapi16::{Fields, FileObject, InodeType, Name, Sha256, Writer};

use crate::dirent::ATTR_READ_ONLY;
use crate::errno::*;
use crate::progress::Progress;
use crate::sha256;
use crate::volume::Volume;
use crate::{CorruptPlace, Detail, Result};

impl Volume {
    /// Writes the UAPI.16 manifest of everything the volume holds to `out`:
    /// the root object, one object per entry, the trailer. `root_time` is
    /// the time the root object carries when `fields` has
    /// [`Fields::MTIME`]: the root directory of a FAT volume has no entry
    /// of its own and so no time, the caller passes the one it knows, the
    /// source directory's or the label entry's. Each record goes out in
    /// one write and `out` is flushed at the end, so a descriptor wants a
    /// `BufWriter` around it.
    ///
    /// The inode type is always given, and `readOnly` is written where the
    /// attribute is set, which no field governs. FAT has no mode, owner,
    /// symbolic links, device nodes, hardlinks, extended attributes or
    /// user and group names, so of the fields only [`Fields::SIZE`],
    /// [`Fields::HASH`] and [`Fields::MTIME`] change what is written.
    ///
    /// Names the manifest cannot carry are left out, with everything below
    /// them. The names the specification reserves in the top level for the
    /// manifest itself and its signatures (`Uapi16Manifest`,
    /// `Uapi16Manifest.*`) are left out silently, as `systemd-manifest`
    /// leaves them out; any other, a component of more than 255 bytes of
    /// UTF-8 for instance, which FAT stores in UTF-16 but no manifest
    /// reader takes, is counted in the report's `omitted`.
    pub fn write_manifest(
        &self,
        root_time: Option<SystemTime>,
        fields: Fields,
        out: &mut dyn Write,
    ) -> Result<WriteReport> {
        self.write_manifest_with_progress(root_time, fields, out, &mut |_| {})
    }

    /// [`Volume::write_manifest`], telling `progress` what the manifest
    /// covers so far after every entry and every chunk of a file it reads
    /// for the hash.
    pub fn write_manifest_with_progress(
        &self,
        root_time: Option<SystemTime>,
        fields: Fields,
        out: &mut dyn Write,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<WriteReport> {
        let top = self.metadata("/")?;
        // The root object is a directory by definition and carries no type.
        let mut root = FileObject::root();
        if let Some(time) = root_time.filter(|_| fields.contains(Fields::MTIME)) {
            root.set_mtime(time);
        }
        let mut listing = Listing {
            volume: self,
            fields,
            writer: Writer::begin(out, &root)?,
            report: WriteReport::default(),
            buf: vec![0u8; self.layout().cluster_size() as usize],
            seen: HashSet::from([top.first_cluster]),
            progress,
        };
        listing.directory("/", &Name::ROOT)?;
        listing.writer.finish()?;
        Ok(listing.report)
    }
}

/// The manifest of a volume while it is written.
struct Listing<'a, W: Write> {
    volume: &'a Volume,
    fields: Fields,
    writer: Writer<W>,
    report: WriteReport,
    /// One cluster, the most one read of a file returns.
    buf: Vec<u8>,
    /// First clusters of the root and of every directory written so far. A
    /// directory reached twice is a cross-linked or looping tree; without
    /// the check a loop would run until the path limit.
    seen: HashSet<u32>,
    progress: &'a mut dyn FnMut(&Progress),
}

impl<W: Write> Listing<'_, W> {
    /// Writes the entries of the directory at `path` inside the volume,
    /// whose name in the manifest is `prefix` (the root's for the root),
    /// sorted by the bytes of their names, each directory followed by what
    /// is below it.
    fn directory(&mut self, path: &str, prefix: &Name) -> Result<()> {
        let mut entries = self.volume.read_dir(path)?;
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for md in &entries {
            let name = if prefix.is_root() {
                md.name.clone()
            } else {
                format!("{}/{}", prefix, md.name)
            };
            let path = crate::path::join(path, &md.name);
            // A name that is reserved for the manifest is left out and is
            // no omission.
            if Name::is_reserved(&name) {
                continue;
            }
            let name = match Name::new(name) {
                Ok(name) if path.len() <= crate::path::MAX_PATH => name,
                _ => {
                    self.report.omitted += 1;
                    continue;
                }
            };
            // A regular file is what an object without a type is.
            let mut object = FileObject::new(name);
            if md.attributes & ATTR_READ_ONLY != 0 {
                object.read_only = Some(true);
            }
            if self.fields.contains(Fields::MTIME) {
                object.set_mtime(md.modified);
            }
            if md.is_dir {
                if !self.seen.insert(md.first_cluster) {
                    bail!(
                        EUCLEAN,
                        Detail::Corrupt {
                            place: CorruptPlace::Directory,
                            field: None,
                            path: Some(path.clone()),
                            cluster: Some(md.first_cluster),
                        },
                        "'{}' is a directory reached before, the directory tree is cross-linked or loops",
                        path
                    );
                }
                object.inode_type = InodeType::Directory;
                self.writer.file(&object)?;
                self.report.directories += 1;
                (self.progress)(&self.report.progress());
                self.directory(&path, &object.name)?;
            } else {
                if self.fields.contains(Fields::SIZE) {
                    object.size = Some(md.size);
                }
                if self.fields.contains(Fields::HASH) {
                    object.sha256 = Some(self.hash(&path)?);
                }
                self.writer.file(&object)?;
                self.report.files += 1;
                self.report.bytes += md.size;
                (self.progress)(&self.report.progress());
            }
        }
        Ok(())
    }

    /// The SHA-256 of the file at `path`, read from the volume.
    fn hash(&mut self, path: &str) -> Result<Sha256> {
        let mut file = self.volume.begin_read(path)?;
        let mut hasher = sha256::Sha256::new();
        let mut done = self.report.progress();
        loop {
            let n = self.volume.read_file_data(&mut file, &mut self.buf)?;
            if n == 0 {
                return Ok(Sha256::from(hasher.finalize()));
            }
            hasher.update(&self.buf[..n]);
            done.bytes += n as u64;
            (self.progress)(&done);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{HostTree, Manifest};
    use crate::populate::CopyOptions;
    use crate::test_util::{volume, TempDir, TempImage};
    use json::Object;
    use std::os::fd::AsFd;
    use std::time::{Duration, UNIX_EPOCH};
    use uapi16::{Digest, RECORD_SEPARATOR};

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// Creates a file with `data`.
    fn put(v: &mut Volume, path: &str, data: &[u8], time: SystemTime, read_only: bool) {
        let mut w = v.create_file(path, time, false).unwrap();
        w.write_all(data).unwrap();
        w.set_read_only(read_only);
        w.finish().unwrap();
    }

    /// Several clusters of a pattern.
    fn boot_data() -> Vec<u8> {
        (0..5000u32).map(|i| (i % 251) as u8).collect()
    }

    /// The names of the tree below, in the order the manifest lists them:
    /// by bytes, so the upper case names and the underscore come before
    /// the lower case ones, and each directory's entries right after it.
    const NAMES: [&str; 9] = [
        "B.txt",
        "EFI",
        "EFI/BOOT",
        "EFI/BOOT/BOOTX64.EFI",
        "EFI/a.txt",
        "_notes",
        "_notes/empty",
        "a.txt",
        "zz",
    ];

    /// A volume with a few directories and files, created in an order that
    /// is neither the sorted one nor the reverse, so that on-disk order
    /// would show.
    fn populated() -> (TempImage, Volume) {
        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        put(&mut v, "/a.txt", b"lower a", t0, false);
        v.create_dir("/zz", t0).unwrap();
        v.create_dir_all("/EFI/BOOT", t0).unwrap();
        put(&mut v, "/EFI/BOOT/BOOTX64.EFI", &boot_data(), t(1_700_000_002), true);
        put(&mut v, "/EFI/a.txt", b"first file", t0, false);
        v.create_dir("/_notes", t0).unwrap();
        put(&mut v, "/_notes/empty", b"", t0, false);
        put(&mut v, "/B.txt", b"upper B", t0, false);
        (img, v)
    }

    /// The same tree on the host, with times FAT keeps as they are: the
    /// files two seconds apart, the directories all at one time.
    fn host_tree() -> TempDir {
        let tmp = TempDir::new("manifest-volume");
        let dir = tmp.path();
        std::fs::create_dir_all(dir.join("EFI/BOOT")).unwrap();
        std::fs::create_dir_all(dir.join("_notes")).unwrap();
        std::fs::create_dir_all(dir.join("zz")).unwrap();
        let files = [
            ("a.txt", &b"lower a"[..]),
            ("EFI/BOOT/BOOTX64.EFI", &boot_data()),
            ("EFI/a.txt", b"first file"),
            ("_notes/empty", b""),
            ("B.txt", b"upper B"),
        ];
        for (i, (name, data)) in files.iter().enumerate() {
            std::fs::write(dir.join(name), data).unwrap();
            std::fs::File::options()
                .write(true)
                .open(dir.join(name))
                .unwrap()
                .set_modified(t(1_700_000_000 + 2 * i as u64))
                .unwrap();
        }
        // The directories last, since what goes into them changes their
        // times.
        for name in ["EFI/BOOT", "EFI", "_notes", "zz", "."] {
            std::fs::File::open(dir.join(name))
                .unwrap()
                .set_modified(t(1_699_999_000))
                .unwrap();
        }
        tmp
    }

    fn written(v: &Volume, root_time: Option<SystemTime>, fields: Fields) -> (Vec<u8>, WriteReport) {
        let mut out = Vec::new();
        let report = v.write_manifest(root_time, fields, &mut out).unwrap();
        (out, report)
    }

    /// The records as text and as objects, to look at what the parser
    /// drops. Checks the frame on the way: one separator, one newline per
    /// record, keys sorted, no whitespace (none of the names here has any).
    fn records(bytes: &[u8]) -> Vec<(String, Object)> {
        let text = std::str::from_utf8(bytes).unwrap();
        assert!(text.starts_with(RECORD_SEPARATOR as char));
        text.split(RECORD_SEPARATOR as char)
            .skip(1)
            .map(|r| {
                let r = r.strip_suffix('\n').unwrap();
                assert!(!r.chars().any(char::is_whitespace), "{}", r);
                let o = match json::parse(r).unwrap() {
                    json::Value::Object(o) => o,
                    other => panic!("{} is not an object", other),
                };
                let keys: Vec<&str> = o.keys().collect();
                let mut sorted = keys.clone();
                sorted.sort_unstable();
                assert_eq!(keys, sorted, "{}", r);
                (r.to_string(), o)
            })
            .collect()
    }

    fn names(m: &Manifest) -> Vec<&str> {
        m.entries.iter().map(|e| e.name.as_str()).collect()
    }

    fn entry<'a>(m: &'a Manifest, name: &str) -> &'a FileObject {
        m.entries.iter().find(|e| e.name == name).unwrap()
    }

    #[test]
    fn writes_what_the_volume_holds() {
        let (_img, v) = populated();
        let (bytes, report) = written(&v, None, Fields::default());
        assert_eq!(
            report,
            WriteReport {
                files: 5,
                directories: 4,
                bytes: 7 + 5000 + 10 + 7,
                omitted: 0,
            }
        );
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), NAMES);
        use InodeType::{Directory as D, Regular as R};
        let types: Vec<InodeType> = m.entries.iter().map(|e| e.inode_type).collect();
        assert_eq!(types, [R, D, D, R, R, D, R, R, D]);
        assert_eq!(m.root.inode_type, D);
        assert_eq!(m.root.mtime_nsec, None);
        for (name, data) in [
            ("B.txt", &b"upper B"[..]),
            ("EFI/BOOT/BOOTX64.EFI", &boot_data()),
            ("EFI/a.txt", b"first file"),
            ("_notes/empty", b""),
            ("a.txt", b"lower a"),
        ] {
            let e = entry(&m, name);
            assert_eq!(e.size, Some(data.len() as u64), "{}", name);
            assert_eq!(e.sha256, Some(Sha256::of(data)), "{}", name);
        }
        assert_eq!(entry(&m, "_notes/empty").sha256, Some(Sha256::EMPTY));
        for name in ["EFI", "EFI/BOOT", "_notes", "zz"] {
            assert_eq!((entry(&m, name).size, entry(&m, name).sha256), (None, None), "{}", name);
        }
        let boot = entry(&m, "EFI/BOOT/BOOTX64.EFI");
        assert_eq!(boot.read_only, Some(true));
        assert!(boot.is_read_only());
        for e in m.entries.iter().filter(|e| e.name != "EFI/BOOT/BOOTX64.EFI") {
            assert_eq!(e.read_only, None, "{:?}", e.name);
            assert!(!e.is_read_only());
        }
        assert!(m.entries.iter().all(|e| e.mtime_nsec.is_none() && e.mode.is_none()));

        // The raw records: the root object, one per entry, the trailer. As
        // systemd-manifest writes them, the root object and the regular
        // files carry no type, and FAT has no extended attributes to list.
        let recs = records(&bytes);
        assert_eq!(recs.len(), 1 + NAMES.len() + 1);
        assert_eq!(recs[0].0, r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#);
        assert_eq!(recs[2].0, r#"{"name":"EFI","type":"dir"}"#);
        assert_eq!(
            recs[4].0,
            format!(
                r#"{{"name":"EFI/BOOT/BOOTX64.EFI","readOnly":true,"sha256":"{}","size":5000}}"#,
                Sha256::of(&boot_data())
            )
        );
        assert_eq!(
            recs[7].0,
            format!(r#"{{"name":"_notes/empty","sha256":"{}","size":0}}"#, Sha256::EMPTY)
        );
        assert_eq!(recs[10].0, r#"{"mediaType":"application/vnd.uapi.16.trailer"}"#);
        for ((text, o), e) in recs[1..=NAMES.len()].iter().zip(&m.entries) {
            assert_eq!(
                o.get("type").and_then(json::Value::as_str),
                (e.inode_type == D).then_some("dir"),
                "{}",
                text
            );
            for key in [
                "mediaType",
                "mode",
                "uid",
                "gid",
                "inodeToken",
                "major",
                "minor",
                "userName",
                "groupName",
                "mTimeNSec",
                "contents",
                "extendedAttributes",
            ] {
                assert!(!o.contains_key(key), "{} in {}", key, text);
            }
        }
    }

    #[test]
    fn fields_govern_what_is_written() {
        let (_img, v) = populated();
        // Nothing but names and the types of directories, and the attribute
        // no field governs.
        let (bytes, report) = written(&v, Some(t(1_600_000_000)), Fields::NONE);
        assert_eq!((report.files, report.directories, report.bytes), (5, 4, 5024));
        let recs = records(&bytes);
        assert_eq!(recs[0].0, r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#);
        assert_eq!(recs[1].0, r#"{"name":"B.txt"}"#);
        assert_eq!(recs[2].0, r#"{"name":"EFI","type":"dir"}"#);
        assert_eq!(recs[4].0, r#"{"name":"EFI/BOOT/BOOTX64.EFI","readOnly":true}"#);
        for (text, o) in &recs[1..=NAMES.len()] {
            let keys: Vec<&str> = o.keys().filter(|k| *k != "readOnly").collect();
            let name = o.get("name").and_then(json::Value::as_str).unwrap();
            let expected: &[&str] = if ["EFI", "EFI/BOOT", "_notes", "zz"].contains(&name) {
                &["name", "type"]
            } else {
                &["name"]
            };
            assert_eq!(keys, expected, "{}", text);
        }
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), NAMES);
        assert_eq!(m.root.mtime_nsec, None);
        assert!(m.entries.iter().all(|e| e.size.is_none() && e.sha256.is_none()));

        // Sizes without hashes, hashes without sizes. The empty file's hash
        // alone still tells the reader its size.
        let (bytes, _) = written(&v, None, Fields::from_names(["size"]).unwrap());
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(entry(&m, "a.txt").size, Some(7));
        assert_eq!(entry(&m, "a.txt").sha256, None);
        let (bytes, _) = written(&v, None, Fields::from_names(["hash"]).unwrap());
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(entry(&m, "a.txt").size, None);
        assert_eq!(entry(&m, "a.txt").sha256, Some(Sha256::of(b"lower a")));
        assert_eq!(entry(&m, "_notes/empty").size, Some(0));
        assert!(!records(&bytes)[7].1.contains_key("size"));

        // Times: the stored ones, which FAT keeps at 2 s, and the root's
        // only when the caller has one.
        let fields = Fields::MTIME;
        let (bytes, _) = written(&v, None, fields);
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(m.root.mtime_nsec, None);
        for e in &m.entries {
            let stored = v.metadata(&format!("/{}", e.name)).unwrap().modified;
            assert_eq!(e.mtime(), Some(stored), "{}", e.name);
        }
        assert_eq!(
            entry(&m, "EFI/BOOT/BOOTX64.EFI").mtime_nsec,
            Some(1_700_000_002 * 1_000_000_000)
        );
        assert_eq!(entry(&m, "zz").mtime_nsec, Some(1_700_000_000 * 1_000_000_000));
        let root_time = t(1_600_000_000) + Duration::from_nanos(5);
        let (bytes, _) = written(&v, Some(root_time), fields);
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(m.root.mtime_nsec, Some(1_600_000_000_000_000_005));
        assert_eq!(m.root.mtime(), Some(root_time));
        assert_eq!(
            records(&bytes)[0].0,
            r#"{"mTimeNSec":1600000000000000005,"mediaType":"application/vnd.uapi.16.manifest"}"#
        );
        // Without the field the caller's time is not written either.
        let (bytes, _) = written(&v, Some(root_time), Fields::default());
        assert_eq!(Manifest::parse(&bytes).unwrap().root.mtime_nsec, None);
    }

    #[test]
    fn agrees_with_the_host_tree_generator() {
        let tree = host_tree();
        let dir = crate::host::open_dir(tree.path()).unwrap();
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let copied = v.copy_tree(dir.as_fd(), "/", &CopyOptions::default()).unwrap();
        assert_eq!((copied.files, copied.directories), (5, 4));
        // The generator writes the fields size, hash and mtime. With the
        // tree's own time for the root and times FAT keeps as they are, the
        // two manifests are the same bytes.
        let mut host = Vec::new();
        HostTree::new(dir.as_fd()).write_manifest(&mut host).unwrap();
        let root_time = std::fs::metadata(tree.path()).unwrap().modified().unwrap();
        let fields = Fields::from_names(["size", "hash", "mtime"]).unwrap();
        let (bytes, report) = written(&v, Some(root_time), fields);
        assert_eq!(String::from_utf8_lossy(&bytes), String::from_utf8_lossy(&host));
        assert_eq!(names(&Manifest::parse(&bytes).unwrap()), NAMES);
        assert_eq!((report.files, report.directories, report.bytes), (5, 4, copied.bytes));
    }

    #[test]
    fn names_the_manifest_cannot_carry() {
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        // The reserved names of the top level, as the generator leaves them
        // out: they are the manifest's own.
        put(&mut v, "/Uapi16Manifest", b"old", t0, false);
        put(&mut v, "/Uapi16Manifest.sig", b"old", t0, false);
        put(&mut v, "/Uapi16Manifest2", b"kept", t0, false);
        v.create_dir("/sub", t0).unwrap();
        put(&mut v, "/sub/Uapi16Manifest", b"kept", t0, false);
        let (bytes, report) = written(&v, None, Fields::default());
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), ["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
        assert_eq!(
            report,
            WriteReport {
                files: 2,
                directories: 1,
                bytes: 8,
                omitted: 0,
            }
        );

        // A name of 100 three-byte characters is 100 UTF-16 units, which
        // FAT stores, but 300 bytes of UTF-8, more than a manifest
        // component may have. Such entries are left out and counted, a
        // directory with everything below it as one.
        let long: String = std::iter::repeat_n('\u{20ac}', 100).collect();
        v.create_dir(&format!("/{}", long), t0).unwrap();
        put(&mut v, &format!("/{}/inside", long), b"x", t0, false);
        put(&mut v, &format!("/sub/{}", long), b"y", t0, false);
        let (bytes, report) = written(&v, None, Fields::default());
        let m = Manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), ["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
        assert_eq!((report.files, report.directories, report.omitted), (2, 1, 2));
    }

    #[test]
    fn a_cross_linked_directory_tree_is_refused() {
        use crate::bytes::le16_at;
        use crate::dirent::{self, ATTR_DIRECTORY, DIR_ENTRY_SIZE};

        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir_all("/a/b", t0).unwrap();
        put(&mut v, "/a/b/x", b"x", t0, false);
        let a = v.metadata("/a").unwrap();
        let b = v.metadata("/a/b").unwrap();
        let offset = v.layout().cluster_offset(a.first_cluster).unwrap();
        let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
        v.close().unwrap();
        // Point the entry of "b" inside "a" back at "a". The first cluster
        // of an entry is split over a high and a low half; the entry is the
        // directory one, not a dot entry, that refers to b's cluster.
        let dev = img.device();
        dev.read_at(offset, &mut cluster).unwrap();
        let slot = (0..cluster.len() / DIR_ENTRY_SIZE)
            .find(|&i| {
                let e = &cluster[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE];
                let first = (u32::from(le16_at(e, dirent::field::FIRST_CLUSTER_HI)) << u16::BITS)
                    | u32::from(le16_at(e, dirent::field::FIRST_CLUSTER_LO));
                !e[dirent::field::NAME].starts_with(b".")
                    && e[dirent::field::ATTR] & ATTR_DIRECTORY != 0
                    && first == b.first_cluster
            })
            .unwrap();
        // Where that entry is in the image: slot `slot` of the cluster at
        // `offset`.
        let at = offset + (slot * DIR_ENTRY_SIZE) as u64;
        dev.write_at(
            at + dirent::field::FIRST_CLUSTER_HI.start as u64,
            &((a.first_cluster >> u16::BITS) as u16).to_le_bytes(),
        )
        .unwrap();
        dev.write_at(
            at + dirent::field::FIRST_CLUSTER_LO.start as u64,
            &(a.first_cluster as u16).to_le_bytes(),
        )
        .unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = v.write_manifest(None, Fields::NONE, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if p == "/a/b" && *c == a.first_cluster
            ),
            "{:?}",
            e
        );
        // What was written before the walk ran into it is intact.
        let recs = records(&out);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].0, r#"{"name":"a","type":"dir"}"#);
    }
}
