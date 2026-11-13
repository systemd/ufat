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

use json::Object;

use super::generate::{time_nsec, write_record};
use super::{valid_name, FILENAME, MEDIA_TYPE, TRAILER_MEDIA_TYPE};
use crate::dirent::ATTR_READ_ONLY;
use crate::errno::*;
use crate::progress::Progress;
use crate::sha256::{self, Sha256, DIGEST_SIZE};
use crate::volume::Volume;
use crate::{CorruptPlace, Detail, Result};

/// The per-file fields a written manifest carries: systemd-manifest's
/// vocabulary, the names its `--field=` and repart's `--manifest-fields=`
/// take, as the Varlink interface's `ManifestField` spells them. The inode
/// type is always given, and `readOnly` is written where the attribute is
/// set, which no field governs. FAT has no mode, owner, symbolic links,
/// device nodes, hardlinks, extended attributes or user and group names,
/// so of these only `size`, `hash` and `mtime` change what the volume
/// writer puts out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    /// `mode`: the access mode.
    pub mode: bool,
    /// `uid`: the owning user.
    pub uid: bool,
    /// `gid`: the owning group.
    pub gid: bool,
    /// `size`: the size of regular files.
    pub size: bool,
    /// `hash`: the SHA-256 of regular files.
    pub hash: bool,
    /// `symlink`: the target of symbolic links.
    pub symlink: bool,
    /// `device`: the numbers of device nodes.
    pub device: bool,
    /// `hardlink`: the hardlink group token.
    pub hardlink: bool,
    /// `mtime`: the modification time.
    pub mtime: bool,
    /// `userXattr`: the extended attributes of the user namespace.
    pub user_xattr: bool,
    /// `userName`: the owning user's name.
    pub user_name: bool,
    /// `groupName`: the owning group's name.
    pub group_name: bool,
}

impl Default for Fields {
    /// systemd's default set: everything but `mtime`, `userName` and
    /// `groupName`.
    fn default() -> Fields {
        Fields {
            mode: true,
            uid: true,
            gid: true,
            size: true,
            hash: true,
            symlink: true,
            device: true,
            hardlink: true,
            mtime: false,
            user_xattr: true,
            user_name: false,
            group_name: false,
        }
    }
}

impl Fields {
    /// No field at all: the manifest carries the names and the inode types,
    /// and `readOnly` where the attribute is set.
    pub fn none() -> Fields {
        Fields {
            mode: false,
            uid: false,
            gid: false,
            size: false,
            hash: false,
            symlink: false,
            device: false,
            hardlink: false,
            mtime: false,
            user_xattr: false,
            user_name: false,
            group_name: false,
        }
    }

    /// The fields named with the interface's names: `mode`, `uid`, `gid`,
    /// `size`, `hash`, `symlink`, `device`, `hardlink`, `mtime`,
    /// `userXattr`, `userName` and `groupName`. None when a name is not one
    /// of them.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Option<Fields> {
        let mut fields = Fields::none();
        for name in names {
            match name {
                "mode" => fields.mode = true,
                "uid" => fields.uid = true,
                "gid" => fields.gid = true,
                "size" => fields.size = true,
                "hash" => fields.hash = true,
                "symlink" => fields.symlink = true,
                "device" => fields.device = true,
                "hardlink" => fields.hardlink = true,
                "mtime" => fields.mtime = true,
                "userXattr" => fields.user_xattr = true,
                "userName" => fields.user_name = true,
                "groupName" => fields.group_name = true,
                _ => return None,
            }
        }
        Some(fields)
    }
}

/// What a written manifest covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Regular files listed.
    pub files: u64,
    /// Directories listed, the root not counted.
    pub directories: u64,
    /// Bytes of the regular files listed.
    pub bytes: u64,
    /// What the volume holds that the manifest could not record: entries
    /// whose names a manifest cannot carry, a directory with everything
    /// below it counting once. A field FAT has no notion of is not an
    /// omission. A manifest with omissions does not describe the whole
    /// volume, which is what repart refuses.
    pub omitted: u64,
}

impl WriteReport {
    /// What the manifest covers so far, as a progress callback hears it.
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}

/// Writes the UAPI.16 manifest of everything the volume holds to `out`:
/// the root object, one object per entry, the trailer. `root_time` is the
/// time the root object carries when `fields.mtime` is on: the root
/// directory of a FAT volume has no entry of its own and so no time, the
/// caller passes the one it knows, the source directory's or the label
/// entry's. Each record goes out in one write and `out` is flushed at the
/// end, so a descriptor wants a `BufWriter` around it.
///
/// Names the manifest cannot carry are left out, with everything below
/// them. The names the specification reserves in the top level for the
/// manifest itself and its signatures (`Uapi16Manifest`,
/// `Uapi16Manifest.*`) are left out silently, as `systemd-manifest` leaves
/// them out; any other, a component of more than 255 bytes of UTF-8 for
/// instance, which FAT stores in UTF-16 but no manifest reader takes, is
/// counted in the report's `omitted`.
pub fn write(
    volume: &Volume,
    root_time: Option<SystemTime>,
    fields: Fields,
    out: &mut dyn Write,
) -> Result<WriteReport> {
    write_with_progress(volume, root_time, fields, out, &mut |_| {})
}

/// [`write`], telling `progress` what the manifest covers so far after
/// every entry and every chunk of a file it reads for the hash.
pub fn write_with_progress(
    volume: &Volume,
    root_time: Option<SystemTime>,
    fields: Fields,
    out: &mut dyn Write,
    progress: &mut dyn FnMut(&Progress),
) -> Result<WriteReport> {
    let root = volume.metadata("/")?;
    let mut writer = Writer {
        volume,
        fields,
        out,
        report: WriteReport::default(),
        buf: vec![0u8; volume.layout().cluster_size() as usize],
        seen: HashSet::from([root.first_cluster]),
        progress,
    };
    // The root object is a directory by definition and carries no type.
    let mut top = Object::new();
    top.insert("mediaType", MEDIA_TYPE);
    if fields.mtime {
        if let Some(nsec) = root_time.and_then(time_nsec) {
            top.insert("mTimeNSec", nsec);
        }
    }
    write_record(writer.out, top)?;
    writer.directory("/", "")?;
    write_record(writer.out, json::object! { "mediaType" => TRAILER_MEDIA_TYPE })?;
    writer.out.flush()?;
    Ok(writer.report)
}

/// Whether `name`, relative to the root, is one the specification reserves
/// in the top level for the manifest itself and its signatures.
fn reserved(name: &str) -> bool {
    name == FILENAME || name.strip_prefix(FILENAME).is_some_and(|rest| rest.starts_with('.'))
}

struct Writer<'a> {
    volume: &'a Volume,
    fields: Fields,
    out: &'a mut dyn Write,
    report: WriteReport,
    /// One cluster, the most one read of a file returns.
    buf: Vec<u8>,
    /// First clusters of the root and of every directory written so far. A
    /// directory reached twice is a cross-linked or looping tree; without
    /// the check a loop would run until the path limit.
    seen: HashSet<u32>,
    progress: &'a mut dyn FnMut(&Progress),
}

impl Writer<'_> {
    /// Writes the entries of the directory at `path` inside the volume,
    /// whose name in the manifest is `prefix` (empty for the root), sorted
    /// by the bytes of their names, each directory followed by what is
    /// below it.
    fn directory(&mut self, path: &str, prefix: &str) -> Result<()> {
        let mut entries = self.volume.read_dir(path)?;
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        for md in &entries {
            let name = if prefix.is_empty() {
                md.name.clone()
            } else {
                format!("{}/{}", prefix, md.name)
            };
            let path = format!("/{}", name);
            if !valid_name(&name) || path.len() > crate::path::MAX_PATH {
                if !reserved(&name) {
                    self.report.omitted += 1;
                }
                continue;
            }
            let mut o = Object::new();
            o.insert("name", name.as_str());
            // A regular file is what an object without a type is.
            if md.is_dir {
                o.insert("type", "dir");
            }
            if md.attributes & ATTR_READ_ONLY != 0 {
                o.insert("readOnly", true);
            }
            if self.fields.mtime {
                if let Some(nsec) = time_nsec(md.modified) {
                    o.insert("mTimeNSec", nsec);
                }
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
                write_record(self.out, o)?;
                self.report.directories += 1;
                (self.progress)(&self.report.progress());
                self.directory(&path, &name)?;
            } else {
                if self.fields.size {
                    o.insert("size", md.size);
                }
                if self.fields.hash {
                    o.insert("sha256", sha256::to_hex(&self.hash(&path)?));
                }
                write_record(self.out, o)?;
                self.report.files += 1;
                self.report.bytes += md.size;
                (self.progress)(&self.report.progress());
            }
        }
        Ok(())
    }

    /// The SHA-256 of the file at `path`, read from the volume.
    fn hash(&mut self, path: &str) -> Result<[u8; DIGEST_SIZE]> {
        let mut file = self.volume.begin_read(path)?;
        let mut hasher = Sha256::new();
        let mut done = self.report.progress();
        loop {
            let n = self.volume.read_file_data(&mut file, &mut self.buf)?;
            if n == 0 {
                return Ok(hasher.finalize());
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
    use crate::manifest::{self, Entry, InodeType, Manifest, RECORD_SEPARATOR};
    use crate::populate::CopyOptions;
    use crate::test_util::{volume, TempDir, TempImage};
    use std::os::fd::AsFd;
    use std::time::{Duration, UNIX_EPOCH};

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
        let report = write(v, root_time, fields, &mut out).unwrap();
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
        m.entries.iter().map(|e| e.name.as_deref().unwrap()).collect()
    }

    fn entry<'a>(m: &'a Manifest, name: &str) -> &'a Entry {
        m.entries.iter().find(|e| e.name.as_deref() == Some(name)).unwrap()
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
        let m = manifest::parse(&bytes).unwrap();
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
            assert_eq!(e.sha256, Some(sha256::digest(data)), "{}", name);
        }
        assert_eq!(entry(&m, "_notes/empty").sha256, Some(sha256::EMPTY));
        for name in ["EFI", "EFI/BOOT", "_notes", "zz"] {
            assert_eq!((entry(&m, name).size, entry(&m, name).sha256), (None, None), "{}", name);
        }
        let boot = entry(&m, "EFI/BOOT/BOOTX64.EFI");
        assert_eq!(boot.read_only, Some(true));
        assert!(boot.is_read_only());
        for e in m
            .entries
            .iter()
            .filter(|e| e.name.as_deref() != Some("EFI/BOOT/BOOTX64.EFI"))
        {
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
                sha256::to_hex(&sha256::digest(&boot_data()))
            )
        );
        assert_eq!(
            recs[7].0,
            format!(
                r#"{{"name":"_notes/empty","sha256":"{}","size":0}}"#,
                sha256::to_hex(&sha256::EMPTY)
            )
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
        let (bytes, report) = written(&v, Some(t(1_600_000_000)), Fields::none());
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
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), NAMES);
        assert_eq!(m.root.mtime_nsec, None);
        assert!(m.entries.iter().all(|e| e.size.is_none() && e.sha256.is_none()));

        // Sizes without hashes, hashes without sizes. The empty file's hash
        // alone still tells the reader its size.
        let (bytes, _) = written(&v, None, Fields::from_names(["size"]).unwrap());
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(entry(&m, "a.txt").size, Some(7));
        assert_eq!(entry(&m, "a.txt").sha256, None);
        let (bytes, _) = written(&v, None, Fields::from_names(["hash"]).unwrap());
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(entry(&m, "a.txt").size, None);
        assert_eq!(entry(&m, "a.txt").sha256, Some(sha256::digest(b"lower a")));
        assert_eq!(entry(&m, "_notes/empty").size, Some(0));
        assert!(!records(&bytes)[7].1.contains_key("size"));

        // Times: the stored ones, which FAT keeps at 2 s, and the root's
        // only when the caller has one.
        let fields = Fields {
            mtime: true,
            ..Fields::none()
        };
        let (bytes, _) = written(&v, None, fields);
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(m.root.mtime_nsec, None);
        for e in &m.entries {
            let stored = v.metadata(&e.path()).unwrap().modified;
            assert_eq!(e.mtime(), Some(stored), "{}", e.path());
        }
        assert_eq!(
            entry(&m, "EFI/BOOT/BOOTX64.EFI").mtime_nsec,
            Some(1_700_000_002 * 1_000_000_000)
        );
        assert_eq!(entry(&m, "zz").mtime_nsec, Some(1_700_000_000 * 1_000_000_000));
        let root_time = t(1_600_000_000) + Duration::from_nanos(5);
        let (bytes, _) = written(&v, Some(root_time), fields);
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(m.root.mtime_nsec, Some(1_600_000_000_000_000_005));
        assert_eq!(m.root.mtime(), Some(root_time));
        assert_eq!(
            records(&bytes)[0].0,
            r#"{"mTimeNSec":1600000000000000005,"mediaType":"application/vnd.uapi.16.manifest"}"#
        );
        // Without the field the caller's time is not written either.
        let (bytes, _) = written(&v, Some(root_time), Fields::default());
        assert_eq!(manifest::parse(&bytes).unwrap().root.mtime_nsec, None);
    }

    #[test]
    fn fields_from_names() {
        let all = [
            "mode",
            "uid",
            "gid",
            "size",
            "hash",
            "symlink",
            "device",
            "hardlink",
            "mtime",
            "userXattr",
            "userName",
            "groupName",
        ];
        assert_eq!(
            Fields::from_names(all).unwrap(),
            Fields {
                mode: true,
                uid: true,
                gid: true,
                size: true,
                hash: true,
                symlink: true,
                device: true,
                hardlink: true,
                mtime: true,
                user_xattr: true,
                user_name: true,
                group_name: true,
            }
        );
        assert_eq!(Fields::from_names(Vec::<&str>::new()).unwrap(), Fields::none());
        // systemd's default set.
        assert_eq!(
            Fields::from_names([
                "mode",
                "uid",
                "gid",
                "size",
                "hash",
                "symlink",
                "device",
                "hardlink",
                "userXattr"
            ])
            .unwrap(),
            Fields::default()
        );
        assert_eq!(
            Fields::from_names(["size", "hash", "mtime", "size"]).unwrap(),
            Fields {
                size: true,
                hash: true,
                mtime: true,
                ..Fields::none()
            }
        );
        for bad in [
            &["sha256"][..],
            &["size", "user_xattr"],
            &["Mode"],
            &[""],
            &[
                "mode",
                "uid",
                "gid",
                "size",
                "hash",
                "symlink",
                "device",
                "hardlink",
                "mtime",
                "userXattr",
                "userName",
                "groupName",
                "type",
            ],
        ] {
            assert_eq!(Fields::from_names(bad.iter().copied()), None, "{:?}", bad);
        }
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
        let host = manifest::generate(dir.as_fd()).unwrap();
        let root_time = std::fs::metadata(tree.path()).unwrap().modified().unwrap();
        let fields = Fields::from_names(["size", "hash", "mtime"]).unwrap();
        let (bytes, report) = written(&v, Some(root_time), fields);
        assert_eq!(String::from_utf8_lossy(&bytes), String::from_utf8_lossy(&host));
        assert_eq!(names(&manifest::parse(&bytes).unwrap()), NAMES);
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
        let m = manifest::parse(&bytes).unwrap();
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
        let m = manifest::parse(&bytes).unwrap();
        assert_eq!(names(&m), ["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
        assert_eq!((report.files, report.directories, report.omitted), (2, 1, 2));
    }

    #[test]
    fn a_cross_linked_directory_tree_is_refused() {
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
        // of a 32-byte entry is split over bytes 20 (high half) and 26 (low
        // half); the entry is the directory one, not a dot entry, that
        // refers to b's cluster.
        let dev = img.device();
        dev.read_at(offset, &mut cluster).unwrap();
        let slot = (0..cluster.len() / 32)
            .find(|&i| {
                let e = &cluster[i * 32..(i + 1) * 32];
                let first = (u32::from(u16::from_le_bytes([e[20], e[21]])) << 16)
                    | u32::from(u16::from_le_bytes([e[26], e[27]]));
                e[0] != b'.' && e[11] & crate::dirent::ATTR_DIRECTORY != 0 && first == b.first_cluster
            })
            .unwrap();
        let at = offset + (slot * 32) as u64;
        dev.write_at(at + 20, &((a.first_cluster >> 16) as u16).to_le_bytes())
            .unwrap();
        dev.write_at(at + 26, &(a.first_cluster as u16).to_le_bytes()).unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = write(&v, None, Fields::none(), &mut out).unwrap_err();
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
