// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing the manifest of what a volume holds: the UAPI.16 description of
//! every file and directory in it, in the stored form.
//!
//! This is the manifest the Varlink interface's `ManifestSink` receives
//! from Assemble, Populate and Describe, see
//! docs/org.uapi-group.FileSystem.varlink. It says what the volume stores
//! as the volume stores it: times at FAT's 2 s, the read-only attribute as
//! `readOnly`, the hidden, system and archive attributes as flags when
//! asked for, and no mode, owner, device numbers, hardlinks, extended
//! attributes or inode flags, since FAT has no notion of them. A feature
//! the file system has no notion of is not recorded and not counted; what
//! FAT keeps and the manifest could not record is counted in the report's
//! `omitted`.
//!
//! The order is the specification's code point order: the root object
//! first, every directory's entries right after it, sorted by the bytes of
//! their names and never in on-disk order, the trailer last. The records
//! are what the `uapi16` crate writes, as `systemd-manifest` writes them:
//! keys sorted, no whitespace, no inode type on the root object and on
//! regular files. So with the same features the manifest of a volume is
//! the one the host tree generator writes for the tree the volume was
//! filled from, apart from what FAT changes on the way: FAT keeps times at
//! 2 s, the manifest always lists `read-only`, and a read-only file gets
//! `readOnly`.

use std::io::Write;
use std::time::SystemTime;

use uapi16::{Features, FileObject, Finalize, InodeType, Name, Order, RootObject, Sha256, Sha256Context, Writer};

use super::DosAttributes;
use crate::dir::NameDecoding;
use crate::errno::*;
use crate::fat::BitSet;
use crate::progress::Progress;
use crate::volume::{Metadata, Volume};
use crate::{CorruptPlace, Detail, Result};

/// What a written manifest covers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WriteReport {
    /// Regular files listed.
    pub files: u64,
    /// Directories listed, the root not counted.
    pub directories: u64,
    /// Bytes of the regular files listed.
    pub bytes: u64,
    /// What the tree or the volume holds that the manifest could not
    /// record: entries whose names a manifest cannot carry, a directory
    /// with everything below it counting once. A feature the file system
    /// has no notion of is not an omission. A manifest with omissions does
    /// not describe all of it, and repart refuses such a manifest of a
    /// volume.
    pub omitted: u64,
    /// Regular files of a host tree that changed while they were read for
    /// their hash. The manifest has the size and the hash of what was
    /// read, which need not be what the file holds now. A volume does not
    /// change while its manifest is written.
    pub changed: u64,
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

impl Volume {
    /// What the manifest of a FAT volume records whatever it is asked for:
    /// the read-only attribute, which every entry has set or cleared.
    const ALWAYS_RECORDED_FEATURES: Features = Features::READ_ONLY;

    /// What the manifest of a FAT volume can record: sizes, hashes, times,
    /// the read-only attribute and the hidden, system and archive
    /// attributes, and that there are no symbolic links, device nodes,
    /// hardlinks, extended attributes or inode flags.
    const MANIFEST_FEATURES: Features = Features::SIZE
        .union(Features::SHA256)
        .union(Features::MTIME)
        .union(Features::READ_ONLY)
        .union(Features::SYMLINK)
        .union(Features::DEVICE)
        .union(Features::HARDLINK)
        .union(Features::USER_XATTR)
        .union(Features::FLAG_HIDDEN)
        .union(Features::FLAG_SYSTEM)
        .union(Features::FLAG_ARCHIVE)
        .union(Features::FLAG_APPEND_ONLY)
        .union(Features::FLAG_IMMUTABLE)
        .union(Features::FLAG_NO_ATIME)
        .union(Features::FLAG_NO_COW)
        .union(Features::FLAG_NO_DUMP);

    /// Writes the UAPI.16 manifest of everything the volume holds to `out`:
    /// the root object, one object per entry, the trailer. `root_time` is
    /// the time the root object carries when `features` has
    /// [`Features::MTIME`]: the root directory of a FAT volume has no entry
    /// of its own and so no time, the caller passes the one it knows, the
    /// source directory's or the label entry's. Each record goes out in
    /// one write and `out` is flushed at the end, so a descriptor wants a
    /// `BufWriter` around it.
    ///
    /// The manifest records what `features` asks for and FAT has a notion
    /// of. Of the features only [`Features::SIZE`], [`Features::SHA256`],
    /// [`Features::MTIME`] and the flags of the hidden, system and archive
    /// attributes add fields: a flag is written on a file or a directory
    /// that has the attribute, and cleared where it is not written. FAT has
    /// no symbolic links, device nodes, hardlinks, extended attributes and
    /// inode flags, so the manifest records that it has none of them where
    /// `features` asks for them. FAT has no mode, owner or user and group
    /// names, so the manifest does not record them. It always records the
    /// read-only attribute, which every entry has set or cleared:
    /// `readOnly` is written where it is set, and an entry without it is
    /// not read-only. The manifest lists its features, and declares the
    /// code point ordering its objects are in.
    ///
    /// Names the manifest cannot carry are left out, with everything below
    /// them. The names the specification reserves in the top level for the
    /// manifest itself and its signatures (`Uapi16Manifest`,
    /// `Uapi16Manifest.*`) are left out silently, as `systemd-manifest`
    /// leaves them out; any other, one with a noncharacter or an unpaired
    /// surrogate for instance, which FAT stores but no manifest has, is
    /// counted in the report's `omitted`. Names that FAT takes for one,
    /// such as `README.TXT` and `readme.txt`, are two names to a manifest,
    /// and each is listed with what its entry holds.
    ///
    /// What only a damaged volume has fails with EUCLEAN: a cluster that
    /// belongs to two entries, or twice to one, as in a loop or a
    /// cross-link, a directory whose chain is longer than a directory can
    /// be, an entry that points at a cluster the volume does not have, a
    /// chain that runs into a free, bad or invalid entry, a file whose
    /// chain is shorter than the file, and two entries of the same name in
    /// a directory. The walk lists a directory from the first cluster its
    /// entry names and reads a file the same way, never by path. It keeps
    /// one bit for every cluster of the volume, set for every cluster of a
    /// directory it lists and of a file it reads for the hash, and ends
    /// where it reaches a cluster a second time. So it lists no directory
    /// and reads no file twice, and takes time in proportion to the size of
    /// the volume. It reads files only for [`Features::SHA256`], and only
    /// then finds what is wrong with their chains.
    pub fn write_manifest(
        &self,
        root_time: Option<SystemTime>,
        features: Features,
        out: impl Write,
    ) -> Result<WriteReport> {
        self.write_manifest_with_progress(root_time, features, out, &mut |_| {})
    }

    /// [`Volume::write_manifest`], telling `progress` what the manifest
    /// covers so far after every entry and every chunk of a file it reads
    /// for the hash.
    pub fn write_manifest_with_progress(
        &self,
        root_time: Option<SystemTime>,
        features: Features,
        out: impl Write,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<WriteReport> {
        let top = self.metadata("/")?;
        let features = (features | Volume::ALWAYS_RECORDED_FEATURES) & Volume::MANIFEST_FEATURES;
        // The root object is a directory by definition and carries no type.
        let mut root = RootObject::default();
        root.features = Some(features);
        root.order = Some(Order::CodePoint);
        if let Some(time) = root_time.filter(|_| features.contains(Features::MTIME)) {
            root.inode.set_mtime(time);
        }
        let mut listing = Listing {
            volume: self,
            features,
            writer: Writer::begin(out, &root)?,
            report: WriteReport::default(),
            buf: vec![0u8; self.layout().cluster_size() as usize],
            claimed: BitSet::new(self.layout().max_cluster() as usize + 1),
            progress,
        };
        let entries = listing.list("/", top.first_cluster)?;
        listing.directory("/", &Name::ROOT, entries)?;
        listing.writer.finish()?;
        Ok(listing.report)
    }
}

/// The manifest of a volume while it is written.
struct Listing<'a, W: Write> {
    volume: &'a Volume,
    /// What the manifest records.
    features: Features,
    writer: Writer<W>,
    report: WriteReport,
    /// One cluster, the most one read of a file returns.
    buf: Vec<u8>,
    /// The clusters the walk read so far, one bit for every cluster of the
    /// volume: those of every directory it listed and of every file it
    /// read for the hash. On a damaged volume a cluster can belong to two
    /// entries, or twice to one, through a loop or a cross-link, and a walk
    /// that read it again would list a directory or read a file as often
    /// as there are paths to it: in a loop without end, and in a chain of
    /// cross-linked directories twice as often per level.
    claimed: BitSet,
    progress: &'a mut dyn FnMut(&Progress),
}

impl<W: Write> Listing<'_, W> {
    /// Notes that the walk read `cluster` for the entry at `path`, a
    /// directory or a file as `place` says. A cluster it read before
    /// belongs to two entries, or twice to one, and fails with EUCLEAN.
    fn claim(&mut self, path: &str, place: CorruptPlace, cluster: u32) -> Result<()> {
        // The clusters of chains are valid, below the number of FAT entries
        // the set was made for.
        let bit = cluster as usize;
        if self.claimed.contains(bit) {
            bail!(
                EUCLEAN,
                Detail::Corrupt {
                    place,
                    field: None,
                    path: Some(path.to_string()),
                    cluster: Some(cluster),
                },
                "'{}' is at cluster {}, which the walk reached before, the volume is cross-linked or loops",
                path,
                cluster
            );
        }
        self.claimed.insert(bit);
        Ok(())
    }

    /// The entries of the directory at `path` inside the volume, whose
    /// first cluster is `first_cluster`, sorted by the bytes of their
    /// names, without those whose names have an unpaired surrogate, which
    /// are counted as omitted. Every cluster of the directory is claimed. A
    /// first cluster the volume does not have fails with EUCLEAN, and so do
    /// two entries of the same name.
    fn list(&mut self, path: &str, first_cluster: u32) -> Result<Vec<Metadata>> {
        if !self.volume.layout().valid_cluster(first_cluster) {
            bail!(
                EUCLEAN,
                Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    field: None,
                    path: Some(path.to_string()),
                    cluster: Some(first_cluster),
                },
                "'{}' is a directory at cluster {}, which the volume does not have",
                path,
                first_cluster
            );
        }
        let volume = self.volume;
        let mut entries = volume
            .read_dir_at(first_cluster, |chain| {
                chain
                    .iter()
                    .try_for_each(|&cluster| self.claim(path, CorruptPlace::Directory, cluster))
            })
            .map_err(|e| e.at_path(path))?;
        // A long name with an unpaired surrogate has no spelling a manifest
        // takes. The listing shows it with U+FFFD in its place, which two
        // such names can share, so it is left out before names are compared.
        let listed = entries.len();
        entries.retain(|md| md.name_decoding == NameDecoding::Exact);
        self.report.omitted += (listed - entries.len()) as u64;
        entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        // Sorted, two entries of the same name are next to each other. Names
        // that FAT takes for one, such as "AAAA" and "aaaa", are two names
        // to a manifest, and each is listed with what its own entry holds.
        if let Some(pair) = entries.windows(2).find(|pair| pair[0].name == pair[1].name) {
            let path = crate::path::join(path, &pair[1].name);
            bail!(
                EUCLEAN,
                Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    field: None,
                    path: Some(path.clone()),
                    cluster: Some(first_cluster),
                },
                "'{}' is in its directory twice, the directory is damaged",
                path
            );
        }
        Ok(entries)
    }

    /// Writes `entries`, the entries of the directory at `path` inside the
    /// volume as [`Listing::list`] returned them, whose name in the
    /// manifest is `prefix` (the root's for the root), each directory
    /// followed by what is below it. A directory is listed before its own
    /// record goes out, so that a damaged one ends the manifest before it.
    fn directory(&mut self, path: &str, prefix: &Name, entries: Vec<Metadata>) -> Result<()> {
        for md in &entries {
            let path = crate::path::join(path, &md.name);
            // A name that is reserved for the manifest, which only a name
            // at the top can be, is left out and is no omission.
            if prefix.is_root() && Name::is_reserved(&md.name) {
                continue;
            }
            let name = match prefix.join(&md.name) {
                Ok(name) if path.len() <= crate::path::MAX_PATH => name,
                _ => {
                    self.report.omitted += 1;
                    continue;
                }
            };
            // A regular file is what an object without a type is.
            let mut object = FileObject::new(name);
            DosAttributes::new(md.attributes).record_in(&mut object, self.features);
            if self.features.contains(Features::MTIME) {
                object.inode.set_mtime(md.modified);
            }
            if md.is_dir {
                let below = self.list(&path, md.first_cluster)?;
                object.inode_type = InodeType::Directory;
                self.writer.file(&object)?;
                self.report.directories += 1;
                (self.progress)(&self.report.progress());
                self.directory(&path, &object.name, below)?;
            } else {
                if self.features.contains(Features::SIZE) {
                    object.size = Some(md.size);
                }
                if self.features.contains(Features::SHA256) {
                    object.sha256 = Some(self.hash(&path, md)?);
                }
                self.writer.file(&object)?;
                self.report.files += 1;
                self.report.bytes += md.size;
                (self.progress)(&self.report.progress());
            }
        }
        Ok(())
    }

    /// The SHA-256 of the file at `path` inside the volume, read from the
    /// first cluster its entry `md` names for the size the entry gives.
    /// Every cluster it reads is claimed.
    fn hash(&mut self, path: &str, md: &Metadata) -> Result<Sha256> {
        let mut file = self
            .volume
            .begin_read_at(md.first_cluster, md.size)
            .map_err(|e| e.at_path(path))?;
        let mut context = Sha256Context::default();
        let mut done = self.report.progress();
        loop {
            let n = self
                .volume
                .read_file_data(&mut file, &mut self.buf)
                .map_err(|e| e.at_path(path))?;
            if n == 0 {
                return Ok(context.finalize());
            }
            // A read ends at the end of a cluster and the buffer holds one,
            // so every read is of a cluster of its own.
            self.claim(path, CorruptPlace::Chain, file.cluster())?;
            context.update(&self.buf[..n]);
            done.bytes += n as u64;
            (self.progress)(&done);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dirent::ATTR_READ_ONLY;
    use crate::manifest::HostTree;
    use crate::populate::CopyOptions;
    use crate::test_util::{volume, TempDir, TempImage};
    use crate::volume::NameCollision;
    use json::Object;
    use std::os::fd::AsFd;
    use std::time::{Duration, UNIX_EPOCH};
    use uapi16::{Digest, DosFlags, InodeFlags, Object as ManifestObject, Reader, RECORD_SEPARATOR};

    fn t(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// Creates a file with `data`, read-only as `read_only` says.
    fn put(v: &mut Volume, path: &str, data: &[u8], time: SystemTime, read_only: bool) {
        let mut w = v.create_file(path, time, NameCollision::Fail).unwrap();
        w.write_all(data).unwrap();
        if read_only {
            w.set_attributes(w.attributes() | ATTR_READ_ONLY).unwrap();
        }
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

    fn written(v: &Volume, root_time: Option<SystemTime>, features: Features) -> (Vec<u8>, WriteReport) {
        let mut out = Vec::new();
        let report = v.write_manifest(root_time, features, &mut out).unwrap();
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

    /// A manifest a volume wrote as the tests look at it: the root file
    /// object and the others.
    struct WrittenManifest {
        root: RootObject,
        entries: Vec<FileObject>,
    }

    impl WrittenManifest {
        /// Reads the manifest `bytes` to its end with the reader of the
        /// `uapi16` crate, which requires the code point order.
        fn read(bytes: &[u8]) -> WrittenManifest {
            let reader = Reader::open(bytes).unwrap();
            reader.root().require_order(Order::CodePoint).unwrap();
            let root = reader.root().clone();
            let mut entries = Vec::new();
            for object in reader {
                if let ManifestObject::File(object) = object.unwrap() {
                    entries.push(*object);
                }
            }
            WrittenManifest { root, entries }
        }

        /// The names of the file objects, in the order of the manifest.
        fn names(&self) -> Vec<&str> {
            self.entries.iter().map(|e| e.name.as_str()).collect()
        }

        /// The file object of the name `name`.
        fn entry(&self, name: &str) -> &FileObject {
            self.entries.iter().find(|e| e.name == name).unwrap()
        }
    }

    #[test]
    fn writes_what_the_volume_holds() {
        let (_img, v) = populated();
        let (bytes, report) = written(&v, None, Features::DEFAULT);
        assert_eq!(
            report,
            WriteReport {
                files: 5,
                directories: 4,
                bytes: 7 + 5000 + 10 + 7,
                omitted: 0,
                changed: 0,
            }
        );
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.names(), NAMES);
        use InodeType::{Directory as D, Regular as R};
        let types: Vec<InodeType> = m.entries.iter().map(|e| e.inode_type).collect();
        assert_eq!(types, [R, D, D, R, R, D, R, R, D]);
        assert_eq!(m.root.inode.mtime_nsec, None);
        for (name, data) in [
            ("B.txt", &b"upper B"[..]),
            ("EFI/BOOT/BOOTX64.EFI", &boot_data()),
            ("EFI/a.txt", b"first file"),
            ("_notes/empty", b""),
            ("a.txt", b"lower a"),
        ] {
            let e = m.entry(name);
            assert_eq!(e.size, Some(data.len() as u64), "{}", name);
            assert_eq!(e.sha256, Some(Sha256::digest(data)), "{}", name);
        }
        assert_eq!(m.entry("_notes/empty").sha256, Some(Sha256::EMPTY));
        for name in ["EFI", "EFI/BOOT", "_notes", "zz"] {
            assert_eq!((m.entry(name).size, m.entry(name).sha256), (None, None), "{}", name);
        }
        // The manifest records the read-only attribute, so what it does not
        // mark read-only is not.
        let boot = m.entry("EFI/BOOT/BOOTX64.EFI");
        assert_eq!(boot.inode.read_only, Some(true));
        assert!(boot.inode.is_read_only());
        for e in m.entries.iter().filter(|e| e.name != "EFI/BOOT/BOOTX64.EFI") {
            assert_eq!(e.inode.read_only, Some(false), "{:?}", e.name);
            assert!(!e.inode.is_read_only());
        }
        assert!(m
            .entries
            .iter()
            .all(|e| e.inode.mtime_nsec.is_none() && e.inode.mode.is_none()));

        // The raw records: the root object, one per entry, the trailer. As
        // systemd-manifest writes them, the root object and the regular
        // files carry no type, and FAT has no extended attributes to list.
        // The empty file has no hash, which its size implies, as the
        // specification recommends.
        let recs = records(&bytes);
        assert_eq!(recs.len(), 1 + NAMES.len() + 1);
        assert_eq!(
            recs[0].0,
            concat!(
                r#"{"features":["device","hardlink","read-only","sha256","size","symlink"],"#,
                r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
            )
        );
        assert_eq!(recs[2].0, r#"{"name":"EFI","type":"dir"}"#);
        assert_eq!(
            recs[4].0,
            format!(
                r#"{{"name":"EFI/BOOT/BOOTX64.EFI","readOnly":true,"sha256":"{}","size":5000}}"#,
                Sha256::digest(&boot_data())
            )
        );
        assert_eq!(recs[7].0, r#"{"name":"_notes/empty","size":0}"#);
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
    fn features_govern_what_is_written() {
        let (_img, v) = populated();
        // Nothing but names, the types of directories and the read-only
        // attribute, which the manifest always records.
        let (bytes, report) = written(&v, Some(t(1_600_000_000)), Features::NONE);
        assert_eq!((report.files, report.directories, report.bytes), (5, 4, 5024));
        let recs = records(&bytes);
        assert_eq!(
            recs[0].0,
            r#"{"features":["read-only"],"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
        );
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
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.names(), NAMES);
        assert_eq!(m.root.inode.mtime_nsec, None);
        assert!(m.entries.iter().all(|e| e.size.is_none() && e.sha256.is_none()));

        // Sizes without hashes, hashes without sizes. The empty file's hash
        // alone still tells the reader its size.
        let (bytes, _) = written(&v, None, Features::from_names(["size"]).unwrap());
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.entry("a.txt").size, Some(7));
        assert_eq!(m.entry("a.txt").sha256, None);
        let (bytes, _) = written(&v, None, Features::from_names(["sha256"]).unwrap());
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.entry("a.txt").size, None);
        assert_eq!(m.entry("a.txt").sha256, Some(Sha256::digest(b"lower a")));
        assert_eq!(m.entry("_notes/empty").size, Some(0));
        assert!(!records(&bytes)[7].1.contains_key("size"));

        // Times: the stored ones, which FAT keeps at 2 s, and the root's
        // only when the caller has one.
        let features = Features::MTIME;
        let (bytes, _) = written(&v, None, features);
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.root.inode.mtime_nsec, None);
        for e in &m.entries {
            let stored = v.metadata(&format!("/{}", e.name)).unwrap().modified;
            assert_eq!(e.inode.mtime(), Some(stored), "{}", e.name);
        }
        assert_eq!(
            m.entry("EFI/BOOT/BOOTX64.EFI").inode.mtime_nsec,
            Some(1_700_000_002 * 1_000_000_000)
        );
        assert_eq!(m.entry("zz").inode.mtime_nsec, Some(1_700_000_000 * 1_000_000_000));
        let root_time = t(1_600_000_000) + Duration::from_nanos(5);
        let (bytes, _) = written(&v, Some(root_time), features);
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.root.inode.mtime_nsec, Some(1_600_000_000_000_000_005));
        assert_eq!(m.root.inode.mtime(), Some(root_time));
        assert_eq!(
            records(&bytes)[0].0,
            concat!(
                r#"{"features":["mtime","read-only"],"mTimeNSec":1600000000000000005,"#,
                r#""mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#
            )
        );
        // Without the feature the caller's time is not written either.
        let (bytes, _) = written(&v, Some(root_time), Features::DEFAULT);
        assert_eq!(WrittenManifest::read(&bytes).root.inode.mtime_nsec, None);
    }

    #[test]
    fn records_the_flags_and_what_fat_has_none_of() {
        let (_img, v) = populated();
        // Asked for everything, the manifest lists what FAT records:
        // sizes, hashes, times, the read-only attribute and the other DOS
        // attributes, and that it has no symbolic links, device nodes,
        // hardlinks, extended attributes and inode flags. Modes, owners and
        // their names are not listed.
        let (bytes, _) = written(&v, None, Features::ALL);
        let m = WrittenManifest::read(&bytes);
        assert_eq!(
            m.root.features.unwrap().names().collect::<Vec<_>>(),
            [
                "device",
                "flag-append-only",
                "flag-archive",
                "flag-hidden",
                "flag-immutable",
                "flag-no-atime",
                "flag-no-cow",
                "flag-no-dump",
                "flag-system",
                "hardlink",
                "mtime",
                "read-only",
                "sha256",
                "size",
                "symlink",
                "user-xattr"
            ]
        );
        // The inode flags are cleared everywhere, the root's too, and the
        // DOS attributes are what the entries have: every file the volume
        // made has the archive attribute, a directory has not.
        let inode_flags = [
            InodeFlags::APPEND_ONLY,
            InodeFlags::IMMUTABLE,
            InodeFlags::NO_ATIME,
            InodeFlags::NO_COW,
            InodeFlags::NO_DUMP,
        ];
        for flag in inode_flags {
            assert_eq!(m.root.inode.flags.get(flag), Some(false), "{:?}", flag);
            assert!(
                m.entries.iter().all(|e| e.inode.flags.get(flag) == Some(false)),
                "{:?}",
                flag
            );
        }
        for e in &m.entries {
            let archive = e.inode_type == InodeType::Regular;
            assert_eq!(e.dos_flags.get(DosFlags::ARCHIVE), Some(archive), "{}", e.name);
            assert_eq!(e.dos_flags.get(DosFlags::HIDDEN), Some(false), "{}", e.name);
            assert_eq!(e.dos_flags.get(DosFlags::SYSTEM), Some(false), "{}", e.name);
        }
        let records = records(&bytes);
        assert_eq!(
            records[1].0,
            format!(
                r#"{{"flagArchive":true,"mTimeNSec":1700000000000000000,"name":"B.txt","sha256":"{}","size":7}}"#,
                Sha256::digest(b"upper B")
            )
        );
        assert_eq!(
            records[2].0,
            r#"{"mTimeNSec":1700000000000000000,"name":"EFI","type":"dir"}"#
        );
        // A read-only file has its other attributes as well.
        assert_eq!(
            records[4].0,
            format!(
                concat!(
                    r#"{{"flagArchive":true,"mTimeNSec":1700000002000000000,"#,
                    r#""name":"EFI/BOOT/BOOTX64.EFI","readOnly":true,"sha256":"{}","size":5000}}"#
                ),
                Sha256::digest(&boot_data())
            )
        );
    }

    #[test]
    fn agrees_with_the_host_tree_generator() {
        let tree = host_tree();
        let dir = crate::host::open_dir(tree.path()).unwrap();
        let (_img, mut v) = volume(8 << 20, 512, 512);
        let copied = v.copy_tree(dir.as_fd(), "/", &CopyOptions::default()).unwrap();
        assert_eq!((copied.files, copied.directories), (5, 4));
        // The generator records sizes, hashes and times. With the tree's own
        // time for the root and times FAT keeps as they are, the two
        // manifests are the same bytes, but for the read-only attribute,
        // which the manifest of a volume always lists in its features.
        let mut host = Vec::new();
        let host_report = HostTree::new(dir.as_fd()).write_manifest(&mut host).unwrap();
        let host = String::from_utf8(host).unwrap();
        let listed = r#""features":["mtime","sha256","size"]"#;
        assert!(host.contains(listed), "{}", host);
        let host = host.replacen(listed, r#""features":["mtime","read-only","sha256","size"]"#, 1);
        let root_time = std::fs::metadata(tree.path()).unwrap().modified().unwrap();
        let features = Features::from_names(["size", "sha256", "mtime"]).unwrap();
        let (bytes, report) = written(&v, Some(root_time), features);
        assert_eq!(String::from_utf8_lossy(&bytes), host);
        assert_eq!(WrittenManifest::read(&bytes).names(), NAMES);
        assert_eq!((report.files, report.directories, report.bytes), (5, 4, copied.bytes));
        assert_eq!(report, host_report);
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
        let (bytes, report) = written(&v, None, Features::DEFAULT);
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.names(), ["Uapi16Manifest2", "sub", "sub/Uapi16Manifest"]);
        assert_eq!(
            report,
            WriteReport {
                files: 2,
                directories: 1,
                bytes: 8,
                omitted: 0,
                changed: 0,
            }
        );

        // FAT stores a noncharacter such as U+FDD0, a manifest has none.
        // Such entries are left out and counted, a directory with
        // everything below it as one.
        let odd = "a\u{fdd0}";
        v.create_dir(&format!("/{}", odd), t0).unwrap();
        put(&mut v, &format!("/{}/inside", odd), b"x", t0, false);
        put(&mut v, &format!("/sub/{}", odd), b"y", t0, false);
        // A name of 100 three-byte characters is 300 bytes of UTF-8. A
        // manifest does not limit its components.
        let long: String = std::iter::repeat_n('\u{20ac}', 100).collect();
        put(&mut v, &format!("/sub/{}", long), b"z", t0, false);
        let (bytes, report) = written(&v, None, Features::DEFAULT);
        let m = WrittenManifest::read(&bytes);
        let carried = format!("sub/{}", long);
        assert_eq!(
            m.names(),
            ["Uapi16Manifest2", "sub", "sub/Uapi16Manifest", carried.as_str()]
        );
        assert_eq!((report.files, report.directories, report.omitted), (3, 1, 2));
    }

    /// The slot of the entry of the directory cluster `cluster` that
    /// `matches`, from its 32 bytes.
    fn slot_of(cluster: &[u8], matches: impl Fn(&[u8]) -> bool) -> usize {
        use crate::dirent::DIR_ENTRY_SIZE;
        (0..cluster.len() / DIR_ENTRY_SIZE)
            .find(|&i| matches(&cluster[i * DIR_ENTRY_SIZE..(i + 1) * DIR_ENTRY_SIZE]))
            .unwrap()
    }

    /// Points the directory entry at the byte `entry` of the image `dev` at
    /// the cluster `cluster`: the high and the low half of its first
    /// cluster.
    fn set_first_cluster(dev: &crate::device::Device, entry: u64, cluster: u32) {
        use crate::dirent;
        dev.write_at(
            entry + dirent::field::FIRST_CLUSTER_HI.start as u64,
            &((cluster >> u16::BITS) as u16).to_le_bytes(),
        )
        .unwrap();
        dev.write_at(
            entry + dirent::field::FIRST_CLUSTER_LO.start as u64,
            &(cluster as u16).to_le_bytes(),
        )
        .unwrap();
    }

    /// The 8.3 name of every short entry of the directory whose chain
    /// starts at `first_cluster`, and the byte of the image it is at.
    fn short_entries(v: &Volume, first_cluster: u32) -> Vec<([u8; 11], u64)> {
        use crate::dirent::DIR_ENTRY_SIZE;
        let dir = v.load_directory(first_cluster).unwrap();
        let cs = v.layout().cluster_size() as usize;
        dir.iter()
            .map(|e| {
                let at = e.slot * DIR_ENTRY_SIZE;
                let cluster = dir.chain()[at / cs];
                (
                    e.short.name,
                    v.layout().cluster_offset(cluster).unwrap() + (at % cs) as u64,
                )
            })
            .collect()
    }

    /// Sets the entry of `cluster` to `value` in every copy of the FAT of
    /// the image `dev`.
    fn set_fat_entry(dev: &crate::device::Device, layout: &crate::layout::Layout, cluster: u32, value: u32) {
        use crate::fat::ENTRY_SIZE;
        for copy in 0..layout.fats {
            dev.write_at(
                layout.fat_offset(copy) + u64::from(cluster) * ENTRY_SIZE as u64,
                &value.to_le_bytes(),
            )
            .unwrap();
        }
    }

    #[test]
    fn a_looping_directory_tree_is_refused() {
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
        // Point the entry of "b" inside "a" back at "a", the directory
        // above it. The first cluster of an entry is split over a high and
        // a low half; the entry is the directory one, not a dot entry, that
        // refers to b's cluster.
        let dev = img.device();
        dev.read_at(offset, &mut cluster).unwrap();
        let slot = slot_of(&cluster, |e| {
            let first = (u32::from(le16_at(e, dirent::field::FIRST_CLUSTER_HI)) << u16::BITS)
                | u32::from(le16_at(e, dirent::field::FIRST_CLUSTER_LO));
            !e[dirent::field::NAME].starts_with(b".")
                && e[dirent::field::ATTR] & ATTR_DIRECTORY != 0
                && first == b.first_cluster
        });
        // That entry is slot `slot` of the cluster at `offset`.
        set_first_cluster(&dev, offset + (slot * DIR_ENTRY_SIZE) as u64, a.first_cluster);
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
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

    /// Two entries of one name are a damaged directory, not a manifest
    /// that names a file twice. The directory is listed before its own
    /// record goes out, so the manifest ends before it.
    #[test]
    fn a_name_twice_in_a_directory_is_refused() {
        use crate::dirent::{self, DIR_ENTRY_SIZE};

        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir("/d", t0).unwrap();
        // Names of the 8.3 form in one case have no long name, so the short
        // name is all there is to change.
        put(&mut v, "/d/a.txt", b"a", t0, false);
        put(&mut v, "/d/b.txt", b"b", t0, false);
        let d = v.metadata("/d").unwrap();
        let offset = v.layout().cluster_offset(d.first_cluster).unwrap();
        let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
        v.close().unwrap();
        let dev = img.device();
        dev.read_at(offset, &mut cluster).unwrap();
        let slot = slot_of(&cluster, |e| &e[dirent::field::NAME] == b"B       TXT");
        dev.write_at(
            offset + (slot * DIR_ENTRY_SIZE + dirent::field::NAME.start) as u64,
            b"A",
        )
        .unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        assert_eq!(v.read_dir("/d").unwrap().len(), 2);
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if p == "/d/a.txt" && *c == d.first_cluster
            ),
            "{:?}",
            e
        );
        assert_eq!(records(&out).len(), 1);
    }

    /// A directory at a cluster the volume does not have, 0 or one past its
    /// last, is damage, found before anything is read from that cluster.
    #[test]
    fn a_directory_at_a_cluster_the_volume_lacks_is_refused() {
        use crate::dirent::{self, DIR_ENTRY_SIZE};

        let (img, mut v) = volume(8 << 20, 512, 512);
        v.create_dir("/d", t(1_700_000_000)).unwrap();
        let root = v.metadata("/").unwrap();
        let offset = v.layout().cluster_offset(root.first_cluster).unwrap();
        let past = v.layout().max_cluster() + 1;
        let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
        v.close().unwrap();
        img.device().read_at(offset, &mut cluster).unwrap();
        let slot = slot_of(&cluster, |e| &e[dirent::field::NAME] == b"D          ");
        let entry = offset + (slot * DIR_ENTRY_SIZE) as u64;
        for lacking in [0, past] {
            set_first_cluster(&img.device(), entry, lacking);
            let v = Volume::open(img.device()).unwrap();
            let mut out = Vec::new();
            let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
            assert_eq!(e.errno(), EUCLEAN);
            assert!(
                matches!(
                    e.detail(),
                    Some(Detail::Corrupt {
                        place: CorruptPlace::Directory,
                        path: Some(p),
                        cluster: Some(c),
                        ..
                    }) if p == "/d" && *c == lacking
                ),
                "{:?}",
                e
            );
            assert_eq!(records(&out).len(), 1);
        }
    }

    /// A chain of directories each of which holds two entries, "x" and
    /// "y", that point at the next directory: none of them is above itself,
    /// and a walk that took both would list 2^40 paths for 40 levels. The
    /// walk ends at the first directory it reaches a second time.
    #[test]
    fn a_cross_linked_chain_of_directories_is_refused() {
        use crate::dirent::{self, DIR_ENTRY_SIZE};

        const LEVELS: usize = 40;
        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        // /x/x/.../x, with a "y" next to every "x". Each "y" gets the first
        // cluster of the "x" next to it: where the directory holding both
        // is, and that cluster.
        let mut path = String::new();
        let mut links = Vec::new();
        for _ in 0..LEVELS {
            let holder = v.metadata(if path.is_empty() { "/" } else { &path }).unwrap();
            v.create_dir(&format!("{}/y", path), t0).unwrap();
            path.push_str("/x");
            v.create_dir(&path, t0).unwrap();
            let x = v.metadata(&path).unwrap();
            links.push((
                v.layout().cluster_offset(holder.first_cluster).unwrap(),
                x.first_cluster,
            ));
        }
        let last = links.last().unwrap().1;
        let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
        v.close().unwrap();
        let dev = img.device();
        for (offset, target) in links {
            dev.read_at(offset, &mut cluster).unwrap();
            let slot = slot_of(&cluster, |e| &e[dirent::field::NAME] == b"Y          ");
            set_first_cluster(&dev, offset + (slot * DIR_ENTRY_SIZE) as u64, target);
        }
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        let expected = format!("{}/y", "/x".repeat(LEVELS - 1));
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if *p == expected && *c == last
            ),
            "{:?}",
            e
        );
        // The root and the chain of "x", each once.
        assert_eq!(records(&out).len(), 1 + LEVELS);
    }

    /// "AAAA" and "aaaa" are two names to a manifest and one to FAT, which
    /// Linux writes with some mount options. A lookup by name finds only
    /// one of them, but the walk follows the cluster of each entry, so each
    /// is listed with what it holds.
    #[test]
    fn names_that_fold_alike_are_listed_with_their_own_data() {
        use crate::dirent;

        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir("/aaaa", t0).unwrap();
        put(&mut v, "/aaaa/f1", b"1", t0, false);
        put(&mut v, "/aaaa/f2", b"2", t0, false);
        v.create_dir("/bbbb", t0).unwrap();
        put(&mut v, "/bbbb/g", b"3", t0, false);
        let root = v.metadata("/").unwrap();
        // "bbbb" is a name of the 8.3 form in one case, a short entry
        // "BBBB" whose case flags say lower case. It becomes "AAAA".
        let (_, entry) = short_entries(&v, root.first_cluster)
            .into_iter()
            .find(|(name, _)| name == b"BBBB       ")
            .unwrap();
        v.close().unwrap();
        let dev = img.device();
        dev.write_at(entry + dirent::field::NAME.start as u64, b"AAAA").unwrap();
        dev.write_at(entry + dirent::field::NT_FLAGS as u64, &[0]).unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        // A lookup of "/AAAA" finds "aaaa", the first of the two.
        assert_eq!(v.read_dir("/AAAA").unwrap().len(), 2);
        let (bytes, report) = written(&v, None, Features::SHA256);
        let m = WrittenManifest::read(&bytes);
        assert_eq!(m.names(), ["AAAA", "AAAA/g", "aaaa", "aaaa/f1", "aaaa/f2"]);
        for (name, data) in [("AAAA/g", b"3"), ("aaaa/f1", b"1"), ("aaaa/f2", b"2")] {
            assert_eq!(m.entry(name).sha256, Some(Sha256::digest(data)), "{}", name);
        }
        assert_eq!((report.files, report.directories, report.omitted), (3, 2, 0));
    }

    /// Directories whose chains run on into the chain of another one share
    /// its clusters: here 200 empty directories run into the chain of "t",
    /// which holds 1000 files. A walk that listed every directory it
    /// reached in full would list these files 201 times. The walk ends at
    /// the second directory that reaches the clusters of "t".
    #[test]
    fn directories_that_run_into_another_are_refused() {
        use crate::dirent::{DIR_ENTRY_SIZE, ENTRY_DELETED};

        const DIRS: usize = 200;
        const FILES: usize = 1000;
        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir("/t", t0).unwrap();
        for i in 0..FILES {
            put(&mut v, &format!("/t/f{:04}", i), b"", t0, false);
        }
        let mut dirs = Vec::with_capacity(DIRS);
        for i in 0..DIRS {
            let path = format!("/d{:03}", i);
            v.create_dir(&path, t0).unwrap();
            dirs.push(v.metadata(&path).unwrap().first_cluster);
        }
        let target = v.metadata("/t").unwrap().first_cluster;
        let layout = *v.layout();
        v.close().unwrap();
        let dev = img.device();
        for &dir in &dirs {
            // The slots after the dot entries are deleted instead of
            // unused, so that the directory goes on in its next cluster,
            // which is the first one of "t".
            let offset = layout.cluster_offset(dir).unwrap();
            for slot in 2..layout.cluster_size() as usize / DIR_ENTRY_SIZE {
                dev.write_at(offset + (slot * DIR_ENTRY_SIZE) as u64, &[ENTRY_DELETED])
                    .unwrap();
            }
            set_fat_entry(&dev, &layout, dir, target);
        }
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        assert_eq!(v.read_dir("/d199").unwrap().len(), FILES);
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if p == "/d001" && *c == target
            ),
            "{:?}",
            e
        );
        // The root, the first directory and the files of "t", which it
        // lists as its own.
        assert_eq!(records(&out).len(), 1 + 1 + FILES);
    }

    /// 1000 entries of files of 4 MiB on one chain: a walk that read every
    /// file in full would hash 4 GiB. The walk ends at the first cluster
    /// of the second file.
    #[test]
    fn files_on_one_chain_are_refused() {
        use crate::dirent;

        const FILES: usize = 1000;
        const SIZE: usize = 4 << 20;
        let (img, mut v) = volume(8 << 20, 512, 4096);
        let t0 = t(1_700_000_000);
        let data: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
        put(&mut v, "/f0000", &data, t0, false);
        for i in 1..FILES {
            put(&mut v, &format!("/f{:04}", i), b"", t0, false);
        }
        let first = v.metadata("/f0000").unwrap().first_cluster;
        let root = v.metadata("/").unwrap();
        let others: Vec<u64> = short_entries(&v, root.first_cluster)
            .into_iter()
            .filter(|(name, _)| name.starts_with(b"F") && !name.starts_with(b"F0000"))
            .map(|(_, entry)| entry)
            .collect();
        assert_eq!(others.len(), FILES - 1);
        v.close().unwrap();
        let dev = img.device();
        for entry in others {
            set_first_cluster(&dev, entry, first);
            dev.write_at(entry + dirent::field::SIZE.start as u64, &(SIZE as u32).to_le_bytes())
                .unwrap();
        }
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::SHA256, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Chain,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if p == "/f0001" && *c == first
            ),
            "{:?}",
            e
        );
        let recs = records(&out);
        assert_eq!(recs.len(), 2);
        assert_eq!(
            recs[1].0,
            format!(r#"{{"name":"f0000","sha256":"{}"}}"#, Sha256::digest(&data))
        );
    }

    /// A file whose chain ends before the file does, or that starts at a
    /// cluster the volume does not have, is damage, found where the read
    /// for the hash runs out of the chain.
    #[test]
    fn a_file_longer_than_its_chain_is_refused() {
        use crate::dirent;
        use crate::fat::Entry;

        let (img, mut v) = volume(8 << 20, 512, 512);
        put(&mut v, "/f", &boot_data(), t(1_700_000_000), false);
        let f = v.metadata("/f").unwrap();
        let mut last = f.first_cluster;
        while let Entry::Next(next) = v.fat_entry(last).unwrap() {
            last = next;
        }
        let root = v.metadata("/").unwrap();
        let (_, entry) = short_entries(&v, root.first_cluster)
            .into_iter()
            .find(|(name, _)| name == b"F          ")
            .unwrap();
        let cs = u64::from(v.layout().cluster_size());
        let past = v.layout().max_cluster() + 1;
        v.close().unwrap();
        // One byte more than the chain holds, and the size it has at a
        // cluster that is not the volume's.
        let longer = boot_data().len().div_ceil(cs as usize) as u64 * cs + 1;
        for (first, size, found) in [(f.first_cluster, longer, last), (0, f.size, 0), (past, f.size, past)] {
            let dev = img.device();
            set_first_cluster(&dev, entry, first);
            dev.write_at(entry + dirent::field::SIZE.start as u64, &(size as u32).to_le_bytes())
                .unwrap();
            drop(dev);
            let v = Volume::open(img.device()).unwrap();
            let mut out = Vec::new();
            let e = v.write_manifest(None, Features::SHA256, &mut out).unwrap_err();
            assert_eq!(e.errno(), EUCLEAN);
            assert!(
                matches!(
                    e.detail(),
                    Some(Detail::Corrupt {
                        place: CorruptPlace::Chain,
                        path: Some(p),
                        cluster: Some(c),
                        ..
                    }) if p == "/f" && *c == found
                ),
                "{:?}",
                e
            );
            assert_eq!(records(&out).len(), 1);
        }
    }

    /// The read of the last cluster of a file looks at the FAT entry of
    /// that cluster, which ends the chain or goes on: one that is free,
    /// bad or no cluster at all is damage. The rest of a chain that goes on
    /// past the file is not read.
    #[test]
    fn the_fat_entry_of_the_last_cluster_of_a_file_is_checked() {
        use crate::dirent;
        use crate::fat::{Entry, BAD_CLUSTER, END_OF_CHAIN, FREE};

        let (img, mut v) = volume(8 << 20, 512, 512);
        let data = boot_data();
        put(&mut v, "/f", &data, t(1_700_000_000), false);
        let f = v.metadata("/f").unwrap();
        let mut last = f.first_cluster;
        while let Entry::Next(next) = v.fat_entry(last).unwrap() {
            last = next;
        }
        let root = v.metadata("/").unwrap();
        let (_, entry) = short_entries(&v, root.first_cluster)
            .into_iter()
            .find(|(name, _)| name == b"F          ")
            .unwrap();
        let layout = *v.layout();
        v.close().unwrap();
        // 1 is no cluster: the first one is 2.
        for value in [FREE, BAD_CLUSTER, 1] {
            set_fat_entry(&img.device(), &layout, last, value);
            let v = Volume::open(img.device()).unwrap();
            let mut out = Vec::new();
            let e = v.write_manifest(None, Features::SHA256, &mut out).unwrap_err();
            assert_eq!(e.errno(), EUCLEAN);
            assert!(
                matches!(
                    e.detail(),
                    Some(Detail::Corrupt {
                        place: CorruptPlace::Chain,
                        path: Some(p),
                        cluster: Some(c),
                        ..
                    }) if p == "/f" && *c == last
                ),
                "{:?}",
                e
            );
            assert_eq!(records(&out).len(), 1);
        }
        // A file of one cluster on that chain is fine: its cluster goes on
        // to the next one, and the broken end is never reached.
        let cs = layout.cluster_size() as usize;
        let dev = img.device();
        dev.write_at(entry + dirent::field::SIZE.start as u64, &(cs as u32).to_le_bytes())
            .unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let (bytes, _) = written(&v, None, Features::SHA256);
        assert_eq!(
            WrittenManifest::read(&bytes).entry("f").sha256,
            Some(Sha256::digest(&data[..cs]))
        );
        drop(v);
        // And with the end of the chain where it was, all of it hashes.
        set_fat_entry(&img.device(), &layout, last, END_OF_CHAIN);
        let dev = img.device();
        dev.write_at(
            entry + dirent::field::SIZE.start as u64,
            &(data.len() as u32).to_le_bytes(),
        )
        .unwrap();
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let (bytes, _) = written(&v, None, Features::SHA256);
        assert_eq!(
            WrittenManifest::read(&bytes).entry("f").sha256,
            Some(Sha256::digest(&data))
        );
    }

    /// A directory whose chain loops, here one whose FAT entry points at
    /// itself, is longer than a directory can be. It fails with Corrupt
    /// for the directory, which a client sees as such, and not with a
    /// plain error.
    #[test]
    fn a_directory_whose_chain_loops_is_refused() {
        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir("/d", t0).unwrap();
        put(&mut v, "/d/f", b"f", t0, false);
        let d = v.metadata("/d").unwrap().first_cluster;
        let layout = *v.layout();
        v.close().unwrap();
        set_fat_entry(&img.device(), &layout, d, d);
        let v = Volume::open(img.device()).unwrap();
        let mut out = Vec::new();
        let e = v.write_manifest(None, Features::NONE, &mut out).unwrap_err();
        assert_eq!(e.errno(), EUCLEAN);
        assert!(
            matches!(
                e.detail(),
                Some(Detail::Corrupt {
                    place: CorruptPlace::Directory,
                    path: Some(p),
                    cluster: Some(c),
                    ..
                }) if p == "/d" && *c == d
            ),
            "{:?}",
            e
        );
        assert_eq!(records(&out).len(), 1);
    }

    /// A long name with a unit that is an unpaired surrogate has no
    /// spelling in a manifest. Two such names that differ only there read
    /// as the same name with U+FFFD, and are no name twice: both are left
    /// out and counted.
    #[test]
    fn names_with_an_unpaired_surrogate_are_left_out() {
        use crate::dirent::{self, ATTR_LONG_NAME, DIR_ENTRY_SIZE};

        let (img, mut v) = volume(8 << 20, 512, 512);
        let t0 = t(1_700_000_000);
        v.create_dir("/d", t0).unwrap();
        // A '+' has no place in a short name, so each of these names is a
        // long name of one long name entry.
        put(&mut v, "/d/x+1", b"1", t0, false);
        put(&mut v, "/d/x+2", b"2", t0, false);
        put(&mut v, "/d/kept", b"k", t0, false);
        let d = v.metadata("/d").unwrap();
        let offset = v.layout().cluster_offset(d.first_cluster).unwrap();
        let mut cluster = vec![0u8; v.layout().cluster_size() as usize];
        v.close().unwrap();
        let dev = img.device();
        dev.read_at(offset, &mut cluster).unwrap();
        // The third unit of the names, the digit, becomes a high surrogate
        // that no low one follows, a different one in each name.
        let third = dirent::lfn_field::NAME1.start + 2 * size_of::<u16>();
        for (digit, surrogate) in [(b'1', 0xd800u16), (b'2', 0xd801)] {
            let slot = slot_of(&cluster, |e| {
                e[dirent::lfn_field::ATTR] == ATTR_LONG_NAME && e[third..third + 2] == [digit, 0]
            });
            dev.write_at(
                offset + (slot * DIR_ENTRY_SIZE + third) as u64,
                &surrogate.to_le_bytes(),
            )
            .unwrap();
        }
        drop(dev);
        let v = Volume::open(img.device()).unwrap();
        let lossy: Vec<String> = v
            .read_dir("/d")
            .unwrap()
            .into_iter()
            .filter(|md| md.name_decoding == NameDecoding::Lossy)
            .map(|md| md.name)
            .collect();
        assert_eq!(lossy, ["x+\u{fffd}", "x+\u{fffd}"]);
        let (bytes, report) = written(&v, None, Features::NONE);
        assert_eq!(WrittenManifest::read(&bytes).names(), ["d", "d/kept"]);
        assert_eq!((report.files, report.directories, report.omitted), (1, 1, 2));
    }
}
