// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `org.uapi-group.FileSystem` Varlink interface for cpio archives.
//!
//! An archive is no file system, and the interface is one for file
//! systems. What the two have in common is what a caller needs: something
//! in an image that is made from a tree or a manifest, added to, listed
//! and checked. Where an archive has no notion of what the interface asks
//! for, a label or an identifier, the call is refused the way the
//! interface says. Where the interface needs a number an archive has none
//! for, it gets the one that is true of an archive: the sector size is 1,
//! since an archive is addressed in bytes, and the block size is 4, the
//! multiple every entry starts at.

use std::io::BufWriter;
use std::time::SystemTime;

use ::service::{
    bad, fail, fd_param, invalid, optional, phase, required_fd, Failure, Image, ManifestSink, Outcome, Params,
    Reporter, Shown, INTERFACE, INTERFACE_NAME,
};
use cpio::check::{self, Problem, Severity};
use cpio::device::{Access, Device};
use cpio::header::{Format, Kind, MAX_FILE_SIZE, MAX_MTIME};
use cpio::host::{self, PassedSource};
use cpio::manifest::{Described, Manifest, SourceDirectory, WriteReport};
use cpio::name::{self, Name, NameBuf};
use cpio::plan::Plan;
use cpio::populate;
use cpio::progress::Progress;
use cpio::read::{self, Foreign};
use cpio::times::{TimePolicy, NSEC_PER_SEC, USEC_PER_SEC};
use cpio::tree::{Inode, Tree};
use cpio::write;
use cpio::Detail;
use json::{Object, Value};
use shared::hash::Hash;
use shared::manifest::{read_all, MAX_MANIFEST_BYTES};
use shared::times::{now, to_usec};
use varlink::{Activation, Call, Connection, Info, Reply, Server, Service};

use crate::ops::{Addition, How, Source};

const VERSION: &str = "0.1";
/// The one type this service makes. The kernel has no name for it, since
/// it unpacks an archive and mounts none: this is the name of the format.
const FILE_SYSTEM_TYPE: &str = "cpio";
/// Findings per intermediate reply of Check.
const PROBLEM_BATCH: usize = 100;
/// What the interface calls a sector and a block, see the top of this
/// file.
const SECTOR_SIZE: u32 = 1;
const BLOCK_SIZE: u32 = 4;

/// Serves the interface on whatever the environment handed over.
pub(crate) fn run(activation: Activation) -> std::io::Result<()> {
    let mut server = Server::new(Info {
        vendor: "ucpio".into(),
        product: "ucpio".into(),
        version: VERSION.into(),
        url: String::new(),
    });
    server
        .add_interface(INTERFACE)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    server.run(activation, &FileSystemService)
}

pub(crate) struct FileSystemService;

/// Assemble's options as the library takes them.
struct Options {
    layout: write::Options,
    root_entry: bool,
    time: Option<SystemTime>,
}

impl Options {
    /// The options of a call. What an archive has no notion of is refused the
    /// way the interface says: by the operation it would be, or as a parameter
    /// that is out of range.
    fn take(p: Option<Params<'_>>) -> Outcome<Options> {
        let mut options = Options {
            layout: write::Options::default(),
            root_entry: true,
            time: None,
        };
        let Some(p) = p else {
            return Ok(options);
        };
        if p.str("label").is_some() {
            return Err(Failure::Unsupported("label"));
        }
        if p.str("identifier").is_some() {
            return Err(Failure::Unsupported("identifier"));
        }
        if !p.strings("enableFeatures")?.is_empty() || !p.strings("disableFeatures")?.is_empty() {
            return Err(Failure::Unsupported("features"));
        }
        if p.bool("discard", false) {
            return Err(Failure::Unsupported("discard"));
        }
        if p.u32("sectorSize")?.is_some_and(|size| size != SECTOR_SIZE) {
            return Err(invalid("sectorSize"));
        }
        if p.u32("blockSize")?.is_some_and(|size| size != BLOCK_SIZE) {
            return Err(invalid("blockSize"));
        }
        if p.object("vfat").is_some() {
            return Err(invalid("vfat"));
        }
        options.time = p.time("timestampUSec")?;
        if p.bool("reproducible", false) && options.time.is_none() {
            return Err(Failure::NotReproducible("timestampRequired"));
        }
        if let Some(cpio) = p.object("cpio") {
            if let Some(alignment) = cpio.u32("endAlignment")? {
                options.layout.end_alignment = alignment;
            }
            if let Some(alignment) = cpio.u32("dataAlignment")? {
                options.layout.data_alignment = alignment;
            }
            if cpio.bool("checksums", false) {
                options.layout.format = Format::Crc;
            }
            options.root_entry = cpio.bool("rootEntry", true);
            options.layout.check().map_err(|_| invalid("cpio"))?;
        }
        Ok(options)
    }
}

/// The `Content` parameter, taken and vetted: every descriptor checked
/// and the manifest parsed before any image is touched.
struct Content {
    source: Option<Source>,
    how: How,
    sink: Option<ManifestSink>,
}

impl Content {
    /// What a call without content says: nothing goes in, and what is
    /// made is made at `time`.
    fn none(time: SystemTime) -> Content {
        Content {
            source: None,
            how: How {
                times: TimePolicy::Preserve,
                time,
                uid: None,
                gid: None,
                replace: true,
                now_usec: None,
            },
            sink: None,
        }
    }

    /// Takes the content's descriptors and reads its manifest. `time` is
    /// the content's time, Assemble's `timestampUSec` or Populate's, the
    /// current time when neither was given. One file is a source for
    /// Populate only.
    fn take(p: &Params<'_>, c: &mut Connection, time: SystemTime, populate: bool) -> Outcome<Content> {
        let source = match fd_param(c, p, "sourceFileDescriptor")? {
            None => None,
            Some(fd) => Some(host::passed_source(fd).map_err(bad("sourceFileDescriptor"))?),
        };
        let mut check_validity = true;
        let manifest = match p.object("manifest") {
            None => None,
            Some(m) => {
                let fd = required_fd(c, &m, "fileDescriptor").map_err(|_| invalid("manifest"))?;
                let file = host::passed_stream(fd).map_err(bad("manifest"))?;
                check_validity = m.bool("checkValidity", true);
                let text = read_all(file, MAX_MANIFEST_BYTES)?;
                Some(Manifest::parse(&text).map_err(cpio::Error::from)?)
            }
        };
        let sink = match p.object("manifestSink") {
            None => None,
            Some(s) => Some(ManifestSink::take(&s, c)?),
        };
        let times = match p.str("times").unwrap_or("preserve") {
            "fixed" => TimePolicy::Fixed(time),
            "clamp" => TimePolicy::Clamp(time),
            _ => TimePolicy::Preserve,
        };
        let how = How {
            times,
            time,
            uid: p.u32("uid")?,
            gid: p.u32("gid")?,
            replace: p.bool("replace", true),
            now_usec: check_validity.then(|| to_usec(now())),
        };
        // unsupported and extendedAttributes are accepted and change
        // nothing: an archive holds every kind of file there is, and of no
        // file its extended attributes.
        let source = match (manifest, source) {
            // The files a manifest names are checked to be where its
            // contents are before anything else happens.
            (Some(manifest), Some(PassedSource::Directory(fd))) => {
                let directory = SourceDirectory::new(fd).follow_symlinks(true);
                Some(Source::Manifest(Box::new(Described::in_directory(
                    manifest, directory,
                )?)))
            }
            (Some(manifest), Some(PassedSource::Stream(file))) => {
                Some(Source::Manifest(Box::new(Described::in_stream(manifest, file))))
            }
            // A manifest that has everything in it needs no source.
            (Some(manifest), None) => Some(Source::Manifest(Box::new(Described::in_stream(
                manifest,
                std::io::empty(),
            )))),
            (None, Some(PassedSource::Directory(fd))) => Some(Source::Tree(fd)),
            (None, Some(PassedSource::Stream(file))) => {
                if !populate || !file.metadata()?.is_file() {
                    return Err(invalid("sourceFileDescriptor"));
                }
                Some(Source::File(file))
            }
            (None, None) => None,
        };
        Ok(Content { source, how, sink })
    }
}

impl FileSystemService {
    /// Refuses any type but cpio, the one this service makes.
    fn check_type(p: &Params<'_>) -> Outcome<()> {
        match p.str("fileSystemType") {
            None | Some(FILE_SYSTEM_TYPE) => Ok(()),
            Some(other) => Err(Failure::FileSystemType(other.to_string())),
        }
    }

    /// What this implementation does for cpio; nothing in it depends on a
    /// call.
    pub(crate) fn capabilities() -> Object {
        json::object! {
            "fileSystemType" => FILE_SYSTEM_TYPE,
            "implementation" => "ucpio",
            "version" => VERSION,
            "readOnly" => false,
            "operations" => vec![
                "plan",
                "assembleWithContent",
                "populate",
                "list",
                "check",
                "reproducible",
                "manifest",
                "writeManifest",
            ],
            "sizeToFit" => "exact",
            // An archive without entries, padded to a multiple of four.
            "minimalSizeBytes" => write::Options {
                end_alignment: write::MIN_END_ALIGNMENT,
                ..write::Options::default()
            }
            .empty_len(),
            "sizeGranularityBytes" => BLOCK_SIZE,
            "sectorSizes" => vec![SECTOR_SIZE],
            "blockSizes" => vec![BLOCK_SIZE],
            "identifier" => "none",
            "preserves" => vec!["ownership", "modes", "hardlinks", "symlinks", "specialFiles"],
            "times" => json::object! {
                "resolutionNSec" => NSEC_PER_SEC,
                "minUSec" => 0u64,
                "maxUSec" => u64::from(MAX_MTIME) * USEC_PER_SEC,
                "created" => false,
                "accessed" => false,
                "changed" => false,
                "utc" => true,
            },
            "caseSensitive" => true,
            "nameLengthMax" => name::MAX_COMPONENT_LEN,
            "nameUnit" => "bytes",
            "fileSizeMaxBytes" => MAX_FILE_SIZE,
        }
    }

    /// A path of the interface, which starts at the root with a slash, as the
    /// name an archive has for it.
    fn name(path: &str, parameter: &str) -> Outcome<NameBuf> {
        if !path.starts_with('/') {
            return Err(invalid(parameter));
        }
        Ok(NameBuf::from_path(path.as_bytes())?)
    }

    /// The names the library has in its errors are the ones of the archive.
    /// The interface has paths from the root.
    fn rooted(failure: Failure) -> Failure {
        match failure {
            Failure::Other(e) => match e.detail() {
                Some(Detail::Path(path)) if !path.starts_with('/') => {
                    let rooted = if path == "." {
                        "/".to_string()
                    } else {
                        format!("/{}", path)
                    };
                    Failure::Other(e.with(Detail::Path(rooted)))
                }
                _ => Failure::Other(e),
            },
            other => other,
        }
    }

    /// A finding of Check as the interface carries it: its class, its kind and
    /// the facts it has. `slot` is the position of the entry among the entries
    /// and `block` where it starts, in units of four bytes.
    fn finding(p: &Problem) -> Object {
        let mut o = json::object! {
            "severity" => if p.severity == Severity::Error { "error" } else { "warning" },
            "class" => p.kind.class().as_str(),
            "kind" => p.kind.as_str(),
        };
        optional(&mut o, "path", p.path.as_deref());
        optional(&mut o, "slot", p.index);
        optional(&mut o, "block", p.offset.map(|offset| offset / u64::from(BLOCK_SIZE)));
        optional(&mut o, "sizeBytes", p.size_bytes);
        optional(&mut o, "value", p.value);
        optional(&mut o, "expected", p.expected);
        optional(&mut o, "name", p.found.map(Foreign::name));
        optional(&mut o, "field", p.field);
        optional(&mut o, "count", p.count);
        o
    }

    /// What an archive is, as the interface describes a file system.
    fn description(size: u64, minimal: Option<u64>) -> Object {
        let mut o = json::object! {
            "fileSystemType" => FILE_SYSTEM_TYPE,
            "sectorSize" => SECTOR_SIZE,
            "blockSize" => BLOCK_SIZE,
            "sizeBytes" => size,
        };
        optional(&mut o, "minimalSizeBytes", minimal);
        o
    }

    /// Writes the manifest of the archive in `archive` to `sink`, telling
    /// `progress` what it covered so far. `tree` is what the archive
    /// unpacks to, when the caller has worked that out already.
    fn write_manifest<S: read::Source + ?Sized>(
        sink: ManifestSink,
        archive: &S,
        tree: Option<&Tree>,
        progress: &mut dyn FnMut(&Progress),
    ) -> Outcome<WriteReport> {
        let opened;
        let tree = match tree {
            Some(tree) => tree,
            None => {
                opened = Tree::open(archive)?;
                &opened
            }
        };
        let mut out = BufWriter::new(sink.file);
        Ok(tree.write_manifest(archive, sink.fields, &mut out, progress)?)
    }

    /// An entry of List.
    fn entry(device: &Device, name: &[u8], inode: &Inode) -> Outcome<Object> {
        let mut o = json::object! {
            "name" => String::from_utf8_lossy(name).into_owned(),
            "type" => match inode.kind {
                Kind::Regular => "reg",
                Kind::Directory => "dir",
                Kind::Symlink => "lnk",
                Kind::CharDevice => "chr",
                Kind::BlockDevice => "blk",
                Kind::Fifo => "fifo",
                Kind::Socket => "sock",
            },
            "sizeBytes" => inode.size,
            "modifiedUSec" => to_usec(inode.modified()),
            "mode" => inode.mode,
            "uid" => inode.uid,
            "gid" => inode.gid,
        };
        if inode.kind == Kind::Symlink {
            let mut target = vec![0u8; inode.size as usize];
            device.read_at(inode.data_offset, &mut target)?;
            o.insert("target", String::from_utf8_lossy(&target).into_owned());
        }
        Ok(o)
    }

    fn get_capabilities(&self, p: &Params<'_>) -> Outcome<Object> {
        Self::check_type(p)?;
        Ok(json::object! { "capabilities" => Self::capabilities() })
    }

    fn assemble(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        Self::check_type(p)?;
        let plan_only = p.str("mode") == Some("plan");
        // Planning needs no image. One given with it says how much room
        // there is.
        let image = if plan_only {
            Image::take_optional(p, c)?
        } else {
            Some(Image::take(p, c)?)
        };
        let hash = match p.str("imageHash") {
            None => None,
            Some(a) => Some(Hash::new(a).ok_or_else(|| invalid("imageHash"))?),
        };
        let options = Options::take(p.object("options"))?;
        let time = options.time.unwrap_or_else(now);
        let Content { source, how, sink } = match p.object("content") {
            None => Content::none(time),
            Some(cp) => Content::take(&cp, c, time, false)?,
        };
        phase(c, more, "planning")?;
        let sources: Vec<Source> = source.into_iter().collect();
        let mut plan = Plan::new();
        if options.root_entry {
            plan.add_directory(Name::ROOT, how.root_attributes(&sources)?)?;
        }
        how.plan(&mut plan, sources, Name::ROOT)?;
        let measure = plan.measure(&options.layout, 0, &|_| false)?;
        if plan_only {
            if let Some(size) = image.and_then(|image| image.size).filter(|size| *size < measure.len) {
                return Err(Failure::TooSmall {
                    minimal: measure.len,
                    actual: size,
                });
            }
            return Ok(json::object! {
                "description" => Self::description(measure.len, Some(measure.len)),
                "exact" => true,
            });
        }
        let Some(image) = image else {
            return Err(invalid("image"));
        };
        let (device, offset, size) = image.device(Access::ReadWrite)?;
        let window = measure.make_room(device, offset, size)?;
        // The archive stays stopped until all of what was asked for is
        // done: a call that fails leaves nothing that is taken for an
        // archive.
        let (report, stopped) = {
            let mut r = Reporter::start(c, more, "populating", Shown::EntriesAndBytes)?;
            plan.assemble_stopped(&window, &options.layout, &measure, &mut |p| r.tick(p))?
        };
        let mut o = json::object! {
            "description" => Self::description(report.len, Some(measure.len)),
            "exact" => true,
            "files" => report.files,
            "directories" => report.directories,
            "bytes" => report.bytes,
            "skipped" => 0u64,
        };
        if let Some(sink) = sink {
            let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
            let written = Self::write_manifest(sink, &stopped.archive(), None, &mut |p| r.tick(p))?;
            o.insert("omitted", written.omitted);
        }
        stopped.finish()?;
        if let Some(hash) = hash {
            let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
            o.insert("imageHash", hash.of(&window, &mut |p| r.tick(p))?);
        }
        Ok(o)
    }

    fn describe(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        Self::check_type(p)?;
        let image = Image::take(p, c)?;
        let sink = match p.object("manifestSink") {
            None => None,
            Some(s) => Some(ManifestSink::take(&s, c)?),
        };
        let device = image.open(Access::ReadOnly)?;
        let tree = Tree::open(&device)?;
        let size = tree.archive_len(&device)?;
        let mut o = json::object! { "description" => Self::description(size, None) };
        if let Some(sink) = sink {
            let mut r = Reporter::start(c, more, "reading", Shown::EntriesAndBytes)?;
            let w = Self::write_manifest(sink, &device, Some(&tree), &mut |p| r.tick(p))?;
            o.insert("files", w.files);
            o.insert("directories", w.directories);
            o.insert("bytes", w.bytes);
            o.insert("omitted", w.omitted);
        }
        Ok(o)
    }

    fn populate(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        Self::check_type(p)?;
        let image = Image::take(p, c)?;
        let dest = Self::name(p.string("path")?, "path")?;
        let parents = p.bool("parents", false);
        let time = p.time("timestampUSec")?.unwrap_or_else(now);
        let Content { source, how, sink } = match p.object("content") {
            None => Content::none(time),
            Some(cp) => Content::take(&cp, c, time, true)?,
        };
        let (mut device, offset, size) = image.device(Access::ReadWrite)?;
        let report = {
            let mut r = Reporter::start(c, more, "populating", Shown::EntriesAndBytes)?;
            let addition = Addition {
                dest: dest.as_name(),
                source,
                parents,
                how,
                options: populate::Options {
                    replace: how.replace,
                    ..populate::Options::default()
                },
            };
            addition.apply(&mut device, offset, size, &mut |p| r.tick(p))?
        };
        let mut o = json::object! {
            "files" => report.files,
            "directories" => report.directories,
            "bytes" => report.bytes,
            "skipped" => 0u64,
        };
        if let Some(sink) = sink {
            let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
            let window = device.window(offset, size)?;
            let written = Self::write_manifest(sink, &window, None, &mut |p| r.tick(p))?;
            o.insert("omitted", written.omitted);
        }
        Ok(o)
    }

    fn list(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        Self::check_type(p)?;
        let image = Image::take(p, c)?;
        let path = Self::name(p.str("path").unwrap_or("/"), "path")?;
        let device = image.open(Access::ReadOnly)?;
        let tree = Tree::open(&device)?;
        let path = path.as_name();
        let Some(children) = tree.children(path.as_bytes()) else {
            return match tree.get(path.as_bytes()) {
                Some(inode) => Ok(json::object! { "entry" => Self::entry(&device, path.file_name(), inode)? }),
                None => Err(Failure::Other(
                    cpio::Error::new(cpio::errno::ENOENT, "no such entry").with(Detail::Path(path.to_string())),
                )),
            };
        };
        if !more {
            return Err(Failure::ExpectedMore);
        }
        // One entry per reply, the last one in the final reply; an empty
        // directory ends with a reply without an entry.
        let mut it = children.peekable();
        while let Some((name, inode)) = it.next() {
            let o = json::object! { "entry" => Self::entry(&device, name, inode)? };
            if it.peek().is_none() {
                return Ok(o);
            }
            c.notify(o)?;
        }
        Ok(Object::new())
    }

    fn check(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        Self::check_type(p)?;
        let image = Image::take(p, c)?;
        match p.str("repair") {
            None | Some("none") => {}
            Some(_) => return Err(Failure::Unsupported("repair")),
        }
        let device = image.open(Access::ReadOnly)?;
        let mut r = Reporter::start(c, more, "checking", Shown::PhaseOnly)?;
        let report = check::check_with_progress(&device, &mut |p| r.tick(p))?;
        let mut o = json::object! {
            "errors" => report.errors(),
            "warnings" => report.warnings(),
            "repaired" => 0u64,
            "dropped" => report.dropped,
            // Warnings are what another reader stumbles over; errors are
            // what the kernel loses.
            "clean" => report.errors() == 0,
        };
        if more {
            // The findings in batches, the counts in the final reply.
            for batch in report.problems.chunks(PROBLEM_BATCH) {
                let problems: Vec<Value> = batch.iter().map(|pr| Value::Object(Self::finding(pr))).collect();
                c.notify(json::object! { "problems" => problems })?;
            }
        } else {
            let problems: Vec<Value> = report
                .problems
                .iter()
                .map(|pr| Value::Object(Self::finding(pr)))
                .collect();
            o.insert("problems", problems);
        }
        Ok(o)
    }
}

impl Service for FileSystemService {
    fn call(&self, call: &Call, connection: &mut Connection) -> Reply {
        let p = Params(&call.parameters);
        let more = call.more;
        let method = call
            .method
            .strip_prefix(INTERFACE_NAME)
            .and_then(|m| m.strip_prefix('.'))
            .unwrap_or("");
        let result = match method {
            "GetCapabilities" => self.get_capabilities(&p),
            "Assemble" => self.assemble(&p, connection, more),
            "Describe" => self.describe(&p, connection, more),
            "Populate" => self.populate(&p, connection, more),
            // Nothing can be taken out of an archive without writing all
            // that follows it again.
            "Remove" => Self::check_type(&p).and(Err(Failure::Unsupported("remove"))),
            "List" => self.list(&p, connection, more),
            "Check" => self.check(&p, connection, more),
            _ => return Reply::Error(varlink::Error::method_not_implemented(&call.method)),
        };
        match result {
            Ok(o) => Reply::Final(o),
            Err(e) => Reply::Error(fail(Self::rooted(e))),
        }
    }
}
