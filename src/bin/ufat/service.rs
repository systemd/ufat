// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `org.uapi-group.FileSystem` Varlink service, serving vfat.
//!
//! Everything on the host reaches the service as a file descriptor passed
//! along with the call, never as a path: the caller opens what it may open
//! and hands it over, and nothing is resolved with the service's
//! privileges on its behalf. Every descriptor is vetted before use, the
//! way systemd's services vet an extrinsic descriptor (see
//! [`host::passed_image`] and friends): no O_PATH, no flags beyond the
//! access mode, read-only for everything that is read, read-write without
//! O_APPEND for the image, open for writing for a manifest sink.
//!
//! Nothing the service answers is text meant for a person: every error is
//! a name with typed fields and every finding of Check is a kind with its
//! facts; the client renders them in its own language.

use std::fs::File;
use std::io::BufWriter;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use json::{Object, Value};
use ufat::device::{Access, Device};
use ufat::dirent::{ATTR_ARCHIVE, ATTR_HIDDEN, ATTR_READ_ONLY, ATTR_SYSTEM};
use ufat::errno;
use ufat::format::{self, FormatOptions, VolumeId};
use ufat::fsck::{self, Problem};
use ufat::host;
use ufat::layout::{self, LayoutParams, MAX_CLUSTER_SIZE, MAX_SECTOR_SIZE, MIN_CLUSTERS, MIN_SECTOR_SIZE};
use ufat::manifest::volume::{Fields, WriteReport};
use ufat::manifest::{AssembleOptions, AssembleReport, DirectorySource, Manifest, StreamSource};
use ufat::plan::{Plan, PlanOptions};
use ufat::populate::{CopyOptions, CopyReport, TimePolicy};
use ufat::progress::Progress;
use ufat::sha256::Sha256;
use ufat::sha512::Sha512;
use ufat::volume::{Metadata, Volume};
use ufat::{CorruptPlace, Detail, NoSpaceReason, NotFat32Reason, UnsupportedKind};
use varlink::{Activation, Call, Connection, Info, Reply, Server, Service};

use crate::util;

/// The interface description, served verbatim.
pub(crate) const INTERFACE: &str = include_str!("../../../docs/org.uapi-group.FileSystem.varlink");
const INTERFACE_NAME: &str = "org.uapi-group.FileSystem";
const VERSION: &str = "0.1";
/// The one file system type this service makes, as the kernel names it.
const FILE_SYSTEM_TYPE: &str = "vfat";
/// Findings per intermediate reply of Check.
const PROBLEM_BATCH: usize = 100;
/// Bytes read at a time when the image is hashed.
const HASH_STEP: usize = 1 << 20;

/// Serves the interface on whatever the environment handed over.
pub(crate) fn run(activation: Activation) -> std::io::Result<()> {
    let mut server = Server::new(Info {
        vendor: "ufat".into(),
        product: "ufat".into(),
        version: VERSION.into(),
        url: String::new(),
    });
    server
        .add_interface(INTERFACE)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    server.run(activation, &FileSystemService)
}

struct FileSystemService;

/// Why a call failed, as the interface reports it. No error carries text:
/// every one is a name with typed fields, and the client puts them into
/// words. What the library's error says in words goes to the service's
/// own log at most; what it says in its [`Detail`] becomes the fields.
enum Failure {
    /// A parameter is missing, of the wrong shape or out of range:
    /// `org.varlink.service.InvalidParameter` with its name.
    Invalid(String),
    /// A descriptor passed with the call is not usable as the parameter
    /// names it: `BadFileDescriptor`.
    BadDescriptor { parameter: String, error: ufat::Error },
    /// The image cannot hold what the content needs.
    TooSmall { minimal: u64, actual: u64 },
    /// What was asked for is not among the operations vfat offers.
    Unsupported(&'static str),
    /// Another file system type than vfat was asked for.
    FileSystemType(String),
    /// Reproducible output was asked for without what it needs.
    NotReproducible(&'static str),
    /// Nothing says how large the file system is to be.
    SizeRequired,
    /// The image is claimed by something else, a mount most likely.
    Busy,
    /// A directory listing was asked for without the more flag.
    ExpectedMore,
    /// Anything else, mapped by its detail, or by its errno when it has
    /// none.
    Other(ufat::Error),
}

impl From<ufat::Error> for Failure {
    fn from(e: ufat::Error) -> Failure {
        Failure::Other(e)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Failure {
        Failure::Other(ufat::Error::from(e))
    }
}

type Outcome<T> = Result<T, Failure>;

fn invalid(parameter: &str) -> Failure {
    Failure::Invalid(parameter.to_string())
}

/// Turns the vetting error of a passed descriptor into the interface's
/// error for it, naming the parameter; anything else passes through.
fn bad(parameter: &str) -> impl Fn(ufat::Error) -> Failure + '_ {
    move |e| {
        if e.errno() == errno::EBADFD {
            Failure::BadDescriptor {
                parameter: parameter.to_string(),
                error: e,
            }
        } else {
            Failure::Other(e)
        }
    }
}

fn interface_error(name: &str, parameters: Object) -> varlink::Error {
    varlink::Error::new(format!("{}.{}", INTERFACE_NAME, name), parameters)
}

/// Adds `value` to `o` under `key` when there is one.
fn optional<T: Into<Value>>(o: &mut Object, key: &str, value: Option<T>) {
    if let Some(v) = value {
        o.insert(key, v);
    }
}

/// The interface's name for an option the library refuses: the library
/// speaks of the cluster size where the interface says block size.
fn option_name(name: &str) -> &str {
    match name {
        "clusterSize" => "blockSize",
        other => other,
    }
}

/// The library's damaged structure as the interface's `CorruptPlace`.
fn corrupt_place(place: CorruptPlace) -> &'static str {
    match place {
        CorruptPlace::BootSector => "superblock",
        CorruptPlace::Fat => "allocation",
        CorruptPlace::Chain => "chain",
        CorruptPlace::Directory => "directory",
    }
}

/// What ran out, as the interface's `NoSpaceReason`: clusters are its
/// blocks, short name tails its names.
fn no_space_reason(reason: NoSpaceReason) -> &'static str {
    match reason {
        NoSpaceReason::Clusters => "blocks",
        NoSpaceReason::Volume => "volume",
        NoSpaceReason::DirectoryEntries => "directoryEntries",
        NoSpaceReason::ShortNames => "names",
    }
}

/// Why the image holds no FAT32 volume, as the interface's
/// `NotFileSystemReason`. A boot sector that is not blank and not FAT32
/// belongs to something else, a FAT12 or FAT16 volume or another file
/// system altogether, which is `otherFileSystem`; the library does not
/// say what it found, so `found` stays unset.
fn not_file_system_reason(reason: NotFat32Reason) -> &'static str {
    match reason {
        NotFat32Reason::Blank => "blank",
        NotFat32Reason::NotFat32 => "otherFileSystem",
        NotFat32Reason::SectorSize => "sectorSize",
        NotFat32Reason::TooSmall => "tooSmall",
    }
}

/// Maps a library error to the interface's errors by its detail, falling
/// back to the generic errno error systemd tools use when it has none.
fn map_error(e: &ufat::Error) -> varlink::Error {
    let Some(detail) = e.detail() else {
        return varlink::Error::system(e.errno());
    };
    match detail {
        Detail::Path(path) => {
            let name = match e.errno() {
                errno::ENOENT => "NoSuchFile",
                errno::EEXIST => "FileExists",
                errno::ENOTDIR => "NotADirectory",
                errno::EISDIR => "IsADirectory",
                errno::ENOTEMPTY => "DirectoryNotEmpty",
                other => return varlink::Error::system(other),
            };
            interface_error(name, json::object! { "path" => path.as_str() })
        }
        Detail::Name { name, problem } => interface_error(
            "InvalidName",
            json::object! { "name" => name.as_str(), "reason" => problem.as_str() },
        ),
        Detail::Label { label, problem } => interface_error(
            "InvalidLabel",
            json::object! { "label" => label.as_str(), "reason" => problem.as_str() },
        ),
        Detail::Identifier { identifier, problem } => interface_error(
            "InvalidIdentifier",
            json::object! { "identifier" => identifier.as_str(), "reason" => problem.as_str() },
        ),
        Detail::TooLarge { path, size, maximum } => {
            let mut o = json::object! { "sizeBytes" => *size, "sizeMaxBytes" => *maximum };
            optional(&mut o, "path", path.as_deref());
            interface_error("TooLarge", o)
        }
        Detail::NoSpace { reason, path } => {
            let mut o = json::object! { "reason" => no_space_reason(*reason) };
            optional(&mut o, "path", path.as_deref());
            interface_error("NoSpaceLeft", o)
        }
        Detail::NotFat32 { reason, sector_size } => {
            let mut o = json::object! { "reason" => not_file_system_reason(*reason) };
            optional(&mut o, "sectorSize", *sector_size);
            interface_error("NotFileSystem", o)
        }
        Detail::Corrupt {
            place,
            field,
            path,
            cluster,
        } => {
            let mut o = json::object! { "where" => corrupt_place(*place) };
            optional(&mut o, "field", *field);
            optional(&mut o, "path", path.as_deref());
            optional(&mut o, "block", *cluster);
            interface_error("Corrupt", o)
        }
        // A descriptor problem is reported by the method that knows which
        // parameter it came with, see `bad`; one without is a plain errno.
        Detail::Descriptor { .. } => varlink::Error::system(e.errno()),
        Detail::Manifest {
            problem,
            record,
            name,
            field,
        } => {
            let mut o = json::object! { "reason" => problem.as_str() };
            optional(&mut o, "record", *record);
            optional(&mut o, "name", name.as_deref());
            optional(&mut o, "field", field.as_deref());
            interface_error("InvalidManifest", o)
        }
        Detail::Source {
            name,
            problem,
            size,
            expected,
        } => {
            let mut o = json::object! { "name" => name.as_str(), "reason" => problem.as_str() };
            optional(&mut o, "sizeBytes", *size);
            optional(&mut o, "expectedSizeBytes", *expected);
            interface_error("SourceMismatch", o)
        }
        Detail::Content {
            name,
            problem,
            size,
            expected,
        } => {
            let mut o = json::object! { "name" => name.as_str(), "reason" => problem.as_str() };
            optional(&mut o, "sizeBytes", *size);
            optional(&mut o, "expectedSizeBytes", *expected);
            interface_error("ContentMismatch", o)
        }
        Detail::Unsupported { name, what, value } => {
            let mut o = json::object! { "what" => what.as_str() };
            optional(&mut o, "name", name.as_deref());
            optional(&mut o, "value", value.as_deref());
            interface_error("ContentNotSupported", o)
        }
        Detail::Validity { name, problem } => interface_error(
            "EntryNotValid",
            json::object! { "name" => name.as_str(), "reason" => problem.as_str() },
        ),
        Detail::InvalidOption(name) => varlink::Error::invalid_parameter(option_name(name)),
    }
}

fn fail(f: Failure) -> varlink::Error {
    match f {
        Failure::Invalid(parameter) => varlink::Error::invalid_parameter(&parameter),
        Failure::BadDescriptor { parameter, error } => {
            let (problem, flags) = match error.detail() {
                Some(Detail::Descriptor { problem, flags }) => (problem.as_str(), *flags),
                _ => ("wrongType", None),
            };
            let mut o = json::object! { "parameter" => parameter, "reason" => problem };
            optional(&mut o, "flags", flags);
            interface_error("BadFileDescriptor", o)
        }
        Failure::TooSmall { minimal, actual } => interface_error(
            "TooSmall",
            json::object! {
                "minimalSizeBytes" => minimal,
                "sizeBytes" => actual,
            },
        ),
        Failure::Unsupported(operation) => {
            interface_error("OperationNotSupported", json::object! { "operation" => operation })
        }
        Failure::FileSystemType(t) => {
            interface_error("FileSystemTypeNotSupported", json::object! { "fileSystemType" => t })
        }
        Failure::NotReproducible(reason) => interface_error("NotReproducible", json::object! { "reason" => reason }),
        Failure::SizeRequired => interface_error("SizeRequired", Object::new()),
        Failure::Busy => interface_error("ImageBusy", Object::new()),
        Failure::ExpectedMore => varlink::Error::expected_more(),
        Failure::Other(e) => map_error(&e),
    }
}

/// The error of the fit, as a failure of the call.
fn fit_error(e: util::FitError) -> Failure {
    match e {
        util::FitError::TooSmall { minimal, actual } => Failure::TooSmall { minimal, actual },
        util::FitError::Other(e) => Failure::Other(e),
    }
}

/// A finding of Check as the interface carries it: its class, its kind and
/// the facts it has, with the interface's names (a cluster is a block).
fn problem(p: &Problem) -> Object {
    let mut o = json::object! {
        "severity" => if p.severity == fsck::Severity::Error { "error" } else { "warning" },
        "class" => p.kind.class().as_str(),
        "kind" => p.kind.as_str(),
    };
    optional(&mut o, "path", p.path.as_deref());
    optional(&mut o, "otherPath", p.other_path.as_deref());
    optional(&mut o, "slot", p.slot);
    optional(&mut o, "slots", p.slots);
    optional(&mut o, "block", p.cluster);
    optional(&mut o, "blocks", p.clusters);
    optional(&mut o, "blocksNeeded", p.clusters_needed);
    optional(&mut o, "sizeBytes", p.size_bytes);
    optional(&mut o, "value", p.value);
    optional(&mut o, "expected", p.expected);
    optional(&mut o, "name", p.name.as_deref());
    optional(&mut o, "otherName", p.other_name.as_deref());
    optional(&mut o, "field", p.field);
    optional(&mut o, "copy", p.copy);
    optional(&mut o, "count", p.count);
    o
}

/// Typed access to validated parameters. A value that is there but out of
/// range is InvalidParameter with the parameter's name, as in systemd.
struct Params<'a>(&'a Object);

impl Params<'_> {
    fn str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    fn string(&self, key: &str) -> Outcome<&str> {
        self.str(key).ok_or_else(|| invalid(key))
    }

    fn u64(&self, key: &str) -> Outcome<Option<u64>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(i)) => u64::try_from(*i).map(Some).map_err(|_| invalid(key)),
            Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(|_| invalid(key)),
            Some(_) => Err(invalid(key)),
        }
    }

    fn u32(&self, key: &str) -> Outcome<Option<u32>> {
        self.u64(key)?.map(u32::try_from).transpose().map_err(|_| invalid(key))
    }

    /// The index an `...FileDescriptor` parameter carries.
    fn index(&self, key: &str) -> Outcome<Option<usize>> {
        self.u64(key)?
            .map(|v| usize::try_from(v).map_err(|_| invalid(key)))
            .transpose()
    }

    /// The strings of an array parameter, none when it is absent.
    fn strings(&self, key: &str) -> Outcome<Vec<&str>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => a.iter().map(|v| v.as_str().ok_or_else(|| invalid(key))).collect(),
            Some(_) => Err(invalid(key)),
        }
    }

    fn bool(&self, key: &str, default: bool) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(default)
    }

    fn object(&self, key: &str) -> Option<Params<'_>> {
        self.0.get(key).and_then(Value::as_object).map(Params)
    }

    fn time(&self, key: &str) -> Outcome<Option<SystemTime>> {
        Ok(self.u64(key)?.map(ufat::time::from_usec))
    }
}

/// Takes the descriptor the parameter `key` names from the call, if the
/// parameter is there. An index that names no descriptor is as wrong as a
/// value out of range.
fn fd_param(c: &mut Connection, p: &Params<'_>, key: &str) -> Outcome<Option<OwnedFd>> {
    match p.index(key)? {
        None => Ok(None),
        Some(i) => c.take_fd(i).map(Some).map_err(|_| invalid(key)),
    }
}

fn required_fd(c: &mut Connection, p: &Params<'_>, key: &str) -> Outcome<OwnedFd> {
    fd_param(c, p, key)?.ok_or_else(|| invalid(key))
}

/// Refuses any file system type but vfat, the one this service makes.
fn check_type(p: &Params<'_>) -> Outcome<()> {
    match p.str("fileSystemType") {
        None | Some(FILE_SYSTEM_TYPE) => Ok(()),
        Some(other) => Err(Failure::FileSystemType(other.to_string())),
    }
}

/// Tells a client that asked for intermediate replies which step begins.
fn phase(c: &mut Connection, more: bool, phase: &str) -> Outcome<()> {
    if more {
        c.notify(json::object! { "phase" => phase })?;
    }
    Ok(())
}

/// How often a call made with the more flag hears how far a phase got.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(1);

/// What a progress reply shows beside the phase: the counts the method's
/// final reply has fields for, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shown {
    PhaseOnly,
    Entries,
    EntriesAndBytes,
}

/// The intermediate replies of a phase that does long work, for a call
/// made with the more flag: the phase when it starts, then the phase again
/// at most once per PROGRESS_INTERVAL while it lasts, with the counts so
/// far. So a caller sees how far the phase got, and the connection is
/// never quiet long enough for the caller's idle timeout to fire.
struct Reporter<'c> {
    connection: &'c mut Connection,
    more: bool,
    phase: &'static str,
    shown: Shown,
    last: Instant,
    /// The caller stopped taking replies. It is not told again; the final
    /// reply finds out.
    gone: bool,
}

impl<'c> Reporter<'c> {
    /// Enters `phase` and tells the caller, as [`phase`] does.
    fn start(connection: &'c mut Connection, more: bool, phase: &'static str, shown: Shown) -> Outcome<Reporter<'c>> {
        if more {
            connection.notify(json::object! { "phase" => phase })?;
        }
        Ok(Reporter {
            connection,
            more,
            phase,
            shown,
            last: Instant::now(),
            gone: false,
        })
    }

    /// Tells the caller how far the phase got, once PROGRESS_INTERVAL has
    /// passed since the last reply.
    fn tick(&mut self, progress: &Progress) {
        if !self.more || self.gone || self.last.elapsed() < PROGRESS_INTERVAL {
            return;
        }
        let mut o = json::object! { "phase" => self.phase };
        if self.shown != Shown::PhaseOnly {
            o.insert("files", progress.files);
            o.insert("directories", progress.directories);
        }
        if self.shown == Shown::EntriesAndBytes {
            o.insert("bytes", progress.bytes);
        }
        self.gone = self.connection.notify(o).is_err();
        self.last = Instant::now();
    }
}

/// The image parameter: the descriptor passed for it plus the byte range.
struct Image {
    fd: OwnedFd,
    offset: u64,
    size: Option<u64>,
}

impl Image {
    /// The `image` parameter, which has to be there.
    fn take(p: &Params<'_>, c: &mut Connection) -> Outcome<Image> {
        Image::take_optional(p, c)?.ok_or_else(|| invalid("image"))
    }

    /// The `image` parameter, when there is one.
    fn take_optional(p: &Params<'_>, c: &mut Connection) -> Outcome<Option<Image>> {
        let Some(image) = p.object("image") else {
            return Ok(None);
        };
        // Whatever is wrong inside is reported for the parameter as a whole.
        let inside = |_| invalid("image");
        let fd = required_fd(c, &image, "fileDescriptor").map_err(inside)?;
        Ok(Some(Image {
            fd,
            offset: image.u64("offset").map_err(inside)?.unwrap_or(0),
            size: image.u64("size").map_err(inside)?,
        }))
    }

    /// A second descriptor of the image, to read it back once the volume
    /// is closed.
    fn reader(&self) -> Outcome<OwnedFd> {
        Ok(self.fd.try_clone()?)
    }

    /// The whole image, vetted and claimed, with the window still to apply.
    /// A block device that is mounted or claimed by another process is
    /// `ImageBusy`.
    fn device(self, access: Access) -> Outcome<(Device, u64, Option<u64>)> {
        let device = host::passed_image(self.fd, access).map_err(|e| {
            if e.errno() == errno::EBUSY {
                Failure::Busy
            } else {
                bad("image")(e)
            }
        })?;
        Ok((device, self.offset, self.size))
    }

    /// The file system's byte range of the image.
    fn open(self, access: Access) -> Outcome<Device> {
        let (device, offset, size) = self.device(access)?;
        Ok(device.window(offset, size)?)
    }

    fn open_volume(self, access: Access) -> Outcome<Volume> {
        Ok(Volume::open(self.open(access)?)?)
    }
}

/// Assemble's options as the library takes them, plus what the service has
/// to remember about them.
struct Options {
    format: FormatOptions,
    /// `timestampUSec` as given; None when the current time stands in.
    time: Option<SystemTime>,
}

fn format_options(p: Option<Params<'_>>) -> Outcome<Options> {
    let mut o = FormatOptions {
        // Never fewer than 65525 clusters: EDK2 refuses a smaller volume,
        // and an interface for ESPs has no use for one.
        allow_small: false,
        ..FormatOptions::default()
    };
    let Some(p) = p else {
        o.volume_id = util::pick_volume_id(util::now(), None, false);
        o.timestamp = Some(util::now());
        return Ok(Options { format: o, time: None });
    };
    // What FAT has no notion of is refused, not ignored.
    if p.bool("discard", false) {
        return Err(Failure::Unsupported("discard"));
    }
    if !p.strings("enableFeatures")?.is_empty() || !p.strings("disableFeatures")?.is_empty() {
        return Err(Failure::Unsupported("features"));
    }
    o.sector_size = p.u32("sectorSize")?;
    o.cluster_size = p.u32("blockSize")?;
    if let Some(bs) = o.cluster_size {
        if !bs.is_power_of_two() || bs < MIN_SECTOR_SIZE {
            return Err(invalid("blockSize"));
        }
    }
    // The label is validated by the library when the volume is planned or
    // formatted; a bad one surfaces as InvalidLabel.
    o.label = p.str("label").map(str::to_string);
    let time = p.time("timestampUSec")?;
    o.timestamp = Some(time.unwrap_or_else(util::now));
    let identifier = p.str("identifier");
    if p.bool("reproducible", false) {
        if identifier.is_none() {
            return Err(Failure::NotReproducible("identifierRequired"));
        }
        if time.is_none() {
            return Err(Failure::NotReproducible("timestampRequired"));
        }
    }
    o.volume_id = match identifier {
        Some(id) => id.parse::<VolumeId>()?.0,
        None => util::pick_volume_id(time.unwrap_or_else(util::now), o.label.as_deref(), time.is_some()),
    };
    o.zero_data_area = p.bool("zero", false);
    if let Some(v) = p.object("vfat") {
        if let Some(reserved) = v.u32("reservedSectors")? {
            o.reserved_sectors = reserved;
        }
        if let Some(fats) = v.u32("fats")? {
            o.fats = fats;
        }
        if let Some(name) = v.str("oemName") {
            o.oem_name = format::encode_oem_name(name)?;
        }
        o.hidden_sectors = v.u32("hiddenSectors")?;
        o.mkfs_fat_compat = v.bool("mkfsFatCompatible", false);
    }
    Ok(Options { format: o, time })
}

/// The block size against the sector size the format will use, checked
/// before the device is written: the library refuses the combination too,
/// but without a detail that names the parameter.
fn check_block_size(options: &FormatOptions, device: &Device) -> Outcome<()> {
    if let Some(bs) = options.cluster_size {
        let ss = format::resolve_sector_size(options.sector_size, device.logical_block_size()?)?;
        if bs % ss != 0 || bs / ss > layout::MAX_SECTORS_PER_CLUSTER {
            return Err(invalid("blockSize"));
        }
    }
    Ok(())
}

/// The label as a volume formatted with `options` reports it: the stored
/// form, trimmed, and none for the blank label.
fn stored_label(options: &FormatOptions) -> Outcome<Option<String>> {
    Ok(match &options.label {
        None => None,
        Some(l) => {
            let raw = format::encode_label(l)?;
            if raw == ufat::boot::NO_NAME {
                None
            } else {
                Some(format::decode_label(&raw))
            }
        }
    })
}

/// The file system as it is: the interface's `Description`.
fn description(v: &Volume) -> Outcome<Object> {
    let l = v.layout();
    let mut o = json::object! {
        "fileSystemType" => FILE_SYSTEM_TYPE,
        "identifier" => VolumeId(v.boot_sector().volume_id).to_string(),
        "sectorSize" => l.sector_size,
        "blockSize" => l.cluster_size(),
        "sizeBytes" => l.size(),
        "freeBytes" => v.free_bytes(),
    };
    optional(&mut o, "label", v.label()?);
    Ok(o)
}

/// A directory entry as the interface's `Entry`: FAT has names, an 8.3
/// alias, sizes, two times and the DOS attributes, and nothing else.
fn entry(m: &Metadata) -> Object {
    let mut o = json::object! {
        "name" => m.name.as_str(),
        "type" => if m.is_dir { "dir" } else { "reg" },
        "sizeBytes" => m.size,
        "modifiedUSec" => ufat::time::to_usec(m.modified),
        "createdUSec" => ufat::time::to_usec(m.created),
        "alternateName" => m.short_name.as_str(),
    };
    let attributes: Vec<&str> = [
        (ATTR_READ_ONLY, "readOnly"),
        (ATTR_HIDDEN, "hidden"),
        (ATTR_SYSTEM, "system"),
        (ATTR_ARCHIVE, "archive"),
    ]
    .iter()
    .filter(|(bit, _)| m.attributes & bit != 0)
    .map(|(_, name)| *name)
    .collect();
    if !attributes.is_empty() {
        o.insert("dosAttributes", attributes);
    }
    o
}

/// What this implementation does for vfat; nothing in it depends on a
/// call.
pub(crate) fn capabilities() -> ufat::Result<Object> {
    // The smallest volume: MIN_CLUSTERS clusters of one 512 byte sector.
    let mut params = LayoutParams::new(MIN_SECTOR_SIZE);
    params.sectors_per_cluster = Some(1);
    let minimal = layout::minimal(&params, MIN_CLUSTERS)?.size();
    let powers_of_two =
        |from: u32, to: u32| -> Vec<u32> { (0..).map(|i| from << i).take_while(|&s| s <= to).collect() };
    Ok(json::object! {
        "fileSystemType" => FILE_SYSTEM_TYPE,
        "implementation" => "ufat",
        "version" => VERSION,
        "readOnly" => false,
        "operations" => vec![
            "plan",
            "assembleWithContent",
            "populate",
            "remove",
            "list",
            "check",
            "label",
            "identifier",
            "reproducible",
            "manifest",
            "writeManifest",
        ],
        "sizeToFit" => "exact",
        "minimalSizeBytes" => minimal,
        // 0xFFFFFFFF sectors of 512 bytes, the total sectors field's limit.
        "maximalSizeBytes" => u64::from(u32::MAX) * u64::from(MIN_SECTOR_SIZE),
        "sizeGranularityBytes" => MIN_SECTOR_SIZE,
        "sectorSizes" => powers_of_two(MIN_SECTOR_SIZE, MAX_SECTOR_SIZE),
        // Cluster sizes up to the specification's 32 KiB, which is as far
        // as the planner goes; larger clusters work on Linux but not
        // everywhere.
        "blockSizes" => powers_of_two(MIN_SECTOR_SIZE, MAX_CLUSTER_SIZE),
        "label" => json::object! { "lengthMax" => 11, "unit" => "bytes", "charset" => "fat" },
        "identifier" => "serial",
        "preserves" => vec!["dosAttributes"],
        "times" => json::object! {
            "resolutionNSec" => 2_000_000_000u64,
            "minUSec" => ufat::time::FAT_EPOCH as u64 * 1_000_000,
            "maxUSec" => ufat::time::FAT_MAX as u64 * 1_000_000,
            "created" => true,
            "accessed" => true,
            "changed" => false,
            "utc" => true,
        },
        "caseSensitive" => false,
        "nameLengthMax" => 255,
        "nameUnit" => "utf16Units",
        "fileSizeMaxBytes" => ufat::volume::MAX_FILE_SIZE,
    })
}

/// The hash of an image window, as `imageHash` asks for it.
pub(crate) enum Hash {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hash {
    pub(crate) fn new(algorithm: &str) -> Option<Hash> {
        match algorithm {
            "sha256" => Some(Hash::Sha256(Sha256::new())),
            "sha512" => Some(Hash::Sha512(Sha512::new())),
            _ => None,
        }
    }

    /// Reads the whole window of `device` back and returns the hash in
    /// lowercase hex, telling `progress` how many bytes it read so far after
    /// every read.
    pub(crate) fn of(mut self, device: &Device, progress: &mut dyn FnMut(&Progress)) -> ufat::Result<String> {
        let mut buf = vec![0u8; HASH_STEP];
        let mut offset = 0;
        while offset < device.len() {
            let n = (device.len() - offset).min(HASH_STEP as u64) as usize;
            device.read_at(offset, &mut buf[..n])?;
            match &mut self {
                Hash::Sha256(h) => h.update(&buf[..n]),
                Hash::Sha512(h) => h.update(&buf[..n]),
            }
            offset += n as u64;
            progress(&Progress {
                bytes: offset,
                ..Progress::default()
            });
        }
        Ok(match self {
            Hash::Sha256(h) => ufat::sha256::to_hex(&h.finalize()),
            Hash::Sha512(h) => ufat::sha512::to_hex(&h.finalize()),
        })
    }
}

/// The manifest sink: the descriptor and the fields the manifest carries.
struct Sink {
    file: File,
    fields: Fields,
}

impl Sink {
    fn take(p: &Params<'_>, c: &mut Connection) -> Outcome<Sink> {
        let fd = required_fd(c, p, "fileDescriptor").map_err(|_| invalid("manifestSink"))?;
        let file = host::passed_sink(fd).map_err(bad("manifestSink"))?;
        let fields = match p.0.get("fields") {
            None | Some(Value::Null) => Fields::default(),
            Some(_) => Fields::from_names(p.strings("fields")?).ok_or_else(|| invalid("manifestSink"))?,
        };
        Ok(Sink { file, fields })
    }

    /// Writes the manifest of everything `volume` holds, telling `progress`
    /// what it covered so far.
    fn write(self, volume: &Volume, progress: &mut dyn FnMut(&Progress)) -> Outcome<WriteReport> {
        let mut out = BufWriter::new(self.file);
        Ok(ufat::manifest::volume::write_with_progress(
            volume,
            volume.root_time()?,
            self.fields,
            &mut out,
            progress,
        )?)
    }
}

/// What goes into the file system once the content is vetted; the fill
/// depends on it.
enum Fill {
    /// The tree below a directory, copied as it is.
    Tree(OwnedFd),
    /// One regular file, Populate only.
    File(File),
    /// A manifest with its files below a directory.
    FromDirectory(Manifest, DirectorySource),
    /// A manifest with its files' contents in a stream.
    FromStream(Manifest, File),
    /// A manifest alone, enough for a plan.
    ManifestOnly(Manifest),
}

/// Which method takes the content: what it may be depends on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Taker {
    /// Assemble with mode plan: a manifest needs no source.
    Plan,
    /// Assemble: a tree, or a manifest with its source.
    Assemble,
    /// Populate: as Assemble, and one regular file.
    Populate,
}

/// The shape of the content, for the method to decide its steps.
enum Shape {
    Nothing,
    Tree,
    File,
    Manifest,
}

/// What was written, as the replies count it.
#[derive(Default)]
struct Counts {
    files: u64,
    directories: u64,
    bytes: u64,
    skipped: u64,
}

impl Counts {
    fn of_copy(r: &CopyReport) -> Counts {
        Counts {
            files: r.files,
            directories: r.directories,
            bytes: r.bytes,
            skipped: r.skipped.len() as u64,
        }
    }

    fn of_assembly(r: &AssembleReport) -> Counts {
        Counts {
            files: r.files,
            directories: r.directories,
            bytes: r.bytes,
            skipped: r.skipped.len() as u64,
        }
    }

    /// What was skipped is counted, not named: the names would be paths
    /// relative to a directory the caller knows by descriptor only, and
    /// a list is as long as the caller's tree lets it be.
    fn put(&self, o: &mut Object) {
        o.insert("files", self.files);
        o.insert("directories", self.directories);
        o.insert("bytes", self.bytes);
        o.insert("skipped", self.skipped);
    }
}

/// Refuses a tree whose copy would leave entries out, under
/// UnsupportedPolicy fail: the first of them is named, as the inode type
/// FAT has no notion of.
fn refuse_skipped(skipped: &[PathBuf]) -> ufat::Result<()> {
    match skipped.first() {
        None => Ok(()),
        Some(path) => Err(
            ufat::Error::new(errno::EINVAL, format!("{} cannot be stored on FAT", path.display())).with(
                Detail::Unsupported {
                    name: Some(path.display().to_string()),
                    what: UnsupportedKind::InodeType,
                    value: None,
                },
            ),
        ),
    }
}

/// The `Content` parameter, taken and vetted: every descriptor checked,
/// the manifest parsed, the source verified against it, before any image
/// is touched.
struct Content {
    fill: Option<Fill>,
    /// The fixed or clamping time of the time policy, and the time of
    /// what a manifest leaves undated.
    time: SystemTime,
    times: TimePolicy,
    replace: bool,
    /// UnsupportedPolicy fail: refuse what cannot be stored instead of
    /// leaving it out.
    fail_unsupported: bool,
    check_validity: bool,
    sink: Option<Sink>,
    /// The source directory's modification time, for the root.
    source_mtime: Option<SystemTime>,
    /// The manifest's root object's time, for the root.
    manifest_mtime: Option<SystemTime>,
}

impl Content {
    /// Takes the content's descriptors and reads its manifest. `time` is
    /// the content's time, Assemble's `timestampUSec` or Populate's, the
    /// current time when neither was given.
    fn take(p: &Params<'_>, c: &mut Connection, time: SystemTime, taker: Taker) -> Outcome<Content> {
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
                Some(util::read_manifest(file)?)
            }
        };
        let sink = match p.object("manifestSink") {
            None => None,
            Some(s) => Some(Sink::take(&s, c)?),
        };
        let times = match p.str("times").unwrap_or("preserve") {
            "fixed" => TimePolicy::Fixed(time),
            "clamp" => TimePolicy::Clamp(time),
            _ => TimePolicy::Preserve,
        };
        let fail_unsupported = p.str("unsupported") == Some("fail");
        // extendedAttributes, uid and gid are accepted and ignored: FAT
        // keeps none of them.
        if fail_unsupported {
            if let Some(m) = &manifest {
                m.check_supported()?;
            }
        }
        let source_mtime = match &source {
            Some(host::PassedSource::Directory(dir)) => File::from(dir.try_clone()?).metadata()?.modified().ok(),
            _ => None,
        };
        let manifest_mtime = manifest.as_ref().and_then(|m| m.root.mtime());
        let fill = match (source, manifest) {
            (None, None) => None,
            // A manifest names files that have to come from somewhere,
            // unless nothing is going to be written.
            (None, Some(m)) if taker == Taker::Plan => Some(Fill::ManifestOnly(m)),
            (None, Some(_)) => return Err(invalid("content")),
            (Some(host::PassedSource::Directory(dir)), None) => Some(Fill::Tree(dir)),
            (Some(host::PassedSource::Stream(file)), None) => {
                // A stream carries nothing without a manifest saying what
                // is in it; a regular file is one file where that is
                // allowed.
                if taker != Taker::Populate || !file.metadata()?.is_file() {
                    return Err(invalid("content"));
                }
                Some(Fill::File(file))
            }
            (Some(host::PassedSource::Directory(dir)), Some(m)) => {
                // Symbolic links are followed, resolved below the source
                // directory and never outside it; the interface has no
                // switch for that.
                let source = DirectorySource::new(dir).follow_symlinks(true);
                source.verify(&m)?;
                Some(Fill::FromDirectory(m, source))
            }
            (Some(host::PassedSource::Stream(file)), Some(m)) => Some(Fill::FromStream(m, file)),
        };
        Ok(Content {
            fill,
            time,
            times,
            replace: p.bool("replace", true),
            fail_unsupported,
            check_validity,
            sink,
            source_mtime,
            manifest_mtime,
        })
    }

    fn shape(&self) -> Shape {
        match &self.fill {
            None => Shape::Nothing,
            Some(Fill::Tree(_)) => Shape::Tree,
            Some(Fill::File(_)) => Shape::File,
            Some(Fill::FromDirectory(..) | Fill::FromStream(..) | Fill::ManifestOnly(_)) => Shape::Manifest,
        }
    }

    /// The time the root directory takes from the content: the
    /// manifest's root object's, else the source directory's.
    fn root_time(&self) -> Option<SystemTime> {
        self.manifest_mtime.or(self.source_mtime)
    }

    /// Puts the content into `plan`, at the root. Under UnsupportedPolicy
    /// fail a tree with entries FAT cannot hold is refused here, before
    /// anything is written.
    fn plan(&self, plan: &mut Plan) -> ufat::Result<()> {
        match &self.fill {
            Some(Fill::Tree(dir)) => {
                let skipped = plan.add_tree(dir.as_fd(), "/", true)?;
                if self.fail_unsupported {
                    refuse_skipped(&skipped)?;
                }
            }
            Some(Fill::FromDirectory(m, _) | Fill::FromStream(m, _) | Fill::ManifestOnly(m)) => {
                plan.add_manifest(m)?;
            }
            Some(Fill::File(_)) | None => {
                return Err(
                    ufat::Error::new(errno::EINVAL, "the content is not a tree or a manifest")
                        .with(Detail::InvalidOption("content")),
                )
            }
        }
        Ok(())
    }

    /// Under UnsupportedPolicy fail, walks a tree that is to go below
    /// `dest` before anything is copied, so that an entry FAT cannot hold
    /// fails the call with nothing written.
    fn check_tree(&self, dest: &str) -> Outcome<()> {
        if let (true, Some(Fill::Tree(dir))) = (self.fail_unsupported, &self.fill) {
            let mut plan = Plan::new(PlanOptions::new(MIN_SECTOR_SIZE));
            refuse_skipped(&plan.add_tree(dir.as_fd(), dest, true)?)?;
        }
        Ok(())
    }

    /// Puts the content into the volume at `dest`: the directory a tree goes
    /// below, the path of one file. A manifest's tree goes below the root.
    fn write_into(&mut self, v: &mut Volume, dest: &str, progress: &mut dyn FnMut(&Progress)) -> Outcome<Counts> {
        let copy = CopyOptions {
            times: self.times,
            replace: self.replace,
            follow_symlinks: true,
        };
        let assembly = AssembleOptions {
            default_time: self.time,
            replace: self.replace,
            skip_unsupported: !self.fail_unsupported,
            now_usec: if self.check_validity {
                Some(ufat::time::to_usec(util::now()))
            } else {
                None
            },
        };
        Ok(match self.fill.take() {
            None => Counts::default(),
            Some(Fill::Tree(dir)) => Counts::of_copy(&v.copy_tree_with_progress(dir.as_fd(), dest, &copy, progress)?),
            Some(Fill::File(file)) => Counts {
                files: 1,
                bytes: v.copy_file_with_progress(file.as_fd(), dest, &copy, progress)?,
                ..Counts::default()
            },
            Some(Fill::FromDirectory(m, mut source)) => {
                Counts::of_assembly(&v.assemble_with_progress(&m, &mut source, &assembly, progress)?)
            }
            Some(Fill::FromStream(m, mut file)) => Counts::of_assembly(&v.assemble_with_progress(
                &m,
                &mut StreamSource::new(&mut file),
                &assembly,
                progress,
            )?),
            // Never taken for a method that writes, see Content::take.
            Some(Fill::ManifestOnly(_)) => return Err(invalid("content")),
        })
    }
}

/// Makes sure `path` is a directory for content to go below: created when
/// missing, with its parents when `parents` is set.
fn ensure_dir(v: &mut Volume, path: &str, parents: bool, time: SystemTime) -> Outcome<()> {
    if parents {
        return Ok(v.create_dir_all(path, time)?);
    }
    match v.metadata(path) {
        Ok(md) if md.is_dir => Ok(()),
        Ok(_) => Err(
            ufat::Error::new(errno::ENOTDIR, format!("'{}' is not a directory", path))
                .with(Detail::Path(path.to_string()))
                .into(),
        ),
        Err(e) if e.errno() == errno::ENOENT => Ok(v.create_dir(path, time)?),
        Err(e) => Err(e.into()),
    }
}

/// The directory a path is in, none for an entry of the root.
fn parent_of(path: &str) -> Option<&str> {
    path.trim_end_matches('/')
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.trim_matches('/').is_empty())
}

impl FileSystemService {
    fn get_capabilities(&self, p: &Params<'_>) -> Outcome<Object> {
        check_type(p)?;
        Ok(json::object! { "capabilities" => capabilities()? })
    }

    fn assemble(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        check_type(p)?;
        let plan_only = p.str("mode") == Some("plan");
        // Planning needs no image; one given with it is left alone.
        let image = if plan_only { None } else { Some(Image::take(p, c)?) };
        let hash = match p.str("imageHash") {
            None => None,
            Some(a) => Some(Hash::new(a).ok_or_else(|| invalid("imageHash"))?),
        };
        let options = format_options(p.object("options"))?;
        let content_time = options.format.timestamp.unwrap_or_else(util::now);
        let taker = if plan_only { Taker::Plan } else { Taker::Assemble };
        let content = match p.object("content") {
            None => None,
            Some(cp) => {
                let content = Content::take(&cp, c, content_time, taker)?;
                if matches!(content.shape(), Shape::Nothing) {
                    return Err(invalid("content"));
                }
                Some(content)
            }
        };
        match image {
            None => plan(options, content, c, more),
            Some(image) => assemble_image(image, options, content, hash, c, more),
        }
    }

    fn describe(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        let image = Image::take(p, c)?;
        let sink = match p.object("manifestSink") {
            None => None,
            Some(s) => Some(Sink::take(&s, c)?),
        };
        let volume = image.open_volume(Access::ReadOnly)?;
        let mut o = json::object! { "description" => description(&volume)? };
        if let Some(sink) = sink {
            let mut r = Reporter::start(c, more, "reading", Shown::EntriesAndBytes)?;
            let w = sink.write(&volume, &mut |p| r.tick(p))?;
            o.insert("files", w.files);
            o.insert("directories", w.directories);
            o.insert("bytes", w.bytes);
            o.insert("omitted", w.omitted);
        }
        Ok(o)
    }

    fn populate(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        let image = Image::take(p, c)?;
        let path = p.string("path")?;
        let parents = p.bool("parents", false);
        let time = p.time("timestampUSec")?.unwrap_or_else(util::now);
        let mut content = match p.object("content") {
            None => None,
            Some(cp) => Some(Content::take(&cp, c, time, Taker::Populate)?),
        };
        // A manifest names its paths from the root.
        if matches!(content.as_ref().map(Content::shape), Some(Shape::Manifest)) && path != "/" {
            return Err(invalid("path"));
        }
        let mut v = image.open_volume(Access::ReadWrite)?;
        let mut r = Reporter::start(c, more, "populating", Shown::EntriesAndBytes)?;
        let counts = match content.as_mut() {
            Some(ct) if !matches!(ct.shape(), Shape::Nothing) => {
                match ct.shape() {
                    Shape::File => {
                        if parents {
                            if let Some(parent) = parent_of(path) {
                                v.create_dir_all(parent, time)?;
                            }
                        }
                    }
                    _ => {
                        ct.check_tree(path)?;
                        ensure_dir(&mut v, path, parents, time)?;
                    }
                }
                ct.write_into(&mut v, path, &mut |p| r.tick(p))?
            }
            // Nothing to put in: an empty directory at path.
            _ => {
                let existed = matches!(v.metadata(path), Ok(md) if md.is_dir);
                if parents {
                    v.create_dir_all(path, time)?;
                } else {
                    v.create_dir(path, time)?;
                }
                Counts {
                    directories: u64::from(!existed),
                    ..Counts::default()
                }
            }
        };
        let omitted = match content.and_then(|ct| ct.sink) {
            None => None,
            Some(sink) => {
                let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
                Some(sink.write(&v, &mut |p| r.tick(p))?.omitted)
            }
        };
        v.close()?;
        let mut o = Object::new();
        counts.put(&mut o);
        optional(&mut o, "omitted", omitted);
        Ok(o)
    }

    fn remove(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        let image = Image::take(p, c)?;
        let path = p.string("path")?;
        let recursive = p.bool("recursive", false);
        let mut v = image.open_volume(Access::ReadWrite)?;
        let md = v.metadata(path)?;
        // The root directory itself stays.
        if md.name.is_empty() {
            return Err(invalid("path"));
        }
        let (files, directories) = if !md.is_dir {
            v.remove_file(path)?;
            (1, 0)
        } else if recursive {
            let mut r = Reporter::start(c, more, "removing", Shown::Entries)?;
            let report = v.remove_tree_with_progress(path, &mut |p| r.tick(p))?;
            (report.files, report.directories)
        } else {
            v.remove_dir(path)?;
            (0, 1)
        };
        v.close()?;
        Ok(json::object! { "files" => files, "directories" => directories })
    }

    fn list(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        let image = Image::take(p, c)?;
        let path = p.str("path").unwrap_or("/");
        let v = image.open_volume(Access::ReadOnly)?;
        let md = v.metadata(path)?;
        if !md.is_dir {
            return Ok(json::object! { "entry" => entry(&md) });
        }
        if !more {
            return Err(Failure::ExpectedMore);
        }
        // One entry per reply, the last one in the final reply; an empty
        // directory ends with a reply without an entry.
        let entries = v.read_dir(path)?;
        let mut it = entries.iter().peekable();
        while let Some(m) = it.next() {
            let o = json::object! { "entry" => entry(m) };
            if it.peek().is_none() {
                return Ok(o);
            }
            c.notify(o)?;
        }
        Ok(Object::new())
    }

    fn check(&self, p: &Params<'_>, c: &mut Connection, more: bool) -> Outcome<Object> {
        let image = Image::take(p, c)?;
        match p.str("repair") {
            None | Some("none") => {}
            Some(_) => return Err(Failure::Unsupported("repair")),
        }
        let device = image.open(Access::ReadOnly)?;
        let mut r = Reporter::start(c, more, "checking", Shown::PhaseOnly)?;
        let report = fsck::check_with_progress(&device, &mut |p| r.tick(p))?;
        let mut o = json::object! {
            "errors" => report.errors(),
            "warnings" => report.warnings(),
            "repaired" => 0u64,
            "dropped" => report.dropped,
            // Warnings are recoverable; errors are what makes a volume
            // unclean.
            "clean" => report.errors() == 0,
        };
        if more {
            // The findings in batches, the counts in the final reply.
            for batch in report.problems.chunks(PROBLEM_BATCH) {
                let problems: Vec<Value> = batch.iter().map(|pr| Value::Object(problem(pr))).collect();
                c.notify(json::object! { "problems" => problems })?;
            }
        } else {
            let problems: Vec<Value> = report.problems.iter().map(|pr| Value::Object(problem(pr))).collect();
            o.insert("problems", problems);
        }
        Ok(o)
    }
}

/// Assemble with mode plan: the geometry and the size the content needs,
/// with nothing written.
fn plan(mut options: Options, content: Option<Content>, c: &mut Connection, more: bool) -> Outcome<Object> {
    phase(c, more, "planning")?;
    // No device, so 512 byte sectors unless the options say otherwise.
    let mut plan_options = PlanOptions::from_format_options(&options.format, None)?;
    // The root directory ends up with a volume label entry in any case:
    // for the label, or to carry the root's time (see format_image).
    plan_options.label = true;
    let mut plan = Plan::new(plan_options);
    if let Some(ct) = &content {
        ct.plan(&mut plan)?;
    }
    let e = plan.estimate()?;
    e.apply(&mut options.format);
    let mut d = json::object! {
        "fileSystemType" => FILE_SYSTEM_TYPE,
        "identifier" => VolumeId(options.format.volume_id).to_string(),
        "sectorSize" => e.layout.sector_size,
        "blockSize" => e.layout.cluster_size(),
        "sizeBytes" => e.size(),
        "minimalSizeBytes" => e.size(),
    };
    optional(&mut d, "label", stored_label(&options.format)?);
    Ok(json::object! {
        "description" => d,
        "exact" => true,
        "files" => e.files,
        "directories" => e.directories,
        "bytes" => e.bytes,
    })
}

/// Assemble with mode assemble: the image written, filled with the content
/// when there is one, sized to fit when no size is given. Everything that
/// can be checked before the image is touched has been checked by now:
/// the descriptors vetted, the manifest parsed and its source verified,
/// the options validated.
fn assemble_image(
    image: Image,
    mut options: Options,
    content: Option<Content>,
    hash: Option<Hash>,
    c: &mut Connection,
    more: bool,
) -> Outcome<Object> {
    let reader = match hash {
        Some(_) => Some(image.reader()?),
        None => None,
    };
    let (mut device, offset, size) = image.device(Access::ReadWrite)?;
    let (mut volume, exact) = match &content {
        Some(ct) => {
            phase(c, more, "planning")?;
            let (estimate, fit) = util::plan_fit(&mut device, offset, size, &mut options.format, true, &mut |plan| {
                ct.plan(plan)
            })
            .map_err(fit_error)?;
            phase(c, more, "formatting")?;
            let (volume, _) = util::format_fit(device, offset, fit, estimate, &options.format).map_err(fit_error)?;
            (volume, size.is_none())
        }
        None => {
            // A regular file is grown to a size given; a window with no
            // bytes in it has no size at all.
            if let Some(s) = size {
                util::size_image(&mut device, offset, s)?;
            }
            let device = device.window(offset, size)?;
            if device.is_empty() {
                return Err(Failure::SizeRequired);
            }
            check_block_size(&options.format, &device)?;
            phase(c, more, "formatting")?;
            (Volume::create(device, &options.format)?, false)
        }
    };
    let mut counts = None;
    let mut content_time = None;
    let mut sink = None;
    if let Some(mut ct) = content {
        let mut r = Reporter::start(c, more, "populating", Shown::EntriesAndBytes)?;
        counts = Some(ct.write_into(&mut volume, "/", &mut |p| r.tick(p))?);
        content_time = Some(ct.root_time());
        sink = ct.sink.take();
    }
    // The root directory's time, on the volume label entry: the timestamp
    // given, else what the content says about its root, else now. Without
    // content and without a timestamp the format left the entry, if any,
    // stamped with the current time already.
    let root_time = match (options.time, content_time) {
        (Some(t), _) => Some(t),
        (None, Some(from_content)) => Some(from_content.unwrap_or_else(util::now)),
        (None, None) => None,
    };
    if let Some(t) = root_time {
        volume.set_root_time(t)?;
    }
    let omitted = match sink {
        None => 0,
        Some(sink) => {
            let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
            sink.write(&volume, &mut |p| r.tick(p))?.omitted
        }
    };
    let description = description(&volume)?;
    let window = volume.device().len();
    volume.close()?;
    let mut o = json::object! { "description" => description, "exact" => exact };
    if let Some(counts) = counts {
        counts.put(&mut o);
        o.insert("omitted", omitted);
    }
    if let (Some(hash), Some(fd)) = (hash, reader) {
        let mut r = Reporter::start(c, more, "reading", Shown::PhaseOnly)?;
        let device = Device::from_passed(fd, Access::ReadOnly)?.window(offset, Some(window))?;
        o.insert("imageHash", hash.of(&device, &mut |p| r.tick(p))?);
    }
    Ok(o)
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
            "Remove" => self.remove(&p, connection, more),
            "List" => self.list(&p, connection, more),
            "Check" => self.check(&p, connection, more),
            _ => return Reply::Error(varlink::Error::method_not_implemented(&call.method)),
        };
        match result {
            Ok(o) => Reply::Final(o),
            Err(e) => Reply::Error(fail(e)),
        }
    }
}
