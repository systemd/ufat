// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the Varlink services of this repository have in common. Each of
//! them serves the `org.uapi-group.FileSystem` interface for what it
//! makes. They share the errors of the interface, typed access to the
//! parameters of a call and to the descriptors passed with it, and the
//! replies of a call that tells how far it got.
//!
//! This crate is not an interface of its own and changes with the tools.
//! It uses the standard library and the json, shared, uapi16 and varlink
//! crates.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::fs::File;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant, SystemTime};

use json::{Object, Value};
use shared::device::{Access, Device};
use shared::errno;
use shared::host;
use shared::progress::Progress;
use shared::{CorruptPlace, Detail, NoSpaceReason, NotFat32Reason};
use uapi16::Fields;
use varlink::Connection;

/// The interface description, served verbatim.
pub const INTERFACE: &str = include_str!("../../docs/org.uapi-group.FileSystem.varlink");
/// The name of the interface.
pub const INTERFACE_NAME: &str = "org.uapi-group.FileSystem";

/// Why a call failed, as the interface reports it. No error carries text:
/// every one is a name with typed fields, and the client puts them into
/// words. What the library's error says in words goes to the service's
/// own log at most; what it says in its [`Detail`] becomes the fields.
pub enum Failure {
    /// A parameter is missing, of the wrong shape or out of range:
    /// `org.varlink.service.InvalidParameter` with its name.
    Invalid(String),
    /// A descriptor passed with the call is not usable as the parameter
    /// names it: `BadFileDescriptor`.
    BadDescriptor {
        /// The parameter the descriptor came with.
        parameter: String,
        /// What is wrong with the descriptor.
        error: shared::Error,
    },
    /// The image cannot hold what the content needs.
    TooSmall {
        /// The smallest size that holds the content.
        minimal: u64,
        /// The size the image has.
        actual: u64,
    },
    /// What was asked for is not among the operations the service offers.
    Unsupported(&'static str),
    /// Another file system type than the one the service makes was asked
    /// for.
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
    Other(shared::Error),
}

impl From<shared::Error> for Failure {
    fn from(e: shared::Error) -> Failure {
        Failure::Other(e)
    }
}

impl From<std::io::Error> for Failure {
    fn from(e: std::io::Error) -> Failure {
        Failure::Other(shared::Error::from(e))
    }
}

/// The result of a method, or of a step of one.
pub type Outcome<T> = Result<T, Failure>;

/// The failure that reports the parameter `parameter` as invalid.
pub fn invalid(parameter: &str) -> Failure {
    Failure::Invalid(parameter.to_string())
}

/// Turns the vetting error of a passed descriptor into the interface's
/// error for it, naming the parameter; anything else passes through.
pub fn bad(parameter: &str) -> impl Fn(shared::Error) -> Failure + '_ {
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
pub fn optional<T: Into<Value>>(o: &mut Object, key: &str, value: Option<T>) {
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
        // An entry of a cpio archive, which the interface has no place for.
        CorruptPlace::Directory | CorruptPlace::Entry => "directory",
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
/// `NotFileSystemReason`. Another file system, a partition table or
/// anything else libblkid recognizes, a FAT12 or FAT16 volume included, is
/// `foreignImageType`, and `found` names it.
fn not_file_system_reason(reason: NotFat32Reason) -> &'static str {
    match reason {
        NotFat32Reason::Blank => "blank",
        NotFat32Reason::NotFat32 => "foreignImageType",
        NotFat32Reason::SectorSize => "sectorSize",
        NotFat32Reason::TooSmall => "tooSmall",
        NotFat32Reason::Unknown => "unknown",
    }
}

/// Maps a library error to the interface's errors by its detail, falling
/// back to the generic errno error systemd tools use when it has none.
fn map_error(e: &shared::Error) -> varlink::Error {
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
        Detail::TooSmall { minimal, actual } => interface_error(
            "TooSmall",
            json::object! { "minimalSizeBytes" => *minimal, "sizeBytes" => *actual },
        ),
        Detail::NoSpace { reason, path } => {
            let mut o = json::object! { "reason" => no_space_reason(*reason) };
            optional(&mut o, "path", path.as_deref());
            interface_error("NoSpaceLeft", o)
        }
        Detail::NotFat32 {
            reason,
            found,
            sector_size,
        } => {
            let mut o = json::object! { "reason" => not_file_system_reason(*reason) };
            optional(&mut o, "found", found.as_deref());
            optional(&mut o, "sectorSize", *sector_size);
            interface_error("NotFileSystem", o)
        }
        Detail::NotEmpty { found } => interface_error("ImageNotEmpty", json::object! { "found" => found.as_str() }),
        Detail::NotCpio { reason, found } => {
            let mut o = json::object! { "reason" => reason.as_str() };
            optional(&mut o, "found", *found);
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

/// A failure as the error the caller gets.
pub fn fail(f: Failure) -> varlink::Error {
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

/// Typed access to validated parameters. A value that is there but out of
/// range is InvalidParameter with the parameter's name, as in systemd.
pub struct Params<'a>(pub &'a Object);

impl Params<'_> {
    /// The string `key`, when it is there and a string.
    pub fn str(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(Value::as_str)
    }

    /// The string `key`, which has to be there.
    pub fn string(&self, key: &str) -> Outcome<&str> {
        self.str(key).ok_or_else(|| invalid(key))
    }

    /// The number `key`, when it is there. It is a number or a string that
    /// holds one.
    pub fn u64(&self, key: &str) -> Outcome<Option<u64>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Int(i)) => u64::try_from(*i).map(Some).map_err(|_| invalid(key)),
            Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(|_| invalid(key)),
            Some(_) => Err(invalid(key)),
        }
    }

    /// The number `key`, which has to fit 32 bits.
    pub fn u32(&self, key: &str) -> Outcome<Option<u32>> {
        self.u64(key)?.map(u32::try_from).transpose().map_err(|_| invalid(key))
    }

    /// The index an `...FileDescriptor` parameter carries.
    pub fn index(&self, key: &str) -> Outcome<Option<usize>> {
        self.u64(key)?
            .map(|v| usize::try_from(v).map_err(|_| invalid(key)))
            .transpose()
    }

    /// The strings of an array parameter, none when it is absent.
    pub fn strings(&self, key: &str) -> Outcome<Vec<&str>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(Vec::new()),
            Some(Value::Array(a)) => a.iter().map(|v| v.as_str().ok_or_else(|| invalid(key))).collect(),
            Some(_) => Err(invalid(key)),
        }
    }

    /// The flag `key`, `default` when it is not there.
    pub fn bool(&self, key: &str, default: bool) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(default)
    }

    /// The object `key`, when it is there.
    pub fn object(&self, key: &str) -> Option<Params<'_>> {
        self.0.get(key).and_then(Value::as_object).map(Params)
    }

    /// The time `key`, which is in microseconds since the epoch.
    pub fn time(&self, key: &str) -> Outcome<Option<SystemTime>> {
        Ok(self.u64(key)?.map(shared::times::from_usec))
    }
}

/// Takes the descriptor the parameter `key` names from the call, if the
/// parameter is there. An index that names no descriptor is as wrong as a
/// value out of range.
pub fn fd_param(c: &mut Connection, p: &Params<'_>, key: &str) -> Outcome<Option<OwnedFd>> {
    match p.index(key)? {
        None => Ok(None),
        Some(i) => c.take_fd(i).map(Some).map_err(|_| invalid(key)),
    }
}

/// The descriptor the parameter `key` names, which has to be there.
pub fn required_fd(c: &mut Connection, p: &Params<'_>, key: &str) -> Outcome<OwnedFd> {
    fd_param(c, p, key)?.ok_or_else(|| invalid(key))
}

/// Tells a client that asked for intermediate replies which step begins.
pub fn phase(c: &mut Connection, more: bool, phase: &str) -> Outcome<()> {
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
pub enum Shown {
    /// The phase and nothing else.
    PhaseOnly,
    /// The files and the directories done so far.
    Entries,
    /// The files, the directories and the bytes done so far.
    EntriesAndBytes,
}

/// The intermediate replies of a phase that does long work, for a call
/// made with the more flag: the phase when it starts, then the phase again
/// at most once per PROGRESS_INTERVAL while it lasts, with the counts so
/// far. So a caller sees how far the phase got, and the connection is
/// never quiet long enough for the caller's idle timeout to fire.
pub struct Reporter<'c> {
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
    pub fn start(
        connection: &'c mut Connection,
        more: bool,
        phase: &'static str,
        shown: Shown,
    ) -> Outcome<Reporter<'c>> {
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
    pub fn tick(&mut self, progress: &Progress) {
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
pub struct Image {
    fd: OwnedFd,
    /// The byte offset of the file system inside the image.
    pub offset: u64,
    /// The size of the file system inside the image, when the call gives
    /// one.
    pub size: Option<u64>,
}

impl Image {
    /// The `image` parameter, which has to be there.
    pub fn take(p: &Params<'_>, c: &mut Connection) -> Outcome<Image> {
        Image::take_optional(p, c)?.ok_or_else(|| invalid("image"))
    }

    /// The `image` parameter, when there is one.
    pub fn take_optional(p: &Params<'_>, c: &mut Connection) -> Outcome<Option<Image>> {
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
    pub fn reader(&self) -> Outcome<OwnedFd> {
        Ok(self.fd.try_clone()?)
    }

    /// The whole image, vetted and claimed, with the window still to apply.
    /// A block device that is mounted or claimed by another process is
    /// `ImageBusy`.
    pub fn device(self, access: Access) -> Outcome<(Device, u64, Option<u64>)> {
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
    pub fn open(self, access: Access) -> Outcome<Device> {
        let (device, offset, size) = self.device(access)?;
        Ok(device.window(offset, size)?)
    }
}

/// The manifest sink: the descriptor and the fields the manifest carries.
pub struct ManifestSink {
    /// Where the manifest is written to.
    pub file: File,
    /// The fields the manifest carries.
    pub fields: Fields,
}

impl ManifestSink {
    /// The sink that the `manifestSink` parameter `p` describes.
    pub fn take(p: &Params<'_>, c: &mut Connection) -> Outcome<ManifestSink> {
        let fd = required_fd(c, p, "fileDescriptor").map_err(|_| invalid("manifestSink"))?;
        let file = host::passed_sink(fd).map_err(bad("manifestSink"))?;
        let fields = match p.0.get("fields") {
            None | Some(Value::Null) => Fields::default(),
            Some(_) => Fields::from_names(p.strings("fields")?).map_err(|_| invalid("manifestSink"))?,
        };
        Ok(ManifestSink { file, fields })
    }
}
