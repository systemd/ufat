// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers shared by the command line interface and the Varlink service.

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fat::device::{Access, Device};
use fat::errno;
use fat::format::{FormatOptions, VolumeId};
use fat::host::{LinkError, Linked, Naming, NewFile};
use fat::layout::Layout;
use fat::manifest::{
    AssembleFlags, Finalize, Order, Reader, RootObject, SerialSource, Sha256, Sha256Context, VolumeIdentity,
};
use fat::plan::{Estimate, Plan, PlanOptions};
use fat::probe::Prober;
use fat::volume::Volume;
use fat::{bail, err, DescriptorProblem, Detail, Error, Result};

/// The current time.
pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

/// Where the bytes of a manifest come from.
enum Origin {
    /// A regular file, read with positional reads from `offset` on. The
    /// manifest starts at `start` in it. Positional reads leave the
    /// position of the descriptor alone, so the file can be read once more
    /// from the same place.
    At { file: File, start: u64, offset: u64 },
    /// A pipe, read as the bytes come.
    Stream(Box<dyn Read + Send>),
}

/// The SHA-256 hash of the bytes of a manifest, taken while they are read.
enum ManifestHash {
    /// Not wanted, and not taken.
    Unwanted,
    /// The hash of the bytes read so far.
    Partial(Sha256Context),
    /// The hash of all of them, once their end was read.
    Complete(Sha256),
}

/// Whether the serial number of a file system may be derived from the
/// bytes of a manifest, see [`SerialSource::Derived`]. The bytes are hashed
/// for it, so a manifest is hashed only where that is possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SerialDerivation {
    /// A file system is made from the manifest and no serial number was
    /// given for it: unless the manifest names one, it is derived.
    Possible,
    /// None is derived: the manifest goes into a file system that is there,
    /// the serial number was given, or nobody asks for it.
    Never,
}

/// What a command or a method of the Varlink service does with the
/// manifest it reads, as far as the serial number of a file system goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManifestOperation {
    /// It makes a file system from the manifest: `assemble`, Assemble.
    Assemble,
    /// It plans the file system the manifest makes and reports it with its
    /// serial number: Assemble in mode plan.
    Plan,
    /// It plans the size the content needs and reports nothing else:
    /// `assemble --plan`.
    PlanSize,
    /// It puts the content into a file system that is there: `populate`,
    /// Populate.
    Populate,
}

impl ManifestOperation {
    /// Whether a serial number may be derived from the manifest where the
    /// caller gave the serial number `identifier`, if any: only for a file
    /// system the operation makes or reports, and only where none is given.
    pub(crate) fn serial_derivation(self, identifier: Option<VolumeId>) -> SerialDerivation {
        match (self, identifier) {
            (ManifestOperation::Assemble | ManifestOperation::Plan, None) => SerialDerivation::Possible,
            (ManifestOperation::Assemble | ManifestOperation::Plan, Some(_)) => SerialDerivation::Never,
            (ManifestOperation::PlanSize | ManifestOperation::Populate, _) => SerialDerivation::Never,
        }
    }
}

/// The bytes of a manifest, as its reader takes them, and their SHA-256
/// hash while it is wanted.
pub(crate) struct ManifestBytes {
    origin: Origin,
    hash: ManifestHash,
}

impl ManifestBytes {
    /// The bytes from `origin`, hashed where `derivation` says that a
    /// serial number may be derived from them.
    fn new(origin: Origin, derivation: SerialDerivation) -> ManifestBytes {
        let hash = match derivation {
            SerialDerivation::Possible => ManifestHash::Partial(Sha256Context::default()),
            SerialDerivation::Never => ManifestHash::Unwanted,
        };
        ManifestBytes { origin, hash }
    }

    /// The bytes of the same manifest once more from its start, hashed if
    /// these are. None for a pipe, which can be read once only.
    fn again(&self) -> io::Result<Option<ManifestBytes>> {
        let Origin::At { file, start, .. } = &self.origin else {
            return Ok(None);
        };
        let derivation = match self.hash {
            ManifestHash::Unwanted => SerialDerivation::Never,
            ManifestHash::Partial(_) | ManifestHash::Complete(_) => SerialDerivation::Possible,
        };
        let origin = Origin::At {
            file: file.try_clone()?,
            start: *start,
            offset: *start,
        };
        Ok(Some(ManifestBytes::new(origin, derivation)))
    }

    /// Stops hashing the bytes, and drops what was hashed.
    fn stop_hashing(&mut self) {
        self.hash = ManifestHash::Unwanted;
    }

    /// The hash of the whole manifest, once its end was read, where it is
    /// wanted. The reader reads the end when it is asked for a record after
    /// the last one.
    fn digest(&self) -> Option<Sha256> {
        match self.hash {
            ManifestHash::Complete(digest) => Some(digest),
            ManifestHash::Unwanted | ManifestHash::Partial(_) => None,
        }
    }
}

impl Read for ManifestBytes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = match &mut self.origin {
            Origin::At { file, offset, .. } => {
                let read = file.read_at(buf, *offset)?;
                *offset += read as u64;
                read
            }
            Origin::Stream(stream) => stream.read(buf)?,
        };
        if let ManifestHash::Partial(context) = &mut self.hash {
            if read > 0 {
                context.update(&buf[..read]);
            } else if !buf.is_empty() {
                let context = std::mem::take(context);
                self.hash = ManifestHash::Complete(context.finalize());
            }
        }
        Ok(read)
    }
}

/// What a command does with its manifest, which decides what the manifest
/// can come through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManifestUse {
    /// It is read once, while the content it describes is written. A pipe
    /// will do.
    Write,
    /// It is planned and none of its content is written: it is read once,
    /// on from its root file object. A pipe will do.
    PlanOnly,
    /// It is planned before its content is written, with `--minimize` or
    /// `minimize`, and has to be in a regular file for that: the plan reads
    /// it once more from its start.
    Plan,
}

/// What a plan found when it read a manifest.
pub(crate) struct PlanOutcome {
    /// The file objects the plan leaves out, see [`Plan::add_records`].
    pub skipped: u64,
    /// The hash of the manifest's bytes, where it is wanted.
    pub digest: Option<Sha256>,
}

/// A manifest the tool was handed, open for reading.
///
/// Its first record, the root file object, is read when it is opened, so a
/// file that is not a manifest, or a manifest that does not declare the
/// code point order, is found before anything is written. The reader goes
/// on from there when the content is written, or a plan alone reads on
/// from there. A manifest in a regular file can be read once more before
/// the content is written, from its start, for a plan. Standard input and
/// pipes can be read once only.
///
/// Where the serial number of a file system made from the manifest may be
/// derived from its bytes, see [`SerialDerivation`], they are hashed as
/// they are read, until [`ManifestInput::stop_hashing`] says that the hash
/// is not wanted. The first pass that reads all of them gives it.
pub(crate) struct ManifestInput {
    /// The reader the content is taken from.
    reader: Reader<ManifestBytes>,
    /// The hash of the manifest a plan found, which reads it all once more.
    digest: Option<Sha256>,
}

impl ManifestInput {
    /// Opens the manifest `stream`, a regular file or a pipe, from where its
    /// position is, for `manifest_use`, and reads its root file object. A
    /// pipe for [`ManifestUse::Plan`] is refused before anything is read
    /// from it, so what it holds is left to whoever reads it next. A pipe
    /// is read through `stream`, such as a [`fat::host::PassedStream`],
    /// which fails a read when the pipe was made non-blocking during the
    /// call. The manifest has to declare the code point order, see
    /// [`RootObject::require_order`]. Its bytes are hashed where
    /// `derivation` says that a serial number may be derived from them.
    pub(crate) fn open<S>(stream: S, manifest_use: ManifestUse, derivation: SerialDerivation) -> Result<ManifestInput>
    where
        S: Read + AsFd + Send + 'static,
    {
        // A regular file is read with positional reads, through a
        // descriptor of its own.
        let mut file = File::from(stream.as_fd().try_clone_to_owned()?);
        let origin = if file.metadata()?.is_file() {
            let start = file.stream_position()?;
            Origin::At {
                file,
                start,
                offset: start,
            }
        } else if manifest_use == ManifestUse::Plan {
            return Err(ManifestInput::not_plannable());
        } else {
            Origin::Stream(Box::new(stream))
        };
        let reader = Reader::open(ManifestBytes::new(origin, derivation))?;
        reader.root().require_order(Order::CodePoint)?;
        Ok(ManifestInput { reader, digest: None })
    }

    /// Stops hashing the manifest: no serial number is derived from it.
    /// Hashing never starts again.
    pub(crate) fn stop_hashing(&mut self) {
        self.reader.get_mut().stop_hashing();
    }

    /// The root file object of the manifest.
    pub(crate) fn root(&self) -> &RootObject {
        self.reader.root()
    }

    /// The volume the manifest is for, as its root file object says.
    pub(crate) fn identity(&self) -> VolumeIdentity {
        VolumeIdentity::from_root(self.root())
    }

    /// The error for a manifest that cannot be read once more for a plan:
    /// its descriptor is not of the type a plan needs.
    pub(crate) fn not_plannable() -> Error {
        err!(
            errno::EBADFD,
            Detail::Descriptor {
                problem: DescriptorProblem::WrongType,
                flags: None,
                parameter: None,
            },
            "the manifest is not in a regular file, and sizing to fit reads it before its content is written"
        )
    }

    /// Reads the whole manifest once more, from its start, into `plan`,
    /// for content written with `flags` after it. The reader the content
    /// is taken from is left as it is. The hash of the manifest the plan
    /// finds is the one of the content, which is not hashed again when it
    /// is written. Returns how many file objects the plan leaves out.
    pub(crate) fn plan(&mut self, plan: &mut Plan, flags: AssembleFlags) -> Result<u64> {
        let Some(bytes) = self.reader.get_ref().again()? else {
            return Err(ManifestInput::not_plannable());
        };
        let mut reader = Reader::open(bytes)?;
        let skipped = plan.add_records(&mut reader, flags)?;
        self.digest = reader.get_ref().digest();
        if self.digest.is_some() {
            self.stop_hashing();
        }
        Ok(skipped)
    }

    /// Reads the rest of the manifest into `plan` with the reader the
    /// content would be taken from, for a plan alone of content written
    /// with `flags`. So the manifest is read once.
    pub(crate) fn plan_once(mut self, plan: &mut Plan, flags: AssembleFlags) -> Result<PlanOutcome> {
        let skipped = plan.add_records(&mut self.reader, flags)?;
        Ok(PlanOutcome {
            skipped,
            digest: self.reader.get_ref().digest(),
        })
    }

    /// The reader the content is taken from, which goes on after the root
    /// file object.
    pub(crate) fn reader(&mut self) -> &mut Reader<ManifestBytes> {
        &mut self.reader
    }

    /// Gives `volume`, made from the manifest, the serial number derived
    /// from the manifest's bytes where `serial` says that it takes that one.
    /// A plan or the reader the content was taken from has read them all by
    /// then.
    pub(crate) fn stamp_serial(&self, volume: &mut Volume, serial: SerialSource) -> Result<()> {
        let digest = self.digest.or_else(|| self.reader.get_ref().digest());
        match serial.derived_serial(digest)? {
            Some(id) => volume.set_volume_id(id),
            None => Ok(()),
        }
    }
}

/// Parses seconds since the epoch, as `--timestamp` and `SOURCE_DATE_EPOCH`
/// give them. Adding to a SystemTime panics on overflow, so check.
pub(crate) fn time_from_secs(text: &str, what: &str) -> Result<SystemTime> {
    let secs: u64 = text
        .parse()
        .map_err(|_| err!(errno::EINVAL, "invalid {} '{}'", what, text))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| err!(errno::ERANGE, "{} '{}' is out of range", what, text))
}

/// `SOURCE_DATE_EPOCH`, if set and valid.
pub(crate) fn source_date_epoch() -> Result<Option<SystemTime>> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(t) => time_from_secs(&t, "$SOURCE_DATE_EPOCH").map(Some),
        Err(_) => Ok(None),
    }
}

/// Parses a size with an optional binary suffix.
pub(crate) fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m: u64 = match c.to_ascii_uppercase() {
                'K' => 1 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => bail!(errno::EINVAL, "unknown size suffix in '{}'", s),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| err!(errno::EINVAL, "invalid size '{}'", s))?;
    n.checked_mul(mult)
        .ok_or_else(|| err!(errno::ERANGE, "size '{}' is too large", s))
}

/// A volume id for a new file system: random, unless the build is meant to
/// be reproducible, in which case it is derived from the timestamp and the
/// label. GRUB's `search --fs-uuid`, fstab and blkid tell volumes apart by
/// this serial, so an ESP and an XBOOTLDR partition built in one run with
/// the same timestamp must not end up with the same one.
pub(crate) fn pick_volume_id(time: SystemTime, label: Option<&str>, reproducible: bool) -> u32 {
    if !reproducible {
        if let Ok(id) = fat::format::random_volume_id() {
            return id;
        }
    }
    // FNV-1a over the time and the label.
    let mut h: u32 = 0x811c_9dc5;
    for b in fat::time::to_usec(time)
        .to_le_bytes()
        .iter()
        .chain(label.unwrap_or("").as_bytes())
    {
        h = (h ^ u32::from(*b)).wrapping_mul(0x0100_0193);
    }
    h
}

/// Opens the image at `path`, narrowed to `offset` and `size`.
pub(crate) fn open_image(path: &Path, offset: u64, size: Option<u64>, access: Access) -> Result<Device> {
    Device::open(path, access)?.window(offset, size)
}

/// The image a file system is going to be written to, open for writing and
/// not yet narrowed: created when `target` allows it and nothing is there.
/// This is the one lookup of the image path; sizing, growing, formatting
/// and populating all go through the descriptor.
pub(crate) fn open_target(target: &Target<'_>) -> Result<Device> {
    if target.flags.contains(ImageFlags::CREATE) {
        Device::create(target.path)
    } else {
        Device::open(target.path, Access::ReadWrite)
    }
}

/// Grows the regular image file `device` so that `size` bytes are
/// available at `offset`. A file that is large enough already is left
/// alone: shrinking it would cut off whatever lives behind the file system
/// in a disk image. A block device is left as it is.
pub(crate) fn size_image(device: &mut Device, offset: u64, size: u64) -> Result<()> {
    let total = offset
        .checked_add(size)
        .ok_or_else(|| err!(errno::ERANGE, "image size overflows"))?;
    device.grow(total)
}

/// What may be done to the image a file system goes to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ImageFlags(u8);

impl ImageFlags {
    /// Create the image file when it does not exist.
    pub(crate) const CREATE: ImageFlags = ImageFlags(1 << 0);
    /// Format the image whatever it holds.
    pub(crate) const FORCE: ImageFlags = ImageFlags(1 << 1);

    /// Whether all of `flags` are set.
    pub(crate) fn contains(self, flags: ImageFlags) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// Sets `flags` when `on` is true, and clears them otherwise.
    pub(crate) fn set(&mut self, flags: ImageFlags, on: bool) {
        if on {
            self.0 |= flags.0;
        } else {
            self.0 &= !flags.0;
        }
    }
}

/// Where a file system goes: an image path, the part of the image it
/// takes up, and what may be done to the image.
pub(crate) struct Target<'a> {
    pub path: &'a Path,
    pub offset: u64,
    pub size: Option<u64>,
    pub flags: ImageFlags,
}

/// Why the size of a new file system could not be decided.
pub(crate) enum FitError {
    /// Nothing says how large the file system is to be: no size was given
    /// and the image is empty.
    SizeRequired,
    /// The smallest file system that holds the content, `minimal` bytes,
    /// is larger than the most it may take, `actual` bytes: the size given
    /// with a file system sized to fit, or the block device behind the
    /// offset.
    TooSmall { minimal: u64, actual: u64 },
    /// The file system of the size given holds fewer clusters than the
    /// content takes.
    TooFewClusters(ClusterShortfall),
    /// Anything else.
    Other(Error),
}

impl From<Error> for FitError {
    fn from(e: Error) -> FitError {
        FitError::Other(e)
    }
}

impl FitError {
    /// The error as the command line tool reports it.
    pub(crate) fn into_error(self, image: &Path) -> Error {
        match self {
            FitError::SizeRequired => err!(
                errno::EINVAL,
                "{} is empty: give --size, or --minimize to make the file system as small as its content allows",
                image.display()
            ),
            FitError::TooSmall { minimal, actual } => {
                err!(
                    errno::ENOSPC,
                    "{} holds {} bytes but the content needs {}",
                    image.display(),
                    actual,
                    minimal
                )
            }
            FitError::TooFewClusters(shortfall) => err!(errno::ENOSPC, "{}: {}", image.display(), shortfall),
            FitError::Other(e) => e,
        }
    }
}

/// The partition start [`fat::format::prepare`] is given where only the
/// layout of a file system is wanted. It goes into the hidden sectors field
/// of the boot sector, and the layout does not depend on it.
const PARTITION_START_FOR_LAYOUT: u64 = 0;

/// A size given for a new file system, with the layout the formatter makes
/// of it. What goes into that file system is planned with the cluster size
/// of the layout, and has to fit its clusters.
pub(crate) struct GivenSize {
    pub size: u64,
    pub layout: Layout,
}

impl GivenSize {
    /// Lays out a file system of `size` bytes the way the formatter does
    /// with `options` on a device of `block_size`, and writes nothing. A
    /// size no file system of the options fits in, 0 among them, fails as
    /// the formatter fails on it.
    pub(crate) fn new(options: &FormatOptions, size: u64, block_size: Option<u32>) -> Result<GivenSize> {
        let layout = fat::format::prepare(options, size, block_size, PARTITION_START_FOR_LAYOUT)?.layout;
        Ok(GivenSize { size, layout })
    }

    /// Whether the clusters a plan counts, `estimate`, fit the file system.
    pub(crate) fn check(&self, estimate: &Estimate) -> std::result::Result<(), ClusterShortfall> {
        if self.layout.clusters < estimate.data_clusters {
            return Err(ClusterShortfall {
                size: self.size,
                cluster_size: self.layout.cluster_size(),
                clusters: self.layout.clusters,
                needed: estimate.data_clusters,
            });
        }
        Ok(())
    }
}

/// A file system of a size given that holds fewer clusters than the content
/// takes. The clusters do not grow with the size in every step: one sector
/// more can take one more sector for each FAT and leave one cluster less.
/// So this is counted in clusters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClusterShortfall {
    size: u64,
    cluster_size: u32,
    clusters: u32,
    needed: u32,
}

impl fmt::Display for ClusterShortfall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a file system of {} bytes holds {} clusters of {} bytes, the content needs {}",
            self.size, self.clusters, self.cluster_size, self.needed
        )
    }
}

/// How large a new file system is made, decided before its content is
/// looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SizeMode {
    /// The size given, or else the rest of the image behind the offset, as
    /// mkfs.fat does. The content is not planned.
    Given,
    /// The size given, which the content has to fit, or else the smallest
    /// size that holds it.
    Fit,
    /// The smallest size that holds the content. A size given is the most
    /// it may take.
    Minimize,
}

impl SizeMode {
    /// What it asks of the manifest of the content: everything but the
    /// size given plans it before its content is written.
    pub(crate) fn manifest_use(self) -> ManifestUse {
        match self {
            SizeMode::Given => ManifestUse::Write,
            SizeMode::Fit | SizeMode::Minimize => ManifestUse::Plan,
        }
    }
}

/// How large a new file system is made, see [`SizeMode`], with the closure
/// that puts its content into the plan.
pub(crate) enum SizeRequest<'a> {
    Given,
    Fit(&'a mut dyn FnMut(&mut Plan) -> Result<()>),
    Minimize(&'a mut dyn FnMut(&mut Plan) -> Result<()>),
}

impl<'a> SizeRequest<'a> {
    /// The request for `mode`, with `add` to put the content into the
    /// plan.
    pub(crate) fn new(mode: SizeMode, add: &'a mut dyn FnMut(&mut Plan) -> Result<()>) -> SizeRequest<'a> {
        match mode {
            SizeMode::Given => SizeRequest::Given,
            SizeMode::Fit => SizeRequest::Fit(add),
            SizeMode::Minimize => SizeRequest::Minimize(add),
        }
    }
}

/// The size decided for a new file system, and the estimate of the plan
/// when the content was planned.
pub(crate) struct SizeDecision {
    pub size: u64,
    pub estimate: Option<Estimate>,
}

/// Makes and opens a file system the way `request` says: the one way the
/// command line makes a volume, and what the Varlink Assemble method does
/// in two steps with [`decide_size`] and [`format_sized`]. The image is
/// opened once; a block device is planned for its logical block size, a
/// regular image file is grown, never shrunk, to the size, and made first
/// with [`ImageFlags::CREATE`]. What can be found out before the first
/// write is found out while the image is untouched: a size no file system
/// fits in and, when the content is planned, a source tree that cannot be
/// read, a manifest that cannot be planned, and content that does not fit
/// a size given. Without [`ImageFlags::FORCE`], an image that holds a file
/// system, a partition table or other data is not formatted over
/// ([`Prober::ensure_empty`]). An image file made for the file system has
/// no name yet, see [`fat::device::Device::create`]. It goes away again
/// when this fails, and is handed over in the [`NewVolume`] otherwise.
/// Errors are the command line's, see [`FitError::into_error`].
pub(crate) fn fit_and_format(
    target: &Target<'_>,
    options: &mut FormatOptions,
    request: SizeRequest<'_>,
) -> std::result::Result<(NewVolume, Option<Estimate>), Failure> {
    let mut device = open_target(target)?;
    let created = device.take_created().map(|file| Pending { file });
    match format_fitted(device, target, options, request) {
        Ok((volume, estimate)) => Ok((NewVolume::new(volume, created), estimate)),
        Err(e) => {
            let mut leftovers = Leftovers::default();
            if let Some(created) = created {
                created.discard(&mut leftovers);
            }
            Err(Failure::new(e.into_error(target.path), leftovers))
        }
    }
}

/// What [`fit_and_format`] does once the image is open.
fn format_fitted(
    mut device: Device,
    target: &Target<'_>,
    options: &mut FormatOptions,
    request: SizeRequest<'_>,
) -> std::result::Result<(Volume, Option<Estimate>), FitError> {
    let decision = decide_size(&mut device, target.offset, target.size, options, false, request)?;
    if !target.flags.contains(ImageFlags::FORCE) {
        Prober::new().ensure_empty(&device, target.offset, Some(decision.size))?;
    }
    let volume = format_sized(device, target.offset, decision.size, options)?;
    Ok((volume, decision.estimate))
}

/// What of the files a command made stays where it gave them up or named
/// them, one line each, which the command line prints after its error,
/// or as warnings after a command that succeeded.
#[derive(Debug, Default)]
pub(crate) struct Leftovers(Vec<String>);

impl Leftovers {
    /// The lines, in the order the files were given up or named.
    pub(crate) fn lines(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }

    fn note(&mut self, line: String) {
        self.0.push(line);
    }
}

/// An error a command of the command line failed with, and what of the
/// files it made stays, which the command line prints after the error:
/// what failed, then what that left behind.
#[derive(Debug)]
pub(crate) struct Failure {
    pub error: Error,
    pub leftovers: Leftovers,
}

impl Failure {
    pub(crate) fn new(error: Error, leftovers: Leftovers) -> Failure {
        Failure { error, leftovers }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Failure {
        Failure::new(error, Leftovers::default())
    }
}

/// A file the command line tool made, which gets its name once the command
/// succeeded.
struct Pending {
    file: NewFile,
}

impl Pending {
    /// Gives the file up, noting in `leftovers` what of it stays.
    fn discard(self, leftovers: &mut Leftovers) {
        if let Some(line) = self.file.give_up() {
            leftovers.note(line);
        }
    }

    /// Gives the file its name, and puts it into `linked` once it has it,
    /// also where checking the name failed then. One that does not get it
    /// is given up, with what of it stays noted in `leftovers`, and its
    /// error gets `context` and the path in front. A temporary name the
    /// file was linked from that stays after it got its name goes into
    /// `leftovers` too.
    fn link(self, context: &str, linked: &mut Vec<Linked>, leftovers: &mut Leftovers) -> Result<()> {
        match self.file.link() {
            Ok(named) => {
                if let Some(stray) = named.stray() {
                    leftovers.note(stray.to_string());
                }
                linked.push(named);
                Ok(())
            }
            Err(failed) => Err(Pending::failed(failed, context, linked, leftovers)),
        }
    }

    /// The error of the link `failed`. A file that did not get its name is
    /// given up, with what of it stays noted in `leftovers`, and `context`
    /// and its path go in front of the error. A file that has its name goes
    /// into `linked`, and its error, which says so, stays as it is.
    fn failed(failed: LinkError, context: &str, linked: &mut Vec<Linked>, leftovers: &mut Leftovers) -> Error {
        match failed {
            LinkError::Unnamed { error, file } => {
                let path = file.path().display().to_string();
                Pending { file }.discard(leftovers);
                error.context(format!("{} {}", context, path))
            }
            LinkError::Unchecked { error, linked: named } => {
                linked.push(named);
                error
            }
        }
    }
}

/// A file system the command line tool made, the image file it made for it
/// with [`ImageFlags::CREATE`] if it made one, and the files it writes next
/// to the image. None of these files gets its name before the command
/// succeeded ([`NewVolume::link`]), so a command that fails, is killed or
/// crashes before leaves nothing under their names, but where the file
/// system leaves the image no other way than the last resort of
/// [`NewFile`].
///
/// A new volume that is dropped before [`NewVolume::link`] or
/// [`NewVolume::abandon`], as by an early return, is given up the way
/// abandon() gives it up, without a word: an image made for it goes away
/// with nothing more written to it, and an image that was there is closed
/// as not cleanly unmounted. While a panic unwinds nothing more is written
/// to that one either: it keeps the mark of a file system that was being
/// written, but a panic before the first write leaves the file system as
/// it was formatted, empty and clean.
pub(crate) struct NewVolume {
    /// The image file made for the file system.
    created: Option<Pending>,
    /// The file system, until it is closed or given up.
    volume: Option<Volume>,
    /// The files written next to the image.
    outputs: Vec<Pending>,
}

impl NewVolume {
    fn new(volume: Volume, created: Option<Pending>) -> NewVolume {
        NewVolume {
            created,
            volume: Some(volume),
            outputs: Vec::new(),
        }
    }

    /// The file system. A new volume holds it until it is closed or given
    /// up, which consumes the new volume.
    pub(crate) fn volume(&self) -> &Volume {
        self.volume.as_ref().expect("a new volume holds its volume")
    }

    /// The file system, to fill it.
    pub(crate) fn volume_mut(&mut self) -> &mut Volume {
        self.volume.as_mut().expect("a new volume holds its volume")
    }

    /// A file to write to `path` next to the image, for `--write-manifest`
    /// and `--write-hash`. Where nothing or a regular file is there, it is
    /// a new file, which gets the name after the image got its own, in
    /// place of what is there ([`Naming::Replacing`]), and is given up with
    /// the image. What is there and not a regular file, such as a pipe, a
    /// device or a symbolic link, is opened for writing as File::create()
    /// opens it and written to as the command goes: as with standard
    /// output, nothing written there can be taken back.
    pub(crate) fn output(&mut self, path: &Path) -> Result<File> {
        let regular = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.is_file(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => true,
            Err(e) => return Err(e.into()),
        };
        if !regular {
            return Ok(File::create(path)?);
        }
        let pending = Pending {
            file: NewFile::create(path, Naming::Replacing)?,
        };
        let writer = pending.file.file().try_clone();
        // Kept before anything can fail, so that giving up gives it up.
        self.outputs.push(pending);
        Ok(writer?)
    }

    /// Gives up the file system after the command failed, and returns what
    /// of the image or the files next to it stays, where something does,
    /// for the command line to print after its error. An image file made
    /// for the file system goes away with nothing more written to it, and
    /// so do the files next to it. Any other image keeps what was written,
    /// closed as not cleanly unmounted, as after a crash, so that nobody
    /// takes it for a finished file system. An error of that close is not
    /// the one the user needs to hear about.
    pub(crate) fn abandon(mut self) -> Leftovers {
        self.give_up_volume();
        let mut leftovers = Leftovers::default();
        let created = self.created.take();
        for pending in created.into_iter().chain(std::mem::take(&mut self.outputs)) {
            pending.discard(&mut leftovers);
        }
        leftovers
    }

    /// Closes the finished file system and gives the image file made for it
    /// its name, and then the files written next to it theirs, each synced
    /// before (the image by the close). The image takes no name that
    /// something else took while it was made (EEXIST), and the files next
    /// to it replace what has their names. Once all of them have their
    /// names, each directory they are in is synced once, so that the names
    /// last too. Where closing the file system or naming its image file
    /// fails, these files go away as after any other failure. A file next
    /// to the image that cannot get its own name goes away with the ones
    /// after it, and the image keeps its name. A file that has its name
    /// keeps it, also where checking it or syncing its directory fails,
    /// and the error says so. Its directory is synced also where something
    /// fails after it got its name. Returns what stays besides, such as a
    /// temporary name that could not be removed, for the command line to
    /// warn about. A failure carries that as well.
    pub(crate) fn link(mut self) -> std::result::Result<Leftovers, Failure> {
        let mut leftovers = Leftovers::default();
        match self.link_all(&mut leftovers) {
            Ok(()) => Ok(leftovers),
            Err(e) => Err(Failure::new(e, leftovers)),
        }
    }

    /// What [`NewVolume::link`] does, noting in `leftovers` what stays. The
    /// directories of the files that got their names are synced also where
    /// something failed after, since those files keep their names. A sync
    /// that fails then goes into `leftovers`, after what came before.
    fn link_all(&mut self, leftovers: &mut Leftovers) -> Result<()> {
        let mut linked = Vec::new();
        let named = self.give_names(&mut linked, leftovers);
        let synced = Linked::sync_directories(&linked);
        match (named, synced) {
            (Err(e), Err(unsynced)) => {
                leftovers.note(unsynced.to_string());
                Err(e)
            }
            (named, synced) => named.and(synced),
        }
    }

    /// Closes the file system and gives the image file made for it and the
    /// files next to it their names, as [`NewVolume::link`] says. Each file
    /// that got its name goes into `linked`.
    fn give_names(&mut self, linked: &mut Vec<Linked>, leftovers: &mut Leftovers) -> Result<()> {
        let mut outputs = std::mem::take(&mut self.outputs).into_iter();
        let closed = self.volume.take().map_or(Ok(()), Volume::close);
        let created = self.created.take();
        if let Err(e) = closed {
            for pending in created.into_iter().chain(outputs) {
                pending.discard(leftovers);
            }
            return Err(e);
        }
        if let Some(created) = created {
            // The image's file is given up already where this fails, or it
            // keeps its name.
            if let Err(e) = created.link("failed to create", linked, leftovers) {
                outputs.for_each(|pending| pending.discard(leftovers));
                return Err(e);
            }
        }
        while let Some(pending) = outputs.next() {
            let named = match pending.file.file().sync_all() {
                Ok(()) => pending.link("cannot write", linked, leftovers),
                Err(e) => {
                    let e = Error::from(e).context(format!("cannot write {}", pending.file.path().display()));
                    pending.discard(leftovers);
                    Err(e)
                }
            };
            if let Err(e) = named {
                outputs.by_ref().for_each(|pending| pending.discard(leftovers));
                return Err(e);
            }
        }
        Ok(())
    }

    /// Gives up the file system, if it is still held, without a word: with
    /// nothing more written to an image made for it or while a panic
    /// unwinds, and closed as not cleanly unmounted otherwise.
    fn give_up_volume(&mut self) {
        let Some(volume) = self.volume.take() else {
            return;
        };
        if self.created.is_some() || std::thread::panicking() {
            volume.abandon();
        } else {
            let _ = volume.close_unfinished();
        }
    }
}

impl Drop for NewVolume {
    fn drop(&mut self) {
        // Only an early return or a panic comes here with the volume. The
        // image file and the files next to it give themselves up when they
        // are dropped right after.
        self.give_up_volume();
    }
}

/// Decides the size of a new file system the way `request` says. Nothing
/// is written; the image is only asked for its type, block size and
/// length. `device` covers the whole image, a descriptor the service was
/// handed or the file the command line tool opened or created; the file
/// system goes to `offset` and takes `size` bytes. With `label_slot` the
/// root directory is planned with a volume label entry whether or not a
/// label is given, for a caller that stamps the root's time on one
/// afterwards ([`Volume::set_root_time`]).
///
/// [`SizeRequest::Given`] without a size takes the rest of the image, and
/// an empty image is [`FitError::SizeRequired`] then. A size the file
/// system is to take that no file system of the options fits in, 0 among
/// them, fails as the formatter fails on it. [`SizeRequest::Fit`] plans the
/// content of a file system that takes the size given with the cluster
/// size the formatter picks for that size, and the content has to fit the
/// clusters the formatter lays out for it ([`FitError::TooFewClusters`]).
/// A file system sized to fit has to fit a size given and a block device
/// ([`FitError::TooSmall`]), and only it gets the sector and the cluster
/// size it was planned with in `options`. Content that does not fit is
/// reported while the image is as it was.
pub(crate) fn decide_size(
    device: &mut Device,
    offset: u64,
    size: Option<u64>,
    options: &mut FormatOptions,
    label_slot: bool,
    request: SizeRequest<'_>,
) -> std::result::Result<SizeDecision, FitError> {
    let block_size = device.logical_block_size()?;
    // The size the file system keeps when the content fits it.
    let (add, kept) = match request {
        SizeRequest::Given => {
            let size = match size {
                Some(size) => size,
                None if device.is_empty() => return Err(FitError::SizeRequired),
                None => device.len().checked_sub(offset).ok_or_else(|| {
                    err!(
                        errno::EINVAL,
                        "offset {} is beyond the end of the device ({} bytes)",
                        offset,
                        device.len()
                    )
                })?,
            };
            // A size no file system of the options fits in is found before
            // the image is grown.
            GivenSize::new(options, size, block_size)?;
            return Ok(SizeDecision { size, estimate: None });
        }
        SizeRequest::Fit(add) => (add, size),
        SizeRequest::Minimize(add) => (add, None),
    };
    let mut plan_options = PlanOptions::from_format_options(options, block_size)?;
    plan_options.label |= label_slot;
    // The content of a file system of the size kept is planned with the
    // cluster size the formatter picks for that size. A size no file system
    // of the options fits in is found before the image is grown.
    let kept = kept.map(|size| GivenSize::new(options, size, block_size)).transpose()?;
    if let Some(kept) = &kept {
        plan_options.cluster_size = Some(kept.layout.cluster_size());
    }
    let mut plan = Plan::new(plan_options);
    add(&mut plan)?;
    let estimate = plan.estimate()?;
    let size = match kept {
        // The content has to fit the clusters of that file system.
        Some(kept) => {
            kept.check(&estimate).map_err(FitError::TooFewClusters)?;
            kept.size
        }
        // Sized to fit, the file system is formatted as it was planned. A
        // size given is the most it may take, and a block device cannot
        // grow: what lies behind the offset is all there is.
        None => {
            let room = device.is_block_device().then(|| device.len().saturating_sub(offset));
            if let Some(actual) = [size, room]
                .into_iter()
                .flatten()
                .min()
                .filter(|&actual| actual < estimate.size())
            {
                return Err(FitError::TooSmall {
                    minimal: estimate.size(),
                    actual,
                });
            }
            estimate.apply(options);
            estimate.size()
        }
    };
    Ok(SizeDecision {
        size,
        estimate: Some(estimate),
    })
}

/// Sizes the image for a new file system of `size` bytes at `offset`,
/// formats it and opens it: the second step of [`fit_and_format`], after
/// [`decide_size`].
pub(crate) fn format_sized(mut device: Device, offset: u64, size: u64, options: &FormatOptions) -> Result<Volume> {
    size_image(&mut device, offset, size)?;
    let device = device.window(offset, Some(size))?;
    Volume::create(device, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fat::fsck::{self, ProblemKind};
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    /// The size of the test images: room for the 65525 clusters of the
    /// smallest FAT32 file system with 512 byte clusters.
    const IMAGE_SIZE: u64 = 40 << 20;

    /// A directory below TMPDIR, removed with what is in it when dropped.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> TempDir {
            let dir = std::env::temp_dir().join(format!("ufat-{}-{}", name, std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Whether the file system in the image `path` is marked as not cleanly
    /// unmounted.
    fn marked_dirty(path: &Path) -> bool {
        let report = fsck::check(&Device::open(path, Access::ReadOnly).unwrap()).unwrap();
        report
            .problems
            .iter()
            .any(|problem| problem.kind == ProblemKind::DirtyFlag)
    }

    /// A new volume, as fit_and_format() makes it: not being written yet.
    fn formatted(target: &Target<'_>) -> NewVolume {
        fit_and_format(target, &mut FormatOptions::default(), SizeRequest::Given)
            .unwrap()
            .0
    }

    /// A new volume with a directory written into it: being written, with
    /// the marks of that on the image.
    fn written(target: &Target<'_>) -> NewVolume {
        let mut new = formatted(target);
        new.volume_mut().create_dir("/d", now()).unwrap();
        new
    }

    /// Gives the file `file`, whatever its names, the name `to` as well,
    /// through its magic link in /proc/self/fd.
    fn hard_link(file: &File, to: &Path) {
        let from = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
        let to = CString::new(to.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL terminated paths and plain flags.
        let linked = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        assert_eq!(linked, 0, "{}", io::Error::last_os_error());
    }

    /// A new volume over an image that was there, dropped without link() or
    /// abandon(), as an early return drops it, leaves the file system marked
    /// as not cleanly unmounted. One that is linked leaves it clean.
    #[test]
    fn a_dropped_new_volume_leaves_its_image_marked() {
        let dir = TempDir::new("dropped");
        let path = dir.0.join("a.img");
        File::create(&path).unwrap().set_len(IMAGE_SIZE).unwrap();
        let target = Target {
            path: &path,
            offset: 0,
            size: None,
            flags: ImageFlags::FORCE,
        };
        let leftovers = written(&target).link().unwrap();
        assert_eq!(leftovers.lines().count(), 0);
        assert!(!marked_dirty(&path));
        drop(written(&target));
        assert!(marked_dirty(&path));
    }

    /// Giving up an image made for a new volume writes nothing more to it:
    /// not the marks a volume that is not being written would get from a
    /// close as unfinished, and not the clean marks a close would put back
    /// on one that is. A name the image got meanwhile, through its
    /// descriptor, keeps the bytes it had.
    #[test]
    fn abandon_writes_nothing() {
        let dir = TempDir::new("abandoned");
        let path = dir.0.join("a.img");
        let kept = dir.0.join("kept.img");
        let target = Target {
            path: &path,
            offset: 0,
            size: Some(IMAGE_SIZE),
            flags: ImageFlags::CREATE,
        };
        for new in [formatted(&target), written(&target)] {
            hard_link(new.created.as_ref().unwrap().file.file(), &kept);
            let before = std::fs::read(&kept).unwrap();
            let leftovers = new.abandon();
            assert_eq!(leftovers.lines().count(), 0);
            assert!(!path.exists());
            assert!(std::fs::read(&kept).unwrap() == before, "abandon() wrote to the image");
            std::fs::remove_file(&kept).unwrap();
        }
    }

    /// A new volume over an image that was there, dropped while a panic
    /// unwinds, writes nothing more to it either, not even the marks of a
    /// close as unfinished: what the volume holds in memory is not to be
    /// trusted then.
    #[test]
    fn a_new_volume_dropped_by_a_panic_writes_nothing() {
        let dir = TempDir::new("panicked");
        let path = dir.0.join("a.img");
        File::create(&path).unwrap().set_len(IMAGE_SIZE).unwrap();
        let target = Target {
            path: &path,
            offset: 0,
            size: None,
            flags: ImageFlags::FORCE,
        };
        let mut before = Vec::new();
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let new = formatted(&target);
            before = std::fs::read(&path).unwrap();
            let _held = new;
            panic!("unwinding with a new volume");
        }));
        assert!(unwound.is_err());
        assert!(std::fs::read(&path).unwrap() == before, "a panic wrote to the image");
        assert!(!marked_dirty(&path));
    }

    /// A link that fails gives a file that did not get its name up, and its
    /// error says what was being made. A file that got its name and only
    /// the check after failed goes with the others that have their names,
    /// to sync its directory, and its error says that it has its name, with
    /// nothing in front of it.
    #[test]
    fn a_failed_link_says_whether_the_file_has_its_name() {
        let dir = TempDir::new("unlinked");
        let path = dir.0.join("a.img");
        let new = || NewFile::create(&path, Naming::Exclusive).unwrap();
        let (mut linked, mut leftovers) = (Vec::new(), Leftovers::default());
        let unnamed = LinkError::Unnamed {
            error: err!(errno::EIO, "why"),
            file: new(),
        };
        let e = Pending::failed(unnamed, "failed to create", &mut linked, &mut leftovers);
        assert_eq!(e.to_string(), format!("failed to create {}: why", path.display()));
        assert!(linked.is_empty());
        let unchecked = LinkError::Unchecked {
            error: err!(errno::EIO, "why"),
            linked: new().link().unwrap(),
        };
        let e = Pending::failed(unchecked, "failed to create", &mut linked, &mut leftovers);
        assert_eq!(e.to_string(), "why");
        assert_eq!(linked.len(), 1);
        assert_eq!(leftovers.lines().count(), 0);
    }

    /// Makes the system call `call` fail with `errno` in the calling thread
    /// from here on, with a seccomp filter of the thread's own: every call,
    /// or with `flags` only one whose third argument, the flags of
    /// openat(2), has one of those bits set. Returns false where seccomp
    /// filters cannot be had: on an architecture this does not know, or
    /// under qemu-user, which refuses them.
    fn refuse_in_this_thread(call: libc::c_long, errno: i32, flags: Option<libc::c_int>) -> bool {
        // The flags of include/uapi/linux/audit.h that make the AUDIT_ARCH a
        // filter compares with of a machine of elf.h.
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        const AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
        #[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
        const AUDIT_ARCH_LE: u32 = 0x4000_0000;
        #[cfg(target_arch = "x86_64")]
        const ARCH: Option<u32> = Some(libc::EM_X86_64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE);
        #[cfg(target_arch = "x86")]
        const ARCH: Option<u32> = Some(libc::EM_386 as u32 | AUDIT_ARCH_LE);
        #[cfg(target_arch = "aarch64")]
        const ARCH: Option<u32> = Some(libc::EM_AARCH64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        const ARCH: Option<u32> = None;
        let Some(arch) = ARCH else {
            return false;
        };
        let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let equal = libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K;
        let any_of = libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K;
        let onward = libc::BPF_JMP | libc::BPF_JA;
        let give = libc::BPF_RET | libc::BPF_K;
        // Each of these architectures is little endian, so the low 32 bits
        // of the third argument come first.
        let third = std::mem::offset_of!(libc::seccomp_data, args) + 2 * size_of::<u64>();
        // Without flags the call is refused whatever its third argument is.
        let refused = match flags {
            Some(bits) => statement(any_of, bits as u32, 0, 1),
            None => statement(onward, 0, 0, 0),
        };
        // Another architecture, another call or flags without those bits
        // jump to the last statement, which allows the call.
        let filter = [
            statement(load, std::mem::offset_of!(libc::seccomp_data, arch) as u32, 0, 0),
            statement(equal, arch, 0, 5),
            statement(load, std::mem::offset_of!(libc::seccomp_data, nr) as u32, 0, 0),
            statement(equal, call as u32, 0, 3),
            statement(load, third as u32, 0, 0),
            refused,
            statement(give, libc::SECCOMP_RET_ERRNO | errno as u32, 0, 0),
            statement(give, libc::SECCOMP_RET_ALLOW, 0, 0),
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        let (on, unused): (libc::c_ulong, libc::c_ulong) = (1, 0);
        let mode = libc::SECCOMP_MODE_FILTER as libc::c_ulong;
        // SAFETY: prctl() takes plain values and a filter, which it copies
        // before it returns.
        unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, on, unused, unused, unused) == 0
                && libc::prctl(libc::PR_SET_SECCOMP, mode, std::ptr::from_ref(&program)) == 0
        }
    }

    /// Where a file written next to the image cannot get its name after the
    /// image got its own, the image keeps its name, and its directory is
    /// synced all the same, so that a crash does not take the name of an
    /// image that the command said it kept. Filters of the test's own thread
    /// refuse the rename that the file next to the image gets its name by,
    /// and the opening of a directory, which the sync of the image's
    /// directory starts with, so that the sync fails and says so. Nothing
    /// else the link does opens a directory.
    #[test]
    fn a_failure_after_the_image_got_its_name_syncs_its_directory() {
        // What a rename that may replace is: renameat() where there is one,
        // renameat2() without flags elsewhere.
        #[cfg(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64"))]
        const RENAME: libc::c_long = libc::SYS_renameat;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
        const RENAME: libc::c_long = libc::SYS_renameat2;
        let dir = TempDir::new("named");
        let (path, written) = (dir.0.join("a.img"), dir.0.join("a.manifest"));
        std::fs::write(&written, b"old\n").unwrap();
        let image = Pending {
            file: NewFile::create(&path, Naming::Exclusive).unwrap(),
        };
        let output = Pending {
            file: NewFile::create(&written, Naming::Replacing).unwrap(),
        };
        let new = NewVolume {
            created: Some(image),
            volume: None,
            outputs: vec![output],
        };
        let linked = std::thread::spawn(move || {
            let refused = refuse_in_this_thread(RENAME, libc::EIO, None)
                && refuse_in_this_thread(libc::SYS_openat, libc::EIO, Some(libc::O_DIRECTORY));
            refused.then(|| new.link())
        })
        .join()
        .unwrap();
        let Some(linked) = linked else {
            return eprintln!("skipping: no seccomp filters here");
        };
        let failure = linked.unwrap_err();
        let failed = format!("cannot write {}: ", written.display());
        assert!(failure.error.message().starts_with(&failed), "{}", failure.error);
        let unsynced = format!(
            "{} is complete and has its name, but syncing its directory failed: ",
            path.display()
        );
        let lines: Vec<&str> = failure.leftovers.lines().collect();
        assert!(lines.len() == 1 && lines[0].starts_with(&unsynced), "{:?}", lines);
        assert!(path.exists());
        assert_eq!(std::fs::read(&written).unwrap(), b"old\n");
    }

    /// A manifest of a directory with a file in it.
    const MANIFEST: &str = concat!(
        "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
        "\x1e{\"name\":\"d\",\"type\":\"dir\"}\n",
        "\x1e{\"name\":\"d/f\",\"size\":0}\n",
        "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
    );

    /// A manifest is hashed only where a serial number may be derived from
    /// it. populate opens its manifest so that none is, and reads it to its
    /// end without hashing it. assemble without a serial number given gets
    /// the hash of the whole manifest from the pass that reads all of it:
    /// the content, or a plan that reads the manifest once more, after
    /// which the content is not hashed again. A serial number that turns
    /// out to be given stops the hashing.
    #[test]
    fn manifests_are_hashed_only_where_a_serial_number_may_be_derived() {
        let dir = TempDir::new("hashed");
        let path = dir.0.join("manifest");
        std::fs::write(&path, MANIFEST).unwrap();
        let open = |derivation| ManifestInput::open(File::open(&path).unwrap(), ManifestUse::Plan, derivation).unwrap();
        let unwanted = |input: &ManifestInput| matches!(input.reader.get_ref().hash, ManifestHash::Unwanted);
        let read_to_end = |input: &mut ManifestInput| {
            for object in input.reader() {
                object.unwrap();
            }
        };
        let plan = || Plan::new(PlanOptions::new(fat::layout::MIN_SECTOR_SIZE));
        let digest = Sha256::digest(MANIFEST.as_bytes());
        // As populate opens it: never hashed.
        let mut input = open(SerialDerivation::Never);
        read_to_end(&mut input);
        assert!(unwanted(&input));
        assert_eq!(input.reader.get_ref().digest(), None);
        // As assemble opens it: hashed, and the hash is there once the end
        // of the manifest was read.
        let mut input = open(SerialDerivation::Possible);
        assert_eq!(input.reader.get_ref().digest(), None);
        read_to_end(&mut input);
        assert_eq!(input.reader.get_ref().digest(), Some(digest));
        // A serial number given stops it.
        let mut input = open(SerialDerivation::Possible);
        input.stop_hashing();
        read_to_end(&mut input);
        assert!(unwanted(&input));
        // A plan that reads the manifest once more takes the hash, and the
        // content is not hashed again.
        let mut input = open(SerialDerivation::Possible);
        input.plan(&mut plan(), AssembleFlags::NONE).unwrap();
        assert_eq!(input.digest, Some(digest));
        assert!(unwanted(&input));
        read_to_end(&mut input);
        assert!(unwanted(&input));
        let mut input = open(SerialDerivation::Never);
        input.plan(&mut plan(), AssembleFlags::NONE).unwrap();
        assert_eq!(input.digest, None);
        // A plan alone reads the manifest once, hashed where it may be.
        let planned = open(SerialDerivation::Possible).plan_once(&mut plan(), AssembleFlags::NONE);
        assert_eq!(planned.unwrap().digest, Some(digest));
        let planned = open(SerialDerivation::Never).plan_once(&mut plan(), AssembleFlags::NONE);
        assert_eq!(planned.unwrap().digest, None);
        // The serial number derived from the hash goes into a volume made
        // from the manifest, and none does where it is given.
        let image = dir.0.join("a.img");
        File::create(&image).unwrap().set_len(IMAGE_SIZE).unwrap();
        let target = Target {
            path: &image,
            offset: 0,
            size: None,
            flags: ImageFlags::FORCE,
        };
        let mut new = formatted(&target);
        let formatted_id = new.volume().boot_sector().volume_id;
        let mut input = open(SerialDerivation::Possible);
        read_to_end(&mut input);
        input.stamp_serial(new.volume_mut(), SerialSource::Given).unwrap();
        assert_eq!(new.volume().boot_sector().volume_id, formatted_id);
        input.stamp_serial(new.volume_mut(), SerialSource::Derived).unwrap();
        let derived = VolumeId::from_manifest_digest(&digest);
        assert_eq!(new.volume().boot_sector().volume_id, derived.0);
    }

    /// A serial number may be derived only by what makes a file system or
    /// reports the one it would make, and only where none is given. So
    /// populate and assemble --plan never hash their manifests.
    #[test]
    fn what_derives_a_serial_number() {
        let given = Some(VolumeId(0x1234_abcd));
        for (operation, without, with) in [
            (
                ManifestOperation::Assemble,
                SerialDerivation::Possible,
                SerialDerivation::Never,
            ),
            (
                ManifestOperation::Plan,
                SerialDerivation::Possible,
                SerialDerivation::Never,
            ),
            (
                ManifestOperation::PlanSize,
                SerialDerivation::Never,
                SerialDerivation::Never,
            ),
            (
                ManifestOperation::Populate,
                SerialDerivation::Never,
                SerialDerivation::Never,
            ),
        ] {
            assert_eq!(operation.serial_derivation(None), without, "{:?}", operation);
            assert_eq!(operation.serial_derivation(given), with, "{:?}", operation);
        }
    }
}
