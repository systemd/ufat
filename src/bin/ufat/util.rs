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
use fat::format::FormatOptions;
use fat::layout::Layout;
use fat::manifest::{Order, Reader, RootObject};
use fat::plan::{Estimate, Plan, PlanOptions};
use fat::probe::Prober;
use fat::volume::Volume;
use fat::{bail, err, DescriptorProblem, Detail, Error, Result};

/// The current time.
pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

/// The bytes of a manifest, as its reader takes them.
pub(crate) enum ManifestBytes {
    /// A regular file, read with positional reads from `offset` on. The
    /// manifest starts at `start` in it. Positional reads leave the
    /// position of the descriptor alone, so the file can be read once more
    /// from the same place.
    At { file: File, start: u64, offset: u64 },
    /// A pipe, read as the bytes come.
    Stream(Box<dyn Read + Send>),
}

impl ManifestBytes {
    /// The bytes of the same manifest once more from its start. None for a
    /// pipe, which can be read once only.
    fn again(&self) -> io::Result<Option<ManifestBytes>> {
        let ManifestBytes::At { file, start, .. } = self else {
            return Ok(None);
        };
        Ok(Some(ManifestBytes::At {
            file: file.try_clone()?,
            start: *start,
            offset: *start,
        }))
    }
}

impl Read for ManifestBytes {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ManifestBytes::At { file, offset, .. } => {
                let read = file.read_at(buf, *offset)?;
                *offset += read as u64;
                Ok(read)
            }
            ManifestBytes::Stream(stream) => stream.read(buf),
        }
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

/// A manifest the tool was handed, open for reading.
///
/// Its first record, the root file object, is read when it is opened, so a
/// file that is not a manifest, or a manifest that does not declare the
/// code point order, is found before anything is written. The reader goes
/// on from there when the content is written, or a plan alone reads on
/// from there. A manifest in a regular file can be read once more before
/// the content is written, from its start, for a plan. Standard input and
/// pipes can be read once only.
pub(crate) struct ManifestInput {
    /// The reader the content is taken from.
    reader: Reader<ManifestBytes>,
}

impl ManifestInput {
    /// Opens the manifest `stream`, a regular file or a pipe, from where its
    /// position is, for `manifest_use`, and reads its root file object. A
    /// pipe for [`ManifestUse::Plan`] is refused before anything is read
    /// from it, so what it holds is left to whoever reads it next. A pipe
    /// is read through `stream`, such as a [`fat::host::PassedStream`],
    /// which fails a read when the pipe was made non-blocking during the
    /// call. The manifest has to declare the code point order, see
    /// [`RootObject::require_order`].
    pub(crate) fn open<S>(stream: S, manifest_use: ManifestUse) -> Result<ManifestInput>
    where
        S: Read + AsFd + Send + 'static,
    {
        // A regular file is read with positional reads, through a
        // descriptor of its own.
        let mut file = File::from(stream.as_fd().try_clone_to_owned()?);
        let bytes = if file.metadata()?.is_file() {
            let start = file.stream_position()?;
            ManifestBytes::At {
                file,
                start,
                offset: start,
            }
        } else if manifest_use == ManifestUse::Plan {
            return Err(ManifestInput::not_plannable());
        } else {
            ManifestBytes::Stream(Box::new(stream))
        };
        let reader = Reader::open(bytes)?;
        reader.root().require_order(Order::CodePoint)?;
        Ok(ManifestInput { reader })
    }

    /// The root file object of the manifest.
    pub(crate) fn root(&self) -> &RootObject {
        self.reader.root()
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

    /// A reader of the whole manifest once more, for a plan before the
    /// content is written. The reader the content is taken from is left as
    /// it is.
    pub(crate) fn plan_reader(&self) -> Result<Reader<ManifestBytes>> {
        let Some(bytes) = self.reader.get_ref().again()? else {
            return Err(ManifestInput::not_plannable());
        };
        Ok(Reader::open(bytes)?)
    }

    /// The reader the content is taken from, which goes on after the root
    /// file object.
    pub(crate) fn reader(&mut self) -> &mut Reader<ManifestBytes> {
        &mut self.reader
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
/// regular image file is grown, never shrunk, to the size, and created
/// first with [`ImageFlags::CREATE`]. What can be found out before the
/// first write is found out while the image is untouched: a size no file
/// system fits in and, when the content is planned, a source tree that
/// cannot be read, a manifest that cannot be planned, and content that
/// does not fit a size given. A file created for the file system is
/// removed again then, so a failed command leaves nothing behind. Without
/// [`ImageFlags::FORCE`], an image that holds a file system, a partition
/// table or other data is not formatted over ([`Prober::ensure_empty`]).
pub(crate) fn fit_and_format(
    target: &Target<'_>,
    options: &mut FormatOptions,
    request: SizeRequest<'_>,
) -> std::result::Result<(Volume, Option<Estimate>), FitError> {
    let mut device = open_target(target)?;
    let decision = match decide_size(&mut device, target.offset, target.size, options, false, request) {
        Ok(decision) => decision,
        Err(e) => {
            // Nothing has been written. The error of the removal, if any,
            // is not the one the user needs to hear about.
            let _ = device.remove_if_created();
            return Err(e);
        }
    };
    if !target.flags.contains(ImageFlags::FORCE) {
        Prober::new().ensure_empty(&device, target.offset, Some(decision.size))?;
    }
    let volume = format_sized(device, target.offset, decision.size, options)?;
    Ok((volume, decision.estimate))
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
