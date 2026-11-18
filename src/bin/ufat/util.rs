// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers shared by the command line interface and the Varlink service.

use std::fs::File;
use std::io::{self, Read, Seek};
use std::os::fd::AsFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fat::device::{Access, Device};
use fat::errno;
use fat::format::FormatOptions;
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
    /// It is planned before its content is written, and has to be in a
    /// regular file for that: the plan reads it once more from its start.
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

/// Why [`fit_and_format`] could not fit the content.
pub(crate) enum FitError {
    /// The image is fixed in size and smaller than the content needs.
    TooSmall { minimal: u64, actual: u64 },
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
            FitError::TooSmall { minimal, actual } => {
                err!(
                    errno::ENOSPC,
                    "{} holds {} bytes but the content needs {}",
                    image.display(),
                    actual,
                    minimal
                )
            }
            FitError::Other(e) => e,
        }
    }
}

/// Sizes, formats and opens a file system that fits what `add` puts into
/// the plan: the one way mkfs --fit and assemble make a volume, and what
/// the Varlink Assemble method does in two steps with [`plan_fit`] and
/// [`format_fit`]. The image is opened once; a block device
/// is planned for its logical block size, a regular image file is grown,
/// never shrunk, to the size given or to the fit, and created first with
/// [`ImageFlags::CREATE`]. Everything that can go wrong before the first
/// write, a source that cannot be read, content that does not fit the
/// size given, is found out while the image is untouched, and a file created
/// for the file system is removed again then, so a failed command leaves
/// nothing behind. Without [`ImageFlags::FORCE`], an image that holds a
/// file system, a partition table or other data is not formatted over
/// ([`Prober::ensure_empty`]).
pub(crate) fn fit_and_format(
    target: &Target<'_>,
    options: &mut FormatOptions,
    add: &mut dyn FnMut(&mut Plan) -> Result<()>,
) -> std::result::Result<(Volume, Estimate), FitError> {
    let mut device = open_target(target)?;
    let (estimate, size) = match plan_fit(&mut device, target.offset, target.size, options, false, add) {
        Ok(fit) => fit,
        Err(e) => {
            // Nothing has been written. The error of the removal, if any,
            // is not the one the user needs to hear about.
            let _ = device.remove_if_created();
            return Err(e);
        }
    };
    if !target.flags.contains(ImageFlags::FORCE) {
        Prober::new().ensure_empty(&device, target.offset, Some(size))?;
    }
    format_fit(device, target.offset, size, estimate, options)
}

/// Plans the content and decides the size of the file system: the size
/// given, or the smallest that fits. Nothing is written; the image is only
/// asked for its type, block size and length, so that content that does
/// not fit is reported while the image is as it was. `device` covers the
/// whole image, a descriptor the service was handed or the file the
/// command line tool opened or created; the file system goes to `offset`
/// and takes `size` bytes, or what fits when there is no size. With
/// `label_slot` the root directory is planned with a volume label entry
/// whether or not a label is given, for a caller that stamps the root's
/// time on one afterwards ([`Volume::set_root_time`]).
pub(crate) fn plan_fit(
    device: &mut Device,
    offset: u64,
    size: Option<u64>,
    options: &mut FormatOptions,
    label_slot: bool,
    add: &mut dyn FnMut(&mut Plan) -> Result<()>,
) -> std::result::Result<(Estimate, u64), FitError> {
    let block_size = device.logical_block_size()?;
    let mut plan_options = PlanOptions::from_format_options(options, block_size)?;
    plan_options.label |= label_slot;
    let mut plan = Plan::new(plan_options);
    add(&mut plan)?;
    let estimate = plan.estimate()?;
    estimate.apply(options);
    let size = size.unwrap_or(estimate.size());
    // A block device cannot grow: what lies behind the offset is all there
    // is. A regular file is grown to the size, so the size is the limit.
    let available = if device.is_block_device() {
        size.min(device.len().saturating_sub(offset))
    } else {
        size
    };
    if available < estimate.size() {
        return Err(FitError::TooSmall {
            minimal: estimate.size(),
            actual: available,
        });
    }
    Ok((estimate, size))
}

/// Sizes the image for a planned file system, formats it and opens it:
/// the second step of [`fit_and_format`], after [`plan_fit`].
pub(crate) fn format_fit(
    mut device: Device,
    offset: u64,
    size: u64,
    estimate: Estimate,
    options: &FormatOptions,
) -> std::result::Result<(Volume, Estimate), FitError> {
    size_image(&mut device, offset, size)?;
    let device = device.window(offset, Some(size))?;
    Ok((Volume::create(device, options)?, estimate))
}
