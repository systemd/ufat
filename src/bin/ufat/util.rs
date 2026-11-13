// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers shared by the command line interface and the Varlink service.

use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ufat::device::{Access, Device};
use ufat::errno;
use ufat::format::FormatOptions;
use ufat::plan::{Estimate, Plan, PlanOptions};
use ufat::probe::Prober;
use ufat::volume::Volume;
use ufat::{bail, err, Context, Error, Result};

/// The current time.
pub(crate) fn now() -> SystemTime {
    SystemTime::now()
}

/// The largest manifest read into memory. A record is at most 4 MiB and a
/// tree of a hundred thousand files describes itself in some tens of MiB,
/// so anything above this is not a manifest, an image given by mistake for
/// one, and is refused before it is read into memory.
pub(crate) const MAX_MANIFEST_BYTES: u64 = 256 * 1024 * 1024;

/// Reads a UAPI.16 manifest from an open file or pipe to its end, within
/// [`MAX_MANIFEST_BYTES`], and parses it.
pub(crate) fn read_manifest(file: std::fs::File) -> Result<ufat::manifest::Manifest> {
    let text = read_all(file, MAX_MANIFEST_BYTES).with_context(|| "cannot read the manifest")?;
    ufat::manifest::parse(&text)
}

/// Reads an open file to its end, refusing one of more than `limit` bytes
/// (EFBIG) instead of holding it in memory.
pub(crate) fn read_all(file: std::fs::File, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        bail!(errno::EFBIG, "more than {} bytes", limit);
    }
    Ok(data)
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
        if let Ok(id) = ufat::format::random_volume_id() {
            return id;
        }
    }
    // FNV-1a over the time and the label.
    let mut h: u32 = 0x811c_9dc5;
    for b in ufat::time::to_usec(time)
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
