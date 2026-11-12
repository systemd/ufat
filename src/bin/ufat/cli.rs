// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line interface.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use ufat::device::{Access, Device};
use ufat::errno;
use ufat::format::{self, FormatOptions, VolumeId};
use ufat::fsck;
use ufat::host;
use ufat::layout::MIN_SECTOR_SIZE;
use ufat::manifest::{self, AssembleOptions, DirectorySource, StreamSource};
use ufat::plan::{Plan, PlanOptions};
use ufat::populate::{CopyOptions, TimePolicy};
use ufat::time::civil_from_days;
use ufat::volume::Volume;
use ufat::{bail, err, Context, Result};

use crate::service;
use crate::util;

const USAGE: &str = "\
Usage: ufat COMMAND [OPTIONS...] ARGS...

Commands:
  assemble [OPTIONS] IMAGE [SOURCE...]   Create a FAT32 file system sized to fit
                                         the sources and fill it with them
  assemble --plan [OPTIONS] [SOURCE...]  Print the smallest file system size for
                                         the sources
  populate [OPTIONS] IMAGE [SOURCE...]   Fill an existing FAT32 file system
  remove [OPTIONS] IMAGE PATH...         Remove files and directories
  list [-l] IMAGE [PATH]                 List a directory
  describe [OPTIONS] IMAGE               Show a file system's geometry
  check IMAGE                            Check a file system
  capabilities                           Print what ufat supports, as JSON
  cat IMAGE PATH                         Print a file
  manifest DIR                           Write a UAPI.16 manifest of a directory
                                         tree

The commands are the methods of the org.uapi-group.FileSystem Varlink
interface that ufat serves; cat and manifest have no method.

assemble without a SOURCE creates an empty file system of the size of IMAGE or
--size, or sized to hold the --fit directories or what --manifest describes.
populate puts a SOURCE directory below --path and a SOURCE file at --path.
Without a SOURCE it creates the directory --path.

A SOURCE is a directory tree, or for populate one file. With --manifest the
one SOURCE is the tree the manifest describes, where its file contents are
read, or - for the contents on standard input, back to back in manifest order:
  --manifest PATH       Build what the UAPI.16 manifest at PATH, or on standard
                        input for -, describes
  --no-check-validity   Accept revoked and expired manifest entries
  --unsupported POLICY  What to do with what FAT cannot store: skip (default)
                        or fail

Options common to commands taking IMAGE:
  --offset BYTES        Byte offset of the file system inside IMAGE
  --size BYTES          Size of the file system inside IMAGE (assemble: instead
                        of the size that fits the sources; assemble --plan:
                        fail when the sources do not fit this size)

Options for assemble:
  --plan                Print the size the sources need and write nothing
  --sector-size BYTES   Logical sector size, 512 or 4096 (1024 and 2048 work)
  --cluster-size BYTES  Cluster size
  --identifier ID       Volume serial number, XXXX-XXXX or 8 hex digits
  --label LABEL         Volume label, up to 11 characters
  --oem-name NAME       OEM name in the boot sector (default MSWIN4.1)
  --hidden-sectors N    Hidden sectors field (default: the partition's start,
                        0 for image files)
  --no-align            Do not align structures to cluster boundaries
  --reserved-sectors N  Reserved sectors (default 32)
  --fats N              FAT copies (default 2)
  --mkfs-fat-compat     Reproduce mkfs.fat's layout quirks exactly
  --zero                Zero the whole data area
  --create              Create IMAGE if it does not exist (without a SOURCE it
                        needs --size, --fit or --manifest for that)
  --fit DIR             Size IMAGE to the smallest file system holding DIR
                        and leave it empty (no SOURCE; repeatable)
  --hash ALGORITHM      Print the sha256 or sha512 hash of the file system
                        written
  --write-hash PATH     Write that hash to PATH instead, or to standard output
                        for -
  --verbose             Report the geometry chosen

Options for assemble and populate:
  --timestamp SECONDS   Time to stamp, default $SOURCE_DATE_EPOCH, else now;
                        for a manifest the time of entries that carry none
  --times POLICY        preserve (default), fixed or clamp (clamp is the default
                        when $SOURCE_DATE_EPOCH is set; trees and files)
  --no-replace          Fail on existing files instead of replacing them
  --path PATH           The directory a SOURCE tree goes below (default /), the
                        path of a SOURCE file, or the directory to create
  --parents             Create missing parent directories of --path, and
                        accept a directory that exists (populate)
  --write-manifest PATH Write the UAPI.16 manifest of the file system to PATH,
                        or to standard output for -, afterwards (also describe)
  --verbose             Report what was written

Options for remove:
  --recursive, -r       Remove directories with everything below them

Sizes take K, M, G and T suffixes. Timestamps are seconds since the epoch.
Exit status: 0 on success, 1 on failure. check uses the fsck(8) codes: 0 for a
clean volume (warnings do not count), 4 when errors were found (the check
never repairs), 8 when the image could not be checked.
";

/// Options whose value is a path on the host, which can be any bytes. The
/// values of all other options are UTF-8.
const PATH_OPTIONS: &[&str] = &["fit", "manifest", "write-manifest", "write-hash"];

/// Parsed command line: options with optional values plus positional
/// arguments. Paths on the host are taken as the bytes they are; paths
/// inside the volume and other text have to be UTF-8.
struct Args {
    options: Vec<(String, Option<OsString>)>,
    positional: Vec<OsString>,
}

impl Args {
    /// Splits `args` with lexopt: `--name=value` or `--name value` for the
    /// options in `with_value`, `--name` for those in `flags`, and -p, -l
    /// and -r for `--parents`, `--long` and `--recursive` where `flags` has
    /// them. Short options can be bundled, as in `-lh`. `--` ends the
    /// options, and `-` is a positional argument. `-h` or `--help` anywhere
    /// among the options prints the usage and exits, whatever else is on
    /// the command line. After `--`, or as the value of an option, `-h` is
    /// an argument like any other.
    fn parse(args: &[OsString], with_value: &[&str], flags: &[&str]) -> Result<Args> {
        use lexopt::Arg::{Long, Short, Value};

        let mut options = Vec::new();
        let mut positional = Vec::new();
        let mut help = false;
        let mut problem = None;
        let mut parser = lexopt::Parser::from_args(args.iter().cloned());
        loop {
            let error = match parser.next() {
                Ok(None) => break,
                Ok(Some(Short('h') | Long("help"))) => {
                    help = true;
                    continue;
                }
                Ok(Some(Short(c))) => match short_option(c).filter(|name| flags.contains(name)) {
                    Some(name) => {
                        options.push((name.to_string(), None));
                        continue;
                    }
                    None => err!(errno::EINVAL, "unknown option -{}", c),
                },
                Ok(Some(Long(name))) if with_value.contains(&name) => {
                    let name = name.to_string();
                    match parser.value() {
                        Err(_) => err!(errno::EINVAL, "option --{} needs a value", name),
                        Ok(value) if !PATH_OPTIONS.contains(&name.as_str()) && value.to_str().is_none() => {
                            err!(errno::EINVAL, "the value of --{} is not valid UTF-8", name)
                        }
                        Ok(value) => {
                            options.push((name, Some(value)));
                            continue;
                        }
                    }
                }
                Ok(Some(Long(name))) if flags.contains(&name) => {
                    let name = name.to_string();
                    if parser.optional_value().is_some() {
                        err!(errno::EINVAL, "option --{} takes no value", name)
                    } else {
                        options.push((name, None));
                        continue;
                    }
                }
                Ok(Some(Long(name))) => err!(errno::EINVAL, "unknown option --{}", name),
                Ok(Some(Value(value))) => {
                    positional.push(value);
                    continue;
                }
                // A value attached to a short option, as in -r=x.
                Err(lexopt::Error::UnexpectedValue { option, .. }) => {
                    err!(errno::EINVAL, "option {} takes no value", option)
                }
                Err(e) => err!(errno::EINVAL, "{}", e),
            };
            problem.get_or_insert(error);
        }
        if help {
            print!("{}", USAGE);
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        match problem {
            Some(e) => Err(e),
            None => Ok(Args { options, positional }),
        }
    }

    /// The last value given to the option `name`.
    fn last(&self, name: &str) -> Option<&OsStr> {
        self.options
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    /// The value of a text option; see [`PATH_OPTIONS`] for the others.
    fn value(&self, name: &str) -> Option<&str> {
        self.last(name).and_then(OsStr::to_str)
    }

    /// The value of a path option.
    fn path(&self, name: &str) -> Option<&Path> {
        self.last(name).map(Path::new)
    }

    /// All values of a path option that can be given more than once.
    fn paths(&self, name: &str) -> Vec<&Path> {
        self.options
            .iter()
            .filter(|(n, _)| n == name)
            .filter_map(|(_, v)| v.as_deref().map(Path::new))
            .collect()
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }

    fn u32(&self, name: &str) -> Result<Option<u32>> {
        let Some(v) = self.value(name) else {
            return Ok(None);
        };
        let n = util::parse_size(v)?;
        u32::try_from(n)
            .map(Some)
            .map_err(|_| err!(errno::ERANGE, "--{} '{}' is too large", name, v))
    }

    fn size(&self, name: &str) -> Result<Option<u64>> {
        self.value(name).map(util::parse_size).transpose()
    }

    /// The positional arguments as paths on the host.
    fn positional_paths(&self) -> Vec<&Path> {
        self.positional.iter().map(Path::new).collect()
    }
}

/// The long option a short option stands for.
fn short_option(c: char) -> Option<&'static str> {
    match c {
        'p' => Some("parents"),
        'l' => Some("long"),
        'r' => Some("recursive"),
        _ => None,
    }
}

/// A path inside the volume, given on the command line. FAT stores names
/// in Unicode, so it has to be UTF-8.
fn volume_path(arg: &OsStr) -> Result<&str> {
    arg.to_str().ok_or_else(|| {
        err!(
            errno::EINVAL,
            "'{}' is not valid UTF-8; paths inside the volume are Unicode",
            arg.to_string_lossy()
        )
    })
}

const IMAGE_OPTIONS: &[&str] = &["offset", "size"];
const FORMAT_VALUES: &[&str] = &[
    "sector-size",
    "cluster-size",
    "identifier",
    "label",
    "timestamp",
    "oem-name",
    "reserved-sectors",
    "fats",
    "hidden-sectors",
];
/// Options of the commands that fill a volume from sources.
const FILL_VALUES: &[&str] = &[
    "timestamp",
    "times",
    "path",
    "manifest",
    "unsupported",
    "write-manifest",
];
const FILL_FLAGS: &[&str] = &["no-replace", "no-check-validity", "verbose"];
const FORMAT_FLAGS: &[&str] = &["no-align", "mkfs-fat-compat", "zero", "create", "verbose"];

fn with(a: &[&'static str], b: &[&'static str]) -> Vec<&'static str> {
    a.iter().chain(b).copied().collect()
}

/// The time to stamp: --timestamp, SOURCE_DATE_EPOCH, or now.
fn stamp_time(args: &Args) -> Result<(SystemTime, bool)> {
    if let Some(t) = args.value("timestamp") {
        return Ok((util::time_from_secs(t, "timestamp")?, true));
    }
    if let Some(t) = util::source_date_epoch()? {
        return Ok((t, true));
    }
    Ok((util::now(), false))
}

fn time_policy(args: &Args) -> Result<TimePolicy> {
    let (time, reproducible) = stamp_time(args)?;
    Ok(match args.value("times") {
        Some("preserve") => TimePolicy::Preserve,
        Some("fixed") => TimePolicy::Fixed(time),
        Some("clamp") => TimePolicy::Clamp(time),
        Some(other) => bail!(errno::EINVAL, "unknown time policy '{}'", other),
        None if reproducible => TimePolicy::Clamp(time),
        None => TimePolicy::Preserve,
    })
}

fn format_options(args: &Args) -> Result<FormatOptions> {
    let (time, reproducible) = stamp_time(args)?;
    let mut o = FormatOptions::default();
    o.sector_size = args.u32("sector-size")?;
    o.cluster_size = args.u32("cluster-size")?;
    o.label = args.value("label").map(str::to_string);
    o.volume_id = match args.value("identifier") {
        Some(v) => v.parse::<VolumeId>()?.0,
        None => util::pick_volume_id(time, o.label.as_deref(), reproducible),
    };
    o.timestamp = Some(time);
    if let Some(v) = args.value("oem-name") {
        o.oem_name = format::encode_oem_name(v)?;
    }
    if let Some(v) = args.u32("reserved-sectors")? {
        o.reserved_sectors = v;
    }
    if let Some(v) = args.u32("fats")? {
        o.fats = v;
    }
    o.hidden_sectors = args.u32("hidden-sectors")?;
    o.align = !args.flag("no-align");
    o.mkfs_fat_compat = args.flag("mkfs-fat-compat");
    o.zero_data_area = args.flag("zero");
    Ok(o)
}

/// Whether `--unsupported` asks to fail on what FAT cannot store instead of
/// leaving it out.
fn fail_unsupported(args: &Args) -> Result<bool> {
    match args.value("unsupported") {
        None | Some("skip") => Ok(false),
        Some("fail") => Ok(true),
        Some(other) => bail!(
            errno::EINVAL,
            "unknown policy '{}' for --unsupported, skip or fail",
            other
        ),
    }
}

/// Where SOURCE trees go: `--path`, the root by default.
fn dest(args: &Args) -> &str {
    args.value("path").unwrap_or("/")
}

/// Where the contents of a manifest's files come from.
enum Data {
    /// The tree the manifest describes, pinned.
    Directory { path: PathBuf, dir: OwnedFd },
    /// Standard input: every file's contents back to back, in manifest
    /// order.
    Stdin,
}

/// The manifest `--manifest` named, read once, and where its data is.
struct ManifestSource {
    /// How messages name the manifest: its path, or standard input.
    name: String,
    manifest: manifest::Manifest,
    /// None for the commands that only size.
    data: Option<Data>,
}

/// The SOURCE arguments, resolved once and before any image is touched:
/// directory trees, or with `--manifest` the one place the manifest's file
/// contents come from.
struct Sources {
    trees: Vec<(PathBuf, OwnedFd)>,
    manifest: Option<ManifestSource>,
}

/// Reads and parses the manifest `path` names, or the one on standard input
/// for "-". Returns it with the name messages give it.
fn read_manifest(path: &Path) -> Result<(manifest::Manifest, String)> {
    let (file, name) = if path == Path::new("-") {
        // A descriptor of our own, since the reader closes it.
        let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
        (std::fs::File::from(fd), "standard input".to_string())
    } else {
        (host::open_file(path)?, path.display().to_string())
    };
    let manifest = util::read_manifest(file).map_err(|e| {
        if e.is_manifest() {
            e.context(format_args!("{} is not a UAPI.16 manifest", name))
        } else {
            e.context(format_args!("cannot read {} as a manifest", name))
        }
    })?;
    Ok((manifest, name))
}

/// Resolves the SOURCE arguments (the `--fit` directories for an empty
/// file system), each exactly once. Without `--manifest` every one is a
/// directory tree. With it there is exactly one, the directory the manifest
/// describes or "-" for the file contents on standard input; sizing takes
/// none, the manifest carries the sizes. `--path` is for trees only.
fn sources(args: &Args, paths: &[&Path], sizing: bool) -> Result<Sources> {
    let Some(m) = args.path("manifest") else {
        let mut trees = Vec::with_capacity(paths.len());
        for &p in paths {
            let dir = host::open_dir(p).map_err(|e| {
                if e.errno() == errno::ENOTDIR {
                    e.context("a SOURCE is a directory tree; --manifest PATH names a manifest")
                } else {
                    e
                }
            })?;
            trees.push((p.to_path_buf(), dir));
        }
        return Ok(Sources { trees, manifest: None });
    };
    if m == Path::new("-") && !sizing && matches!(paths, [p] if *p == Path::new("-")) {
        bail!(
            errno::EINVAL,
            "--manifest - and a SOURCE of - cannot both read standard input"
        );
    }
    let (manifest, name) = read_manifest(m)?;
    if dest(args) != "/" {
        bail!(
            errno::EINVAL,
            "--path applies to directory trees; a manifest names its paths from the root"
        );
    }
    let data = match (sizing, paths) {
        (true, []) => None,
        (true, _) => bail!(
            errno::EINVAL,
            "--manifest carries the sizes, no SOURCE or --fit directory is taken with it"
        ),
        (false, [p]) if *p == Path::new("-") => Some(Data::Stdin),
        (false, [p]) => Some(Data::Directory {
            path: p.to_path_buf(),
            dir: host::open_dir(p)?,
        }),
        (false, _) => bail!(
            errno::EINVAL,
            "--manifest takes exactly one SOURCE: the directory the manifest describes, or - for the file contents on standard input"
        ),
    };
    Ok(Sources {
        trees: Vec::new(),
        manifest: Some(ManifestSource { name, manifest, data }),
    })
}

/// What can be checked before an image is created, formatted or written:
/// that the manifest and, under `--unsupported fail`, the trees can be
/// stored, and that every file the manifest names is below the SOURCE with
/// the size it says.
fn check_sources(args: &Args, sources: &Sources) -> Result<()> {
    if fail_unsupported(args)? {
        for (path, dir) in &sources.trees {
            let mut plan = Plan::new(PlanOptions::new(MIN_SECTOR_SIZE));
            if let Some(skipped) = plan.add_tree(dir.as_fd(), dest(args), true)?.first() {
                bail!(
                    errno::EINVAL,
                    "{} cannot be stored on FAT",
                    path.join(skipped).display()
                );
            }
        }
    }
    let Some(m) = &sources.manifest else {
        return Ok(());
    };
    if fail_unsupported(args)? {
        m.manifest.check_supported()?;
    }
    if let Some(Data::Directory { path, dir }) = &m.data {
        DirectorySource::new(dir.try_clone()?)
            .follow_symlinks(true)
            .verify(&m.manifest)
            .map_err(|e| {
                e.context(format!(
                    "the files {} describes are not all below {}",
                    m.name,
                    path.display()
                ))
            })?;
    }
    Ok(())
}

/// Adds the sources to a plan, the way `fill` will write them.
fn plan_sources(plan: &mut Plan, args: &Args, sources: &Sources) -> Result<()> {
    for (_, dir) in &sources.trees {
        plan.add_tree(dir.as_fd(), dest(args), true)?;
    }
    if let Some(m) = &sources.manifest {
        for skipped in plan.add_manifest(&m.manifest)? {
            eprintln!("ufat: not counted {}: it cannot be stored on FAT", skipped);
        }
    }
    Ok(())
}

fn assemble_options(args: &Args) -> Result<AssembleOptions> {
    let (time, _) = stamp_time(args)?;
    Ok(AssembleOptions {
        default_time: time,
        replace: !args.flag("no-replace"),
        skip_unsupported: !fail_unsupported(args)?,
        now_usec: if args.flag("no-check-validity") {
            None
        } else {
            Some(ufat::time::to_usec(util::now()))
        },
    })
}

/// Writes the sources into an open volume: the trees copied in the order
/// given, or the manifest assembled.
fn fill(v: &mut Volume, args: &Args, sources: &Sources) -> Result<()> {
    let copy = CopyOptions {
        times: time_policy(args)?,
        replace: !args.flag("no-replace"),
        follow_symlinks: true,
    };
    for (path, dir) in &sources.trees {
        let report = v.copy_tree(dir.as_fd(), dest(args), &copy)?;
        if args.flag("verbose") {
            eprintln!(
                "{}: {} files, {} directories, {} bytes",
                path.display(),
                report.files,
                report.directories,
                report.bytes
            );
        }
        for skipped in report.skipped {
            eprintln!(
                "ufat: skipped {}: not a regular file or directory",
                path.join(skipped).display()
            );
        }
    }
    if let Some(m) = &sources.manifest {
        let options = assemble_options(args)?;
        let report = match &m.data {
            Some(Data::Stdin) => {
                let stdin = std::io::stdin();
                let mut lock = stdin.lock();
                v.assemble(&m.manifest, &mut StreamSource::new(&mut lock), &options)?
            }
            Some(Data::Directory { dir, .. }) => v.assemble(
                &m.manifest,
                &mut DirectorySource::new(dir.try_clone()?).follow_symlinks(true),
                &options,
            )?,
            None => bail!(errno::EINVAL, "a manifest needs a SOURCE to be filled from"),
        };
        if args.flag("verbose") {
            eprintln!(
                "{}: {} files, {} directories, {} bytes",
                m.name, report.files, report.directories, report.bytes
            );
        }
        for skipped in report.skipped {
            eprintln!("ufat: skipped {}: it cannot be stored on FAT", skipped);
        }
    }
    Ok(())
}

/// Whether `--write-manifest -` puts the manifest on standard output. What
/// the command prints there otherwise goes to standard error then.
fn manifest_to_stdout(args: &Args) -> bool {
    args.path("write-manifest") == Some(Path::new("-"))
}

/// Writes the UAPI.16 manifest of everything `v` holds to the file `path`,
/// or to standard output for "-", for `--write-manifest`.
fn write_manifest(v: &Volume, path: &Path) -> Result<()> {
    let fields = manifest::volume::Fields::default();
    let (report, shown) = if path == Path::new("-") {
        let mut out = std::io::BufWriter::new(std::io::stdout().lock());
        let report = manifest::volume::write(v, v.root_time()?, fields, &mut out)?;
        (report, "the manifest on standard output".to_string())
    } else {
        let file = std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut out = std::io::BufWriter::new(file);
        let report = manifest::volume::write(v, v.root_time()?, fields, &mut out)?;
        (report, path.display().to_string())
    };
    if report.omitted > 0 {
        eprintln!(
            "ufat: {} entries are not in {}: their names cannot be written in a manifest",
            report.omitted, shown
        );
    }
    Ok(())
}

/// Reports the geometry of a freshly made file system.
fn report_layout(image: &Path, layout: &ufat::layout::Layout, verbose: bool) {
    if verbose {
        eprintln!(
            "{}: {} sectors of {} bytes, {} clusters of {} bytes, {} reserved sectors, {} FATs of {} sectors",
            image.display(),
            layout.total_sectors,
            layout.sector_size,
            layout.clusters,
            layout.cluster_size(),
            layout.reserved_sectors,
            layout.fats,
            layout.fat_sectors
        );
    }
}

fn open_image(args: &Args, path: &Path, access: Access) -> Result<Device> {
    let offset = args.size("offset")?.unwrap_or(0);
    util::open_image(path, offset, args.size("size")?, access)
}

fn open_volume(args: &Args, path: &Path, access: Access) -> Result<Volume> {
    Volume::open(open_image(args, path, access)?)
}

fn image_arg<'a>(args: &'a Args, command: &str) -> Result<&'a Path> {
    match args.positional.as_slice() {
        [image] => Ok(Path::new(image)),
        _ => bail!(errno::EINVAL, "{} takes exactly one IMAGE argument", command),
    }
}

/// `assemble --plan`: the size the sources need, with nothing written.
fn plan(args: &Args) -> Result<()> {
    if args.positional.is_empty() && args.path("manifest").is_none() {
        bail!(errno::EINVAL, "assemble --plan needs at least one SOURCE or --manifest");
    }
    let options = format_options(args)?;
    let mut plan = Plan::new(PlanOptions::from_format_options(&options, None)?);
    let sources = sources(args, &args.positional_paths(), true)?;
    plan_sources(&mut plan, args, &sources)?;
    let e = plan.estimate()?;
    if let Some(size) = args.size("size")? {
        if e.size() > size {
            bail!(
                errno::ENOSPC,
                "the sources need a {} byte file system, more than --size {}",
                e.size(),
                size
            );
        }
    }
    println!("{}", e.size());
    if args.flag("verbose") {
        eprintln!(
            "{} files, {} directories, {} bytes: {} clusters of {} bytes, {} sector size",
            e.files,
            e.directories,
            e.bytes,
            e.data_clusters,
            e.layout.cluster_size(),
            e.layout.sector_size
        );
    }
    Ok(())
}

/// `assemble` without a SOURCE: an empty file system, of the size of the
/// image or `--size`, or sized for the `--fit` directories or what
/// `--manifest` describes.
fn assemble_empty(args: &Args, path: &Path) -> Result<Volume> {
    let mut options = format_options(args)?;
    let offset = args.size("offset")?.unwrap_or(0);
    let size = args.size("size")?;
    let fit = args.paths("fit");
    let target = util::Target {
        path,
        offset,
        size,
        create: args.flag("create"),
    };
    if fit.is_empty() && args.path("manifest").is_none() {
        let mut device = util::open_target(&target)?;
        if target.create {
            let size = size.ok_or_else(|| err!(errno::EINVAL, "--create needs --size, --fit or --manifest"))?;
            util::size_image(&mut device, offset, size)?;
        }
        let device = device.window(offset, size)?;
        format::format(&device, &options)?;
        return Volume::open(device);
    }
    let sources = sources(args, &fit, true)?;
    let (volume, estimate) =
        util::fit_and_format(&target, &mut options, &mut |plan| plan_sources(plan, args, &sources))
            .map_err(|e| e.into_error(path))?;
    report_estimate(args, path, &estimate);
    Ok(volume)
}

/// `assemble` with SOURCE arguments: the file system sized to fit them,
/// unless `--size` says otherwise, and filled with them.
fn assemble_filled(args: &Args, path: &Path, paths: &[&Path]) -> Result<Volume> {
    if !args.paths("fit").is_empty() {
        bail!(
            errno::EINVAL,
            "--fit sizes an empty file system; with a SOURCE the file system is sized for it"
        );
    }
    let sources = sources(args, paths, false)?;
    // Better to learn about a bad manifest or tree before an image is sized
    // and formatted.
    check_sources(args, &sources)?;
    let mut options = format_options(args)?;
    let target = util::Target {
        path,
        offset: args.size("offset")?.unwrap_or(0),
        size: args.size("size")?,
        create: args.flag("create"),
    };
    let (mut v, estimate) = util::fit_and_format(&target, &mut options, &mut |plan| plan_sources(plan, args, &sources))
        .map_err(|e| e.into_error(path))?;
    report_estimate(args, path, &estimate);
    match fill(&mut v, args, &sources) {
        Ok(()) => Ok(v),
        Err(e) => Err(unfinished(v, e)),
    }
}

/// Closes the file system `assemble` failed to finish with `e`, marked as
/// not cleanly unmounted as after a crash, so that nobody takes it for a
/// finished one. Returns `e`: an error of the close is not the one the
/// user needs to hear about.
fn unfinished(v: Volume, e: ufat::Error) -> ufat::Error {
    let _ = v.close_unfinished();
    e
}

fn report_estimate(args: &Args, path: &Path, estimate: &ufat::plan::Estimate) {
    if args.flag("verbose") {
        eprintln!(
            "{}: {} files and {} directories in {} bytes need a {} byte file system with {} byte clusters",
            path.display(),
            estimate.files,
            estimate.directories,
            estimate.bytes,
            estimate.size(),
            estimate.layout.cluster_size()
        );
    }
}

fn cmd_assemble(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(
        argv,
        &with(
            FORMAT_VALUES,
            &with(IMAGE_OPTIONS, &with(FILL_VALUES, &["fit", "hash", "write-hash"])),
        ),
        &with(FORMAT_FLAGS, &with(FILL_FLAGS, &["plan"])),
    )?;
    if args.flag("plan") {
        return plan(&args);
    }
    let hash = match args.value("hash") {
        None => None,
        Some(a) => Some(
            service::Hash::new(a)
                .ok_or_else(|| err!(errno::EINVAL, "unknown hash algorithm '{}', sha256 or sha512", a))?,
        ),
    };
    let hash_path = args.path("write-hash");
    if hash_path.is_some() && hash.is_none() {
        bail!(errno::EINVAL, "--write-hash needs --hash");
    }
    if hash_path == Some(Path::new("-")) && manifest_to_stdout(&args) {
        bail!(
            errno::EINVAL,
            "--write-manifest - and --write-hash - cannot both write to standard output"
        );
    }
    let (path, paths) = match args.positional_paths().split_first() {
        Some((&i, s)) => (i, s.to_vec()),
        None => bail!(errno::EINVAL, "assemble takes an IMAGE and SOURCE arguments"),
    };
    let v = if paths.is_empty() {
        assemble_empty(&args, path)?
    } else {
        assemble_filled(&args, path, &paths)?
    };
    if let Some(m) = args.path("write-manifest") {
        if let Err(e) = write_manifest(&v, m) {
            return Err(unfinished(v, e));
        }
    }
    let layout = *v.layout();
    v.close()?;
    report_layout(path, &layout, args.flag("verbose"));
    if let Some(hash) = hash {
        let digest = hash.of(&open_image(&args, path, Access::ReadOnly)?, &mut |_| {})?;
        match hash_path {
            Some(p) if p != Path::new("-") => {
                std::fs::write(p, format!("{}\n", digest)).with_context(|| format!("cannot write {}", p.display()))?
            }
            None if manifest_to_stdout(&args) => eprintln!("{}", digest),
            _ => println!("{}", digest),
        }
    }
    Ok(())
}

/// The path of the parent directory of `path`, None for one at the root.
fn parent_of(path: &str) -> Option<&str> {
    path.trim_end_matches('/')
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .filter(|parent| !parent.trim_matches('/').is_empty())
}

/// The directory `path` for a tree to go below: created when missing, with
/// its parents under `--parents`.
fn ensure_dir(v: &mut Volume, path: &str, parents: bool, time: SystemTime) -> Result<()> {
    if parents {
        return v.create_dir_all(path, time);
    }
    match v.metadata(path) {
        Ok(md) if md.is_dir => Ok(()),
        Ok(_) => bail!(errno::ENOTDIR, "'{}' is not a directory", path),
        Err(e) if e.errno() == errno::ENOENT => v.create_dir(path, time),
        Err(e) => Err(e),
    }
}

fn cmd_populate(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, &with(IMAGE_OPTIONS, FILL_VALUES), &with(FILL_FLAGS, &["parents"]))?;
    let (image, paths) = match args.positional_paths().split_first() {
        Some((&i, s)) => (i, s.to_vec()),
        None => bail!(errno::EINVAL, "populate takes an IMAGE and SOURCE arguments"),
    };
    let path = volume_path(args.last("path").unwrap_or(OsStr::new("/")))?;
    let (time, _) = stamp_time(&args)?;
    let parents = args.flag("parents");
    // One SOURCE that is not a directory is a file that goes to --path.
    let file = match paths.as_slice() {
        [p] if args.path("manifest").is_none() => match host::open_dir(p) {
            Err(e) if e.errno() == errno::ENOTDIR => Some(host::open_file(p)?),
            _ => None,
        },
        _ => None,
    };
    if let Some(file) = file {
        if path == "/" {
            bail!(
                errno::EINVAL,
                "a SOURCE file needs --path, the path it gets in the file system"
            );
        }
        let options = CopyOptions {
            times: time_policy(&args)?,
            replace: !args.flag("no-replace"),
            ..CopyOptions::default()
        };
        let mut v = open_volume(&args, image, Access::ReadWrite)?;
        if parents {
            if let Some(parent) = parent_of(path) {
                v.create_dir_all(parent, time)?;
            }
        }
        v.copy_file(file.as_fd(), path, &options)?;
        if let Some(m) = args.path("write-manifest") {
            write_manifest(&v, m)?;
        }
        return v.close();
    }
    if paths.is_empty() && args.path("manifest").is_none() {
        if path == "/" {
            bail!(
                errno::EINVAL,
                "populate takes a SOURCE, or --path for the directory to create"
            );
        }
        let mut v = open_volume(&args, image, Access::ReadWrite)?;
        if parents {
            v.create_dir_all(path, time)?;
        } else {
            v.create_dir(path, time)?;
        }
        if let Some(m) = args.path("write-manifest") {
            write_manifest(&v, m)?;
        }
        return v.close();
    }
    let sources = sources(&args, &paths, false)?;
    check_sources(&args, &sources)?;
    let mut v = open_volume(&args, image, Access::ReadWrite)?;
    if !sources.trees.is_empty() {
        ensure_dir(&mut v, path, parents, time)?;
    }
    fill(&mut v, &args, &sources)?;
    if let Some(m) = args.path("write-manifest") {
        write_manifest(&v, m)?;
    }
    v.close()
}

fn cmd_remove(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, IMAGE_OPTIONS, &["recursive"])?;
    let (image, paths) = match args.positional.split_first() {
        Some((i, p)) if !p.is_empty() => (i, p),
        _ => bail!(errno::EINVAL, "remove takes an IMAGE and at least one PATH"),
    };
    let paths = paths.iter().map(|p| volume_path(p)).collect::<Result<Vec<_>>>()?;
    let mut v = open_volume(&args, Path::new(image), Access::ReadWrite)?;
    for path in paths {
        let md = v.metadata(path)?;
        // The root directory itself stays.
        if md.name.is_empty() {
            bail!(errno::EBUSY, "the root directory cannot be removed");
        }
        if !md.is_dir {
            v.remove_file(path)?;
        } else if args.flag("recursive") {
            v.remove_tree(path)?;
        } else {
            v.remove_dir(path)?;
        }
    }
    v.close()
}

fn format_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

fn cmd_list(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, IMAGE_OPTIONS, &["long"])?;
    let (image, path) = match args.positional.as_slice() {
        [i] => (i, "/"),
        [i, p] => (i, volume_path(p)?),
        _ => bail!(errno::EINVAL, "list takes an IMAGE and optionally a PATH"),
    };
    let v = open_volume(&args, Path::new(image), Access::ReadOnly)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for m in v.read_dir(path)? {
        if args.flag("long") {
            writeln!(
                out,
                "{} {:>10} {} {}{}{}",
                if m.is_dir { 'd' } else { '-' },
                m.size,
                format_time(m.modified),
                m.name,
                if m.is_dir { "/" } else { "" },
                if m.short_name == m.name {
                    String::new()
                } else {
                    format!("  ({})", m.short_name)
                }
            )?;
        } else {
            writeln!(out, "{}{}", m.name, if m.is_dir { "/" } else { "" })?;
        }
    }
    Ok(())
}

/// Prints the geometry, the serial number and the label of `v` to `out`.
fn print_description(v: &Volume, out: &mut dyn Write) -> Result<()> {
    let l = v.layout();
    let bs = v.boot_sector();
    writeln!(out, "sector size:      {}", l.sector_size)?;
    writeln!(
        out,
        "usable on:        devices with a logical block size up to {} bytes",
        l.sector_size
    )?;
    writeln!(out, "cluster size:     {}", l.cluster_size())?;
    writeln!(out, "total sectors:    {}", l.total_sectors)?;
    writeln!(out, "size:             {}", l.size())?;
    writeln!(out, "reserved sectors: {}", l.reserved_sectors)?;
    writeln!(out, "FATs:             {} x {} sectors", l.fats, l.fat_sectors)?;
    writeln!(out, "clusters:         {} ({} free)", l.clusters, v.free_clusters())?;
    writeln!(out, "root cluster:     {}", bs.root_cluster)?;
    writeln!(out, "volume id:        {}", VolumeId(bs.volume_id))?;
    writeln!(out, "volume label:     {}", v.label()?.unwrap_or_default())?;
    writeln!(
        out,
        "OEM name:         {}",
        String::from_utf8_lossy(&bs.oem_name).trim_end()
    )?;
    if l.below_spec_minimum() {
        writeln!(
            out,
            "note:             below the FAT32 minimum of {} clusters",
            ufat::layout::MIN_CLUSTERS
        )?;
    }
    Ok(())
}

fn cmd_describe(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, &with(IMAGE_OPTIONS, &["write-manifest"]), &[])?;
    let image = image_arg(&args, "describe")?;
    let v = open_volume(&args, image, Access::ReadOnly)?;
    if manifest_to_stdout(&args) {
        print_description(&v, &mut std::io::stderr().lock())?;
    } else {
        print_description(&v, &mut std::io::stdout().lock())?;
    }
    if let Some(m) = args.path("write-manifest") {
        write_manifest(&v, m)?;
    }
    Ok(())
}

fn cmd_cat(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, IMAGE_OPTIONS, &[])?;
    let [image, path] = args.positional.as_slice() else {
        bail!(errno::EINVAL, "cat takes an IMAGE and a PATH");
    };
    let path = volume_path(path)?;
    let v = open_volume(&args, Path::new(image), Access::ReadOnly)?;
    let mut reader = v.open_file(path)?;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
    }
    Ok(())
}

/// The fsck(8) exit codes, as systemd-fsck and fsck(8) read them
/// (systemd's src/shared/fsck-util.h). The check is read-only, so errors it
/// finds are always left uncorrected.
const FSCK_ERRORS_LEFT_UNCORRECTED: u8 = 4;
const FSCK_OPERATIONAL_ERROR: u8 = 8;

/// Checks the volume and returns the fsck(8) exit code.
fn cmd_check(argv: &[OsString]) -> Result<ExitCode> {
    let args = Args::parse(argv, IMAGE_OPTIONS, &[])?;
    let image = image_arg(&args, "check")?;
    let report = match open_image(&args, image, Access::ReadOnly).and_then(|d| fsck::check(&d)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ufat: {}", e);
            return Ok(ExitCode::from(FSCK_OPERATIONAL_ERROR));
        }
    };
    for p in &report.problems {
        println!(
            "{}: {}",
            if p.severity == fsck::Severity::Error {
                "error"
            } else {
                "warning"
            },
            p
        );
    }
    if report.dropped > 0 {
        println!("... and {} more problems not shown", report.dropped);
    }
    println!(
        "{}: {} files, {} directories, {} clusters used, {} free, {} lost; {} errors, {} warnings",
        image.display(),
        report.files,
        report.directories,
        report.used_clusters,
        report.free_clusters,
        report.lost_clusters,
        report.errors(),
        report.warnings()
    );
    Ok(if report.errors() > 0 {
        ExitCode::from(FSCK_ERRORS_LEFT_UNCORRECTED)
    } else {
        ExitCode::SUCCESS
    })
}

/// Prints what `GetCapabilities` answers, as JSON.
fn cmd_capabilities(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, &[], &[])?;
    if !args.positional.is_empty() {
        bail!(errno::EINVAL, "capabilities takes no arguments");
    }
    println!("{}", json::Value::Object(service::capabilities()?));
    Ok(())
}

fn cmd_manifest(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, &[], &[])?;
    let [dir] = args.positional.as_slice() else {
        bail!(errno::EINVAL, "manifest takes exactly one DIR");
    };
    let dir = host::open_dir(Path::new(dir))?;
    let bytes = manifest::generate(dir.as_fd())?;
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

fn run(argv: &[OsString]) -> Result<ExitCode> {
    let Some(command) = argv.first() else {
        eprint!("{}", USAGE);
        return Ok(ExitCode::FAILURE);
    };
    let command = command
        .to_str()
        .ok_or_else(|| err!(errno::EINVAL, "unknown command '{}'", command.to_string_lossy()))?;
    // A -h or --help after the command is left to Args::parse(), which
    // knows where the options end.
    if matches!(command, "help" | "--help" | "-h") {
        print!("{}", USAGE);
        return Ok(ExitCode::SUCCESS);
    }
    let rest = &argv[1..];
    match command {
        "assemble" => cmd_assemble(rest)?,
        "populate" => cmd_populate(rest)?,
        "remove" => cmd_remove(rest)?,
        "list" => cmd_list(rest)?,
        "describe" => cmd_describe(rest)?,
        "check" => return cmd_check(rest),
        "capabilities" => cmd_capabilities(rest)?,
        "cat" => cmd_cat(rest)?,
        "manifest" => cmd_manifest(rest)?,
        other => bail!(errno::EINVAL, "unknown command '{}'", other),
    }
    Ok(ExitCode::SUCCESS)
}

/// Runs the command line interface.
pub(crate) fn main() -> ExitCode {
    // Rust starts programs with SIGPIPE ignored, so writing to a pipe whose
    // reader is gone fails with EPIPE, and print!() panics on that, as in
    // `ufat describe IMAGE | head -1`. Let the signal end the tool quietly
    // instead, as it ends other command line tools. The service keeps
    // ignoring it: it writes its replies to the socket with plain writes.
    // SAFETY: signal() only sets how SIGPIPE is handled, and SIG_DFL is a
    // valid disposition.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ufat: {}", e);
            ExitCode::FAILURE
        }
    }
}
