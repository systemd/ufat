// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line interface.

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use fat::device::{Access, Device};
use fat::errno;
use fat::format::{self, FormatOptions, VolumeId};
use fat::fsck;
use fat::host;
use fat::layout::MIN_SECTOR_SIZE;
use fat::manifest::{
    AssembleFlags, AssembleObserver, AssembleOptions, DirectorySource, Features, HostTree, Name, PinnedDirectory,
    Problem, SkipReason, StreamSource, WriteReport,
};
use fat::plan::{Plan, PlanOptions};
use fat::populate::{CopyOptions, TimePolicy};
use fat::time::civil_from_days;
use fat::volume::{NameCollision, Volume};
use fat::{bail, err, Context, DescriptorProblem, Detail, Error, ManifestProblem, Result};

use crate::service;
use crate::util::{self, Failure, GivenSize, ImageFlags, ManifestInput, ManifestUse, NewVolume, SizeMode, SizeRequest};

const USAGE: &str = "\
Usage: ufat COMMAND [OPTIONS...] ARGS...
       ufat --help
       ufat --version

Commands:
  assemble [OPTIONS] IMAGE [SOURCE]      Create a FAT32 file system and fill it
                                         with SOURCE or what --manifest
                                         describes
  assemble --plan [OPTIONS] [SOURCE]     Print the smallest file system size for
                                         SOURCE or what --manifest describes
  populate [OPTIONS] IMAGE [SOURCE]      Fill an existing FAT32 file system
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

assemble makes the file system as large as --size, or else as large as the
part of IMAGE behind --offset. --minimize makes it the smallest that holds the
content, and --size is then the most it may take. Without a SOURCE it is
empty. The --fit directory or what --manifest describes then has to fit
--size, and without --size the file system is the smallest that holds it.
assemble refuses an IMAGE that holds a file system, a partition table or other
data libblkid recognizes, or without libblkid anything that is not blank.
--force formats it anyway.
populate puts a SOURCE directory below --path and a SOURCE file at --path.
Without a SOURCE it creates the directory --path.

A SOURCE is a directory tree, or for populate one file. With --manifest the
one SOURCE is the tree the manifest describes, where its file contents are
read, or - for the contents on standard input, back to back in manifest order.
The manifest has to declare \"order\": \"codepoint\" and be in that order.
assemble --minimize with a SOURCE reads the manifest twice, to plan the file
system and to fill it, and needs it in a regular file. Everything else reads
it once and takes a pipe:
  --manifest PATH       Build what the UAPI.16 manifest at PATH, or on standard
                        input for -, describes
  --no-check-validity   Accept revoked and expired manifest entries
  --unsupported POLICY  What to do with what FAT cannot store: skip (default)
                        or fail

Options common to commands taking IMAGE:
  --offset BYTES        Byte offset of the file system inside IMAGE
  --size BYTES          Size of the file system inside IMAGE, or with
                        --minimize the most it may take (--minimize, --plan,
                        --fit and --manifest without a SOURCE fail when the
                        content does not fit this size)

Options for assemble:
  --plan                Print the size the content needs and write nothing
  --minimize            Make the file system the smallest that holds the
                        content
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
  --create              Create IMAGE if it does not exist (it then needs --size,
                        --minimize, --fit, or --manifest without a SOURCE).
                        IMAGE gets its name only once assemble succeeded (the
                        README says when a failure leaves it nonetheless)
  --force, -f           Format IMAGE whatever it holds
  --fit DIR             Size IMAGE for DIR and leave it empty (no SOURCE):
                        --size, which DIR has to fit, or else the smallest
                        file system holding DIR
  --hash ALGORITHM      Print the sha256 or sha512 hash of the file system
                        written
  --write-hash PATH     Write that hash to PATH instead, or to standard output
                        for -

Options for assemble and populate:
  --timestamp SECONDS   Time to stamp, default $SOURCE_DATE_EPOCH, else now;
                        for a manifest the time of entries that carry none
  --times POLICY        preserve (default), fixed or clamp (clamp is the default
                        when $SOURCE_DATE_EPOCH is set; trees and files)
  --replace             Replace a file that is there already, and take a name
                        FAT does not tell apart from one that is there as that
                        name, instead of failing
  --path PATH           The directory a SOURCE tree goes below (default /), the
                        path of a SOURCE file, or the directory to create
  --parents             Create missing parent directories of --path, and
                        accept a directory that exists (populate)
  --write-manifest PATH Write the UAPI.16 manifest of the file system to PATH,
                        or to standard output for -, afterwards (also describe)
  --verbose             Report the geometry chosen and what was written

Options for remove:
  --recursive, -r       Remove directories with everything below them
  --verbose             Report what was removed

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
    /// options in `with_value`, `--name` for those in `flags`, and -p, -l,
    /// -r and -f for `--parents`, `--long`, `--recursive` and `--force`
    /// where `flags` has them. Short options can be bundled, as in `-lh`.
    /// `--` ends the options, and `-` is a positional argument. `-h` or
    /// `--help` anywhere among the options prints the usage and exits,
    /// whatever else is on the command line. After `--`, or as the value of
    /// an option, `-h` is an argument like any other.
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

    /// What `--create` and `--force` allow to be done to the image.
    fn image_flags(&self) -> ImageFlags {
        let mut flags = ImageFlags::default();
        flags.set(ImageFlags::CREATE, self.flag("create"));
        flags.set(ImageFlags::FORCE, self.flag("force"));
        flags
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
        'f' => Some("force"),
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

/// `n` followed by `one` or `many`, as the count asks for.
fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", n, if n == 1 { one } else { many })
}

/// What a copy wrote, or what a plan found, for `--verbose`.
fn contents(files: u64, directories: u64, bytes: u64) -> String {
    format!(
        "{}, {}, {}",
        plural(files, "file", "files"),
        plural(directories, "directory", "directories"),
        plural(bytes, "byte", "bytes")
    )
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
const FILL_FLAGS: &[&str] = &["no-check-validity", "replace", "verbose"];
const FORMAT_FLAGS: &[&str] = &[
    "no-align",
    "mkfs-fat-compat",
    "zero",
    "create",
    "force",
    "minimize",
    "verbose",
];

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

/// Where a SOURCE tree goes: `--path`, the root by default.
fn dest(args: &Args) -> &str {
    args.value("path").unwrap_or("/")
}

/// Where the contents of a manifest's files come from.
enum ContentOrigin {
    /// The tree the manifest describes, pinned.
    Directory { path: PathBuf, dir: OwnedFd },
    /// Standard input: every file's contents back to back, in manifest
    /// order.
    Stdin,
}

/// The SOURCE argument, resolved once and before any image is touched.
enum Source {
    /// Neither a SOURCE nor `--manifest`.
    None,
    /// A directory tree, pinned.
    Tree { path: PathBuf, dir: OwnedFd },
    /// The manifest `--manifest` named, open with its root file object
    /// read, and where the contents of its files come from.
    Manifest {
        /// How messages name the manifest: its path, or standard input.
        name: String,
        manifest: Box<ManifestInput>,
        /// None for the commands that only size, and once the contents
        /// were written.
        contents: Option<ContentOrigin>,
    },
}

/// What a command does with its SOURCE.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sourcing {
    /// The caller sizes a file system for the SOURCE and writes nothing of
    /// it. A manifest takes no SOURCE then, since it carries the sizes, and
    /// is planned on from its root file object, so it is read once.
    Size,
    /// The caller writes the SOURCE into a file system, and reads a manifest
    /// as the use says. A manifest takes one SOURCE then: the directory its
    /// file contents are read from, or "-" for standard input.
    Write(ManifestUse),
}

impl Sourcing {
    /// What the command does with a manifest.
    fn manifest_use(self) -> ManifestUse {
        match self {
            Sourcing::Size => ManifestUse::PlanOnly,
            Sourcing::Write(manifest_use) => manifest_use,
        }
    }
}

/// Opens the manifest `path` names, or the one on standard input for "-",
/// for `manifest_use`, and reads its first record. Returns it with the name
/// messages give it.
fn read_manifest(path: &Path, manifest_use: ManifestUse) -> Result<(ManifestInput, String)> {
    let (file, name) = if path == Path::new("-") {
        // A descriptor of our own, since the reader closes it.
        let fd = std::io::stdin().as_fd().try_clone_to_owned()?;
        (std::fs::File::from(fd), "standard input".to_string())
    } else {
        (host::open_file(path)?, path.display().to_string())
    };
    let input = ManifestInput::open(file, manifest_use).map_err(|e| match e.detail() {
        // A manifest, but not one ufat takes.
        Some(Detail::Manifest {
            problem: ManifestProblem::Malformed(Problem::NoOrder),
            ..
        }) => e.context(&name),
        // A pipe, refused before anything was read from it.
        Some(Detail::Descriptor {
            problem: DescriptorProblem::WrongType,
            ..
        }) => err!(
            errno::EINVAL,
            "{} is not a regular file: --minimize with a SOURCE needs the manifest in one",
            name
        ),
        _ if e.is_manifest() => e.context(format_args!("{} is not a UAPI.16 manifest", name)),
        _ => e.context(format_args!("cannot read {} as a manifest", name)),
    })?;
    Ok((input, name))
}

impl Source {
    /// Resolves the SOURCE argument (the `--fit` directory for an empty file
    /// system) exactly once. Without `--manifest` it is a directory tree.
    /// With it, it is the directory the manifest describes or "-" for the
    /// file contents on standard input; [`Sourcing::Size`] takes none, the
    /// manifest carries the sizes. `--path` is for trees only. The SOURCE
    /// arguments and `--path` are checked before anything is opened. The
    /// manifest is opened last, for what `sourcing` does with it, and its
    /// root file object is read.
    fn open(args: &Args, paths: &[&Path], sourcing: Sourcing) -> Result<Source> {
        let Some(m) = args.path("manifest") else {
            return match paths {
                [] => Ok(Source::None),
                [path] => {
                    let dir = host::open_dir(path).map_err(|e| {
                        if e.errno() == errno::ENOTDIR {
                            e.context("a SOURCE is a directory tree; --manifest PATH names a manifest")
                        } else {
                            e
                        }
                    })?;
                    Ok(Source::Tree {
                        path: path.to_path_buf(),
                        dir,
                    })
                }
                _ => bail!(
                    errno::EINVAL,
                    "only one directory tree can be given; --manifest PATH names a manifest"
                ),
            };
        };
        if m == Path::new("-") && sourcing != Sourcing::Size && matches!(paths, [p] if *p == Path::new("-")) {
            bail!(
                errno::EINVAL,
                "--manifest - and a SOURCE of - cannot both read standard input"
            );
        }
        if dest(args) != "/" {
            bail!(
                errno::EINVAL,
                "--path applies to directory trees; a manifest names its paths from the root"
            );
        }
        let contents = match (sourcing, paths) {
            (Sourcing::Size, []) => None,
            (Sourcing::Size, _) => bail!(
                errno::EINVAL,
                "--manifest carries the sizes, no SOURCE or --fit directory is taken with it"
            ),
            (Sourcing::Write(_), [path]) if *path == Path::new("-") => Some(ContentOrigin::Stdin),
            (Sourcing::Write(_), [path]) => Some(ContentOrigin::Directory {
                path: path.to_path_buf(),
                dir: host::open_dir(path)?,
            }),
            (Sourcing::Write(_), _) => bail!(
                errno::EINVAL,
                "--manifest takes exactly one SOURCE: the directory the manifest describes, or - for the file contents on standard input"
            ),
        };
        let (manifest, name) = read_manifest(m, sourcing.manifest_use())?;
        Ok(Source::Manifest {
            name,
            manifest: Box::new(manifest),
            contents,
        })
    }

    /// What can be checked before an image is created, formatted or
    /// written: under `--unsupported fail`, that the tree can be stored. A
    /// manifest is checked as it is written.
    fn check(&self, args: &Args) -> Result<()> {
        match self {
            Source::Tree { .. } if fail_unsupported(args)? => {
                self.add_to(&mut Plan::new(PlanOptions::new(MIN_SECTOR_SIZE)), args)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Adds the source to a plan, the way [`Source::fill`] writes it, and
    /// returns how many objects of a manifest are left out. Under
    /// `--unsupported fail` what FAT cannot store of a tree fails the plan.
    /// The plan reads the manifest once more from its start, so its content
    /// can be written after.
    fn add_to(&self, plan: &mut Plan, args: &Args) -> Result<u64> {
        match self {
            Source::None => Ok(0),
            Source::Tree { path, dir } => {
                let skipped = plan.add_tree(dir.as_fd(), dest(args), &copy_options(args)?)?;
                if let (Some(skipped), true) = (skipped.first(), fail_unsupported(args)?) {
                    bail!(
                        errno::EINVAL,
                        "{} cannot be stored on FAT",
                        path.join(skipped).display()
                    );
                }
                Ok(0)
            }
            Source::Manifest { name, manifest, .. } => plan
                .add_records(&mut manifest.plan_reader()?, assemble_flags(args)?)
                .map_err(about_manifest(name)),
        }
    }

    /// Adds the source to a plan when nothing is written after it, and
    /// returns how many objects of a manifest are left out. The manifest is
    /// read on from its root file object, so it is read once.
    fn into_plan(self, plan: &mut Plan, args: &Args) -> Result<u64> {
        match self {
            Source::Manifest { name, mut manifest, .. } => plan
                .add_records(manifest.reader(), assemble_flags(args)?)
                .map_err(about_manifest(&name)),
            source => source.add_to(plan, args),
        }
    }

    /// Writes the source into an open volume: the tree copied, or the
    /// manifest assembled while it is read, which takes the contents of its
    /// files.
    fn fill(&mut self, volume: &mut Volume, args: &Args) -> Result<()> {
        let copy = copy_options(args)?;
        match self {
            Source::None => {}
            Source::Tree { path, dir } => {
                let report = volume.copy_tree(dir.as_fd(), dest(args), &copy)?;
                if args.flag("verbose") {
                    eprintln!(
                        "{}: {}",
                        path.display(),
                        contents(report.files, report.directories, report.bytes)
                    );
                }
                for skipped in report.skipped {
                    eprintln!(
                        "ufat: skipped {}: not a regular file or directory",
                        path.join(skipped).display()
                    );
                }
            }
            Source::Manifest {
                name,
                manifest,
                contents: origin,
            } => {
                let options = assemble_options(args)?;
                let reader = manifest.reader();
                let report = match origin.take() {
                    Some(ContentOrigin::Stdin) => {
                        let stdin = std::io::stdin();
                        let mut lock = stdin.lock();
                        let mut source = StreamSource::new(&mut lock);
                        volume.assemble_with_observer(reader, &mut source, &options, &mut SkipNotes)
                    }
                    Some(ContentOrigin::Directory { path, dir }) => {
                        let mut source = DirectorySource::new(PinnedDirectory::new(dir).follow_symlinks(true));
                        volume
                            .assemble_with_observer(reader, &mut source, &options, &mut SkipNotes)
                            .map_err(about_source_directory(&path))
                    }
                    None => bail!(errno::EINVAL, "a manifest needs a SOURCE to be filled from"),
                }
                .map_err(about_manifest(name))?;
                if args.flag("verbose") {
                    eprintln!("{}: {}", name, contents(report.files, report.directories, report.bytes));
                }
            }
        }
        Ok(())
    }
}

/// Says what an assembly leaves out, on standard error.
struct SkipNotes;

impl AssembleObserver for SkipNotes {
    fn skipped(&mut self, name: &Name, reason: SkipReason) {
        match reason {
            SkipReason::Unsupported => eprintln!("ufat: skipped {}: it cannot be stored on FAT", name),
            _ => eprintln!("ufat: skipped {}: the directory it is in was skipped", name),
        }
    }
}

/// What a copy does with a name the volume holds already: it takes what is
/// there with `--replace` and fails without.
fn name_collision(args: &Args) -> NameCollision {
    if args.flag("replace") {
        NameCollision::Replace
    } else {
        NameCollision::Fail
    }
}

/// How the command line asks a copy of a tree, and the plan of one, to
/// take it: following symbolic links, and replacing what is there with
/// `--replace`.
fn copy_options(args: &Args) -> Result<CopyOptions> {
    Ok(CopyOptions {
        times: time_policy(args)?,
        name_collision: name_collision(args),
        follow_symlinks: true,
    })
}

/// How the command line asks an assembly, and the plan of one, to store a
/// manifest's objects: replacing what is there with `--replace`, and
/// leaving out what FAT cannot store unless `--unsupported fail`.
fn assemble_flags(args: &Args) -> Result<AssembleFlags> {
    Ok(AssembleFlags::NONE
        .with(AssembleFlags::REPLACE, args.flag("replace"))
        .with(AssembleFlags::SKIP_UNSUPPORTED, !fail_unsupported(args)?))
}

/// What the command line asks of an assembly.
fn assemble_options(args: &Args) -> Result<AssembleOptions> {
    let (time, _) = stamp_time(args)?;
    Ok(AssembleOptions {
        default_time: time,
        flags: assemble_flags(args)?,
        now_usec: if args.flag("no-check-validity") {
            None
        } else {
            Some(fat::time::to_usec(util::now()))
        },
    })
}

/// Names the manifest `name` in an error that is about it.
fn about_manifest(name: &str) -> impl Fn(Error) -> Error + '_ {
    move |e| if e.is_manifest() { e.context(name) } else { e }
}

/// Names the directory `path`, where the contents of a manifest's files
/// are looked up, in an error about one of its files: one that is missing
/// or not a regular file, or whose contents are not what the manifest says.
fn about_source_directory(path: &Path) -> impl Fn(Error) -> Error + '_ {
    move |e| match e.detail() {
        Some(Detail::Source { .. } | Detail::Content { .. }) => e.context(path.display()),
        _ => e,
    }
}

/// Whether `--write-manifest -` puts the manifest on standard output. What
/// the command prints there otherwise goes to standard error then.
fn manifest_to_stdout(args: &Args) -> bool {
    args.path("write-manifest") == Some(Path::new("-"))
}

/// Writes the UAPI.16 manifest of everything `v` holds to the file `path`,
/// or to standard output for "-", for `--write-manifest`.
fn write_manifest(v: &Volume, path: &Path) -> Result<()> {
    if path == Path::new("-") {
        write_manifest_to(v, std::io::stdout().lock(), STDOUT_MANIFEST)
    } else {
        let file = std::fs::File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
        write_manifest_to(v, file, &path.display().to_string())
    }
}

/// Writes the UAPI.16 manifest of everything `v` holds to `out`, which the
/// messages call `shown`.
fn write_manifest_to(v: &Volume, out: impl Write, shown: &str) -> Result<()> {
    let report = v.write_manifest(v.root_time()?, Features::DEFAULT, std::io::BufWriter::new(out))?;
    warn_about_manifest(&report, shown);
    Ok(())
}

/// How the messages name a manifest written to standard output.
const STDOUT_MANIFEST: &str = "the manifest on standard output";

/// Says how many entries the manifest `shown`, of which `report` is what
/// it covers, leaves out, and how many files changed while they were read
/// for it.
fn warn_about_manifest(report: &WriteReport, shown: &str) {
    match report.omitted {
        0 => {}
        1 => eprintln!(
            "ufat: 1 entry is not in {}: its name cannot be written in a manifest",
            shown
        ),
        n => eprintln!(
            "ufat: {} entries are not in {}: their names cannot be written in a manifest",
            n, shown
        ),
    }
    match report.changed {
        0 => {}
        1 => eprintln!(
            "ufat: 1 file changed while it was read: {} has the size and the hash of what was read",
            shown
        ),
        n => eprintln!(
            "ufat: {} files changed while they were read: {} has the sizes and the hashes of what was read",
            n, shown
        ),
    }
}

/// Reports the geometry of a freshly made file system.
fn report_layout(image: &Path, layout: &fat::layout::Layout, verbose: bool) {
    if verbose {
        eprintln!(
            "{}: {} sectors of {} bytes, {} clusters of {} bytes, {} reserved sectors, {} of {} sectors",
            image.display(),
            layout.total_sectors,
            layout.sector_size,
            layout.clusters,
            layout.cluster_size(),
            layout.reserved_sectors,
            plural(u64::from(layout.fats), "FAT", "FATs"),
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

/// `assemble --plan`: the size the content needs, with nothing written. It
/// answers for `assemble` with the same options. With `--size` and without
/// `--minimize` that makes a file system of that size, so the content is
/// planned with the cluster size the formatter picks for it and has to fit
/// its clusters. Otherwise the plan is of the smallest file system, which
/// with `--minimize` has to fit in `--size`.
fn plan(args: &Args) -> Result<()> {
    if args.positional.is_empty() && args.path("manifest").is_none() {
        bail!(errno::EINVAL, "assemble --plan needs a SOURCE or --manifest");
    }
    let options = format_options(args)?;
    let mut plan_options = PlanOptions::from_format_options(&options, None)?;
    let size = args.size("size")?;
    let given = match size {
        Some(size) if !args.flag("minimize") => Some(GivenSize::new(&options, size, None)?),
        _ => None,
    };
    if let Some(given) = &given {
        plan_options.cluster_size = Some(given.layout.cluster_size());
    }
    let mut plan = Plan::new(plan_options);
    // Nothing is written after a plan, so it reads the manifest on from its
    // root file object, and the manifest is read once. A pipe will do.
    let source = Source::open(args, &args.positional_paths(), Sourcing::Size)?;
    let skipped = source.into_plan(&mut plan, args)?;
    if skipped > 0 {
        eprintln!(
            "ufat: not counted: {}",
            plural(skipped, "object FAT cannot store", "objects FAT cannot store")
        );
    }
    let e = plan.estimate()?;
    match (&given, size) {
        (Some(given), _) => given
            .check(&e)
            .map_err(|shortfall| err!(errno::ENOSPC, "{}", shortfall))?,
        (None, Some(size)) if e.size() > size => bail!(
            errno::ENOSPC,
            "the content needs a {} byte file system, more than --size {}",
            e.size(),
            size
        ),
        _ => {}
    }
    println!("{}", e.size());
    if args.flag("verbose") {
        eprintln!(
            "{}: {} of {} bytes, {} byte sectors",
            contents(e.files, e.directories, e.bytes),
            plural(u64::from(e.data_clusters), "cluster", "clusters"),
            e.layout.cluster_size(),
            e.layout.sector_size
        );
    }
    Ok(())
}

/// `assemble` without a SOURCE: an empty file system of the size of
/// `--size` or of the image, or with `--minimize` the smallest one. The
/// `--fit` directory or what `--manifest` describes has to fit a size
/// given, and without one the file system is the smallest that holds it.
fn assemble_empty(args: &Args, path: &Path) -> std::result::Result<NewVolume, Failure> {
    let mut options = format_options(args)?;
    let fit = args.paths("fit");
    let target = util::Target {
        path,
        offset: args.size("offset")?.unwrap_or(0),
        size: args.size("size")?,
        flags: args.image_flags(),
    };
    // Nothing of the content is written, so a manifest is planned on from
    // its root file object, through the reader that read it, and is read
    // once: a pipe will do. fit_and_format() plans the content at most once.
    let source = Source::open(args, &fit, Sourcing::Size)?;
    let mode = if args.flag("minimize") {
        SizeMode::Minimize
    } else if matches!(source, Source::None) {
        SizeMode::Given
    } else {
        SizeMode::Fit
    };
    let mut source = Some(source);
    let mut add = |plan: &mut Plan| match source.take() {
        Some(source) => source.into_plan(plan, args).map(drop),
        None => bail!(errno::EINVAL, "the content is planned once"),
    };
    let (new, estimate) = util::fit_and_format(&target, &mut options, SizeRequest::new(mode, &mut add))?;
    if let Some(estimate) = estimate {
        report_estimate(args, path, &estimate);
    }
    Ok(new)
}

/// `assemble` with a SOURCE: the file system of the size of `--size` or of
/// the image, or with `--minimize` the smallest that holds it, filled with
/// it.
fn assemble_filled(args: &Args, path: &Path, paths: &[&Path]) -> std::result::Result<NewVolume, Failure> {
    if !args.paths("fit").is_empty() {
        return Err(err!(
            errno::EINVAL,
            "--fit sizes an empty file system; with a SOURCE --minimize sizes it for the SOURCE"
        )
        .into());
    }
    let mode = if args.flag("minimize") {
        SizeMode::Minimize
    } else {
        SizeMode::Given
    };
    let mut source = Source::open(args, paths, Sourcing::Write(mode.manifest_use()))?;
    // Better to learn about a tree FAT cannot hold before an image is sized
    // and formatted. With --minimize the plan finds it.
    if mode == SizeMode::Given {
        source.check(args)?;
    }
    let mut options = format_options(args)?;
    let target = util::Target {
        path,
        offset: args.size("offset")?.unwrap_or(0),
        size: args.size("size")?,
        flags: args.image_flags(),
    };
    let mut add = |plan: &mut Plan| source.add_to(plan, args).map(drop);
    let (mut new, estimate) = util::fit_and_format(&target, &mut options, SizeRequest::new(mode, &mut add))?;
    if let Some(estimate) = estimate {
        report_estimate(args, path, &estimate);
    }
    if let Err(e) = source.fill(new.volume_mut(), args) {
        let leftovers = new.abandon();
        return Err(Failure::new(e, leftovers));
    }
    Ok(new)
}

fn report_estimate(args: &Args, path: &Path, estimate: &fat::plan::Estimate) {
    if args.flag("verbose") {
        eprintln!(
            "{}: {} and {} in {} need a {} byte file system with {} byte clusters",
            path.display(),
            plural(estimate.files, "file", "files"),
            plural(estimate.directories, "directory", "directories"),
            plural(estimate.bytes, "byte", "bytes"),
            estimate.size(),
            estimate.layout.cluster_size()
        );
    }
}

/// Says how to format an image that holds something anyway.
fn force_hint(e: Error) -> Error {
    match e.detail() {
        Some(detail @ Detail::NotEmpty { .. }) => {
            Error::new(e.errno(), format!("{}, use --force to format it anyway", e.message())).with(detail.clone())
        }
        _ => e,
    }
}

fn cmd_assemble(argv: &[OsString]) -> std::result::Result<(), Failure> {
    let args = Args::parse(
        argv,
        &with(
            FORMAT_VALUES,
            &with(IMAGE_OPTIONS, &with(FILL_VALUES, &["fit", "hash", "write-hash"])),
        ),
        &with(FORMAT_FLAGS, &with(FILL_FLAGS, &["plan"])),
    )?;
    // Bad values fail here, whatever the command goes on to do. What uses
    // them takes them from args again.
    fail_unsupported(&args)?;
    time_policy(&args)?;
    if args.flag("plan") {
        return Ok(plan(&args)?);
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
        return Err(err!(errno::EINVAL, "--write-hash needs --hash").into());
    }
    if hash_path == Some(Path::new("-")) && manifest_to_stdout(&args) {
        return Err(err!(
            errno::EINVAL,
            "--write-manifest - and --write-hash - cannot both write to standard output"
        )
        .into());
    }
    let (path, paths) = match args.positional_paths().split_first() {
        Some((&i, s)) => (i, s.to_vec()),
        None => return Err(err!(errno::EINVAL, "assemble takes an IMAGE and a SOURCE").into()),
    };
    let mut new = if paths.is_empty() {
        assemble_empty(&args, path)
    } else {
        assemble_filled(&args, path, &paths)
    }
    .map_err(|failure| Failure::new(force_hint(failure.error), failure.leftovers))?;
    // The image and the files written next to it get their names only once
    // everything else succeeded, the hash of the file system included, so
    // a failure before leaves none of them behind.
    let digest = match write_outputs(&args, path, &mut new, hash, hash_path) {
        Ok(digest) => digest,
        Err(e) => {
            let leftovers = new.abandon();
            return Err(Failure::new(e, leftovers));
        }
    };
    let leftovers = new.link()?;
    for line in leftovers.lines() {
        eprintln!("ufat: {}", line);
    }
    // Unlike a manifest, which streams, the hash is complete before the
    // image gets its name, and printed only once it has it.
    match digest {
        Some(digest) if manifest_to_stdout(&args) => eprintln!("{}", digest),
        Some(digest) => writeln!(std::io::stdout().lock(), "{}", digest).with_context(|| "cannot write the hash")?,
        None => {}
    }
    Ok(())
}

/// Writes what `assemble` writes about the file system it made in the
/// image `path`: the manifest of `--write-manifest`, and the hash of
/// `--hash`, which is taken through the descriptor the file system was
/// written through, once it is synced. Returns the hash where it is printed
/// rather than written to `--write-hash`.
fn write_outputs(
    args: &Args,
    path: &Path,
    new: &mut NewVolume,
    hash: Option<service::Hash>,
    hash_path: Option<&Path>,
) -> Result<Option<String>> {
    match args.path("write-manifest") {
        Some(m) if m != Path::new("-") => {
            let out = new
                .output(m)
                .with_context(|| format!("cannot create {}", m.display()))?;
            write_manifest_to(new.volume(), out, &m.display().to_string())?;
        }
        Some(m) => write_manifest(new.volume(), m)?,
        None => {}
    }
    report_layout(path, new.volume().layout(), args.flag("verbose"));
    let Some(hash) = hash else {
        return Ok(None);
    };
    // The device of the volume covers the file system's own bytes, which
    // with --minimize can end before --size does.
    new.volume_mut().sync()?;
    let digest = hash.of(new.volume().device(), &mut |_| {})?;
    match hash_path {
        Some(p) if p != Path::new("-") => {
            let cannot = || format!("cannot write {}", p.display());
            let mut out = new.output(p).with_context(cannot)?;
            writeln!(out, "{}", digest).with_context(cannot)?;
            Ok(None)
        }
        _ => Ok(Some(digest)),
    }
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
    // Bad values fail here, whatever the command goes on to do. What uses
    // them takes them from args again.
    fail_unsupported(&args)?;
    time_policy(&args)?;
    let (image, paths) = match args.positional_paths().split_first() {
        Some((&i, s)) => (i, s.to_vec()),
        None => bail!(errno::EINVAL, "populate takes an IMAGE and a SOURCE"),
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
            name_collision: name_collision(&args),
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
    let mut source = Source::open(&args, &paths, Sourcing::Write(ManifestUse::Write))?;
    source.check(&args)?;
    let mut v = open_volume(&args, image, Access::ReadWrite)?;
    if matches!(source, Source::Tree { .. }) {
        ensure_dir(&mut v, path, parents, time)?;
    }
    if let Err(e) = source.fill(&mut v, &args) {
        // Once something was written, the file system is left marked as not
        // cleanly unmounted, as after a crash, with what was complete. A
        // SOURCE refused before that, such as a manifest refused at its
        // first object, leaves it as it was. An error of the close is not
        // the one the user needs to hear about.
        if v.is_writing() {
            let _ = v.close_unfinished();
        }
        return Err(e);
    }
    if let Some(m) = args.path("write-manifest") {
        write_manifest(&v, m)?;
    }
    v.close()
}

fn cmd_remove(argv: &[OsString]) -> Result<()> {
    let args = Args::parse(argv, IMAGE_OPTIONS, &["recursive", "verbose"])?;
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
        let (files, directories) = if !md.is_dir {
            v.remove_file(path)?;
            (1, 0)
        } else if args.flag("recursive") {
            let report = v.remove_tree(path)?;
            (report.files, report.directories)
        } else {
            v.remove_dir(path)?;
            (0, 1)
        };
        if args.flag("verbose") {
            eprintln!(
                "{}: {}, {}",
                path,
                plural(files, "file", "files"),
                plural(directories, "directory", "directories")
            );
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
            fat::layout::MIN_CLUSTERS
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
        println!(
            "... and {} not shown",
            plural(report.dropped as u64, "more problem", "more problems")
        );
    }
    println!(
        "{}: {}, {}, {} used, {} free, {} lost; {}, {}",
        image.display(),
        plural(report.files, "file", "files"),
        plural(report.directories, "directory", "directories"),
        plural(u64::from(report.used_clusters), "cluster", "clusters"),
        report.free_clusters,
        report.lost_clusters,
        plural(report.errors() as u64, "error", "errors"),
        plural(report.warnings() as u64, "warning", "warnings")
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
    // A manifest is complete with its trailer. What is printed of a tree
    // that cannot be listed to its end has none, and the exit status says
    // that it failed.
    let out = std::io::BufWriter::new(std::io::stdout().lock());
    let report = HostTree::new(dir.as_fd()).write_manifest(out)?;
    warn_about_manifest(&report, STDOUT_MANIFEST);
    Ok(())
}

fn run(argv: &[OsString]) -> std::result::Result<ExitCode, Failure> {
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
    if matches!(command, "version" | "--version") {
        println!("ufat {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    let rest = &argv[1..];
    match command {
        "assemble" => cmd_assemble(rest)?,
        "populate" => cmd_populate(rest)?,
        "remove" => cmd_remove(rest)?,
        "list" => cmd_list(rest)?,
        "describe" => cmd_describe(rest)?,
        "check" => return Ok(cmd_check(rest)?),
        "capabilities" => cmd_capabilities(rest)?,
        "cat" => cmd_cat(rest)?,
        "manifest" => cmd_manifest(rest)?,
        other => return Err(err!(errno::EINVAL, "unknown command '{}'", other).into()),
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
        Err(failure) => {
            // What failed, then what that left behind.
            eprintln!("ufat: {}", failure.error);
            for line in failure.leftovers.lines() {
                eprintln!("ufat: {}", line);
            }
            ExitCode::FAILURE
        }
    }
}
