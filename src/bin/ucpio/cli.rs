// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line interface.

use std::ffi::OsString;
use std::fs::File;
use std::io::Write;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::SystemTime;

use ::cli::{format_time, plural, source_date_epoch, time_from_secs, Args};
use cpio::assemble::Report;
use cpio::check::{self, Severity};
use cpio::device::{Access, Device};
use cpio::errno;
use cpio::header::{Format, Kind};
use cpio::host;
use cpio::image::Region;
use cpio::manifest::{Described, Fields, Manifest, SourceDirectory};
use cpio::name::{Name, NameBuf};
use cpio::plan::Plan;
use cpio::populate;
use cpio::read::{self, End, Source as _};
use cpio::times::TimePolicy;
use cpio::tree::{Inode, RootStated, Tree};
use cpio::write;
use cpio::{bail, err, Context, Detail, Result};
use shared::hash::Hash;
use shared::manifest::{read_all, MAX_MANIFEST_BYTES};
use shared::times::{now, to_usec};

use crate::ops::{Addition, How, Source};
use crate::service::FileSystemService;

/// The id that stands for no id where ids are 32 bits wide, as chown(2)
/// takes it. No file can have it.
const INVALID_ID: u32 = u32::MAX;
/// The same from when ids were 16 bits wide.
const INVALID_ID_16: u32 = u16::MAX as u32;
/// Size of the buffer cat copies a file through.
const CAT_BUFFER: usize = 1024 * 1024;

const USAGE: &str = "\
Usage: ucpio COMMAND [OPTIONS...] ARGS...

Commands:
  assemble [OPTIONS] IMAGE [SOURCE...]   Create a cpio archive of the sources
  assemble --plan [OPTIONS] [SOURCE...]  Print the size of the archive of the
                                         sources
  populate [OPTIONS] IMAGE [SOURCE...]   Add to an existing cpio archive
  list [-l] IMAGE [PATH]                 List a directory
  describe [OPTIONS] IMAGE               Show what an archive holds
  check IMAGE                            Check an archive
  capabilities                           Print what ucpio supports, as JSON
  cat IMAGE PATH                         Print a file

The commands are the methods of the org.uapi-group.FileSystem Varlink
interface that ucpio serves; cat has no method.

An archive is in the new ASCII format, the one the kernel unpacks an
initramfs from. It is one archive and it is not compressed.

assemble without a SOURCE creates an archive without entries. populate puts
a SOURCE directory below --path and a SOURCE file at --path. Without a SOURCE
it creates the directory --path. An entry that is added takes the place of
one of the same name when the archive is unpacked.

A SOURCE is a directory tree, or for populate one file. With --manifest the
one SOURCE is the tree the manifest describes, where its file contents are
read, or - for the contents on standard input, back to back in manifest order:
  --manifest PATH       Build what the UAPI.16 manifest at PATH describes
  --no-check-validity   Accept revoked and expired manifest entries

Options common to commands taking IMAGE:
  --offset BYTES        Byte offset of the archive inside IMAGE
  --size BYTES          Size of the room for the archive inside IMAGE (by
                        default IMAGE is grown to hold the archive)

Options for assemble:
  --plan                Print the size the archive needs and write nothing
  --checksums           Write the form with checksums (070702)
  --no-root-entry       Write no entry for the root directory
  --hash ALGORITHM      Print the sha256 or sha512 hash of what was written

Options for assemble and populate:
  --end-alignment BYTES   Pad the end of the archive to a multiple of BYTES
                          (default 512, a multiple of 4)
  --data-alignment BYTES  Start the contents of files of at least BYTES bytes
                          at a multiple of BYTES (a power of two)
  --timestamp SECONDS   Time to stamp, default $SOURCE_DATE_EPOCH, else now;
                        for a manifest the time of entries that carry none
  --times POLICY        preserve (default), fixed or clamp (clamp is the default
                        when $SOURCE_DATE_EPOCH is set)
  --uid UID, --gid GID  Store every entry with this owner
  --no-replace          Fail on files that exist instead of replacing them
  --path PATH           The directory a SOURCE tree goes below (default /), the
                        path of a SOURCE file, or the directory to create
  --parents, -p         Create missing parent directories of --path, and
                        accept a directory that exists (populate)
  --write-manifest PATH Write the UAPI.16 manifest of the archive to PATH
                        afterwards (also describe)
  --verbose             Report what was written

Sizes take K, M, G and T suffixes. Timestamps are seconds since the epoch.
Exit status: 0 on success, 1 on failure. check uses the fsck(8) codes: 0 for
an archive without errors (warnings do not count), 4 when errors were found,
8 when the image could not be checked.
";

/// Options whose value is a path on the host, which can be any bytes. The
/// values of all other options are UTF-8.
const PATH_OPTIONS: &[&str] = &["manifest", "write-manifest"];
const IMAGE_OPTIONS: &[&str] = &["offset", "size"];
const FILL_VALUES: &[&str] = &[
    "end-alignment",
    "data-alignment",
    "timestamp",
    "times",
    "uid",
    "gid",
    "path",
    "manifest",
    "write-manifest",
];
const FILL_FLAGS: &[&str] = &["no-replace", "no-check-validity", "parents", "verbose"];

/// The fsck(8) exit codes, as systemd-fsck and fsck(8) read them
/// (systemd's src/shared/fsck-util.h). The check changes nothing, so the
/// errors it finds are always left uncorrected.
const FSCK_ERRORS_LEFT_UNCORRECTED: u8 = 4;
const FSCK_OPERATIONAL_ERROR: u8 = 8;

/// The archive at IMAGE, read.
struct Opened {
    device: Device,
    offset: u64,
    size: Option<u64>,
}

impl Opened {
    fn region(&self) -> Result<Region<'_>> {
        Region::new(&self.device, self.offset, self.size)
    }
}

/// One line of a listing.
struct Line<'a> {
    name: &'a [u8],
    inode: &'a Inode,
}

impl Line<'_> {
    /// The letter `ls -l` has for what the entry is.
    fn letter(&self) -> char {
        match self.inode.kind {
            Kind::Regular => '-',
            Kind::Directory => 'd',
            Kind::Symlink => 'l',
            Kind::CharDevice => 'c',
            Kind::BlockDevice => 'b',
            Kind::Fifo => 'p',
            Kind::Socket => 's',
        }
    }

    /// Writes the line to `out`: the name, and with `long` what the entry
    /// is. `region` is the archive, the target of a symbolic link is read
    /// from it.
    fn write(&self, out: &mut dyn Write, region: &Region<'_>, long: bool) -> Result<()> {
        let inode = self.inode;
        let shown = String::from_utf8_lossy(self.name);
        if !long {
            writeln!(out, "{}", shown)?;
            return Ok(());
        }
        let size = if inode.kind.is_device() {
            format!("{},{}", inode.rdev.major, inode.rdev.minor)
        } else {
            inode.size.to_string()
        };
        // The names of a directory are not counted.
        let names = if inode.kind == Kind::Directory {
            "-".to_string()
        } else {
            inode.nlink.to_string()
        };
        let mut line = format!(
            "{}{:04o} {:>2} {:>5} {:>5} {:>10} {} {}",
            self.letter(),
            inode.mode,
            names,
            inode.uid,
            inode.gid,
            size,
            format_time(inode.modified()),
            shown
        );
        if inode.kind == Kind::Directory {
            line.push('/');
        }
        if inode.kind == Kind::Symlink {
            let mut target = vec![0u8; inode.size as usize];
            region.read_at(inode.data_offset, &mut target)?;
            line.push_str(" -> ");
            line.push_str(&String::from_utf8_lossy(&target));
        }
        writeln!(out, "{}", line)?;
        Ok(())
    }
}

/// The command line of one command.
struct Given(Args);

impl Deref for Given {
    type Target = Args;

    fn deref(&self) -> &Args {
        &self.0
    }
}

impl Given {
    /// Parses `argv` for a command that takes the options `with_value`,
    /// each with a value, and the flags `flags`.
    fn parse(argv: &[OsString], with_value: &[&[&str]], flags: &[&[&str]]) -> Result<Given> {
        Args::parse(argv, &with_value.concat(), &flags.concat(), PATH_OPTIONS, USAGE).map(Given)
    }

    /// The time to stamp: --timestamp, SOURCE_DATE_EPOCH, or now. And
    /// whether it was given, which asks for the same archive every time.
    fn stamp_time(&self) -> Result<(SystemTime, bool)> {
        if let Some(t) = self.value("timestamp") {
            return Ok((time_from_secs(t, "timestamp")?, true));
        }
        if let Some(t) = source_date_epoch()? {
            return Ok((t, true));
        }
        Ok((now(), false))
    }

    /// The user or the group the option `name` gives.
    fn id(&self, name: &str) -> Result<Option<u32>> {
        let Some(text) = self.value(name) else {
            return Ok(None);
        };
        match text.parse::<u32>() {
            Ok(id) if id != INVALID_ID && id != INVALID_ID_16 => Ok(Some(id)),
            _ => bail!(errno::EINVAL, "invalid --{} '{}'", name, text),
        }
    }

    /// How the sources become entries, as the options say.
    fn how(&self) -> Result<How> {
        let (time, reproducible) = self.stamp_time()?;
        let times = match self.value("times") {
            Some("preserve") => TimePolicy::Preserve,
            Some("fixed") => TimePolicy::Fixed(time),
            Some("clamp") => TimePolicy::Clamp(time),
            Some(other) => bail!(errno::EINVAL, "unknown time policy '{}'", other),
            None if reproducible => TimePolicy::Clamp(time),
            None => TimePolicy::Preserve,
        };
        Ok(How {
            times,
            time,
            uid: self.id("uid")?,
            gid: self.id("gid")?,
            replace: !self.flag("no-replace"),
            now_usec: (!self.flag("no-check-validity")).then(|| to_usec(now())),
        })
    }

    /// The alignment the option `name` gives, or `default`.
    fn alignment(&self, name: &str, default: u32) -> Result<u32> {
        Ok(self.u32(name)?.unwrap_or(default))
    }

    /// The layout of an archive that is made, as the options say.
    fn layout(&self) -> Result<write::Options> {
        let options = write::Options {
            format: if self.flag("checksums") {
                Format::Crc
            } else {
                Format::Newc
            },
            end_alignment: self.alignment("end-alignment", write::DEFAULT_END_ALIGNMENT)?,
            data_alignment: self.alignment("data-alignment", 0)?,
        };
        options.check()?;
        Ok(options)
    }

    /// Where in the archive the sources go: --path, or the root.
    fn dest(&self) -> Result<NameBuf> {
        match self.last("path") {
            Some(path) => NameBuf::from_path(path.as_bytes()),
            None => Ok(NameBuf::from(Name::ROOT)),
        }
    }

    /// The part of the image the archive is in: --offset and --size.
    fn window(&self) -> Result<(u64, Option<u64>)> {
        Ok((self.size("offset")?.unwrap_or(0), self.size("size")?))
    }

    /// The archive at `image`, to read.
    fn open(&self, image: &Path) -> Result<Opened> {
        let (offset, size) = self.window()?;
        Ok(Opened {
            device: Device::open(image, Access::ReadOnly)?,
            offset,
            size,
        })
    }

    /// The one IMAGE the command `command` takes.
    fn image(&self, command: &str) -> Result<&Path> {
        match self.positional.as_slice() {
            [image] => Ok(Path::new(image)),
            _ => bail!(errno::EINVAL, "{} takes exactly one IMAGE", command),
        }
    }

    /// The sources at `paths`, opened: with --manifest what the manifest
    /// describes, with the files in the one directory or on standard
    /// input. `populate` takes a single file as well.
    fn sources(&self, paths: &[&Path], populate: bool) -> Result<Vec<Source>> {
        if let Some(path) = self.path("manifest") {
            let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
            let text = read_all(file, MAX_MANIFEST_BYTES)
                .with_context(|| format!("cannot read the manifest {}", path.display()))?;
            let manifest = Manifest::parse(&text).map_err(|e| cpio::Error::from(e).context(path.display()))?;
            let described = match paths {
                [source] if source.as_os_str() == "-" => Described::in_stream(manifest, std::io::stdin()),
                [source] => {
                    let directory = SourceDirectory::new(host::open_dir(source)?).follow_symlinks(true);
                    Described::in_directory(manifest, directory)?
                }
                _ => bail!(
                    errno::EINVAL,
                    "--manifest takes one SOURCE: the directory the files are in, or - for their contents on standard input"
                ),
            };
            return Ok(vec![Source::Manifest(Box::new(described))]);
        }
        let mut sources = Vec::new();
        for path in paths {
            let md = std::fs::metadata(path).with_context(|| format!("cannot open {}", path.display()))?;
            if md.is_dir() {
                sources.push(Source::Tree(host::open_dir(path)?));
            } else if populate && paths.len() == 1 {
                sources.push(Source::File(host::open_file(path)?));
            } else if populate {
                bail!(
                    errno::EINVAL,
                    "{} is a file: populate takes one file at a time",
                    path.display()
                );
            } else {
                bail!(errno::ENOTDIR, "{} is not a directory", path.display());
            }
        }
        Ok(sources)
    }

    /// Says what was written to `image`, for --verbose.
    fn report_written(&self, image: &Path, report: &Report) {
        if self.flag("verbose") {
            eprintln!(
                "{}: {} and {} with {} of contents, the archive is {}",
                image.display(),
                plural(report.files, "file", "files"),
                plural(report.directories, "directory", "directories"),
                plural(report.bytes, "byte", "bytes"),
                plural(report.len, "byte", "bytes")
            );
        }
    }

    /// Writes the manifest of `archive` where --write-manifest says, when
    /// it was given. `tree` is what the archive unpacks to, when the
    /// caller has worked that out already.
    fn write_manifest<S: read::Source + ?Sized>(&self, archive: &S, tree: Option<&Tree>) -> Result<()> {
        let Some(path) = self.path("write-manifest") else {
            return Ok(());
        };
        let opened;
        let tree = match tree {
            Some(tree) => tree,
            None => {
                opened = Tree::open(archive)?;
                &opened
            }
        };
        let file = File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
        let mut out = std::io::BufWriter::new(file);
        let report = tree.write_manifest(archive, Fields::default(), &mut out, &mut |_| {})?;
        match report.omitted {
            0 => {}
            1 => eprintln!(
                "ucpio: 1 entry is not in {}: its name cannot be written in a manifest",
                path.display()
            ),
            n => eprintln!(
                "ucpio: {} entries are not in {}: their names cannot be written in a manifest",
                n,
                path.display()
            ),
        }
        Ok(())
    }

    fn assemble(&self) -> Result<()> {
        let plan_only = self.flag("plan");
        let positional = self.positional_paths();
        let (image, paths) = match (plan_only, positional.split_first()) {
            (true, _) => (None, positional.clone()),
            (false, Some((&image, paths))) => (Some(image), paths.to_vec()),
            (false, None) => bail!(errno::EINVAL, "assemble takes an IMAGE and SOURCE arguments"),
        };
        let hash = match self.value("hash") {
            None => None,
            Some(a) => Some(
                Hash::new(a).ok_or_else(|| err!(errno::EINVAL, "unknown hash algorithm '{}', sha256 or sha512", a))?,
            ),
        };
        let how = self.how()?;
        let layout = self.layout()?;
        let dest = self.dest()?;
        let dest = dest.as_name();
        let sources = self.sources(&paths, false)?;
        let mut plan = Plan::new();
        if !self.flag("no-root-entry") {
            plan.add_directory(Name::ROOT, how.root_attributes(&sources)?)?;
        }
        // The directories that lead to where the sources go, and that one
        // itself.
        let itself = Some(dest).filter(|dest| !dest.is_root());
        let leading: Vec<Name<'_>> = itself.into_iter().chain(dest.ancestors()).collect();
        for directory in leading.into_iter().rev() {
            plan.add_directory(directory, how.made())?;
        }
        how.plan(&mut plan, sources, dest)?;
        let measure = plan.measure(&layout, 0, &|_| false)?;
        let (offset, size) = self.window()?;
        let Some(image) = image else {
            if let Some(size) = size.filter(|size| *size < measure.len) {
                bail!(
                    errno::ENOSPC,
                    Detail::TooSmall {
                        minimal: measure.len,
                        actual: size,
                    },
                    "the archive needs {} bytes, more than the {} given",
                    measure.len,
                    size
                );
            }
            println!("{}", measure.len);
            if self.flag("verbose") {
                eprintln!(
                    "{} and {} with {} of contents need an archive of {}",
                    plural(measure.files, "file", "files"),
                    plural(measure.directories, "directory", "directories"),
                    plural(measure.bytes, "byte", "bytes"),
                    plural(measure.len, "byte", "bytes")
                );
            }
            return Ok(());
        };
        let device = Device::create(image)?;
        let window = measure.make_room(device, offset, size)?;
        // The archive stays stopped until all of what was asked for is
        // done: a command that fails leaves nothing that is taken for an
        // archive.
        let (report, stopped) = plan.assemble_stopped(&window, &layout, &measure, &mut |_| {})?;
        self.write_manifest(&stopped.archive(), None)?;
        stopped.finish()?;
        self.report_written(image, &report);
        if let Some(hash) = hash {
            println!("{}", hash.of(&window, &mut |_| {})?);
        }
        Ok(())
    }

    fn populate(&self) -> Result<()> {
        let positional = self.positional_paths();
        let Some((&image, paths)) = positional.split_first() else {
            bail!(errno::EINVAL, "populate takes an IMAGE and SOURCE arguments");
        };
        let how = self.how()?;
        let dest = self.dest()?;
        let options = populate::Options {
            end_alignment: self.alignment("end-alignment", write::DEFAULT_END_ALIGNMENT)?,
            data_alignment: self.alignment("data-alignment", 0)?,
            replace: how.replace,
        };
        let sources = self.sources(paths, true)?;
        let (offset, size) = self.window()?;
        let mut device = Device::open(image, Access::ReadWrite)?;
        let mut total = Report::default();
        // Without a source the directory at --path is made.
        let mut sources: Vec<Option<Source>> = sources.into_iter().map(Some).collect();
        if sources.is_empty() {
            sources.push(None);
        }
        for source in sources {
            let addition = Addition {
                dest: dest.as_name(),
                source,
                parents: self.flag("parents"),
                how,
                options,
            };
            let report = addition.apply(&mut device, offset, size, &mut |_| {})?;
            total.files += report.files;
            total.directories += report.directories;
            total.bytes += report.bytes;
            total.len = report.len;
        }
        self.write_manifest(&Region::new(&device, offset, size)?, None)?;
        self.report_written(image, &total);
        Ok(())
    }

    fn list(&self) -> Result<()> {
        let (image, path) = match self.positional.as_slice() {
            [image] => (image, NameBuf::from(Name::ROOT)),
            [image, path] => (image, NameBuf::from_path(path.as_bytes())?),
            _ => bail!(errno::EINVAL, "list takes an IMAGE and optionally a PATH"),
        };
        let opened = self.open(Path::new(image))?;
        let region = opened.region()?;
        let tree = Tree::open(&region)?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let long = self.flag("long");
        let path = path.as_name();
        match (tree.children(path.as_bytes()), tree.get(path.as_bytes())) {
            (Some(children), _) => {
                for (name, inode) in children {
                    Line { name, inode }.write(&mut out, &region, long)?;
                }
            }
            // A file answers with itself.
            (None, Some(inode)) => {
                let name = path.file_name();
                Line { name, inode }.write(&mut out, &region, long)?
            }
            (None, None) => bail!(
                errno::ENOENT,
                Detail::Path(path.to_string()),
                "'{}' is not in the archive",
                path
            ),
        }
        Ok(())
    }

    fn describe(&self) -> Result<()> {
        let opened = self.open(self.image("describe")?)?;
        let region = opened.region()?;
        let tree = Tree::open(&region)?;
        let counts = tree.counts();
        let trailer = match (tree.trailer_offset(), tree.end()) {
            (Some(trailer), End::Trailer(_)) => trailer.to_string(),
            _ => "none".to_string(),
        };
        println!(
            "format:        {}",
            match tree.format() {
                Some(Format::Crc) => "070702, the new ASCII format with checksums",
                _ => "070701, the new ASCII format",
            }
        );
        println!("size:          {}", tree.archive_len(&region)?);
        println!("entries:       {}", tree.records());
        println!("trailer at:    {}", trailer);
        println!("files:         {} ({} bytes)", counts.files, counts.bytes);
        println!("directories:   {}", counts.directories);
        println!("symlinks:      {}", counts.symlinks);
        println!("nodes:         {}", counts.nodes);
        let stated = tree.root_stated();
        let root = tree.root();
        println!(
            "root:          {}",
            match (stated.contains(RootStated::MODE), stated.contains(RootStated::OWNER)) {
                (true, true) => format!("mode {:04o}, owner {}:{}", root.mode, root.uid, root.gid),
                (true, false) => format!("mode {:04o}", root.mode),
                (false, true) => format!("owner {}:{}", root.uid, root.gid),
                (false, false) => "as the kernel makes it, the archive has no entry for it".to_string(),
            }
        );
        if tree.approximate() {
            println!("note:          entries with '..' or below symbolic links are left out");
        }
        self.write_manifest(&region, Some(&tree))
    }

    fn cat(&self) -> Result<()> {
        let [image, path] = self.positional.as_slice() else {
            bail!(errno::EINVAL, "cat takes an IMAGE and a PATH");
        };
        let path = NameBuf::from_path(path.as_bytes())?;
        let opened = self.open(Path::new(image))?;
        let region = opened.region()?;
        let tree = Tree::open(&region)?;
        let shown = path.to_string();
        let inode = match tree.get(path.as_name().as_bytes()) {
            Some(inode) if inode.kind == Kind::Regular => inode,
            Some(inode) if inode.kind == Kind::Directory => {
                bail!(errno::EISDIR, Detail::Path(shown.clone()), "'{}' is a directory", shown)
            }
            Some(_) => bail!(errno::EINVAL, "'{}' is no regular file", shown),
            None => bail!(
                errno::ENOENT,
                Detail::Path(shown.clone()),
                "'{}' is not in the archive",
                shown
            ),
        };
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let mut buf = vec![0u8; CAT_BUFFER];
        let mut at = inode.data_offset;
        let end = at + u64::from(inode.size);
        while at < end {
            let n = (end - at).min(buf.len() as u64) as usize;
            region.read_at(at, &mut buf[..n])?;
            out.write_all(&buf[..n])?;
            at += n as u64;
        }
        Ok(())
    }

    /// Checks the archive and returns the fsck(8) exit code.
    fn check(&self) -> Result<ExitCode> {
        let image = self.image("check")?;
        let report = match self.open(image).and_then(|opened| check::check(&opened.region()?)) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("ucpio: {}", e);
                return Ok(ExitCode::from(FSCK_OPERATIONAL_ERROR));
            }
        };
        for problem in &report.problems {
            println!(
                "{}: {}",
                if problem.severity == Severity::Error {
                    "error"
                } else {
                    "warning"
                },
                problem
            );
        }
        if report.dropped > 0 {
            println!(
                "... and {} not shown",
                plural(report.dropped as u64, "more problem", "more problems")
            );
        }
        println!(
            "{}: {}, {}, {}, {}, {}, {}; {}, {}",
            image.display(),
            plural(report.records, "entry", "entries"),
            plural(report.counts.files, "file", "files"),
            plural(report.counts.directories, "directory", "directories"),
            plural(report.counts.symlinks, "symlink", "symlinks"),
            plural(report.counts.nodes, "node", "nodes"),
            plural(report.archive_len, "byte", "bytes"),
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
    fn capabilities(&self) -> Result<()> {
        if !self.positional.is_empty() {
            bail!(errno::EINVAL, "capabilities takes no arguments");
        }
        println!("{}", json::Value::Object(FileSystemService::capabilities()));
        Ok(())
    }
}

/// What the tool can be told to do.
#[derive(Clone, Copy)]
enum Command {
    Assemble,
    Populate,
    List,
    Describe,
    Check,
    Capabilities,
    Cat,
}

impl Command {
    /// The command `name` names.
    fn named(name: &str) -> Option<Command> {
        Some(match name {
            "assemble" => Command::Assemble,
            "populate" => Command::Populate,
            "list" => Command::List,
            "describe" => Command::Describe,
            "check" => Command::Check,
            "capabilities" => Command::Capabilities,
            "cat" => Command::Cat,
            _ => return None,
        })
    }

    /// Runs the command with the arguments `argv`.
    fn run(self, argv: &[OsString]) -> Result<ExitCode> {
        match self {
            Command::Assemble => Given::parse(
                argv,
                &[IMAGE_OPTIONS, FILL_VALUES, &["hash"]],
                &[FILL_FLAGS, &["plan", "checksums", "no-root-entry"]],
            )?
            .assemble()?,
            Command::Populate => Given::parse(argv, &[IMAGE_OPTIONS, FILL_VALUES], &[FILL_FLAGS])?.populate()?,
            Command::List => Given::parse(argv, &[IMAGE_OPTIONS], &[&["long"]])?.list()?,
            Command::Describe => Given::parse(argv, &[IMAGE_OPTIONS, &["write-manifest"]], &[])?.describe()?,
            Command::Check => return Given::parse(argv, &[IMAGE_OPTIONS], &[])?.check(),
            Command::Capabilities => Given::parse(argv, &[], &[])?.capabilities()?,
            Command::Cat => Given::parse(argv, &[IMAGE_OPTIONS], &[])?.cat()?,
        }
        Ok(ExitCode::SUCCESS)
    }
}

fn run(argv: &[OsString]) -> Result<ExitCode> {
    let Some((command, rest)) = argv.split_first() else {
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
    match Command::named(command) {
        Some(command) => command.run(rest),
        None => bail!(errno::EINVAL, "unknown command '{}'", command),
    }
}

/// Runs the command line interface.
pub(crate) fn main() -> ExitCode {
    // Rust starts programs with SIGPIPE ignored, so writing to a pipe whose
    // reader is gone fails with EPIPE, and print!() panics on that, as in
    // `ucpio list IMAGE | head -1`. Let the signal end the tool quietly
    // instead, as it ends other command line tools. The service keeps
    // ignoring it: it writes its replies to the socket with plain writes.
    // SAFETY: signal() only sets how SIGPIPE is handled, and SIG_DFL is a
    // valid disposition.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let argv: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(&argv) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ucpio: {}", e);
            ExitCode::FAILURE
        }
    }
}
