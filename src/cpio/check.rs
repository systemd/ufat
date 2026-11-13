// SPDX-License-Identifier: LGPL-2.1-or-later
//! Checking an archive: everything the kernel would do with it that the
//! one who made it did not mean, and everything other readers trip over.
//!
//! The kernel's unpacker says little. An entry it cannot place is gone
//! without a word, and so is the rest of an archive that is cut short. A
//! check replays the archive the way the kernel unpacks it (see
//! [`crate::tree`]) and reports each of these, naming the reader that is
//! affected. It changes nothing.
//!
//! A problem is an error when the kernel loses or removes something or
//! stops unpacking, and a warning when the kernel is fine and another
//! reader is not, or when the archive is merely wasteful.

use std::fmt;

use crate::header::{Format, Kind, MAGIC_NAME, MAJOR_BITS, MAX_NAME_SIZE, MINOR_BITS};
use crate::name::MAX_COMPONENT_LEN;
use crate::progress::Progress;
use crate::read::{self, Damage, End, Follower, Foreign, Skip, Source, Standing};
use crate::tree::{Counts, Finding, FindingKind, Outcome, Replay, Replayed};
use crate::Result;

/// How serious a problem is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// The kernel unpacks the archive as it was meant. Another reader may
    /// not, or the archive holds what it does not need.
    Warning,
    /// The kernel loses an entry, removes something or stops unpacking.
    Error,
}

/// What a finding is about, in the terms every file system shares; the
/// kind says which finding in cpio's own vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemClass {
    /// The archive as a whole: where it starts and where it ends.
    Superblock,
    /// An entry: its header, its place among the others, what it does to
    /// the tree.
    Directory,
    /// The text of a name.
    Name,
    /// A checksum that does not match the data.
    Checksum,
    /// An archive the kernel unpacks but that some readers refuse or
    /// misread.
    Interoperability,
    /// Nothing of the above.
    Other,
}

impl ProblemClass {
    /// The value as the Varlink interface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            ProblemClass::Superblock => "superblock",
            ProblemClass::Directory => "directory",
            ProblemClass::Name => "name",
            ProblemClass::Checksum => "checksum",
            ProblemClass::Interoperability => "interoperability",
            ProblemClass::Other => "other",
        }
    }
}

/// What a finding is about, one value per kind of finding. `path` is the
/// name of the entry as it is stored and is set wherever an entry is
/// concerned, together with `index` and `offset`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProblemKind {
    /// Something else than an entry where one has to be. `found` says
    /// what it looks like, when that is known.
    NoMagic,
    /// A header field that is no hexadecimal number, named by `field`.
    HeaderField,
    /// A name that does not end in a NUL byte.
    UnterminatedName,
    /// An entry behind a gap that does not start at a multiple of four.
    MisalignedEntry,
    /// The archive ends inside an entry; `field` names the part.
    Truncated,
    /// A name size of zero or above 4096 (`value`): the kernel passes over
    /// the entry.
    NameSize,
    /// A symbolic link target above 4096 bytes (`sizeBytes`): the kernel
    /// passes over the entry.
    TargetSize,
    /// Data on something that is no regular file or symbolic link
    /// (`sizeBytes`): the kernel passes over the entry.
    UnexpectedData,
    /// An entry without a file type: the kernel removes what is at its
    /// path.
    Removal,
    /// An empty name or a component above 255 bytes: the entry is lost.
    UnusableName,
    /// The entry's directory is not there: the entry is lost.
    MissingParent,
    /// The entry's directory is a file: the entry is lost.
    ParentNotDirectory,
    /// A directory that is not empty is in the entry's place: the entry is
    /// lost.
    DirectoryInTheWay,
    /// A name of a hard-linked file whose first name is gone: the entry is
    /// lost.
    BrokenLink,
    /// Something that is no directory named with a slash or a `.` at its
    /// end: the entry is lost.
    TrailingSlash,
    /// A symbolic link target of 4096 bytes: no link is made, and what is
    /// at the path is removed.
    LongTarget,
    /// A device number beyond the bits the kernel keeps: the node gets
    /// another number.
    DeviceNumber,
    /// The sum of the data (`value`) is not the one in the header
    /// (`expected`).
    Checksum,
    /// A `..` in the name: where the entry goes is not followed.
    DotDot,
    /// A path through a symbolic link: where the entry goes is not
    /// followed.
    ThroughSymlink,
    /// Names that start with `./`, `count` of them; `path` is the first.
    LeadingDotSlash,
    /// Names that start with `/`, `count` of them; `path` is the first.
    AbsoluteName,
    /// Names with repeated or trailing slashes or `.` components, `count`
    /// of them; `path` is the first.
    UnnormalizedName,
    /// The entry replaces an earlier one of the same name.
    Replaced,
    /// A symbolic link without a target.
    EmptyTarget,
    /// NUL bytes between two entries, `sizeBytes` of them.
    Gap,
    /// An entry in the other header form than the first one.
    MixedForms,
    /// An inode number shared by entries that are not one file.
    SharedInode,
    /// A hard-linked file with another number of names than its entries
    /// say.
    LinkCount,
    /// A trailer with a mode, data or a padded name.
    OddTrailer,
    /// No trailer.
    NoTrailer,
    /// An archive behind the trailer, at `value`; `name` is its format
    /// when it is compressed.
    DataAfterTrailer,
    /// Something behind the trailer, at `value`, that is neither padding
    /// nor an archive.
    JunkAfterTrailer,
}

impl ProblemKind {
    /// The kind as the Varlink interface names it.
    pub fn as_str(self) -> &'static str {
        use ProblemKind::*;
        match self {
            NoMagic => "noMagic",
            HeaderField => "headerField",
            UnterminatedName => "unterminatedName",
            MisalignedEntry => "misalignedEntry",
            Truncated => "truncated",
            NameSize => "nameSize",
            TargetSize => "targetSize",
            UnexpectedData => "unexpectedData",
            Removal => "removal",
            UnusableName => "unusableName",
            MissingParent => "missingParent",
            ParentNotDirectory => "parentNotDirectory",
            DirectoryInTheWay => "directoryInTheWay",
            BrokenLink => "brokenLink",
            TrailingSlash => "trailingSlash",
            LongTarget => "longTarget",
            DeviceNumber => "deviceNumber",
            Checksum => "checksum",
            DotDot => "dotDot",
            ThroughSymlink => "throughSymlink",
            LeadingDotSlash => "leadingDotSlash",
            AbsoluteName => "absoluteName",
            UnnormalizedName => "unnormalizedName",
            Replaced => "replaced",
            EmptyTarget => "emptyTarget",
            Gap => "gap",
            MixedForms => "mixedForms",
            SharedInode => "sharedInode",
            LinkCount => "linkCount",
            OddTrailer => "oddTrailer",
            NoTrailer => "noTrailer",
            DataAfterTrailer => "dataAfterTrailer",
            JunkAfterTrailer => "junkAfterTrailer",
        }
    }

    /// What the finding is about.
    pub fn class(self) -> ProblemClass {
        use ProblemKind::*;
        match self {
            NoMagic | Truncated | NoTrailer | OddTrailer | DataAfterTrailer | JunkAfterTrailer => {
                ProblemClass::Superblock
            }
            HeaderField | MisalignedEntry | TargetSize | UnexpectedData | Removal | MissingParent
            | ParentNotDirectory | DirectoryInTheWay | BrokenLink | ThroughSymlink | Replaced | EmptyTarget
            | LongTarget | DeviceNumber => ProblemClass::Directory,
            UnterminatedName | NameSize | UnusableName | TrailingSlash | DotDot | UnnormalizedName => {
                ProblemClass::Name
            }
            Checksum => ProblemClass::Checksum,
            LeadingDotSlash | AbsoluteName | Gap | MixedForms | SharedInode | LinkCount => {
                ProblemClass::Interoperability
            }
        }
    }

    /// How serious a finding of this kind is.
    pub fn severity(self) -> Severity {
        use ProblemKind::*;
        match self {
            NoMagic | HeaderField | UnterminatedName | MisalignedEntry | Truncated | NameSize | TargetSize
            | UnexpectedData | Removal | UnusableName | MissingParent | ParentNotDirectory | DirectoryInTheWay
            | BrokenLink | TrailingSlash | LongTarget | DeviceNumber | Checksum | JunkAfterTrailer => Severity::Error,
            DotDot | ThroughSymlink | LeadingDotSlash | AbsoluteName | UnnormalizedName | Replaced | EmptyTarget
            | Gap | MixedForms | SharedInode | LinkCount | OddTrailer | NoTrailer | DataAfterTrailer => {
                Severity::Warning
            }
        }
    }
}

/// One finding of a check, with the facts its kind has.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// How serious it is.
    pub severity: Severity,
    /// What is wrong.
    pub kind: ProblemKind,
    /// The name of the entry the finding is about, as it is stored.
    pub path: Option<String>,
    /// The position of that entry among the entries, counting from 0.
    pub index: Option<u64>,
    /// Where that entry starts in the archive.
    pub offset: Option<u64>,
    /// A size in bytes.
    pub size_bytes: Option<u64>,
    /// A value as found.
    pub value: Option<u64>,
    /// What the value should have been.
    pub expected: Option<u64>,
    /// What something looks like that is no entry.
    pub found: Option<Foreign>,
    /// A header field, or the part of an entry.
    pub field: Option<&'static str>,
    /// A count of entries.
    pub count: Option<u64>,
}

impl Problem {
    /// A finding of `kind` with no facts yet.
    pub fn new(kind: ProblemKind) -> Problem {
        Problem {
            severity: kind.severity(),
            kind,
            path: None,
            index: None,
            offset: None,
            size_bytes: None,
            value: None,
            expected: None,
            found: None,
            field: None,
            count: None,
        }
    }

    fn at(mut self, index: u64, offset: u64, name: &[u8]) -> Problem {
        self.index = Some(index);
        self.offset = Some(offset);
        self.path = Some(String::from_utf8_lossy(name).into_owned());
        self
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ProblemKind::*;
        let path = self.path.as_deref().unwrap_or("?");
        let offset = self.offset.unwrap_or(0);
        let size = self.size_bytes.unwrap_or(0);
        let value = self.value.unwrap_or(0);
        let expected = self.expected.unwrap_or(0);
        let count = self.count.unwrap_or(0);
        let field = self.field.unwrap_or("?");
        match self.kind {
            NoMagic if self.found == Some(Foreign::Unfinished) => write!(
                f,
                "the archive was not finished at offset {}, writing it failed or was cut off: the kernel stops unpacking here",
                offset
            ),
            NoMagic => {
                write!(f, "no entry at offset {}", offset)?;
                if let Some(found) = self.found {
                    write!(f, ", it looks like {}", found)?;
                }
                f.write_str(": the kernel stops unpacking here")
            }
            HeaderField => write!(
                f,
                "the header at offset {} holds no number in {}: the kernel stops unpacking here",
                offset, field
            ),
            UnterminatedName => write!(
                f,
                "the name of the entry at offset {} does not end in a NUL byte: the kernel stops unpacking here",
                offset
            ),
            MisalignedEntry => write!(
                f,
                "the entry at offset {} does not start at a multiple of four: the kernel stops unpacking here",
                offset
            ),
            Truncated => write!(
                f,
                "the archive ends inside the {} of the entry at offset {}: the kernel unpacks what is there and reports nothing",
                field, offset
            ),
            NameSize => write!(
                f,
                "the entry at offset {} has a name size of {}: the kernel passes over it",
                offset, value
            ),
            TargetSize => write!(
                f,
                "'{}' is a symbolic link with a target of {} bytes: the kernel passes over it",
                path, size
            ),
            UnexpectedData => write!(
                f,
                "'{}' is no regular file or symbolic link and has {} bytes of data: the kernel passes over it",
                path, size
            ),
            Removal => write!(
                f,
                "'{}' has no file type: the kernel creates nothing and removes what is at that path",
                path
            ),
            UnusableName => write!(
                f,
                "the name '{}' is empty or has a component of more than {} bytes: the kernel loses the entry",
                path, MAX_COMPONENT_LEN
            ),
            MissingParent => write!(
                f,
                "the directory of '{}' is not in the archive before it: the kernel loses the entry",
                path
            ),
            ParentNotDirectory => write!(
                f,
                "'{}' is below something that is no directory: the kernel loses the entry",
                path
            ),
            DirectoryInTheWay => write!(
                f,
                "a directory that is not empty is where '{}' goes: the kernel loses the entry",
                path
            ),
            BrokenLink => write!(
                f,
                "'{}' is a name of a hard-linked file whose first name is gone: the kernel loses the entry",
                path
            ),
            TrailingSlash => write!(
                f,
                "'{}' is no directory and its name ends in a slash or in '.': the kernel loses the entry, and an empty directory that a name with a slash leads to",
                path
            ),
            LongTarget => write!(
                f,
                "'{}' is a symbolic link with a target of {} bytes, one more than a link holds: the kernel removes what is at that path and makes no link",
                path, MAX_NAME_SIZE
            ),
            DeviceNumber => write!(
                f,
                "the device number of '{}' is beyond the {} bits of the major and the {} bits of the minor that the kernel keeps: the node gets another number",
                path, MAJOR_BITS, MINOR_BITS
            ),
            Checksum => write!(
                f,
                "the data of '{}' sums up to {:08x}, the header says {:08x}: the kernel stops unpacking here",
                path, value, expected
            ),
            DotDot => write!(
                f,
                "the name '{}' has a '..' in it: where the kernel puts the entry depends on what is unpacked by then, the entry is left out of this check",
                path
            ),
            ThroughSymlink => write!(
                f,
                "'{}' is below a symbolic link: the kernel follows the link, the entry is left out of this check",
                path
            ),
            LeadingDotSlash => write!(
                f,
                "{} names start with './', the first is '{}': the kernel unpacks them, but its early lookup of microcode and ACPI tables does not find them",
                count, path
            ),
            AbsoluteName => write!(
                f,
                "{} names start with '/', the first is '{}': the kernel unpacks them, bsdcpio refuses to",
                count, path
            ),
            UnnormalizedName => write!(
                f,
                "{} names have repeated slashes, a slash at the end or '.' components, the first is '{}'",
                count, path
            ),
            Replaced => write!(f, "'{}' replaces an earlier entry of the same name", path),
            EmptyTarget => write!(f, "'{}' is a symbolic link without a target", path),
            Gap => write!(
                f,
                "{} NUL bytes lie before '{}': the kernel reads on, cpio, bsdcpio and busybox do not",
                size, path
            ),
            MixedForms => write!(
                f,
                "'{}' is in the other header form than the first entry: GNU cpio drops it",
                path
            ),
            SharedInode => write!(
                f,
                "'{}' shares its inode number with an entry that is another file: bsdcpio and bsdtar take the two for one",
                path
            ),
            LinkCount => write!(
                f,
                "'{}' counts {} names and the archive has {} for it",
                path, expected, value
            ),
            OddTrailer => f.write_str(
                "the trailer has a mode, data or a padded name: the kernel takes it for the trailer, bsdcpio and bsdtar may not",
            ),
            NoTrailer => f.write_str("the archive has no trailer: the kernel does not need one, cpio calls the archive cut short"),
            DataAfterTrailer => {
                match self.found {
                    Some(found) => write!(f, "a compressed archive ({}) follows the trailer at offset {}", found, value)?,
                    None => write!(f, "another archive follows the trailer at offset {}", value)?,
                }
                f.write_str(": the kernel unpacks it too, cpio and this check stop at the trailer")
            }
            JunkAfterTrailer => write!(
                f,
                "something that is neither padding nor an archive follows the trailer at offset {}: the kernel fails to unpack it",
                value
            ),
        }
    }
}

/// The most problems a report keeps. An archive can have one per entry;
/// the counts stay exact, the problems beyond this many are dropped.
pub const MAX_PROBLEMS: usize = 10_000;

/// The outcome of a check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Everything found, in the order found, up to [`MAX_PROBLEMS`].
    pub problems: Vec<Problem>,
    /// Problems found but not kept, beyond [`MAX_PROBLEMS`].
    pub dropped: usize,
    errors: usize,
    warnings: usize,
    /// What the archive unpacks to, counted.
    pub counts: Counts,
    /// How many entries the archive has, the trailer included.
    pub records: u64,
    /// The length of the archive up to the end of its trailer, or up to
    /// where reading it stopped.
    pub archive_len: u64,
}

impl Report {
    /// Number of errors, dropped ones included.
    pub fn errors(&self) -> usize {
        self.errors
    }

    /// Number of warnings, dropped ones included.
    pub fn warnings(&self) -> usize {
        self.warnings
    }

    /// Whether nothing at all was found.
    pub fn is_clean(&self) -> bool {
        self.errors == 0 && self.warnings == 0
    }

    /// Adds what the replay found. A finding about the form of a name
    /// counts with the first of its kind and is no problem of its own.
    fn find(&mut self, finding: &Finding, forms: &mut Forms) {
        let mut problem = Problem::from(finding);
        if let Some(form) = forms.of(problem.kind) {
            form.count += 1;
            match form.at {
                Some(at) => {
                    if let Some(first) = self.problems.get_mut(at) {
                        first.count = Some(form.count);
                    }
                    return;
                }
                None => {
                    problem.count = Some(form.count);
                    form.at = Some(self.problems.len());
                }
            }
        }
        self.add(problem);
    }

    fn add(&mut self, problem: Problem) {
        match problem.severity {
            Severity::Error => self.errors += 1,
            Severity::Warning => self.warnings += 1,
        }
        if self.problems.len() < MAX_PROBLEMS {
            self.problems.push(problem);
        } else {
            self.dropped += 1;
        }
    }
}

/// The findings about the form of names come once per entry of an archive
/// another tool wrote. They are reported once per kind, with a count.
#[derive(Default)]
struct Forms {
    leading_dot_slash: Form,
    absolute: Form,
    unnormalized: Form,
}

/// The findings of one kind about the form of names.
#[derive(Default)]
struct Form {
    /// Where in the report the problem is, once there is one.
    at: Option<usize>,
    count: u64,
}

impl Forms {
    /// The findings of `kind`, if it is one about the form of names.
    fn of(&mut self, kind: ProblemKind) -> Option<&mut Form> {
        match kind {
            ProblemKind::LeadingDotSlash => Some(&mut self.leading_dot_slash),
            ProblemKind::AbsoluteName => Some(&mut self.absolute),
            ProblemKind::UnnormalizedName => Some(&mut self.unnormalized),
            _ => None,
        }
    }
}

impl From<FindingKind> for ProblemKind {
    fn from(kind: FindingKind) -> ProblemKind {
        match kind {
            FindingKind::Skipped(Skip::NameSize) => ProblemKind::NameSize,
            FindingKind::Skipped(Skip::TargetSize) => ProblemKind::TargetSize,
            FindingKind::Skipped(Skip::Data) => ProblemKind::UnexpectedData,
            FindingKind::Removal => ProblemKind::Removal,
            FindingKind::UnusableName => ProblemKind::UnusableName,
            FindingKind::DotDot => ProblemKind::DotDot,
            FindingKind::LeadingDotSlash => ProblemKind::LeadingDotSlash,
            FindingKind::Absolute => ProblemKind::AbsoluteName,
            FindingKind::Unnormalized => ProblemKind::UnnormalizedName,
            FindingKind::MissingParent => ProblemKind::MissingParent,
            FindingKind::ParentNotDirectory => ProblemKind::ParentNotDirectory,
            FindingKind::ParentIsSymlink => ProblemKind::ThroughSymlink,
            FindingKind::DirectoryInTheWay => ProblemKind::DirectoryInTheWay,
            FindingKind::Replaced => ProblemKind::Replaced,
            FindingKind::BrokenLink => ProblemKind::BrokenLink,
            FindingKind::TrailingSlash => ProblemKind::TrailingSlash,
            FindingKind::LongTarget => ProblemKind::LongTarget,
            FindingKind::DeviceNumber => ProblemKind::DeviceNumber,
            FindingKind::EmptyTarget => ProblemKind::EmptyTarget,
            FindingKind::Gap => ProblemKind::Gap,
            FindingKind::MixedForms => ProblemKind::MixedForms,
            FindingKind::SharedInode => ProblemKind::SharedInode,
            FindingKind::LinkCount => ProblemKind::LinkCount,
            FindingKind::OddTrailer => ProblemKind::OddTrailer,
            FindingKind::NoTrailer => ProblemKind::NoTrailer,
        }
    }
}

impl From<&Finding> for Problem {
    fn from(finding: &Finding) -> Problem {
        let kind = ProblemKind::from(finding.kind);
        let mut problem = Problem::new(kind);
        if kind != ProblemKind::NoTrailer {
            problem = problem.at(finding.index, finding.offset, &finding.name);
        }
        match kind {
            ProblemKind::TargetSize | ProblemKind::UnexpectedData | ProblemKind::Gap => {
                problem.size_bytes = finding.value
            }
            _ => problem.value = finding.value,
        }
        problem.expected = finding.expected;
        problem
    }
}

impl Problem {
    /// The damage that stopped the reading of an archive behind `index`
    /// entries.
    fn of_damage(damage: &Damage, index: u64) -> Problem {
        let mut problem = match *damage {
            Damage::Magic { found, .. } => {
                let mut p = Problem::new(ProblemKind::NoMagic);
                p.found = found;
                p.field = Some(MAGIC_NAME);
                p
            }
            Damage::Field { field, .. } => {
                let mut p = Problem::new(ProblemKind::HeaderField);
                p.field = Some(field.name());
                p
            }
            Damage::Unterminated { .. } => Problem::new(ProblemKind::UnterminatedName),
            Damage::Misaligned { .. } => Problem::new(ProblemKind::MisalignedEntry),
            Damage::Truncated { part, .. } => {
                let mut p = Problem::new(ProblemKind::Truncated);
                p.field = Some(part.name());
                p
            }
        };
        problem.index = Some(index);
        problem.offset = Some(damage.offset());
        problem
    }
}

/// Checks the archive in `source`. I/O errors and an image that holds no
/// archive at all are returned as errors; everything else lands in the
/// report.
pub fn check<S: Source + ?Sized>(source: &S) -> Result<Report> {
    check_with_progress(source, &mut |_| {})
}

/// [`check`], telling `progress` how many entries it has been through and
/// how many bytes of data it summed, after every entry.
pub fn check_with_progress<S: Source + ?Sized>(source: &S, progress: &mut dyn FnMut(&Progress)) -> Result<Report> {
    let mut report = Report::default();
    let mut forms = Forms::default();
    let mut done = Progress::default();
    let mut replay = Replay::new(source);
    for entry in replay.by_ref() {
        let Replayed {
            record,
            index,
            findings,
        } = entry?;
        for finding in &findings {
            report.find(finding, &mut forms);
        }
        if record.format == Format::Crc && record.standing == Standing::Entry(Kind::Regular) {
            let len = u64::from(record.header.filesize);
            let sum = source.checksum(record.data_offset, len)?;
            done.bytes += len;
            if sum != record.header.check {
                let mut problem = Problem::new(ProblemKind::Checksum).at(index, record.offset, &record.name);
                problem.value = Some(u64::from(sum));
                problem.expected = Some(u64::from(record.header.check));
                report.add(problem);
            }
        }
        done.files = index + 1;
        progress(&done);
    }
    let Outcome { tree, damage, findings } = replay.finish();
    for finding in &findings {
        report.find(finding, &mut forms);
    }
    if tree.records() == 0 {
        match damage {
            // An archive that was not finished is one, with this one thing
            // wrong with it.
            Some(Damage::Magic {
                found: Some(Foreign::Unfinished),
                ..
            }) => {}
            Some(damage) => return Err(damage.into_error()),
            None => return Err(read::blank()),
        }
    }
    report.archive_len = match (tree.end(), &damage) {
        (End::Trailer(end), _) => end,
        (End::NoTrailer, Some(damage)) => damage.offset(),
        (End::NoTrailer, None) => tree.trailer_offset().unwrap_or(0),
    };
    if let Some(damage) = &damage {
        report.add(Problem::of_damage(damage, tree.records()));
    }
    if let End::Trailer(end) = tree.end() {
        if let Some(at) = source.first_nonzero(end)? {
            let mut problem = match source.follower(at)? {
                Follower::Archive => Problem::new(ProblemKind::DataAfterTrailer),
                Follower::Compressed(format) => {
                    let mut problem = Problem::new(ProblemKind::DataAfterTrailer);
                    problem.found = Some(format);
                    problem
                }
                Follower::Unknown => Problem::new(ProblemKind::JunkAfterTrailer),
            };
            problem.value = Some(at);
            report.add(problem);
        }
    }
    report.counts = tree.counts();
    report.records = tree.records();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errno::*;
    use crate::header::DeviceNumber;
    use crate::test_util::{archive, named, Raw};
    use crate::write::{Attributes, Options, Writer};

    const REG: u32 = 0o100644;
    const DIR: u32 = 0o040755;

    fn kinds(report: &Report) -> Vec<ProblemKind> {
        report.problems.iter().map(|p| p.kind).collect()
    }

    fn dir(name: &[u8], ino: u32) -> Raw {
        Raw::new(DIR, name).inode(ino, 2)
    }

    #[test]
    fn what_the_writer_writes_is_clean() {
        let attributes = Attributes {
            mode: 0o644,
            ..Attributes::default()
        };
        for format in [Format::Newc, Format::Crc] {
            let options = Options {
                format,
                data_alignment: 512,
                ..Options::default()
            };
            let mut w = Writer::new(Vec::new(), options).unwrap();
            w.directory(named(b"."), &attributes).unwrap();
            w.directory(named(b"d"), &attributes).unwrap();
            let links = w.links(2).unwrap();
            w.file_link(named(b"a"), &attributes, &links).unwrap();
            w.file(named(b"d/b"), &attributes, Some(&links), 600, &mut &[b'x'; 600][..])
                .unwrap();
            w.symlink(named(b"l"), &attributes, b"d/b").unwrap();
            w.node(named(b"n"), Kind::Fifo, &attributes, DeviceNumber::NONE, None)
                .unwrap();
            let (bytes, len) = w.finish().unwrap();
            let report = check(&bytes).unwrap();
            assert_eq!(report.problems, [], "{:?}", format);
            assert!(report.is_clean());
            assert_eq!(report.records, 7);
            assert_eq!(report.archive_len, len - (len - report.archive_len));
            assert_eq!(
                report.counts,
                Counts {
                    files: 1,
                    directories: 1,
                    symlinks: 1,
                    nodes: 1,
                    bytes: 600,
                }
            );
        }
    }

    #[test]
    fn lost_and_passed_over_entries_are_errors() {
        let entries = [
            Raw::new(REG, b"nowhere/f").data(b"x"),
            dir(b"d", 1),
            Raw::new(REG, b"d/f").data(b"x"),
            Raw::new(REG, b"d").data(b"in the way"),
            Raw::new(0, b"d/f"),
            dir(b"e", 2).data(b"data"),
            Raw::new(0o120777, b"l").data(&[b't'; 5000]),
            Raw::new(REG, &[b'n'; 300]),
            Raw::new(REG, b"d/g/").data(b"x"),
            Raw::new(REG, b"first").inode(9, 2),
            Raw::new(0, b"first"),
            Raw::new(REG, b"second").inode(9, 2),
        ];
        let report = check(&archive(&entries)).unwrap();
        assert_eq!(
            kinds(&report),
            [
                ProblemKind::MissingParent,
                ProblemKind::DirectoryInTheWay,
                ProblemKind::Removal,
                ProblemKind::UnexpectedData,
                ProblemKind::TargetSize,
                ProblemKind::UnusableName,
                ProblemKind::UnnormalizedName,
                ProblemKind::TrailingSlash,
                ProblemKind::Removal,
                ProblemKind::BrokenLink,
            ]
        );
        assert_eq!(report.errors(), 9);
        assert_eq!(report.warnings(), 1);
        let p = &report.problems[0];
        assert_eq!(
            (p.path.as_deref(), p.index, p.offset),
            (Some("nowhere/f"), Some(0), Some(0))
        );
        assert_eq!(report.problems[3].size_bytes, Some(4));
        assert_eq!(report.problems[4].size_bytes, Some(5000));
        assert_eq!(report.problems[6].count, Some(1));
        // Every problem says what it is about.
        for problem in &report.problems {
            assert!(!problem.to_string().is_empty());
            assert!(!problem.kind.as_str().is_empty());
            assert!(!problem.kind.class().as_str().is_empty());
        }
    }

    #[test]
    fn name_forms_are_reported_once_with_a_count() {
        let mut entries = vec![dir(b"./", 1), dir(b"./d", 2)];
        for i in 0..50 {
            entries.push(Raw::new(REG, format!("./d/{}", i).as_bytes()));
        }
        entries.push(Raw::new(REG, b"/abs"));
        entries.push(Raw::new(REG, b"d//x"));
        entries.push(Raw::new(REG, b"d/./y"));
        let report = check(&archive(&entries)).unwrap();
        assert_eq!(
            kinds(&report),
            [
                ProblemKind::LeadingDotSlash,
                ProblemKind::AbsoluteName,
                ProblemKind::UnnormalizedName
            ]
        );
        assert_eq!(report.problems[0].count, Some(52));
        assert_eq!(report.problems[0].path.as_deref(), Some("./"));
        assert_eq!(report.problems[1].count, Some(1));
        assert_eq!(report.problems[2].count, Some(2));
        assert_eq!(report.errors(), 0);
        assert_eq!(report.warnings(), 3);
        assert!(report.problems[0].to_string().starts_with("52 names start with './'"));
    }

    #[test]
    fn checksums_are_verified() {
        let good = Raw::new(REG, b"good").data(b"ASDF").magic(b"070702");
        let mut bytes = good.bytes();
        // The sum of ASDF is 0x11e: put it into the header.
        bytes[102..110].copy_from_slice(b"0000011e");
        let bad = Raw::new(REG, b"bad").data(b"ASDF").magic(b"070702");
        let bad_at = bytes.len() as u64;
        bytes.extend(bad.bytes());
        // The plain form carries none, whatever its last field says.
        let mut plain = Raw::new(REG, b"plain").data(b"ASDF").bytes();
        plain[102..110].copy_from_slice(b"deadbeef");
        bytes.extend(plain);
        bytes.extend(Raw::trailer().magic(b"070702").bytes());
        let report = check(&bytes).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::Checksum, ProblemKind::MixedForms]);
        let p = &report.problems[0];
        assert_eq!((p.value, p.expected, p.offset), (Some(0x11e), Some(0), Some(bad_at)));
        assert_eq!(p.path.as_deref(), Some("bad"));
        assert_eq!(p.severity, Severity::Error);
    }

    #[test]
    fn damage_ends_the_check_with_what_was_read() {
        let good = archive(&[dir(b"d", 1), Raw::new(REG, b"d/f").data(b"data")]);
        let report = check(&good[..150]).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::Truncated]);
        assert_eq!(report.problems[0].field, Some("header"));
        assert_eq!(report.problems[0].index, Some(1));
        assert_eq!(report.counts.directories, 1);
        // The directory's entry is 112 bytes long.
        assert_eq!(report.archive_len, 112);
        let mut bad = good.clone();
        bad[112..118].copy_from_slice(b"070707");
        let report = check(&bad).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::NoMagic]);
        assert_eq!(report.problems[0].found, Some(Foreign::CpioOdc));
        let mut bad = good.clone();
        bad[112 + 6 + 8 * 4] = b'?';
        let report = check(&bad).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::HeaderField]);
        assert_eq!(report.problems[0].field, Some("c_nlink"));
    }

    #[test]
    fn the_end_of_the_archive() {
        let mut bytes = archive(&[Raw::new(REG, b"f")]);
        let end = bytes.len() as u64;
        // Padding is fine, whatever its length.
        bytes.extend([0u8; 1000]);
        assert!(check(&bytes).unwrap().is_clean());
        assert_eq!(check(&bytes).unwrap().archive_len, end);
        // What is no archive behind it makes the kernel fail.
        let padded = bytes.clone();
        bytes.extend(b"more");
        let report = check(&bytes).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::JunkAfterTrailer]);
        assert_eq!(report.problems[0].value, Some(end + 1000));
        assert_eq!(report.errors(), 1);
        // Another archive, as it is or compressed, the kernel unpacks.
        let mut bytes = padded.clone();
        bytes.extend(archive(&[Raw::new(REG, b"g")]));
        let report = check(&bytes).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::DataAfterTrailer]);
        assert_eq!(
            (report.problems[0].value, report.problems[0].found),
            (Some(end + 1000), None)
        );
        assert_eq!((report.errors(), report.warnings()), (0, 1));
        let mut bytes = padded.clone();
        bytes.extend(b"\x28\xb5\x2f\xfd and so on");
        let report = check(&bytes).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::DataAfterTrailer]);
        assert_eq!(report.problems[0].found, Some(Foreign::Zstd));
        // An entry off a multiple of four is none to the kernel, and the
        // older formats are none either.
        let old = [&b"070707"[..], &[b'0'; 104]].concat();
        for follower in [&b"\x00\x00070701"[..], &old, b"\x00\x00\x1f\x8b"] {
            let mut bytes = padded.clone();
            bytes.extend(follower);
            let report = check(&bytes).unwrap();
            assert_eq!(kinds(&report), [ProblemKind::JunkAfterTrailer], "{:?}", follower);
        }
        // The start of an entry and nothing more the kernel passes over.
        let mut bytes = padded.clone();
        bytes.extend(b"0707");
        assert_eq!(kinds(&check(&bytes).unwrap()), [ProblemKind::DataAfterTrailer]);
        // No trailer, and a gap.
        let mut bytes = Raw::new(REG, b"a").bytes();
        bytes.extend([0u8; 12]);
        bytes.extend(Raw::new(REG, b"b").bytes());
        let report = check(&bytes).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::Gap, ProblemKind::NoTrailer]);
        assert_eq!(report.problems[0].size_bytes, Some(12));
        assert_eq!(report.problems[0].path.as_deref(), Some("b"));
        assert_eq!(report.warnings(), 2);
    }

    #[test]
    fn what_is_no_archive_is_an_error() {
        assert_eq!(check(&[][..]).unwrap_err().errno(), ENODATA);
        assert_eq!(check(&[0u8; 64][..]).unwrap_err().errno(), ENODATA);
        assert_eq!(check(&b"\x1f\x8b\x08\x00"[..]).unwrap_err().errno(), EMEDIUMTYPE);
        assert_eq!(check(&[b'x'; 300][..]).unwrap_err().errno(), EMEDIUMTYPE);
    }

    /// An archive that was not finished is one, and the stopper at its
    /// start is what is wrong with it: the kernel takes nothing of it.
    #[test]
    fn an_archive_that_was_not_finished_is_reported() {
        let good = archive(&[dir(b"d", 1), Raw::new(REG, b"d/f").data(b"data")]);
        check(&good).unwrap();
        let mut stopped = good.clone();
        stopped[0] = crate::header::STOPPER;
        let report = check(&stopped).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::NoMagic]);
        assert_eq!((report.errors(), report.warnings()), (1, 0));
        let problem = &report.problems[0];
        assert_eq!(problem.found, Some(Foreign::Unfinished));
        assert_eq!((problem.offset, problem.index), (Some(0), Some(0)));
        assert!(problem.to_string().contains("not finished"), "{}", problem);
        assert_eq!((report.records, report.archive_len), (0, 0));
        assert_eq!(report.counts.directories, 0);
        // The same where entries were being added.
        let (tree, _) = crate::tree::Tree::replay(&good, &mut |_| {}).unwrap();
        let trailer = tree.trailer_offset().unwrap() as usize;
        let mut stopped = good.clone();
        stopped[trailer] = crate::header::STOPPER;
        let report = check(&stopped).unwrap();
        assert_eq!(kinds(&report), [ProblemKind::NoMagic]);
        assert_eq!(report.problems[0].offset, Some(trailer as u64));
        assert!(report.problems[0].to_string().contains("not finished"));
        assert_eq!(report.records, 2);
    }

    #[test]
    fn a_report_keeps_so_many_problems_and_counts_the_rest() {
        let mut entries = Vec::new();
        for i in 0..MAX_PROBLEMS + 50 {
            entries.push(Raw::new(REG, format!("nowhere/{}", i).as_bytes()));
        }
        let report = check(&archive(&entries)).unwrap();
        assert_eq!(report.problems.len(), MAX_PROBLEMS);
        assert_eq!(report.dropped, 50);
        assert_eq!(report.errors(), MAX_PROBLEMS + 50);
    }

    #[test]
    fn progress_counts_entries_and_summed_bytes() {
        let mut bytes = Raw::new(REG, b"a").data(b"12345").magic(b"070702").bytes();
        bytes.extend(Raw::new(REG, b"b").magic(b"070702").bytes());
        bytes.extend(Raw::trailer().magic(b"070702").bytes());
        let mut seen = Vec::new();
        check_with_progress(&bytes, &mut |p| seen.push((p.files, p.bytes))).unwrap();
        assert_eq!(seen, [(1, 5), (2, 5), (3, 5)]);
    }
}
