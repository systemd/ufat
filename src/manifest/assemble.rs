// SPDX-License-Identifier: LGPL-2.1-or-later
//! Assembling a volume from a manifest: where file contents come from, and
//! the walk over the manifest that creates directories and files and
//! verifies sizes and hashes.

use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Contents, Entry, InodeType, Manifest, Storable};
use crate::errno::*;
use crate::sha256::{Sha256, DIGEST_SIZE};
use crate::sys;
use crate::volume::Volume;
use crate::{ContentProblem, Detail, ManifestProblem, SourceProblem, UnsupportedKind};
use crate::{Context, Error, Result};

/// Supplies the data of regular files during assembly.
pub trait ContentSource {
    /// Writes the data of `entry` to `sink`: exactly `entry.size` bytes when
    /// the size is known. `contents` is the contents entry chosen by
    /// [`Entry::fat_contents`], if there is one.
    fn copy(&mut self, entry: &Entry, contents: Option<&Contents>, sink: &mut dyn Write) -> Result<()>;
}

/// Size of the buffer a source copies through.
const COPY_BUFFER: usize = 1024 * 1024;

/// The buffer a source copies through, allocated on first use and kept.
fn copy_buffer(buf: &mut Vec<u8>) -> &mut [u8] {
    if buf.len() != COPY_BUFFER {
        buf.resize(COPY_BUFFER, 0);
    }
    buf
}

/// Reads file data from the directory the manifest lives in, or from the
/// directory the caller chose instead.
#[derive(Debug)]
pub struct DirectorySource {
    dir: OwnedFd,
    follow_symlinks: bool,
    buf: Vec<u8>,
}

/// The detail of a file the manifest names that is not below the source
/// directory as described.
fn mismatch(name: &str, problem: SourceProblem, size: Option<u64>, expected: Option<u64>) -> Detail {
    Detail::Source {
        name: name.to_string(),
        problem,
        size,
        expected,
    }
}

/// The detail of file contents that do not match the manifest.
fn differs(name: &str, problem: ContentProblem, size: Option<u64>, expected: Option<u64>) -> Detail {
    Detail::Content {
        name: name.to_string(),
        problem,
        size,
        expected,
    }
}

/// The detail of something the manifest asks for that cannot be done.
fn unsupported(name: &str, what: UnsupportedKind, value: Option<&str>) -> Detail {
    Detail::Unsupported {
        name: Some(name.to_string()),
        what,
        value: value.map(str::to_string),
    }
}

/// A failure to reach a file the manifest names, as the source mismatch of
/// the entry `name` where the failure says the file is not what the
/// manifest describes: missing (or behind something that is not a
/// directory), or not a regular file.
fn source_failure(e: Error, name: &str) -> Error {
    let problem = match e.errno() {
        ENOENT | ENOTDIR => Some(SourceProblem::Missing),
        EINVAL => Some(SourceProblem::NotRegular),
        _ => None,
    };
    let e = e.context(name);
    match problem {
        Some(p) => e.with(mismatch(name, p, None, None)),
        None => e,
    }
}

impl DirectorySource {
    /// Reads files below the open directory `dir`, which the caller resolved
    /// once (with [`crate::host::open_dir`] when it has a path) and which is
    /// never looked up again. A file reference is resolved below it the way
    /// systemd's chase() resolves a path below a root: an absolute symbolic
    /// link target starts over at `dir`, `..` at `dir` stays there, nothing
    /// resolves to anything outside it, and symbolic links are followed
    /// only when [`DirectorySource::follow_symlinks`] allows them.
    pub fn new(dir: OwnedFd) -> DirectorySource {
        DirectorySource {
            dir,
            follow_symlinks: false,
            buf: Vec::new(),
        }
    }

    /// Follows symbolic links inside the source tree, as long as they stay
    /// inside it. Off by default, like the populator: a link planted in a
    /// tree would otherwise make a privileged assembly read any file on the
    /// host.
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> DirectorySource {
        self.follow_symlinks = follow;
        self
    }

    /// Opens the file `relative` names below the directory: pinned, checked
    /// to be a regular file, and only then opened for reading.
    fn open(&self, relative: &str) -> Result<(std::fs::File, std::fs::Metadata)> {
        let failed = || format!("failed to open {}", relative);
        let pinned =
            sys::chase(self.dir.as_fd(), relative.as_bytes(), self.follow_symlinks, false).with_context(failed)?;
        let md = sys::fstat(pinned.as_fd()).with_context(failed)?;
        if !md.is_file() {
            bail!(EINVAL, "{} is not a regular file", relative);
        }
        let fd = sys::reopen(pinned.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY).with_context(failed)?;
        Ok((std::fs::File::from(fd), md))
    }

    /// Checks, without reading any data, that every file the manifest would
    /// read from the directory is there, is a regular file and is as long
    /// as the manifest says: one lookup and one fstat each, found the way
    /// the copy will find them. Run before an image is created or
    /// formatted, so that a wrong source directory fails with nothing
    /// half-made left behind. Entries the assembly cannot store, literal
    /// contents and contents it would refuse anyway are passed over here;
    /// the sizes and hashes of the data itself are checked while copying.
    pub fn verify(&self, manifest: &Manifest) -> Result<()> {
        for entry in &manifest.entries {
            if !matches!(entry.inode_type, InodeType::Regular) || entry.check_supported().is_err() {
                continue;
            }
            let Ok(contents) = entry.fat_contents() else { continue };
            if contents.is_some_and(|c| c.literal.is_some()) {
                continue;
            }
            let Ok(source) = reference(entry, contents) else {
                continue;
            };
            let path = entry.path();
            let failed = |e: std::io::Error| {
                source_failure(
                    Error::from(e).context(format_args!("failed to open {}", source.relative)),
                    &path,
                )
            };
            let pinned = sys::chase(
                self.dir.as_fd(),
                source.relative.as_bytes(),
                self.follow_symlinks,
                false,
            )
            .map_err(failed)?;
            let md = sys::fstat(pinned.as_fd()).map_err(failed)?;
            if !md.is_file() {
                bail!(
                    EINVAL,
                    mismatch(&path, SourceProblem::NotRegular, None, None),
                    "{}: {} is not a regular file",
                    path,
                    source.relative
                );
            }
            source.check_len(&path, md.len(), entry.size, |found, expected| {
                mismatch(&path, SourceProblem::Size, found, expected)
            })?;
        }
        Ok(())
    }
}

/// The file below the source directory a regular entry's data comes from.
struct Reference {
    /// The file's path below the source directory.
    relative: String,
    /// Where the entry's data starts in the file.
    offset: u64,
    /// The size the manifest declares for the whole file, if any.
    original_size: Option<u64>,
    /// The hash the manifest declares for the whole file, if any.
    original_sha256: Option<[u8; DIGEST_SIZE]>,
}

impl Reference {
    /// Checks the length `len` of the file against the manifest, for the
    /// entry `path` of `size` bytes, and returns the size of its data: the
    /// rest of the file after the offset when the manifest gives none.
    /// `detail` makes the error's detail of the length found and the one
    /// expected.
    fn check_len(
        &self,
        path: &str,
        len: u64,
        size: Option<u64>,
        detail: impl Fn(Option<u64>, Option<u64>) -> Detail,
    ) -> Result<u64> {
        if let Some(total) = self.original_size {
            if total != len {
                bail!(
                    EBADMSG,
                    detail(Some(len), Some(total)),
                    "{}: {} is {} bytes, the manifest says {}",
                    path,
                    self.relative,
                    len,
                    total
                );
            }
        }
        let size = size.unwrap_or(len.saturating_sub(self.offset));
        if self.offset.checked_add(size).is_none_or(|end| end > len) {
            bail!(
                EBADMSG,
                detail(Some(len), self.offset.checked_add(size)),
                "{}: {} is too short for offset {} and size {}",
                path,
                self.relative,
                self.offset,
                size
            );
        }
        Ok(size)
    }
}

/// Where a regular entry's data comes from. Contents that would have to be
/// fetched or decoded are refused (EOPNOTSUPP).
fn reference(entry: &Entry, contents: Option<&Contents>) -> Result<Reference> {
    let path = entry.path();
    match contents {
        None => Ok(Reference {
            relative: entry.name.clone().unwrap_or_default(),
            offset: 0,
            original_size: None,
            original_sha256: None,
        }),
        Some(c) => {
            if c.url.is_some() {
                bail!(
                    EOPNOTSUPP,
                    unsupported(&path, UnsupportedKind::Url, None),
                    "{}: fetching contents from a URL is not supported",
                    path
                );
            }
            if let Some(enc) = &c.encoding {
                bail!(
                    EOPNOTSUPP,
                    unsupported(&path, UnsupportedKind::Encoding, Some(enc)),
                    "{}: contents encoded with '{}' are not supported",
                    path,
                    enc
                );
            }
            Ok(Reference {
                relative: c.file.clone().or_else(|| entry.name.clone()).unwrap_or_default(),
                offset: c.offset,
                original_size: c.original_size,
                original_sha256: c.original_sha256,
            })
        }
    }
}

impl ContentSource for DirectorySource {
    fn copy(&mut self, entry: &Entry, contents: Option<&Contents>, sink: &mut dyn Write) -> Result<()> {
        let path = entry.path();
        let source = reference(entry, contents)?;
        let (mut file, md) = self.open(&source.relative).map_err(|e| source_failure(e, &path))?;
        let size = source.check_len(&path, md.len(), entry.size, |found, expected| {
            differs(&path, ContentProblem::Size, found, expected)
        })?;
        let offset = source.offset;
        // The hash of the whole source, when given, is checked by reading
        // everything; the part before the offset is hashed but not copied.
        let mut hasher = source.original_sha256.map(|_| Sha256::new());
        let buf = copy_buffer(&mut self.buf);
        let mut pos = 0u64;
        loop {
            let n = crate::host::read_some(&mut file, buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            if let Some(h) = hasher.as_mut() {
                h.update(chunk);
            }
            let start = offset.saturating_sub(pos).min(n as u64) as usize;
            let end = (offset + size).saturating_sub(pos).min(n as u64) as usize;
            if start < end {
                sink.write_all(&chunk[start..end])?;
            }
            pos += n as u64;
            if hasher.is_none() && pos >= offset + size {
                break;
            }
        }
        if let (Some(h), Some(expected)) = (hasher, source.original_sha256) {
            if h.finalize() != expected {
                bail!(
                    EBADMSG,
                    differs(&path, ContentProblem::Hash, None, None),
                    "{}: {} does not match the hash in the manifest",
                    path,
                    source.relative
                );
            }
        }
        Ok(())
    }
}

/// Reads file data from one stream carrying every streamed file's contents
/// back to back in manifest order.
pub struct StreamSource<'a> {
    reader: &'a mut dyn Read,
    buf: Vec<u8>,
}

impl std::fmt::Debug for StreamSource<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamSource").finish_non_exhaustive()
    }
}

impl<'a> StreamSource<'a> {
    /// Wraps the stream.
    pub fn new(reader: &'a mut dyn Read) -> StreamSource<'a> {
        StreamSource {
            reader,
            buf: Vec::new(),
        }
    }
}

impl ContentSource for StreamSource<'_> {
    fn copy(&mut self, entry: &Entry, contents: Option<&Contents>, sink: &mut dyn Write) -> Result<()> {
        let path = entry.path();
        if let Some(c) = contents {
            if c.encoding.is_some() || c.offset != 0 {
                let what = if c.encoding.is_some() {
                    UnsupportedKind::Encoding
                } else {
                    UnsupportedKind::Offset
                };
                bail!(
                    EOPNOTSUPP,
                    unsupported(&path, what, c.encoding.as_deref()),
                    "{}: encodings and offsets cannot be used with streamed contents",
                    path
                );
            }
        }
        let total = entry.size.ok_or_else(|| {
            err!(
                EINVAL,
                Detail::Manifest {
                    problem: ManifestProblem::NoSize,
                    record: None,
                    name: Some(path.clone()),
                    field: Some("size".into()),
                },
                "{}: streamed contents need a known size",
                path
            )
        })?;
        let mut remaining = total;
        let buf = copy_buffer(&mut self.buf);
        while remaining > 0 {
            let want = (buf.len() as u64).min(remaining) as usize;
            let n = crate::host::read_some(&mut *self.reader, &mut buf[..want])?;
            if n == 0 {
                bail!(
                    EBADMSG,
                    differs(&path, ContentProblem::StreamEnded, Some(total - remaining), Some(total)),
                    "{}: the stream ended {} bytes early",
                    path,
                    remaining
                );
            }
            sink.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        Ok(())
    }
}

/// Options for [`Volume::assemble`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembleOptions {
    /// Time stamped on entries without `mTimeNSec` and on directories
    /// created implicitly.
    pub default_time: SystemTime,
    /// Replace files that exist in the volume instead of failing.
    pub replace: bool,
    /// Skip entries this crate cannot store (see [`Entry::check_supported`])
    /// instead of failing.
    pub skip_unsupported: bool,
    /// The current time for validity checks, or None to skip them.
    pub now_usec: Option<u64>,
}

impl Default for AssembleOptions {
    fn default() -> Self {
        AssembleOptions {
            default_time: UNIX_EPOCH,
            replace: true,
            skip_unsupported: false,
            now_usec: None,
        }
    }
}

/// What an assembly did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AssembleReport {
    /// Files written.
    pub files: u64,
    /// Directory objects applied: directories created, or existing ones
    /// that got the manifest's timestamp.
    pub directories: u64,
    /// File bytes written.
    pub bytes: u64,
    /// Entries skipped because they cannot be stored.
    pub skipped: Vec<String>,
}

/// Hashes what passes through it.
struct HashingWriter<'a> {
    inner: &'a mut dyn Write,
    hasher: Sha256,
    written: u64,
}

impl Write for HashingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write_all(buf)?;
        self.hasher.update(buf);
        self.written += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Volume {
    /// Creates the directories and files a manifest describes, each at its
    /// name below the root directory. Data comes from `source` for regular
    /// files without literal contents. Sizes and SHA-256 hashes in the
    /// manifest are verified; a mismatch removes the file again and fails
    /// with EBADMSG. A directory object listed after its children, or for a
    /// directory that already exists, sets the directory's timestamp.
    pub fn assemble(
        &mut self,
        manifest: &Manifest,
        source: &mut dyn ContentSource,
        options: &AssembleOptions,
    ) -> Result<AssembleReport> {
        let mut report = AssembleReport::default();
        if let Some(now) = options.now_usec {
            manifest.root.check_validity(now)?;
        }
        for entry in &manifest.entries {
            let name = entry.name.clone().unwrap_or_default();
            let path = format!("/{name}");
            // An invalid directory takes its children with it: the directory
            // object comes first and fails the whole assembly here.
            if let Some(now) = options.now_usec {
                entry.check_validity(now)?;
            }
            let storable = match entry.storable() {
                Ok(storable) => storable,
                Err(e) if e.errno() == EOPNOTSUPP && options.skip_unsupported => {
                    report.skipped.push(name);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let time = entry.mtime().unwrap_or(options.default_time);
            if let Some((parent, _)) = name.rsplit_once('/') {
                self.create_dir_all(&format!("/{parent}"), options.default_time)?;
            }
            match storable {
                Storable::Directory => {
                    match self.metadata(&path) {
                        Ok(m) if m.is_dir => self.set_times(&path, time)?,
                        Ok(_) => bail!(
                            ENOTDIR,
                            Detail::Path(path.clone()),
                            "'{}' exists in the volume and is not a directory",
                            path
                        ),
                        Err(e) if e.errno() == ENOENT => self.create_dir(&path, time)?,
                        Err(e) => return Err(e),
                    }
                    report.directories += 1;
                }
                Storable::File(contents) => {
                    // The writer aborts the file when it is dropped on an
                    // error.
                    let mut writer = self.create_file(&path, time, options.replace)?;
                    writer.set_read_only(entry.is_read_only());
                    let mut hashing = HashingWriter {
                        inner: &mut writer,
                        hasher: Sha256::new(),
                        written: 0,
                    };
                    match contents.and_then(|c| c.literal.as_ref()) {
                        Some(literal) => {
                            // An offset or a size beyond the literal takes it
                            // all; the checks below find the difference.
                            let offset = usize::try_from(contents.map_or(0, |c| c.offset)).unwrap_or(usize::MAX);
                            let data = literal.get(offset..).unwrap_or(&[]);
                            let data = match entry.size.map(usize::try_from) {
                                Some(Ok(size)) => data.get(..size).unwrap_or(data),
                                _ => data,
                            };
                            hashing.write_all(data)?;
                        }
                        None => source.copy(entry, contents, &mut hashing)?,
                    }
                    let HashingWriter { written, hasher, .. } = hashing;
                    let digest = hasher.finalize();
                    if let Some(size) = entry.size {
                        if written != size {
                            bail!(
                                EBADMSG,
                                differs(&path, ContentProblem::Size, Some(written), Some(size)),
                                "'{}' is {} bytes, the manifest says {}",
                                path,
                                written,
                                size
                            );
                        }
                    }
                    if let Some(expected) = entry.sha256 {
                        if digest != expected {
                            bail!(
                                EBADMSG,
                                differs(&path, ContentProblem::Hash, None, None),
                                "'{}' does not match the hash in the manifest",
                                path
                            );
                        }
                    }
                    writer.finish()?;
                    report.files += 1;
                    report.bytes += written;
                }
            }
        }
        Ok(report)
    }
}

impl crate::plan::Plan {
    /// Adds the files and directories of a manifest. Returns the entries
    /// that cannot be stored (see [`Entry::check_supported`]), which the
    /// assembler skips or refuses, so a plan and an assembly with
    /// `skip_unsupported` cover the same entries.
    pub fn add_manifest(&mut self, manifest: &Manifest) -> Result<Vec<String>> {
        let mut skipped = Vec::new();
        for entry in &manifest.entries {
            let name = entry.name.clone().unwrap_or_default();
            let storable = match entry.storable() {
                Ok(storable) => storable,
                Err(e) if e.errno() == EOPNOTSUPP => {
                    skipped.push(name);
                    continue;
                }
                Err(e) => return Err(e),
            };
            match storable {
                Storable::Directory => self.add_dir(&format!("/{}", name))?,
                Storable::File(_) => {
                    let Some(size) = entry.size else {
                        bail!(
                            EINVAL,
                            Detail::Manifest {
                                problem: ManifestProblem::NoSize,
                                record: None,
                                name: Some(format!("/{}", name)),
                                field: Some("size".into()),
                            },
                            "'{}' has no size in the manifest",
                            name
                        );
                    };
                    self.add_file(&format!("/{}", name), size)?;
                }
            }
        }
        Ok(skipped)
    }
}
