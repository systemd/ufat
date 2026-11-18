// SPDX-License-Identifier: LGPL-2.1-or-later
//! Assembling a volume from a manifest while it is read: the directory on
//! the host the contents of the files come from, and the walk over the
//! records that creates directories and files and verifies sizes and
//! hashes.

use std::fmt;
use std::io::{self, Read, Write};
use std::ops::{BitOr, BitOrAssign};
use std::os::fd::{AsFd, OwnedFd};
use std::time::{SystemTime, UNIX_EPOCH};

use uapi16::{ContentSource, Directory, ErrorKind, FileObject, Name, Object, OpenError, Order, Reader};

use super::{path_in_volume, DosAttributes, EntryKind, ObjectAction, ObjectTriage};
use crate::errno::*;
use crate::progress::Progress;
use crate::sys;
use crate::volume::{DirectoryOrigin, FileWriter, NameCollision, Volume};
use crate::{Error, Result};

/// The directory on the host the files of a manifest are taken from: the
/// one the manifest lives in, or the one the caller chose instead. It is
/// opened once and never looked up again, and each file below it is
/// pinned before it is opened.
///
/// A [`uapi16::DirectorySource`] reads the data of the files from it for an
/// assembly. A file that is missing, is not a regular file or is too short
/// for the data the manifest says it holds fails the assembly when its
/// object comes.
#[derive(Debug)]
pub struct PinnedDirectory {
    dir: OwnedFd,
    follow_symlinks: bool,
}

impl PinnedDirectory {
    /// The files below the open directory `dir`, which the caller resolved
    /// once (with [`crate::host::open_dir`] when it has a path) and which is
    /// never looked up again. A file reference is resolved below it the way
    /// systemd's chase() resolves a path below a root: an absolute symbolic
    /// link target starts over at `dir`, `..` at `dir` stays there, nothing
    /// resolves to anything outside it, and symbolic links are followed
    /// only when [`PinnedDirectory::follow_symlinks`] allows them.
    pub fn new(dir: OwnedFd) -> PinnedDirectory {
        PinnedDirectory {
            dir,
            follow_symlinks: false,
        }
    }

    /// Follows symbolic links inside the source tree, as long as they stay
    /// inside it. Off by default, like the populator: a link planted in a
    /// tree would otherwise make a privileged assembly read any file on the
    /// host.
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> PinnedDirectory {
        self.follow_symlinks = follow;
        self
    }

    /// Pins the file `file` names below the directory and checks that it
    /// is a regular file. Returns it with its size.
    fn pin(&self, file: &Name) -> std::result::Result<(OwnedFd, u64), OpenError> {
        let pinned = sys::chase(self.dir.as_fd(), file.as_bytes(), self.follow_symlinks, false)?;
        let md = sys::fstat(pinned.as_fd())?;
        if !md.is_file() {
            return Err(OpenError::NotRegular);
        }
        Ok((pinned, md.len()))
    }
}

impl Directory for PinnedDirectory {
    type File = std::fs::File;

    /// Opens the file: pinned, checked to be a regular file, and only then
    /// opened for reading.
    fn open(&self, file: &Name) -> std::result::Result<(std::fs::File, u64), OpenError> {
        let (pinned, len) = self.pin(file)?;
        let fd = sys::reopen(pinned.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)?;
        Ok((std::fs::File::from(fd), len))
    }
}

/// What an assembly does where it could also fail.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct AssembleFlags(u8);

impl AssembleFlags {
    /// Use what the volume holds under a name FAT does not tell apart from
    /// the name of an object, and an existing file of the object's name:
    /// replace a file, and put the entries of a directory into the one that
    /// is there.
    pub const REPLACE: AssembleFlags = AssembleFlags(1 << 0);
    /// Skip entries this crate cannot store (see [`EntryKind`]) instead of
    /// failing.
    pub const SKIP_UNSUPPORTED: AssembleFlags = AssembleFlags(1 << 1);
    /// No flag: an assembly fails in both cases. This is the default.
    pub const NONE: AssembleFlags = AssembleFlags(0);

    /// Every single flag with its name.
    const NAMES: [(AssembleFlags, &'static str); 2] = [
        (AssembleFlags::REPLACE, "REPLACE"),
        (AssembleFlags::SKIP_UNSUPPORTED, "SKIP_UNSUPPORTED"),
    ];

    /// Whether every flag of `flags` is among these.
    pub const fn contains(self, flags: AssembleFlags) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// These flags with `flags` among them if `on` says so, and without
    /// them if not.
    #[must_use]
    pub const fn with(self, flags: AssembleFlags, on: bool) -> AssembleFlags {
        if on {
            AssembleFlags(self.0 | flags.0)
        } else {
            AssembleFlags(self.0 & !flags.0)
        }
    }

    /// What an assembly does where the name of an object collides with an
    /// entry the volume holds, as [`AssembleFlags::REPLACE`] says.
    fn name_collision(self) -> NameCollision {
        if self.contains(AssembleFlags::REPLACE) {
            NameCollision::Replace
        } else {
            NameCollision::Fail
        }
    }
}

impl BitOr for AssembleFlags {
    type Output = AssembleFlags;

    fn bitor(self, other: AssembleFlags) -> AssembleFlags {
        AssembleFlags(self.0 | other.0)
    }
}

impl BitOrAssign for AssembleFlags {
    fn bitor_assign(&mut self, other: AssembleFlags) {
        self.0 |= other.0;
    }
}

impl fmt::Debug for AssembleFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = AssembleFlags::NAMES.iter().filter(|(flag, _)| self.contains(*flag));
        f.write_str("AssembleFlags(")?;
        for (i, (_, name)) in names.enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

/// Options for [`Volume::assemble`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssembleOptions {
    /// Time stamped on entries without `mTimeNSec`.
    pub default_time: SystemTime,
    /// What to do where an assembly could also fail.
    pub flags: AssembleFlags,
    /// The current time for validity checks, or None to skip them.
    pub now_usec: Option<u64>,
}

impl Default for AssembleOptions {
    fn default() -> Self {
        AssembleOptions {
            default_time: UNIX_EPOCH,
            flags: AssembleFlags::default(),
            now_usec: None,
        }
    }
}

/// What an assembly did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AssembleReport {
    /// Files written.
    pub files: u64,
    /// Directory objects applied: directories created, or existing ones
    /// that got the manifest's timestamp.
    pub directories: u64,
    /// File bytes written.
    pub bytes: u64,
    /// File objects left out, see [`SkipReason`].
    pub skipped: u64,
}

impl AssembleReport {
    /// What the assembly has done so far, as an observer hears it.
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}

/// Why an assembly leaves a file object out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// This crate cannot store the object, see [`EntryKind`], and
    /// [`AssembleFlags::SKIP_UNSUPPORTED`] says to leave it out.
    Unsupported,
    /// The object is below a directory that is left out.
    BelowSkipped,
}

/// What an assembly tells its caller while it runs. Every method does
/// nothing unless an observer has it do something.
///
/// A closure that takes a [`Progress`] is an observer of the progress.
pub trait AssembleObserver {
    /// What was written so far, after every directory, every file and
    /// every chunk of a file's contents.
    fn progress(&mut self, _progress: &Progress) {}

    /// The file object of the name `name` is left out, for the reason
    /// `reason`.
    fn skipped(&mut self, _name: &Name, _reason: SkipReason) {}
}

impl<F: FnMut(&Progress)> AssembleObserver for F {
    fn progress(&mut self, progress: &Progress) {
        self(progress);
    }
}

/// A writer that passes everything on to `inner` and tells the observer
/// after every write how many bytes went through, on top of what `done`
/// counts.
struct ProgressWriter<'a> {
    inner: &'a mut dyn Write,
    written: u64,
    done: Progress,
    observer: &'a mut dyn AssembleObserver,
}

impl Write for ProgressWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_all(buf)?;
        self.written += buf.len() as u64;
        self.observer.progress(&Progress {
            bytes: self.done.bytes + self.written,
            ..self.done
        });
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A file an assembly writes, created in the volume when its first data
/// comes, or when it is finished without any. So a file object whose
/// source refuses it, such as a stream that needs its size, leaves nothing
/// in the volume, not even the marks of a write.
struct PendingFile<'a> {
    /// The volume, until the file is created in it.
    volume: Option<&'a mut Volume>,
    /// The file once it is created. It is aborted when it is dropped
    /// unfinished.
    writer: Option<FileWriter<'a>>,
    /// Where the file goes in the volume.
    path: &'a str,
    /// The file object the file is made for.
    object: &'a FileObject,
    /// The assembly's options. The file takes their `default_time` where
    /// its object has no time, and their `flags` say whether it replaces a
    /// file of the same name.
    options: &'a AssembleOptions,
}

impl PendingFile<'_> {
    /// Whether the file is created.
    fn is_created(&self) -> bool {
        self.writer.is_some()
    }

    /// Creates the file unless it is created: with the object's time, or
    /// the assembly's where it gives none, with the read-only, hidden,
    /// system and archive attributes the object gives it, see
    /// [`DosAttributes::with_object`], and replacing a file of the same
    /// name where the assembly says so. The archive attribute a new file
    /// has stays where the manifest says nothing about it.
    fn create(&mut self) -> Result<()> {
        if let Some(volume) = self.volume.take() {
            let time = self.object.inode.mtime().unwrap_or(self.options.default_time);
            let collision = self.options.flags.name_collision();
            let mut writer = volume.create_file(self.path, time, collision)?;
            let attributes = DosAttributes::new(writer.attributes()).with_object(self.object);
            writer.set_attributes(attributes.settable())?;
            self.writer = Some(writer);
        }
        Ok(())
    }

    /// Finishes the file that was created.
    fn finish(self) -> Result<()> {
        match self.writer {
            Some(writer) => writer.finish(),
            None => Err(self.not_created()),
        }
    }

    /// The error of a write or a finish after the file could not be
    /// created.
    fn not_created(&self) -> Error {
        err!(EBADF, "'{}' was not created", self.path)
    }
}

impl Write for PendingFile<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.create()?;
        match &mut self.writer {
            Some(writer) => writer.write(buf),
            None => Err(self.not_created().into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.writer {
            Some(writer) => writer.flush(),
            None => Ok(()),
        }
    }
}

/// An assembly while the records of its manifest come.
struct Assembly<'a> {
    volume: &'a mut Volume,
    source: &'a mut dyn ContentSource,
    options: &'a AssembleOptions,
    observer: &'a mut dyn AssembleObserver,
    report: AssembleReport,
    triage: ObjectTriage,
}

impl Assembly<'_> {
    /// Applies the file object that came next: stores it as a file or as a
    /// directory, or leaves it out. An object that is not valid fails the
    /// assembly, also one that would be left out.
    fn apply(&mut self, object: &FileObject) -> Result<()> {
        // An invalid directory takes its entries with it: its object comes
        // first and fails the whole assembly.
        if let Some(now) = self.options.now_usec {
            object.check_validity(now)?;
        }
        match self.triage.decide(object, self.options.flags)? {
            ObjectAction::Store(EntryKind::Directory) => self.store_directory(object),
            ObjectAction::Store(EntryKind::File) => self.store_file(object),
            ObjectAction::Skip(reason) => self.skip(object, reason),
        }
    }

    /// Leaves `object` out. A source that hands out the contents in
    /// manifest order has them all the same, and passes over them with the
    /// checks of a copy: data that does not match the object's size and
    /// hash means that the stream is out of step with the manifest, and
    /// every object after it would get the wrong bytes.
    fn skip(&mut self, object: &FileObject, reason: SkipReason) -> Result<()> {
        self.report.skipped += 1;
        self.observer.skipped(&object.name, reason);
        self.source.skip(object)?;
        Ok(())
    }

    /// Creates the directory `object` describes, or gives the one that is
    /// there its time. Either gets the read-only, hidden, system and
    /// archive attributes the object gives it, see
    /// [`DosAttributes::with_object`]. A new directory has no others, and
    /// one that is there keeps the hidden, system and archive attributes
    /// whose flags the manifest does not list.
    fn store_directory(&mut self, object: &FileObject) -> Result<()> {
        let path = path_in_volume(&object.name);
        let time = object.inode.mtime().unwrap_or(self.options.default_time);
        let made = DosAttributes::NONE.with_object(object);
        let collision = self.options.flags.name_collision();
        match self
            .volume
            .find_or_create_dir(&path, time, made.settable(), collision)?
        {
            DirectoryOrigin::Created => {}
            DirectoryOrigin::Existing { attributes } => {
                self.volume.set_times(&path, time)?;
                // Only what changes is written.
                let existing = DosAttributes::new(attributes);
                let attributes = existing.with_object(object);
                if attributes != existing {
                    self.volume.set_attributes(&path, attributes.settable())?;
                }
            }
        }
        self.report.directories += 1;
        self.observer.progress(&self.report.progress());
        Ok(())
    }

    /// Creates the file `object` describes, with its contents checked
    /// against the manifest. The file is created when its first data comes,
    /// see [`PendingFile`].
    fn store_file(&mut self, object: &FileObject) -> Result<()> {
        let path = path_in_volume(&object.name);
        let mut file = PendingFile {
            volume: Some(&mut *self.volume),
            writer: None,
            path: &path,
            object,
            options: self.options,
        };
        let mut sink = ProgressWriter {
            inner: &mut file,
            written: 0,
            done: self.report.progress(),
            observer: &mut *self.observer,
        };
        let copied = object.copy_contents(self.source, &mut sink);
        // An error of the volume comes back from the copy as an I/O error.
        // One of creating the file is as the volume said it. One of writing
        // it knows nothing of the file it was writing, while those of the
        // manifest and of its files name the file already.
        let named = |e: Error| e.at_path(&path).context(format!("copying {}", object.name));
        let written = copied.map_err(|e| match e.kind() {
            ErrorKind::Io if file.is_created() => named(e.into()),
            _ => e.into(),
        })?;
        file.create()?;
        file.finish().map_err(named)?;
        self.report.files += 1;
        self.report.bytes += written;
        self.observer.progress(&self.report.progress());
        Ok(())
    }

    /// Ends the assembly after the trailer of the manifest.
    fn finish(self) -> Result<AssembleReport> {
        self.source.end()?;
        Ok(self.report)
    }
}

impl Volume {
    /// Creates the directories and files a manifest describes, each at its
    /// name below the root directory, while `reader` reads the manifest to
    /// its end. The caller opened the reader, and the reader read the root
    /// file object then.
    ///
    /// The manifest has to declare the code point order, see
    /// [`Order::CodePoint`], in its root file object, as UAPI.16 asks of a
    /// manifest that a file system is made from. One that does not fails
    /// with EBADMSG before anything is written. The reader checks the file
    /// objects against that order, so it refuses a name that comes twice,
    /// and every directory comes before what is in it. Data comes from
    /// `source` for regular files without literal contents. Sizes and
    /// SHA-256 hashes in the manifest are verified; a mismatch removes the
    /// file again and fails with EBADMSG. So does data the source has after
    /// the last file it supplies, which is found after the trailer of the
    /// manifest.
    ///
    /// A name FAT does not tell apart from one the volume holds fails with
    /// EEXIST, and so does a file the volume holds under the same name,
    /// unless [`AssembleFlags::REPLACE`] is set. A file fails so when its
    /// first data comes, or at its end when it has none: after the errors
    /// `source` finds before the data, such as a missing file, and before
    /// those in the data, such as a hash that does not match. A directory
    /// the volume holds under the same name gets the directory object's
    /// time and attributes.
    pub fn assemble<R: Read>(
        &mut self,
        reader: &mut Reader<R>,
        source: &mut dyn ContentSource,
        options: &AssembleOptions,
    ) -> Result<AssembleReport> {
        self.assemble_with_observer(reader, source, options, &mut |_: &Progress| {})
    }

    /// [`Volume::assemble`], telling `observer` what it wrote so far after
    /// every directory, every file and every chunk of a file, and every
    /// object it leaves out.
    pub fn assemble_with_observer<R: Read>(
        &mut self,
        reader: &mut Reader<R>,
        source: &mut dyn ContentSource,
        options: &AssembleOptions,
        observer: &mut dyn AssembleObserver,
    ) -> Result<AssembleReport> {
        reader.root().require_order(Order::CodePoint)?;
        if let Some(now) = options.now_usec {
            reader.root().check_validity(now)?;
        }
        let mut assembly = Assembly {
            volume: self,
            source,
            options,
            observer,
            report: AssembleReport::default(),
            triage: ObjectTriage::default(),
        };
        for object in reader {
            if let Object::File(object) = object? {
                assembly.apply(&object)?;
            }
        }
        assembly.finish()
    }
}
