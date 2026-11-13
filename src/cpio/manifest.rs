// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 manifests and cpio: the entries of an archive from a manifest,
//! and the manifest of what an archive unpacks to.
//!
//! The manifests themselves are the business of the `uapi16` crate: the
//! objects, the reader that checks them against the specification and the
//! writer. An
//! archive holds what a manifest describes but for extended attributes
//! and the names of users and groups: directories, regular files,
//! symbolic links, device nodes, FIFOs and sockets with their owner, mode
//! and time, and the objects that share an `inodeToken` as the names of
//! one hard-linked file.
//!
//! The contents of regular files come from where a [`Described`] has
//! them: the files next to the manifest, or one stream that carries the
//! contents of every file in the order of the manifest. An archive is
//! written in one order, a directory right before what is in it and the
//! entries of a directory sorted by the bytes of their names, which is the
//! order systemd-manifest writes a manifest in. A stream cannot be gone
//! back in, so it is taken for a manifest in that order only.
//!
//! Every name of a hard-linked file has its contents in a manifest. They
//! are all read and held against the manifest, and written once, with the
//! last name.
//!
//! Signatures are recognised but not verified: that needs an X.509 stack.
//! Callers who need authenticated manifests must verify them before
//! handing them over.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::time::SystemTime;

pub use shared::manifest::{DirectorySource, SourceDirectory, WriteReport};
use uapi16::{ContentSource, Data, Field, Location, Mode, Sha256Hasher};
pub use uapi16::{Fields, FileObject, InodeType, Manifest, Sha256, StreamSource, FILENAME, SUFFIX};

use crate::errno::*;
use crate::header::{DeviceNumber, Kind, MAX_FILE_SIZE, PERMISSIONS};
use crate::name::{Name, NameBuf};
use crate::plan::{Contents, Identity, Plan, Planned};
use crate::progress::Progress;
use crate::read::Source;
use crate::times::TimePolicy;
use crate::tree::{Inode, RootStated, Tree};
use crate::write::{Attributes, Sink, Writer};
use crate::{ContentProblem, Detail, ManifestProblem, Result, UnsupportedKind};

/// How the objects of a manifest become entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestOptions {
    /// Which modification times the entries get. [`TimePolicy::Preserve`]
    /// keeps the ones of the manifest.
    pub times: TimePolicy,
    /// The time of an object the manifest has no time for, and of the
    /// directories that are made for objects whose directory the manifest
    /// does not list.
    pub default_time: SystemTime,
    /// The owning user of every entry, instead of the one the manifest
    /// says.
    pub uid: Option<u32>,
    /// The owning group of every entry, instead of the one the manifest
    /// says.
    pub gid: Option<u32>,
    /// Replace an entry that is planned already with one of the same name
    /// instead of failing with EEXIST.
    pub replace: bool,
    /// The current time in microseconds since the epoch, to refuse what is
    /// revoked or not valid at it. None skips that.
    pub now_usec: Option<u64>,
}

impl Default for ManifestOptions {
    fn default() -> ManifestOptions {
        ManifestOptions {
            times: TimePolicy::Preserve,
            default_time: SystemTime::UNIX_EPOCH,
            uid: None,
            gid: None,
            replace: true,
            now_usec: None,
        }
    }
}

impl ManifestOptions {
    /// Permissions, owner and time of `object`, as an entry carries them.
    /// What the manifest leaves out is root as the owner,
    /// [`Attributes::DIRECTORY_MODE`] for a directory and
    /// [`Attributes::FILE_MODE`] for everything else, without the write
    /// bits when the object is read-only. A symbolic link has no mode in a
    /// manifest and gets the one it has on Linux.
    pub fn attributes(&self, object: &FileObject) -> Attributes {
        let mode = match (object.inode_type, object.mode) {
            (InodeType::Symlink, _) => Attributes::SYMLINK_MODE,
            (_, Some(mode)) => mode.bits() & PERMISSIONS,
            (InodeType::Directory, None) => Attributes::DIRECTORY_MODE,
            (_, None) if object.is_read_only() => Attributes::READ_ONLY_MODE,
            (_, None) => Attributes::FILE_MODE,
        };
        Attributes {
            mode,
            uid: self.uid.or(object.uid).unwrap_or(0),
            gid: self.gid.or(object.gid).unwrap_or(0),
            mtime: Attributes::seconds(self.times.resolve(object.mtime().unwrap_or(self.default_time))),
        }
    }

    /// What a directory is that is made because an object is in it and
    /// the manifest does not list it.
    fn made(&self) -> Attributes {
        Attributes {
            mode: Attributes::DIRECTORY_MODE,
            uid: self.uid.unwrap_or(0),
            gid: self.gid.unwrap_or(0),
            mtime: Attributes::seconds(self.times.resolve(self.default_time)),
        }
    }
}

impl From<InodeType> for Kind {
    fn from(inode_type: InodeType) -> Kind {
        match inode_type {
            InodeType::Regular => Kind::Regular,
            InodeType::Directory => Kind::Directory,
            InodeType::Symlink => Kind::Symlink,
            InodeType::Fifo => Kind::Fifo,
            InodeType::CharDevice => Kind::CharDevice,
            InodeType::BlockDevice => Kind::BlockDevice,
            InodeType::Socket => Kind::Socket,
        }
    }
}

/// What an error says of a file object.
trait Told {
    /// The path a client is told the object by: its name below the root.
    fn path(&self) -> String;

    /// What a client is told when the manifest does not say of the object
    /// what `field` would.
    fn lacks(&self, problem: ManifestProblem, field: Field) -> Detail;
}

impl Told for FileObject {
    fn path(&self) -> String {
        format!("/{}", self.name)
    }

    fn lacks(&self, problem: ManifestProblem, field: Field) -> Detail {
        Detail::Manifest {
            problem,
            record: None,
            name: Some(self.path()),
            field: Some(field.to_string()),
        }
    }
}

/// Where the files of a manifest have their contents.
enum Files {
    /// In the files below a directory, by their names.
    Directory(DirectorySource),
    /// In one stream, back to back in the order of the manifest.
    Stream(StreamSource<Box<dyn Read>>),
}

/// A manifest with where the files it describes have their contents:
/// what a plan takes entries from, see [`Plan::add_manifest`].
pub struct Described {
    manifest: Manifest,
    files: Files,
}

impl fmt::Debug for Described {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let files = match self.files {
            Files::Directory(_) => "directory",
            Files::Stream(_) => "stream",
        };
        f.debug_struct("Described")
            .field("objects", &self.manifest.objects.len())
            .field("files", &files)
            .finish()
    }
}

impl Described {
    /// What `manifest` describes, with the contents of its files in the
    /// files below `directory`: the one the manifest is in, as a rule.
    /// The targets of symbolic links the manifest does not carry are read
    /// there as well.
    ///
    /// Fails when a file the manifest refers to is not there, is no
    /// regular file or is not as long as the manifest says. No data is
    /// read for that.
    pub fn in_directory(manifest: Manifest, directory: SourceDirectory) -> Result<Described> {
        let source = DirectorySource::new(directory);
        source.verify(&manifest.objects)?;
        Ok(Described {
            manifest,
            files: Files::Directory(source),
        })
    }

    /// What `manifest` describes, with the contents of its files in
    /// `stream`: those of every regular file that does not have them in
    /// the manifest, back to back in the order of the manifest.
    pub fn in_stream(manifest: Manifest, stream: impl Read + 'static) -> Described {
        Described {
            manifest,
            files: Files::Stream(StreamSource::new(Box::new(stream))),
        }
    }

    /// The manifest.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The target of the symbolic link `object`, which the manifest does
    /// not carry.
    fn read_link(&self, object: &FileObject) -> Result<Vec<u8>> {
        match &self.files {
            Files::Directory(source) => source.directory().read_link(&object.name),
            Files::Stream(_) => bail!(
                EINVAL,
                object.lacks(ManifestProblem::NoTarget, Field::Contents),
                "'{}' is a symbolic link and the manifest does not have its target",
                object.path()
            ),
        }
    }

    /// The entry of a plan for the object at `index` of the manifest,
    /// which goes to `name`.
    fn planned(&self, index: usize, name: Name<'_>, options: &ManifestOptions) -> Result<Planned> {
        let object = &self.manifest.objects[index];
        let kind = Kind::from(object.inode_type);
        let path = object.path();
        let mut planned = Planned::new(kind, options.attributes(object));
        match kind {
            Kind::Directory => {
                if !object.contents.is_empty() || object.sha256.is_some() {
                    bail!(
                        EOPNOTSUPP,
                        Detail::Unsupported {
                            name: Some(path.clone()),
                            what: UnsupportedKind::SubManifest,
                            value: None,
                        },
                        "'{}' refers to a sub-manifest, which is not supported",
                        path
                    );
                }
            }
            Kind::Regular => {
                let size = match object.data()? {
                    Data::Literal(data) => data.len() as u64,
                    Data::External(_) => object.size.ok_or_else(|| {
                        err!(
                            EINVAL,
                            object.lacks(ManifestProblem::NoSize, Field::Size),
                            "'{}' has no size in the manifest",
                            path
                        )
                    })?,
                };
                if size > MAX_FILE_SIZE {
                    bail!(
                        EFBIG,
                        Detail::TooLarge {
                            path: Some(name.to_string()),
                            size,
                            maximum: MAX_FILE_SIZE,
                        },
                        "'{}' has {} bytes, more than the {} a cpio archive can hold",
                        path,
                        size,
                        MAX_FILE_SIZE
                    );
                }
                planned.size = size;
                planned.contents = Contents::Manifest { object: index as u32 };
            }
            Kind::Symlink => {
                let target = match object.data()? {
                    Data::Literal(data) => data.to_vec(),
                    Data::External(_) => self.read_link(object)?,
                };
                // A mismatch names the object the way the manifest has it.
                let differs = |problem, size: Option<u64>| Detail::Content {
                    name: object.name.to_string(),
                    problem,
                    size,
                    expected: object.size.filter(|_| size.is_some()),
                };
                let len = target.len() as u64;
                if let Some(size) = object.size.filter(|&size| size != len) {
                    bail!(
                        EBADMSG,
                        differs(ContentProblem::Size, Some(len)),
                        "the target of '{}' is {} bytes, the manifest says {}",
                        object.name,
                        len,
                        size
                    );
                }
                if object.sha256.is_some_and(|expected| expected != Sha256::of(&target)) {
                    bail!(
                        EBADMSG,
                        differs(ContentProblem::Hash, None),
                        "the target of '{}' does not match the hash in the manifest",
                        object.name
                    );
                }
                name.check_target(&target)?;
                planned.target = target;
            }
            Kind::CharDevice | Kind::BlockDevice => {
                let (Some(major), Some(minor)) = (object.major, object.minor) else {
                    bail!(
                        EINVAL,
                        object.lacks(ManifestProblem::NoDeviceNumber, Field::Major),
                        "'{}' is a device node and the manifest does not have its device number",
                        path
                    );
                };
                planned.rdev = DeviceNumber::saturating(major, minor);
                name.check_node(kind, planned.rdev)?;
            }
            Kind::Fifo | Kind::Socket => {}
        }
        // A directory has one name and the kernel never links symbolic links.
        if !matches!(kind, Kind::Directory | Kind::Symlink) {
            planned.identity = object.inode_token.map(Identity::Manifest);
        }
        Ok(planned)
    }

    /// Whether the objects `first` and `other`, which share an
    /// `inodeToken`, can be two names of one file.
    fn one_file(first: &FileObject, other: &FileObject, options: &ManifestOptions) -> bool {
        first.inode_type == other.inode_type
            && options.attributes(first) == options.attributes(other)
            && first.size == other.size
            && (first.major, first.minor) == (other.major, other.minor)
            && (first.sha256.is_none() || other.sha256.is_none() || first.sha256 == other.sha256)
    }
}

impl Plan {
    /// Plans what `described` describes, below the directory `dest` of
    /// the archive, `.` for its root. The leading object of the manifest
    /// stands for `dest` itself and is not planned here: see
    /// [`ManifestOptions::attributes`] for what it says.
    ///
    /// A directory an object is in and that the manifest does not list is
    /// planned with the defaults of [`ManifestOptions::attributes`], and
    /// so are the directories that lead to `dest`. The objects of one
    /// `inodeToken` are the names of one file: they have to be of one kind
    /// with one owner, mode, time and size.
    ///
    /// The plan keeps what it is given. The contents of the regular files
    /// are read when the plan is written, and a plan takes the entries of
    /// one manifest only.
    pub fn add_manifest(&mut self, described: Described, dest: Name<'_>, options: &ManifestOptions) -> Result<()> {
        if self.described.is_some() {
            bail!(EINVAL, "a plan takes the entries of one manifest only");
        }
        let manifest = &described.manifest;
        if let Some(now) = options.now_usec {
            manifest.root.check_validity(now)?;
        }
        // The directories made here because nothing listed them yet. An
        // object that lists one later says what it is.
        let mut implied: HashSet<NameBuf> = HashSet::new();
        // The first object of every hard-linked file.
        let mut groups: HashMap<NonZeroU64, usize> = HashMap::new();
        for (index, object) in manifest.objects.iter().enumerate() {
            // An invalid directory takes what is in it along: the
            // directory comes first and fails everything here.
            if let Some(now) = options.now_usec {
                object.check_validity(now)?;
            }
            let held = dest.join(object.name.as_bytes())?;
            let name = held.as_name();
            // The directories on the way that are not planned yet.
            let missing: Vec<NameBuf> = name
                .ancestors()
                .take_while(|parent| self.get(*parent).is_none())
                .map(NameBuf::from)
                .collect();
            for parent in missing.into_iter().rev() {
                self.add_directory(parent.as_name(), options.made())?;
                implied.insert(parent);
            }
            if let Some(parent) = name.parent().filter(|parent| !parent.is_root()) {
                if self.get(parent).is_some_and(|planned| planned.kind != Kind::Directory) {
                    bail!(
                        ENOTDIR,
                        Detail::from(parent),
                        "'{}' is below '{}', which is no directory",
                        name,
                        parent
                    );
                }
            }
            let planned = described.planned(index, name, options)?;
            if planned.kind == Kind::Directory && implied.remove(&held) {
                self.restate_directory(name, planned.attributes);
                continue;
            }
            if let Some(Identity::Manifest(token)) = planned.identity {
                let first = &manifest.objects[*groups.entry(token).or_insert(index)];
                if !Described::one_file(first, object, options) {
                    bail!(
                        EBADMSG,
                        object.lacks(ManifestProblem::Contradiction, Field::InodeToken),
                        "'{}' and '{}' share the inodeToken {} and are not one file: they differ in type, owner, mode, time, size or hash",
                        first.path(),
                        object.path(),
                        token
                    );
                }
            }
            self.insert(name, planned, options.replace)?;
        }
        self.described = Some(described);
        Ok(())
    }
}

/// The contents of a file that is being written, as something to write
/// to. Tells `progress` after every piece how many bytes went through, on
/// top of what `done` counted before.
struct Pieces<'w, S: Sink> {
    writer: &'w mut Writer<S>,
    done: Progress,
    progress: &'w mut dyn FnMut(&Progress),
}

impl<S: Sink> Write for Pieces<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.file_data(buf)?;
        self.done.bytes += buf.len() as u64;
        (self.progress)(&self.done);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Takes the contents of the objects of a manifest from where they are
/// while an archive is written, and keeps to the order a stream has them
/// in.
pub(crate) struct Feed<'a> {
    manifest: &'a Manifest,
    source: &'a mut dyn ContentSource,
    /// With a stream, the object whose contents are the next in it.
    next: usize,
    /// The last object whose contents come from the source.
    last: Option<usize>,
}

impl<'a> Feed<'a> {
    /// A feed of what `described` has.
    pub(crate) fn new(described: &'a mut Described) -> Feed<'a> {
        let Described { manifest, files } = described;
        let source: &mut dyn ContentSource = match files {
            Files::Directory(directory) => directory,
            Files::Stream(stream) => stream,
        };
        Feed {
            last: manifest.objects.iter().rposition(FileObject::is_streamed),
            manifest,
            source,
            next: 0,
        }
    }

    /// Tells the source when the contents of the object at `index`, which
    /// were just read and held against the manifest, are the last it
    /// supplies. A stream that goes on behind them fails here: the last
    /// file got more than the manifest says.
    fn ended(&mut self, index: usize) -> Result<()> {
        if self.last == Some(index) {
            self.source.end(&self.manifest.objects[index])?;
        }
        Ok(())
    }

    /// With a stream, makes sure that the contents of the object at
    /// `index` are the next in it.
    fn at(&mut self, index: usize) -> Result<()> {
        let objects = &self.manifest.objects;
        if !self.source.sequential() || !objects[index].is_streamed() {
            return Ok(());
        }
        // Everything streamed before it has to be taken by now.
        let before = (self.next..index).find(|&i| objects[i].is_streamed());
        if index < self.next || before.is_some() {
            let other = &objects[before.unwrap_or(self.next.saturating_sub(1))];
            bail!(
                EINVAL,
                "the stream has the contents of '{}' and of '{}' in the order of the manifest, which is not the order of the archive: a directory before what is in it, and the entries of a directory sorted by their names",
                other.path(),
                objects[index].path()
            );
        }
        self.next = index + 1;
        Ok(())
    }

    /// Reads the contents of the object at `index` and holds them against
    /// the manifest without writing them: a name of a hard-linked file
    /// that is not the last one.
    pub(crate) fn check(&mut self, index: usize) -> Result<()> {
        self.at(index)?;
        self.manifest.objects[index].copy_contents(self.source, &mut io::sink())?;
        self.ended(index)
    }

    /// Writes the contents of the object at `index` into the file `writer`
    /// has begun, held against the manifest, and tells `progress` of
    /// every piece on top of what `done` counts. Returns how many bytes
    /// they are.
    pub(crate) fn write<S: Sink>(
        &mut self,
        index: usize,
        writer: &mut Writer<S>,
        done: Progress,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<u64> {
        self.at(index)?;
        let mut pieces = Pieces { writer, done, progress };
        let written = self.manifest.objects[index].copy_contents(self.source, &mut pieces)?;
        self.ended(index)?;
        Ok(written)
    }

    /// With a stream, makes sure nothing is left in it that the archive
    /// did not take.
    pub(crate) fn finish(&self) -> Result<()> {
        let objects = &self.manifest.objects;
        if !self.source.sequential() {
            return Ok(());
        }
        match (self.next..objects.len()).find(|&i| objects[i].is_streamed()) {
            Some(left) => bail!(
                EINVAL,
                "the stream has the contents of '{}', which is not written to the archive",
                objects[left].path()
            ),
            None => Ok(()),
        }
    }
}

impl From<Kind> for InodeType {
    fn from(kind: Kind) -> InodeType {
        match kind {
            Kind::Regular => InodeType::Regular,
            Kind::Directory => InodeType::Directory,
            Kind::Symlink => InodeType::Symlink,
            Kind::Fifo => InodeType::Fifo,
            Kind::CharDevice => InodeType::CharDevice,
            Kind::BlockDevice => InodeType::BlockDevice,
            Kind::Socket => InodeType::Socket,
        }
    }
}

/// How much of a file is read at a time for its hash.
const HASH_BUFFER: usize = 1024 * 1024;

impl Tree {
    /// Writes the UAPI.16 manifest of what the archive in `source` unpacks
    /// to, which is this tree, to `out`: the leading object, one object
    /// for every name in the order of the archive, the trailer. Each
    /// record goes out in one write and `out` is flushed at the end, so a
    /// descriptor wants a `BufWriter` around it.
    ///
    /// `fields` chooses what is said of an object beyond its name and its
    /// type: mode, owner, time, the size and hash of a regular file, the
    /// target of a symbolic link as a literal, the number of a device node,
    /// and a token that the names of one hard-linked file share. The
    /// leading object stands for the root and carries what the archive
    /// says of it. The hashes are of the contents as they are in the
    /// archive, read here.
    ///
    /// Names a manifest cannot carry are left out with everything below
    /// them: the ones the specification reserves in the top level for the
    /// manifest itself and its signatures silently, as `systemd-manifest`
    /// leaves them out, any other, one that is not UTF-8 for instance,
    /// counted in the report's `omitted`.
    pub fn write_manifest<S: Source + ?Sized>(
        &self,
        source: &S,
        fields: Fields,
        out: impl Write,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<WriteReport> {
        let stated = self.root_stated();
        let root = self.root();
        // The leading object is a directory by definition.
        let mut top = FileObject::root();
        if fields.contains(Fields::MODE) && stated.contains(RootStated::MODE) {
            top.mode = Mode::new(root.mode);
        }
        if fields.contains(Fields::UID) && stated.contains(RootStated::OWNER) {
            top.uid = Some(root.uid);
        }
        if fields.contains(Fields::GID) && stated.contains(RootStated::OWNER) {
            top.gid = Some(root.gid);
        }
        if fields.contains(Fields::MTIME) && stated.contains(RootStated::TIME) {
            top.set_mtime(root.modified());
        }
        if fields.contains(Fields::USER_XATTR) {
            top.user_xattrs = Some(Box::default());
        }
        let mut listing = Listing {
            tree: self,
            source,
            fields,
            writer: uapi16::Writer::begin(out, &top)?,
            report: WriteReport::default(),
            tokens: HashMap::new(),
            hashes: HashMap::new(),
            buffer: vec![0u8; HASH_BUFFER],
            progress,
        };
        listing.entries()?;
        listing.writer.finish()?;
        Ok(listing.report)
    }
}

/// The manifest of an archive while it is written.
struct Listing<'a, S: Source + ?Sized, W: Write> {
    tree: &'a Tree,
    source: &'a S,
    fields: Fields,
    writer: uapi16::Writer<W>,
    report: WriteReport,
    /// The token of every file with several names that was listed, by the
    /// number the tree has for the file.
    tokens: HashMap<u32, NonZeroU64>,
    /// The hash of every such file.
    hashes: HashMap<u32, Sha256>,
    /// What a file is read through for its hash.
    buffer: Vec<u8>,
    progress: &'a mut dyn FnMut(&Progress),
}

impl<S: Source + ?Sized, W: Write> Listing<'_, S, W> {
    /// Writes the object of every name of the tree a manifest can carry.
    fn entries(&mut self) -> Result<()> {
        // The directory that was left out last, with the slash behind it.
        let mut left_out: Option<Vec<u8>> = None;
        for (name, inode) in self.tree.entries() {
            if name == Name::ROOT.as_bytes() {
                continue;
            }
            if left_out.as_ref().is_some_and(|prefix| name.starts_with(prefix)) {
                continue;
            }
            let text = std::str::from_utf8(&name).ok();
            let reserved = text.is_some_and(uapi16::Name::is_reserved);
            let listed = text.filter(|_| !reserved).and_then(|text| uapi16::Name::new(text).ok());
            let Some(listed) = listed else {
                if !reserved {
                    self.report.omitted += 1;
                }
                if inode.kind == Kind::Directory {
                    left_out = Some([&name[..], b"/"].concat());
                }
                continue;
            };
            self.entry(listed, self.tree.inode_id(&name), inode)?;
        }
        Ok(())
    }

    /// Writes the object of the file `inode`, the one the tree numbers
    /// `id`, under the name `name`.
    fn entry(&mut self, name: uapi16::Name, id: Option<u32>, inode: &Inode) -> Result<()> {
        let fields = self.fields;
        let mut object = FileObject::new(name);
        object.inode_type = InodeType::from(inode.kind);
        // A symbolic link has neither a mode nor extended attributes in a
        // manifest.
        if fields.contains(Fields::MODE) && inode.kind != Kind::Symlink {
            object.mode = Mode::new(inode.mode);
        }
        if fields.contains(Fields::UID) {
            object.uid = Some(inode.uid);
        }
        if fields.contains(Fields::GID) {
            object.gid = Some(inode.gid);
        }
        if fields.contains(Fields::MTIME) {
            object.set_mtime(inode.modified());
        }
        if fields.contains(Fields::USER_XATTR) && inode.kind != Kind::Symlink {
            object.user_xattrs = Some(Box::default());
        }
        // A directory has one name and the kernel never links symbolic
        // links.
        let linked = inode.nlink > 1 && !matches!(inode.kind, Kind::Directory | Kind::Symlink);
        if let Some(id) = id.filter(|_| linked && fields.contains(Fields::HARDLINK)) {
            let next = NonZeroU64::MIN.saturating_add(self.tokens.len() as u64);
            object.inode_token = Some(*self.tokens.entry(id).or_insert(next));
        }
        match inode.kind {
            Kind::Regular => {
                if fields.contains(Fields::SIZE) {
                    object.size = Some(u64::from(inode.size));
                }
                if fields.contains(Fields::HASH) {
                    object.sha256 = Some(self.hash(id, inode)?);
                }
                self.report.files += 1;
                self.report.bytes += u64::from(inode.size);
            }
            Kind::Symlink => {
                if fields.contains(Fields::SIZE) {
                    object.size = Some(u64::from(inode.size));
                }
                if fields.contains(Fields::SYMLINK) {
                    let mut target = vec![0u8; inode.size as usize];
                    self.source.read_at(inode.data_offset, &mut target)?;
                    object.contents = vec![uapi16::Contents::new(Location::Literal(target))];
                }
            }
            Kind::CharDevice | Kind::BlockDevice => {
                if fields.contains(Fields::DEVICE) {
                    object.major = Some(u64::from(inode.rdev.major));
                    object.minor = Some(u64::from(inode.rdev.minor));
                }
            }
            Kind::Directory => self.report.directories += 1,
            Kind::Fifo | Kind::Socket => {}
        }
        self.writer.file(&object)?;
        (self.progress)(&self.report.progress());
        Ok(())
    }

    /// The hash of the contents of the file `inode`, read from the
    /// archive. A file with several names is read for the first of them.
    fn hash(&mut self, id: Option<u32>, inode: &Inode) -> Result<Sha256> {
        if let Some(known) = id.and_then(|id| self.hashes.get(&id)) {
            return Ok(*known);
        }
        let mut hasher = Sha256Hasher::default();
        let mut done = self.report.progress();
        let mut at = inode.data_offset;
        let end = at + u64::from(inode.size);
        while at < end {
            let n = (end - at).min(HASH_BUFFER as u64) as usize;
            self.source.read_at(at, &mut self.buffer[..n])?;
            hasher.update(&self.buffer[..n]);
            at += n as u64;
            done.bytes += n as u64;
            (self.progress)(&done);
        }
        let digest = hasher.finish();
        if let Some(id) = id.filter(|_| inode.nlink > 1) {
            self.hashes.insert(id, digest);
        }
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check;
    use crate::host::open_dir;
    use crate::plan::Role;
    use crate::test_util::{named, TempDir};
    use crate::tree::Tree;
    use crate::write;
    use std::fs;
    use std::io::Cursor;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};
    use uapi16::{MEDIA_TYPE, RECORD_SEPARATOR, TRAILER_MEDIA_TYPE};

    /// The manifest with the file objects `records` behind the leading
    /// object `root`.
    fn manifest_below(root: &str, records: &[&str]) -> Manifest {
        let trailer = format!(r#"{{"mediaType":"{}"}}"#, TRAILER_MEDIA_TYPE);
        let mut bytes = Vec::new();
        for record in [&[root][..], records, &[&trailer]].concat() {
            bytes.push(RECORD_SEPARATOR);
            bytes.extend_from_slice(record.as_bytes());
            bytes.push(b'\n');
        }
        Manifest::parse(&bytes).unwrap()
    }

    fn manifest(records: &[&str]) -> Manifest {
        manifest_below(&format!(r#"{{"mediaType":"{}"}}"#, MEDIA_TYPE), records)
    }

    fn hash(data: &[u8]) -> String {
        Sha256::of(data).to_string()
    }

    /// What `records` describe, with no contents but the ones the
    /// manifest carries.
    fn bare(records: &[&str]) -> Described {
        Described::in_stream(manifest(records), io::empty())
    }

    /// What `records` describe, with the files in the directory `tmp`.
    fn in_directory(records: &[&str], tmp: &TempDir) -> Result<Described> {
        Described::in_directory(manifest(records), SourceDirectory::new(open_dir(tmp.path()).unwrap()))
    }

    fn plan_of(records: &[&str]) -> Result<Plan> {
        let mut plan = Plan::new();
        plan.add_manifest(bare(records), named(b"."), &ManifestOptions::default())?;
        Ok(plan)
    }

    fn names(plan: &Plan) -> Vec<(String, Role)> {
        plan.steps().map(|step| (step.name.to_string(), step.role)).collect()
    }

    fn refused(records: &[&str]) -> crate::Error {
        plan_of(records).expect_err("the manifest was taken")
    }

    fn problem_of(error: &crate::Error) -> Option<ManifestProblem> {
        match error.detail() {
            Some(Detail::Manifest { problem, .. }) => Some(*problem),
            _ => None,
        }
    }

    #[test]
    fn the_objects_of_a_manifest_become_entries() {
        let file = format!(
            r#"{{"name":"d/file","size":5,"sha256":"{}","mode":416,"uid":3,"mTimeNSec":2000999999999}}"#,
            hash(b"hello")
        );
        let plan = plan_of(&[
            r#"{"name":"d","type":"dir","mode":448,"uid":1,"gid":2,"mTimeNSec":1000000000000}"#,
            &file,
            r#"{"name":"d/literal","contents":[{"literal":"aGVsbG8="}]}"#,
            r#"{"name":"d/part","contents":[{"literal":"aGVsbG8=","offset":1}],"size":3}"#,
            r#"{"name":"d/ro","size":0,"readOnly":true}"#,
            r#"{"name":"d/link","type":"lnk","contents":[{"literal":"ZmlsZQ=="}],"uid":4}"#,
            r#"{"name":"d/null","type":"chr","major":1,"minor":3,"mode":438}"#,
            r#"{"name":"d/sda","type":"blk","major":8,"minor":0}"#,
            r#"{"name":"d/fifo","type":"fifo"}"#,
            r#"{"name":"d/sock","type":"sock","mode":384}"#,
        ])
        .unwrap();
        let facts = |name: &[u8]| {
            let p = plan.get(named(name)).unwrap();
            let a = p.attributes;
            (p.kind, a.mode, (a.uid, a.gid), a.mtime, p.size)
        };
        assert_eq!(facts(b"d"), (Kind::Directory, 0o700, (1, 2), 1000, 0));
        // A time is cut to whole seconds.
        assert_eq!(facts(b"d/file"), (Kind::Regular, 0o640, (3, 0), 2000, 5));
        // What the manifest leaves out.
        assert_eq!(facts(b"d/literal"), (Kind::Regular, 0o644, (0, 0), 0, 5));
        assert_eq!(facts(b"d/part"), (Kind::Regular, 0o644, (0, 0), 0, 3));
        assert_eq!(facts(b"d/ro"), (Kind::Regular, 0o444, (0, 0), 0, 0));
        assert_eq!(facts(b"d/link"), (Kind::Symlink, 0o777, (4, 0), 0, 0));
        assert_eq!(plan.get(named(b"d/link")).unwrap().target, b"file");
        assert_eq!(facts(b"d/null"), (Kind::CharDevice, 0o666, (0, 0), 0, 0));
        assert_eq!(plan.get(named(b"d/null")).unwrap().rdev, DeviceNumber::new(1, 3));
        assert_eq!(plan.get(named(b"d/sda")).unwrap().rdev, DeviceNumber::new(8, 0));
        assert_eq!(facts(b"d/fifo").0, Kind::Fifo);
        assert_eq!(facts(b"d/sock"), (Kind::Socket, 0o600, (0, 0), 0, 0));
        assert_eq!(plan.len(), 10);
        assert!(plan.manifest().is_some());
    }

    #[test]
    fn the_options_decide_owners_and_times() {
        let records = [
            r#"{"name":"old","size":0,"uid":7,"gid":8,"mTimeNSec":1000000000000}"#,
            r#"{"name":"new","size":0,"mTimeNSec":9000000000000}"#,
            r#"{"name":"none","size":0}"#,
            r#"{"name":"sub/deep","size":0}"#,
        ];
        let with = |options: &ManifestOptions| {
            let mut plan = Plan::new();
            plan.add_manifest(bare(&records), named(b"."), options).unwrap();
            ["old", "new", "none", "sub"].map(|name| {
                let a = plan.get(named(name.as_bytes())).unwrap().attributes;
                (a.uid, a.gid, a.mtime)
            })
        };
        let at = |secs| UNIX_EPOCH + Duration::from_secs(secs);
        let defaults = ManifestOptions {
            default_time: at(5000),
            ..ManifestOptions::default()
        };
        assert_eq!(
            with(&defaults),
            [(7, 8, 1000), (0, 0, 9000), (0, 0, 5000), (0, 0, 5000)]
        );
        let clamped = ManifestOptions {
            times: TimePolicy::Clamp(at(3000)),
            uid: Some(1),
            ..defaults
        };
        assert_eq!(with(&clamped), [(1, 8, 1000), (1, 0, 3000), (1, 0, 3000), (1, 0, 3000)]);
        let fixed = ManifestOptions {
            times: TimePolicy::Fixed(at(42)),
            gid: Some(2),
            ..defaults
        };
        assert_eq!(with(&fixed), [(7, 2, 42), (0, 2, 42), (0, 2, 42), (0, 2, 42)]);
        // The leading object says what the directory itself is.
        let leading = format!(
            r#"{{"mediaType":"{}","mode":509,"uid":1000,"mTimeNSec":7000000000000}}"#,
            MEDIA_TYPE
        );
        let m = manifest_below(&leading, &[]);
        let root = ManifestOptions::default().attributes(&m.root);
        assert_eq!((root.mode, root.uid, root.gid, root.mtime), (0o775, 1000, 0, 7000));
    }

    #[test]
    fn the_objects_of_one_token_are_one_file() {
        let h = hash(b"hello");
        let a = format!(r#"{{"name":"a","size":5,"sha256":"{}","inodeToken":7}}"#, h);
        let b = format!(r#"{{"name":"sub/b","size":5,"sha256":"{}","inodeToken":7}}"#, h);
        let plan = plan_of(&[
            &a,
            r#"{"name":"c","size":5,"inodeToken":0}"#,
            r#"{"name":"f1","type":"fifo","inodeToken":8}"#,
            r#"{"name":"f2","type":"fifo","inodeToken":8}"#,
            r#"{"name":"l1","type":"lnk","contents":[{"literal":"YQ=="}],"inodeToken":9}"#,
            r#"{"name":"l2","type":"lnk","contents":[{"literal":"YQ=="}],"inodeToken":9}"#,
            &b,
        ])
        .unwrap();
        let link = |group, last| Role::Link { group, names: 2, last };
        assert_eq!(
            names(&plan),
            [
                ("a".to_string(), link(0, false)),
                ("c".to_string(), Role::Only),
                ("f1".to_string(), link(1, false)),
                ("f2".to_string(), link(1, true)),
                // The kernel never links symbolic links.
                ("l1".to_string(), Role::Only),
                ("l2".to_string(), Role::Only),
                ("sub".to_string(), Role::Only),
                ("sub/b".to_string(), link(0, true)),
            ]
        );
        // Objects that are not one file.
        for other in [
            r#"{"name":"b","size":6,"inodeToken":7}"#,
            r#"{"name":"b","size":5,"mode":384,"inodeToken":7}"#,
            r#"{"name":"b","size":5,"uid":1,"inodeToken":7}"#,
            r#"{"name":"b","size":5,"mTimeNSec":1000000000,"inodeToken":7}"#,
            r#"{"name":"b","type":"fifo","inodeToken":7}"#,
            r#"{"name":"b","size":5,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b854","inodeToken":7}"#,
        ] {
            let error = refused(&[&a, other]);
            assert_eq!(
                (error.errno(), problem_of(&error)),
                (EBADMSG, Some(ManifestProblem::Contradiction)),
                "{}",
                other
            );
        }
        let error = refused(&[
            r#"{"name":"n1","type":"chr","major":1,"minor":3,"inodeToken":7}"#,
            r#"{"name":"n2","type":"chr","major":1,"minor":5,"inodeToken":7}"#,
        ]);
        assert_eq!(error.errno(), EBADMSG);
    }

    #[test]
    fn directories_the_manifest_does_not_list_are_made() {
        let records = [
            r#"{"name":"x/y/z","size":0}"#,
            r#"{"name":"x","type":"dir","mode":448,"uid":5}"#,
            r#"{"name":"x/y/w","type":"fifo"}"#,
        ];
        let plan = plan_of(&records).unwrap();
        let listed: Vec<String> = names(&plan).into_iter().map(|(name, _)| name).collect();
        assert_eq!(listed, ["x", "x/y", "x/y/w", "x/y/z"]);
        // The object that lists a directory later says what it is.
        let x = plan.get(named(b"x")).unwrap().attributes;
        assert_eq!((x.mode, x.uid), (0o700, 5));
        let y = plan.get(named(b"x/y")).unwrap().attributes;
        assert_eq!((y.mode, y.uid), (0o755, 0));
        // Below a directory of the archive, which is made as well.
        let mut plan = Plan::new();
        plan.add_manifest(bare(&records), named(b"opt/pkg"), &ManifestOptions::default())
            .unwrap();
        let listed: Vec<String> = names(&plan).into_iter().map(|(name, _)| name).collect();
        assert_eq!(
            listed,
            [
                "opt",
                "opt/pkg",
                "opt/pkg/x",
                "opt/pkg/x/y",
                "opt/pkg/x/y/w",
                "opt/pkg/x/y/z"
            ]
        );
        assert_eq!(plan.get(named(b"opt/pkg/x")).unwrap().attributes.mode, 0o700);
    }

    #[test]
    fn what_an_archive_cannot_take_from_a_manifest() {
        let errno_and_problem = |records: &[&str]| {
            let error = refused(records);
            (error.errno(), problem_of(&error))
        };
        assert_eq!(
            errno_and_problem(&[r#"{"name":"f"}"#]),
            (EINVAL, Some(ManifestProblem::NoSize))
        );
        assert_eq!(
            errno_and_problem(&[r#"{"name":"l","type":"lnk"}"#]),
            (EINVAL, Some(ManifestProblem::NoTarget))
        );
        assert_eq!(
            errno_and_problem(&[r#"{"name":"n","type":"chr","major":1}"#]),
            (EINVAL, Some(ManifestProblem::NoDeviceNumber))
        );
        // A device number the kernel would cut.
        assert_eq!(
            refused(&[r#"{"name":"n","type":"blk","major":4096,"minor":0}"#]).errno(),
            EOVERFLOW
        );
        assert_eq!(
            refused(&[r#"{"name":"n","type":"chr","major":1,"minor":4294967296}"#]).errno(),
            EOVERFLOW
        );
        // A file larger than an archive holds.
        assert_eq!(refused(&[r#"{"name":"f","size":4294967296}"#]).errno(), EFBIG);
        plan_of(&[r#"{"name":"f","size":4294967295}"#]).unwrap();
        // Contents that would have to be fetched, and a sub-manifest.
        assert_eq!(
            refused(&[r#"{"name":"f","size":1,"contents":[{"url":"https://example.com/f"}]}"#]).errno(),
            EOPNOTSUPP
        );
        let sub = format!(r#"{{"name":"d","type":"dir","sha256":"{}"}}"#, hash(b""));
        assert_eq!(refused(&[&sub]).errno(), EOPNOTSUPP);
        // A target that is not the one the manifest describes, and one a
        // link cannot have.
        let wrong = format!(
            r#"{{"name":"l","type":"lnk","contents":[{{"literal":"ZmlsZQ=="}}],"sha256":"{}"}}"#,
            hash(b"other")
        );
        assert_eq!(refused(&[&wrong]).errno(), EBADMSG);
        assert_eq!(
            refused(&[r#"{"name":"l","type":"lnk","contents":[{"literal":""}]}"#]).errno(),
            EINVAL
        );
        let tmp = TempDir::new("manifest-links");
        symlink("somewhere", tmp.path().join("l")).unwrap();
        fs::write(tmp.path().join("f"), b"f").unwrap();
        let with_links = |record: &str| {
            let mut plan = Plan::new();
            plan.add_manifest(in_directory(&[record], &tmp)?, named(b"."), &ManifestOptions::default())
                .map(|()| plan)
        };
        let plan = with_links(r#"{"name":"l","type":"lnk","size":9}"#).unwrap();
        assert_eq!(plan.get(named(b"l")).unwrap().target, b"somewhere");
        assert_eq!(
            with_links(r#"{"name":"l","type":"lnk","size":8}"#).unwrap_err().errno(),
            EBADMSG
        );
        // What is no link where the files are, or not there.
        assert_eq!(with_links(r#"{"name":"f","type":"lnk"}"#).unwrap_err().errno(), EINVAL);
        assert_eq!(
            with_links(r#"{"name":"missing","type":"lnk"}"#).unwrap_err().errno(),
            ENOENT
        );
        // Something where a file of the manifest is.
        assert_eq!(
            refused(&[r#"{"name":"a","size":0}"#, r#"{"name":"a/b","size":0}"#]).errno(),
            ENOTDIR
        );
        // What is revoked, when the time is given to tell.
        let mut plan = Plan::new();
        let options = ManifestOptions {
            now_usec: Some(1),
            ..ManifestOptions::default()
        };
        let revoked = [r#"{"name":"f","size":0,"validity":"revoked"}"#];
        assert_eq!(
            plan.add_manifest(bare(&revoked), named(b"."), &options)
                .unwrap_err()
                .errno(),
            EKEYREVOKED
        );
        plan.add_manifest(bare(&revoked), named(b"."), &ManifestOptions::default())
            .unwrap();
        // One manifest to a plan.
        assert_eq!(
            plan.add_manifest(bare(&[]), named(b"."), &ManifestOptions::default())
                .unwrap_err()
                .errno(),
            EINVAL
        );
    }

    /// A tree, the manifest that describes it and the stream of its
    /// contents.
    fn described() -> (TempDir, Vec<String>, Vec<u8>) {
        let tmp = TempDir::new("manifest-tree");
        let root = tmp.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/conf"), b"configuration\n").unwrap();
        fs::write(root.join("big"), vec![b'b'; 70_000]).unwrap();
        fs::write(root.join("one"), b"linked").unwrap();
        fs::write(root.join("two"), b"linked").unwrap();
        symlink("etc/conf", root.join("link")).unwrap();
        let file = |name: &str, extra: &str| {
            let data = fs::read(root.join(name)).unwrap();
            format!(
                r#"{{"name":"{}","size":{},"sha256":"{}"{}}}"#,
                name,
                data.len(),
                hash(&data),
                extra
            )
        };
        let records = vec![
            file("big", ""),
            r#"{"name":"etc","type":"dir","mode":493}"#.to_string(),
            file("etc/conf", r#","mode":384"#),
            r#"{"name":"link","type":"lnk"}"#.to_string(),
            r#"{"name":"note","contents":[{"literal":"bm90ZQ=="}]}"#.to_string(),
            file("one", r#","inodeToken":1"#),
            file("two", r#","inodeToken":1"#),
        ];
        let mut stream = Vec::new();
        for name in ["big", "etc/conf", "one", "two"] {
            stream.extend(fs::read(root.join(name)).unwrap());
        }
        (tmp, records, stream)
    }

    /// The record of the link of [`described`] with its target in the
    /// manifest: a stream has no place to read it from.
    const LINK: &str = r#"{"name":"link","type":"lnk","contents":[{"literal":"ZXRjL2NvbmY="}]}"#;

    /// The plan of what `records` describe, with the files in the
    /// directory `tmp`.
    fn plan_in_directory(records: &[String], tmp: &TempDir) -> Plan {
        let records: Vec<&str> = records.iter().map(String::as_str).collect();
        let mut plan = Plan::new();
        plan.add_manifest(
            in_directory(&records, tmp).unwrap(),
            named(b"."),
            &ManifestOptions::default(),
        )
        .unwrap();
        plan
    }

    /// The plan of what `records` describe, with the contents of the
    /// files in `stream`.
    fn plan_in_stream(records: &[String], stream: &[u8]) -> Plan {
        let records: Vec<&str> = records
            .iter()
            .map(|record| if record.contains(r#""lnk""#) { LINK } else { record })
            .collect();
        let mut plan = Plan::new();
        plan.add_manifest(
            Described::in_stream(manifest(&records), Cursor::new(stream.to_vec())),
            named(b"."),
            &ManifestOptions::default(),
        )
        .unwrap();
        plan
    }

    fn written(plan: &mut Plan) -> Result<Vec<u8>> {
        let mut writer = Writer::new(Vec::new(), write::Options::default())?;
        plan.write(&mut writer, &mut |_| {})?;
        Ok(writer.finish()?.0)
    }

    #[test]
    fn the_contents_come_from_the_directory_or_from_a_stream() {
        let (tmp, records, stream) = described();
        let mut plan = plan_in_directory(&records, &tmp);
        // The link's target is read where the files are.
        assert_eq!(plan.get(named(b"link")).unwrap().target, b"etc/conf");
        let from_directory = written(&mut plan).unwrap();
        let tree = Tree::open(&from_directory[..]).unwrap();
        let data = |name: &[u8]| {
            let inode = tree.get(name).unwrap();
            &from_directory[inode.data_offset as usize..][..inode.size as usize]
        };
        assert!(data(b"big") == vec![b'b'; 70_000]);
        assert_eq!(data(b"etc/conf"), b"configuration\n");
        assert_eq!(tree.get(b"etc/conf").unwrap().mode, 0o600);
        assert_eq!(data(b"note"), b"note");
        assert_eq!(data(b"two"), b"linked");
        assert_eq!(tree.inode_id(b"one"), tree.inode_id(b"two"));
        assert_eq!(tree.get(b"one").unwrap().nlink, 2);
        assert_eq!(check::check(&from_directory[..]).unwrap().problems, []);
        // The files can be read again for a second archive.
        assert!(written(&mut plan).unwrap() == from_directory);
        // A stream gives the same archive, and is used up by it.
        let mut streamed = plan_in_stream(&records, &stream);
        assert!(written(&mut streamed).unwrap() == from_directory);
        assert_eq!(written(&mut streamed).unwrap_err().errno(), EBADMSG);
        // Contents that are not what the manifest says, in the name that
        // is written and in the one that is only read.
        for (name, problem) in [("etc/conf", ContentProblem::Hash), ("one", ContentProblem::Hash)] {
            let kept = fs::read(tmp.path().join(name)).unwrap();
            let mut other = kept.clone();
            other[0] ^= 1;
            fs::write(tmp.path().join(name), other).unwrap();
            let error = written(&mut plan).unwrap_err();
            assert_eq!(error.errno(), EBADMSG, "{}", name);
            assert!(
                matches!(error.detail(), Some(Detail::Content { problem: found, .. }) if *found == problem),
                "{}: {:?}",
                name,
                error.detail()
            );
            fs::write(tmp.path().join(name), kept).unwrap();
        }
        // A stream that ends early.
        let short = &stream[..stream.len() - 1];
        assert_eq!(
            written(&mut plan_in_stream(&records, short)).unwrap_err().errno(),
            EBADMSG
        );
        // A stream that goes on after the last file: that file got more
        // than the manifest says.
        let long = [&stream[..], b"more"].concat();
        let error = written(&mut plan_in_stream(&records, &long)).unwrap_err();
        assert_eq!(error.errno(), EBADMSG);
        assert!(
            matches!(
                error.detail(),
                Some(Detail::Content {
                    problem: ContentProblem::Size,
                    size: None,
                    expected: Some(_),
                    ..
                })
            ),
            "{:?}",
            error.detail()
        );
        // Files next to the manifest's are not its business.
        fs::write(tmp.path().join("more"), b"more").unwrap();
        assert!(written(&mut plan).unwrap() == from_directory);
        // A file the manifest names that is not where the files are, or
        // not as long as the manifest says, is found before anything is
        // planned.
        fs::write(tmp.path().join("one"), b"longer than it was").unwrap();
        let listed: Vec<&str> = records.iter().map(String::as_str).collect();
        let error = in_directory(&listed, &tmp).unwrap_err();
        assert_eq!(error.errno(), EBADMSG);
        assert!(
            matches!(error.detail(), Some(Detail::Source { .. })),
            "{:?}",
            error.detail()
        );
        fs::remove_file(tmp.path().join("one")).unwrap();
        assert_eq!(in_directory(&listed, &tmp).unwrap_err().errno(), ENOENT);
    }

    #[test]
    fn a_stream_is_taken_in_the_order_of_the_archive_only() {
        let (tmp, mut records, stream) = described();
        // The manifest lists 'etc/conf' before 'big': not the order of the
        // archive.
        records.swap(0, 2);
        records.swap(1, 2);
        // The files next to the manifest can be read in any order.
        written(&mut plan_in_directory(&records, &tmp)).unwrap();
        let error = written(&mut plan_in_stream(&records, &stream)).unwrap_err();
        assert_eq!(error.errno(), EINVAL);
        assert!(error.message().contains("order"), "{}", error.message());
        // An object of the manifest that is not written leaves its
        // contents in the stream.
        let (_tmp, records, stream) = described();
        for left_out in ["two", "big"] {
            let mut plan = plan_in_stream(&records, &stream);
            plan.retain(&mut |name, _| name != named(left_out.as_bytes()));
            assert_eq!(written(&mut plan).unwrap_err().errno(), EINVAL, "{}", left_out);
        }
    }

    fn manifest_of(archive: &[u8], fields: Fields) -> (Vec<u8>, WriteReport) {
        let tree = Tree::open(archive).unwrap();
        let mut out = Vec::new();
        let report = tree.write_manifest(archive, fields, &mut out, &mut |_| {}).unwrap();
        (out, report)
    }

    #[test]
    fn the_manifest_of_an_archive_is_the_one_it_was_made_from() {
        let h = hash(b"hello");
        let records = [
            r#"{"name":"d","type":"dir","mode":448,"uid":1,"gid":2,"mTimeNSec":1000000000000}"#.to_string(),
            format!(
                r#"{{"name":"d/a","type":"reg","mode":416,"uid":3,"gid":0,"mTimeNSec":2000000000000,"size":5,"sha256":"{}","inodeToken":1}}"#,
                h
            ),
            format!(
                r#"{{"name":"d/b","type":"reg","mode":416,"uid":3,"gid":0,"mTimeNSec":2000000000000,"size":5,"sha256":"{}","inodeToken":1}}"#,
                h
            ),
            format!(
                r#"{{"name":"d/empty","type":"reg","mode":420,"uid":0,"gid":0,"mTimeNSec":0,"size":0,"sha256":"{}"}}"#,
                hash(b"")
            ),
            r#"{"name":"d/f1","type":"fifo","mode":420,"uid":0,"gid":0,"mTimeNSec":0,"inodeToken":2}"#.to_string(),
            r#"{"name":"d/f2","type":"fifo","mode":420,"uid":0,"gid":0,"mTimeNSec":0,"inodeToken":2}"#.to_string(),
            r#"{"name":"d/link","type":"lnk","uid":4,"gid":5,"mTimeNSec":3000000000000,"size":4,"contents":[{"literal":"ZmlsZQ=="}]}"#.to_string(),
            r#"{"name":"d/null","type":"chr","mode":438,"uid":0,"gid":0,"mTimeNSec":0,"major":1,"minor":3}"#.to_string(),
            r#"{"name":"d/sda","type":"blk","mode":432,"uid":0,"gid":6,"mTimeNSec":0,"major":8,"minor":16}"#.to_string(),
            r#"{"name":"d/sock","type":"sock","mode":384,"uid":0,"gid":0,"mTimeNSec":0}"#.to_string(),
        ];
        let records: Vec<&str> = records.iter().map(String::as_str).collect();
        let given = manifest(&records);
        let mut plan = Plan::new();
        plan.add_manifest(
            Described::in_stream(given.clone(), Cursor::new(b"hellohello".to_vec())),
            named(b"."),
            &ManifestOptions::default(),
        )
        .unwrap();
        let archive = written(&mut plan).unwrap();
        // Everything an archive holds of what a manifest says.
        let held = Fields::MODE
            | Fields::UID
            | Fields::GID
            | Fields::SIZE
            | Fields::HASH
            | Fields::SYMLINK
            | Fields::DEVICE
            | Fields::HARDLINK
            | Fields::MTIME;
        let (bytes, report) = manifest_of(&archive, held);
        let back = Manifest::parse(&bytes).unwrap();
        assert_eq!(back.objects, given.objects);
        assert_eq!(
            (report.files, report.directories, report.bytes, report.omitted),
            (3, 1, 10, 0)
        );
        // The root says nothing here, the archive has no entry for it.
        assert_eq!(
            (back.root.mode, back.root.uid, back.root.mtime_nsec),
            (None, None, None)
        );
        // Asked for extended attributes, the manifest says that there are
        // none. A symbolic link has none to speak of.
        let (bytes, _) = manifest_of(&archive, Fields::ALL);
        let all = Manifest::parse(&bytes).unwrap();
        assert_eq!(all.root.user_xattrs, Some(Box::default()));
        for (object, given) in all.objects.iter().zip(&given.objects) {
            let none = (object.inode_type != InodeType::Symlink).then(Box::default);
            assert_eq!(object.user_xattrs, none, "{}", object.name);
            let mut rest = object.clone();
            rest.user_xattrs = None;
            assert_eq!(rest, *given);
        }
        // Without fields there are names and types. A regular file is what
        // an object without a type is.
        let (bytes, _) = manifest_of(&archive, Fields::NONE);
        let text = String::from_utf8(bytes).unwrap();
        let bare: Vec<&str> = text
            .split(char::from(RECORD_SEPARATOR))
            .skip(2)
            .map(str::trim_end)
            .collect();
        assert_eq!(bare[0], r#"{"name":"d","type":"dir"}"#);
        assert_eq!(bare[1], r#"{"name":"d/a"}"#);
        assert_eq!(bare[6], r#"{"name":"d/link","type":"lnk"}"#);
        assert_eq!(bare.len(), 11);
    }

    #[test]
    fn the_root_and_names_a_manifest_cannot_carry() {
        use crate::test_util::{archive, Raw};
        let bytes = archive(&[
            Raw::new(0o040750, b".").owner(7, 8).mtime(9),
            Raw::new(0o100644, b"Uapi16Manifest").data(b"m"),
            Raw::new(0o100644, b"Uapi16Manifest.p7s").data(b"s"),
            Raw::new(0o100644, b"fine").data(b"f"),
            Raw::new(0o100644, b"not-utf8-\xff").data(b"x"),
            Raw::new(0o040755, b"new\nline"),
            Raw::new(0o100644, b"new\nline/below").data(b"y"),
            Raw::new(0o100644, b"new\nline/more").data(b"z"),
            Raw::new(0o040755, b"sub"),
            Raw::new(0o100644, b"sub/Uapi16Manifest").data(b"k"),
        ]);
        let (out, report) = manifest_of(&bytes, Fields::ALL);
        let m = Manifest::parse(&out).unwrap();
        let listed: Vec<&str> = m.objects.iter().map(|object| object.name.as_str()).collect();
        // The reserved names go silently, in the top level only. The
        // others are counted, a directory with what is in it once.
        assert_eq!(listed, ["fine", "sub", "sub/Uapi16Manifest"]);
        assert_eq!(report.omitted, 2);
        assert_eq!(
            (m.root.mode.map(Mode::bits), m.root.uid, m.root.gid, m.root.mtime()),
            (Some(0o750), Some(7), Some(8), Some(UNIX_EPOCH + Duration::from_secs(9)))
        );
    }
}
