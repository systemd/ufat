// SPDX-License-Identifier: LGPL-2.1-or-later
//! What is going to be in an archive, worked out before a byte of it is
//! written.
//!
//! A [`Plan`] collects the entries of host trees and then knows three
//! things a writer needs up front: the order of the entries, which names
//! are one hard-linked file and which of them comes last, and how long
//! the archive gets, to the byte.
//!
//! The order is the same whatever order the entries come in: a directory
//! right before what is in it, each directory's entries sorted by the
//! bytes of their names. That is the order the trees are walked in and the
//! order of a UAPI.16 manifest, and it puts every directory before what
//! is in it, which the kernel needs.
//!
//! Everything an archive cannot hold is found here, while nothing is
//! written: a file that is too large, a name the kernel would drop, a
//! device number it would truncate.

use std::collections::{btree_map, BTreeMap, HashMap};
use std::fs::{File, Metadata};
use std::num::NonZeroU64;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::time::UNIX_EPOCH;

use crate::errno::*;
use crate::header::{DeviceNumber, Kind, MAX_FILE_SIZE, PERMISSIONS};
use crate::host::{walk_with, HostEntry};
use crate::manifest::{Described, Manifest};
use crate::name::{Name, NameBuf};
use crate::sys;
use crate::times::TimePolicy;
use crate::tree::{Key, KeyBuf};
use crate::write::{self, Attributes, Cursor};
use crate::{Context, Detail, Result};

/// How the entries of a host tree are taken into a plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeOptions {
    /// Which modification times the entries get.
    pub times: TimePolicy,
    /// The owning user of every entry, instead of the one it has.
    pub uid: Option<u32>,
    /// The owning group of every entry, instead of the one it has.
    pub gid: Option<u32>,
    /// Replace an entry that is planned already with one of the same name
    /// instead of failing with EEXIST.
    pub replace: bool,
}

impl Default for TreeOptions {
    fn default() -> TreeOptions {
        TreeOptions {
            times: TimePolicy::Preserve,
            uid: None,
            gid: None,
            replace: true,
        }
    }
}

impl TreeOptions {
    /// Permissions, owner and time of something on the host, as an entry
    /// carries them.
    pub fn attributes(&self, md: &Metadata) -> Attributes {
        Attributes {
            mode: md.mode() & PERMISSIONS,
            uid: self.uid.unwrap_or(md.uid()),
            gid: self.gid.unwrap_or(md.gid()),
            mtime: Attributes::seconds(self.times.resolve(md.modified().unwrap_or(UNIX_EPOCH))),
        }
    }
}

/// Where the contents of a planned regular file are.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Contents {
    /// In a file of a host tree: the tree by its position in the plan,
    /// how much of the entry's name is the directory the tree went below,
    /// and the file that was seen there.
    Host { root: u32, strip: u32, dev: u64, ino: u64 },
    /// In an open file the plan holds, by its position there.
    File { index: u32 },
    /// Where the manifest of the plan has them, by the position of the
    /// object in the manifest.
    Manifest { object: u32 },
    /// Nowhere: the entry is no regular file.
    None,
}

/// What can have several names: a file on the host by its device and
/// inode number, an inode of a manifest by its token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Identity {
    Host(u64, u64),
    Manifest(NonZeroU64),
}

/// An entry of a plan.
#[derive(Clone, Debug)]
pub struct Planned {
    /// What it is.
    pub kind: Kind,
    /// Permissions, owner and time.
    pub attributes: Attributes,
    /// The length of a regular file's contents.
    pub size: u64,
    /// The device number of a device node.
    pub rdev: DeviceNumber,
    /// The target of a symbolic link.
    pub target: Vec<u8>,
    /// The file itself, for what can have several names: the entries of
    /// a plan with the same one are hard links of each other.
    pub(crate) identity: Option<Identity>,
    pub(crate) contents: Contents,
}

impl Planned {
    /// An entry of the kind `kind` with nothing to it but `attributes`.
    pub(crate) fn new(kind: Kind, attributes: Attributes) -> Planned {
        Planned {
            kind,
            attributes,
            size: 0,
            rdev: DeviceNumber::NONE,
            target: Vec::new(),
            identity: None,
            contents: Contents::None,
        }
    }

    /// The entry for what a walk found on the host, which goes to
    /// `target`. `root` is the tree it was found in, by its position in
    /// the plan, and `strip` how much of `target` is the directory the
    /// tree goes below.
    fn from_host(target: Name<'_>, entry: &HostEntry, options: &TreeOptions, root: u32, strip: u32) -> Result<Planned> {
        let md = &entry.metadata;
        let ft = md.file_type();
        let kind = if ft.is_file() {
            Kind::Regular
        } else if ft.is_dir() {
            Kind::Directory
        } else if ft.is_symlink() {
            Kind::Symlink
        } else if ft.is_char_device() {
            Kind::CharDevice
        } else if ft.is_block_device() {
            Kind::BlockDevice
        } else if ft.is_fifo() {
            Kind::Fifo
        } else if ft.is_socket() {
            Kind::Socket
        } else {
            bail!(EINVAL, "{} is of no file type an archive holds", entry.path.display());
        };
        let mut planned = Planned::new(kind, options.attributes(md));
        match kind {
            Kind::Regular => {
                if md.len() > MAX_FILE_SIZE {
                    bail!(
                        EFBIG,
                        Detail::TooLarge {
                            path: Some(target.to_string()),
                            size: md.len(),
                            maximum: MAX_FILE_SIZE,
                        },
                        "{} has {} bytes, more than the {} a cpio archive can hold",
                        entry.path.display(),
                        md.len(),
                        MAX_FILE_SIZE
                    );
                }
                planned.size = md.len();
                planned.contents = Contents::Host {
                    root,
                    strip,
                    dev: md.dev(),
                    ino: md.ino(),
                };
            }
            Kind::Symlink => {
                planned.target = entry.read_link()?;
                target.check_target(&planned.target)?;
            }
            Kind::CharDevice | Kind::BlockDevice => {
                let (major, minor) = sys::devnum_parts(md.rdev());
                planned.rdev = DeviceNumber::saturating(major, minor);
                target.check_node(kind, planned.rdev)?;
            }
            Kind::Directory | Kind::Fifo | Kind::Socket => {}
        }
        // A directory has one name and the kernel never links symbolic links.
        if md.nlink() > 1 && !matches!(kind, Kind::Directory | Kind::Symlink) {
            planned.identity = Some(Identity::Host(md.dev(), md.ino()));
        }
        Ok(planned)
    }
}

#[cfg(test)]
impl Planned {
    /// A planned node, for the tests of rules that only look at what an
    /// entry is.
    pub(crate) fn for_test(kind: Kind, rdev: DeviceNumber) -> Planned {
        Planned {
            rdev,
            ..Planned::new(kind, Attributes::default())
        }
    }
}

/// What a name of a plan is to the file it leads to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The one name of its file.
    Only,
    /// One of several names, numbered in the order the names come, and
    /// whether it is the last. The last one carries the contents.
    Link {
        /// Which hard-linked file of the plan, counting from 0.
        group: u32,
        /// How many names the file has.
        names: u32,
        /// Whether this is the last of them.
        last: bool,
    },
}

impl Role {
    /// Whether the name is the one that carries the contents of its
    /// file: the only one, or the last of several.
    pub fn carries_contents(self) -> bool {
        !matches!(self, Role::Link { last: false, .. })
    }
}

/// An entry of a plan as [`Plan::steps`] hands it out.
#[derive(Clone, Debug)]
pub struct Step<'a> {
    /// The name of the entry.
    pub name: NameBuf,
    /// What is planned for it.
    pub planned: &'a Planned,
    /// What the name is to its file.
    pub role: Role,
}

/// A file with several names while the entries of a plan are gone
/// through.
#[derive(Clone, Copy, Debug, Default)]
struct Group {
    /// How many names the plan has for the file.
    names: u32,
    /// How many of them were handed out.
    seen: u32,
    /// Which hard-linked file of the plan it is, counting from 0.
    number: u32,
}

/// The entries of a plan in the order of the archive, see
/// [`Plan::steps`].
#[derive(Debug)]
pub struct Steps<'a> {
    entries: btree_map::Iter<'a, Box<[u8]>, Planned>,
    /// The files with several names.
    groups: HashMap<Identity, Group>,
    /// The number the next hard-linked file gets.
    next: u32,
}

impl<'a> Iterator for Steps<'a> {
    type Item = Step<'a>;

    fn next(&mut self) -> Option<Step<'a>> {
        let (key, planned) = self.entries.next()?;
        let role = match planned.identity.and_then(|identity| self.groups.get_mut(&identity)) {
            Some(group) if group.names > 1 => {
                if group.seen == 0 {
                    group.number = self.next;
                    self.next += 1;
                }
                group.seen += 1;
                Role::Link {
                    group: group.number,
                    names: group.names,
                    last: group.seen == group.names,
                }
            }
            _ => Role::Only,
        };
        Some(Step {
            name: NameBuf::from_checked(Key::new(key).name()),
            planned,
            role,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for Steps<'_> {}

/// What a plan amounts to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Measure {
    /// The length of the archive, with the trailer and the padding of its
    /// end.
    pub len: u64,
    /// Where the trailer starts in the archive.
    pub trailer: u64,
    /// Regular files, each counted once whatever the number of its names.
    pub files: u64,
    /// Directories, the root not among them.
    pub directories: u64,
    /// The bytes of the regular files.
    pub bytes: u64,
}

/// The entries an archive is going to have.
#[derive(Debug, Default)]
pub struct Plan {
    /// By the key of [`crate::tree`], which is the order of the archive.
    entries: BTreeMap<Box<[u8]>, Planned>,
    /// The directories the trees were read from, pinned.
    roots: Vec<OwnedFd>,
    /// The files that were planned one by one, open.
    files: Vec<File>,
    /// The manifest entries were planned from, with where the contents of
    /// its files are. A plan has one at most.
    pub(crate) described: Option<Described>,
}

impl Plan {
    /// A plan without entries.
    pub fn new() -> Plan {
        Plan::default()
    }

    /// Whether nothing is planned.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many entries are planned.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// What is planned at `name`.
    pub fn get(&self, name: Name<'_>) -> Option<&Planned> {
        self.entries.get(KeyBuf::of(name.as_bytes()).as_bytes())
    }

    /// Puts an entry into the plan. A directory that is planned already
    /// stays as it is. Anything else replaces what is planned under its
    /// name when `replace` allows it, and a directory and something that is
    /// none never replace each other.
    pub(crate) fn insert(&mut self, name: Name<'_>, planned: Planned, replace: bool) -> Result<()> {
        let key = KeyBuf::of(name.as_bytes()).into_bytes();
        match self.entries.get(&key[..]).map(|p| p.kind) {
            None => {}
            Some(Kind::Directory) if planned.kind == Kind::Directory => return Ok(()),
            Some(Kind::Directory) => bail!(EISDIR, Detail::from(name), "'{}' is a directory", name),
            Some(_) if planned.kind == Kind::Directory => {
                bail!(ENOTDIR, Detail::from(name), "'{}' is not a directory", name)
            }
            Some(_) if !replace => bail!(EEXIST, Detail::from(name), "'{}' exists", name),
            Some(_) => {}
        }
        self.entries.insert(key.into(), planned);
        Ok(())
    }

    /// Plans the directory `name` with `attributes`, the root as `.`. One
    /// that is planned already stays as it is.
    pub fn add_directory(&mut self, name: Name<'_>, attributes: Attributes) -> Result<()> {
        self.insert(name, Planned::new(Kind::Directory, attributes), true)
    }

    /// Plans the open regular file `file` as `name`, read from its first
    /// byte when the archive is written. Its permissions, owner and time
    /// are the file's, as `options` passes them on.
    pub fn add_file(&mut self, name: Name<'_>, file: File, options: &TreeOptions) -> Result<()> {
        let md = file.metadata()?;
        if !md.is_file() {
            bail!(EINVAL, "the source of '{}' is not a regular file", name);
        }
        if md.len() > MAX_FILE_SIZE {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: Some(name.to_string()),
                    size: md.len(),
                    maximum: MAX_FILE_SIZE,
                },
                "the source of '{}' has {} bytes, more than the {} a cpio archive can hold",
                name,
                md.len(),
                MAX_FILE_SIZE
            );
        }
        let index = u32::try_from(self.files.len()).map_err(|_| err!(E2BIG, "too many source files"))?;
        let planned = Planned {
            size: md.len(),
            contents: Contents::File { index },
            ..Planned::new(Kind::Regular, options.attributes(&md))
        };
        self.insert(name, planned, options.replace)?;
        self.files.push(file);
        Ok(())
    }

    /// Takes out of the plan every entry `keep` says no to.
    pub fn retain(&mut self, keep: &mut dyn FnMut(Name<'_>, &Planned) -> bool) {
        self.entries
            .retain(|key, planned| keep(Name::from_checked(&Key::new(key).name()), planned));
    }

    /// Plans everything below the open directory `root`, the entries going
    /// below the directory `dest` of the archive, `.` for its root. The
    /// directory `dest` itself is not planned here.
    ///
    /// The tree is walked by descriptor, in the order of the archive, and
    /// nothing is read but names, metadata and the targets of symbolic
    /// links. The descriptor is kept: the contents of the files are read
    /// through it when the archive is written, and a file that is not the
    /// one seen here by then fails the writing.
    pub fn add_tree(&mut self, root: BorrowedFd<'_>, dest: Name<'_>, options: &TreeOptions) -> Result<()> {
        if !sys::fstat(root)
            .with_context(|| "failed to stat the source directory")?
            .is_dir()
        {
            bail!(ENOTDIR, "the source is not a directory");
        }
        let index = u32::try_from(self.roots.len()).map_err(|_| err!(E2BIG, "too many source trees"))?;
        self.roots.push(root.try_clone_to_owned()?);
        // What a name has before the path of its file below `root`: the
        // directory and the slash behind it.
        let strip = if dest.is_root() {
            0
        } else {
            dest.as_bytes().len() as u32 + 1
        };
        walk_with(
            root,
            NameBuf::from(dest),
            false,
            &mut |parent: &NameBuf, _, name| parent.as_name().join(name),
            &mut |target, entry| {
                let target = target.as_name();
                let planned = Planned::from_host(target, entry, options, index, strip)?;
                let descend = planned.kind == Kind::Directory;
                self.insert(target, planned, options.replace)?;
                Ok(descend)
            },
        )
    }

    /// The entries in the order of the archive, each with what its name
    /// is to its file. A name is a link when the plan has another one for
    /// the same file. What has one name in the plan is a file of its own,
    /// however many names it has on the host.
    pub fn steps(&self) -> Steps<'_> {
        let mut groups: HashMap<Identity, Group> = HashMap::new();
        for identity in self.entries.values().filter_map(|planned| planned.identity) {
            groups.entry(identity).or_default().names += 1;
        }
        Steps {
            entries: self.entries.iter(),
            groups,
            next: 0,
        }
    }

    /// What the plan amounts to in an archive laid out with `options`
    /// whose entries start at `offset`: at 0 for a new archive, where the
    /// trailer was for one that is added to. Also refuses a plan the
    /// kernel could not unpack: one with an entry whose directory is
    /// neither planned nor among `existing`, the directories that are in
    /// the archive already.
    pub fn measure(
        &self,
        options: &write::Options,
        offset: u64,
        existing: &dyn Fn(Name<'_>) -> bool,
    ) -> Result<Measure> {
        options.check()?;
        let mut cursor = Cursor::new(*options, offset);
        let mut measure = Measure::default();
        for key in self.entries.keys() {
            // The root is there before anything is unpacked.
            let key = Key::new(key);
            if let Some(parent) = key.parent().filter(|parent| !parent.is_root()) {
                let planned_directory = self
                    .entries
                    .get(parent.as_bytes())
                    .is_some_and(|p| p.kind == Kind::Directory);
                let parent = parent.name();
                let parent = Name::from_checked(&parent);
                if !planned_directory && !existing(parent) {
                    bail!(
                        ENOENT,
                        Detail::from(parent),
                        "the directory of '{}' is not there",
                        Name::from_checked(&key.name())
                    );
                }
            }
        }
        for Step { name, planned, role } in self.steps() {
            let name = name.as_name();
            let carries = role.carries_contents();
            let filesize = match planned.kind {
                Kind::Regular if carries => planned.size,
                Kind::Symlink => planned.target.len() as u64,
                _ => 0,
            };
            cursor.place(name.as_bytes().len(), planned.kind, filesize as u32);
            match planned.kind {
                Kind::Regular if carries => {
                    measure.files += 1;
                    measure.bytes += planned.size;
                }
                Kind::Directory if !name.is_root() => measure.directories += 1,
                _ => {}
            }
        }
        if self.entries.len() as u64 >= u64::from(u32::MAX) {
            bail!(
                EOVERFLOW,
                "the archive would have more entries than the format can number"
            );
        }
        measure.trailer = cursor.offset();
        measure.len = cursor.finish();
        Ok(measure)
    }

    /// The directory a planned file of a host tree is read below, and its
    /// path there.
    fn host_path<'a>(&self, name: Name<'a>, root: u32, strip: u32) -> (BorrowedFd<'_>, &'a [u8]) {
        (self.roots[root as usize].as_fd(), &name.as_bytes()[strip as usize..])
    }

    /// Opens the file the entry `planned` at `name` was made for, and
    /// makes sure it still is the file that was planned.
    pub(crate) fn open(&self, name: Name<'_>, planned: &Planned) -> Result<File> {
        let changed = |shown: &str| {
            err!(
                ESTALE,
                "{} changed while the archive was written: it is not the file of {} bytes that was there",
                shown,
                planned.size
            )
        };
        match planned.contents {
            Contents::Host { root, strip, dev, ino } => {
                let (root, path) = self.host_path(name, root, strip);
                let shown = String::from_utf8_lossy(path);
                let pinned =
                    sys::chase(root, path, false, false).with_context(|| format!("failed to open {}", shown))?;
                let md = sys::fstat(pinned.as_fd()).with_context(|| format!("failed to stat {}", shown))?;
                if !md.is_file() || (md.dev(), md.ino()) != (dev, ino) || md.len() != planned.size {
                    return Err(changed(&shown));
                }
                let fd = sys::reopen(pinned.as_fd(), sys::O_RDONLY | sys::O_NONBLOCK | sys::O_NOCTTY)
                    .with_context(|| format!("failed to open {}", shown))?;
                Ok(File::from(fd))
            }
            Contents::File { index } => {
                let file = &self.files[index as usize];
                if file.metadata()?.len() != planned.size {
                    return Err(changed(&format!("the source of '{}'", name)));
                }
                Ok(file.try_clone()?)
            }
            Contents::Manifest { .. } | Contents::None => bail!(EINVAL, "'{}' has no contents to read", name),
        }
    }

    /// The manifest entries were planned from.
    pub fn manifest(&self) -> Option<&Manifest> {
        self.described.as_ref().map(Described::manifest)
    }

    /// Gives the directory that is planned at `name` the attributes
    /// `attributes`.
    pub(crate) fn restate_directory(&mut self, name: Name<'_>, attributes: Attributes) {
        if let Some(planned) = self.entries.get_mut(KeyBuf::of(name.as_bytes()).as_bytes()) {
            if planned.kind == Kind::Directory {
                planned.attributes = attributes;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::open_dir;
    use crate::test_util::{named, TempDir};
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::time::Duration;

    fn tree() -> TempDir {
        let tmp = TempDir::new("plan");
        let root = tmp.path();
        fs::create_dir_all(root.join("d/sub")).unwrap();
        fs::write(root.join("d/file"), b"hello\n").unwrap();
        fs::write(root.join("a"), b"x").unwrap();
        fs::hard_link(root.join("a"), root.join("d/hl1")).unwrap();
        fs::hard_link(root.join("a"), root.join("hl2")).unwrap();
        symlink("d/file", root.join("sym")).unwrap();
        fs::write(root.join("zero"), b"").unwrap();
        fs::write(root.join("a.b"), b"dot").unwrap();
        fs::set_permissions(root.join("d/file"), fs::Permissions::from_mode(0o4750)).unwrap();
        tmp
    }

    fn names(plan: &Plan) -> Vec<(String, Role)> {
        plan.steps().map(|step| (step.name.to_string(), step.role)).collect()
    }

    #[test]
    fn a_tree_is_planned_in_the_order_of_the_archive() {
        let tmp = tree();
        let root = open_dir(tmp.path()).unwrap();
        let mut plan = Plan::new();
        plan.add_tree(root.as_fd(), named(b"."), &TreeOptions::default())
            .unwrap();
        let link = |last| Role::Link {
            group: 0,
            names: 3,
            last,
        };
        assert_eq!(
            names(&plan),
            [
                ("a".to_string(), link(false)),
                ("a.b".to_string(), Role::Only),
                ("d".to_string(), Role::Only),
                ("d/file".to_string(), Role::Only),
                ("d/hl1".to_string(), link(false)),
                ("d/sub".to_string(), Role::Only),
                ("hl2".to_string(), link(true)),
                ("sym".to_string(), Role::Only),
                ("zero".to_string(), Role::Only),
            ]
        );
        let file = plan.get(named(b"d/file")).unwrap();
        assert_eq!((file.kind, file.size, file.attributes.mode), (Kind::Regular, 6, 0o4750));
        assert_eq!(plan.get(named(b"sym")).unwrap().target, b"d/file");
        assert_eq!(plan.get(named(b"d")).unwrap().kind, Kind::Directory);
        assert_eq!(plan.len(), 9);
        let measure = plan.measure(&write::Options::default(), 0, &|_| false).unwrap();
        // The file with three names counts once, with its last name.
        assert_eq!(
            measure,
            Measure {
                len: 1536,
                trailer: measure.trailer,
                files: 4,
                directories: 2,
                bytes: 6 + 1 + 3,
            }
        );
        // The trailer is all that follows the entries but padding.
        assert_eq!(measure.len, (measure.trailer + 124).div_ceil(512) * 512);
    }

    #[test]
    fn owners_and_times_follow_the_options() {
        let tmp = tree();
        let root = open_dir(tmp.path()).unwrap();
        let stamp = UNIX_EPOCH + Duration::from_secs(1000);
        let mut plan = Plan::new();
        let options = TreeOptions {
            times: TimePolicy::Fixed(stamp),
            uid: Some(7),
            gid: Some(8),
            replace: true,
        };
        plan.add_tree(root.as_fd(), named(b"."), &options).unwrap();
        for step in plan.steps() {
            let a = step.planned.attributes;
            assert_eq!((a.uid, a.gid, a.mtime), (7, 8, 1000));
        }
        // Clamping keeps what is older.
        let mut plan = Plan::new();
        let options = TreeOptions {
            times: TimePolicy::Clamp(stamp),
            ..TreeOptions::default()
        };
        plan.add_tree(root.as_fd(), named(b"."), &options).unwrap();
        assert_eq!(plan.get(named(b"a")).unwrap().attributes.mtime, 1000);
        assert_eq!(Attributes::seconds(UNIX_EPOCH - Duration::from_secs(5)), 0);
        assert_eq!(Attributes::seconds(UNIX_EPOCH + Duration::from_secs(1 << 33)), u32::MAX);
        assert_eq!(
            Attributes::seconds(UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX))),
            u32::MAX
        );
    }

    #[test]
    fn a_tree_goes_below_a_directory() {
        let tmp = tree();
        let root = open_dir(tmp.path().join("d").as_path()).unwrap();
        let mut plan = Plan::new();
        plan.add_tree(root.as_fd(), named(b"usr/lib"), &TreeOptions::default())
            .unwrap();
        assert_eq!(
            names(&plan).into_iter().map(|(name, _)| name).collect::<Vec<_>>(),
            ["usr/lib/file", "usr/lib/hl1", "usr/lib/sub"]
        );
        // With one name in the plan the file is no link, whatever it is on
        // the host.
        assert!(names(&plan).iter().all(|(_, role)| *role == Role::Only));
        // The directory the tree goes below has to come from somewhere.
        let error = plan.measure(&write::Options::default(), 0, &|_| false).unwrap_err();
        assert_eq!(error.errno(), ENOENT);
        assert_eq!(error.detail(), Some(&Detail::Path("usr/lib".into())));
        plan.measure(&write::Options::default(), 0, &|name| name == named(b"usr/lib"))
            .unwrap();
        let attributes = Attributes {
            mode: 0o755,
            ..Attributes::default()
        };
        plan.add_directory(named(b"usr"), attributes).unwrap();
        plan.add_directory(named(b"usr/lib"), attributes).unwrap();
        plan.measure(&write::Options::default(), 0, &|_| false).unwrap();
        // Where the contents are read on the host.
        let Contents::Host { root: index, strip, .. } = plan.get(named(b"usr/lib/file")).unwrap().contents else {
            panic!("no contents");
        };
        assert_eq!(plan.host_path(named(b"usr/lib/file"), index, strip).1, b"file");
    }

    #[test]
    fn trees_are_laid_over_each_other() {
        let first = tree();
        let second = TempDir::new("plan-second");
        fs::create_dir(second.path().join("d")).unwrap();
        fs::write(second.path().join("d/file"), b"replaced").unwrap();
        fs::write(second.path().join("new"), b"new").unwrap();
        let mut plan = Plan::new();
        plan.add_tree(
            open_dir(first.path()).unwrap().as_fd(),
            named(b"."),
            &TreeOptions::default(),
        )
        .unwrap();
        plan.add_tree(
            open_dir(second.path()).unwrap().as_fd(),
            named(b"."),
            &TreeOptions::default(),
        )
        .unwrap();
        assert_eq!(plan.get(named(b"d/file")).unwrap().size, 8);
        assert_eq!(plan.get(named(b"new")).unwrap().size, 3);
        assert_eq!(plan.len(), 10);
        // Without replacing, the same name twice is refused.
        let mut plan = Plan::new();
        let keep = TreeOptions {
            replace: false,
            ..TreeOptions::default()
        };
        plan.add_tree(open_dir(first.path()).unwrap().as_fd(), named(b"."), &keep)
            .unwrap();
        let error = plan
            .add_tree(open_dir(second.path()).unwrap().as_fd(), named(b"."), &keep)
            .unwrap_err();
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(error.detail(), Some(&Detail::Path("d/file".into())));
        // A file where a directory is planned, and the other way around.
        let third = TempDir::new("plan-third");
        fs::write(third.path().join("d"), b"a file").unwrap();
        fs::create_dir(third.path().join("a")).unwrap();
        let mut plan = Plan::new();
        plan.add_tree(
            open_dir(first.path()).unwrap().as_fd(),
            named(b"."),
            &TreeOptions::default(),
        )
        .unwrap();
        let error = plan
            .add_tree(
                open_dir(third.path()).unwrap().as_fd(),
                named(b"."),
                &TreeOptions::default(),
            )
            .unwrap_err();
        assert_eq!(error.errno(), ENOTDIR);
    }

    #[test]
    fn what_an_archive_cannot_hold_is_found_while_planning() {
        let tmp = TempDir::new("plan-bad");
        fs::write(tmp.path().join("TRAILER!!!"), b"").unwrap();
        let mut plan = Plan::new();
        let error = plan
            .add_tree(
                open_dir(tmp.path()).unwrap().as_fd(),
                named(b"."),
                &TreeOptions::default(),
            )
            .unwrap_err();
        assert!(matches!(error.detail(), Some(Detail::Name { .. })));
        // Below a directory the name is fine.
        let mut plan = Plan::new();
        plan.add_tree(
            open_dir(tmp.path()).unwrap().as_fd(),
            named(b"d"),
            &TreeOptions::default(),
        )
        .unwrap();
        assert!(plan.get(named(b"d/TRAILER!!!")).is_some());
        // A file of four gigabytes, without writing one.
        let tmp = TempDir::new("plan-large");
        File::create(tmp.path().join("huge")).unwrap().set_len(1 << 32).unwrap();
        File::create(tmp.path().join("fits"))
            .unwrap()
            .set_len((1 << 32) - 1)
            .unwrap();
        let mut plan = Plan::new();
        let error = plan
            .add_tree(
                open_dir(tmp.path()).unwrap().as_fd(),
                named(b"."),
                &TreeOptions::default(),
            )
            .unwrap_err();
        assert_eq!(error.errno(), EFBIG);
        assert!(matches!(error.detail(), Some(Detail::TooLarge { size, .. }) if *size == 1 << 32));
        // A path that gets too long below where it goes.
        let tmp = TempDir::new("plan-long");
        fs::write(tmp.path().join("f"), b"").unwrap();
        let mut dest = vec![b'd'; 255];
        while dest.len() + 256 < 4095 {
            dest.push(b'/');
            dest.extend([b'd'; 255]);
        }
        dest.push(b'/');
        dest.extend(vec![b'd'; 4094 - dest.len()]);
        assert_eq!(dest.len(), 4094);
        let mut plan = Plan::new();
        let error = plan
            .add_tree(
                open_dir(tmp.path()).unwrap().as_fd(),
                named(&dest),
                &TreeOptions::default(),
            )
            .unwrap_err();
        assert_eq!(error.errno(), ENAMETOOLONG);
    }

    #[test]
    fn the_measure_is_the_length_the_writer_writes() {
        let tmp = tree();
        let root = open_dir(tmp.path()).unwrap();
        let mut plan = Plan::new();
        plan.add_directory(
            named(b"."),
            Attributes {
                mode: 0o755,
                ..Attributes::default()
            },
        )
        .unwrap();
        plan.add_tree(root.as_fd(), named(b"."), &TreeOptions::default())
            .unwrap();
        // The root, nine entries and the trailer, by hand: every header is
        // 110 bytes, names and data are padded to four.
        let entry = |name: usize, data: usize| (110 + name + 1).next_multiple_of(4) + data.next_multiple_of(4);
        let by_hand = entry(1, 0)
            + entry(1, 0)
            + entry(1, 0)
            + entry(6, 6)
            + entry(5, 0)
            + entry(5, 0)
            + entry(3, 3)
            + entry(3, 1)
            + entry(3, 6)
            + entry(4, 0)
            + 124;
        let options = write::Options {
            end_alignment: 4,
            ..write::Options::default()
        };
        let measure = plan.measure(&options, 0, &|_| false).unwrap();
        assert_eq!((measure.len, measure.trailer), (by_hand as u64, by_hand as u64 - 124));
        // Entries that start further into an archive take as much room.
        let measure = plan.measure(&options, 1000, &|_| false).unwrap();
        assert_eq!(
            (measure.len, measure.trailer),
            (1000 + by_hand as u64, 876 + by_hand as u64)
        );
        let bad = write::Options {
            end_alignment: 3,
            ..write::Options::default()
        };
        assert!(plan.measure(&bad, 0, &|_| false).is_err());
    }
}
