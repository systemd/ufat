// SPDX-License-Identifier: LGPL-2.1-or-later
//! What an archive unpacks to.
//!
//! An archive is a log. The kernel takes one entry after the other and
//! does to its root file system what the entry says, so what is there in
//! the end depends on the order: a later entry replaces an earlier one of
//! the same name, an entry whose directory is not there yet is lost, a
//! name of a hard-linked file is a link to whatever its first name is by
//! then. [`Replay`] does to a tree in memory what the kernel does to the
//! file system, rule for rule (init/initramfs.c), and reports what the
//! kernel does without saying so, see [`Finding`].
//!
//! The tree is as large as the archive has entries, in memory. Every step
//! is a lookup in an ordered map, so an archive of n entries takes
//! n log n steps whatever its entries are.
//!
//! Two things the kernel resolves when it unpacks are not followed here: a
//! `..` in a name, and a name that leads through a symbolic link. Entries
//! with either are reported and left out, and [`Tree::approximate`] says
//! so.
//!
//! The contents of the files are not read. The kernel stops unpacking at
//! the first file whose checksum does not hold, which only the `070702`
//! form can have: [`crate::check`] finds that, and the tree is what such
//! an archive would unpack to if every checksum held.
//!
//! The rules are held against what kernels did with the archives in
//! tests/fixtures/cpio, see tests/cpio_kernel.rs.

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use crate::errno::*;
use crate::header::{DeviceNumber, Format, Header, Kind, MAX_TARGET_LEN, PERMISSIONS, S_IFMT};
use crate::name::{Ending, Form, Name, Normalized, Unusable};
use crate::read::{Damage, End, Record, Scanner, Skip, Source, Standing};
use crate::Result;

/// The most entries a tree holds. An archive with more is refused: the
/// tree is kept in memory, and this bounds it to a few gigabytes.
pub const MAX_ENTRIES: u64 = 1 << 24;

/// A file as it is after unpacking. Several names can lead to one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inode {
    /// What it is.
    pub kind: Kind,
    /// The permissions.
    pub mode: u32,
    /// The owning user.
    pub uid: u32,
    /// The owning group.
    pub gid: u32,
    /// The modification time in seconds since the epoch.
    pub mtime: u32,
    /// How many names lead to it.
    pub nlink: u32,
    /// The length of a regular file's contents or of a symbolic link's
    /// target, zero for everything else.
    pub size: u32,
    /// Where the contents or the target are in the archive.
    pub data_offset: u64,
    /// The device number of a device node.
    pub rdev: DeviceNumber,
}

/// What the kernel does with an entry, or with the archive as a whole,
/// that an archive made with care does not ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindingKind {
    /// The kernel passes over the entry.
    Skipped(Skip),
    /// An entry without a file type: it removes what is at its path.
    Removal,
    /// The name is empty or has a component longer than 255 bytes. No
    /// lookup takes it and the entry is lost.
    UnusableName,
    /// The name has a `..` component. Where the entry goes is not followed.
    DotDot,
    /// The name is not in the form this crate writes: it starts with `./`.
    /// The kernel's early lookup of microcode and ACPI tables does not
    /// find such an entry.
    LeadingDotSlash,
    /// The name starts with `/`.
    Absolute,
    /// The name has repeated or trailing slashes or `.` components.
    Unnormalized,
    /// The directory the entry is in is not there. The entry is lost.
    MissingParent,
    /// What the entry's directory should be is a file. The entry is lost.
    ParentNotDirectory,
    /// The entry's path leads through a symbolic link. Where the entry
    /// goes is not followed.
    ParentIsSymlink,
    /// A directory that is not empty is where the entry wants to be. The
    /// entry is lost.
    DirectoryInTheWay,
    /// The entry replaces an earlier one of the same name.
    Replaced,
    /// A name of a hard-linked file whose first name is not there anymore.
    /// The entry is lost.
    BrokenLink,
    /// Something that is no directory is named with a slash or a `.`
    /// component at its end. The entry is lost, and so is an empty
    /// directory that the name with the slash leads to.
    TrailingSlash,
    /// A symbolic link whose target has 4096 bytes, one more than a link
    /// holds. The kernel takes away what is at the path and makes no link.
    LongTarget,
    /// A device number beyond the 12 bits of the major and the 20 bits of
    /// the minor that the kernel keeps. The node gets another number.
    DeviceNumber,
    /// A symbolic link without a target.
    EmptyTarget,
    /// A gap of NUL bytes before the entry. Only the kernel reads on.
    Gap,
    /// The entry is in the other of the two forms than the first one. GNU
    /// cpio drops such an entry.
    MixedForms,
    /// The entry counts more than one name and shares its inode number
    /// with an entry that is another file. Readers built on libarchive
    /// take the two for one.
    SharedInode,
    /// A hard-linked file whose entries say another number of names than
    /// the archive has for it.
    LinkCount,
    /// The trailer has a mode, data or a padded name. Some readers do not
    /// take it for the trailer.
    OddTrailer,
    /// The archive has no trailer. The kernel does not need one, cpio(1)
    /// calls the archive cut short.
    NoTrailer,
}

/// One thing found while an archive was replayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    /// What was found.
    pub kind: FindingKind,
    /// The position of the entry among the entries, counting from 0.
    pub index: u64,
    /// Where the entry starts in the archive.
    pub offset: u64,
    /// The entry's name as it is stored.
    pub name: Vec<u8>,
    /// The number the finding is about: the name size or the data size of
    /// an entry passed over, the length of a gap, the names an archive has
    /// for a hard-linked file.
    pub value: Option<u64>,
    /// For a hard-linked file, the names its entries say it has.
    pub expected: Option<u64>,
}

/// What every component of a key has before it: a NUL byte. No name holds
/// one, and it sorts before every byte a name holds.
const SEPARATOR: u8 = 0;

/// The inode of the root directory, which every tree has.
const ROOT_INODE: u32 = 0;

/// The key of a name in a tree: every component with [`SEPARATOR`]
/// before it, the root being empty. Ordered by their bytes such keys list
/// a directory right before what is in it, each directory's entries
/// sorted by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Key<'a>(&'a [u8]);

impl<'a> Key<'a> {
    /// The key `bytes` are: what a name is filed under.
    pub(crate) fn new(bytes: &'a [u8]) -> Key<'a> {
        Key(bytes)
    }

    /// The bytes of the key.
    pub(crate) fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Whether it is the key of the root.
    pub(crate) fn is_root(self) -> bool {
        self.0.is_empty()
    }

    /// The name the key stands for.
    pub(crate) fn name(self) -> Vec<u8> {
        // Only the key of the root has no component.
        let Some(components) = self.0.strip_prefix(&[SEPARATOR]) else {
            return Name::ROOT.as_bytes().to_vec();
        };
        components
            .iter()
            .map(|&b| if b == SEPARATOR { b'/' } else { b })
            .collect()
    }

    /// The key of the directory the entry is in. None for the root.
    pub(crate) fn parent(self) -> Option<Key<'a>> {
        self.0
            .iter()
            .rposition(|&b| b == SEPARATOR)
            .map(|at| Key(&self.0[..at]))
    }

    /// The key of the lowest directory on the way to this one that `there`
    /// says is in the tree. The key itself is not there and the root
    /// always is.
    ///
    /// Every name in the tree is in a directory of the tree. So the
    /// directories on the way to a key are there down to one of them and
    /// not from there on, and where that changes is found by halving: a
    /// dozen lookups for the deepest path there can be, where asking for
    /// one directory after the other took a lookup for each of them.
    fn lowest_there(self, there: &mut dyn FnMut(Key<'_>) -> bool) -> Key<'a> {
        // Every component starts with a NUL byte. What is before the i-th
        // of them is the key of a directory on the way, the root for the
        // first.
        let starts: Vec<usize> = self
            .0
            .iter()
            .enumerate()
            .filter_map(|(at, &b)| (b == SEPARATOR).then_some(at))
            .collect();
        let (mut low, mut high) = (0, starts.len());
        while high - low > 1 {
            let middle = low + (high - low) / 2;
            if there(Key(&self.0[..starts[middle]])) {
                low = middle;
            } else {
                high = middle;
            }
        }
        Key(&self.0[..starts.get(low).copied().unwrap_or(0)])
    }
}

/// A [`Key`] that is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyBuf(Vec<u8>);

impl KeyBuf {
    /// The key of the name `name`.
    pub(crate) fn of(name: &[u8]) -> KeyBuf {
        if name == Name::ROOT.as_bytes() {
            return KeyBuf(Vec::new());
        }
        KeyBuf::from_components(name.split(|&b| b == b'/'), name.len())
    }

    /// The key of the path with the components `components`, which have
    /// `len` bytes with the slashes between them.
    fn from_components<'c>(components: impl Iterator<Item = &'c [u8]>, len: usize) -> KeyBuf {
        let mut key = Vec::with_capacity(len + 1);
        for component in components {
            key.push(SEPARATOR);
            key.extend_from_slice(component);
        }
        KeyBuf(key)
    }

    /// The bytes of the key.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The bytes of the key, to file a name under.
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// What a tree holds, counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Regular files, each counted once whatever the number of its names.
    pub files: u64,
    /// Directories, the root not among them.
    pub directories: u64,
    /// Symbolic links.
    pub symlinks: u64,
    /// Device nodes, FIFOs and sockets.
    pub nodes: u64,
    /// The bytes of the regular files.
    pub bytes: u64,
}

flags! {
    /// What of the root directory an archive sets. The rest is whatever
    /// the kernel gives the root of the file system it unpacks into.
    pub struct RootStated: u8 {
        /// The owning user and group.
        const OWNER = 1 << 0;
        /// The permissions.
        const MODE = 1 << 1;
        /// The modification time.
        const TIME = 1 << 2;
    }
}

/// The tree an archive unpacks to.
#[derive(Clone, Debug)]
pub struct Tree {
    /// The names, each leading to an inode.
    names: BTreeMap<Box<[u8]>, u32>,
    inodes: Vec<Inode>,
    /// What of the root the archive sets.
    root_stated: RootStated,
    /// The time an entry that is no directory left on the root, as long
    /// as nothing was made or removed in the root since.
    root_time: Option<u32>,
    approximate: bool,
    end: End,
    /// Where the trailer starts, if there is one.
    trailer_offset: Option<u64>,
    records: u64,
    format: Option<Format>,
    max_ino: u32,
}

/// What is at a path once an entry of some kind wants to be there.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place {
    /// Nothing.
    Free,
    /// What was there and stays: something of the kind asked for, or a
    /// directory that is not empty and cannot go.
    Taken(u32),
}

impl Tree {
    /// A tree with nothing but its root.
    fn empty() -> Tree {
        let root = Inode {
            kind: Kind::Directory,
            mode: 0,
            uid: 0,
            gid: 0,
            mtime: 0,
            nlink: 1,
            size: 0,
            data_offset: 0,
            rdev: DeviceNumber::NONE,
        };
        let mut names = BTreeMap::new();
        names.insert(Vec::new().into_boxed_slice(), ROOT_INODE);
        Tree {
            names,
            inodes: vec![root],
            root_stated: RootStated::default(),
            root_time: None,
            approximate: false,
            end: End::NoTrailer,
            trailer_offset: None,
            records: 0,
            format: None,
            max_ino: 0,
        }
    }

    /// Replays the archive in `source` for an operation that needs it
    /// sound: an image that holds no archive and an archive that is
    /// damaged are errors.
    pub fn open<S: Source + ?Sized>(source: &S) -> Result<Tree> {
        let (tree, damage) = Tree::replay(source, &mut |_| {})?;
        if let Some(damage) = damage {
            return Err(damage.into_error());
        }
        if tree.records == 0 {
            return Err(crate::read::blank());
        }
        Ok(tree)
    }

    /// What is at `name`, a path as [`Normalized`] has it.
    pub fn get(&self, name: &[u8]) -> Option<&Inode> {
        self.names
            .get(KeyBuf::of(name).as_bytes())
            .map(|&id| &self.inodes[id as usize])
    }

    /// The root directory. Its owner, mode and time are the archive's only
    /// as far as [`Tree::root_stated`] says.
    pub fn root(&self) -> &Inode {
        &self.inodes[ROOT_INODE as usize]
    }

    /// What of the root's owner, mode and time the archive sets. A
    /// directory entry for the root sets all three.
    pub fn root_stated(&self) -> RootStated {
        self.root_stated
    }

    /// Whether entries were left out because where they go depends on a
    /// `..` or a symbolic link in their path.
    pub fn approximate(&self) -> bool {
        self.approximate
    }

    /// How the archive ends.
    pub fn end(&self) -> End {
        self.end
    }

    /// Where the trailer starts: where an entry added to the archive goes.
    /// The end of the entries when there is no trailer.
    pub fn trailer_offset(&self) -> Option<u64> {
        self.trailer_offset
    }

    /// How many entries the archive has, the trailer included.
    pub fn records(&self) -> u64 {
        self.records
    }

    /// The form of the archive's first header.
    pub fn format(&self) -> Option<Format> {
        self.format
    }

    /// The largest inode number of any header.
    pub fn max_ino(&self) -> u32 {
        self.max_ino
    }

    /// Every name with what it leads to, the root first, a directory
    /// right before what is in it, each directory's entries sorted by the
    /// bytes of their names. The name of the root is `.`.
    pub fn entries(&self) -> impl Iterator<Item = (Vec<u8>, &Inode)> {
        self.names
            .iter()
            .map(|(key, &id)| (Key::new(key).name(), &self.inodes[id as usize]))
    }

    /// The entries of the directory `name`, sorted by the bytes of their
    /// names, each with its last component. None if `name` is no
    /// directory.
    pub fn children(&self, name: &[u8]) -> Option<Children<'_>> {
        let key = KeyBuf::of(name).into_bytes();
        let id = *self.names.get(&key[..])?;
        if self.inodes[id as usize].kind != Kind::Directory {
            return None;
        }
        let mut prefix = key;
        prefix.push(SEPARATOR);
        Some(Children {
            tree: self,
            cursor: prefix.clone(),
            prefix,
        })
    }

    /// What the tree holds, counted.
    pub fn counts(&self) -> Counts {
        let mut counts = Counts::default();
        // A file with several names is counted with its first one.
        let mut seen = vec![false; self.inodes.len()];
        for (key, &id) in &self.names {
            if key.is_empty() || std::mem::replace(&mut seen[id as usize], true) {
                continue;
            }
            let inode = &self.inodes[id as usize];
            match inode.kind {
                Kind::Regular => {
                    counts.files += 1;
                    counts.bytes += u64::from(inode.size);
                }
                Kind::Directory => counts.directories += 1,
                Kind::Symlink => counts.symlinks += 1,
                Kind::CharDevice | Kind::BlockDevice | Kind::Fifo | Kind::Socket => counts.nodes += 1,
            }
        }
        counts
    }

    /// An identity for what `name` leads to: two names with the same one
    /// are hard links of one file.
    pub fn inode_id(&self, name: &[u8]) -> Option<u32> {
        self.names.get(KeyBuf::of(name).as_bytes()).copied()
    }

    fn has_children(&self, key: &[u8]) -> bool {
        let mut prefix = key.to_vec();
        prefix.push(SEPARATOR);
        self.names
            .range::<[u8], _>((Bound::Included(&prefix[..]), Bound::Unbounded))
            .next()
            .is_some_and(|(k, _)| k.starts_with(&prefix))
    }

    /// Something was made or removed at `key`. In the root that changes
    /// the root's time, which no entry sets back.
    fn changed(&mut self, key: &[u8]) {
        if Key::new(key).parent().is_some_and(Key::is_root) {
            self.root_time = None;
        }
    }

    fn unlink(&mut self, key: &[u8]) {
        if let Some(id) = self.names.remove(key) {
            let inode = &mut self.inodes[id as usize];
            inode.nlink = inode.nlink.saturating_sub(1);
            self.changed(key);
        }
    }

    /// Another name for the inode `id`.
    fn link(&mut self, key: &[u8], id: u32) {
        self.names.insert(key.into(), id);
        self.inodes[id as usize].nlink += 1;
        self.changed(key);
    }

    /// The kernel's clean_path(): what is at `key` goes, unless it is of
    /// the kind `keep` or a directory with something in it. The root never
    /// goes.
    fn clean(&mut self, key: &[u8], keep: Option<Kind>) -> Place {
        let Some(&id) = self.names.get(key) else {
            return Place::Free;
        };
        let kind = self.inodes[id as usize].kind;
        if keep == Some(kind) {
            return Place::Taken(id);
        }
        if kind == Kind::Directory && (key.is_empty() || self.has_children(key)) {
            return Place::Taken(id);
        }
        self.unlink(key);
        Place::Free
    }

    fn create(&mut self, key: &[u8], inode: Inode) -> u32 {
        let id = self.inodes.len() as u32;
        self.inodes.push(inode);
        self.names.insert(key.into(), id);
        self.changed(key);
        id
    }
}

/// The entries of one directory, see [`Tree::children`].
pub struct Children<'a> {
    tree: &'a Tree,
    /// The key of the directory with the separator behind it.
    prefix: Vec<u8>,
    /// Where the next entry is looked for.
    cursor: Vec<u8>,
}

impl<'a> Iterator for Children<'a> {
    type Item = (&'a [u8], &'a Inode);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, &id) = self
            .tree
            .names
            .range::<[u8], _>((Bound::Included(&self.cursor[..]), Bound::Unbounded))
            .next()?;
        if !key.starts_with(&self.prefix) {
            return None;
        }
        // The next entry of this directory comes behind everything below
        // the one just found, all of which starts with its key and a NUL.
        self.cursor.clear();
        self.cursor.extend_from_slice(key);
        self.cursor.push(1);
        Some((&key[self.prefix.len()..], &self.tree.inodes[id as usize]))
    }
}

/// The first name of a hard-linked file, as the kernel remembers it, and
/// how many names the archive had for the file so far.
struct LinkGroup {
    /// The stored name of the first entry.
    first: Vec<u8>,
    /// Where that entry starts, and its position among the entries.
    offset: u64,
    index: u64,
    /// The names the headers say the file has.
    stated: u32,
    seen: u32,
}

/// Where an entry goes: the key of its path, and how its name ends. A
/// directory entry makes the directory a name with a slash at its end
/// stands for. Any other entry under such a name is lost and takes an
/// empty directory of that name with it. Under a name that ends in a `.`
/// nothing is made and nothing goes.
struct Spot {
    key: Vec<u8>,
    ending: Ending,
}

/// What the kernel sets on a directory that stays where an entry that is
/// no directory wants to be.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lands {
    Nothing,
    /// A symbolic link: its owner.
    Owner,
    /// A device node, FIFO or socket: its owner and mode.
    OwnerAndMode,
}

/// The times the directory entries for one path have.
struct Times {
    /// The time of the first entry.
    first: u32,
    /// The time of the first entry whose name ends in a component of its
    /// own. Only such a name leads to what is no directory.
    plain: Option<u32>,
    /// Whether an entry had a name that ends in a slash or a `.`.
    other: bool,
}

/// What tells the names of one file from those of other files: the device
/// the file was on and its inode number there.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    device: DeviceNumber,
    ino: u32,
}

impl From<&Header> for FileId {
    fn from(header: &Header) -> FileId {
        FileId {
            device: header.dev(),
            ino: header.ino,
        }
    }
}

/// What the kernel's table of hard links tells files by: it takes two
/// entries for names of one file only if their file types are the same.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct LinkKey {
    file: FileId,
    type_bits: u32,
}

impl From<&Header> for LinkKey {
    fn from(header: &Header) -> LinkKey {
        LinkKey {
            file: FileId::from(header),
            type_bits: header.mode & S_IFMT,
        }
    }
}

/// The state of a replay beside the tree.
struct Replayer {
    tree: Tree,
    /// Where the last entry read ends.
    entries_end: u64,
    /// What was found and not handed out yet.
    findings: Vec<Finding>,
    /// The kernel's table of hard links.
    links: HashMap<LinkKey, LinkGroup>,
    /// Every entry that counts more than one name, with the kind of the
    /// first one seen.
    shared: HashMap<FileId, Kind>,
    /// The times of the directory entries, by path. The kernel keeps the
    /// time of every directory entry, whether it made a directory or not,
    /// and sets them when everything is unpacked, last entry first. So the
    /// first entry's time is the one that stays, on whatever is at the
    /// path by then.
    directory_times: HashMap<Box<[u8]>, Times>,
}

impl Replayer {
    fn find(&mut self, kind: FindingKind, record: &Record) {
        let value = match kind {
            FindingKind::Skipped(Skip::NameSize) => Some(u64::from(record.header.namesize)),
            FindingKind::Skipped(Skip::TargetSize | Skip::Data) => Some(u64::from(record.header.filesize)),
            FindingKind::Gap => Some(record.gap),
            _ => None,
        };
        self.findings.push(Finding {
            kind,
            index: self.tree.records - 1,
            offset: record.offset,
            name: record.name.clone(),
            value,
            expected: None,
        });
    }

    fn inode_of(record: &Record, kind: Kind) -> Inode {
        let h = &record.header;
        Inode {
            kind,
            mode: h.mode & PERMISSIONS,
            uid: h.uid,
            gid: h.gid,
            mtime: h.mtime,
            nlink: 1,
            size: 0,
            data_offset: record.data_offset,
            rdev: if kind.is_device() {
                h.rdev().packed()
            } else {
                DeviceNumber::NONE
            },
        }
    }

    /// The path the entry's name stands for, if that can be told from the
    /// name alone.
    fn spot(&mut self, record: &Record) -> Option<Spot> {
        let normalized = match Normalized::new(&record.name) {
            Ok(normalized) => normalized,
            Err(Unusable::DotDot) => {
                self.tree.approximate = true;
                self.find(FindingKind::DotDot, record);
                return None;
            }
            Err(Unusable::Empty | Unusable::ComponentTooLong) => {
                self.find(FindingKind::UnusableName, record);
                return None;
            }
        };
        let form = match normalized.form {
            Form::Written => None,
            Form::LeadingDotSlash => Some(FindingKind::LeadingDotSlash),
            Form::Absolute => Some(FindingKind::Absolute),
            Form::Unnormalized => Some(FindingKind::Unnormalized),
        };
        if let Some(form) = form {
            self.find(form, record);
        }
        Some(Spot {
            key: KeyBuf::from_components(normalized.components(), record.name.len()).into_bytes(),
            ending: normalized.ending,
        })
    }

    /// Whether the directory the entry goes into is there.
    fn parent_is_there(&mut self, record: &Record, key: &[u8]) -> bool {
        // Every name in the tree is in a directory of the tree. So when the
        // directory of this one is there, all of its path is.
        let Some(parent) = Key::new(key).parent() else {
            return true;
        };
        match self
            .tree
            .names
            .get(parent.as_bytes())
            .map(|&id| self.tree.inodes[id as usize].kind)
        {
            Some(Kind::Directory) => return true,
            Some(Kind::Symlink) => {
                self.tree.approximate = true;
                self.find(FindingKind::ParentIsSymlink, record);
                return false;
            }
            Some(_) => {
                self.find(FindingKind::ParentNotDirectory, record);
                return false;
            }
            None => {}
        }
        // Something further up is missing or in the way. Find out which.
        let names = &self.tree.names;
        let lowest = parent.lowest_there(&mut |key| names.contains_key(key.as_bytes()));
        match self
            .tree
            .names
            .get(lowest.as_bytes())
            .map(|&id| self.tree.inodes[id as usize].kind)
        {
            Some(Kind::Symlink) => {
                self.tree.approximate = true;
                self.find(FindingKind::ParentIsSymlink, record);
            }
            Some(Kind::Directory) | None => self.find(FindingKind::MissingParent, record),
            Some(_) => self.find(FindingKind::ParentNotDirectory, record),
        }
        false
    }

    /// The path the entry is unpacked at, if it can be told and its
    /// directory is there.
    fn place(&mut self, record: &Record) -> Option<Spot> {
        let spot = self.spot(record)?;
        self.parent_is_there(record, &spot.key).then_some(spot)
    }

    /// The kernel's find_link(): the first name of the file an entry that
    /// counts more than one name belongs to, if the kernel has seen one.
    /// Otherwise this entry's name is the first from now on. The kernel
    /// does this before it tries to make anything, so a name it then fails
    /// to make is remembered all the same.
    fn first_name(&mut self, record: &Record) -> Option<Vec<u8>> {
        let h = &record.header;
        if h.nlink <= 1 {
            return None;
        }
        let table_key = LinkKey::from(h);
        match self.links.get_mut(&table_key) {
            Some(group) => {
                group.seen += 1;
                Some(group.first.clone())
            }
            None => {
                self.links.insert(
                    table_key,
                    LinkGroup {
                        first: record.name.clone(),
                        offset: record.offset,
                        index: self.tree.records - 1,
                        stated: h.nlink,
                        seen: 1,
                    },
                );
                None
            }
        }
    }

    /// The kernel's maybe_link(): an entry that counts more than one name
    /// becomes a link to the first name of its file, if the kernel has seen
    /// one. Returns whether the entry is dealt with: linked, or lost in the
    /// attempt.
    fn link(&mut self, record: &Record, key: &[u8], kind: Kind) -> Option<std::result::Result<u32, ()>> {
        let first = self.first_name(record)?;
        // What is at the entry's path goes first, whatever it is. That
        // takes the first name away when the entry names it again.
        if let Place::Taken(_) = self.tree.clean(key, None) {
            self.find(FindingKind::DirectoryInTheWay, record);
            return Some(Err(()));
        }
        // A first name that ends in a slash or a `.` leads to a directory
        // or to nothing, and neither can be linked.
        let target = Normalized::new(&first)
            .ok()
            .filter(|n| n.ending == Ending::Plain)
            .map(|n| KeyBuf::from_components(n.components(), first.len()))
            .and_then(|key| self.tree.names.get(key.as_bytes()).copied());
        let id = match target {
            Some(id) if self.tree.inodes[id as usize].kind == kind => id,
            other => {
                // Nothing is at the first name, or a directory, which
                // cannot be linked. Anything else the kernel does link, and
                // then writes through the new name to wherever that leads.
                // That is not followed here.
                if other.is_some_and(|id| self.tree.inodes[id as usize].kind != Kind::Directory) {
                    self.tree.approximate = true;
                }
                self.find(FindingKind::BrokenLink, record);
                return Some(Err(()));
            }
        };
        self.tree.link(key, id);
        Some(Ok(id))
    }

    /// An entry that is no directory under a name that a lookup takes for
    /// one. Nothing is made. An empty directory goes when the name ends in
    /// a slash, and on a directory that stays the kernel sets what `lands`
    /// says, as it does on a directory that is in the way of any name.
    fn onto_directory(&mut self, record: &Record, spot: &Spot, lands: Lands, removal: bool) {
        let h = &record.header;
        let there = self
            .tree
            .names
            .get(&spot.key[..])
            .map(|&id| (id, self.tree.inodes[id as usize].kind));
        let lost = match there {
            None if spot.ending == Ending::Dot => FindingKind::MissingParent,
            None => FindingKind::TrailingSlash,
            // The lookup goes through the link.
            Some((_, Kind::Symlink)) => {
                self.tree.approximate = true;
                self.find(FindingKind::ParentIsSymlink, record);
                return;
            }
            Some((id, Kind::Directory)) => {
                let root = spot.key.is_empty();
                if spot.ending == Ending::Slash && !root && !self.tree.has_children(&spot.key) {
                    self.tree.unlink(&spot.key);
                } else if lands != Lands::Nothing {
                    let inode = &mut self.tree.inodes[id as usize];
                    inode.uid = h.uid;
                    inode.gid = h.gid;
                    if lands == Lands::OwnerAndMode {
                        inode.mode = h.mode & PERMISSIONS;
                    }
                    // The time lands too. On a directory an entry made it
                    // does not last: the kernel sets those times again at
                    // the end. The root may have no entry.
                    if root {
                        self.tree.root_stated |= RootStated::OWNER;
                        if lands == Lands::OwnerAndMode {
                            self.tree.root_stated |= RootStated::MODE;
                        }
                        self.tree.root_time = Some(h.mtime);
                    }
                }
                FindingKind::TrailingSlash
            }
            Some(_) if spot.ending == Ending::Dot => FindingKind::ParentNotDirectory,
            Some(_) => FindingKind::TrailingSlash,
        };
        if !removal {
            self.find(lost, record);
        }
    }

    fn regular(&mut self, record: &Record) {
        let spot = match self.place(record) {
            Some(spot) if spot.ending == Ending::Plain => spot,
            other => {
                // The kernel remembers the name of a hard-linked file
                // before it finds that it cannot make it.
                self.first_name(record);
                if let Some(spot) = other {
                    self.onto_directory(record, &spot, Lands::Nothing, false);
                }
                return;
            }
        };
        let key = spot.key;
        let h = &record.header;
        let before = self.tree.clean(&key, Some(Kind::Regular));
        let id = match self.link(record, &key, Kind::Regular) {
            Some(Err(())) => return,
            // A link is opened without truncating it: an entry without
            // data leaves the contents as they are.
            Some(Ok(id)) => {
                if h.filesize == 0 {
                    let inode = &mut self.tree.inodes[id as usize];
                    inode.mode = h.mode & PERMISSIONS;
                    inode.uid = h.uid;
                    inode.gid = h.gid;
                    inode.mtime = h.mtime;
                    return;
                }
                id
            }
            None => match before {
                Place::Free => self.tree.create(&key, Self::inode_of(record, Kind::Regular)),
                Place::Taken(id) if self.tree.inodes[id as usize].kind == Kind::Regular => {
                    self.find(FindingKind::Replaced, record);
                    id
                }
                Place::Taken(_) => {
                    self.find(FindingKind::DirectoryInTheWay, record);
                    return;
                }
            },
        };
        let inode = &mut self.tree.inodes[id as usize];
        inode.mode = h.mode & PERMISSIONS;
        inode.uid = h.uid;
        inode.gid = h.gid;
        inode.mtime = h.mtime;
        inode.size = h.filesize;
        inode.data_offset = record.data_offset;
    }

    fn directory(&mut self, record: &Record) {
        let Some(spot) = self.spot(record) else { return };
        let h = &record.header;
        // The time goes on the kernel's list whatever becomes of the entry.
        let plain = spot.ending == Ending::Plain;
        let times = self.directory_times.entry(spot.key.clone().into()).or_insert(Times {
            first: h.mtime,
            plain: None,
            other: false,
        });
        if plain {
            times.plain.get_or_insert(h.mtime);
        } else {
            times.other = true;
        }
        if !self.parent_is_there(record, &spot.key) {
            return;
        }
        let key = spot.key;
        let there = match spot.ending {
            Ending::Plain => match self.tree.clean(&key, Some(Kind::Directory)) {
                Place::Free => None,
                Place::Taken(id) => Some(id),
            },
            // Under such a name nothing goes to make room.
            Ending::Slash | Ending::Dot => match self.tree.names.get(&key[..]).copied() {
                None if spot.ending == Ending::Dot => {
                    self.find(FindingKind::MissingParent, record);
                    return;
                }
                None => None,
                Some(id) => match self.tree.inodes[id as usize].kind {
                    Kind::Directory => Some(id),
                    Kind::Symlink => {
                        self.tree.approximate = true;
                        self.find(FindingKind::ParentIsSymlink, record);
                        return;
                    }
                    _ => {
                        self.find(FindingKind::ParentNotDirectory, record);
                        return;
                    }
                },
            },
        };
        match there {
            None => {
                self.tree.create(&key, Self::inode_of(record, Kind::Directory));
            }
            Some(id) => {
                if key.is_empty() {
                    self.tree.root_stated |= RootStated::OWNER | RootStated::MODE;
                } else {
                    self.find(FindingKind::Replaced, record);
                }
                let inode = &mut self.tree.inodes[id as usize];
                inode.mode = h.mode & PERMISSIONS;
                inode.uid = h.uid;
                inode.gid = h.gid;
            }
        }
    }

    fn symlink(&mut self, record: &Record) {
        let Some(spot) = self.place(record) else { return };
        let h = &record.header;
        if record.target_len == 0 {
            self.find(FindingKind::EmptyTarget, record);
        }
        if spot.ending != Ending::Plain {
            self.onto_directory(record, &spot, Lands::Owner, false);
            return;
        }
        let key = spot.key;
        let had = self.tree.names.contains_key(&key[..]);
        match self.tree.clean(&key, None) {
            // What was there is gone by now, and a target of 4096 bytes is
            // one more than a link holds.
            Place::Free if record.target_len as usize > MAX_TARGET_LEN => {
                self.find(FindingKind::LongTarget, record);
            }
            Place::Free => {
                if had {
                    self.find(FindingKind::Replaced, record);
                }
                let mut inode = Self::inode_of(record, Kind::Symlink);
                inode.size = record.target_len;
                self.tree.create(&key, inode);
            }
            // The link is not made, but the kernel goes on to set owner
            // and time, which lands on the directory in the way.
            Place::Taken(id) => {
                self.find(FindingKind::DirectoryInTheWay, record);
                let inode = &mut self.tree.inodes[id as usize];
                inode.uid = h.uid;
                inode.gid = h.gid;
                inode.mtime = h.mtime;
            }
        }
    }

    fn node(&mut self, record: &Record, kind: Kind) {
        let h = &record.header;
        if kind.is_device() && !h.rdev().fits() {
            self.find(FindingKind::DeviceNumber, record);
        }
        let spot = match self.place(record) {
            Some(spot) if spot.ending == Ending::Plain => spot,
            other => {
                // As with a regular file the name is remembered first. An
                // entry that is a later name of its file sets nothing.
                let later = self.first_name(record).is_some();
                if let Some(spot) = other {
                    let lands = if later { Lands::Nothing } else { Lands::OwnerAndMode };
                    self.onto_directory(record, &spot, lands, false);
                }
                return;
            }
        };
        let key = spot.key;
        let before = self.tree.clean(&key, Some(kind));
        if self.link(record, &key, kind).is_some() {
            return;
        }
        match before {
            Place::Free => {
                self.tree.create(&key, Self::inode_of(record, kind));
            }
            // mknod() fails on what is there, a node of this kind or a
            // directory in the way, and owner, mode and time are set on it
            // all the same.
            Place::Taken(id) => {
                let existing = self.tree.inodes[id as usize].kind;
                self.find(
                    if existing == kind {
                        FindingKind::Replaced
                    } else {
                        FindingKind::DirectoryInTheWay
                    },
                    record,
                );
                let inode = &mut self.tree.inodes[id as usize];
                inode.mode = h.mode & PERMISSIONS;
                inode.uid = h.uid;
                inode.gid = h.gid;
                inode.mtime = h.mtime;
            }
        }
    }

    fn removal(&mut self, record: &Record) {
        self.find(FindingKind::Removal, record);
        let Some(spot) = self.place(record) else { return };
        match spot.ending {
            Ending::Plain => {
                self.tree.clean(&spot.key, None);
            }
            Ending::Slash | Ending::Dot => self.onto_directory(record, &spot, Lands::Nothing, true),
        }
    }

    fn apply(&mut self, record: &Record) {
        let h = &record.header;
        if record.gap != 0 {
            self.find(FindingKind::Gap, record);
        }
        if self.tree.format.is_some_and(|first| first != record.format) {
            self.find(FindingKind::MixedForms, record);
        }
        self.tree.format.get_or_insert(record.format);
        self.tree.max_ino = self.tree.max_ino.max(h.ino);
        // Readers that take equal numbers for one file look at every entry
        // that counts more than one name, directories among them.
        if h.nlink > 1 && !matches!(record.standing, Standing::Trailer | Standing::Skipped(_)) {
            if let Some(kind) = h.kind() {
                match self.shared.insert(FileId::from(h), kind) {
                    // Names of one file are of one kind, and a directory
                    // has one name.
                    Some(first) if first != kind || kind == Kind::Directory => {
                        self.find(FindingKind::SharedInode, record);
                    }
                    _ => {}
                }
            }
        }
        match record.standing {
            Standing::Skipped(skip) => self.find(FindingKind::Skipped(skip), record),
            Standing::Removal => self.removal(record),
            Standing::Entry(Kind::Regular) => self.regular(record),
            Standing::Entry(Kind::Directory) => self.directory(record),
            Standing::Entry(Kind::Symlink) => self.symlink(record),
            Standing::Entry(kind) => self.node(record, kind),
            Standing::Trailer => {
                if h.mode != 0 || h.filesize != 0 || record.name_padding != 0 {
                    self.find(FindingKind::OddTrailer, record);
                }
                self.tree.trailer_offset = Some(record.offset);
            }
        }
    }

    /// Ends the replay. Returns the tree and what is only found now.
    fn finish(mut self, end: End, damaged: bool) -> (Tree, Vec<Finding>) {
        // The times of the directories, set when everything is unpacked.
        // They go to whatever is at the path by then. A name that ends in
        // a slash or a `.` leads to a directory only, and through a
        // symbolic link.
        for (key, times) in std::mem::take(&mut self.directory_times) {
            let Some(&id) = self.tree.names.get(&key) else { continue };
            let inode = &mut self.tree.inodes[id as usize];
            let time = if inode.kind == Kind::Directory {
                Some(times.first)
            } else {
                times.plain
            };
            if let Some(time) = time {
                inode.mtime = time;
            }
            if inode.kind == Kind::Symlink && times.other {
                self.tree.approximate = true;
            }
            if key.is_empty() {
                self.tree.root_stated |= RootStated::TIME;
            }
        }
        // Without a directory entry for the root, the time another entry
        // left there stays unless the root changed since.
        if let (false, Some(time)) = (self.tree.root_stated.contains(RootStated::TIME), self.tree.root_time) {
            self.tree.inodes[ROOT_INODE as usize].mtime = time;
            self.tree.root_stated |= RootStated::TIME;
        }
        let mut miscounted: Vec<LinkGroup> = self
            .links
            .drain()
            .map(|(_, group)| group)
            .filter(|group| group.stated != group.seen)
            .collect();
        miscounted.sort_by_key(|group| group.index);
        for group in miscounted {
            self.findings.push(Finding {
                kind: FindingKind::LinkCount,
                index: group.index,
                offset: group.offset,
                name: group.first,
                value: Some(u64::from(group.seen)),
                expected: Some(u64::from(group.stated)),
            });
        }
        // An archive that is damaged ends where the damage is.
        if end == End::NoTrailer && self.tree.records != 0 && !damaged {
            self.findings.push(Finding {
                kind: FindingKind::NoTrailer,
                index: self.tree.records,
                offset: self.entries_end,
                name: Vec::new(),
                value: None,
                expected: None,
            });
        }
        self.tree.end = end;
        (self.tree, self.findings)
    }
}

/// One entry of a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replayed {
    /// The entry as it is stored.
    pub record: Record,
    /// Its position among the entries, counting from 0.
    pub index: u64,
    /// What the kernel does with it that an archive made with care does
    /// not ask for.
    pub findings: Vec<Finding>,
}

/// What a replay comes to.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// The tree as far as the archive could be read.
    pub tree: Tree,
    /// The damage that stopped the reading, if there is any.
    pub damage: Option<Damage>,
    /// What is only found once all entries are replayed: a hard-linked
    /// file that has another number of names than its entries say, and
    /// an archive without a trailer.
    pub findings: Vec<Finding>,
}

/// Replays an archive the way the kernel unpacks it. It is an iterator
/// over the entries, each handed out once the tree has it, and
/// [`Replay::finish`] ends it.
pub struct Replay<'a, S: Source + ?Sized> {
    scanner: Scanner<'a, S>,
    /// How long the archive is.
    len: u64,
    replayer: Replayer,
    damage: Option<Damage>,
}

impl<'a, S: Source + ?Sized> Replay<'a, S> {
    /// Starts at the first byte of `source`.
    pub fn new(source: &'a S) -> Replay<'a, S> {
        Replay {
            scanner: Scanner::new(source),
            len: source.len(),
            replayer: Replayer {
                tree: Tree::empty(),
                entries_end: 0,
                findings: Vec::new(),
                links: HashMap::new(),
                shared: HashMap::new(),
                directory_times: HashMap::new(),
            },
            damage: None,
        }
    }

    /// Ends the replay with what was replayed so far.
    pub fn finish(self) -> Outcome {
        let Replay {
            scanner,
            mut replayer,
            damage,
            ..
        } = self;
        let end = scanner.end().unwrap_or(End::NoTrailer);
        if replayer.tree.trailer_offset.is_none() {
            // Without a trailer an entry added to the archive goes where
            // the entries end.
            replayer.tree.trailer_offset = damage.is_none().then_some(replayer.entries_end);
        }
        let (tree, findings) = replayer.finish(end, damage.is_some());
        Outcome { tree, damage, findings }
    }
}

impl<S: Source + ?Sized> Iterator for Replay<'_, S> {
    /// An entry that was replayed. An error is one of reading, or says
    /// that the archive has more entries than a tree holds.
    type Item = Result<Replayed>;

    fn next(&mut self) -> Option<Result<Replayed>> {
        let record = match self.scanner.next()? {
            Ok(Ok(record)) => record,
            // The scan ends with the damage.
            Ok(Err(damage)) => {
                self.damage = Some(damage);
                return None;
            }
            Err(e) => return Some(Err(e)),
        };
        let replayer = &mut self.replayer;
        replayer.tree.records += 1;
        if replayer.tree.records > MAX_ENTRIES {
            return Some(Err(err!(
                E2BIG,
                "the archive has more than {} entries, more than are kept in memory",
                MAX_ENTRIES
            )));
        }
        replayer.apply(&record);
        replayer.entries_end = record.end().min(self.len);
        Some(Ok(Replayed {
            index: replayer.tree.records - 1,
            findings: std::mem::take(&mut replayer.findings),
            record,
        }))
    }
}

impl Tree {
    /// Replays the archive in `source` and tells `findings` what the
    /// kernel would do with it that an archive made with care does not
    /// ask for, in the order of the entries. Returns the tree as far as
    /// the archive could be read, and the damage that stopped the reading
    /// if there is any.
    pub fn replay<S: Source + ?Sized>(source: &S, findings: &mut dyn FnMut(Finding)) -> Result<(Tree, Option<Damage>)> {
        let mut replay = Replay::new(source);
        for entry in replay.by_ref() {
            entry?.findings.into_iter().for_each(&mut *findings);
        }
        let outcome = replay.finish();
        outcome.findings.into_iter().for_each(&mut *findings);
        Ok((outcome.tree, outcome.damage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{archive, Raw};

    const REG: u32 = 0o100644;
    const DIR: u32 = 0o040755;
    const LNK: u32 = 0o120777;
    const CHR: u32 = 0o020600;
    const T: u32 = 1_577_934_245;

    fn reg(name: &[u8], data: &[u8]) -> Raw {
        Raw::new(REG, name).data(data).mtime(T)
    }

    /// A directory the way archives have them: counting two names, with
    /// a number of its own.
    fn dir(name: &[u8]) -> Raw {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(1000);
        Raw::new(DIR, name)
            .inode(NEXT.fetch_add(1, Ordering::Relaxed), 2)
            .mtime(T)
    }

    fn lnk(name: &[u8], target: &[u8]) -> Raw {
        Raw::new(LNK, name).data(target).mtime(T)
    }

    /// Replays `entries` with a trailer behind them.
    fn run(entries: &[Raw]) -> (Tree, Vec<(FindingKind, Vec<u8>)>) {
        run_bytes(&archive(entries))
    }

    fn run_bytes(bytes: &[u8]) -> (Tree, Vec<(FindingKind, Vec<u8>)>) {
        let mut findings = Vec::new();
        let (tree, damage) = Tree::replay(bytes, &mut |f| findings.push((f.kind, f.name))).unwrap();
        assert_eq!(damage, None);
        assert_every_name_is_in_a_directory(&tree);
        (tree, findings)
    }

    /// What [`Key::lowest_there`] relies on.
    fn assert_every_name_is_in_a_directory(tree: &Tree) {
        for key in tree.names.keys() {
            let key = Key::new(key);
            if let Some(parent) = key.parent() {
                let id = tree.names.get(parent.as_bytes()).copied();
                assert_eq!(
                    id.map(|id| tree.inodes[id as usize].kind),
                    Some(Kind::Directory),
                    "{:?}",
                    String::from_utf8_lossy(&key.name())
                );
            }
        }
    }

    fn data<'a>(bytes: &'a [u8], inode: &Inode) -> &'a [u8] {
        &bytes[inode.data_offset as usize..][..inode.size as usize]
    }

    fn names(tree: &Tree) -> Vec<String> {
        tree.entries()
            .map(|(name, _)| String::from_utf8(name).unwrap())
            .collect()
    }

    /// What a booted kernel made of the same entries.
    #[test]
    fn an_archive_unpacks_like_the_kernel_unpacks_it() {
        let entries = [
            dir(b"."),
            dir(b"t"),
            reg(b"t/hl-last-a", b"").inode(7, 3),
            reg(b"t/hl-last-b", b"").inode(7, 3),
            reg(b"t/hl-last-c", b"last").inode(7, 3),
            reg(b"t/hl-first-a", b"first").inode(8, 3),
            reg(b"t/hl-first-b", b"").inode(8, 3),
            reg(b"t/hl-first-c", b"").inode(8, 3),
            Raw::new(0o104755, b"t/suid").data(b"s").mtime(T),
            Raw::new(0o041777, b"t/sticky").mtime(T),
            Raw::new(0o100640, b"t/own").data(b"o").owner(1234, 5678).mtime(T),
            Raw::new(CHR, b"t/chr").rdev(1, 3).mtime(T),
            Raw::new(0o060660, b"t/blk").rdev(8, 1).mtime(T),
            Raw::new(0o010644, b"t/fifo").mtime(T),
            Raw::new(0o140755, b"t/sock").mtime(T),
            lnk(b"t/sym", b"hl-last-c").owner(42, 43),
            reg(b"t/orphan/child", b"child"),
            dir(b"t/orphan"),
            Raw::new(0o100600, b"t/dup").data(b"one").mtime(T),
            reg(b"t/dup", b"two!").mtime(T + 1),
            dir(b"t/dirfile"),
            reg(b"t/dirfile", b"wasdir"),
            reg(b"t/zeroino-a", b"za"),
            reg(b"t/zeroino-b", b"zb"),
            reg(b"t/nl2-single", b"solo").inode(9, 2),
            Raw::new(CHR, b"t/devhl-a").rdev(1, 5).inode(10, 2).mtime(T),
            Raw::new(CHR, b"t/devhl-b").rdev(1, 5).inode(10, 2).mtime(T),
            lnk(b"t/symhl-a", b"own").inode(11, 2),
            lnk(b"t/symhl-b", b"own").inode(11, 2),
            dir(b"t/dirsize").data(b"junk"),
            reg(b"t/after-dirsize", b"ok"),
            lnk(b"t/emptysym", b""),
            reg(b"t/TRAILER!!!", b"notatrailer"),
        ];
        let bytes = archive(&entries);
        let (tree, findings) = run_bytes(&bytes);
        let at = |name: &[u8]| {
            tree.get(name)
                .unwrap_or_else(|| panic!("{} is missing", String::from_utf8_lossy(name)))
        };
        assert_eq!(tree.root_stated(), RootStated::all());
        assert!(!tree.approximate());
        assert_eq!(tree.root().mode, 0o755);
        // Both layouts of a hard-linked file.
        for group in [
            [&b"t/hl-last-a"[..], b"t/hl-last-b", b"t/hl-last-c"],
            [b"t/hl-first-a", b"t/hl-first-b", b"t/hl-first-c"],
        ] {
            let id = tree.inode_id(group[0]).unwrap();
            for name in group {
                assert_eq!(tree.inode_id(name), Some(id));
                assert_eq!(at(name).nlink, 3);
            }
        }
        assert_eq!(data(&bytes, at(b"t/hl-last-a")), b"last");
        assert_eq!(data(&bytes, at(b"t/hl-first-c")), b"first");
        assert_eq!(at(b"t/suid").mode, 0o4755);
        assert_eq!((at(b"t/sticky").kind, at(b"t/sticky").mode), (Kind::Directory, 0o1777));
        assert_eq!(
            (at(b"t/own").mode, at(b"t/own").uid, at(b"t/own").gid),
            (0o640, 1234, 5678)
        );
        assert_eq!(
            (at(b"t/chr").kind, at(b"t/chr").rdev),
            (Kind::CharDevice, DeviceNumber::new(1, 3))
        );
        assert_eq!(
            (at(b"t/blk").kind, at(b"t/blk").rdev),
            (Kind::BlockDevice, DeviceNumber::new(8, 1))
        );
        assert_eq!(at(b"t/fifo").kind, Kind::Fifo);
        assert_eq!(at(b"t/sock").kind, Kind::Socket);
        assert_eq!(
            (at(b"t/sym").kind, at(b"t/sym").uid, at(b"t/sym").gid),
            (Kind::Symlink, 42, 43)
        );
        assert_eq!(data(&bytes, at(b"t/sym")), b"hl-last-c");
        // A file before its directory is lost, the directory is there.
        assert_eq!(tree.get(b"t/orphan/child"), None);
        assert_eq!(at(b"t/orphan").kind, Kind::Directory);
        // The later of two entries wins.
        assert_eq!(data(&bytes, at(b"t/dup")), b"two!");
        assert_eq!((at(b"t/dup").mode, at(b"t/dup").mtime), (0o644, T + 1));
        assert_eq!(
            (at(b"t/dirfile").kind, data(&bytes, at(b"t/dirfile"))),
            (Kind::Regular, &b"wasdir"[..])
        );
        // Equal inode numbers mean nothing without a link count.
        assert_ne!(tree.inode_id(b"t/zeroino-a"), tree.inode_id(b"t/zeroino-b"));
        assert_eq!(at(b"t/nl2-single").nlink, 1);
        // Device nodes are linked, symbolic links never are.
        assert_eq!(tree.inode_id(b"t/devhl-a"), tree.inode_id(b"t/devhl-b"));
        assert_eq!(at(b"t/devhl-b").nlink, 2);
        assert_ne!(tree.inode_id(b"t/symhl-a"), tree.inode_id(b"t/symhl-b"));
        assert_eq!(at(b"t/symhl-a").nlink, 1);
        assert_eq!(tree.get(b"t/dirsize"), None);
        assert_eq!(data(&bytes, at(b"t/after-dirsize")), b"ok");
        assert_eq!((at(b"t/emptysym").kind, at(b"t/emptysym").size), (Kind::Symlink, 0));
        assert_eq!(data(&bytes, at(b"t/TRAILER!!!")), b"notatrailer");
        assert_eq!(
            findings,
            [
                (FindingKind::MissingParent, b"t/orphan/child".to_vec()),
                (FindingKind::Replaced, b"t/dup".to_vec()),
                (FindingKind::Skipped(Skip::Data), b"t/dirsize".to_vec()),
                (FindingKind::EmptyTarget, b"t/emptysym".to_vec()),
                (FindingKind::LinkCount, b"t/nl2-single".to_vec()),
            ]
        );
        assert_eq!(tree.records(), entries.len() as u64 + 1);
        assert_eq!(tree.max_ino(), entries.iter().map(|e| e.ino).max().unwrap());
        assert_eq!(tree.format(), Some(Format::Newc));
        assert_eq!(tree.end(), End::Trailer(bytes.len() as u64));
        assert_eq!(tree.trailer_offset(), Some(bytes.len() as u64 - 124));
    }

    /// Entries that come after what they change, as booted.
    #[test]
    fn later_entries_change_what_earlier_ones_made() {
        let entries = [
            dir(b"t"),
            Raw::new(DIR, b"t/d").owner(1, 1).mtime(1000),
            dir(b"t/full"),
            reg(b"t/full/x", b"x"),
            reg(b"t/f2d", b"file"),
            reg(b"t/h1", b"").inode(5, 2),
            reg(b"t/h2", b"OLD").inode(5, 2),
            lnk(b"t/s2f", b"h2"),
            reg(b"t/f2s", b"file"),
            Raw::new(0o040700, b"t/d").owner(2, 2).mtime(2000),
            reg(b"t/full", b"F"),
            dir(b"t/f2d"),
            reg(b"t/h1", b"NEW!").owner(9, 0).mtime(T + 5),
            reg(b"t/s2f", b"nowfile"),
            lnk(b"t/f2s", b"gap-after"),
        ];
        let bytes = archive(&entries);
        let (tree, findings) = run_bytes(&bytes);
        let at = |name: &[u8]| tree.get(name).unwrap();
        // Mode and owner of the last entry, the time of the first.
        let d = at(b"t/d");
        assert_eq!((d.mode, d.uid, d.gid, d.mtime), (0o700, 2, 2, 1000));
        // A directory with something in it stays.
        assert_eq!(at(b"t/full").kind, Kind::Directory);
        assert_eq!(data(&bytes, at(b"t/full/x")), b"x");
        assert_eq!(at(b"t/f2d").kind, Kind::Directory);
        // Writing to one name of a file writes to all of them.
        assert_eq!(tree.inode_id(b"t/h1"), tree.inode_id(b"t/h2"));
        let h2 = at(b"t/h2");
        assert_eq!(
            (data(&bytes, h2), h2.uid, h2.mtime, h2.nlink),
            (&b"NEW!"[..], 9, T + 5, 2)
        );
        assert_eq!(
            (at(b"t/s2f").kind, data(&bytes, at(b"t/s2f"))),
            (Kind::Regular, &b"nowfile"[..])
        );
        assert_eq!(
            (at(b"t/f2s").kind, data(&bytes, at(b"t/f2s"))),
            (Kind::Symlink, &b"gap-after"[..])
        );
        assert_eq!(
            findings,
            [
                (FindingKind::Replaced, b"t/d".to_vec()),
                (FindingKind::DirectoryInTheWay, b"t/full".to_vec()),
                (FindingKind::Replaced, b"t/h1".to_vec()),
                (FindingKind::Replaced, b"t/f2s".to_vec()),
            ]
        );
    }

    /// Entries without a file type take away what is at their path, as
    /// booted.
    #[test]
    fn entries_without_a_type_remove() {
        let entries = [
            dir(b"t"),
            reg(b"t/file", b"data"),
            reg(b"t/keep", b"data"),
            lnk(b"t/sym", b"keep"),
            dir(b"t/emptydir"),
            dir(b"t/fulldir"),
            reg(b"t/fulldir/x", b"x"),
            Raw::new(CHR, b"t/node").rdev(1, 3),
            Raw::new(0, b"t/file"),
            Raw::new(0, b"t/sym"),
            Raw::new(0, b"t/emptydir"),
            Raw::new(0, b"t/fulldir"),
            Raw::new(0, b"t/node"),
            Raw::new(0, b"t/absent"),
            Raw::new(0o030644, b"t/keep"),
            Raw::new(0, b"t/data-notype").data(b"junk"),
            Raw::new(0, b"."),
        ];
        let (tree, findings) = run(&entries);
        assert_eq!(names(&tree), [".", "t", "t/fulldir", "t/fulldir/x"]);
        assert_eq!(
            findings
                .iter()
                .filter(|(kind, _)| *kind == FindingKind::Removal)
                .count(),
            8
        );
        assert!(findings.contains(&(FindingKind::Skipped(Skip::Data), b"t/data-notype".to_vec())));
    }

    /// The corners of the unpacker, as booted: what an entry does to a
    /// directory it cannot replace, whose time a path ends up with, and
    /// what becomes of a link whose first name is gone.
    #[test]
    fn the_corners_of_the_unpacker() {
        let entries = [
            dir(b"t"),
            dir(b"t/nd"),
            reg(b"t/nd/x", b"x"),
            Raw::new(CHR, b"t/nd").rdev(1, 3).owner(7, 8).mtime(5000),
            dir(b"t/sd"),
            reg(b"t/sd/x", b"x"),
            lnk(b"t/sd", b"x").owner(9, 9).mtime(6000),
            dir(b"t/p").mtime(1000),
            reg(b"t/p", b"f").mtime(7000),
            reg(b"t/twice", b"T").inode(50, 2),
            reg(b"t/twice", b"").inode(50, 2),
            reg(b"t/b1", b"B").inode(51, 2),
            Raw::new(0, b"t/b1"),
            reg(b"t/b2", b"").inode(51, 2),
            reg(b"t/c1", b"C").inode(52, 2),
            dir(b"t/c1"),
            reg(b"t/c2", b"").inode(52, 2),
            reg(b"t/slash/", b"s"),
            Raw::new(CHR, b"t/n").rdev(1, 3).mtime(T),
            Raw::new(0o020666, b"t/n").rdev(1, 5).owner(3, 0).mtime(T + 9),
        ];
        let (tree, _) = run(&entries);
        assert_eq!(
            names(&tree),
            [".", "t", "t/c1", "t/n", "t/nd", "t/nd/x", "t/p", "t/sd", "t/sd/x"]
        );
        let at = |name: &[u8]| tree.get(name).unwrap();
        // Owner and mode of the node land on the directory in its way, and
        // the time of the directory's own entry comes last.
        let nd = at(b"t/nd");
        assert_eq!(
            (nd.kind, nd.mode, nd.uid, nd.gid, nd.mtime),
            (Kind::Directory, 0o600, 7, 8, T)
        );
        let sd = at(b"t/sd");
        assert_eq!(
            (sd.kind, sd.mode, sd.uid, sd.gid, sd.mtime),
            (Kind::Directory, 0o755, 9, 9, T)
        );
        // The file that took the place of a directory gets the time of the
        // directory's entry.
        assert_eq!((at(b"t/p").kind, at(b"t/p").mtime), (Kind::Regular, 1000));
        assert_eq!(at(b"t/c1").kind, Kind::Directory);
        // A node that is there keeps its number.
        let n = at(b"t/n");
        assert_eq!(
            (n.mode, n.uid, n.mtime, n.rdev),
            (0o666, 3, T + 9, DeviceNumber::new(1, 3))
        );
        assert!(!tree.approximate());
    }

    #[test]
    fn names_are_read_as_a_lookup_reads_them() {
        let entries = [
            dir(b"./"),
            dir(b"./a"),
            reg(b"/a/b", b"1"),
            reg(b"a//c", b"2"),
            dir(b"a/d/"),
            dir(b"a/./e"),
            // The same file under another spelling replaces it.
            reg(b"./a/b", b"3"),
            reg(b"a/c/", b"lost"),
            reg(b"a/../z", b"unknown"),
            reg(b"", b"lost"),
            reg(&[b'n'; 256], b"lost"),
            lnk(b"l", b"a"),
            reg(b"l/x", b"through a link"),
            reg(b"a/b/x", b"below a file"),
            reg(b"nowhere/deep/x", b"lost"),
            reg(b"a/b/deep/x", b"below a file"),
            reg(b"l/deep/x", b"through a link"),
        ];
        let bytes = archive(&entries);
        let (tree, findings) = run_bytes(&bytes);
        assert_eq!(names(&tree), [".", "a", "a/b", "a/c", "a/d", "a/e", "l"]);
        assert_eq!(data(&bytes, tree.get(b"a/b").unwrap()), b"3");
        assert_eq!(data(&bytes, tree.get(b"a/c").unwrap()), b"2");
        assert_eq!(tree.root_stated(), RootStated::all());
        assert!(tree.approximate());
        let kinds: Vec<FindingKind> = findings.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            kinds,
            [
                FindingKind::LeadingDotSlash,
                FindingKind::LeadingDotSlash,
                FindingKind::Absolute,
                FindingKind::Unnormalized,
                FindingKind::Unnormalized,
                FindingKind::Unnormalized,
                FindingKind::LeadingDotSlash,
                FindingKind::Replaced,
                FindingKind::Unnormalized,
                FindingKind::TrailingSlash,
                FindingKind::DotDot,
                FindingKind::UnusableName,
                FindingKind::UnusableName,
                FindingKind::ParentIsSymlink,
                FindingKind::ParentNotDirectory,
                FindingKind::MissingParent,
                FindingKind::ParentNotDirectory,
                FindingKind::ParentIsSymlink,
            ]
        );
    }

    #[test]
    fn the_order_is_a_directory_then_what_is_in_it() {
        let entries = [
            dir(b"a"),
            reg(b"a.b", b""),
            reg(b"a/b", b""),
            dir(b"a/a"),
            reg(b"a/a/z", b""),
            reg(b"a0", b""),
            reg(b"B", b""),
            reg(b"a/Z", b""),
        ];
        let (tree, findings) = run(&entries);
        assert_eq!(findings, []);
        // The bytes of the names decide, one component at a time: "a/b"
        // comes before "a.b" although '.' sorts before '/'.
        assert_eq!(names(&tree), [".", "B", "a", "a/Z", "a/a", "a/a/z", "a/b", "a.b", "a0"]);
        let children = |name: &[u8]| -> Vec<String> {
            tree.children(name)
                .unwrap()
                .map(|(name, _)| String::from_utf8(name.to_vec()).unwrap())
                .collect()
        };
        assert_eq!(children(b"."), ["B", "a", "a.b", "a0"]);
        assert_eq!(children(b"a"), ["Z", "a", "b"]);
        assert_eq!(children(b"a/a"), ["z"]);
        assert!(tree.children(b"a/b").is_none());
        assert!(tree.children(b"nothing").is_none());
        assert_eq!(
            tree.counts(),
            Counts {
                files: 6,
                directories: 2,
                ..Counts::default()
            }
        );
        assert_eq!(tree.root_stated(), RootStated::empty());
    }

    #[test]
    fn a_file_with_several_names_is_counted_once() {
        let entries = [
            reg(b"a", b"").inode(1, 2),
            reg(b"b", b"12345").inode(1, 2),
            lnk(b"l", b"a"),
            Raw::new(CHR, b"n").rdev(1, 3),
        ];
        let (tree, _) = run(&entries);
        assert_eq!(
            tree.counts(),
            Counts {
                files: 1,
                directories: 0,
                symlinks: 1,
                nodes: 1,
                bytes: 5,
            }
        );
    }

    #[test]
    fn broken_link_groups() {
        // The first name gone, replaced by a directory, and named twice.
        let entries = [
            reg(b"a", b"A").inode(1, 3),
            Raw::new(0, b"a"),
            reg(b"a2", b"").inode(1, 3),
            reg(b"b", b"B").inode(2, 2),
            dir(b"b"),
            reg(b"b2", b"").inode(2, 2),
            reg(b"c", b"C").inode(3, 2),
            reg(b"c", b"").inode(3, 2),
        ];
        let (tree, findings) = run(&entries);
        assert_eq!(names(&tree), [".", "b"]);
        let kinds: Vec<FindingKind> = findings.iter().map(|(kind, _)| *kind).collect();
        assert_eq!(
            kinds,
            [
                FindingKind::Removal,
                FindingKind::BrokenLink,
                FindingKind::BrokenLink,
                FindingKind::BrokenLink,
                FindingKind::LinkCount,
            ]
        );
    }

    #[test]
    fn what_other_readers_stumble_over_is_found() {
        // Two directories and a file that share a number and count two.
        let shared = |name: &[u8]| Raw::new(DIR, name).inode(0, 2);
        let (_, findings) = run(&[shared(b"d1"), shared(b"d2"), reg(b"f", b"").inode(0, 2)]);
        assert_eq!(
            findings,
            [
                (FindingKind::SharedInode, b"d2".to_vec()),
                (FindingKind::SharedInode, b"f".to_vec()),
                (FindingKind::LinkCount, b"f".to_vec()),
            ]
        );
        // Both forms in one archive, a gap, and no trailer.
        let mut bytes = reg(b"a", b"x").bytes();
        bytes.extend([0u8; 8]);
        bytes.extend(reg(b"b", b"y").magic(b"070702").bytes());
        let (tree, findings) = run_bytes(&bytes);
        assert_eq!(
            findings,
            [
                (FindingKind::Gap, b"b".to_vec()),
                (FindingKind::MixedForms, b"b".to_vec()),
                (FindingKind::NoTrailer, Vec::new()),
            ]
        );
        assert_eq!(tree.end(), End::NoTrailer);
        assert_eq!(tree.trailer_offset(), Some(bytes.len() as u64));
        // A trailer that is more than a trailer.
        let mut bytes = reg(b"a", b"x").bytes();
        bytes.extend(Raw::new(REG, b"TRAILER!!!").data(b"data").bytes());
        let (_, findings) = run_bytes(&bytes);
        assert_eq!(findings, [(FindingKind::OddTrailer, b"TRAILER!!!".to_vec())]);
    }

    #[test]
    fn what_holds_no_archive_or_a_damaged_one_is_an_error() {
        let detail = |bytes: &[u8]| match Tree::open(bytes).unwrap_err().detail() {
            Some(crate::Detail::NotCpio { reason, .. }) => Some(*reason),
            _ => None,
        };
        assert_eq!(detail(&[]), Some(crate::NotCpioReason::Blank));
        assert_eq!(detail(&[0u8; 4096]), Some(crate::NotCpioReason::Blank));
        assert_eq!(detail(b"\x1f\x8b\x08 gzip"), Some(crate::NotCpioReason::OtherFormat));
        let good = archive(&[dir(b"d"), reg(b"d/f", b"data")]);
        Tree::open(&good).unwrap();
        // An archive that is stopped at its start was not finished: it is
        // one, and it is damaged.
        let mut stopped = good.clone();
        stopped[0] = crate::header::STOPPER;
        let unfinished = Tree::open(&stopped).unwrap_err();
        assert_eq!(unfinished.errno(), EUCLEAN);
        assert!(matches!(unfinished.detail(), Some(crate::Detail::Corrupt { .. })));
        assert!(unfinished.message().contains("not finished"));
        let (tree, damage) = Tree::replay(&stopped, &mut |_| {}).unwrap();
        assert_eq!(
            damage,
            Some(Damage::Magic {
                offset: 0,
                found: Some(crate::read::Foreign::Unfinished)
            })
        );
        assert_eq!((tree.records(), names(&tree)), (0, vec![".".to_string()]));
        let cut = Tree::open(&good[..200]).unwrap_err();
        assert_eq!(cut.errno(), EUCLEAN);
        assert!(matches!(cut.detail(), Some(crate::Detail::Corrupt { .. })));
        // The entries before the damage are in the tree a check gets.
        let (tree, damage) = Tree::replay(&good[..200], &mut |_| {}).unwrap();
        assert!(damage.is_some());
        assert_eq!(names(&tree), [".", "d"]);
        assert_eq!(tree.trailer_offset(), None);
    }

    /// Many entries in one directory and a deep path: every step is a
    /// lookup, none walks what is there.
    /// What is in the way of an entry is told by the lowest directory on
    /// its path that is there, however far up that is.
    #[test]
    fn what_is_in_the_way_of_an_entry_is_found_at_any_depth() {
        // A path of `depth` directories below `top`.
        let chain = |top: &str, depth: usize| -> String {
            let mut path = top.to_string();
            for level in 0..depth {
                path.push_str(&format!("/d{}", level));
            }
            path
        };
        for there in 0..6 {
            for below in 1..6 {
                for (top, kind) in [
                    ("dir", FindingKind::MissingParent),
                    ("file", FindingKind::ParentNotDirectory),
                    ("link", FindingKind::ParentIsSymlink),
                ] {
                    // `there` directories are there. The last of them is a
                    // file or a link for two of the three, and the entry
                    // goes `below` levels further down.
                    let mut entries = Vec::new();
                    let mut lowest = top.to_string();
                    entries.push(dir(b"dir"));
                    entries.push(dir(b"file"));
                    entries.push(dir(b"link"));
                    for depth in 1..=there {
                        lowest = chain(top, depth);
                        entries.push(dir(lowest.as_bytes()));
                    }
                    let blocker = format!("{}/blocker", lowest);
                    match top {
                        "file" => entries.push(reg(blocker.as_bytes(), b"x")),
                        "link" => entries.push(lnk(blocker.as_bytes(), b"elsewhere")),
                        _ => {}
                    }
                    let mut lost = blocker.clone();
                    for level in 0..below {
                        lost.push_str(&format!("/m{}", level));
                    }
                    entries.push(reg(lost.as_bytes(), b"lost"));
                    let (tree, findings) = run(&entries);
                    assert_eq!(
                        findings,
                        [(kind, lost.clone().into_bytes())],
                        "{} with {} directories and {} below",
                        top,
                        there,
                        below
                    );
                    assert!(tree.get(lost.as_bytes()).is_none());
                    assert_eq!(tree.approximate(), top == "link");
                }
            }
        }
    }

    /// The lowest directory that is there is found with a few lookups on
    /// the deepest path, wherever it is.
    #[test]
    fn the_lowest_directory_is_found_by_halving() {
        let depth = 2047;
        let key: Vec<u8> = std::iter::repeat_n(&b"\0a"[..], depth).flatten().copied().collect();
        for there in [0, 1, 2, 3, 500, 1023, 1024, 1025, 2045, 2046] {
            // The directories of the first `there` components are there.
            let mut lookups = 0;
            let lowest = Key::new(&key).lowest_there(&mut |part| {
                lookups += 1;
                part.as_bytes().len() <= 2 * there
            });
            assert_eq!(lowest.as_bytes(), &key[..2 * there], "{} are there", there);
            assert!(lookups <= 11, "{} lookups with {} there", lookups, there);
        }
        // The key of something in the root has nothing but the root above.
        assert!(Key::new(b"\0name").lowest_there(&mut |_| unreachable!()).is_root());
    }

    #[test]
    fn large_trees() {
        let mut entries = vec![dir(b"d")];
        for i in 0..20_000 {
            entries.push(reg(format!("d/{:05}", i).as_bytes(), b""));
        }
        let mut deep = String::from("d");
        for _ in 0..200 {
            deep.push_str("/x");
            entries.push(dir(deep.as_bytes()));
        }
        let (tree, findings) = run(&entries);
        assert_eq!(findings, []);
        assert_eq!(tree.children(b"d").unwrap().count(), 20_001);
        assert_eq!(tree.counts().directories, 201);
        assert!(tree.get(deep.as_bytes()).is_some());
    }
}
