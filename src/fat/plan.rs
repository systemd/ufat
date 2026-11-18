// SPDX-License-Identifier: LGPL-2.1-or-later
//! Working out how large a volume has to be for a given set of files.
//!
//! The planner counts directory slots with the same rules the populator
//! uses and rounds files to clusters the same way the writer does, then asks
//! [`layout::minimal`] for the smallest volume that offers that many
//! clusters. Formatting a volume of that size and copying the planned tree
//! into it therefore succeeds, with no cluster to spare beyond what the
//! FAT32 minimum demands, as long as FAT tells all names of a directory
//! apart.
//!
//! The entries come in tree order, as a tree walk and a manifest have them:
//! every directory before what is in it, and what is in it right after it.
//! So the planner keeps only the directories more entries can still go
//! into, the root and the ones on the way to the last entry, with the slots
//! their entries take so far. When the entries of a directory are done,
//! the clusters it takes are added up for every cluster size, and the
//! directory is forgotten. A file only adds its clusters. The memory a plan
//! takes grows with the depth of the tree and not with its entries, so a
//! manifest of any size can be planned while it is read.
//!
//! The planner does not compare names. Two names that FAT does not tell
//! apart, such as `A.TXT` and `a.txt`, or `FOO BAR` and `FOOBAR~1`, the
//! short name of `FOO BAR`, are two entries to the planner and one to a
//! copy. A file under the second name replaces the one under the first,
//! or fails without [`CopyOptions::replace`] or [`AssembleFlags::REPLACE`],
//! whichever the copy takes. The plan counts both files, so the volume
//! keeps the clusters of the replaced one free. The entries of a directory
//! under both names go into one directory, which the plan counts as two,
//! each held to the limit of entry slots on its own. The copy can then
//! still run out of entry slots in it. A file and a directory under such
//! names pass the plan, and the copy fails on the second one, replacing or
//! not.

use std::io::Read;
use std::iter::Peekable;
use std::ops::Range;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use uapi16::{Object, Order, Reader};

use crate::dir::MAX_SLOTS;
use crate::dirent::DIR_ENTRY_SIZE;
use crate::errno::*;
use crate::format::{encode_label, FormatOptions};
use crate::host::{walk_tree, HostEntry, UnnamableEntry};
use crate::layout::{self, Layout, LayoutParams, MAX_CLUSTERS, MAX_CLUSTER_SIZE, MAX_SECTORS_PER_CLUSTER};
use crate::manifest::{path_in_volume_into, AssembleFlags, EntryKind, ObjectAction, ObjectTriage, SizePurpose};
use crate::name::LongName;
use crate::path::{self, SEPARATOR};
use crate::populate::CopyOptions;
use crate::sys;
use crate::volume::MAX_FILE_SIZE;
use crate::{Context, Error, Result};
use crate::{Detail, NoSpaceReason};

/// How many cluster sizes a plan counts for: one for every number of
/// sectors per cluster, the powers of two up to [`MAX_SECTORS_PER_CLUSTER`].
const CLUSTER_SIZES: usize = MAX_SECTORS_PER_CLUSTER.ilog2() as usize + 1;
/// The entries every directory but the root starts with: "." and "..".
const DOT_ENTRIES: u64 = 2;

/// Parameters the size of a volume depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlanOptions {
    /// Bytes per sector.
    pub sector_size: u32,
    /// Bytes per cluster. None tries every cluster size and keeps the one
    /// giving the smallest volume.
    pub cluster_size: Option<u32>,
    /// Reserved sectors.
    pub reserved_sectors: u32,
    /// FAT copies.
    pub fats: u32,
    /// Whether the FATs and the data area are cluster aligned.
    pub align: bool,
    /// Allow fewer than [`layout::MIN_CLUSTERS`] clusters.
    pub allow_small: bool,
    /// Whether formatting will put a volume label entry into the root
    /// directory.
    pub label: bool,
}

impl PlanOptions {
    /// Default parameters for a sector size.
    pub fn new(sector_size: u32) -> PlanOptions {
        PlanOptions {
            sector_size,
            cluster_size: None,
            reserved_sectors: layout::DEFAULT_RESERVED_SECTORS,
            fats: layout::DEFAULT_FATS,
            align: true,
            allow_small: false,
            label: false,
        }
    }

    /// The parameters implied by format options, for a volume that will be
    /// formatted with them on a device with the given logical block size
    /// (None for an image file). The sector size is resolved the way the
    /// formatter resolves it, so that plan and format agree.
    pub fn from_format_options(options: &FormatOptions, device_block_size: Option<u32>) -> Result<PlanOptions> {
        let sector_size = crate::format::resolve_sector_size(options.sector_size, device_block_size)?;
        let label = match &options.label {
            Some(l) => encode_label(l)? != crate::boot::NO_NAME,
            None => false,
        };
        Ok(PlanOptions {
            sector_size,
            cluster_size: options.cluster_size,
            reserved_sectors: options.reserved_sectors,
            fats: options.fats,
            align: options.align,
            allow_small: options.allow_small,
            label,
        })
    }

    /// The parameters of the layout of a volume with `cluster_size` byte
    /// clusters.
    fn layout_params(&self, cluster_size: u32) -> LayoutParams {
        LayoutParams {
            sector_size: self.sector_size,
            sectors_per_cluster: cluster_size.checked_div(self.sector_size),
            reserved_sectors: self.reserved_sectors,
            fats: self.fats,
            align: self.align,
            track_sectors: None,
            allow_small: self.allow_small,
        }
    }
}

/// A directory below the root that more entries can still go into.
#[derive(Debug)]
struct OpenDirectory {
    /// Where its name is in the path of the open directories.
    name: Range<usize>,
    /// The slots its entries take so far.
    slots: u64,
}

/// The clusters a plan takes with one cluster size.
#[derive(Clone, Copy, Debug)]
struct Tally {
    /// The cluster size in bytes.
    cluster_size: u64,
    /// The clusters the files and the directories that are done take.
    clusters: u64,
}

impl Tally {
    /// The clusters `bytes` of data take.
    fn clusters_for(&self, bytes: u64) -> u64 {
        bytes.div_ceil(self.cluster_size)
    }

    /// The clusters a directory with `slots` slots takes: one at least.
    fn directory_clusters(&self, slots: u64) -> u64 {
        self.clusters_for(slots.saturating_mul(DIR_ENTRY_SIZE as u64)).max(1)
    }
}

/// The outcome of planning.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Estimate {
    /// The smallest layout that fits the plan.
    pub layout: Layout,
    /// Clusters the files and directories occupy.
    pub data_clusters: u32,
    /// Files in the plan.
    pub files: u64,
    /// Subdirectories in the plan.
    pub directories: u64,
    /// File bytes in the plan.
    pub bytes: u64,
}

impl Estimate {
    /// The volume size in bytes.
    pub fn size(&self) -> u64 {
        self.layout.size()
    }

    /// Sets the sector and cluster size of `options` to the ones the
    /// estimate was made for, so that formatting matches the plan.
    pub fn apply(&self, options: &mut FormatOptions) {
        options.sector_size = Some(self.layout.sector_size);
        options.cluster_size = Some(self.layout.cluster_size());
    }
}

/// A set of files and directories whose minimal volume size is wanted,
/// added in tree order, see the [module documentation](self).
#[derive(Debug)]
pub struct Plan {
    /// The parameters the plan is made with.
    options: PlanOptions,
    /// What the plan takes with every cluster size it can be estimated
    /// for, the smallest first. Empty for a sector size the layout does not
    /// take.
    tallies: Vec<Tally>,
    /// The slots the entries of the root take so far.
    root_slots: u64,
    /// The open directories below the root, each in the one before it.
    open: Vec<OpenDirectory>,
    /// The path of the deepest open directory: a slash and the name of
    /// every open directory. Empty for the root.
    open_path: String,
    /// The files added.
    files: u64,
    /// The directories added below the root.
    directories: u64,
    /// The bytes of the files added.
    bytes: u64,
}

impl Plan {
    /// An empty plan.
    pub fn new(options: PlanOptions) -> Plan {
        let tallies = if layout::valid_sector_size(options.sector_size) {
            (0..CLUSTER_SIZES)
                .map(|shift| Tally {
                    cluster_size: u64::from(options.sector_size) << shift,
                    clusters: 0,
                })
                .collect()
        } else {
            Vec::new()
        };
        Plan {
            options,
            tallies,
            root_slots: u64::from(options.label),
            open: Vec::new(),
            open_path: String::new(),
            files: 0,
            directories: 0,
            bytes: 0,
        }
    }

    /// The planning parameters.
    pub fn options(&self) -> &PlanOptions {
        &self.options
    }

    /// The path of the deepest open directory, as messages show it.
    fn deepest_path(&self) -> &str {
        if self.open_path.is_empty() {
            "/"
        } else {
            &self.open_path
        }
    }

    /// The name of the entry `path` names in the deepest open directory.
    /// None unless [`path::parent_and_name`] splits `path`, which it does
    /// where `path` fits [`path::MAX_PATH`] and its last name is one that
    /// [`path::names`] lets through, and the directory `path` is in is the
    /// deepest open one, as [`Plan::open_path`] has it. The directories on
    /// the way were checked when they were opened.
    fn name_in_deepest<'p>(&self, path: &'p str) -> Option<&'p str> {
        let (parent, name) = path::parent_and_name(path)?;
        (parent == self.open_path).then_some(name)
    }

    /// Takes the names off the front of `names` that lead from the root
    /// through open directories, and returns how many it took.
    fn skip_open<'n>(&self, names: &mut Peekable<impl Iterator<Item = &'n str>>) -> usize {
        let mut kept = 0;
        for dir in &self.open {
            let open = &self.open_path[dir.name.clone()];
            if names.next_if_eq(&open).is_none() {
                break;
            }
            kept += 1;
        }
        kept
    }

    /// Takes `slots` more slots in the deepest open directory, the one the
    /// next entry goes into. A directory cannot take more than
    /// [`MAX_SLOTS`], so beyond that the plan fails with ENOSPC, naming the
    /// directory.
    fn take_slots(&mut self, slots: u64) -> Result<()> {
        let taken = match self.open.last_mut() {
            Some(dir) => &mut dir.slots,
            None => &mut self.root_slots,
        };
        let total = *taken + slots;
        if total <= MAX_SLOTS as u64 {
            *taken = total;
            return Ok(());
        }
        let path = self.deepest_path();
        bail!(
            ENOSPC,
            Detail::NoSpace {
                reason: NoSpaceReason::DirectoryEntries,
                path: Some(path.to_string()),
            },
            "'{}' needs more than the {} entry slots a FAT32 directory holds",
            path,
            MAX_SLOTS
        )
    }

    /// Makes the directory that `dirs` lead to from the root the deepest
    /// open one: closes the open directories that are not on the way to
    /// it, and opens those on the way that are not open as new
    /// directories.
    fn descend<'n>(&mut self, dirs: impl Iterator<Item = &'n str>) -> Result<()> {
        let mut dirs = dirs.peekable();
        let kept = self.skip_open(&mut dirs);
        self.descend_from(kept, dirs)
    }

    /// [`Plan::descend`] where the first `kept` open directories are on
    /// the way: closes the others, and opens `dirs`, the rest of the way,
    /// as new directories.
    fn descend_from<'n>(&mut self, kept: usize, mut dirs: impl Iterator<Item = &'n str>) -> Result<()> {
        self.close_below(kept);
        dirs.try_for_each(|name| self.open_directory(name))
    }

    /// Closes the open directories but the first `kept`: the clusters they
    /// take are counted for every cluster size, and they are forgotten.
    fn close_below(&mut self, kept: usize) {
        let Some(first) = self.open.get(kept) else {
            return;
        };
        self.open_path.truncate(first.name.start - SEPARATOR.len_utf8());
        for dir in self.open.drain(kept..) {
            for tally in &mut self.tallies {
                tally.clusters = tally.clusters.saturating_add(tally.directory_clusters(dir.slots));
            }
        }
    }

    /// Opens a new directory named `name` in the deepest open one.
    fn open_directory(&mut self, name: &str) -> Result<()> {
        self.take_slots(LongName::slots_for(name)? as u64)?;
        self.open_path.push(SEPARATOR);
        let start = self.open_path.len();
        self.open_path.push_str(name);
        self.open.push(OpenDirectory {
            name: start..self.open_path.len(),
            slots: DOT_ENTRIES,
        });
        self.directories += 1;
        Ok(())
    }

    /// Adds a file of `size` bytes at `path`, from the root of the volume.
    /// Parent directories that are not open are added too. It counts right
    /// only in tree order, see the [module documentation](self): out of
    /// order, a directory is counted once for every run of its entries.
    fn add_file(&mut self, path: &str, size: u64) -> Result<()> {
        if size > MAX_FILE_SIZE {
            let path = path::join("/", path.trim_start_matches(SEPARATOR));
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: Some(path.clone()),
                    size,
                    maximum: MAX_FILE_SIZE,
                },
                "'{}' is larger than FAT32 allows ({} bytes)",
                path,
                MAX_FILE_SIZE
            );
        }
        let name = match self.name_in_deepest(path) {
            Some(name) => name,
            None => {
                let mut names = path::names(path)?;
                let Some(name) = names.next_back() else {
                    bail!(EISDIR, Detail::Path("/".to_string()), "'/' is the root directory")
                };
                self.descend(names)?;
                name
            }
        };
        self.take_slots(LongName::slots_for(name)? as u64)?;
        for tally in &mut self.tallies {
            tally.clusters = tally.clusters.saturating_add(tally.clusters_for(size));
        }
        self.files += 1;
        self.bytes = self.bytes.saturating_add(size);
        Ok(())
    }

    /// Adds a directory at `path`, from the root of the volume. Parent
    /// directories that are not open are added too, and a directory that
    /// is open is there already. It counts right only in tree order, as
    /// [`Plan::add_file`] does.
    fn add_dir(&mut self, path: &str) -> Result<()> {
        if let Some(name) = self.name_in_deepest(path) {
            return self.open_directory(name);
        }
        let mut names = path::names(path)?.peekable();
        let kept = self.skip_open(&mut names);
        // A directory that is open is there already.
        if names.peek().is_none() {
            return Ok(());
        }
        self.descend_from(kept, names)
    }

    /// Adds the tree below the open directory `source` under `dest`, the way
    /// the populator would copy it with `options`. The descriptor is what
    /// the caller resolved its path to, with [`crate::host::open_dir`] when
    /// it has a path, and may be O_PATH; nothing below it is looked up by
    /// path. Returns the entries that would be skipped because they are
    /// neither regular files nor directories, relative to `source`.
    pub fn add_tree(&mut self, source: BorrowedFd<'_>, dest: &str, options: &CopyOptions) -> Result<Vec<PathBuf>> {
        let md = sys::fstat(source).with_context(|| "failed to stat the source directory")?;
        if !md.is_dir() {
            bail!(ENOTDIR, "the source is not a directory");
        }
        self.add_dir(dest)?;
        let mut skipped = Vec::new();
        let mut visit = |target: &str, entry: &HostEntry| -> Result<bool> {
            if entry.is_dir() {
                self.add_dir(target)?;
                Ok(true)
            } else if entry.is_file() {
                self.add_file(target, entry.metadata.len())
                    .with_context(|| entry.path.display())?;
                Ok(false)
            } else {
                skipped.push(entry.path.clone());
                Ok(false)
            }
        };
        walk_tree(source, dest, options.follow_symlinks, UnnamableEntry::Fail, &mut visit)?;
        Ok(skipped)
    }

    /// Adds the files and directories of a manifest while `reader` reads
    /// it to its end, the way an assembly with `flags` stores them: what
    /// this crate cannot store fails the plan as it fails the assembly,
    /// unless [`AssembleFlags::SKIP_UNSUPPORTED`] leaves it out. Returns how
    /// many file objects are left out, see [`EntryKind`]. The manifest has to
    /// declare the code point order, and its file objects have to be in it,
    /// as for an assembly. Every regular file needs a size.
    pub fn add_records<R: Read>(&mut self, reader: &mut Reader<R>, flags: AssembleFlags) -> Result<u64> {
        reader.root().require_order(Order::CodePoint)?;
        let mut triage = ObjectTriage::default();
        let mut skipped = 0;
        // The path of each object in the volume, the one the assembly
        // opens, in one buffer.
        let mut path = String::new();
        while let Some(object) = reader.next() {
            let Object::File(object) = object? else {
                continue;
            };
            let action = triage.decide(&object, flags)?;
            path_in_volume_into(&object.name, &mut path);
            match action {
                ObjectAction::Skip(_) => skipped += 1,
                ObjectAction::Store(EntryKind::Directory) => self.add_dir(&path)?,
                ObjectAction::Store(EntryKind::File) => {
                    let Some(size) = object.size else {
                        return Err(Error::no_size(
                            object.name.as_str(),
                            Some(reader.record_number()),
                            SizePurpose::Planning,
                        ));
                    };
                    self.add_file(&path, size)?;
                }
            }
        }
        Ok(skipped)
    }

    /// The smallest volume for the plan with a given cluster size.
    pub fn estimate_for(&self, cluster_size: u32) -> Result<Estimate> {
        let ss = self.options.sector_size;
        if cluster_size == 0 || cluster_size.checked_rem(ss) != Some(0) {
            bail!(
                EINVAL,
                Detail::InvalidOption("clusterSize"),
                "cluster size {} is not a multiple of the sector size {}",
                cluster_size,
                ss
            );
        }
        let params = self.options.layout_params(cluster_size);
        params.validate()?;
        let Some(tally) = self
            .tallies
            .iter()
            .find(|tally| tally.cluster_size == u64::from(cluster_size))
        else {
            bail!(
                EINVAL,
                Detail::InvalidOption("clusterSize"),
                "cluster size {} is not a power of two up to {} sectors",
                cluster_size,
                MAX_SECTORS_PER_CLUSTER
            );
        };
        // The open directories are done as far as the plan goes.
        let clusters = self
            .open
            .iter()
            .map(|dir| dir.slots)
            .chain([self.root_slots])
            .fold(tally.clusters, |clusters, slots| {
                clusters.saturating_add(tally.directory_clusters(slots))
            });
        let Some(clusters) = u32::try_from(clusters).ok().filter(|&c| c <= MAX_CLUSTERS) else {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: None,
                    size: clusters.saturating_mul(u64::from(cluster_size)),
                    maximum: u64::from(MAX_CLUSTERS) * u64::from(cluster_size),
                },
                "{} clusters of {} bytes exceed the FAT32 maximum of {}",
                clusters,
                cluster_size,
                MAX_CLUSTERS
            );
        };
        let layout = layout::minimal(&params, clusters)?;
        Ok(Estimate {
            layout,
            data_clusters: clusters,
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        })
    }

    /// The smallest volume for the plan. Without a fixed cluster size every
    /// cluster size is tried and the smallest volume wins; among equals the
    /// larger cluster size.
    pub fn estimate(&self) -> Result<Estimate> {
        if let Some(cs) = self.options.cluster_size {
            return self.estimate_for(cs);
        }
        let ss = self.options.sector_size;
        let mut best: Option<Estimate> = None;
        let mut last_error = None;
        let mut spc = 1;
        while spc <= MAX_SECTORS_PER_CLUSTER && spc * ss <= MAX_CLUSTER_SIZE {
            match self.estimate_for(spc * ss) {
                Ok(e) => {
                    if best.as_ref().is_none_or(|b| e.size() <= b.size()) {
                        best = Some(e);
                    }
                }
                Err(e) => last_error = Some(e),
            }
            spc *= 2;
        }
        match best {
            Some(e) => Ok(e),
            None => Err(last_error
                .unwrap_or_else(|| err!(EINVAL, Detail::InvalidOption("clusterSize"), "no usable cluster size"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AssembleOptions, DirectorySource, PinnedDirectory, StreamSource};
    use crate::path::MAX_PATH;
    use crate::test_util::{TempDir, TempImage};
    use crate::volume::Volume;
    use crate::ManifestProblem;
    use std::os::fd::AsFd;
    use std::path::Path;
    use uapi16::{Features, FileObject, InodeType, Name, RootObject, Writer};

    fn options(ss: u32, cs: Option<u32>) -> PlanOptions {
        PlanOptions {
            cluster_size: cs,
            allow_small: true,
            ..PlanOptions::new(ss)
        }
    }

    /// The clusters the plan takes for every cluster size from one sector
    /// to [`MAX_SECTORS_PER_CLUSTER`] sectors.
    fn clusters(plan: &Plan) -> Vec<u32> {
        let ss = plan.options().sector_size;
        (0..CLUSTER_SIZES)
            .map(|shift| plan.estimate_for(ss << shift).unwrap().data_clusters)
            .collect()
    }

    /// The options of a copy that leaves symbolic links alone and replaces
    /// what is there.
    fn no_links() -> CopyOptions {
        CopyOptions {
            replace: true,
            follow_symlinks: false,
            ..CopyOptions::default()
        }
    }

    #[test]
    fn counts_slots_and_clusters() {
        let mut p = Plan::new(options(512, Some(512)));
        // Empty: the root directory alone.
        assert_eq!(p.estimate().unwrap().data_clusters, 1);
        p.add_file("/EFI/BOOT/BOOTX64.EFI", 1000).unwrap();
        p.add_file("/EFI/Linux/linux-6.12.efi", 512 * 10).unwrap();
        p.add_dir("/loader/entries").unwrap();
        let e = p.estimate().unwrap();
        // Root: EFI, loader -> 2 slots -> 1 cluster. EFI: dots + BOOT +
        // Linux -> 1 cluster. BOOT: dots + BOOTX64.EFI -> 1. Linux: dots +
        // (2 LFN + 1) -> 1. loader: dots + entries -> 1. entries: dots -> 1.
        // Files: 2 + 10 clusters.
        assert_eq!(e.data_clusters, 6 + 12);
        assert_eq!((e.files, e.directories, e.bytes), (2, 5, 1000 + 5120));
        // A directory that is open is there; one that was done is counted
        // again, and so is a name that comes twice.
        p.add_dir("/loader").unwrap();
        assert_eq!(p.estimate().unwrap().data_clusters, 6 + 12);
        p.add_file("/loader/entries/a.conf", 1).unwrap();
        assert_eq!(p.estimate().unwrap().data_clusters, 6 + 12 + 1);
        p.add_file("/EFI/Linux/linux-6.12.efi", 512 * 10).unwrap();
        assert_eq!(p.estimate().unwrap().data_clusters, 8 + 12 + 1 + 10);
        assert_eq!(p.add_file("/", 1).unwrap_err().errno(), EISDIR);
        for path in ["/x", "x"] {
            let e = p.add_file(path, MAX_FILE_SIZE + 1).unwrap_err();
            assert_eq!(e.errno(), EFBIG);
            assert!(
                matches!(e.detail(), Some(Detail::TooLarge { path: Some(p), .. }) if p == "/x"),
                "{:?}",
                e
            );
        }
        assert_eq!(p.add_file("/bad:name", 1).unwrap_err().errno(), EINVAL);
        assert_eq!(p.add_dir("/bad:name/x").unwrap_err().errno(), EINVAL);
        assert_eq!(p.add_file("/EFI/../x", 1).unwrap_err().errno(), EINVAL);
        // A last name of "." or ".." is the path's, not the directory's.
        for dots in [".", ".."] {
            let path = format!("/{}", dots);
            let refused = format!("path '{}' contains a '{}' component", path, dots);
            let e = Plan::new(options(512, None)).add_dir(&path).unwrap_err();
            assert_eq!((e.errno(), e.to_string()), (EINVAL, refused.clone()));
            let e = Plan::new(options(512, None)).add_file(&path, 1).unwrap_err();
            assert_eq!((e.errno(), e.to_string()), (EINVAL, refused));
        }
    }

    #[test]
    fn directory_growth_is_accounted() {
        let mut p = Plan::new(options(512, Some(512)));
        // 40 entries of 3 slots (21 character names need two long name
        // entries) plus the dot entries need 122 slots, eight 16-slot
        // clusters.
        for i in 0..40 {
            p.add_file(&format!("/d/Mixed Case File {}.txt", i), 0).unwrap();
        }
        assert_eq!(p.estimate().unwrap().data_clusters, 1 + 8);
        let mut p = Plan::new(PlanOptions {
            label: true,
            ..options(512, Some(512))
        });
        for i in 0..15 {
            p.add_file(&format!("/F{}", i), 0).unwrap();
        }
        // 15 short entries plus the label fill one cluster exactly.
        assert_eq!(p.estimate().unwrap().data_clusters, 1);
        p.add_file("/F15", 0).unwrap();
        assert_eq!(p.estimate().unwrap().data_clusters, 2);
    }

    /// The entry that a directory has no slots left for fails the plan,
    /// which names the directory.
    #[test]
    fn full_directories_are_refused() {
        let full = |path: &str| Detail::NoSpace {
            reason: NoSpaceReason::DirectoryEntries,
            path: Some(path.to_string()),
        };
        // The dot entries and 65534 short names fill a directory.
        let mut p = Plan::new(options(512, None));
        let names = MAX_SLOTS - DOT_ENTRIES as usize;
        for i in 0..names {
            p.add_file(&format!("/d/F{}", i), 0).unwrap();
        }
        let e = p.add_file(&format!("/d/F{}", names), 0).unwrap_err();
        assert_eq!(e.errno(), ENOSPC);
        assert_eq!(e.detail(), Some(&full("/d")));
        assert_eq!(p.estimate().unwrap().files, names as u64);
        // The label and 65535 short names fill the root.
        let mut p = Plan::new(PlanOptions {
            label: true,
            ..options(512, None)
        });
        for i in 0..MAX_SLOTS - 1 {
            p.add_file(&format!("/F{}", i), 0).unwrap();
        }
        let e = p.add_dir("/d").unwrap_err();
        assert_eq!((e.errno(), e.detail()), (ENOSPC, Some(&full("/"))));
    }

    #[test]
    fn picks_the_smallest_cluster_size() {
        let mut p = Plan::new(options(512, None));
        p.add_file("/a", 1).unwrap();
        let e = p.estimate().unwrap();
        // A tiny tree: the smallest volume uses the smallest clusters.
        assert_eq!(e.layout.cluster_size(), 512);
        assert!(e.size() < 64 * 1024);
        // Many large files: bigger clusters shrink the FAT more than the
        // slack costs.
        let mut p = Plan::new(options(512, None));
        for i in 0..64 {
            p.add_file(&format!("/f{}", i), 64 << 20).unwrap();
        }
        let e = p.estimate().unwrap();
        assert!(e.layout.cluster_size() >= 4096, "{:?}", e.layout);
        for spc in [1u32, 2, 4, 8, 16, 32, 64] {
            let other = p.estimate_for(spc * 512).unwrap();
            assert!(other.size() >= e.size());
        }
        for cs in [0, 256, 768, 3 * 512, 256 * 512] {
            assert_eq!(p.estimate_for(cs).unwrap_err().errno(), EINVAL, "{}", cs);
        }
        for cs in [0, 256, 768] {
            assert_eq!(
                p.estimate_for(cs).unwrap_err().to_string(),
                format!("cluster size {} is not a multiple of the sector size 512", cs)
            );
        }
        let p = Plan::new(options(1000, None));
        assert_eq!(p.estimate().unwrap_err().errno(), EINVAL);
    }

    #[test]
    fn strict_minimum_applies() {
        let mut p = Plan::new(PlanOptions {
            cluster_size: Some(4096),
            ..PlanOptions::new(4096)
        });
        p.add_file("/a", 1).unwrap();
        let e = p.estimate().unwrap();
        assert!(e.layout.clusters >= layout::MIN_CLUSTERS);
        assert!(e.size() > 256 << 20);
    }

    /// A tree in tree order: every directory before its entries, and its
    /// entries sorted by the bytes of their names right after it, which is
    /// also the code point order of a manifest. None is a directory,
    /// Some(size) a file. No two names in a directory differ in case only.
    fn synthetic_tree() -> Vec<(String, Option<u64>)> {
        enum Node {
            File(String, u64),
            Dir(String, Vec<Node>),
        }
        const SIZES: [u64; 15] = [
            0,
            1,
            511,
            512,
            513,
            1023,
            4095,
            4096,
            4097,
            32767,
            32768,
            32769,
            65537,
            100_000,
            1 << 20,
        ];
        // Names of every shape the slots depend on: 8.3 in upper and in
        // lower case, mixed case, spaces, a character outside ASCII, long
        // names of up to 255 units, more than one dot.
        fn name(i: usize) -> String {
            match i % 7 {
                0 => format!("F{:05}.BIN", i),
                1 => format!("f{:05}.txt", i),
                2 => format!("Mixed{}.Txt", i),
                3 => format!("{}{}", "long name ".repeat(i % 5 + 1), i),
                4 => format!("\u{fc}{}.dat", i),
                5 => format!("{}{}", "x".repeat((13 * (i % 19 + 1)).min(250)), i),
                _ => format!("{}.tar.gz", i),
            }
        }
        fn files(from: usize, count: usize) -> Vec<Node> {
            (from..from + count)
                .map(|i| Node::File(name(i), SIZES[i % SIZES.len()]))
                .collect()
        }
        fn emit(prefix: &str, mut nodes: Vec<Node>, out: &mut Vec<(String, Option<u64>)>) {
            let key = |node: &Node| match node {
                Node::File(name, _) | Node::Dir(name, _) => name.clone().into_bytes(),
            };
            nodes.sort_by_key(key);
            for node in nodes {
                match node {
                    Node::File(name, size) => out.push((format!("{}{}", prefix, name), Some(size))),
                    Node::Dir(name, children) => {
                        let path = format!("{}{}", prefix, name);
                        out.push((path.clone(), None));
                        emit(&format!("{}/", path), children, out);
                    }
                }
            }
        }
        // A chain of 26 directories, each with two files.
        let mut chain = Node::Dir("deep25".into(), files(5000, 2));
        for level in (0..25).rev() {
            let mut inside = files(5100 + 2 * level, 2);
            inside.push(chain);
            chain = Node::Dir(format!("deep{:02}", level), inside);
        }
        let mut root = files(0, 40);
        root.extend([
            chain,
            // 700 files: many clusters of entries for every cluster size.
            Node::Dir("many".into(), files(1000, 700)),
            // 14 short names and the dot entries fill a cluster of 512
            // bytes, 15 need a second one.
            Node::Dir(
                "SIXTEEN".into(),
                (0..14).map(|i| Node::File(format!("S{:02}", i), 1)).collect(),
            ),
            Node::Dir(
                "SEVENTEEN".into(),
                (0..15).map(|i| Node::File(format!("S{:02}", i), 1)).collect(),
            ),
            Node::Dir("empty".into(), Vec::new()),
            Node::Dir(
                "Mixed Dir".into(),
                vec![
                    Node::Dir("EMPTY".into(), Vec::new()),
                    Node::Dir("sub".into(), files(3000, 30)),
                    Node::File("x".into(), 3),
                ],
            ),
        ]);
        let mut out = Vec::new();
        emit("", root, &mut out);
        out
    }

    /// Creates `tree` below `dir`: its directories, and its files as sparse
    /// files of their sizes.
    fn make_tree(dir: &Path, tree: &[(String, Option<u64>)]) {
        for (path, size) in tree {
            let path = dir.join(path);
            match size {
                Some(size) => std::fs::File::create(&path).unwrap().set_len(*size).unwrap(),
                None => std::fs::create_dir(&path).unwrap(),
            }
        }
    }

    /// A manifest of `tree` that gives the size of every file.
    fn manifest_of(tree: &[(String, Option<u64>)]) -> Vec<u8> {
        let mut root = RootObject::default();
        root.features = Some(Features::SIZE);
        root.order = Some(Order::CodePoint);
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        for (name, size) in tree {
            let mut object = FileObject::new(Name::new(name.as_str()).unwrap());
            match size {
                Some(size) => object.size = Some(*size),
                None => object.inode_type = InodeType::Directory,
            }
            writer.file(&object).unwrap();
        }
        writer.finish().unwrap()
    }

    /// What the planner said for the synthetic tree when it kept every name
    /// of a directory, for 512 and 4096 byte sectors and every number of
    /// sectors per cluster, with the entries below the root, and below
    /// /below/here.
    const SYNTHETIC_512: [u32; CLUSTER_SIZES] = [140547, 70467, 35485, 18021, 9317, 4992, 2830, 1749];
    const SYNTHETIC_4096: [u32; CLUSTER_SIZES] = [18021, 9317, 4992, 2830, 1749, 1208, 992, 884];
    const BELOW_512: [u32; CLUSTER_SIZES] = [140549, 70469, 35487, 18023, 9319, 4994, 2832, 1751];
    const BELOW_4096: [u32; CLUSTER_SIZES] = [18023, 9319, 4994, 2832, 1751, 1210, 994, 886];
    /// And the smallest volumes it found, with their cluster sizes.
    const BEST_512: (u64, u32) = (72739840, 1024);
    const BEST_4096: (u64, u32) = (74092544, 4096);
    const BEST_BELOW_512: u64 = 72741888;
    const BEST_BELOW_4096: u64 = 74100736;

    /// Checks a plan of the synthetic tree against the planner that kept
    /// every name.
    fn agrees(plan: &Plan, expected: &[u32; CLUSTER_SIZES], best: u64, directories: u64) {
        assert_eq!(clusters(plan), expected);
        let e = plan.estimate().unwrap();
        assert_eq!(e.size(), best);
        assert_eq!((e.files, e.directories, e.bytes), (852, directories, 71680534));
    }

    #[test]
    fn agrees_with_the_planner_that_kept_every_name() {
        let tree = synthetic_tree();
        assert_eq!(tree.len(), 885);
        for (ss, label, expected, best) in [
            (512, false, SYNTHETIC_512, BEST_512),
            (512, true, SYNTHETIC_512, BEST_512),
            (4096, false, SYNTHETIC_4096, BEST_4096),
            (4096, true, SYNTHETIC_4096, BEST_4096),
        ] {
            let mut plan = Plan::new(PlanOptions {
                label,
                ..options(ss, None)
            });
            for (path, size) in &tree {
                let path = format!("/{}", path);
                match size {
                    Some(size) => plan.add_file(&path, *size).unwrap(),
                    None => plan.add_dir(&path).unwrap(),
                }
            }
            agrees(&plan, &expected, best.0, 33);
            assert_eq!(plan.estimate().unwrap().layout.cluster_size(), best.1);
        }
    }

    #[test]
    fn walks_a_tree_in_tree_order() {
        let tmp = TempDir::new("plan-walk");
        make_tree(tmp.path(), &synthetic_tree());
        let dir = crate::host::open_dir(tmp.path()).unwrap();
        for (ss, label, expected, below, best, best_below) in [
            (512, false, SYNTHETIC_512, BELOW_512, BEST_512.0, BEST_BELOW_512),
            (4096, true, SYNTHETIC_4096, BELOW_4096, BEST_4096.0, BEST_BELOW_4096),
        ] {
            let plan_options = PlanOptions {
                label,
                ..options(ss, None)
            };
            let mut plan = Plan::new(plan_options);
            assert!(plan.add_tree(dir.as_fd(), "/", &no_links()).unwrap().is_empty());
            agrees(&plan, &expected, best, 33);
            // The directories on the way to the destination are the same
            // however its path is spelled.
            for dest in ["/below/here", "below/here", "//below//here/"] {
                let mut plan = Plan::new(plan_options);
                plan.add_tree(dir.as_fd(), dest, &no_links()).unwrap();
                agrees(&plan, &below, best_below, 35);
            }
        }
    }

    #[test]
    fn plans_a_manifest_while_it_is_read() {
        let manifest = manifest_of(&synthetic_tree());
        let mut plan = Plan::new(options(512, None));
        let mut reader = Reader::open(&manifest[..]).unwrap();
        assert_eq!(
            plan.add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED).unwrap(),
            0
        );
        agrees(&plan, &SYNTHETIC_512, BEST_512.0, 33);
    }

    /// A volume formatted with `options` and the plan's cluster size, of the
    /// size the plan gives.
    fn planned_volume(plan: &Plan, options: &FormatOptions) -> (TempImage, Volume) {
        let estimate = plan.estimate().unwrap();
        // Clusters to spare would hide a plan that counts too few.
        assert_eq!(estimate.layout.clusters, estimate.data_clusters);
        let mut options = options.clone();
        estimate.apply(&mut options);
        let image = TempImage::new(estimate.size());
        crate::format::format(&image.device(), &options).unwrap();
        let volume = Volume::open(image.device()).unwrap();
        (image, volume)
    }

    /// Plans `tree`, which `dir` holds, and puts it into volumes of the
    /// planned sizes, formatted with `options`: walked and copied from
    /// `dir`, and planned from a manifest of it and assembled with the
    /// contents in `dir`. Both replace what is there.
    fn fill_planned(dir: &Path, tree: &[(String, Option<u64>)], options: &FormatOptions) -> [(TempImage, Volume); 2] {
        let plan_options = PlanOptions::from_format_options(options, None).unwrap();
        let source = crate::host::open_dir(dir).unwrap();
        let mut plan = Plan::new(plan_options);
        plan.add_tree(source.as_fd(), "/", &no_links()).unwrap();
        let (copied_image, mut copied) = planned_volume(&plan, options);
        copied.copy_tree(source.as_fd(), "/", &no_links()).unwrap();

        let manifest = manifest_of(tree);
        let mut plan = Plan::new(plan_options);
        plan.add_records(&mut Reader::open(&manifest[..]).unwrap(), AssembleFlags::REPLACE)
            .unwrap();
        let (assembled_image, mut assembled) = planned_volume(&plan, options);
        let mut contents = DirectorySource::new(PinnedDirectory::new(source));
        let replacing = AssembleOptions {
            flags: AssembleFlags::REPLACE,
            ..AssembleOptions::default()
        };
        assembled
            .assemble(&mut Reader::open(&manifest[..]).unwrap(), &mut contents, &replacing)
            .unwrap();
        [(copied_image, copied), (assembled_image, assembled)]
    }

    /// The synthetic tree fills a volume of the size its plan gives, copied
    /// from a walk and assembled from a manifest, to the last cluster.
    #[test]
    fn the_planned_size_is_filled() {
        let tmp = TempDir::new("plan-fill");
        let tree = synthetic_tree();
        make_tree(tmp.path(), &tree);
        for (sector_size, cluster_size, label) in [
            (512, None, None),
            (512, Some(512), Some("PLANNED")),
            (4096, None, Some("PLANNED")),
        ] {
            let options = FormatOptions {
                sector_size: Some(sector_size),
                cluster_size,
                label: label.map(String::from),
                allow_small: true,
                ..FormatOptions::default()
            };
            for (_image, volume) in fill_planned(tmp.path(), &tree, &options) {
                assert_eq!(volume.free_clusters(), 0, "{:?}", options);
            }
        }
    }

    /// Names that FAT does not tell apart are two names to the plan: the
    /// file A.TXT and a.txt, which replaces it, and the directory EFI and
    /// efi, whose entries go into it. Replacing, the volume of the planned
    /// size holds them and keeps the clusters of A.TXT and of efi free.
    #[test]
    fn names_fat_does_not_tell_apart() {
        let tree: Vec<(String, Option<u64>)> = [
            ("A.TXT", Some(3000)),
            ("EFI", None),
            ("EFI/X", Some(1)),
            ("a.txt", Some(1000)),
            ("efi", None),
            ("efi/Y", Some(1)),
        ]
        .into_iter()
        .map(|(path, size)| (path.to_string(), size))
        .collect();
        let tmp = TempDir::new("plan-folded");
        make_tree(tmp.path(), &tree);
        let options = FormatOptions {
            sector_size: Some(512),
            cluster_size: Some(512),
            allow_small: true,
            ..FormatOptions::default()
        };
        let manifest = manifest_of(&tree);
        let plan = |flags| {
            let mut plan = Plan::new(PlanOptions::from_format_options(&options, None).unwrap());
            plan.add_records(&mut Reader::open(&manifest[..]).unwrap(), flags)
                .unwrap();
            plan
        };
        for flags in [AssembleFlags::REPLACE, AssembleFlags::NONE] {
            let e = plan(flags).estimate().unwrap();
            // The root, EFI and efi take a cluster each, A.TXT 6, X 1,
            // a.txt 2 and Y 1.
            assert_eq!((e.data_clusters, e.layout.clusters), (3 + 10, 3 + 10));
            assert_eq!((e.files, e.directories), (4, 2));
        }
        for (_image, volume) in fill_planned(tmp.path(), &tree, &options) {
            // The 6 clusters of A.TXT, which a.txt replaced, and the one of
            // efi, whose entries went into EFI.
            assert_eq!(volume.free_clusters(), 6 + 1);
            assert_eq!(volume.metadata("/A.TXT").unwrap().size, 1000);
            assert_eq!(volume.read_dir("/efi").unwrap().len(), 2);
        }
        // Without replacing, the assembly fails at a.txt, which the plan
        // took.
        let (_image, mut volume) = planned_volume(&plan(AssembleFlags::NONE), &options);
        let mut contents = DirectorySource::new(PinnedDirectory::new(crate::host::open_dir(tmp.path()).unwrap()));
        let not_replacing = AssembleOptions {
            flags: AssembleFlags::NONE,
            ..AssembleOptions::default()
        };
        let e = volume
            .assemble(&mut Reader::open(&manifest[..]).unwrap(), &mut contents, &not_replacing)
            .unwrap_err();
        assert_eq!(e.errno(), EEXIST);
    }

    /// A file and a directory under names that FAT does not tell apart
    /// pass the plan, and the assembly fails on the second one, replacing
    /// or not: ENOTDIR for the directory after the file, EISDIR for the
    /// file after the directory.
    #[test]
    fn a_file_and_a_directory_under_one_name() {
        for (tree, errno) in [
            ([("A", Some(1)), ("a", None), ("a/x", Some(1))], ENOTDIR),
            ([("A", None), ("A/x", Some(1)), ("a", Some(1))], EISDIR),
        ] {
            let tree: Vec<(String, Option<u64>)> =
                tree.into_iter().map(|(path, size)| (path.to_string(), size)).collect();
            let manifest = manifest_of(&tree);
            for flags in [AssembleFlags::REPLACE, AssembleFlags::NONE] {
                let mut plan = Plan::new(options(512, Some(512)));
                plan.add_records(&mut Reader::open(&manifest[..]).unwrap(), flags)
                    .unwrap();
                let (_image, mut volume) = crate::test_util::volume(8 << 20, 512, 512);
                let options = AssembleOptions {
                    flags,
                    ..AssembleOptions::default()
                };
                let e = volume
                    .assemble(
                        &mut Reader::open(&manifest[..]).unwrap(),
                        &mut StreamSource::new(&[1u8, 1][..]),
                        &options,
                    )
                    .unwrap_err();
                assert_eq!(e.errno(), errno, "{:?} {:?}", tree, e);
            }
        }
    }

    /// The plan holds a path to the limit of 4095 bytes as the assembly
    /// does, the slash in front of the name included: a name of 4094 bytes
    /// is planned and assembled, one of 4095 bytes neither.
    #[test]
    fn paths_at_the_limit() {
        // 15 directories of 255 byte names take 3840 bytes with a slash
        // after each, the name of the file the rest.
        let mut dirs = String::new();
        let mut tree = Vec::new();
        for i in 0..15 {
            dirs.push_str(&format!("{}{:x}", "d".repeat(254), i));
            tree.push((dirs.clone(), None));
            dirs.push(SEPARATOR);
        }
        for length in [MAX_PATH - 1, MAX_PATH] {
            let mut tree = tree.clone();
            tree.push((format!("{}{}", dirs, "f".repeat(length - dirs.len())), Some(0)));
            assert_eq!(tree.last().unwrap().0.len(), length);
            let manifest = manifest_of(&tree);
            let planned = Plan::new(options(512, Some(512)))
                .add_records(&mut Reader::open(&manifest[..]).unwrap(), AssembleFlags::NONE)
                .map(drop);
            let (_image, mut volume) = crate::test_util::volume(8 << 20, 512, 512);
            let assembled = volume
                .assemble(
                    &mut Reader::open(&manifest[..]).unwrap(),
                    &mut StreamSource::new(std::io::empty()),
                    &AssembleOptions::default(),
                )
                .map(drop);
            if length < MAX_PATH {
                assert!(planned.is_ok() && assembled.is_ok(), "{:?} {:?}", planned, assembled);
            } else {
                assert_eq!(planned.unwrap_err().errno(), ENAMETOOLONG);
                assert_eq!(assembled.unwrap_err().errno(), ENAMETOOLONG);
            }
        }
    }

    /// A directory whose entries come in two runs, under two names FAT does
    /// not tell apart, is two directories to the plan, each held to the
    /// limit of entry slots on its own. In one run, the plan fails at the
    /// entry that the directory has no slots left for, and names the
    /// directory.
    #[test]
    fn directories_in_two_runs() {
        // A long name of 255 characters takes 21 slots, so either run of
        // 1600 fits a directory, both do not.
        let run = |dir: &'static str, files: Range<usize>| {
            std::iter::once((dir.to_string(), None))
                .chain(files.map(move |i| (format!("{}/{:0>255}", dir, i), Some(0))))
        };
        let plan = |tree: Vec<(String, Option<u64>)>| {
            let manifest = manifest_of(&tree);
            let mut plan = Plan::new(options(512, None));
            plan.add_records(&mut Reader::open(&manifest[..]).unwrap(), AssembleFlags::REPLACE)
                .map(|_| plan)
        };
        let split = plan(run("EFI", 0..1600).chain(run("efi", 1600..3200)).collect()).unwrap();
        assert_eq!(split.estimate().unwrap().directories, 2);
        let e = plan(run("EFI", 0..3200).collect()).unwrap_err();
        assert_eq!(e.errno(), ENOSPC);
        assert_eq!(
            e.detail(),
            Some(&Detail::NoSpace {
                reason: NoSpaceReason::DirectoryEntries,
                path: Some("/EFI".to_string()),
            })
        );
    }

    #[test]
    fn manifests_leave_out_what_an_assembly_leaves_out() {
        let records = concat!(
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
            "\x1e{\"name\":\"a\",\"size\":600}\n",
            "\x1e{\"contents\":[{\"literal\":\"eA==\"}],\"name\":\"link\",\"type\":\"lnk\"}\n",
            "\x1e{\"name\":\"sub\",\"sha256\":\"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824\",\"size\":5,\"type\":\"dir\"}\n",
            "\x1e{\"name\":\"sub/x\",\"size\":1}\n",
            "\x1e{\"name\":\"sub/y\",\"type\":\"dir\"}\n",
            "\x1e{\"name\":\"sub/y/z\",\"size\":1}\n",
            "\x1e{\"name\":\"z\",\"size\":1}\n",
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
        );
        let mut plan = Plan::new(options(512, Some(512)));
        let mut reader = Reader::open(records.as_bytes()).unwrap();
        assert_eq!(
            plan.add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED).unwrap(),
            5
        );
        let e = plan.estimate().unwrap();
        assert_eq!(
            (e.files, e.directories, e.bytes, e.data_clusters),
            (2, 0, 601, 1 + 2 + 1)
        );
        // Without SKIP_UNSUPPORTED the plan fails where the assembly fails.
        let mut plan = Plan::new(options(512, Some(512)));
        let mut reader = Reader::open(records.as_bytes()).unwrap();
        let e = plan.add_records(&mut reader, AssembleFlags::NONE).unwrap_err();
        assert_eq!(e.errno(), EOPNOTSUPP);
        // A file FAT32 cannot hold and one without a size cannot be
        // planned, and a manifest out of code point order not at all.
        for (records, errno) in [
            (
                concat!(
                    "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
                    "\x1e{\"name\":\"big\",\"size\":4294967296}\n",
                    "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
                ),
                EFBIG,
            ),
            (
                concat!(
                    "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
                    "\x1e{\"name\":\"b\",\"size\":1}\n",
                    "\x1e{\"name\":\"a\",\"size\":1}\n",
                    "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
                ),
                EBADMSG,
            ),
            (
                concat!(
                    "\x1e{\"features\":[],\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
                    "\x1e{\"name\":\"a\"}\n",
                    "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
                ),
                EINVAL,
            ),
        ] {
            let mut plan = Plan::new(options(512, None));
            let mut reader = Reader::open(records.as_bytes()).unwrap();
            assert_eq!(
                plan.add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED)
                    .unwrap_err()
                    .errno(),
                errno,
                "{}",
                records
            );
        }
        // Nor one that does not declare the order, even with its objects in
        // it. Nothing of it is counted.
        let undeclared = concat!(
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
            "\x1e{\"name\":\"a\",\"size\":1}\n",
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
        );
        let mut plan = Plan::new(options(512, None));
        let mut reader = Reader::open(undeclared.as_bytes()).unwrap();
        let e = plan
            .add_records(&mut reader, AssembleFlags::SKIP_UNSUPPORTED)
            .unwrap_err();
        assert_eq!(e.errno(), EBADMSG);
        assert_eq!(
            e.detail(),
            Some(&Detail::Manifest {
                problem: ManifestProblem::Malformed(uapi16::Problem::NoOrder),
                record: Some(0),
                name: None,
                field: Some("order".to_string()),
            })
        );
        assert_eq!(plan.estimate().unwrap().files, 0);
    }
}
