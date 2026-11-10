// SPDX-License-Identifier: LGPL-2.1-or-later
//! Working out how large a volume has to be for a given set of files.
//!
//! The planner counts directory slots with the same rules the populator
//! uses and rounds files to clusters the same way the writer does, then asks
//! [`layout::minimal`] for the smallest volume that offers that many
//! clusters. Formatting a volume of that size and copying the planned tree
//! into it therefore succeeds, with no cluster to spare beyond what the
//! FAT32 minimum demands.

use std::collections::BTreeMap;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use crate::dir::MAX_SLOTS;
use crate::dirent::DIR_ENTRY_SIZE;
use crate::errno::*;
use crate::format::{encode_label, FormatOptions};
use crate::host::walk_tree;
use crate::layout::{self, Layout, LayoutParams, MAX_CLUSTERS, MAX_CLUSTER_SIZE, MAX_SECTORS_PER_CLUSTER};
use crate::name::{Alias, LongName};
use crate::path::components;
use crate::sys;
use crate::volume::MAX_FILE_SIZE;
use crate::{Context, Result};
use crate::{Detail, NoSpaceReason};

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
}

#[derive(Debug)]
enum Node {
    File { size: u64 },
    Dir(Dir),
}

/// A planned directory. Entries are keyed by their case folded name.
#[derive(Debug, Default)]
struct Dir {
    entries: BTreeMap<Vec<u16>, (String, Node)>,
}

/// Number of directory slots an entry named `name` occupies.
pub fn entry_slots(name: &LongName) -> usize {
    if Alias::of(name).needs_long_name {
        name.entry_count() + 1
    } else {
        1
    }
}

#[derive(Default)]
struct Totals {
    clusters: u64,
    files: u64,
    directories: u64,
    bytes: u64,
}

impl Dir {
    fn count(&self, is_root: bool, label: bool, cluster_size: u64, totals: &mut Totals) -> Result<()> {
        let mut slots: u64 = if is_root { u64::from(label) } else { 2 };
        for (name, node) in self.entries.values() {
            slots += entry_slots(&LongName::new(name)?) as u64;
            match node {
                Node::File { size } => {
                    totals.files += 1;
                    totals.bytes += size;
                    totals.clusters += size.div_ceil(cluster_size);
                }
                Node::Dir(d) => {
                    totals.directories += 1;
                    d.count(false, label, cluster_size, totals)?;
                }
            }
        }
        if slots > MAX_SLOTS as u64 {
            bail!(
                ENOSPC,
                Detail::NoSpace {
                    reason: NoSpaceReason::DirectoryEntries,
                    path: None,
                },
                "a directory needs {} entry slots, FAT32 directories hold at most {}",
                slots,
                MAX_SLOTS
            );
        }
        totals.clusters += (slots * DIR_ENTRY_SIZE as u64).div_ceil(cluster_size).max(1);
        Ok(())
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

/// A set of files and directories whose minimal volume size is wanted.
#[derive(Debug)]
pub struct Plan {
    options: PlanOptions,
    root: Dir,
}

impl Plan {
    /// An empty plan.
    pub fn new(options: PlanOptions) -> Plan {
        Plan {
            options,
            root: Dir::default(),
        }
    }

    /// The planning parameters.
    pub fn options(&self) -> &PlanOptions {
        &self.options
    }

    /// Finds or creates the directory at `comps`.
    fn dir_mut(&mut self, comps: &[&str]) -> Result<&mut Dir> {
        let mut dir = &mut self.root;
        for (i, c) in comps.iter().enumerate() {
            let name = LongName::new(c)?;
            let (_, node) = dir
                .entries
                .entry(name.folded())
                .or_insert_with(|| (name.as_str().to_string(), Node::Dir(Dir::default())));
            dir = match node {
                Node::Dir(d) => d,
                Node::File { .. } => {
                    let p = format!("/{}", comps[..=i].join("/"));
                    bail!(ENOTDIR, Detail::Path(p.clone()), "'{}' is a file", p)
                }
            };
        }
        Ok(dir)
    }

    /// Adds a file of `size` bytes at `path`, creating parent directories.
    /// A file already planned under that name is replaced.
    pub fn add_file(&mut self, path: &str, size: u64) -> Result<()> {
        if size > MAX_FILE_SIZE {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: Some(path.to_string()),
                    size,
                    maximum: MAX_FILE_SIZE,
                },
                "'{}' is larger than FAT32 allows ({} bytes)",
                path,
                MAX_FILE_SIZE
            );
        }
        let comps = components(path)?;
        let Some((last, parents)) = comps.split_last() else {
            bail!(
                EISDIR,
                Detail::Path(path.to_string()),
                "'{}' is the root directory",
                path
            )
        };
        let name = LongName::new(last)?;
        let dir = self.dir_mut(parents)?;
        if let Some((_, Node::Dir(_))) = dir.entries.get(&name.folded()) {
            bail!(EISDIR, Detail::Path(path.to_string()), "'{}' is a directory", path);
        }
        dir.entries
            .insert(name.folded(), (name.as_str().to_string(), Node::File { size }));
        Ok(())
    }

    /// Adds a directory at `path`, creating parents. Existing directories
    /// are fine.
    pub fn add_dir(&mut self, path: &str) -> Result<()> {
        let comps = components(path)?;
        self.dir_mut(&comps)?;
        Ok(())
    }

    /// Adds the tree below the open directory `source` under `dest`, the way
    /// the populator would copy it. The descriptor is what the caller
    /// resolved its path to, with [`crate::host::open_dir`] when it has a
    /// path, and may be O_PATH; nothing below it is looked up by path.
    /// Returns the entries that would be skipped because they are neither
    /// regular files nor directories, relative to `source`.
    pub fn add_tree(&mut self, source: BorrowedFd<'_>, dest: &str, follow_symlinks: bool) -> Result<Vec<PathBuf>> {
        let md = sys::fstat(source).with_context(|| "failed to stat the source directory")?;
        if !md.is_dir() {
            bail!(ENOTDIR, "the source is not a directory");
        }
        self.add_dir(dest)?;
        let mut skipped = Vec::new();
        walk_tree(source, dest, follow_symlinks, &mut |target, entry| {
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
        })?;
        Ok(skipped)
    }

    /// The smallest volume for the plan with a given cluster size.
    pub fn estimate_for(&self, cluster_size: u32) -> Result<Estimate> {
        let ss = self.options.sector_size;
        if cluster_size == 0 || cluster_size % ss != 0 {
            bail!(
                EINVAL,
                Detail::InvalidOption("clusterSize"),
                "cluster size {} is not a multiple of the sector size {}",
                cluster_size,
                ss
            );
        }
        let spc = cluster_size / ss;
        if !spc.is_power_of_two() || spc > MAX_SECTORS_PER_CLUSTER {
            bail!(
                EINVAL,
                Detail::InvalidOption("clusterSize"),
                "cluster size {} is not a power of two up to {} sectors",
                cluster_size,
                MAX_SECTORS_PER_CLUSTER
            );
        }
        let mut totals = Totals::default();
        self.root
            .count(true, self.options.label, u64::from(cluster_size), &mut totals)?;
        if totals.clusters > u64::from(MAX_CLUSTERS) {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: None,
                    size: totals.clusters * u64::from(cluster_size),
                    maximum: u64::from(MAX_CLUSTERS) * u64::from(cluster_size),
                },
                "{} clusters of {} bytes exceed the FAT32 maximum of {}",
                totals.clusters,
                cluster_size,
                MAX_CLUSTERS
            );
        }
        let params = LayoutParams {
            sector_size: ss,
            sectors_per_cluster: Some(spc),
            reserved_sectors: self.options.reserved_sectors,
            fats: self.options.fats,
            align: self.options.align,
            track_sectors: None,
            allow_small: self.options.allow_small,
        };
        let layout = layout::minimal(&params, totals.clusters as u32)?;
        Ok(Estimate {
            layout,
            data_clusters: totals.clusters as u32,
            files: totals.files,
            directories: totals.directories,
            bytes: totals.bytes,
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

    fn options(ss: u32, cs: Option<u32>) -> PlanOptions {
        PlanOptions {
            cluster_size: cs,
            allow_small: true,
            ..PlanOptions::new(ss)
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
        // Replacing a file does not double count it.
        p.add_file("/EFI/boot/bootx64.efi", 100).unwrap();
        assert_eq!(p.estimate().unwrap().data_clusters, 6 + 11);
        assert_eq!(p.add_file("/EFI", 1).unwrap_err().errno(), EISDIR);
        assert_eq!(p.add_file("/EFI/BOOT/BOOTX64.EFI/x", 1).unwrap_err().errno(), ENOTDIR);
        assert_eq!(p.add_dir("/EFI/BOOT/BOOTX64.EFI").unwrap_err().errno(), ENOTDIR);
        assert_eq!(p.add_file("/x", MAX_FILE_SIZE + 1).unwrap_err().errno(), EFBIG);
        assert_eq!(p.add_file("/bad:name", 1).unwrap_err().errno(), EINVAL);
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
}
