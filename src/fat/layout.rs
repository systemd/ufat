// SPDX-License-Identifier: LGPL-2.1-or-later
//! Volume geometry: how many sectors go to the reserved area, the FATs and
//! the data clusters.
//!
//! The forward computation ([`compute`]) follows mkfs.fat so that volumes
//! formatted by this crate and by mkfs.fat come out identical for the same
//! parameters. The reverse computation ([`minimal`]) answers the question
//! systemd-repart asks: how many sectors does a volume need to offer a given
//! number of data clusters.

use crate::errno::*;
use crate::fat::ENTRY_SIZE;
use crate::Result;
use crate::{Detail, NoSpaceReason};

/// The detail of a volume too small for any FAT32 file system of the
/// geometry asked for.
fn too_small_volume() -> Detail {
    Detail::NoSpace {
        reason: NoSpaceReason::Volume,
        path: None,
    }
}

/// The smallest cluster count the FAT specification allows for FAT32. EDK2
/// based firmware refuses FAT32 volumes with fewer clusters, Windows treats
/// them as FAT16, so for an ESP this is a hard floor.
pub const MIN_CLUSTERS: u32 = 65525;
/// The first cluster of the data area. FAT entries 0 and 1 belong to no
/// cluster: entry 0 holds the media descriptor, entry 1 the volume flags.
pub const FIRST_CLUSTER: u32 = 2;
/// The largest cluster count a FAT32 volume can have (cluster numbers run
/// from 2 to 0x0FFFFFF6).
pub const MAX_CLUSTERS: u32 = 0x0FFF_FFF5;
/// Smallest supported sector size.
pub const MIN_SECTOR_SIZE: u32 = 512;
/// Largest supported sector size. Linux does not mount anything larger.
pub const MAX_SECTOR_SIZE: u32 = 4096;

/// Largest sectors per cluster value.
pub const MAX_SECTORS_PER_CLUSTER: u32 = 128;
/// Largest cluster size in bytes that the FAT specification allows. Larger
/// clusters work on Linux and EDK2 but not everywhere.
pub const MAX_CLUSTER_SIZE: u32 = 32 * 1024;
/// Number of reserved sectors mkfs.fat uses for FAT32.
pub const DEFAULT_RESERVED_SECTORS: u32 = 32;
/// Number of FAT copies mkfs.fat creates.
pub const DEFAULT_FATS: u32 = 2;
/// Volumes with at most this many sectors are laid out without alignment,
/// like mkfs.fat does for floppy sized media.
pub const ALIGNMENT_THRESHOLD_SECTORS: u32 = 8192;

/// Whether `ss` is a sector size this crate accepts: a power of two between
/// [`MIN_SECTOR_SIZE`] and [`MAX_SECTOR_SIZE`].
pub fn valid_sector_size(ss: u32) -> bool {
    ss.is_power_of_two() && (MIN_SECTOR_SIZE..=MAX_SECTOR_SIZE).contains(&ss)
}

/// The geometry of a FAT32 volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Bytes per sector.
    pub sector_size: u32,
    /// Sectors per cluster.
    pub sectors_per_cluster: u32,
    /// Sectors before the first FAT.
    pub reserved_sectors: u32,
    /// Number of FAT copies.
    pub fats: u32,
    /// Sectors per FAT copy.
    pub fat_sectors: u32,
    /// Sectors in the volume.
    pub total_sectors: u32,
    /// Data clusters, numbered 2 to `clusters + 1`.
    pub clusters: u32,
}

impl Layout {
    /// Bytes per cluster.
    pub fn cluster_size(&self) -> u32 {
        self.sector_size * self.sectors_per_cluster
    }

    /// Volume size in bytes.
    pub fn size(&self) -> u64 {
        u64::from(self.total_sectors) * u64::from(self.sector_size)
    }

    /// First sector of FAT copy `index`.
    pub fn fat_start_sector(&self, index: u32) -> u64 {
        u64::from(self.reserved_sectors) + u64::from(index) * u64::from(self.fat_sectors)
    }

    /// Byte offset of FAT copy `index`.
    pub fn fat_offset(&self, index: u32) -> u64 {
        self.fat_start_sector(index) * u64::from(self.sector_size)
    }

    /// Size of one FAT copy in bytes.
    pub fn fat_size(&self) -> u64 {
        u64::from(self.fat_sectors) * u64::from(self.sector_size)
    }

    /// Number of entries one FAT copy can hold.
    pub fn fat_capacity(&self) -> u32 {
        u32::try_from(self.fat_size() / ENTRY_SIZE as u64).unwrap_or(u32::MAX)
    }

    /// Number of FAT entries in use: the reserved ones before
    /// [`FIRST_CLUSTER`] and one per cluster.
    pub fn fat_entries(&self) -> u32 {
        FIRST_CLUSTER + self.clusters
    }

    /// First sector of the data area, i.e. of [`FIRST_CLUSTER`].
    pub fn data_start_sector(&self) -> u64 {
        self.fat_start_sector(self.fats)
    }

    /// Byte offset of the data area.
    pub fn data_start(&self) -> u64 {
        self.data_start_sector() * u64::from(self.sector_size)
    }

    /// Highest valid cluster number.
    pub fn max_cluster(&self) -> u32 {
        self.fat_entries() - 1
    }

    /// Whether `cluster` is a valid data cluster number.
    pub fn valid_cluster(&self, cluster: u32) -> bool {
        (FIRST_CLUSTER..=self.max_cluster()).contains(&cluster)
    }

    /// Byte offset of a data cluster.
    pub fn cluster_offset(&self, cluster: u32) -> Result<u64> {
        if !self.valid_cluster(cluster) {
            bail!(
                EUCLEAN,
                "cluster {} is out of range {}..={}",
                cluster,
                FIRST_CLUSTER,
                self.max_cluster()
            );
        }
        Ok(self.data_start() + u64::from(cluster - FIRST_CLUSTER) * u64::from(self.cluster_size()))
    }

    /// Sectors actually covered by the layout; trailing sectors that do not
    /// fill a cluster are unused.
    pub fn used_sectors(&self) -> u64 {
        self.data_start_sector() + u64::from(self.clusters) * u64::from(self.sectors_per_cluster)
    }

    /// Whether the volume has fewer clusters than the FAT32 specification
    /// requires.
    pub fn below_spec_minimum(&self) -> bool {
        self.clusters < MIN_CLUSTERS
    }
}

/// Parameters for computing a layout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutParams {
    /// Bytes per sector, 512 to 4096.
    pub sector_size: u32,
    /// Sectors per cluster. None picks the value mkfs.fat would pick for the
    /// volume size.
    pub sectors_per_cluster: Option<u32>,
    /// Reserved sectors. mkfs.fat uses 32 and may round it up to the cluster
    /// size for alignment.
    pub reserved_sectors: u32,
    /// Number of FAT copies.
    pub fats: u32,
    /// Align the FATs and the data area to cluster boundaries like mkfs.fat
    /// does by default.
    pub align: bool,
    /// Truncate the total sector count to a multiple of this many sectors.
    /// mkfs.fat does that with the sectors-per-track value it makes up; it
    /// wastes space and is only useful for producing identical images.
    pub track_sectors: Option<u32>,
    /// Accept volumes with fewer than [`MIN_CLUSTERS`] clusters. Such volumes
    /// mount on Linux but are refused by EDK2 firmware.
    pub allow_small: bool,
}

impl LayoutParams {
    /// Default parameters for a given sector size.
    pub fn new(sector_size: u32) -> LayoutParams {
        LayoutParams {
            sector_size,
            sectors_per_cluster: None,
            reserved_sectors: DEFAULT_RESERVED_SECTORS,
            fats: DEFAULT_FATS,
            align: true,
            track_sectors: None,
            allow_small: false,
        }
    }

    /// Checks the parameters for consistency.
    pub fn validate(&self) -> Result<()> {
        let ss = self.sector_size;
        if !valid_sector_size(ss) {
            bail!(
                EINVAL,
                Detail::InvalidOption("sectorSize"),
                "sector size {} is not a power of two between {} and {}",
                ss,
                MIN_SECTOR_SIZE,
                MAX_SECTOR_SIZE
            );
        }
        if let Some(spc) = self.sectors_per_cluster {
            if !spc.is_power_of_two() || spc > MAX_SECTORS_PER_CLUSTER {
                bail!(
                    EINVAL,
                    Detail::InvalidOption("clusterSize"),
                    "sectors per cluster {} is not a power of two up to {}",
                    spc,
                    MAX_SECTORS_PER_CLUSTER
                );
            }
        }
        if self.reserved_sectors < 2 || self.reserved_sectors > u32::from(u16::MAX) {
            bail!(
                EINVAL,
                Detail::InvalidOption("reservedSectors"),
                "reserved sector count {} is not between 2 and 65535",
                self.reserved_sectors
            );
        }
        if self.fats == 0 || self.fats > 4 {
            bail!(
                EINVAL,
                Detail::InvalidOption("fats"),
                "FAT count {} is not between 1 and 4",
                self.fats
            );
        }
        if let Some(t) = self.track_sectors {
            if t == 0 {
                bail!(EINVAL, Detail::InvalidOption("trackSectors"), "track size 0");
            }
        }
        Ok(())
    }
}

fn align_up(value: u64, alignment: u64, align: bool) -> u64 {
    if align {
        value.next_multiple_of(alignment)
    } else {
        value
    }
}

/// The sectors per cluster mkfs.fat picks for a FAT32 volume of the given
/// size, following the table in the FAT specification. The thresholds are in
/// sectors, so with 4096-byte sectors they correspond to eight times larger
/// volumes.
pub fn default_sectors_per_cluster(total_sectors: u64) -> u32 {
    if total_sectors > 64 * 1024 * 1024 {
        64
    } else if total_sectors > 32 * 1024 * 1024 {
        32
    } else if total_sectors > 16 * 1024 * 1024 {
        16
    } else if total_sectors > 532_480 {
        8
    } else {
        1
    }
}

/// The disk geometry a volume claims in its boot sector. It only ends up
/// in informational BPB fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    /// Number of heads.
    pub heads: u16,
    /// Sectors per track.
    pub sectors_per_track: u16,
}

/// The geometry mkfs.fat makes up for a volume with no real geometry.
pub fn default_geometry(total_sectors: u64) -> Geometry {
    if total_sectors <= 524_288 {
        let heads = if total_sectors <= 32_768 {
            2
        } else if total_sectors <= 65_536 {
            4
        } else if total_sectors <= 262_144 {
            8
        } else {
            16
        };
        let sectors_per_track = if total_sectors <= 4096 { 16 } else { 32 };
        Geometry {
            heads,
            sectors_per_track,
        }
    } else {
        let heads = if total_sectors <= 16 * 63 * 1024 {
            16
        } else if total_sectors <= 32 * 63 * 1024 {
            32
        } else if total_sectors <= 64 * 63 * 1024 {
            64
        } else if total_sectors <= 128 * 63 * 1024 {
            128
        } else {
            255
        };
        Geometry {
            heads,
            sectors_per_track: 63,
        }
    }
}

/// Lays out a FAT32 volume of `total_sectors` sectors the way mkfs.fat
/// would.
pub fn compute(params: &LayoutParams, total_sectors: u64) -> Result<Layout> {
    params.validate()?;
    let ss = u64::from(params.sector_size);
    let fats = u64::from(params.fats);
    let mut total = total_sectors.min(u64::from(u32::MAX));
    if let Some(track) = params.track_sectors {
        total = total / u64::from(track) * u64::from(track);
    }
    let align = params.align && total > u64::from(ALIGNMENT_THRESHOLD_SECTORS);
    let mut spc = u64::from(
        params
            .sectors_per_cluster
            .unwrap_or_else(|| default_sectors_per_cluster(total_sectors)),
    );
    let max_spc = u64::from(params.sectors_per_cluster.unwrap_or(MAX_SECTORS_PER_CLUSTER));
    let mut reason = String::new();

    while spc <= max_spc {
        let reserved = align_up(u64::from(params.reserved_sectors), spc, align);
        if reserved > u64::from(u16::MAX) {
            bail!(
                EINVAL,
                Detail::InvalidOption("reservedSectors"),
                "{} reserved sectors aligned to {} sector clusters do not fit the 16 bit field",
                params.reserved_sectors,
                spc
            );
        }
        if total <= reserved {
            bail!(
                ENOSPC,
                too_small_volume(),
                "{} {} not enough for the {} reserved sectors",
                total,
                if total == 1 { "sector is" } else { "sectors are" },
                reserved
            );
        }
        let fatdata = total - reserved;
        // mkfs.fat's estimate: everything after the reserved area is split
        // between the FATs and the clusters they describe. Each FAT holds
        // the entries before the first cluster and one entry per cluster.
        let entry = ENTRY_SIZE as u64;
        let reserved_entries = u64::from(FIRST_CLUSTER);
        let estimate = (fatdata * ss + fats * reserved_entries * entry) / (spc * ss + fats * entry);
        let fat_sectors = align_up(((estimate + reserved_entries) * entry).div_ceil(ss), spc, align);
        let clusters = if fatdata > fats * fat_sectors {
            (fatdata - fats * fat_sectors) / spc
        } else {
            0
        };
        if clusters == 0 {
            reason = format!(
                "{} sectors are too few for a FAT32 volume with {}-sector clusters",
                total, spc
            );
        } else if clusters > u64::from(MAX_CLUSTERS) {
            reason = format!("{} clusters of {} sectors exceed the FAT32 maximum", clusters, spc);
        } else if clusters < u64::from(MIN_CLUSTERS) && !params.allow_small {
            bail!(
                ENOSPC,
                too_small_volume(),
                "{} sectors give only {} clusters of {} bytes, FAT32 needs at least {}",
                total,
                clusters,
                spc * ss,
                MIN_CLUSTERS
            );
        } else {
            return Ok(Layout {
                sector_size: params.sector_size,
                sectors_per_cluster: spc as u32,
                reserved_sectors: reserved as u32,
                fats: params.fats,
                fat_sectors: fat_sectors as u32,
                total_sectors: total as u32,
                clusters: clusters as u32,
            });
        }
        spc *= 2;
    }
    Err(crate::Error::new(ENOSPC, reason).with(too_small_volume()))
}

/// Finds the smallest volume (in sectors) whose layout offers at least
/// `clusters` data clusters with the given cluster size, which must be set
/// in `params`. Unless `allow_small` is set the result has at least
/// [`MIN_CLUSTERS`] clusters.
pub fn minimal(params: &LayoutParams, clusters: u32) -> Result<Layout> {
    params.validate()?;
    let Some(spc) = params.sectors_per_cluster.map(u64::from) else {
        bail!(EINVAL, "minimal layout needs a fixed cluster size");
    };
    let mut need = clusters.max(1);
    if !params.allow_small {
        need = need.max(MIN_CLUSTERS);
    }
    if need > MAX_CLUSTERS {
        bail!(
            EFBIG,
            Detail::TooLarge {
                path: None,
                size: u64::from(need) * spc * u64::from(params.sector_size),
                maximum: u64::from(MAX_CLUSTERS) * spc * u64::from(params.sector_size),
            },
            "{} clusters exceed the FAT32 maximum of {}",
            need,
            MAX_CLUSTERS
        );
    }
    let ss = u64::from(params.sector_size);
    let fats = u64::from(params.fats);
    let candidate = |align: bool| {
        let reserved = align_up(u64::from(params.reserved_sectors), spc, align);
        let entries = u64::from(FIRST_CLUSTER) + u64::from(need);
        let fat_sectors = align_up((entries * ENTRY_SIZE as u64).div_ceil(ss), spc, align);
        let total = reserved + fats * fat_sectors + u64::from(need) * spc;
        match params.track_sectors {
            Some(track) => total.next_multiple_of(u64::from(track)),
            None => total,
        }
    };
    // compute() only aligns volumes above the threshold, so start from the
    // unaligned estimate when that lands below it.
    let unaligned = candidate(false);
    let mut total = if !params.align || unaligned <= u64::from(ALIGNMENT_THRESHOLD_SECTORS) {
        unaligned
    } else {
        candidate(true)
    };
    // The forward computation may lose a cluster to rounding; grow until it
    // agrees.
    for _ in 0..1024 {
        if total > u64::from(u32::MAX) {
            bail!(
                EFBIG,
                Detail::TooLarge {
                    path: None,
                    size: u64::from(need) * spc * ss,
                    maximum: u64::from(MAX_CLUSTERS) * spc * ss,
                },
                "{} clusters of {} bytes do not fit a FAT32 volume",
                need,
                spc * ss
            );
        }
        let layout = compute(params, total)?;
        if layout.clusters >= need {
            return Ok(layout);
        }
        total += spc;
    }
    bail!(EIO, "minimal layout computation did not converge")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(ss: u32) -> LayoutParams {
        LayoutParams {
            allow_small: true,
            ..LayoutParams::new(ss)
        }
    }

    fn mkfs_fat_params(ss: u32, total_sectors: u64) -> LayoutParams {
        LayoutParams {
            track_sectors: Some(u32::from(default_geometry(total_sectors).sectors_per_track)),
            ..params(ss)
        }
    }

    #[test]
    fn matches_mkfs_fat_reference_geometries() {
        // Values observed from mkfs.fat 4.2 -F 32 on image files.
        let l = compute(&mkfs_fat_params(512, 2048), 2048).unwrap();
        assert_eq!(
            (l.sectors_per_cluster, l.reserved_sectors, l.total_sectors),
            (1, 32, 2048)
        );
        let l = compute(&mkfs_fat_params(512, 532_480), 532_480).unwrap();
        assert_eq!((l.sectors_per_cluster, l.total_sectors), (1, 532_476));
        let l = compute(&mkfs_fat_params(512, 614_400), 614_400).unwrap();
        assert_eq!((l.sectors_per_cluster, l.total_sectors), (8, 614_376));
        let l = compute(&mkfs_fat_params(512, 2_097_152), 2_097_152).unwrap();
        assert_eq!((l.sectors_per_cluster, l.total_sectors), (8, 2_097_144));
    }

    #[test]
    fn layout_is_consistent() {
        for ss in [512u32, 1024, 2048, 4096] {
            for total in [2048u64, 8192, 8193, 65_536, 204_800, 532_480, 1 << 21, 1 << 24] {
                let l = compute(&params(ss), total).unwrap();
                assert_eq!(u64::from(l.total_sectors), total);
                assert!(l.used_sectors() <= total);
                assert!(l.fat_entries() <= l.fat_capacity(), "{:?}", l);
                assert!(l.reserved_sectors >= DEFAULT_RESERVED_SECTORS);
                if total > u64::from(ALIGNMENT_THRESHOLD_SECTORS) {
                    assert_eq!(l.reserved_sectors % l.sectors_per_cluster, 0);
                    assert_eq!(l.fat_sectors % l.sectors_per_cluster, 0);
                }
                // One more cluster would not fit.
                assert!(
                    l.used_sectors() + u64::from(l.sectors_per_cluster) > total
                        || l.fat_entries() + 1 > l.fat_capacity()
                );
            }
        }
    }

    #[test]
    fn minimal_is_minimal() {
        for ss in [512u32, 4096] {
            for spc in [1u32, 2, 8, 64] {
                for need in [1u32, 2, 17, 1000, 65_524, 65_525, 65_526, 200_000] {
                    let p = LayoutParams {
                        sectors_per_cluster: Some(spc),
                        ..params(ss)
                    };
                    let l = minimal(&p, need).unwrap();
                    assert!(l.clusters >= need, "{:?} for {}", l, need);
                    // One cluster less of space must not suffice.
                    let smaller = u64::from(l.total_sectors) - u64::from(spc);
                    if let Ok(s) = compute(&p, smaller) {
                        assert!(s.clusters < need, "{:?} still fits {}", s, need)
                    }
                }
            }
        }
    }

    #[test]
    fn strict_minimum_is_enforced() {
        let p = LayoutParams::new(512);
        assert_eq!(compute(&p, 65_536).unwrap_err().errno(), ENOSPC);
        assert!(compute(&p, 67_584).is_ok());
        let p = LayoutParams {
            sectors_per_cluster: Some(1),
            ..LayoutParams::new(4096)
        };
        let l = minimal(&p, 1).unwrap();
        assert!(l.clusters >= MIN_CLUSTERS);
        // 65525 4 KiB clusters plus FATs: a bit over 256 MiB.
        assert!(l.size() > 256 * 1024 * 1024 && l.size() < 260 * 1024 * 1024);
    }

    #[test]
    fn reserved_sectors_must_fit_after_alignment() {
        let mut p = LayoutParams {
            reserved_sectors: 65_535,
            sectors_per_cluster: Some(2),
            ..params(512)
        };
        assert_eq!(compute(&p, 1 << 20).unwrap_err().errno(), EINVAL);
        p.sectors_per_cluster = Some(1);
        assert_eq!(compute(&p, 1 << 20).unwrap().reserved_sectors, 65_535);
    }

    #[test]
    fn too_small_and_too_large() {
        assert_eq!(compute(&params(512), 16).unwrap_err().errno(), ENOSPC);
        let p = LayoutParams {
            sectors_per_cluster: Some(1),
            ..params(512)
        };
        // 2 TiB of 512 byte clusters exceeds the cluster count limit.
        assert_eq!(compute(&p, 1 << 32).unwrap_err().errno(), ENOSPC);
        // Without a fixed cluster size the cluster size is grown instead.
        let l = compute(&params(512), 1 << 32).unwrap();
        assert_eq!(l.total_sectors, u32::MAX);
        assert!(l.clusters <= MAX_CLUSTERS);
    }

    #[test]
    fn geometry_table() {
        let geometry = |total| {
            let g = default_geometry(total);
            (g.heads, g.sectors_per_track)
        };
        assert_eq!(geometry(2048), (2, 16));
        assert_eq!(geometry(65_536), (4, 32));
        assert_eq!(geometry(204_800), (8, 32));
        assert_eq!(geometry(532_480), (16, 63));
        assert_eq!(geometry(2_097_152), (64, 63));
        assert_eq!(default_sectors_per_cluster(532_480), 1);
        assert_eq!(default_sectors_per_cluster(532_481), 8);
    }
}

/// Bounded model checking harnesses for Kani. They are
/// not compiled by rustc. Error message formatting is stubbed out: it is
/// irrelevant to the properties and dominates the solver's work.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn no_format(_: std::fmt::Arguments<'_>) -> String {
        String::new()
    }

    fn any_params(sector_size: u32, fixed_spc: bool) -> LayoutParams {
        let spc: u32 = kani::any_where(|s: &u32| s.is_power_of_two() && *s <= MAX_SECTORS_PER_CLUSTER);
        LayoutParams {
            sector_size,
            sectors_per_cluster: if fixed_spc || kani::any() { Some(spc) } else { None },
            reserved_sectors: kani::any_where(|r: &u32| *r >= 2 && *r <= u16::MAX as u32),
            fats: kani::any_where(|f: &u32| *f >= 1 && *f <= 4),
            align: kani::any(),
            track_sectors: None,
            allow_small: kani::any(),
        }
    }

    /// What every layout compute() returns must satisfy.
    fn consistent(p: &LayoutParams, total: u64, l: &Layout) {
        assert!(l.total_sectors as u64 <= total);
        assert!(l.used_sectors() <= l.total_sectors as u64);
        assert!(l.fat_entries() <= l.fat_capacity());
        assert!(l.clusters >= 1 && l.clusters <= MAX_CLUSTERS);
        assert!(p.allow_small || l.clusters >= MIN_CLUSTERS);
        assert!(l.reserved_sectors >= p.reserved_sectors);
        if p.align && l.total_sectors > ALIGNMENT_THRESHOLD_SECTORS {
            assert!(l.reserved_sectors % l.sectors_per_cluster == 0);
            assert!(l.fat_sectors % l.sectors_per_cluster == 0);
        }
    }

    /// The default parameters of an ESP, for any device size. Seconds.
    #[kani::proof]
    #[kani::unwind(10)]
    #[kani::stub(std::fmt::format, no_format)]
    fn compute_fixed_params_any_total() {
        let mut p = LayoutParams::new(512);
        p.sectors_per_cluster = Some(8);
        p.allow_small = true;
        let total: u64 = kani::any();
        if let Ok(l) = compute(&p, total) {
            consistent(&p, total, &l);
        }
    }

    /// Every parameter symbolic, for 512 byte sectors. Minutes.
    #[kani::proof]
    #[kani::unwind(10)]
    #[kani::stub(std::fmt::format, no_format)]
    fn compute_is_consistent_512() {
        let p = any_params(512, false);
        let total: u64 = kani::any();
        if let Ok(l) = compute(&p, total) {
            consistent(&p, total, &l);
        }
    }

    /// Every parameter symbolic, for 4096 byte sectors. Minutes.
    #[kani::proof]
    #[kani::unwind(10)]
    #[kani::stub(std::fmt::format, no_format)]
    fn compute_is_consistent_4096() {
        let p = any_params(4096, false);
        let total: u64 = kani::any();
        if let Ok(l) = compute(&p, total) {
            consistent(&p, total, &l);
        }
    }

    /// minimal() is the exact inverse of compute(): it offers the clusters
    /// asked for, compute() agrees with it, and one cluster less does not
    /// suffice. The unwind bound also proves the growth loop never needs
    /// more than five steps.
    fn minimal_inverts_compute(p: &LayoutParams) {
        let need: u32 = kani::any();
        if let Ok(l) = minimal(p, need) {
            let want = need.max(if p.allow_small { 1 } else { MIN_CLUSTERS });
            assert!(l.clusters >= want);
            assert!(compute(p, l.total_sectors as u64).unwrap() == l);
            let spc = p.sectors_per_cluster.unwrap() as u64;
            if let Ok(s) = compute(p, (l.total_sectors as u64).saturating_sub(spc)) {
                assert!(s.clusters < want);
            }
        }
    }

    /// mkfs.fat's parameters for an ESP, 32 reserved sectors, two FATs and
    /// aligned structures, with one cluster size and `allow_small` symbolic.
    fn esp_params(sector_size: u32, sectors_per_cluster: u32) -> LayoutParams {
        LayoutParams {
            sector_size,
            sectors_per_cluster: Some(sectors_per_cluster),
            reserved_sectors: 32,
            fats: 2,
            align: true,
            track_sectors: None,
            allow_small: kani::any(),
        }
    }

    /// The inverse property in slices: one harness per sector size (512 and
    /// 4096) and cluster size (1 to 128 sectors), for mkfs.fat's defaults
    /// otherwise, every needed cluster count and both values of
    /// `allow_small`. validate() accepts no other cluster size and
    /// compute() runs its doubling loop once when the cluster size is
    /// given, so the sixteen slices partition the domain of the SLOW
    /// harness below restricted to those defaults, and together they are
    /// that theorem. With the cluster size a constant the multiplications
    /// become shifts and each slice takes under a minute; with it symbolic
    /// the solver does not finish.
    macro_rules! minimal_inverse_slices {
        ($($name:ident: $ss:literal / $spc:literal),* $(,)?) => {
            $(
                #[kani::proof]
                #[kani::unwind(6)]
                #[kani::stub(std::fmt::format, no_format)]
                fn $name() {
                    minimal_inverts_compute(&esp_params($ss, $spc));
                }
            )*
        };
    }
    minimal_inverse_slices! {
        minimal_is_inverse_of_compute_512_spc1: 512 / 1,
        minimal_is_inverse_of_compute_512_spc2: 512 / 2,
        minimal_is_inverse_of_compute_512_spc4: 512 / 4,
        minimal_is_inverse_of_compute_512_spc8: 512 / 8,
        minimal_is_inverse_of_compute_512_spc16: 512 / 16,
        minimal_is_inverse_of_compute_512_spc32: 512 / 32,
        minimal_is_inverse_of_compute_512_spc64: 512 / 64,
        minimal_is_inverse_of_compute_512_spc128: 512 / 128,
        minimal_is_inverse_of_compute_4096_spc1: 4096 / 1,
        minimal_is_inverse_of_compute_4096_spc2: 4096 / 2,
        minimal_is_inverse_of_compute_4096_spc4: 4096 / 4,
        minimal_is_inverse_of_compute_4096_spc8: 4096 / 8,
        minimal_is_inverse_of_compute_4096_spc16: 4096 / 16,
        minimal_is_inverse_of_compute_4096_spc32: 4096 / 32,
        minimal_is_inverse_of_compute_4096_spc64: 4096 / 64,
        minimal_is_inverse_of_compute_4096_spc128: 4096 / 128,
    }

    /// The inverse property with every parameter symbolic: the reserved
    /// sector count, the FAT count and the alignment too. The solver did
    /// not finish this within half an hour, nor a variant with only the
    /// cluster size and count symbolic within twenty minutes, so it only
    /// runs with `SLOW=1 verify/run.sh`. The slices above prove it for
    /// mkfs.fat's defaults; the exhaustive sweep in tests/exhaustive.rs
    /// covers one FAT, no alignment and a track size for every cluster
    /// count up to 200000.
    #[cfg(slow_proofs)]
    #[kani::proof]
    #[kani::unwind(6)]
    #[kani::stub(std::fmt::format, no_format)]
    fn minimal_is_inverse_of_compute_512() {
        minimal_inverts_compute(&any_params(512, true));
    }
}
