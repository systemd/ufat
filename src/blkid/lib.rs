// SPDX-License-Identifier: LGPL-2.1-or-later
//! libblkid of util-linux, loaded at run time.
//!
//! The crate does not link against libblkid. [`Blkid::get`] loads
//! libblkid.so.1 with dlopen() the first time it is called, the way
//! systemd's dlopen_libblkid() does (src/shared/blkid-util.c), and a
//! program goes on without it when that fails. The `.note.dlopen` ELF note
//! of the program names libblkid as a recommended dependency. The
//! prototypes are those of blkid.h of util-linux.
//!
//! [`Blkid::probe`] asks libblkid what a range of a file or a block device
//! holds.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io;
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::{self, NonNull};

use dlopen::{Lazy, Symbols};
use dlopen_note::{Dependency, Priority};
use libc::{EIO, ENOMEM, EOVERFLOW};

// blkid.h: a blkid_probe is a pointer to an opaque struct, a blkid_loff_t
// is an int64_t.
type BlkidProbe = *mut c_void;
type BlkidLoff = i64;

dlopen::symbols! {
    /// libblkid, with the functions this crate calls. Each type is the
    /// prototype blkid.h declares for the function of the field's name.
    //
    // libblkid has had the soname libblkid.so.1 all along. util-linux gives
    // new functions a new symbol version instead of changing it
    // (libblkid/src/libblkid.sym), and systemd loads libblkid.so.1 alone as
    // well (src/shared/blkid-util.c). A libblkid.so.2 would come with a new
    // ABI, which these prototypes would have to be checked against before
    // it is tried.
    pub struct Blkid from c"libblkid.so.1" {
        blkid_new_probe: unsafe extern "C" fn() -> BlkidProbe,
        blkid_free_probe: unsafe extern "C" fn(BlkidProbe),
        blkid_probe_set_device: unsafe extern "C" fn(BlkidProbe, c_int, BlkidLoff, BlkidLoff) -> c_int,
        blkid_probe_enable_superblocks: unsafe extern "C" fn(BlkidProbe, c_int) -> c_int,
        blkid_probe_set_superblocks_flags: unsafe extern "C" fn(BlkidProbe, c_int) -> c_int,
        blkid_probe_enable_partitions: unsafe extern "C" fn(BlkidProbe, c_int) -> c_int,
        blkid_do_fullprobe: unsafe extern "C" fn(BlkidProbe) -> c_int,
        blkid_probe_lookup_value:
            unsafe extern "C" fn(BlkidProbe, *const c_char, *mut *const c_char, *mut usize) -> c_int,
    }
}

dlopen_note::note! {
    /// The note that names libblkid. It is recommended: a program works
    /// without it, but cannot name what an image holds then.
    static NOTE = Dependency {
        feature: "blkid",
        description: "Identification of file systems and partition tables in images",
        priority: Priority::Recommended,
        sonames: Blkid::SONAMES,
    };
}

/// blkid_probe_enable_superblocks() and blkid_probe_enable_partitions()
/// take TRUE to enable their chain.
const ENABLE: c_int = 1;
// The flags of the superblocks chain, BLKID_SUBLKS_* of blkid.h: define
// TYPE, USAGE and VERSION, and report a superblock whose checksum is wrong.
const BLKID_SUBLKS_TYPE: c_int = 1 << 5;
const BLKID_SUBLKS_USAGE: c_int = 1 << 7;
const BLKID_SUBLKS_VERSION: c_int = 1 << 8;
const BLKID_SUBLKS_BADCSUM: c_int = 1 << 10;
/// The superblocks chain defines the values [`Found`] holds, and also
/// reports a superblock whose checksum is wrong, as wipefs has it: a
/// damaged file system is still one.
const SUPERBLOCKS: c_int = BLKID_SUBLKS_TYPE | BLKID_SUBLKS_USAGE | BLKID_SUBLKS_VERSION | BLKID_SUBLKS_BADCSUM;
/// What blkid_do_fullprobe() returns: something found, or nothing.
const BLKID_PROBE_OK: c_int = 0;
const BLKID_PROBE_NONE: c_int = 1;
// The values a probe defines that this crate reads, by the names
// blkid_probe_lookup_value() takes.
const TYPE: &CStr = c"TYPE";
const USAGE: &CStr = c"USAGE";
const VERSION: &CStr = c"VERSION";
const PTTYPE: &CStr = c"PTTYPE";

/// What a probe found: the values of the NAME=value interface of libblkid
/// this crate reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// TYPE: the file system, RAID or LVM member, encrypted volume, swap
    /// space and so on that the superblocks chain found.
    pub name: Option<String>,
    /// USAGE: filesystem, raid, crypto or other.
    pub usage: Option<String>,
    /// VERSION: for vfat, FAT12, FAT16 or FAT32.
    pub version: Option<String>,
    /// PTTYPE: the partition table the partitions chain found.
    pub partition_table: Option<String>,
}

impl Blkid {
    /// libblkid, loaded on the first call. None when libblkid.so.1 cannot
    /// be loaded or lacks one of the functions, which only the first call
    /// tries.
    pub fn get() -> Option<&'static Blkid> {
        static BLKID: Lazy<Blkid> = Lazy::new();
        // Whatever can load libblkid refers to the note, so the note is in
        // every program that can.
        NOTE.keep();
        BLKID.get()
    }

    /// Probes the `len` bytes at `offset` of the file or block device `fd`
    /// refers to, with blkid_do_fullprobe(), as mkfs.xfs and mkfs.btrfs do
    /// before they format. The superblocks chain looks for a file system or
    /// another superblock, the partitions chain for a partition table.
    /// libblkid reads nothing outside the range. A `len` of 0 is all that
    /// follows `offset`.
    ///
    /// libblkid seeks and reads with `fd`, and sets advice and flags on its
    /// open file description. A caller that shares the open file
    /// description probes through one it opened anew. Threads can probe at
    /// the same time, each through an open file description of its own.
    ///
    /// Returns None when nothing was found.
    pub fn probe(&self, fd: BorrowedFd<'_>, offset: u64, len: u64) -> io::Result<Option<Found>> {
        let offset = BlkidLoff::try_from(offset).map_err(|_| io::Error::from_raw_os_error(EOVERFLOW))?;
        let len = BlkidLoff::try_from(len).map_err(|_| io::Error::from_raw_os_error(EOVERFLOW))?;
        let probe = Probe::new(self, fd, offset, len)?;
        probe.enable_superblocks(SUPERBLOCKS)?;
        probe.enable_partitions()?;
        if !probe.run()? {
            return Ok(None);
        }
        Ok(Some(Found {
            name: probe.value(TYPE),
            usage: probe.value(USAGE),
            version: probe.value(VERSION),
            partition_table: probe.value(PTTYPE),
        }))
    }
}

/// A probe of libblkid, freed when it is dropped. It reads with the
/// descriptor it was set up with, which it borrows for that.
struct Probe<'a> {
    blkid: &'a Blkid,
    raw: NonNull<c_void>,
    fd: PhantomData<BorrowedFd<'a>>,
}

#[allow(unsafe_code)]
impl<'a> Probe<'a> {
    /// A probe of the `len` bytes at `offset` of what `fd` refers to.
    fn new(blkid: &'a Blkid, fd: BorrowedFd<'a>, offset: BlkidLoff, len: BlkidLoff) -> io::Result<Probe<'a>> {
        // SAFETY: no arguments.
        let raw = unsafe { (blkid.blkid_new_probe)() };
        let probe = Probe {
            blkid,
            raw: NonNull::new(raw).ok_or_else(|| io::Error::from_raw_os_error(ENOMEM))?,
            fd: PhantomData,
        };
        Probe::call(|| {
            // SAFETY: a live probe, and a descriptor that stays open as long
            // as the probe, which borrows it.
            unsafe { (blkid.blkid_probe_set_device)(probe.raw.as_ptr(), fd.as_raw_fd(), offset, len) }
        })?;
        Ok(probe)
    }

    /// Enables the superblocks chain with `flags`.
    fn enable_superblocks(&self, flags: c_int) -> io::Result<()> {
        Probe::call(|| {
            // SAFETY: a live probe.
            unsafe { (self.blkid.blkid_probe_enable_superblocks)(self.raw.as_ptr(), ENABLE) }
        })?;
        Probe::call(|| {
            // SAFETY: a live probe.
            unsafe { (self.blkid.blkid_probe_set_superblocks_flags)(self.raw.as_ptr(), flags) }
        })?;
        Ok(())
    }

    /// Enables the partitions chain.
    fn enable_partitions(&self) -> io::Result<()> {
        Probe::call(|| {
            // SAFETY: a live probe.
            unsafe { (self.blkid.blkid_probe_enable_partitions)(self.raw.as_ptr(), ENABLE) }
        })?;
        Ok(())
    }

    /// Runs the chains that are enabled, with blkid_do_fullprobe().
    /// Whether one of them found something.
    fn run(&self) -> io::Result<bool> {
        let found = Probe::call(|| {
            // SAFETY: a live probe.
            unsafe { (self.blkid.blkid_do_fullprobe)(self.raw.as_ptr()) }
        })?;
        match found {
            BLKID_PROBE_OK => Ok(true),
            BLKID_PROBE_NONE => Ok(false),
            _ => Err(io::Error::from_raw_os_error(EIO)),
        }
    }

    /// The value `name` the probe defines, if it does.
    fn value(&self, name: &CStr) -> Option<String> {
        let mut data: *const c_char = ptr::null();
        let mut len: usize = 0;
        // SAFETY: a live probe, a NUL terminated name, and two pointers to
        // locals that receive the value and its length.
        let r = unsafe { (self.blkid.blkid_probe_lookup_value)(self.raw.as_ptr(), name.as_ptr(), &mut data, &mut len) };
        if r < 0 || data.is_null() {
            return None;
        }
        // SAFETY: libblkid hands out `len` bytes, the terminating NUL
        // included, which live as long as the probe.
        let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len) };
        let value = CStr::from_bytes_until_nul(bytes).map_or(bytes, CStr::to_bytes);
        Some(String::from_utf8_lossy(value).into_owned())
    }

    /// Makes a call of libblkid, which returns a negative number when it
    /// fails. Most failures set errno. errno is cleared before the call, so
    /// that a failure that leaves it alone is EIO, not an error an earlier
    /// call left there.
    fn call(call: impl FnOnce() -> c_int) -> io::Result<c_int> {
        // SAFETY: __errno_location() returns the address of the errno of
        // the calling thread.
        unsafe { *libc::__errno_location() = 0 };
        let r = call();
        if r >= 0 {
            return Ok(r);
        }
        let e = io::Error::last_os_error();
        Err(match e.raw_os_error() {
            Some(0) => io::Error::from_raw_os_error(EIO),
            _ => e,
        })
    }
}

impl Drop for Probe<'_> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: a probe blkid_new_probe() returned, freed once.
        unsafe { (self.blkid.blkid_free_probe)(self.raw.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    /// The size of the images.
    const IMAGE_SIZE: u64 = 1 << 20;
    /// Where the superblock of ext2 starts, and where its magic number and
    /// its revision are in it.
    const EXT2_SUPERBLOCK: u64 = 1024;
    const EXT2_MAGIC_OFFSET: u64 = 56;
    const EXT2_MAGIC: u16 = 0xef53;
    const EXT2_REVISION_OFFSET: u64 = 76;
    /// The revision mke2fs writes, EXT2_DYNAMIC_REV.
    const EXT2_DYNAMIC_REV: u32 = 1;
    /// Where the first partition entry of a master boot record is, and
    /// where its signature is.
    const MBR_PARTITION: u64 = 446;
    const MBR_SIGNATURE_OFFSET: u64 = 510;
    const MBR_SIGNATURE: [u8; 2] = [0x55, 0xaa];
    /// A partition entry: its type, here Linux, and its first sector and
    /// its size, in sectors of 512 bytes.
    const PARTITION_ENTRY_SIZE: usize = 16;
    const PARTITION_TYPE_OFFSET: usize = 4;
    const PARTITION_LINUX: u8 = 0x83;
    const PARTITION_START_OFFSET: usize = 8;
    const PARTITION_SIZE_OFFSET: usize = 12;
    const SECTOR_SIZE: u64 = 512;
    /// The partition starts at the sector after the master boot record.
    const PARTITION_START: u32 = 1;

    /// An image file below TMPDIR, removed when dropped.
    struct Image {
        path: PathBuf,
    }

    impl Image {
        /// `IMAGE_SIZE` zeros, with `bytes` written at each offset.
        fn new(edits: &[(u64, &[u8])]) -> Image {
            static COUNT: AtomicUsize = AtomicUsize::new(0);
            let n = COUNT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("blkid-{}-{}.img", std::process::id(), n));
            let file = File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.set_len(IMAGE_SIZE).unwrap();
            for &(offset, bytes) in edits {
                file.write_all_at(bytes, offset).unwrap();
            }
            Image { path }
        }

        /// An ext2 superblock at `at`.
        fn ext2(at: u64) -> Image {
            let start = at + EXT2_SUPERBLOCK;
            Image::new(&[
                (start + EXT2_MAGIC_OFFSET, &EXT2_MAGIC.to_le_bytes()),
                (start + EXT2_REVISION_OFFSET, &EXT2_DYNAMIC_REV.to_le_bytes()),
            ])
        }

        /// A master boot record with one Linux partition, which takes the
        /// rest of the image.
        fn dos() -> Image {
            let sectors = u32::try_from(IMAGE_SIZE / SECTOR_SIZE).unwrap();
            let mut entry = [0u8; PARTITION_ENTRY_SIZE];
            entry[PARTITION_TYPE_OFFSET] = PARTITION_LINUX;
            entry[PARTITION_START_OFFSET..PARTITION_SIZE_OFFSET].copy_from_slice(&PARTITION_START.to_le_bytes());
            entry[PARTITION_SIZE_OFFSET..].copy_from_slice(&(sectors - PARTITION_START).to_le_bytes());
            Image::new(&[(MBR_PARTITION, &entry), (MBR_SIGNATURE_OFFSET, &MBR_SIGNATURE)])
        }

        /// What libblkid finds in the `len` bytes at `offset`, through a
        /// descriptor of its own.
        fn probe(&self, blkid: &Blkid, offset: u64, len: u64) -> io::Result<Option<Found>> {
            let own = File::open(&self.path)?;
            blkid.probe(own.as_fd(), offset, len)
        }
    }

    impl Drop for Image {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// libblkid, or None and a note that the test is skipped.
    fn blkid() -> Option<&'static Blkid> {
        let blkid = Blkid::get();
        if blkid.is_none() {
            eprintln!("skipping: libblkid is not available");
        }
        blkid
    }

    #[test]
    fn libblkid_is_loaded_once() {
        let Some(blkid) = blkid() else { return };
        assert!(ptr::eq(blkid, Blkid::get().unwrap()));
    }

    #[test]
    fn what_an_image_holds_is_named() {
        let Some(blkid) = blkid() else { return };
        let ext2 = Found {
            name: Some("ext2".to_string()),
            usage: Some("filesystem".to_string()),
            version: Some("1.0".to_string()),
            partition_table: None,
        };
        assert_eq!(Image::ext2(0).probe(blkid, 0, IMAGE_SIZE).unwrap(), Some(ext2));
        let dos = Found {
            partition_table: Some("dos".to_string()),
            ..Found::default()
        };
        assert_eq!(Image::dos().probe(blkid, 0, IMAGE_SIZE).unwrap(), Some(dos));
        assert_eq!(Image::new(&[]).probe(blkid, 0, IMAGE_SIZE).unwrap(), None);
    }

    /// Only the range is probed, and a range beyond the end of the file is
    /// refused.
    #[test]
    fn only_the_range_is_probed() {
        let Some(blkid) = blkid() else { return };
        let half = IMAGE_SIZE / 2;
        let image = Image::ext2(half);
        assert_eq!(image.probe(blkid, 0, half).unwrap(), None);
        let found = image.probe(blkid, half, half).unwrap().unwrap();
        assert_eq!(found.name.as_deref(), Some("ext2"));
        assert_eq!(image.probe(blkid, half, 0).unwrap(), Some(found));
        let e = image.probe(blkid, half, IMAGE_SIZE).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EINVAL));
        let e = image.probe(blkid, u64::MAX, 1).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(EOVERFLOW));
    }

    /// Threads probe at the same time, each through a descriptor of its
    /// own, and find what one thread alone finds.
    #[test]
    fn threads_probe_at_the_same_time() {
        const THREADS: usize = 8;
        const ROUNDS: usize = 50;
        let Some(blkid) = blkid() else { return };
        let images = [Image::ext2(0), Image::dos(), Image::new(&[])];
        let expected: Vec<_> = images
            .iter()
            .map(|image| image.probe(blkid, 0, IMAGE_SIZE).unwrap())
            .collect();
        thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(|| {
                    for _ in 0..ROUNDS {
                        for (image, expected) in images.iter().zip(&expected) {
                            assert_eq!(&image.probe(blkid, 0, IMAGE_SIZE).unwrap(), expected);
                        }
                    }
                });
            }
        });
    }
}
