// SPDX-License-Identifier: LGPL-2.1-or-later
//! Tests of the volume.
use super::*;
use crate::fat::{END_OF_CHAIN, ENTRY_SIZE};
use crate::format::{self, FormatOptions};
use crate::fsck;
use crate::layout::FIRST_CLUSTER;
use crate::test_util::{format_options, volume, TempImage};
use std::io::{Read, Write};
use std::time::{Duration, UNIX_EPOCH};

fn t(secs: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs as u64)
}

fn names(v: &Volume, path: &str) -> Vec<String> {
    v.read_dir(path).unwrap().into_iter().map(|m| m.name).collect()
}

#[test]
fn directories() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    assert_eq!(v.label().unwrap().as_deref(), Some("TEST"));
    assert!(names(&v, "/").is_empty());
    v.create_dir("EFI", t(1_500_000_000)).unwrap();
    v.create_dir("/EFI/Linux", t(1_500_000_000)).unwrap();
    v.create_dir_all("/EFI/systemd/drop-ins/x", t(1_500_000_000)).unwrap();
    assert_eq!(v.create_dir("efi", t(0)).unwrap_err().errno(), EEXIST);
    assert_eq!(v.create_dir("/nope/x", t(0)).unwrap_err().errno(), ENOENT);
    assert_eq!(names(&v, "/"), vec!["EFI"]);
    assert_eq!(names(&v, "efi"), vec!["Linux", "systemd"]);
    let m = v.metadata("/EFI/LINUX").unwrap();
    assert!(m.is_dir);
    assert_eq!(m.modified, t(1_500_000_000));
    assert_eq!(v.remove_dir("/EFI").unwrap_err().errno(), ENOTEMPTY);
    assert_eq!(v.remove_dir("/").unwrap_err().errno(), EBUSY);
    assert_eq!(v.remove_file("/EFI").unwrap_err().errno(), EISDIR);
    v.remove_dir("/EFI/systemd/drop-ins/x").unwrap();
    v.remove_dir("/EFI/systemd/drop-ins").unwrap();
    v.remove_dir("/EFI/systemd").unwrap();
    assert_eq!(names(&v, "/EFI"), vec!["Linux"]);
    // Four directories were created, two remain: root plus two.
    assert_eq!(v.free_clusters(), v.layout().clusters - 3);

    // Dot entries: "." points at the directory, ".." at the parent, or 0
    // when the parent is the root.
    let linux = v.metadata("/EFI/Linux").unwrap();
    let efi = v.metadata("/EFI").unwrap();
    let d = v.load_directory(linux.first_cluster).unwrap();
    let e = d.entries();
    assert!(e[0].is_dot() && e[1].is_dot());
    assert_eq!(e[0].short.first_cluster, linux.first_cluster);
    assert_eq!(e[1].short.first_cluster, efi.first_cluster);
    let d = v.load_directory(efi.first_cluster).unwrap();
    assert_eq!(d.entries()[1].short.first_cluster, 0);
}

#[test]
fn files_round_trip() {
    for (ss, cs) in [(512u32, 512u32), (512, 4096), (4096, 4096), (4096, 32768)] {
        let (_img, mut v) = volume(64 << 20, ss, cs);
        let free = v.free_clusters();
        let sizes = [
            0u64,
            1,
            u64::from(cs) - 1,
            u64::from(cs),
            u64::from(cs) + 1,
            3 * u64::from(cs) + u64::from(cs) / 2,
        ];
        for (i, &size) in sizes.iter().enumerate() {
            let path = format!("/file{}.bin", i);
            let data: Vec<u8> = (0..size).map(|j| (j * 7 + i as u64) as u8).collect();
            let mut w = v.create_file(&path, t(1_600_000_000), false).unwrap();
            // Write in odd sized pieces to exercise the pending buffer.
            for chunk in data.chunks(1000) {
                w.write_all(chunk).unwrap();
            }
            assert_eq!(w.size(), size);
            w.finish().unwrap();
            let m = v.metadata(&path).unwrap();
            assert_eq!(m.size, size);
            assert!(!m.is_dir);
            assert_eq!(m.modified, t(1_600_000_000));
            let expected_clusters = size.div_ceil(u64::from(cs));
            if size == 0 {
                assert_eq!(m.first_cluster, 0);
            } else {
                assert_eq!(u64::from(v.chain_len(m.first_cluster).unwrap()), expected_clusters);
            }
            let mut back = Vec::new();
            v.open_file(&path).unwrap().read_to_end(&mut back).unwrap();
            assert_eq!(back, data);
        }
        let used: u64 = sizes.iter().map(|s| s.div_ceil(u64::from(cs))).sum();
        assert_eq!(u64::from(v.free_clusters()), u64::from(free) - used);
        // Files were allocated one after another, contiguously.
        let a = v.metadata("/file3.bin").unwrap().first_cluster;
        let b = v.metadata("/file4.bin").unwrap().first_cluster;
        assert_eq!(b, a + 1);
        assert_eq!(v.create_file("/file1.bin", t(0), false).unwrap_err().errno(), EEXIST);
        assert_eq!(v.create_file("/", t(0), false).unwrap_err().errno(), EEXIST);
        assert_eq!(v.open_file("/missing").unwrap_err().errno(), ENOENT);
        assert_eq!(v.open_file("/").unwrap_err().errno(), EISDIR);
        v.remove_file("/file5.bin").unwrap();
        assert_eq!(v.remove_file("/file5.bin").unwrap_err().errno(), ENOENT);
        assert_eq!(
            u64::from(v.free_clusters()),
            u64::from(free) - used + sizes[5].div_ceil(u64::from(cs))
        );
        v.close().unwrap();
    }
}

#[test]
fn replace_and_abort() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    let free = v.free_clusters();
    let mut w = v.create_file("/a.txt", t(0), false).unwrap();
    w.write_all(&[1u8; 2000]).unwrap();
    w.finish().unwrap();
    // Replacing goes through the case-insensitive match and creates the
    // entry anew under the new spelling.
    let mut w = v.create_file("/A.TXT", t(0), true).unwrap();
    w.write_all(&[2u8; 100]).unwrap();
    w.finish().unwrap();
    assert_eq!(names(&v, "/"), vec!["A.TXT"]);
    assert_eq!(v.metadata("/a.txt").unwrap().size, 100);
    assert_eq!(v.free_clusters(), free - 1);
    // Dropping an unfinished writer discards the file.
    {
        let mut w = v.create_file("/b.txt", t(0), false).unwrap();
        w.write_all(&[3u8; 5000]).unwrap();
    }
    assert_eq!(names(&v, "/"), vec!["A.TXT"]);
    assert_eq!(v.free_clusters(), free - 1);
    let mut w = v.create_file("/c.txt", t(0), false).unwrap();
    w.write_all(&[3u8; 5000]).unwrap();
    w.abort().unwrap();
    assert_eq!(names(&v, "/"), vec!["A.TXT"]);
    assert_eq!(v.free_clusters(), free - 1);
    assert_eq!(v.create_file("/a.txt/x", t(0), false).unwrap_err().errno(), ENOTDIR);
    v.create_dir("/d", t(0)).unwrap();
    assert_eq!(v.create_file("/d", t(0), true).unwrap_err().errno(), EISDIR);
}

#[test]
fn short_and_long_names() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    for name in [
        "readme.txt",
        "Readme.md",
        "BOOTX64.EFI",
        "longfilename1.txt",
        "longfilename2.txt",
        "ünïcödé",
    ] {
        v.create_file(&format!("/{}", name), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let root = v.load_directory(v.boot.root_cluster).unwrap();
    let e = root.entries();
    // The label comes first, then the files in creation order.
    assert!(e[0].short.is_volume_label());
    let by_name = |n: &str| e.iter().find(|x| x.name() == n).unwrap().clone();
    let r = by_name("readme.txt");
    assert_eq!(r.long_slots, 0);
    assert_eq!(&r.short.name, b"README  TXT");
    assert_eq!(r.short.nt_flags, 0x18);
    let r = by_name("Readme.md");
    assert_eq!(r.long_slots, 1);
    assert_eq!(&r.short.name, b"README  MD ");
    assert_eq!(by_name("BOOTX64.EFI").long_slots, 0);
    assert_eq!(&by_name("longfilename1.txt").short.name, b"LONGFI~1TXT");
    assert_eq!(&by_name("longfilename2.txt").short.name, b"LONGFI~2TXT");
    // Non-ASCII characters become '_' in the alias, ASCII letters stay.
    assert_eq!(&by_name("ünïcödé").short.name, b"_N_C_D~1   ");
    // Lookups work through either name.
    assert_eq!(v.metadata("/LONGFI~2.TXT").unwrap().name, "longfilename2.txt");
    assert_eq!(v.metadata("/ÜNÏCÖDÉ").unwrap().name, "ünïcödé");
    assert_eq!(v.create_file("/README.TXT", t(0), false).unwrap_err().errno(), EEXIST);
    assert_eq!(v.create_file("/bad:name", t(0), false).unwrap_err().errno(), EINVAL);
    assert_eq!(v.create_file("/a/../b", t(0), false).unwrap_err().errno(), EINVAL);
}

#[test]
fn directory_growth() {
    let (_img, mut v) = volume(8 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    let free = v.free_clusters();
    // 40 entries of 3 slots each (two long name entries plus the short
    // one) need 120 slots plus the dot entries, i.e. 8 clusters of 16
    // slots.
    for i in 0..40 {
        v.create_file(&format!("/d/Mixed Case File {}.txt", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let d = v.metadata("/d").unwrap();
    assert_eq!(v.chain_len(d.first_cluster).unwrap(), 8);
    assert_eq!(v.free_clusters(), free - 7);
    assert_eq!(names(&v, "/d").len(), 40);
    for i in 0..40 {
        assert!(v.metadata(&format!("/d/mixed case file {}.txt", i)).is_ok());
    }
    for i in 0..40 {
        v.remove_file(&format!("/d/Mixed Case File {}.txt", i)).unwrap();
    }
    assert!(names(&v, "/d").is_empty());
    v.remove_dir("/d").unwrap();
}

#[test]
fn growing_a_directory_without_space_changes_nothing() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/sub", t(0)).unwrap();
    // The dots plus 14 one-slot entries fill the directory's cluster.
    for i in 0..14 {
        v.create_file(&format!("/sub/F{}", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let mut w = v.create_file("/junk", t(0), false).unwrap();
    w.write_all(&[b'A'; 512]).unwrap();
    w.finish().unwrap();
    let free = v.free_clusters();
    let mut w = v.create_file("/fill", t(0), false).unwrap();
    w.write_all(&vec![0u8; free as usize * 512]).unwrap();
    w.finish().unwrap();
    assert_eq!(v.free_clusters(), 0);
    // Growing /sub needs a cluster there is not.
    assert_eq!(v.create_file("/sub/F14", t(0), false).unwrap_err().errno(), ENOSPC);
    assert_eq!(names(&v, "/sub").len(), 14);
    // With one free cluster a new directory gets its own cluster but
    // /sub cannot grow to hold its entry: nothing changes either.
    v.remove_file("/junk").unwrap();
    assert_eq!(v.free_clusters(), 1);
    assert_eq!(v.create_dir("/sub/d", t(0)).unwrap_err().errno(), ENOSPC);
    assert_eq!(v.free_clusters(), 1);
    assert_eq!(names(&v, "/sub").len(), 14);
    // A file without contents only needs the directory to grow.
    v.create_file("/sub/F14", t(0), false).unwrap().finish().unwrap();
    assert_eq!(v.free_clusters(), 0);
    assert_eq!(names(&v, "/sub").len(), 15);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    let v = Volume::open(img.device()).unwrap();
    assert_eq!(names(&v, "/sub").len(), 15);
}

#[test]
fn a_failed_write_discards_the_file() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    let free = v.free_clusters();
    let mut w = v.create_file("/big", t(0), false).unwrap();
    let e = w.write_all(&vec![0x5a; (free as usize + 5) * 512]).unwrap_err();
    assert_eq!(crate::Error::from(e).errno(), ENOSPC);
    // From here on the writer refuses to pretend.
    assert_eq!(crate::Error::from(w.write_all(b"more").unwrap_err()).errno(), EIO);
    assert_eq!(w.finish().unwrap_err().errno(), EIO);
    assert_eq!(v.metadata("/big").unwrap_err().errno(), ENOENT);
    assert_eq!(v.free_clusters(), free);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert_eq!(r.lost_clusters, 0);
}

#[test]
fn the_label_is_not_a_name() {
    let img = TempImage::new(1 << 20);
    let opts = FormatOptions {
        label: Some("EFI".into()),
        ..format_options(512, 512)
    };
    format::format(&img.device(), &opts).unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    assert_eq!(v.label().unwrap().as_deref(), Some("EFI"));
    assert_eq!(v.metadata("/EFI").unwrap_err().errno(), ENOENT);
    v.create_dir_all("/EFI/BOOT", t(0)).unwrap();
    v.create_file("/efi.txt", t(0), false).unwrap().finish().unwrap();
    assert_eq!(names(&v, "/"), vec!["EFI", "efi.txt"]);
    assert_eq!(v.label().unwrap().as_deref(), Some("EFI"));
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

#[test]
fn replacing_keeps_the_old_file_until_the_new_one_is_complete() {
    let (_img, mut v) = volume(1 << 20, 512, 512);
    let mut w = v.create_file("/EFI.efi", t(0), false).unwrap();
    w.write_all(&[7u8; 3000]).unwrap();
    w.finish().unwrap();
    let free = v.free_clusters();
    // A replacement that is dropped half way leaves the old file alone.
    {
        let mut w = v.create_file("/efi.EFI", t(1), true).unwrap();
        w.write_all(&[8u8; 1000]).unwrap();
    }
    assert_eq!(names(&v, "/"), vec!["EFI.efi"]);
    assert_eq!(v.metadata("/EFI.efi").unwrap().size, 3000);
    assert_eq!(v.free_clusters(), free);
    // So does one that is aborted.
    let mut w = v.create_file("/efi.EFI", t(1), true).unwrap();
    w.write_all(&[8u8; 1000]).unwrap();
    w.abort().unwrap();
    assert_eq!(names(&v, "/"), vec!["EFI.efi"]);
    assert_eq!(v.metadata("/EFI.efi").unwrap().size, 3000);
    assert_eq!(v.free_clusters(), free);
    // A complete one takes over, under its own spelling, and in the old
    // entry's slots since it needs no more of them.
    let root = v.boot.root_cluster;
    let slot_of = |v: &Volume, name: &str| {
        let e = v.load_directory(root).unwrap().find_name(&fold_str(name)).unwrap();
        (e.first_slot(), e.slot)
    };
    let old = slot_of(&v, "efi.efi");
    let mut w = v.create_file("/efi.EFI", t(1), true).unwrap();
    w.write_all(&[8u8; 1000]).unwrap();
    w.finish().unwrap();
    assert_eq!(names(&v, "/"), vec!["efi.EFI"]);
    assert_eq!(v.metadata("/EFI.EFI").unwrap().size, 1000);
    assert_eq!(v.free_clusters(), free + 6 - 2);
    assert_eq!(slot_of(&v, "efi.efi"), old);
    assert!(!v.load_directory(root).unwrap().has_reservations());
    // A spelling that needs a long name no longer fits into the one slot
    // and goes elsewhere; the old entry is deleted after it.
    let mut w = v.create_file("/Efi.efi", t(1), true).unwrap();
    w.write_all(&[9u8; 500]).unwrap();
    w.finish().unwrap();
    assert_eq!(names(&v, "/"), vec!["Efi.efi"]);
    let moved = slot_of(&v, "efi.efi");
    assert_ne!(moved.1, old.1);
    assert_eq!(moved.1 - moved.0, 1, "a long name slot and the short entry");
    // And back to one slot. Deleting the two slots of the long form leaves
    // the deleted slot before them as the end of the directory, so the new
    // entry goes there and the directory is compact again.
    let mut w = v.create_file("/EFI.EFI", t(1), true).unwrap();
    w.write_all(&[10u8; 500]).unwrap();
    w.finish().unwrap();
    assert_eq!(slot_of(&v, "efi.efi"), (1, 1));
    assert_eq!(v.load_directory(root).unwrap().end(), 2);
    assert_eq!(names(&v, "/"), vec!["EFI.EFI"]);
    v.close().unwrap();
    let r = fsck::check(&_img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

#[test]
fn a_damaged_directory_is_read_but_not_written() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    v.create_file("/d/x", t(0), false).unwrap().finish().unwrap();
    let d = v.metadata("/d").unwrap();
    let layout = *v.layout();
    v.close().unwrap();
    // Garbage behind the end marker, as a foreign writer might leave it,
    // in slot 5 of /d.
    img.device()
        .write_at(
            layout.cluster_offset(d.first_cluster).unwrap() + 5 * DIR_ENTRY_SIZE as u64,
            b"X",
        )
        .unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    // Reading stops at the marker, like Linux.
    assert_eq!(names(&v, "/d"), vec!["x"]);
    assert!(v.metadata("/d/x").is_ok());
    // Writing is refused in every form.
    assert_eq!(v.create_file("/d/y", t(0), false).unwrap_err().errno(), EUCLEAN);
    assert_eq!(v.create_dir("/d/sub", t(0)).unwrap_err().errno(), EUCLEAN);
    assert_eq!(v.remove_file("/d/x").unwrap_err().errno(), EUCLEAN);
    assert_eq!(v.set_times("/d/x", t(1)).unwrap_err().errno(), EUCLEAN);
    assert_eq!(names(&v, "/d"), vec!["x"]);
    // The rest of the volume is still usable.
    v.create_file("/ok", t(0), false).unwrap().finish().unwrap();
    assert_eq!(names(&v, "/"), vec!["d", "ok"]);
}

#[test]
fn set_times() {
    let (_img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    v.create_file("/d/f", t(0), false).unwrap().finish().unwrap();
    v.set_times("/d/f", t(1_700_000_000)).unwrap();
    v.set_times("/d", t(1_600_000_000)).unwrap();
    assert_eq!(v.metadata("/d/f").unwrap().modified, t(1_700_000_000));
    let d = v.metadata("/d").unwrap();
    assert_eq!(d.modified, t(1_600_000_000));
    assert_eq!(d.created, t(1_600_000_000));
    // The dot entries follow the directory's own entry.
    let expected = FatTimestamp::from_system_time(t(1_600_000_000));
    let dots: Vec<DirEntry> = v
        .load_directory(d.first_cluster)
        .unwrap()
        .entries()
        .into_iter()
        .filter(|e| e.is_dot())
        .collect();
    assert_eq!(dots.len(), 2);
    for dot in dots {
        assert_eq!(
            (dot.short.write_date, dot.short.write_time),
            (expected.date, expected.time)
        );
        assert_eq!(
            (dot.short.create_date, dot.short.create_time),
            (expected.date, expected.time)
        );
    }
    assert_eq!(v.set_times("/", t(0)).unwrap_err().errno(), EINVAL);
    assert_eq!(v.set_times("/missing", t(0)).unwrap_err().errno(), ENOENT);
}

#[test]
fn garbage_beyond_the_last_fat_entry_is_ignored() {
    let (img, v) = volume(1 << 20, 512, 512);
    let layout = *v.layout();
    let free = v.free_clusters();
    v.close().unwrap();
    // The table ends with the entry of the last cluster; the rest of the
    // FAT's sectors is padding that nothing should depend on.
    let used = u64::from(layout.fat_entries()) * ENTRY_SIZE as u64;
    let padding = u64::from(layout.fat_sectors) * u64::from(layout.sector_size) - used;
    assert!(padding > 0);
    let dev = img.device();
    for copy in 0..layout.fats {
        dev.write_at(layout.fat_offset(copy) + used, &vec![0xab; padding as usize])
            .unwrap();
    }
    let mut v = Volume::open(dev).unwrap();
    assert_eq!(v.free_clusters(), free);
    v.create_file("/f", t(0), false).unwrap().finish().unwrap();
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

#[test]
fn an_oversized_directory_chain_is_refused() {
    // 8 MiB with 512 byte clusters is 16k clusters, four times what a
    // directory can hold.
    let (img, mut v) = volume(8 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    let d = v.metadata("/d").unwrap();
    let layout = *v.layout();
    v.close().unwrap();
    // Link the directory through every cluster of the volume but the
    // root's, which is the first.
    let mut fat = vec![0u8; layout.fat_size() as usize];
    let dev = img.device();
    dev.read_at(layout.fat_offset(0), &mut fat).unwrap();
    let max = layout.max_cluster();
    let mut c = d.first_cluster;
    for next in FIRST_CLUSTER + 1..=max {
        if next == d.first_cluster {
            continue;
        }
        let at = c as usize * ENTRY_SIZE;
        fat[at..at + ENTRY_SIZE].copy_from_slice(&next.to_le_bytes());
        c = next;
    }
    let at = c as usize * ENTRY_SIZE;
    fat[at..at + ENTRY_SIZE].copy_from_slice(&END_OF_CHAIN.to_le_bytes());
    for copy in 0..layout.fats {
        dev.write_at(layout.fat_offset(copy), &fat).unwrap();
    }
    let v = Volume::open(dev).unwrap();
    assert_eq!(v.read_dir("/d").unwrap_err().errno(), EUCLEAN);
    assert_eq!(v.metadata("/d/x").unwrap_err().errno(), EUCLEAN);
    // fsck reports it instead of reading everything.
    drop(v);
    let r = fsck::check(&img.device()).unwrap();
    assert!(
        r.problems.iter().any(|p| p.kind == fsck::ProblemKind::DirectoryTooLong),
        "{:?}",
        r.problems
    );
}

#[test]
fn reproducible() {
    let mut images = Vec::new();
    for _ in 0..2 {
        let (img, mut v) = volume(4 << 20, 512, 512);
        v.create_dir_all("/EFI/Linux", t(1_700_000_000)).unwrap();
        for i in 0..5 {
            let mut w = v
                .create_file(&format!("/EFI/Linux/kernel-{}.efi", i), t(1_700_000_000 + i), false)
                .unwrap();
            w.write_all(&vec![i as u8; 777 * (i as usize + 1)]).unwrap();
            w.finish().unwrap();
        }
        v.remove_file("/EFI/Linux/kernel-2.efi").unwrap();
        v.close().unwrap();
        images.push(std::fs::read(img.path()).unwrap());
    }
    assert_eq!(images[0], images[1]);
}

#[test]
fn fsinfo_reserved_bytes_survive() {
    use crate::boot::{fsinfo_field, FsInfo};
    use crate::bytes::size;
    let (img, v) = volume(1 << 20, 512, 512);
    let off = u64::from(v.boot_sector().fsinfo_sector) * u64::from(v.layout().sector_size);
    v.close().unwrap();
    // Something else keeps data in the reserved bytes, as lDOS does with its
    // FSIBOOT block, and the trailing signature is missing, as some
    // formatters leave it.
    let dev = img.device();
    dev.write_at(off + fsinfo_field::RESERVED1.start as u64, b"FSIBOOT")
        .unwrap();
    dev.write_at(off + fsinfo_field::RESERVED2.start as u64, b"xyz")
        .unwrap();
    dev.write_at(
        off + fsinfo_field::TRAIL_SIGNATURE.start as u64,
        &[0u8; size(fsinfo_field::TRAIL_SIGNATURE)],
    )
    .unwrap();
    drop(dev);
    let mut v = Volume::open(img.device()).unwrap();
    v.create_dir("/d", t(0)).unwrap();
    let free = v.free_clusters();
    v.close().unwrap();
    let mut sector = [0u8; 512];
    img.device().read_at(off, &mut sector).unwrap();
    assert_eq!(&sector[fsinfo_field::RESERVED1][..7], b"FSIBOOT");
    assert_eq!(&sector[fsinfo_field::RESERVED2][..3], b"xyz");
    let info = FsInfo::parse(&sector).unwrap();
    assert_eq!(info.free_clusters, free);
    assert!(FsInfo::has_trail_signature(&sector));
    // A sector without its signatures is written afresh.
    let dev = img.device();
    dev.write_at(off, &[0u8; 512]).unwrap();
    drop(dev);
    let mut v = Volume::open(img.device()).unwrap();
    v.create_dir("/e", t(0)).unwrap();
    v.close().unwrap();
    img.device().read_at(off, &mut sector).unwrap();
    assert!(FsInfo::parse(&sector).is_some());
    assert!(FsInfo::has_trail_signature(&sector));
}

#[test]
fn durable_mode_runs_the_same_operations() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    assert!(!v.durable(), "an image file is not durable by default");
    v.set_durable(true);
    v.create_dir_all("/a/b", t(0)).unwrap();
    let mut w = v.create_file("/a/b/f", t(0), false).unwrap();
    w.write_all(b"data").unwrap();
    w.finish().unwrap();
    let mut w = v.create_file("/a/b/f", t(0), true).unwrap();
    w.write_all(b"newer").unwrap();
    w.finish().unwrap();
    v.remove_file("/a/b/f").unwrap();
    v.remove_dir("/a/b").unwrap();
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

/// Replacing a file whose chain is damaged must leave it alone: the chain
/// could not be freed once the new entry were on the volume, and the new
/// file's clusters must not be taken away from a published entry either.
#[test]
fn a_damaged_file_is_not_replaced() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    let mut w = v.create_file("/f", t(0), false).unwrap();
    w.write_all(&[7u8; 2000]).unwrap();
    w.finish().unwrap();
    let first = v.metadata("/f").unwrap().first_cluster;
    // The chain runs into a free cluster after its first one.
    v.link(first, 0).unwrap();
    let free = v.free_clusters();
    let mut w = v.create_file("/f", t(1), true).unwrap();
    w.write_all(&[8u8; 1000]).unwrap();
    let e = w.finish().unwrap_err();
    assert_eq!(e.errno(), EUCLEAN, "{}", e);
    assert!(e.message().contains("cannot be replaced"), "{}", e);
    let m = v.metadata("/f").unwrap();
    assert_eq!((m.size, m.first_cluster), (2000, first));
    assert_eq!(v.free_clusters(), free, "the new file's clusters are given back");
    assert_eq!(names(&v, "/"), vec!["f"]);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert!(
        r.problems.iter().any(|p| p.path.as_deref() == Some("/f")),
        "{:?}",
        r.problems
    );
}

/// Several files may be open at once. A reservation holds slots nothing
/// was written to; an entry written behind it must still be reachable, and
/// a replacement moving into the end of the directory must not take the
/// reserved slots.
#[test]
fn open_files_keep_their_slots() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    let sorted = |v: &Volume| {
        let mut n = names(v, "/");
        n.sort();
        n
    };
    // An entry behind a reservation on zero slots.
    let mut a = v.begin_file("/a", t(0), false).unwrap();
    v.write_file_data(&mut a, b"aaa").unwrap();
    v.create_file("/b", t(0), false).unwrap().finish().unwrap();
    assert_eq!(sorted(&v), vec!["b"]);
    let root = v.boot.root_cluster;
    assert_eq!(v.load_directory(root).unwrap().entries().len(), 2, "label and b");
    v.finish_file(a).unwrap();
    assert_eq!(sorted(&v), vec!["a", "b"]);
    // The same with the reservation given up: a deleted slot stays, not
    // an end marker.
    let c = v.begin_file("/c", t(0), false).unwrap();
    v.create_file("/d", t(0), false).unwrap().finish().unwrap();
    v.abort_file(c).unwrap();
    assert_eq!(sorted(&v), vec!["a", "b", "d"]);
    v.create_file("/e", t(0), false).unwrap().finish().unwrap();
    assert_eq!(sorted(&v), vec!["a", "b", "d", "e"]);
    // A replacement whose old entry is last: deleting it moves the end of
    // the directory back over a deleted slot that another open file has
    // reserved; the new entry must go into the old slots instead.
    v.remove_file("/d").unwrap();
    let mut w = v.begin_file("/w", t(0), false).unwrap();
    v.write_file_data(&mut w, b"w").unwrap();
    let mut z = v.create_file("/e", t(1), true).unwrap();
    z.write_all(b"ee").unwrap();
    z.finish().unwrap();
    v.finish_file(w).unwrap();
    assert_eq!(sorted(&v), vec!["a", "b", "e", "w"]);
    assert_eq!(v.metadata("/e").unwrap().size, 2);
    assert_eq!(v.metadata("/w").unwrap().size, 1);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

/// Reading a file and looking up names leave the slots of a file being
/// written in the same directory alone.
#[test]
fn lookups_keep_the_slots_of_open_files() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    let mut x = v.create_file("/d/x", t(0), false).unwrap();
    x.write_all(b"xx").unwrap();
    x.finish().unwrap();
    let mut a = v.begin_file("/d/a", t(0), false).unwrap();
    v.write_file_data(&mut a, b"aaa").unwrap();
    let mut s = String::new();
    v.open_file("/d/x").unwrap().read_to_string(&mut s).unwrap();
    assert_eq!(s, "xx");
    assert_eq!(v.metadata("/d/x").unwrap().size, 2);
    assert_eq!(v.metadata("/d/missing").unwrap_err().errno(), ENOENT);
    v.finish_file(a).unwrap();
    assert_eq!(v.metadata("/d/a").unwrap().size, 3);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

/// A file that cannot be begun, here because its directory cannot grow,
/// leaves the slots of a file being written in that directory alone.
#[test]
fn a_failed_begin_keeps_the_slots_of_open_files() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    // A whole cluster is written right away, so finishing a needs none.
    let mut a = v.begin_file("/d/a", t(0), false).unwrap();
    v.write_file_data(&mut a, &[b'a'; 512]).unwrap();
    // The dots, a's slot and 13 more entries fill the cluster of /d.
    for i in 0..13 {
        v.create_file(&format!("/d/f{}", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let free = v.free_clusters();
    let mut fill = v.create_file("/fill", t(0), false).unwrap();
    fill.write_all(&vec![0u8; free as usize * 512]).unwrap();
    fill.finish().unwrap();
    assert_eq!(v.create_file("/d/b", t(0), false).unwrap_err().errno(), ENOSPC);
    v.finish_file(a).unwrap();
    assert_eq!(v.metadata("/d/a").unwrap().size, 512);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

/// The cache keeps a record of the reserved slots apart from the cached
/// directories, so a directory read back from disk has them too.
#[test]
fn reservations_survive_a_reread_of_the_directory() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    let mut a = v.begin_file("/d/a", t(0), false).unwrap();
    v.write_file_data(&mut a, b"aaa").unwrap();
    v.forget_directory(v.metadata("/d").unwrap().first_cluster);
    // b must not land in the slots kept for a.
    v.create_file("/d/b", t(0), false).unwrap().finish().unwrap();
    v.finish_file(a).unwrap();
    let mut n = names(&v, "/d");
    n.sort();
    assert_eq!(n, ["a", "b"]);
    // An aborted file gives its slots back for good.
    let c = v.begin_file("/d/c", t(0), false).unwrap();
    v.abort_file(c).unwrap();
    assert!(v.dirs.borrow().reserved.is_empty());
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
}

/// Reading the files of a directory one after the other finds the
/// directory in the cache every time.
#[test]
fn reading_files_does_not_reread_their_directory() {
    let (_img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    for i in 0..20 {
        v.create_file(&format!("/d/f{}", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let loads = v.dirs.borrow().loads;
    for i in 0..20 {
        let mut data = Vec::new();
        v.open_file(&format!("/d/f{}", i))
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        v.metadata(&format!("/d/f{}", i)).unwrap();
    }
    assert_eq!(v.dirs.borrow().loads, loads);
}

#[test]
fn the_volume_is_marked_dirty_while_written() {
    use crate::boot::{field, FsInfo, FSINFO_SIZE, FSINFO_UNKNOWN, NT_FLAG_DIRTY};
    let (img, mut v) = volume(1 << 20, 512, 512);
    let layout = *v.layout();
    let fsinfo = usize::from(v.boot_sector().fsinfo_sector) * layout.sector_size as usize;
    // FAT entry 1, the second one, of `copy`.
    let entry1 = |bytes: &[u8], copy: u32| {
        let off = layout.fat_offset(copy) as usize + ENTRY_SIZE;
        u32::from_le_bytes(bytes[off..off + ENTRY_SIZE].try_into().unwrap())
    };
    // Nothing is marked before the first write.
    let bytes = std::fs::read(img.path()).unwrap();
    assert_eq!(bytes[field::NT_FLAGS] & NT_FLAG_DIRTY, 0);
    assert_eq!(entry1(&bytes, 0), END_OF_CHAIN);
    v.read_dir("/").unwrap();
    assert_eq!(std::fs::read(img.path()).unwrap(), bytes, "reading marks nothing");
    // While a file is being written the marks are on disk: the boot
    // sector bit, bit 27 of FAT entry 1 in every copy, unknown counts.
    let mut w = v.create_file("/f", t(0), false).unwrap();
    w.write_all(b"data").unwrap();
    let bytes = std::fs::read(img.path()).unwrap();
    assert_ne!(bytes[field::NT_FLAGS] & NT_FLAG_DIRTY, 0);
    assert_eq!(entry1(&bytes, 0) & (1 << 27), 0);
    assert_eq!(entry1(&bytes, 1) & (1 << 27), 0);
    let info = FsInfo::parse(&bytes[fsinfo..fsinfo + FSINFO_SIZE]).unwrap();
    assert_eq!((info.free_clusters, info.next_free), (FSINFO_UNKNOWN, FSINFO_UNKNOWN));
    w.finish().unwrap();
    // Closed, everything is back and the counts are real.
    v.close().unwrap();
    let bytes = std::fs::read(img.path()).unwrap();
    assert_eq!(bytes[field::NT_FLAGS] & NT_FLAG_DIRTY, 0);
    assert_eq!(entry1(&bytes, 0), END_OF_CHAIN);
    assert_eq!(entry1(&bytes, 1), END_OF_CHAIN);
    let info = FsInfo::parse(&bytes[fsinfo..fsinfo + FSINFO_SIZE]).unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(info.free_clusters, r.free_clusters);
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert!(
        !r.problems
            .iter()
            .any(|p| matches!(p.kind, fsck::ProblemKind::DirtyFlag | fsck::ProblemKind::FatDirtyFlag)),
        "{:?}",
        r.problems
    );
}

/// A volume closed unfinished keeps the marks of a writing session, as a
/// crash would leave them, and what was written before is on disk. One
/// that nothing was written to since it was opened gets the marks too.
#[test]
fn a_volume_closed_unfinished_stays_marked() {
    use crate::boot::{field, FsInfo, FSINFO_SIZE, FSINFO_UNKNOWN, NT_FLAG_DIRTY};
    for written in [true, false] {
        let (img, mut v) = volume(1 << 20, 512, 512);
        let layout = *v.layout();
        let fsinfo = usize::from(v.boot_sector().fsinfo_sector) * layout.sector_size as usize;
        if written {
            let mut w = v.create_file("/f", t(0), false).unwrap();
            w.write_all(b"data").unwrap();
            w.finish().unwrap();
        }
        v.close_unfinished().unwrap();
        let bytes = std::fs::read(img.path()).unwrap();
        assert_ne!(bytes[field::NT_FLAGS] & NT_FLAG_DIRTY, 0);
        for copy in 0..layout.fats {
            // FAT entry 1, the second one, of this copy.
            let off = layout.fat_offset(copy) as usize + ENTRY_SIZE;
            let entry1 = u32::from_le_bytes(bytes[off..off + ENTRY_SIZE].try_into().unwrap());
            assert_eq!(entry1 & ENTRY1_CLEAN_SHUTDOWN, 0, "FAT {}", copy);
        }
        let info = FsInfo::parse(&bytes[fsinfo..fsinfo + FSINFO_SIZE]).unwrap();
        assert_eq!((info.free_clusters, info.next_free), (FSINFO_UNKNOWN, FSINFO_UNKNOWN));
        let r = fsck::check(&img.device()).unwrap();
        assert_eq!(r.errors(), 0, "{:?}", r.problems);
        for kind in [fsck::ProblemKind::DirtyFlag, fsck::ProblemKind::FatDirtyFlag] {
            assert!(r.problems.iter().any(|p| p.kind == kind), "{:?}", r.problems);
        }
        let v = Volume::open(img.device()).unwrap();
        assert_eq!(v.metadata("/f").ok().map(|m| m.size), written.then_some(4));
    }
}

#[test]
fn remove_tree() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_file("/keep", t(0), false).unwrap().finish().unwrap();
    let free = v.free_clusters();
    v.create_dir_all("/a/b/c", t(0)).unwrap();
    v.create_dir("/a/d", t(0)).unwrap();
    v.create_dir("/a/b/empty", t(0)).unwrap();
    let mut files = 0;
    for (i, path) in ["/a/f", "/a/b/f", "/a/b/c/f", "/a/b/c/g", "/a/d/f"]
        .into_iter()
        .enumerate()
    {
        let mut w = v.create_file(path, t(0), false).unwrap();
        w.write_all(&vec![i as u8; 700 * (i + 1)]).unwrap();
        w.finish().unwrap();
        files += 1;
    }
    // Enough long names to take /a/b/c past its first cluster.
    for i in 0..20 {
        v.create_file(&format!("/a/b/c/Mixed Case File {}.txt", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
        files += 1;
    }
    let c = v.metadata("/a/b/c").unwrap();
    assert!(v.chain_len(c.first_cluster).unwrap() > 1);
    let r = v.remove_tree("/a").unwrap();
    assert_eq!(r, RemoveReport { files, directories: 5 });
    assert_eq!(v.metadata("/a").unwrap_err().errno(), ENOENT);
    assert_eq!(names(&v, "/"), vec!["keep"]);
    assert_eq!(v.free_clusters(), free);
    // The root is refused; a missing path fails the way metadata() does.
    let e = v.remove_tree("/").unwrap_err();
    assert_eq!((e.errno(), e.detail()), (EINVAL, Some(&Detail::InvalidOption("path"))));
    let e = v.remove_tree("/missing").unwrap_err();
    assert_eq!(
        (e.errno(), e.detail()),
        (ENOENT, Some(&Detail::Path("/missing".into())))
    );
    assert_eq!(v.remove_tree("/a/b").unwrap_err().errno(), ENOENT);
    // A file, and an empty directory, on their own.
    assert_eq!(
        v.remove_tree("/keep").unwrap(),
        RemoveReport {
            files: 1,
            directories: 0
        }
    );
    v.create_dir("/e", t(0)).unwrap();
    assert_eq!(
        v.remove_tree("/e").unwrap(),
        RemoveReport {
            files: 0,
            directories: 1
        }
    );
    assert!(names(&v, "/").is_empty());
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert_eq!(r.lost_clusters, 0);
}

#[test]
fn root_time() {
    // Formatted without a label there is no entry to carry a time until
    // one is set; the entry made then says NO NAME, which is no label.
    let img = TempImage::new(1 << 20);
    let unlabelled = FormatOptions {
        label: None,
        ..format_options(512, 512)
    };
    format::format(&img.device(), &unlabelled).unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    assert_eq!(v.root_time().unwrap(), None);
    assert_eq!(v.label().unwrap(), None);
    v.create_file("/f", t(0), false).unwrap().finish().unwrap();
    // Modification times go in two second steps.
    v.set_root_time(t(1_700_000_001)).unwrap();
    assert_eq!(v.root_time().unwrap(), Some(t(1_700_000_000)));
    assert_eq!(v.label().unwrap(), None);
    assert_eq!(v.label_bytes().unwrap(), None);
    assert_eq!(names(&v, "/"), vec!["f"]);
    let labels = |v: &Volume| -> Vec<RawDirEntry> {
        v.load_directory(v.boot.root_cluster)
            .unwrap()
            .iter()
            .filter(|e| e.short.is_volume_label())
            .map(|e| e.short)
            .collect()
    };
    let l = labels(&v);
    assert_eq!(l.len(), 1);
    assert_eq!(l[0].name, NO_NAME);
    assert_eq!((l[0].first_cluster, l[0].size), (0, 0));
    // Setting it again rewrites that entry, creation time included.
    v.set_root_time(t(1_600_000_000)).unwrap();
    assert_eq!(v.root_time().unwrap(), Some(t(1_600_000_000)));
    let l = labels(&v);
    assert_eq!(l.len(), 1);
    assert_eq!(
        l[0].create_timestamp(),
        FatTimestamp::from_system_time(t(1_600_000_000))
    );
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert!(
        !r.problems.iter().any(|p| matches!(
            p.kind,
            fsck::ProblemKind::LabelMismatch
                | fsck::ProblemKind::LabelOnlyInBootSector
                | fsck::ProblemKind::LabelEntries
        )),
        "{:?}",
        r.problems
    );
    let v = Volume::open(img.device()).unwrap();
    assert_eq!(v.root_time().unwrap(), Some(t(1_600_000_000)));
    assert_eq!(v.label().unwrap(), None);

    // Formatted with a label, the entry format wrote carries the time and
    // keeps the label.
    let (img, mut v) = volume(1 << 20, 512, 512);
    assert_eq!(v.root_time().unwrap(), Some(FatTimestamp::EPOCH.to_system_time()));
    assert_eq!(v.label().unwrap().as_deref(), Some("TEST"));
    v.set_root_time(t(1_650_000_000)).unwrap();
    assert_eq!(v.root_time().unwrap(), Some(t(1_650_000_000)));
    assert_eq!(v.label().unwrap().as_deref(), Some("TEST"));
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    let v = Volume::open(img.device()).unwrap();
    assert_eq!(v.label().unwrap().as_deref(), Some("TEST"));
    assert_eq!(v.root_time().unwrap(), Some(t(1_650_000_000)));
}

#[test]
fn the_label_entry_grows_a_full_root() {
    let img = TempImage::new(1 << 20);
    let unlabelled = FormatOptions {
        label: None,
        ..format_options(512, 512)
    };
    format::format(&img.device(), &unlabelled).unwrap();
    let mut v = Volume::open(img.device()).unwrap();
    // Sixteen one-slot entries fill the root's cluster.
    for i in 0..16 {
        v.create_file(&format!("/F{}", i), t(0), false)
            .unwrap()
            .finish()
            .unwrap();
    }
    let root = v.boot.root_cluster;
    assert_eq!(v.chain_len(root).unwrap(), 1);
    let free = v.free_clusters();
    v.set_root_time(t(1_700_000_000)).unwrap();
    assert_eq!(v.chain_len(root).unwrap(), 2);
    assert_eq!(v.free_clusters(), free - 1);
    assert_eq!(v.root_time().unwrap(), Some(t(1_700_000_000)));
    assert_eq!(names(&v, "/").len(), 16);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert_eq!(r.lost_clusters, 0);
}

#[test]
fn set_attributes() {
    let (img, mut v) = volume(1 << 20, 512, 512);
    v.create_dir("/d", t(0)).unwrap();
    v.create_file("/d/f", t(0), false).unwrap().finish().unwrap();
    assert_eq!(v.metadata("/d/f").unwrap().attributes, ATTR_ARCHIVE);
    assert_eq!(v.metadata("/d").unwrap().attributes, ATTR_DIRECTORY);
    // The four bits are replaced as a whole: the archive bit goes unless it
    // is given again.
    v.set_attributes("/d/f", ATTR_READ_ONLY | ATTR_HIDDEN).unwrap();
    assert_eq!(v.metadata("/d/f").unwrap().attributes, ATTR_READ_ONLY | ATTR_HIDDEN);
    v.set_attributes("/d", ATTR_HIDDEN | ATTR_SYSTEM).unwrap();
    let d = v.metadata("/d").unwrap();
    assert!(d.is_dir);
    assert_eq!(d.attributes, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM);
    let listed = |v: &Volume, dir: &str| -> Vec<u8> { v.read_dir(dir).unwrap().iter().map(|m| m.attributes).collect() };
    assert_eq!(listed(&v, "/"), vec![ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM]);
    assert_eq!(listed(&v, "/d"), vec![ATTR_READ_ONLY | ATTR_HIDDEN]);
    // The dot entries are not touched.
    let dir = v.load_directory(d.first_cluster).unwrap();
    for e in dir.iter().filter(|e| e.is_dot()) {
        assert_eq!(e.short.attr, ATTR_DIRECTORY);
    }
    // Bits that say what an entry is cannot be set, and a refused call
    // changes nothing.
    for bad in [ATTR_VOLUME_ID, ATTR_DIRECTORY, 0x40, 0x80, ATTR_ARCHIVE | 0x40] {
        let e = v.set_attributes("/d/f", bad).unwrap_err();
        assert_eq!(
            (e.errno(), e.detail()),
            (EINVAL, Some(&Detail::InvalidOption("attributes"))),
            "{:#04x}",
            bad
        );
    }
    assert_eq!(v.metadata("/d/f").unwrap().attributes, ATTR_READ_ONLY | ATTR_HIDDEN);
    let e = v.set_attributes("/", ATTR_HIDDEN).unwrap_err();
    assert_eq!((e.errno(), e.detail()), (EINVAL, Some(&Detail::InvalidOption("path"))));
    assert_eq!(v.set_attributes("/missing", ATTR_HIDDEN).unwrap_err().errno(), ENOENT);
    v.set_attributes("/d/f", 0).unwrap();
    assert_eq!(v.metadata("/d/f").unwrap().attributes, 0);
    // A writer sets them for the entry it is going to write.
    let mut w = v.create_file("/d/g", t(0), false).unwrap();
    assert_eq!(w.set_attributes(ATTR_DIRECTORY).unwrap_err().errno(), EINVAL);
    w.set_attributes(ATTR_SYSTEM | ATTR_ARCHIVE).unwrap();
    w.finish().unwrap();
    assert_eq!(v.metadata("/d/g").unwrap().attributes, ATTR_SYSTEM | ATTR_ARCHIVE);
    v.close().unwrap();
    let r = fsck::check(&img.device()).unwrap();
    assert_eq!(r.errors(), 0, "{:?}", r.problems);
    assert!(
        !r.problems
            .iter()
            .any(|p| p.kind == fsck::ProblemKind::AttributeReservedBits),
        "{:?}",
        r.problems
    );
    let v = Volume::open(img.device()).unwrap();
    assert_eq!(
        v.metadata("/d").unwrap().attributes,
        ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM
    );
    assert_eq!(v.metadata("/d/f").unwrap().attributes, 0);
    assert_eq!(v.metadata("/d/g").unwrap().attributes, ATTR_SYSTEM | ATTR_ARCHIVE);
}
