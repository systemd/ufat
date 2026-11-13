// SPDX-License-Identifier: LGPL-2.1-or-later
//! Differential tests against the reference tools: mkfs.fat, fsck.fat and
//! mtools. Tests whose tool is missing are skipped with a note.

mod common;

use std::io::Read;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use common::{
    build_tree, bytes_at, find_mtool, find_program, first_difference, run, tree_dirs, tree_files, ufat, Temp,
};
use fat::device::{Access, Device};
use fat::format::{self, FormatOptions};
use fat::host;
use fat::populate::{CopyOptions, TimePolicy};
use fat::volume::Volume;

/// A source tree resolved once, the way the tool resolves its arguments.
fn source(path: &Path) -> OwnedFd {
    host::open_dir(path).unwrap()
}

const SIZES: &[u64] = &[
    1 << 20,
    4 << 20,
    5 << 20,
    32 << 20,
    33 << 20,
    64 << 20,
    100 << 20,
    256 << 20,
    260 << 20,
    261 << 20,
    300 << 20,
    512 << 20,
    1 << 30,
    2 << 30,
    3 << 30,
    8 << 30,
    9 << 30,
];

fn skip(tool: &str) {
    eprintln!("skipping: {} not found", tool);
}

/// Our formatter writes the same bytes as mkfs.fat -F 32 --invariant.
#[test]
fn format_matches_mkfs_fat() {
    let _serial = common::serial();
    let Some(mkfs) = find_program("mkfs.fat") else {
        return skip("mkfs.fat");
    };
    for &sector_size in &[512u32, 4096] {
        for &size in SIZES {
            let reference = Temp::image(size);
            let ours = Temp::image(size);
            let ss = sector_size.to_string();
            run(
                &mkfs,
                &[
                    "-F",
                    "32",
                    "-S",
                    &ss,
                    "--invariant",
                    "-n",
                    "ESPLABEL",
                    reference.0.to_str().unwrap(),
                ],
                &[],
            );
            let options = FormatOptions {
                sector_size: Some(sector_size),
                volume_id: 0x1234_abcd,
                label: Some("ESPLABEL".into()),
                timestamp: Some(UNIX_EPOCH + Duration::from_secs(1_426_325_213)),
                oem_name: *b"mkfs.fat",
                allow_small: true,
                mkfs_fat_compat: true,
                ..FormatOptions::default()
            };
            format::format(&Device::open(ours.path(), Access::ReadWrite).unwrap(), &options).unwrap();
            if let Some(first) = first_difference(reference.path(), ours.path()).unwrap() {
                panic!(
                    "images differ for size {} sector size {} at byte {}",
                    size, sector_size, first
                );
            }
        }
    }
}

fn test_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("EFI/BOOT/BOOTX64.EFI", vec![0xAAu8; 70_000]),
        (
            "EFI/Linux/linux-6.12.3-300.fc41.x86_64.efi",
            (0..300_000u32).map(|i| (i % 251) as u8).collect(),
        ),
        ("EFI/Linux/Readme.md", b"mixed case".to_vec()),
        ("EFI/systemd/systemd-bootx64.efi", vec![1u8; 4096]),
        ("loader/entries/linux.conf", b"title Linux\n".to_vec()),
        ("loader/loader.conf", b"timeout 5\n".to_vec()),
        ("loader/random-seed", vec![7u8; 32]),
        ("empty.txt", Vec::new()),
        ("readme.txt", b"lower\n".to_vec()),
        ("a b.txt", b"space\n".to_vec()),
        ("long.file.name.with.dots.bin", vec![9u8; 513]),
    ]
}

fn populate(image: &Path, source: &Path, sector_size: u32, cluster_size: Option<u32>) {
    let options = FormatOptions {
        sector_size: Some(sector_size),
        cluster_size,
        volume_id: 0xdead_beef,
        label: Some("TEST".into()),
        timestamp: Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        allow_small: true,
        ..FormatOptions::default()
    };
    format::format(&Device::open(image, Access::ReadWrite).unwrap(), &options).unwrap();
    let mut v = Volume::open(Device::open(image, Access::ReadWrite).unwrap()).unwrap();
    v.copy_tree(self::source(source).as_fd(), "/", &CopyOptions::default())
        .unwrap();
    // Some churn: a deleted file and a replaced one.
    v.create_file("/deleted.tmp", UNIX_EPOCH + Duration::from_secs(1_700_000_000), false)
        .unwrap()
        .finish()
        .unwrap();
    v.remove_file("/deleted.tmp").unwrap();
    let readme = host::open_file(&source.join("readme.txt")).unwrap();
    v.copy_file(readme.as_fd(), "/readme.txt", &CopyOptions::default())
        .unwrap();
    v.close().unwrap();
}

/// fsck.fat finds nothing to complain about in what we populate.
#[test]
fn fsck_fat_is_happy() {
    let _serial = common::serial();
    let Some(fsck) = find_program("fsck.fat") else {
        return skip("fsck.fat");
    };
    let tree = Temp::dir();
    let files = test_files();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    build_tree(tree.path(), &refs);
    for &(sector_size, cluster_size, size) in &[
        (512u32, None, 40u64 << 20),
        (512, Some(4096), 64 << 20),
        (4096, None, 300 << 20),
        (4096, Some(32768), 300 << 20),
    ] {
        let image = Temp::image(size);
        populate(image.path(), tree.path(), sector_size, cluster_size);
        let out = std::process::Command::new(&fsck)
            .args(["-n", "-v", image.0.to_str().unwrap()])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            out.status.success(),
            "fsck.fat found problems (sector {} cluster {:?}):\n{}",
            sector_size,
            cluster_size,
            text
        );
        for bad in [
            "differences",
            "Free cluster summary wrong",
            "Dirty",
            "Bad",
            "Wrong",
            "unexpected",
            "Reclaim",
            "Orphan",
        ] {
            assert!(!text.contains(bad), "fsck.fat output mentions '{}':\n{}", bad, text);
        }
        // Our own checker agrees.
        let report = fat::fsck::check(&Device::open(image.path(), Access::ReadOnly).unwrap()).unwrap();
        assert_eq!(report.errors(), 0, "{:?}", report.problems);
    }
}

/// mtools reads everything we wrote, by long and by short name.
#[test]
fn mtools_reads_our_images() {
    let _serial = common::serial();
    let (Some(mdir), Some(mtype)) = (find_mtool("mdir"), find_mtool("mtype")) else {
        return skip("mtools");
    };
    let tree = Temp::dir();
    let files = test_files();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    build_tree(tree.path(), &refs);
    for &sector_size in &[512u32, 4096] {
        let image = Temp::image(if sector_size == 512 { 40 << 20 } else { 300 << 20 });
        populate(image.path(), tree.path(), sector_size, None);
        let img = image.0.to_str().unwrap();
        let env = [("MTOOLS_SKIP_CHECK", "1"), ("TZ", "UTC")];
        // Recursive bare listing: one path per line.
        let listing = run(&mdir, &["-i", img, "-/", "-b", "::"], &env);
        let mut listed: Vec<String> = listing
            .lines()
            .filter(|l| !l.ends_with('/'))
            .map(|l| l.trim_start_matches("::/").to_string())
            .collect();
        listed.sort();
        let mut expected = tree_files(tree.path());
        expected.sort();
        assert_eq!(listed, expected, "sector size {}", sector_size);
        for (path, data) in &files {
            let out = std::process::Command::new(&mtype)
                .args(["-i", img, &format!("::/{}", path)])
                .envs(env)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "mtype {} failed: {}",
                path,
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(&out.stdout, data, "contents of {} differ", path);
        }
        // Short names resolve too.
        let v = Volume::open(Device::open(image.path(), Access::ReadOnly).unwrap()).unwrap();
        let linux = v.metadata("/EFI/Linux/linux-6.12.3-300.fc41.x86_64.efi").unwrap();
        assert_eq!(linux.short_name, "LINUX-~1.EFI");
        let out = std::process::Command::new(&mtype)
            .args(["-i", img, &format!("::/EFI/LINUX/{}", linux.short_name)])
            .envs(env)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.stdout.len(), 300_000);
    }
}

/// Populating with mtools and with ufat, in the same order, gives the same
/// bytes.
#[test]
fn matches_mtools_byte_for_byte() {
    let _serial = common::serial();
    let (Some(mkfs), Some(mmd), Some(mcopy)) = (find_program("mkfs.fat"), find_mtool("mmd"), find_mtool("mcopy"))
    else {
        return skip("mkfs.fat or mtools");
    };
    let tree = Temp::dir();
    let files = test_files();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    build_tree(tree.path(), &refs);
    for &sector_size in &[512u32, 4096] {
        let size = if sector_size == 512 { 40u64 << 20 } else { 300 << 20 };
        let reference = Temp::image(size);
        run(
            &mkfs,
            &[
                "-F",
                "32",
                "-S",
                &sector_size.to_string(),
                "--invariant",
                "-n",
                "TEST",
                reference.0.to_str().unwrap(),
            ],
            &[],
        );
        let ours = Temp::new(".img");
        std::fs::copy(reference.path(), ours.path()).unwrap();

        // mtools: directories first (sorted), then files, exactly like our
        // sorted walk interleaves them.
        let env = [
            ("MTOOLS_SKIP_CHECK", "1"),
            ("TZ", "UTC"),
            ("SOURCE_DATE_EPOCH", "1699999000"),
        ];
        let img = reference.0.to_str().unwrap();
        fn walk(mmd: &Path, mcopy: &Path, env: &[(&str, &str)], img: &str, dir: &Path, rel: &str) {
            let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
            entries.sort_by_key(std::fs::DirEntry::file_name);
            for e in entries {
                let name = e.file_name().to_string_lossy().into_owned();
                let target = format!("{}/{}", rel, name);
                if e.file_type().unwrap().is_dir() {
                    // The source directory's time, like mcopy -s would use.
                    let mtime = e
                        .metadata()
                        .unwrap()
                        .modified()
                        .unwrap()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let env2: Vec<(&str, String)> = env.iter().map(|(k, v)| (*k, v.to_string())).collect();
                    let mut c = std::process::Command::new(mmd);
                    c.args(["-i", img, &format!("::{}", target)]);
                    for (k, v) in &env2 {
                        c.env(
                            k,
                            if *k == "SOURCE_DATE_EPOCH" {
                                mtime.to_string()
                            } else {
                                v.clone()
                            },
                        );
                    }
                    let out = c.output().unwrap();
                    assert!(
                        out.status.success(),
                        "mmd {}: {}",
                        target,
                        String::from_utf8_lossy(&out.stderr)
                    );
                    walk(mmd, mcopy, env, img, &e.path(), &target);
                } else {
                    run(
                        mcopy,
                        &["-m", "-i", img, e.path().to_str().unwrap(), &format!("::{}", target)],
                        env,
                    );
                }
            }
        }
        walk(&mmd, &mcopy, &env, img, tree.path(), "");

        let mut v = Volume::open(Device::open(ours.path(), Access::ReadWrite).unwrap()).unwrap();
        v.copy_tree(
            source(tree.path()).as_fd(),
            "/",
            &CopyOptions {
                times: TimePolicy::Preserve,
                replace: true,
                follow_symlinks: false,
            },
        )
        .unwrap();
        v.close().unwrap();

        if let Some(first) = first_difference(reference.path(), ours.path()).unwrap() {
            panic!(
                "mtools and ufat images differ (sector size {}), first at {} (0x{:x}): mtools {:02x?} ufat {:02x?}",
                sector_size,
                first,
                first,
                bytes_at(reference.path(), first, 32),
                bytes_at(ours.path(), first, 32)
            );
        }
    }
}

/// The planner's minimal size is exactly enough: populating fills the
/// volume completely, and one cluster less does not fit.
#[test]
fn planner_is_exact() {
    let _serial = common::serial();
    let tree = Temp::dir();
    let files = test_files();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, d.as_slice())).collect();
    build_tree(tree.path(), &refs);
    for &(sector_size, cluster_size) in &[
        (512u32, Some(512u32)),
        (512, Some(4096)),
        (512, None),
        (4096, Some(4096)),
        (4096, None),
    ] {
        let mut options = FormatOptions {
            sector_size: Some(sector_size),
            cluster_size,
            label: Some("FIT".into()),
            allow_small: true,
            ..FormatOptions::default()
        };
        let mut plan = fat::plan::Plan::new(fat::plan::PlanOptions::from_format_options(&options, None).unwrap());
        plan.add_tree(source(tree.path()).as_fd(), "/", false).unwrap();
        let estimate = plan.estimate().unwrap();
        estimate.apply(&mut options);

        let image = Temp::image(estimate.size());
        format::format(&Device::open(image.path(), Access::ReadWrite).unwrap(), &options).unwrap();
        let mut v = Volume::open(Device::open(image.path(), Access::ReadWrite).unwrap()).unwrap();
        v.copy_tree(source(tree.path()).as_fd(), "/", &CopyOptions::default())
            .unwrap();
        assert_eq!(
            v.free_clusters(),
            0,
            "sector {} cluster {:?}",
            sector_size,
            cluster_size
        );
        let mut back = Vec::new();
        v.open_file("/EFI/BOOT/BOOTX64.EFI")
            .unwrap()
            .read_to_end(&mut back)
            .unwrap();
        assert_eq!(back.len(), 70_000);
        v.close().unwrap();

        // One cluster less: formatting or populating must fail.
        let smaller = Temp::image(estimate.size() - u64::from(estimate.layout.cluster_size()));
        // Formatting closes its handle before the volume opens the image,
        // which holds the exclusive lock in turn.
        let formatted = format::format(&Device::open(smaller.path(), Access::ReadWrite).unwrap(), &options);
        let result = formatted.and_then(|_| {
            let mut v = Volume::open(Device::open(smaller.path(), Access::ReadWrite)?)?;
            v.copy_tree(source(tree.path()).as_fd(), "/", &CopyOptions::default())
                .map(|_| ())
        });
        assert!(result.is_err(), "a smaller volume still fit everything");
    }
}

/// Our SHA-256 agrees with coreutils' sha256sum: files around the block and
/// padding boundaries and a few megabytes of data, hashed once through the
/// one-shot digest and once through the manifest generator, which streams
/// every file of a tree through the walk.
#[test]
fn matches_sha256sum() {
    let _serial = common::serial();
    let Some(sha256sum) = find_program("sha256sum") else {
        return skip("sha256sum");
    };
    let tree = Temp::dir();
    let sizes = [
        0usize,
        1,
        3,
        55,
        56,
        57,
        63,
        64,
        65,
        119,
        120,
        127,
        128,
        129,
        1000,
        4096,
        65536,
        1 << 20,
        (3 << 20) + 1,
    ];
    let mut files = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        let name = format!("f{:02}-{}", i, size);
        let mut data = Vec::with_capacity(size);
        let mut x: u32 = 0x9e37_79b9 ^ size as u32;
        for _ in 0..size {
            data.push((x >> 24) as u8);
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        }
        std::fs::write(tree.path().join(&name), &data).unwrap();
        files.push((name, data));
    }
    let out = std::process::Command::new(&sha256sum)
        .args(files.iter().map(|(n, _)| n))
        .current_dir(tree.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let mut expected = std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let (hash, name) = line.split_once("  ").unwrap();
        expected.insert(name.to_string(), hash.to_string());
    }
    assert_eq!(expected.len(), files.len());
    for (name, data) in &files {
        assert_eq!(
            fat::sha256::to_hex(&fat::sha256::digest(data)),
            expected[name],
            "{}",
            name
        );
    }
    let dir = source(tree.path());
    let manifest = fat::manifest::parse(&fat::manifest::generate(dir.as_fd()).unwrap()).unwrap();
    let mut hashed = 0;
    for entry in &manifest.entries {
        if let (Some(name), Some(hash)) = (&entry.name, &entry.sha256) {
            assert_eq!(fat::sha256::to_hex(hash), expected[name], "{}", name);
            hashed += 1;
        }
    }
    assert_eq!(hashed, files.len());
}

/// A tree shaped like a folder things get downloaded into, which is what
/// an ESP tool is handed by accident as much as by design: a root with
/// eighty entries, names with spaces, umlauts, accents, carets and
/// parentheses, a four letter and an upper-case extension, names whose
/// short names collide, a hidden directory five levels deep full of small
/// files under uuid names, a few files of megabytes and an empty one.
fn real_world_files() -> Vec<(String, Vec<u8>)> {
    let mut x: u32 = 0x1234_5678;
    let mut data = |len: usize| -> Vec<u8> {
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect()
    };
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0..60usize {
        let suffix = if i % 2 == 1 { "(1)" } else { "" };
        files.push((
            format!("scan-2024-03-{}{}.pdf", 1000 + i / 2, suffix),
            data(700 + 37 * i),
        ));
    }
    for (name, len) in [
        ("01_report.pdf", 91_701usize),
        ("02_report.pdf", 67_942),
        ("photo.jpeg", 20_001),
        ("second.jpeg", 20_002),
        ("a.jpg", 3_333),
        ("archive_scan_part-one.jpg", 9_001),
        ("archive_scan_part-two.jpg", 9_002),
        ("notes^draft.jpg", 4_742),
        ("Cover.JPG", 1_772),
        ("\u{dc}bersicht.pdf", 5_000),
        ("Zusammenfassung_f\u{fc}r_M\u{e4}rz.pdf", 2_337),
        ("data.bin", 622),
        ("small.zip", 2_940),
        ("big-archive.zip", (3 << 20) + 1),
        ("medium.zip", (1 << 20) + 513),
        ("empty", 0),
    ] {
        files.push((name.to_string(), data(len)));
    }
    for month in ["January", "February", "March", "April", "May", "June"] {
        files.push((format!("2024/Statement {} 2024.pdf", month), data(2_100)));
    }
    files.push(("2024/R\u{e9}sum\u{e9} 2024.pdf".to_string(), data(1_890)));
    files.push((
        "2024 Reports/Quarterly report with a long name and many words in it.pdf".to_string(),
        data(5_347),
    ));
    files.push(("2024 Reports/Fee_Invoice.pdf".to_string(), data(7_455)));
    files.push((
        "New Documents/2001-2010 - Set 1 - M\u{e9}dia 7 - Scans - Album.jpg".to_string(),
        data(8_829),
    ));
    files.push(("New Documents/archive.zip".to_string(), data(1_949)));
    let tables = [
        "entries",
        "symbols",
        "vectors",
        "files",
        "names",
        "commits",
        "embeddings",
        "messages",
        "threads",
        "branches",
    ];
    for (i, table) in tables.iter().enumerate() {
        let base = format!(".cache.db/{}.store", table);
        for t in 0..2 {
            files.push((
                format!(
                    "{}/_transactions/{}-0f1e2d3c-4b5a-4968-8776-6554433221{:02x}.txn",
                    base,
                    10 + t,
                    16 * i + t
                ),
                data(43),
            ));
        }
        files.push((format!("{}/_versions/1.manifest", base), data(300 + i)));
        files.push((
            format!("{}/_indices/9a8b7c6d-5e4f-4a3b-9c2d-{:012x}/index.idx", base, i),
            data(1_024 + i),
        ));
        files.push((
            format!("{}/data/{:08x}-0000-4000-8000-000000000000.store", base, i),
            data(4_096 + 100 * i),
        ));
    }
    files
}

/// Everything in a tree like the one above comes back out of the image
/// `assemble` made from it: the same directories, the same files with the
/// same bytes and times, read by mtools rather than by us. The image is
/// exactly as large as the planner said and full, and the two verbose
/// lines of `assemble`, our fsck and fsck.fat agree on what is in it.
#[test]
fn an_assembled_tree_comes_back_through_mtools() {
    let _serial = common::serial();
    let (Some(ufat), Some(mcopy)) = (ufat(), find_mtool("mcopy")) else {
        return skip("ufat or mtools");
    };
    let tree = Temp::dir();
    let files = real_world_files();
    let refs: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (p.as_str(), d.as_slice())).collect();
    build_tree(tree.path(), &refs);
    let expected_files = tree_files(tree.path());
    let expected_dirs = tree_dirs(tree.path());
    assert_eq!(expected_files.len(), files.len());
    assert_eq!(std::fs::read_dir(tree.path()).unwrap().count(), 80);
    let (nf, nd) = (expected_files.len(), expected_dirs.len());
    let src = tree.path().to_str().unwrap();
    let image = Temp::new(".img");
    let img = image.0.to_str().unwrap();

    let out = std::process::Command::new(&ufat)
        .args(["assemble", "--create", "--verbose", img, src])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    // The plan and the copy report count the same tree.
    assert!(
        stderr.contains(&format!(": {} files and {} directories in ", nf, nd)),
        "{}",
        stderr
    );
    assert!(
        stderr.contains(&format!(": {} files, {} directories, ", nf, nd)),
        "{}",
        stderr
    );
    let size: u64 = run(&ufat, &["assemble", "--plan", src], &[]).trim().parse().unwrap();
    assert_eq!(std::fs::metadata(image.path()).unwrap().len(), size);
    let info = run(&ufat, &["describe", img], &[]);
    // The tree is far below the 65525 cluster floor, so the fit is the
    // floor itself and the volume is one firmware accepts.
    assert!(!info.contains("below the FAT32 minimum"), "{}", info);
    let fsck = run(&ufat, &["check", img], &[]);
    assert!(
        fsck.contains(&format!(": {} files, {} directories, ", nf, nd)),
        "{}",
        fsck
    );
    if let Some(fsck_fat) = find_program("fsck.fat") {
        let out = std::process::Command::new(&fsck_fat)
            .args(["-n", img])
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(out.status.success(), "{}", text);
        // fsck.fat counts files and directories together, the root left out.
        assert!(text.contains(&format!(": {} files, ", nf + nd)), "{}", text);
    }

    // Out again through mtools, with the times FAT kept: the sources have
    // even seconds, which FAT stores exactly, and mtools reads them in UTC
    // the way we wrote them.
    let out_dir = Temp::dir();
    let env = [("MTOOLS_SKIP_CHECK", "1"), ("TZ", "UTC"), ("LC_ALL", "C.UTF-8")];
    run(
        &mcopy,
        &["-i", img, "-s", "-n", "-m", "::/", out_dir.path().to_str().unwrap()],
        &env,
    );
    assert_eq!(tree_files(out_dir.path()), expected_files);
    assert_eq!(tree_dirs(out_dir.path()), expected_dirs);
    for rel in &expected_files {
        let (a, b) = (tree.path().join(rel), out_dir.path().join(rel));
        assert_eq!(first_difference(&a, &b).unwrap(), None, "{} came back different", rel);
        let (ma, mb) = (std::fs::metadata(&a).unwrap(), std::fs::metadata(&b).unwrap());
        assert_eq!(
            ma.modified().unwrap(),
            mb.modified().unwrap(),
            "{} came back with another time",
            rel
        );
    }
    // The short names: colliding ones got numeric tails, a four letter
    // extension needs a long name, a plain 8.3 name needs none.
    let listing = run(&ufat, &["list", "-l", img, "/"], &[]);
    assert!(
        listing.contains("(ARCHIV~1.JPG)") && listing.contains("(ARCHIV~2.JPG)"),
        "{}",
        listing
    );
    assert!(listing.contains("photo.jpeg  (PHOTO~1.JPE)"), "{}", listing);
    assert!(listing.lines().any(|l| l.ends_with(" a.jpg")), "{}", listing);
}

/// An `assemble` that fails while it copies leaves the file system marked
/// as not cleanly unmounted, and fsck.fat says so.
#[test]
fn fsck_fat_sees_a_failed_assemble() {
    let _serial = common::serial();
    let (Some(ufat), Some(fsck)) = (ufat(), find_program("fsck.fat")) else {
        return skip("ufat or fsck.fat");
    };
    let tree = Temp::dir();
    build_tree(tree.path(), &[("a.txt", b"first"), ("b.txt", b"second")]);
    let src = tree.path().to_str().unwrap();
    let manifest = Temp::new(".manifest");
    std::fs::write(manifest.path(), run(&ufat, &["manifest", src], &[])).unwrap();
    // b.txt changes after the manifest was written and keeps its size.
    std::fs::write(tree.path().join("b.txt"), b"SECOND").unwrap();
    let image = Temp::new(".img");
    let img = image.0.to_str().unwrap();
    let out = std::process::Command::new(&ufat)
        .args([
            "assemble",
            "--create",
            "--manifest",
            manifest.0.to_str().unwrap(),
            img,
            src,
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    let out = std::process::Command::new(&fsck).args(["-n", img]).output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "{}", text);
    assert!(text.contains("Dirty bit is set"), "{}", text);
}
