// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line: assemble makes a file system and fills it, populate
//! fills an existing one, both take directory trees, or with --manifest the
//! tree a UAPI.16 manifest describes.

mod common;

use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use common::{ufat, Temp};

fn run(bin: &Path, args: &[&str]) -> Output {
    Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("ufat runs")
}

/// Runs ufat with `stdin` fed to its standard input.
fn run_in(bin: &Path, args: &[&str], stdin: &[u8]) -> Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new(bin)
        .args(args)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ufat runs");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().expect("ufat runs")
}

fn ok(bin: &Path, args: &[&str]) -> String {
    let out = run(bin, args);
    assert!(
        out.status.success(),
        "ufat {:?} failed: {}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn fails(bin: &Path, args: &[&str], with: &str) {
    let out = run(bin, args);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "ufat {:?}: {}", args, stderr);
    assert!(
        stderr.contains(with),
        "ufat {:?}: expected '{}' in '{}'",
        args,
        with,
        stderr
    );
}

fn tree(root: &Path) {
    fs::create_dir_all(root.join("EFI/Linux")).unwrap();
    fs::create_dir_all(root.join("loader/entries")).unwrap();
    fs::write(root.join("EFI/Linux/linux.efi"), b"kernel").unwrap();
    fs::write(root.join("loader/entries/x.conf"), b"title x\n").unwrap();
}

/// -h and --help print the usage and exit 0 wherever they are, alone or
/// in a bundle of short options, whatever else is on the command line.
/// Every other short option in a bundle is either applied or refused.
#[test]
fn help_and_short_options() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let usage = ok(&bin, &["list", "-h"]);
    assert!(usage.starts_with("Usage: ufat COMMAND"), "{}", usage);
    for args in [
        &["list", "-hl", "x.img"][..],
        &["list", "-lh", "x.img"],
        &["list", "x.img", "-lh"],
        &["remove", "-rh", "x.img", "/a"],
        &["populate", "-ph", "x.img"],
        &["check", "-rh", "x.img"],
        &["list", "--bogus", "-hl", "x.img"],
        &["describe", "--help", "x.img"],
    ] {
        assert_eq!(ok(&bin, args), usage, "ufat {:?}", args);
    }
    fails(&bin, &["list", "-lr", "x.img"], "unknown option -r");
    fails(&bin, &["list", "-rl", "x.img"], "unknown option -r");
    fails(&bin, &["remove", "-rl", "x.img", "/a"], "unknown option -l");
    fails(&bin, &["check", "-p", "x.img"], "unknown option -p");
    fails(&bin, &["list", "-lx", "x.img"], "unknown option -x");
    fails(&bin, &["list", "-l=1", "x.img"], "option -l takes no value");
}

#[test]
fn assemble_and_populate_take_trees_and_manifests() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let tree_arg = root.join("tree");
    let tree_arg = tree_arg.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    // A tree: created, formatted and filled in one command. The size is
    // given so that the replacements below have room: a replacement holds
    // the old file until the new one is complete, and a volume sized to fit
    // exactly has no cluster to spare for that.
    ok(&bin, &["assemble", "--create", "--size", "40M", a, tree_arg]);
    assert_eq!(ok(&bin, &["list", a, "/EFI/Linux"]), "linux.efi\n");
    assert!(run(&bin, &["check", a]).status.success());
    let tree_size = ok(&bin, &["assemble", "--plan", tree_arg]);
    // A manifest of the tree, kept outside it, builds the same content; the
    // one SOURCE says where the files are.
    let manifest = root.join("tree.manifest");
    fs::write(&manifest, ok(&bin, &["manifest", tree_arg])).unwrap();
    let m = manifest.to_str().unwrap();
    let b = root.join("b.img");
    let b = b.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--manifest", m, b, tree_arg]);
    assert_eq!(ok(&bin, &["list", b, "/loader/entries"]), "x.conf\n");
    assert_eq!(ok(&bin, &["cat", b, "/EFI/Linux/linux.efi"]), "kernel");
    // The planner sees the same size from the manifest, which needs no
    // SOURCE to be sized.
    assert_eq!(tree_size, ok(&bin, &["assemble", "--plan", "--manifest", m]));
    // populate fills an existing volume, from a manifest too, replacing.
    ok(&bin, &["populate", "--manifest", m, a, tree_arg]);
    ok(&bin, &["populate", "--path", "/second", a, tree_arg]);
    assert_eq!(ok(&bin, &["list", a, "/second/EFI/Linux"]), "linux.efi\n");
    assert!(run(&bin, &["check", a]).status.success());
    // "-" takes the file contents from standard input, back to back in
    // manifest order: linux.efi sorts before x.conf.
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kerneltitle x\n");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(ok(&bin, &["cat", a, "/loader/entries/x.conf"]), "title x\n");
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kern");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("ended"));
    // A SOURCE is a directory, or for populate one file that needs --path;
    // a manifest is named by --manifest.
    fails(&bin, &["populate", a, m], "needs --path");
    fails(&bin, &["populate", a, m, tree_arg], "a SOURCE is a directory tree");
    fs::write(root.join("garbage"), b"not a manifest").unwrap();
    fails(
        &bin,
        &[
            "populate",
            "--manifest",
            root.join("garbage").to_str().unwrap(),
            a,
            tree_arg,
        ],
        "is not a UAPI.16 manifest",
    );
    // A manifest takes exactly one SOURCE and no --path.
    fails(
        &bin,
        &["populate", "--manifest", m, a, tree_arg, tree_arg],
        "exactly one SOURCE",
    );
    fails(&bin, &["populate", "--manifest", m, a], "exactly one SOURCE");
    fails(
        &bin,
        &["populate", "--manifest", m, "--path", "/x", a, tree_arg],
        "--path applies to directory trees",
    );
    // The switches and commands of the earlier command line are gone.
    fails(&bin, &["populate", "--format", "tree", a, tree_arg], "unknown option");
    fails(&bin, &["populate", "--into", "/x", a, tree_arg], "unknown option");
    for old in ["mkfs", "size", "info", "cp", "mkdir", "rmdir", "rm", "ls", "fsck"] {
        fails(&bin, &[old, a], "unknown command");
    }
    fails(
        &bin,
        &["assemble", "--create", "--source", tree_arg, b, m],
        "unknown option",
    );
    fails(&bin, &["assemble", "--create", "--stream", b, m], "unknown option");
    // The files a manifest names are checked below the SOURCE before an
    // image is created, so a wrong tree leaves nothing behind.
    let d = root.join("d.img");
    let d = d.to_str().unwrap();
    fs::create_dir(root.join("empty")).unwrap();
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--manifest",
            m,
            d,
            root.join("empty").to_str().unwrap(),
        ],
        "linux.efi",
    );
    assert!(!Path::new(d).exists());
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--manifest",
            m,
            d,
            root.join("nowhere").to_str().unwrap(),
        ],
        "nowhere",
    );
    assert!(!Path::new(d).exists());
    // Without a SOURCE assemble makes an empty file system, sized for a
    // manifest as well, and takes no --fit with it.
    let c = root.join("c.img");
    let c = c.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--manifest", m, c]);
    ok(&bin, &["populate", "--manifest", m, c, tree_arg]);
    assert!(run(&bin, &["check", c]).status.success());
    fails(
        &bin,
        &["assemble", "--create", "--fit", tree_arg, "--manifest", m, c],
        "carries the sizes",
    );
    fails(&bin, &["assemble", "--plan"], "at least one SOURCE or --manifest");
    fails(
        &bin,
        &["assemble", "--create", "--fit", tree_arg, c, tree_arg],
        "--fit sizes an empty file system",
    );
}

/// A volume too small for what goes into it. A copy that runs out of
/// clusters says which file did not fit and leaves what came before it in
/// a consistent file system. `assemble` with a `--size` the content does
/// not fit says so before it sizes or formats anything: a file `--create`
/// made is gone again and an existing file is as it was. Without a size an
/// existing file is grown to the fit and never shrunk.
#[test]
fn too_small_volumes_fail_cleanly() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("sub")).unwrap();
    fs::write(tree.join("a.txt"), b"first\n").unwrap();
    fs::write(tree.join("big.bin"), vec![0x5au8; 36 << 20]).unwrap();
    fs::write(tree.join("sub/c.txt"), b"last\n").unwrap();
    let t = tree.to_str().unwrap();

    let small = root.join("small.img");
    let s = small.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "34M", s]);
    fails(&bin, &["populate", s, t], "copying big.bin: no free clusters left");
    assert!(run(&bin, &["check", s]).status.success());
    assert_eq!(ok(&bin, &["cat", s, "/a.txt"]), "first\n");
    assert!(!ok(&bin, &["list", s, "/"]).contains("big.bin"));

    let new = root.join("new.img");
    let n = new.to_str().unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--size", "1M", n, t],
        "holds 1048576 bytes but the content needs",
    );
    assert!(!new.exists(), "a failed assemble left its image behind");
    let existing = root.join("existing.img");
    let e = existing.to_str().unwrap();
    fs::write(&existing, b"").unwrap();
    fails(
        &bin,
        &["assemble", "--size", "1M", e, t],
        "holds 1048576 bytes but the content needs",
    );
    assert_eq!(fs::metadata(&existing).unwrap().len(), 0);

    let size: u64 = ok(&bin, &["assemble", "--plan", t]).trim().parse().unwrap();
    // A plan against a size says whether the sources fit it.
    fails(&bin, &["assemble", "--plan", "--size", "1M", t], "more than --size");
    assert_eq!(
        ok(&bin, &["assemble", "--plan", "--size", "64M", t]),
        format!("{}\n", size)
    );
    fs::File::create(&existing).unwrap().set_len(4096).unwrap();
    ok(&bin, &["assemble", e, t]);
    assert_eq!(fs::metadata(&existing).unwrap().len(), size);
    assert_eq!(ok(&bin, &["cat", e, "/sub/c.txt"]), "last\n");
    let large = root.join("large.img");
    let l = large.to_str().unwrap();
    fs::File::create(&large).unwrap().set_len(64 << 20).unwrap();
    ok(&bin, &["assemble", l, t]);
    assert_eq!(fs::metadata(&large).unwrap().len(), 64 << 20);
    assert!(run(&bin, &["check", l]).status.success());
    assert_eq!(ok(&bin, &["cat", l, "/sub/c.txt"]), "last\n");
}

/// Paths on the host are taken as the bytes they are, UTF-8 or not. Paths
/// inside the volume are Unicode, and one that is not UTF-8 is refused.
#[test]
fn host_paths_need_not_be_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let tree_dir = dir.path().join(OsStr::from_bytes(b"tree-\xfe"));
    tree(&tree_dir);
    let image = dir.path().join(OsStr::from_bytes(b"esp-\xff.img"));
    let manifest = dir.path().join(OsStr::from_bytes(b"m-\xfd.json"));
    let ufat = |args: &[&OsStr]| {
        Command::new(&bin)
            .args(args)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .expect("ufat runs")
    };
    let out = ufat(&[
        "assemble".as_ref(),
        "--create".as_ref(),
        image.as_ref(),
        tree_dir.as_ref(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = ufat(&["cat".as_ref(), image.as_ref(), "/EFI/Linux/linux.efi".as_ref()]);
    assert_eq!(out.stdout, b"kernel");
    let out = ufat(&["manifest".as_ref(), tree_dir.as_ref()]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    fs::write(&manifest, &out.stdout).unwrap();
    let mut with_manifest = OsString::from("--manifest=");
    with_manifest.push(&manifest);
    let out = ufat(&["assemble".as_ref(), "--plan".as_ref(), &with_manifest]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = ufat(&["list".as_ref(), image.as_ref(), OsStr::from_bytes(b"/EFI/\xff")]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not valid UTF-8"));
    let out = ufat(&["assemble".as_ref(), OsStr::from_bytes(b"--label=\xff"), image.as_ref()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not valid UTF-8"));
}

/// populate puts a tree below --path, one file at --path, and makes the
/// directory --path when there is no SOURCE; remove takes files, empty
/// directories and with --recursive whole trees, never the root. What FAT
/// cannot store is left out, or with --unsupported fail refused before
/// anything is written.
#[test]
fn populate_and_remove_work_on_paths() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let img = root.join("a.img");
    let a = img.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", a]);
    // One file, at the path it is given, with its parents on request.
    let file = root.join("bootx64.efi");
    fs::write(&file, b"loader").unwrap();
    let f = file.to_str().unwrap();
    fails(
        &bin,
        &["populate", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
        "does not exist",
    );
    ok(
        &bin,
        &["populate", "--parents", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
    );
    assert_eq!(ok(&bin, &["cat", a, "/EFI/BOOT/BOOTX64.EFI"]), "loader");
    fails(
        &bin,
        &["populate", "--no-replace", "--path", "/EFI/BOOT/BOOTX64.EFI", a, f],
        "exists",
    );
    // No SOURCE: the directory --path, which may exist only with --parents.
    ok(&bin, &["populate", "--path", "/loader", a]);
    fails(&bin, &["populate", "--path", "/loader", a], "exists");
    ok(&bin, &["populate", "--parents", "--path", "/loader/entries", a]);
    ok(&bin, &["populate", "--parents", "--path", "/loader", a]);
    fails(&bin, &["populate", a], "--path for the directory to create");
    // A tree goes below --path, which is made when missing.
    ok(&bin, &["populate", "--path", "/copy", a, t]);
    assert_eq!(ok(&bin, &["list", a, "/copy/EFI/Linux"]), "linux.efi\n");
    // remove: a file, an empty directory, a tree only with --recursive.
    ok(&bin, &["remove", a, "/EFI/BOOT/BOOTX64.EFI", "/loader/entries"]);
    assert_eq!(ok(&bin, &["list", a, "/loader"]), "");
    fails(&bin, &["remove", a, "/copy"], "not empty");
    ok(&bin, &["remove", "-r", a, "/copy"]);
    ok(&bin, &["remove", "--recursive", a, "/EFI"]);
    assert_eq!(ok(&bin, &["list", a, "/"]), "loader/\n");
    fails(&bin, &["remove", "--recursive", a, "/"], "root directory");
    assert!(run(&bin, &["check", a]).status.success());
    // A FIFO cannot go on FAT: left out by default, refused on request.
    sys_mkfifo(&root.join("tree/fifo"));
    let out = run(&bin, &["populate", "--path", "/fifo-skip", a, t]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("skipped"));
    fails(
        &bin,
        &["populate", "--unsupported", "fail", "--path", "/fifo-fail", a, t],
        "cannot be stored on FAT",
    );
    assert!(!ok(&bin, &["list", a, "/"]).contains("fifo-fail"));
    fails(&bin, &["populate", "--unsupported", "maybe", a, t], "skip or fail");
}

/// Creates a FIFO without spawning mkfifo(1).
fn sys_mkfifo(path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    // SAFETY: a valid NUL terminated path; mkfifo touches nothing else.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

/// assemble, populate and describe write the UAPI.16 manifest of what the
/// file system holds on request, one that builds the same content again.
#[test]
fn manifests_of_what_was_written() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    tree(&root.join("tree"));
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    let written = root.join("written.manifest");
    let w = written.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--write-manifest", w, a, t]);
    let described = root.join("described.manifest");
    let d = described.to_str().unwrap();
    ok(&bin, &["describe", "--write-manifest", d, a]);
    assert_eq!(fs::read(&written).unwrap(), fs::read(&described).unwrap());
    let text = String::from_utf8_lossy(&fs::read(&written).unwrap()).into_owned();
    assert!(text.contains("\"EFI/Linux/linux.efi\""), "{}", text);
    // The manifest builds the same files from the tree.
    let b = root.join("b.img");
    let b = b.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--manifest", w, b, t]);
    assert_eq!(ok(&bin, &["cat", b, "/EFI/Linux/linux.efi"]), "kernel");
    let populated = root.join("populated.manifest");
    let p = populated.to_str().unwrap();
    ok(&bin, &["populate", "--path", "/more", "--write-manifest", p, b, t]);
    assert!(String::from_utf8_lossy(&fs::read(&populated).unwrap()).contains("\"more/EFI/Linux/linux.efi\""));
}
