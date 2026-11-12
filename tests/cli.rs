// SPDX-License-Identifier: LGPL-2.1-or-later
//! The command line: assemble makes a file system and fills it, populate
//! fills an existing one, both take directory trees, or with --manifest the
//! tree a UAPI.16 manifest describes. The commands are the methods of the
//! Varlink interface.

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

/// -h and --help print the usage and exit 0 wherever they are among the
/// options, alone or in a bundle of short options, whatever else is on the
/// command line. Every other short option in a bundle is either applied or
/// refused.
#[test]
fn help_and_short_options() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let usage = ok(&bin, &["list", "-h"]);
    assert!(usage.starts_with("Usage: ufat COMMAND"), "{}", usage);
    // assemble's --verbose is described once, with what it reports.
    let verbose: Vec<&str> = usage
        .lines()
        .filter(|l| l.trim_start().starts_with("--verbose"))
        .collect();
    assert_eq!(
        verbose,
        ["  --verbose             Report the geometry chosen and what was written"]
    );
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

/// After `--`, and as the value of an option, -h is an argument like any
/// other.
#[test]
fn help_after_the_options_is_an_argument() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    fs::create_dir(root.join("-h")).unwrap();
    fs::write(root.join("-h/x"), b"x").unwrap();
    let source = root.join("-h");
    let source = source.to_str().unwrap();
    let expected = ok(&bin, &["manifest", source]);
    let out = Command::new(&bin)
        .args(["manifest", "--", "-h"])
        .current_dir(root)
        .env("SOURCE_DATE_EPOCH", "1700000000")
        .output()
        .expect("ufat runs");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), expected);
    fails(
        &bin,
        &["assemble", "--plan", "--size", "-h", source],
        "unknown size suffix in '-h'",
    );
}

/// Output into a pipe whose reader is gone ends ufat with SIGPIPE, as it
/// ends other command line tools, without a panic.
#[test]
fn a_closed_pipe_ends_ufat_quietly() {
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let image = dir.path().join("a.img");
    let image = image.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", image]);
    for args in [
        &["describe", image][..],
        &["capabilities"],
        &["--help"],
        &["list", "-h"],
    ] {
        let mut fds = [0; 2];
        // SAFETY: pipe2() stores two new descriptors in the array.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: both descriptors were just created and nothing else owns
        // them.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // The reader is gone before ufat starts, so its first write fails.
        drop(read);
        let out = Command::new(&bin)
            .args(args)
            .stdout(Stdio::from(write))
            .stderr(Stdio::piped())
            .output()
            .expect("ufat runs");
        assert_eq!(
            out.status.signal(),
            Some(libc::SIGPIPE),
            "ufat {:?}: {:?}",
            args,
            out.status
        );
        assert!(
            out.stderr.is_empty(),
            "ufat {:?}: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// --version, and version like help, print the version of the package.
#[test]
fn version() {
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let version = format!("ufat {}\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(ok(&bin, &["--version"]), version);
    assert_eq!(ok(&bin, &["version"]), version);
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
    let out = run_in(&bin, &["populate", "--manifest", m, a, "-"], b"kerneltitle x\nmore");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("goes on after the last file"));
    // --manifest - reads the manifest from standard input, which then
    // cannot carry the file contents as well.
    let manifest_bytes = fs::read(&manifest).unwrap();
    let out = run_in(&bin, &["assemble", "--plan", "--manifest", "-"], &manifest_bytes);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), tree_size);
    let out = run_in(&bin, &["populate", "--manifest", "-", a, tree_arg], &manifest_bytes);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let out = run_in(&bin, &["populate", "--manifest", "-", a, "-"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot both read standard input"));
    let out = run_in(&bin, &["assemble", "--plan", "--manifest", "-"], b"not a manifest");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("standard input is not a UAPI.16 manifest"));
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
    // A file that grew since the manifest was written is caught the same
    // way.
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernel and more").unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--manifest", m, d, tree_arg],
        ": EFI/Linux/linux.efi: EFI/Linux/linux.efi is 15 bytes, the manifest says 6",
    );
    assert!(!Path::new(d).exists());
    // One whose contents changed fails while it is copied. The messages
    // name the file the way the manifest does.
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernal").unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--manifest", m, d, tree_arg],
        "ufat: 'EFI/Linux/linux.efi' does not match the hash in the manifest",
    );
    fs::write(root.join("tree/EFI/Linux/linux.efi"), b"kernel").unwrap();
    // What a failed assemble wrote is left the way a crash would leave it:
    // the files that were complete, in a file system marked as not cleanly
    // unmounted. check reports the mark.
    fs::write(root.join("tree/loader/entries/x.conf"), b"title y\n").unwrap();
    let e = root.join("e.img");
    let e = e.to_str().unwrap();
    fails(
        &bin,
        &["assemble", "--create", "--manifest", m, e, tree_arg],
        "'loader/entries/x.conf' does not match the hash",
    );
    assert_eq!(ok(&bin, &["cat", e, "/EFI/Linux/linux.efi"]), "kernel");
    let report = ok(&bin, &["check", e]);
    assert!(report.contains("marked dirty"), "{}", report);
    assert!(report.contains("0 errors, 2 warnings"), "{}", report);
    fs::write(root.join("tree/loader/entries/x.conf"), b"title x\n").unwrap();
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

    // "-" is standard output. What the command prints there otherwise, the
    // description or the hash, goes to standard error then. Nothing named
    // "-" is created.
    let run_here = |args: &[&str]| {
        let out = Command::new(&bin)
            .args(args)
            .current_dir(root)
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .output()
            .expect("ufat runs");
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(out.status.success(), "ufat {:?} failed: {}", args, stderr);
        (out.stdout, stderr)
    };
    let (stdout, stderr) = run_here(&["describe", "--write-manifest", "-", a]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    assert!(stderr.contains("volume id:"), "{}", stderr);
    let c = root.join("c.img");
    let c = c.to_str().unwrap();
    let (stdout, stderr) = run_here(&[
        "assemble",
        "--create",
        "--hash",
        "sha256",
        "--write-manifest",
        "-",
        c,
        t,
    ]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    // What --hash sha256 prints for an image sized to fit.
    let sha256_line = |image: &str| {
        let mut h = ufat::sha256::Sha256::new();
        h.update(&fs::read(image).unwrap());
        format!("{}\n", ufat::sha256::to_hex(&h.finalize()))
    };
    assert_eq!(stderr, sha256_line(c));
    // --write-hash writes the hash to a file of its own, or for "-" to
    // standard output, which the manifest then cannot have as well.
    let e = root.join("e.img");
    let e = e.to_str().unwrap();
    let hash_file = root.join("e.sha256");
    let (stdout, stderr) = run_here(&[
        "assemble",
        "--create",
        "--hash",
        "sha256",
        "--write-hash",
        hash_file.to_str().unwrap(),
        "--write-manifest",
        "-",
        e,
        t,
    ]);
    assert_eq!(stdout, fs::read(&written).unwrap());
    assert!(stderr.is_empty(), "{}", stderr);
    assert_eq!(fs::read_to_string(&hash_file).unwrap(), sha256_line(e));
    let f = root.join("f.img");
    let f = f.to_str().unwrap();
    let (stdout, _) = run_here(&["assemble", "--create", "--hash", "sha256", "--write-hash", "-", f, t]);
    assert_eq!(String::from_utf8_lossy(&stdout), sha256_line(f));
    fails(
        &bin,
        &["assemble", "--create", "--write-hash", "-", c, t],
        "--write-hash needs --hash",
    );
    fails(
        &bin,
        &[
            "assemble",
            "--create",
            "--hash",
            "sha256",
            "--write-hash",
            "-",
            "--write-manifest",
            "-",
            c,
            t,
        ],
        "cannot both write to standard output",
    );
    let (stdout, _) = run_here(&["populate", "--path", "/more", "--write-manifest", "-", c, t]);
    assert_eq!(stdout, fs::read(&populated).unwrap());
    assert!(!root.join("-").exists());
}

/// A count of one is said in the singular: in the summary of check, in
/// what --verbose reports and in the note about entries a manifest leaves
/// out.
#[test]
fn counts_of_one() {
    use std::os::unix::fs::FileExt;
    let _serial = common::serial();
    let Some(bin) = ufat() else {
        return eprintln!("skipping: no ufat binary");
    };
    let dir = Temp::dir();
    let root = dir.path();
    fs::create_dir_all(root.join("tree/d")).unwrap();
    fs::write(root.join("tree/d/f"), b"x").unwrap();
    let t = root.join("tree");
    let t = t.to_str().unwrap();
    let a = root.join("a.img");
    let a = a.to_str().unwrap();
    let out = run(&bin, &["assemble", "--create", "--verbose", "--fats", "1", a, t]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert!(
        stderr.contains(": 1 file and 1 directory in 1 byte need a "),
        "{}",
        stderr
    );
    assert!(
        stderr.contains(&format!("{}: 1 file, 1 directory, 1 byte\n", t)),
        "{}",
        stderr
    );
    assert!(stderr.contains(" reserved sectors, 1 FAT of "), "{}", stderr);
    let out = run(&bin, &["assemble", "--plan", "--verbose", t]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("1 file, 1 directory, 1 byte: 3 clusters of 512 bytes"),
        "{}",
        stderr
    );

    // FAT entry 0 without the media byte in the first of two FATs is one
    // error, and the one byte the second FAT differs in is one warning.
    let b = root.join("b.img");
    ok(&bin, &["assemble", "--create", b.to_str().unwrap(), t]);
    let image = fs::OpenOptions::new().read(true).write(true).open(&b).unwrap();
    let mut sector = [0u8; 512];
    image.read_exact_at(&mut sector, 0).unwrap();
    let layout = ufat::boot::BootSector::parse(&sector).unwrap().layout().unwrap();
    image.write_all_at(&[0xf0], layout.fat_offset(0)).unwrap();
    drop(image);
    let out = run(&bin, &["check", b.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(4));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let summary = stdout.lines().last().unwrap();
    assert!(
        summary.starts_with(&format!("{}: 1 file, 1 directory, 3 clusters used, ", b.display())),
        "{}",
        stdout
    );
    assert!(summary.ends_with(" free, 0 lost; 1 error, 1 warning"), "{}", stdout);

    // An empty volume uses the one cluster of its root directory. A name
    // of 100 three-byte characters fits FAT but no manifest.
    let e = root.join("e.img");
    let e = e.to_str().unwrap();
    ok(&bin, &["assemble", "--create", "--size", "40M", e]);
    let summary = ok(&bin, &["check", e]);
    assert!(
        summary.contains(": 0 files, 0 directories, 1 cluster used, "),
        "{}",
        summary
    );
    let device = ufat::device::Device::open(Path::new(e), ufat::device::Access::ReadWrite).unwrap();
    let mut v = ufat::volume::Volume::open(device).unwrap();
    let long: String = std::iter::repeat_n('\u{20ac}', 100).collect();
    v.create_dir(&format!("/{}", long), std::time::SystemTime::now())
        .unwrap();
    v.close().unwrap();
    let m = root.join("e.manifest");
    let out = run(&bin, &["describe", "--write-manifest", m.to_str().unwrap(), e]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", stderr);
    assert!(
        stderr.contains(": its name cannot be written in a manifest"),
        "{}",
        stderr
    );
    assert!(stderr.starts_with("ufat: 1 entry is not in "), "{}", stderr);
}

/// assemble prints the hash of the file system it wrote on request, and
/// capabilities prints what GetCapabilities answers.
#[test]
fn hashes_and_capabilities() {
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
    let hash = ok(&bin, &["assemble", "--create", "--hash", "sha256", a, t]);
    let mut h = ufat::sha256::Sha256::new();
    h.update(&fs::read(a).unwrap());
    assert_eq!(hash, format!("{}\n", ufat::sha256::to_hex(&h.finalize())));
    let hash = ok(&bin, &["assemble", "--hash", "sha512", a, t]);
    assert_eq!(hash.trim().len(), 128);
    fails(&bin, &["assemble", "--hash", "md5", a, t], "sha256 or sha512");
    let caps = ok(&bin, &["capabilities"]);
    assert!(
        caps.starts_with('{') && caps.contains("\"fileSystemType\":\"vfat\""),
        "{}",
        caps
    );
    fails(&bin, &["capabilities", a], "takes no arguments");
}
