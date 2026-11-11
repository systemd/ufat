// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers shared by the integration tests.
#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static COUNTER: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

/// Runs the tests of a binary one at a time. A child process inherits every
/// descriptor open at the moment it is forked, and with it the lock on an
/// image some other test holds, until it execs; a test that opens images
/// while another spawns programs would see a spurious EBUSY. Hold the guard
/// for the whole test.
pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A temporary path, removed on drop (file or directory).
pub struct Temp(pub PathBuf);

impl Temp {
    pub fn new(suffix: &str) -> Temp {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        Temp(std::env::temp_dir().join(format!("ufat-it-{}-{}{}", std::process::id(), n, suffix)))
    }

    /// A zero-filled image file of `size` bytes.
    pub fn image(size: u64) -> Temp {
        let t = Temp::new(".img");
        std::fs::File::create(&t.0).unwrap().set_len(size).unwrap();
        t
    }

    /// An empty directory.
    pub fn dir() -> Temp {
        let t = Temp::new(".d");
        std::fs::create_dir_all(&t.0).unwrap();
        t
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        if self.0.is_dir() {
            let _ = std::fs::remove_dir_all(&self.0);
        } else {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

/// The ufat binary under test, which cargo builds for the integration
/// tests of the ufat package. The crash harness lives in a package without
/// it.
pub fn ufat() -> Option<PathBuf> {
    option_env!("CARGO_BIN_EXE_ufat")
        .map(PathBuf::from)
        .filter(|p| p.is_file())
}

/// Finds a program in PATH, /usr/sbin and /sbin.
pub fn find_program(name: &str) -> Option<PathBuf> {
    let path = std::env::var("PATH").unwrap_or_default();
    for dir in path.split(':').chain(["/usr/sbin", "/sbin", "/usr/bin", "/bin"]) {
        let p = Path::new(dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Finds an mtools program, honouring `UFAT_MTOOLS` (a directory).
pub fn find_mtool(name: &str) -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("UFAT_MTOOLS") {
        let p = Path::new(&dir).join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    find_program(name)
}

/// Runs a program and returns stdout, panicking on failure.
pub fn run(program: &Path, args: &[&str], env: &[(&str, &str)]) -> String {
    let mut c = Command::new(program);
    c.args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c
        .output()
        .unwrap_or_else(|e| panic!("failed to run {}: {}", program.display(), e));
    assert!(
        out.status.success(),
        "{} {:?} failed: {}\n{}",
        program.display(),
        args,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Builds a test tree with the given files (path, contents) under `root`,
/// with even-second timestamps so FAT can store them exactly.
pub fn build_tree(root: &Path, files: &[(&str, &[u8])]) {
    for (i, (path, data)) in files.iter().enumerate() {
        let p = root.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, data).unwrap();
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + 2 * i as u64);
        std::fs::File::options()
            .write(true)
            .open(&p)
            .unwrap()
            .set_modified(t)
            .unwrap();
    }
    // Directories get a fixed time too, deepest first so the parents keep
    // theirs.
    let mut dirs: Vec<PathBuf> = Vec::new();
    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            if e.file_type().unwrap().is_dir() {
                collect(&e.path(), out);
                out.push(e.path());
            }
        }
    }
    collect(root, &mut dirs);
    dirs.push(root.to_path_buf());
    for d in dirs {
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_699_999_000);
        std::fs::File::open(&d).unwrap().set_modified(t).unwrap();
    }
}

/// Lists all regular files of a tree relative to `root`, sorted.
pub fn tree_files(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            let name = e.file_name().to_string_lossy().into_owned();
            let rel = format!("{}{}", prefix, name);
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), &format!("{}/", rel), out);
            } else {
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out
}

/// Lists all directories of a tree relative to `root`, sorted, each
/// before what is below it.
pub fn tree_dirs(root: &Path) -> Vec<String> {
    fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap()).collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for e in entries {
            if e.file_type().unwrap().is_dir() {
                let rel = format!("{}{}", prefix, e.file_name().to_string_lossy());
                out.push(rel.clone());
                walk(&e.path(), &format!("{}/", rel), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, "", &mut out);
    out
}

/// Compares two files without loading them: Ok(None) if identical, else
/// the offset of the first differing byte.
pub fn first_difference(a: &Path, b: &Path) -> std::io::Result<Option<u64>> {
    let mut fa = std::fs::File::open(a)?;
    let mut fb = std::fs::File::open(b)?;
    let mut ba = vec![0u8; 1 << 20];
    let mut bb = vec![0u8; 1 << 20];
    let mut offset = 0u64;
    loop {
        let na = read_full(&mut fa, &mut ba)?;
        let nb = read_full(&mut fb, &mut bb)?;
        if na != nb {
            return Ok(Some(offset + na.min(nb) as u64));
        }
        if na == 0 {
            return Ok(None);
        }
        if let Some(i) = ba[..na].iter().zip(&bb[..nb]).position(|(x, y)| x != y) {
            return Ok(Some(offset + i as u64));
        }
        offset += na as u64;
    }
}

fn read_full(f: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    use std::io::Read;
    let mut n = 0;
    while n < buf.len() {
        let k = f.read(&mut buf[n..])?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
}

/// A few bytes of a file at an offset, for failure messages.
pub fn bytes_at(path: &Path, offset: u64, len: usize) -> Vec<u8> {
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(path).unwrap();
    let mut buf = vec![0u8; len];
    let n = f.read_at(&mut buf, offset).unwrap_or(0);
    buf.truncate(n);
    buf
}
