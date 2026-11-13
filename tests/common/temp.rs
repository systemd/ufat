// SPDX-License-Identifier: LGPL-2.1-or-later
//! Temporary files for the tests, and running the tests of a binary one
//! at a time.
#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};
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
