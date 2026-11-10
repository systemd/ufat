// SPDX-License-Identifier: LGPL-2.1-or-later
//! Helpers shared by the integration tests.
#![allow(dead_code, unreachable_pub)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

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
