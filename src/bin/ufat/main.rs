// SPDX-License-Identifier: LGPL-2.1-or-later
//! The ufat tool: a command line interface and a Varlink service over the
//! FAT library.
//!
//! Started with a socket passed through `LISTEN_FDS` (as `varlinkctl call
//! exec:/path/to/ufat ...` and systemd socket units do) it serves the
//! `org.uapi-group.FileSystem` interface for vfat on that socket and exits
//! when the client hangs up. Otherwise it runs the command given on the
//! command line.

use std::process::ExitCode;

mod cli;
mod service;
mod util;

fn main() -> ExitCode {
    // A tree walk holds one descriptor per level; the soft limit of 1024
    // is select()'s, and nothing here uses select().
    let _ = fat::host::raise_descriptor_limit();
    match varlink::activation() {
        Ok(Some(activation)) => match service::run(activation) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("ufat: varlink: {}", e);
                ExitCode::FAILURE
            }
        },
        Ok(None) => cli::main(),
        Err(e) => {
            eprintln!("ufat: {}", e);
            ExitCode::FAILURE
        }
    }
}
