// SPDX-License-Identifier: LGPL-2.1-or-later
//! The ufat tool: a command line interface over the ufat library.

use std::process::ExitCode;

mod cli;
mod util;

fn main() -> ExitCode {
    // A tree walk holds one descriptor per level; the soft limit of 1024
    // is select()'s, and nothing here uses select().
    let _ = ufat::host::raise_descriptor_limit();
    cli::main()
}
