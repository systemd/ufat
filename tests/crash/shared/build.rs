// SPDX-License-Identifier: LGPL-2.1-or-later
//! Builds the shared crate with the write trace of device.rs.

fn main() {
    println!("cargo::rustc-cfg=ufat_trace");
}
