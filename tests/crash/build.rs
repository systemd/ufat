// SPDX-License-Identifier: LGPL-2.1-or-later
//! Builds the library with the write trace of device.rs.

fn main() {
    println!("cargo::rustc-cfg=ufat_trace");
}
