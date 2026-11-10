// SPDX-License-Identifier: LGPL-2.1-or-later
//! genfile: writes SIZE bytes of deterministic pseudo-random data to FILE.
//!
//!   genfile FILE SIZE SEED
//!
//! The same SIZE and SEED always give the same bytes (xorshift64*), so the
//! benchmark inputs are reproducible without shipping them. SIZE takes K,
//! M and G suffixes.

use std::io::Write;

fn parse_size(s: &str) -> Option<u64> {
    let (digits, mult) = match s.chars().last()? {
        'K' | 'k' => (&s[..s.len() - 1], 1u64 << 10),
        'M' | 'm' => (&s[..s.len() - 1], 1 << 20),
        'G' | 'g' => (&s[..s.len() - 1], 1 << 30),
        _ => (s, 1),
    };
    digits.parse::<u64>().ok()?.checked_mul(mult)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: genfile FILE SIZE SEED");
        std::process::exit(2);
    }
    let size = parse_size(&args[2]).unwrap_or_else(|| {
        eprintln!("genfile: bad size '{}'", args[2]);
        std::process::exit(2);
    });
    let mut state: u64 = args[3].parse::<u64>().unwrap_or(1) | 1;
    let mut out = std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&args[1]).unwrap());
    let mut left = size;
    let mut block = [0u8; 8192];
    while left > 0 {
        for chunk in block.chunks_exact_mut(8) {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            chunk.copy_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
        }
        let n = left.min(block.len() as u64) as usize;
        out.write_all(&block[..n]).unwrap();
        left -= n as u64;
    }
    out.flush().unwrap();
}
