// SPDX-License-Identifier: LGPL-2.1-or-later
//! SHA-256 (FIPS 180-4), used to verify the contents listed in manifests.
//! The sha2 crate computes it, with the SHA instructions of the CPU where
//! it has them.

use sha2::Digest;

/// Size of a digest in bytes.
pub const DIGEST_SIZE: usize = 32;

/// The digest of the empty string.
pub const EMPTY: [u8; DIGEST_SIZE] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
    0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// A streaming SHA-256 computation.
#[derive(Clone, Debug, Default)]
pub struct Sha256(sha2::Sha256);

impl Sha256 {
    /// Starts a new computation.
    pub fn new() -> Sha256 {
        Sha256(sha2::Sha256::new())
    }

    /// Feeds data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finishes the computation and returns the digest.
    pub fn finalize(self) -> [u8; DIGEST_SIZE] {
        self.0.finalize().into()
    }
}

/// The digest of `data`.
pub fn digest(data: &[u8]) -> [u8; DIGEST_SIZE] {
    sha2::Sha256::digest(data).into()
}

/// Lower case hex encoding.
pub fn to_hex(digest: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(digest.len() * 2);
    for &b in digest {
        hex.push(char::from(DIGITS[usize::from(b >> 4)]));
        hex.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    hex
}

/// Decodes 64 hex digits of either case.
pub fn from_hex(text: &str) -> Option<[u8; DIGEST_SIZE]> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * DIGEST_SIZE {
        return None;
    }
    let mut out = [0u8; DIGEST_SIZE];
    for (i, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The FIPS 180-4 vectors.
    #[test]
    fn vectors() {
        let million = vec![b'a'; 1_000_000];
        for (data, expected) in [
            (
                &b""[..],
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                &million[..],
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
        ] {
            assert_eq!(to_hex(&digest(data)), expected, "{} bytes", data.len());
        }
        assert_eq!(digest(b""), EMPTY);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        let expected = digest(&data);
        for chunk in [1usize, 7, 63, 64, 65, 100, 999] {
            let mut h = Sha256::new();
            for piece in data.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), expected, "chunk size {}", chunk);
        }
    }

    #[test]
    fn hex() {
        let hex = to_hex(&EMPTY);
        assert_eq!(from_hex(&hex), Some(EMPTY));
        assert_eq!(from_hex(&hex.to_uppercase()), Some(EMPTY));
        assert_eq!(from_hex("00"), None);
        assert_eq!(from_hex(&"zz".repeat(32)), None);
    }
}
