// SPDX-License-Identifier: LGPL-2.1-or-later
//! SHA-256 (FIPS 180-4), used to verify the contents listed in manifests.

/// Size of a digest in bytes.
pub const DIGEST_SIZE: usize = 32;

/// The digest of the empty string.
pub const EMPTY: [u8; DIGEST_SIZE] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41,
    0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A streaming SHA-256 computation.
#[derive(Clone, Debug)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffered: usize,
    length: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256::new()
    }
}

impl Sha256 {
    /// Starts a new computation.
    pub fn new() -> Sha256 {
        Sha256 {
            state: H0,
            buffer: [0; 64],
            buffered: 0,
            length: 0,
        }
    }

    /// Compresses a whole number of blocks.
    fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % 64, 0);
        for block in blocks.chunks_exact(64) {
            Self::compress(state, block);
        }
    }

    /// The portable compression function, one block at a time.
    ///
    /// The 64 rounds are written out, eight at a time. The schedule is
    /// computed as it is needed in a ring of the last 16 words, and the
    /// working variables are not shifted by assignment: a round only
    /// changes `d` and `h`, and the next round names them one further
    /// along. The straightforward form of this, with a 64 word schedule
    /// and a loop that shifts eight variables per round, is 1.3-1.4x slower.
    fn compress(state: &mut [u32; 8], block: &[u8]) {
        let mut w = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        // Round i with the working variables in the order they have in it.
        macro_rules! round {
            ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $i:expr) => {{
                let i: usize = $i;
                if i >= 16 {
                    // w[i] replaces w[i - 16] in the ring.
                    let w15 = w[(i + 1) % 16];
                    let w2 = w[(i + 14) % 16];
                    let s0 = w15.rotate_right(7) ^ w15.rotate_right(18) ^ (w15 >> 3);
                    let s1 = w2.rotate_right(17) ^ w2.rotate_right(19) ^ (w2 >> 10);
                    w[i % 16] = w[i % 16].wrapping_add(s0).wrapping_add(w[(i + 9) % 16]).wrapping_add(s1);
                }
                let s1 = $e.rotate_right(6) ^ $e.rotate_right(11) ^ $e.rotate_right(25);
                let ch = (($f ^ $g) & $e) ^ $g;
                let t1 = $h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i % 16]);
                let s0 = $a.rotate_right(2) ^ $a.rotate_right(13) ^ $a.rotate_right(22);
                let maj = (($a ^ $b) & ($b ^ $c)) ^ $b;
                $d = $d.wrapping_add(t1);
                $h = t1.wrapping_add(s0).wrapping_add(maj);
            }};
        }
        // Eight rounds bring the names back to where they started.
        macro_rules! eight_rounds {
            ($i:literal) => {
                round!(a, b, c, d, e, f, g, h, $i);
                round!(h, a, b, c, d, e, f, g, $i + 1);
                round!(g, h, a, b, c, d, e, f, $i + 2);
                round!(f, g, h, a, b, c, d, e, $i + 3);
                round!(e, f, g, h, a, b, c, d, $i + 4);
                round!(d, e, f, g, h, a, b, c, $i + 5);
                round!(c, d, e, f, g, h, a, b, $i + 6);
                round!(b, c, d, e, f, g, h, a, $i + 7);
            };
        }
        eight_rounds!(0);
        eight_rounds!(8);
        eight_rounds!(16);
        eight_rounds!(24);
        eight_rounds!(32);
        eight_rounds!(40);
        eight_rounds!(48);
        eight_rounds!(56);
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    /// Feeds data.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let take = data.len().min(64 - self.buffered);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                // Everything fit into the partial block.
                return;
            }
            let block = self.buffer;
            Self::compress_blocks(&mut self.state, &block);
            self.buffered = 0;
        }
        let whole = data.len() / 64 * 64;
        Self::compress_blocks(&mut self.state, &data[..whole]);
        let rest = &data[whole..];
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Finishes the computation and returns the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bits = self.length.wrapping_mul(8);
        let mut padding = [0u8; 72];
        padding[0] = 0x80;
        let pad_len = if self.buffered < 56 {
            56 - self.buffered
        } else {
            120 - self.buffered
        };
        padding[pad_len..pad_len + 8].copy_from_slice(&bits.to_be_bytes());
        self.update(&padding[..pad_len + 8]);
        debug_assert_eq!(self.buffered, 0);
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, s) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&s.to_be_bytes());
        }
        out
    }
}

/// The digest of `data`.
pub fn digest(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
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
