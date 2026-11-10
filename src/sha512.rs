// SPDX-License-Identifier: LGPL-2.1-or-later
//! SHA-512 (FIPS 180-4), for the hash of a whole image a caller may ask
//! for. The hashes inside manifests stay SHA-256, see [`crate::sha256`].
//!
//! Portable code only; the message schedule and the 80 rounds are written
//! out the way the standard gives them.

pub use crate::sha256::to_hex;

/// Size of a digest in bytes.
pub const DIGEST_SIZE: usize = 64;

/// Size of a block in bytes.
const BLOCK_SIZE: usize = 128;

const K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

const H0: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// A streaming SHA-512 computation.
#[derive(Clone, Debug)]
pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; BLOCK_SIZE],
    buffered: usize,
    /// Bytes fed so far; the padding stores it as a 128 bit bit count.
    length: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Sha512::new()
    }
}

impl Sha512 {
    /// Starts a new computation.
    pub fn new() -> Sha512 {
        Sha512 {
            state: H0,
            buffer: [0; BLOCK_SIZE],
            buffered: 0,
            length: 0,
        }
    }

    /// The compression function, one block at a time.
    fn compress(state: &mut [u64; 8], block: &[u8]) {
        let mut w = [0u64; 80];
        for (i, chunk) in block.chunks_exact(8).enumerate() {
            w[i] = u64::from_be_bytes(chunk.try_into().expect("an 8 byte chunk"));
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }

    /// Feeds data.
    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u128);
        if self.buffered > 0 {
            let take = data.len().min(BLOCK_SIZE - self.buffered);
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < BLOCK_SIZE {
                // Everything fit into the partial block.
                return;
            }
            let block = self.buffer;
            Self::compress(&mut self.state, &block);
            self.buffered = 0;
        }
        let mut blocks = data.chunks_exact(BLOCK_SIZE);
        for block in &mut blocks {
            Self::compress(&mut self.state, block);
        }
        let rest = blocks.remainder();
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    /// Finishes the computation and returns the digest.
    pub fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        let bits = self.length.wrapping_mul(8);
        // A 0x80 byte, zeros up to 16 bytes before a block boundary, then
        // the length in bits, big endian.
        let mut padding = [0u8; BLOCK_SIZE + 16];
        padding[0] = 0x80;
        let pad_len = if self.buffered < BLOCK_SIZE - 16 {
            BLOCK_SIZE - 16 - self.buffered
        } else {
            2 * BLOCK_SIZE - 16 - self.buffered
        };
        padding[pad_len..pad_len + 16].copy_from_slice(&bits.to_be_bytes());
        self.update(&padding[..pad_len + 16]);
        debug_assert_eq!(self.buffered, 0);
        let mut out = [0u8; DIGEST_SIZE];
        for (chunk, s) in out.chunks_exact_mut(8).zip(self.state) {
            chunk.copy_from_slice(&s.to_be_bytes());
        }
        out
    }
}

/// The digest of `data`.
pub fn digest(data: &[u8]) -> [u8; DIGEST_SIZE] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
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
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
            ),
            (
                &b"abc"[..],
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                &b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"[..],
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
            (
                &million[..],
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            ),
        ] {
            assert_eq!(to_hex(&digest(data)), expected, "{} bytes", data.len());
        }
    }

    /// Lengths around the end of a block, where the padding either fits
    /// behind the data or needs a block of its own; the answers are from
    /// coreutils' sha512sum and Python's hashlib.
    #[test]
    fn padding_boundaries() {
        for (len, expected) in [
            (
                111,
                "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2",
            ),
            (
                112,
                "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca",
            ),
            (
                113,
                "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d",
            ),
            (
                127,
                "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91bab50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502",
            ),
            (
                128,
                "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a243667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321",
            ),
            (
                129,
                "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab611565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429",
            ),
            (
                255,
                "d8b5a659e365f704ab114ae7079a8da24fb9997b3052a4a63b37d654652bad6fbdd2b52d737e20a9d5ac3c5831d6afdd32ff737a3dd95269d2793bc2aa850aab",
            ),
            (
                256,
                "6a9169eb662f136d87374070e8828b3e615a7eca32a89446e9225b02832709be095e635c824a2bb70213ba2ea0ababac0809827843992c851903b7ac0c136699",
            ),
            (
                257,
                "17fa1d01865805f9e657c5f5088754d19913eb418577b03cd040b99e5e1354fd31d0d7f24b5474c62b49e3271860859510909685c5811eba23b06e1e3369899d",
            ),
        ] {
            assert_eq!(to_hex(&digest(&vec![b'a'; len])), expected, "{} bytes", len);
        }
    }

    /// Feeding the data in pieces of any size, odd ones and ones that
    /// straddle block boundaries, gives the one-shot digest.
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        let expected = digest(&data);
        assert_eq!(
            to_hex(&expected),
            "9001a3f2cd24e4c46c751ab62e0c2f071ef9c319d5a90477d214905270b23d02e8ed527bd332f2dc5d45f7a0c5265f00a45afdf5120ba46709581e81818a57a2"
        );
        for chunk in [1usize, 7, 63, 64, 65, 111, 112, 113, 127, 128, 129, 200, 999] {
            let mut h = Sha512::new();
            for piece in data.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), expected, "chunk size {}", chunk);
        }
        // Pieces of varying size, including empty ones.
        let mut h = Sha512::new();
        let mut pos = 0;
        for (i, step) in [0usize, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377]
            .iter()
            .cycle()
            .enumerate()
        {
            let end = (pos + step).min(data.len());
            h.update(&data[pos..end]);
            pos = end;
            if pos == data.len() && i > 14 {
                break;
            }
        }
        assert_eq!(h.finalize(), expected);
    }

    #[test]
    fn hex() {
        assert_eq!(to_hex(&[0, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(to_hex(&digest(b"")).len(), 2 * DIGEST_SIZE);
    }
}
