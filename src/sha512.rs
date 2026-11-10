// SPDX-License-Identifier: LGPL-2.1-or-later
//! SHA-512 (FIPS 180-4), for the hash of a whole image a caller may ask
//! for. The hashes inside manifests stay SHA-256, see [`crate::sha256`].
//! The sha2 crate computes it.

use sha2::Digest;

pub use crate::sha256::to_hex;

/// Size of a digest in bytes.
pub const DIGEST_SIZE: usize = 64;

/// A streaming SHA-512 computation.
#[derive(Clone, Debug, Default)]
pub struct Sha512(sha2::Sha512);

impl Sha512 {
    /// Starts a new computation.
    pub fn new() -> Sha512 {
        Sha512(sha2::Sha512::new())
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
    sha2::Sha512::digest(data).into()
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
