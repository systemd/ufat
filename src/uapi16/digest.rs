// SPDX-License-Identifier: LGPL-2.1-or-later
//! The hashes a manifest gives for the contents of files.

use std::fmt;
use std::io;
use std::str::FromStr;

use sha2::Digest as _;

use crate::hex::Hex;

/// A hash a manifest gives for contents.
///
/// The specification defines one algorithm, SHA-256, which is [`Sha256`].
/// It says that another algorithm gets fields of its own next to the
/// SHA-256 ones. Such an algorithm is one more type with this trait: the
/// rules that tie a hash to a size and the check of contents against a
/// hash are written for any `Digest`.
pub trait Digest: Copy + Eq {
    /// The hash of no data. Contents of size 0 have this hash, and only
    /// they do.
    const EMPTY: Self;

    /// Computes the hash of data that comes in pieces. What is written to
    /// it is the data, and it turns into the hash of all of it.
    type Hasher: Default + io::Write + Into<Self>;
}

/// A SHA-256 hash, as the `sha256` field of a file object and the
/// `encodedSha256` and `originalSha256` fields of a contents object have
/// it.
///
/// It prints as 64 lower case hex digits. It parses from hex digits of
/// either case, with whitespace between them passed over.
///
/// ```
/// use uapi16::{Digest, Sha256};
///
/// let hash = Sha256::of(b"hello");
/// assert_eq!(
///     hash.to_string(),
///     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
/// );
/// assert_eq!(hash.to_string().parse(), Ok(hash));
/// assert_eq!(Sha256::of(b""), Sha256::EMPTY);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256([u8; Sha256::SIZE]);

/// A string that is not the hex digits of a hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDigest(());

impl fmt::Display for InvalidDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not the hex digits of a hash")
    }
}

impl std::error::Error for InvalidDigest {}

impl Sha256 {
    /// The size of the hash in bytes.
    pub const SIZE: usize = 32;

    /// The hash of `data`.
    pub fn of(data: &[u8]) -> Sha256 {
        Sha256(sha2::Sha256::digest(data).into())
    }

    /// The bytes of the hash.
    pub fn as_bytes(&self) -> &[u8; Sha256::SIZE] {
        &self.0
    }
}

impl Digest for Sha256 {
    const EMPTY: Sha256 = Sha256([
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae,
        0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    ]);

    type Hasher = Sha256Hasher;
}

impl From<[u8; Sha256::SIZE]> for Sha256 {
    fn from(bytes: [u8; Sha256::SIZE]) -> Sha256 {
        Sha256(bytes)
    }
}

impl From<Sha256> for [u8; Sha256::SIZE] {
    fn from(hash: Sha256) -> [u8; Sha256::SIZE] {
        hash.0
    }
}

impl AsRef<[u8]> for Sha256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Hex(&self.0).fmt(f)
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({})", self)
    }
}

impl FromStr for Sha256 {
    type Err = InvalidDigest;

    fn from_str(text: &str) -> Result<Sha256, InvalidDigest> {
        Hex::decode_array(text).map(Sha256).ok_or(InvalidDigest(()))
    }
}

/// Computes the [`Sha256`] of data that comes in pieces, such as the
/// contents of a file a manifest is written for.
///
/// ```
/// use std::io::Write;
/// use uapi16::{Sha256, Sha256Hasher};
///
/// let mut hasher = Sha256Hasher::default();
/// hasher.update(b"hel");
/// hasher.write_all(b"lo")?;
/// assert_eq!(hasher.finish(), Sha256::of(b"hello"));
/// # Ok::<(), std::io::Error>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct Sha256Hasher(sha2::Sha256);

impl Sha256Hasher {
    /// Takes more of the data.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The hash of all the data.
    pub fn finish(self) -> Sha256 {
        Sha256(self.0.finalize().into())
    }
}

impl From<Sha256Hasher> for Sha256 {
    fn from(hasher: Sha256Hasher) -> Sha256 {
        hasher.finish()
    }
}

impl io::Write for Sha256Hasher {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.update(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The FIPS 180-4 vectors.
    #[test]
    fn vectors() {
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
        ] {
            assert_eq!(Sha256::of(data).to_string(), expected);
            let mut hasher = Sha256Hasher::default();
            for piece in data.chunks(7) {
                hasher.update(piece);
            }
            assert_eq!(hasher.finish(), Sha256::of(data));
        }
        assert_eq!(Sha256::of(b""), Sha256::EMPTY);
    }

    #[test]
    fn text() {
        let hash = Sha256::of(b"hello");
        let hex = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hash.to_string(), hex);
        assert_eq!(format!("{:?}", hash), format!("Sha256({})", hex));
        assert_eq!(hex.parse(), Ok(hash));
        assert_eq!(hex.to_uppercase().parse(), Ok(hash));
        // systemd takes whitespace between the digits.
        let spaced = "2cf2 4dba 5fb0 a30e 26e8 3b2a c5b9 e29e 1b16 1e5c 1fa7 425e 7304 3362 938b 9824";
        assert_eq!(spaced.parse(), Ok(hash));
        for text in [
            "",
            "00",
            &hex[1..],
            &format!("{}0", hex),
            &format!("{}00", hex),
            &"zz".repeat(32),
        ] {
            assert!(text.parse::<Sha256>().is_err(), "{:?}", text);
        }
        assert_eq!(Sha256::from(*hash.as_bytes()), hash);
        assert_eq!(<[u8; 32]>::from(hash), *hash.as_bytes());
        assert_eq!(hash.as_ref(), &hash.as_bytes()[..]);
    }
}
