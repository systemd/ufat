// SPDX-License-Identifier: LGPL-2.1-or-later
//! Base64, the way a manifest carries literal contents, the values of
//! extended attributes and the data of a signature.

use std::fmt;

/// The digits of one group, and the bytes a group holds.
const GROUP_DIGITS: usize = 4;
const GROUP_BYTES: usize = 3;
/// The bits of one digit.
const DIGIT_BITS: u32 = 6;
/// The digits of the standard alphabet.
const ALPHABET: &[u8; 1 << DIGIT_BITS] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// The values of the last two digits. They have other spellings in the
/// URL-safe alphabet.
const SIXTY_TWO: u8 = 62;
const SIXTY_THREE: u8 = 63;
/// Where the lower case letters and the decimal digits start in the
/// alphabet.
const FIRST_LOWER: u8 = 26;
const FIRST_DECIMAL: u8 = 52;
/// What fills up the last group.
const PAD: u8 = b'=';
/// The most padding a group has: its first two digits are never padding.
const MAX_PADDING: usize = 2;
/// The whitespace systemd passes over wherever it is.
const WHITESPACE: &[u8] = b" \t\n\r";
/// How many groups are formatted at a time.
const CHUNK_GROUPS: usize = 16;

/// Bytes that print as Base64 in the standard alphabet with padding, the
/// way systemd writes them.
pub(crate) struct Base64<'a>(pub(crate) &'a [u8]);

impl Base64<'_> {
    /// The value of a digit of the standard or of the URL-safe alphabet.
    fn value(digit: u8) -> Option<u8> {
        match digit {
            b'A'..=b'Z' => Some(digit - b'A'),
            b'a'..=b'z' => Some(digit - b'a' + FIRST_LOWER),
            b'0'..=b'9' => Some(digit - b'0' + FIRST_DECIMAL),
            b'+' | b'-' => Some(SIXTY_TWO),
            b'/' | b'_' => Some(SIXTY_THREE),
            _ => None,
        }
    }

    /// Decodes Base64 exactly as systemd's unbase64mem() does:
    ///
    /// - The digits are those of the standard and of the URL-safe
    ///   alphabet, in any mix.
    /// - Space, tab, newline and carriage return are skipped wherever
    ///   they are.
    /// - The digits come in groups of four. The last group can end in "="
    ///   or "==", and then the bits the padding leaves over have to be
    ///   zero. Nothing but whitespace may follow the padding.
    pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() / GROUP_DIGITS * GROUP_BYTES);
        // The digits of the group so far, how many they are and how many
        // of them are padding.
        let mut group = 0u32;
        let mut digits = 0;
        let mut padding = 0;
        let mut ended = false;
        for &b in text.as_bytes() {
            if WHITESPACE.contains(&b) {
                continue;
            }
            if ended {
                return None;
            }
            let value = if b == PAD {
                padding += 1;
                0
            } else if padding > 0 {
                return None;
            } else {
                Base64::value(b)?
            };
            group = (group << DIGIT_BITS) | u32::from(value);
            digits += 1;
            if digits < GROUP_DIGITS {
                continue;
            }
            if padding > MAX_PADDING {
                return None;
            }
            // The three bytes of the group are the low ones. Those the
            // padding stands for have to be zero.
            let bytes = group.to_be_bytes();
            let (kept, rest) = bytes[size_of::<u32>() - GROUP_BYTES..].split_at(GROUP_BYTES - padding);
            if rest.iter().any(|&b| b != 0) {
                return None;
            }
            out.extend_from_slice(kept);
            ended = padding > 0;
            group = 0;
            digits = 0;
            padding = 0;
        }
        (digits == 0).then_some(out)
    }
}

impl fmt::Display for Base64<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = [PAD; CHUNK_GROUPS * GROUP_DIGITS];
        for chunk in self.0.chunks(CHUNK_GROUPS * GROUP_BYTES) {
            let mut len = 0;
            for bytes in chunk.chunks(GROUP_BYTES) {
                let mut group = [0u8; size_of::<u32>()];
                group[size_of::<u32>() - GROUP_BYTES..][..bytes.len()].copy_from_slice(bytes);
                let group = u32::from_be_bytes(group);
                // A group of n bytes has n + 1 digits, padding fills the rest.
                for digit in 0..GROUP_DIGITS {
                    let shift = DIGIT_BITS * (GROUP_DIGITS - 1 - digit) as u32;
                    text[len] = if digit <= bytes.len() {
                        ALPHABET[(group >> shift) as usize % ALPHABET.len()]
                    } else {
                        PAD
                    };
                    len += 1;
                }
            }
            f.write_str(std::str::from_utf8(&text[..len]).expect("ASCII"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test vectors of systemd's unbase64mem() in
    /// src/test/test-hexdecoct.c: what it decodes and what it refuses.
    #[test]
    fn decodes() {
        for (text, data) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            (" ", ""),
            (" \n\r ", ""),
            ("    Zg\n==       ", "f"),
            (" Zm 8=\r", "fo"),
            ("  Zm9\n\r\r\nv   ", "foo"),
            (" Z m9vYg==\n\r", "foob"),
            (" Zm 9vYmE=   ", "fooba"),
            ("   Z m9v    YmFy   ", "foobar"),
            ("aGVs\nbG8 =", "hello"),
        ] {
            assert_eq!(Base64::decode(text).as_deref(), Some(data.as_bytes()), "{:?}", text);
        }
        for text in ["A", "A====", "AAB==", " A A A B = ", " Z m 8 = q u u x "] {
            assert_eq!(Base64::decode(text), None, "{:?}", text);
        }
    }

    /// Both alphabets, in any mix, with the values systemd's unbase64char()
    /// gives the digits, and its test of the two spellings of the same data.
    #[test]
    fn alphabets() {
        assert_eq!(Base64::decode("AZaz").unwrap(), [1, 150, 179]);
        assert_eq!(Base64::decode("09+/").unwrap(), [211, 223, 191]);
        assert_eq!(Base64::decode("09-_").unwrap(), [211, 223, 191]);
        assert_eq!(Base64::decode("_-8=").unwrap(), [0xff, 0xef]);
        let plaintext: &[u8] = &[
            0xcc, 0xa1, 0x72, 0x22, 0xae, 0xda, 0x66, 0x7e, 0x04, 0xa6, 0xe0, 0x82, 0x9a, 0x97, 0x05, 0xf6, 0x33, 0xe0,
            0x0f, 0xc2, 0x45, 0x13, 0x58, 0x3f, 0xc5, 0xf4, 0xf4, 0x31, 0xab, 0x3c, 0x5f, 0x83, 0x34, 0x5b, 0x27, 0x32,
            0x8a, 0x04, 0x6c, 0x43, 0x82, 0x07, 0xe3, 0x2c, 0xac, 0xb9, 0xfb, 0xac, 0xd0, 0x03, 0x91, 0x42, 0xcb, 0xa4,
            0xde, 0x87, 0x86, 0x85, 0x10, 0xbb, 0xb7, 0x5b, 0x4b, 0xc8, 0xa0, 0xf4, 0x22, 0x1d, 0x15, 0x71, 0x87, 0x9d,
            0xbf, 0x9f, 0xa9, 0xf1, 0xee, 0xa2, 0xb6, 0xaa, 0xc8, 0xc3, 0x37, 0x9c, 0xbb, 0xdf, 0x3e, 0xac, 0xdc, 0x94,
            0x54, 0x38, 0x56, 0x07, 0x34, 0xb4, 0x3c, 0xcc, 0x31, 0x13,
        ];
        let standard = "zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g/xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5+p8e6itqrIwzecu98+rNyUVDhWBzS0PMwxEw==";
        let url_safe = "zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g_xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5-p8e6itqrIwzecu98-rNyUVDhWBzS0PMwxEw==";
        for text in [standard, url_safe] {
            assert_eq!(Base64::decode(text).as_deref(), Some(plaintext));
        }
        // What is written is the standard alphabet.
        assert_eq!(Base64(plaintext).to_string(), standard);
    }

    /// What systemd refuses: a last group without its padding, incomplete
    /// padding, padding with nothing to pad, padding that leaves bits set,
    /// anything after the padding, and any character that is not a digit,
    /// "=" or one of space, tab, newline and carriage return.
    #[test]
    fn refuses() {
        for text in [
            "Zg",
            "Zm8",
            "aGVsbG8",
            "Zg=",
            "Zm9v=",
            "Zm9v==",
            "=",
            "==",
            " = ",
            "Zh==",
            "Zm9=",
            "Zg==Zg==",
            "Zg== x",
            "Z=g=",
            "====",
            "Zm9\x0cv",
            "Zm9\x0bv",
            "!!!!",
            "Zm9v\0",
            "=AAA",
            "A=AA",
            "AA=A",
            "Zg===",
            "Zm9v\u{e9}",
        ] {
            assert_eq!(Base64::decode(text), None, "{:?}", text);
        }
    }

    #[test]
    fn prints() {
        for (data, text) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(Base64(data.as_bytes()).to_string(), text);
        }
        assert_eq!(Base64(&[0xfb, 0xff, 0xbf]).to_string(), "+/+/");
    }

    /// Data of every length up to 300 bytes comes back from what is
    /// printed for it, also when that is broken into lines of any width,
    /// the way systemd's base64mem_full() writes it.
    #[test]
    fn round_trip() {
        let mut x = 1u32;
        for len in 0..300usize {
            let data: Vec<u8> = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    (x >> 16) as u8
                })
                .collect();
            let text = Base64(&data).to_string();
            assert_eq!(text.len(), len.div_ceil(GROUP_BYTES) * GROUP_DIGITS);
            assert_eq!(Base64::decode(&text).as_deref(), Some(&data[..]), "{} bytes", len);
            let mut lines = Vec::new();
            for line in text.as_bytes().chunks(1 + len % 77) {
                lines.extend_from_slice(line);
                lines.push(b'\n');
            }
            let decoded = Base64::decode(std::str::from_utf8(&lines).unwrap());
            assert_eq!(decoded.as_deref(), Some(&data[..]), "{} bytes", len);
        }
    }
}
