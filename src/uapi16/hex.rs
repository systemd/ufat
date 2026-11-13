// SPDX-License-Identifier: LGPL-2.1-or-later
//! Hex, the way a manifest spells hashes and the key of a signature.

use std::fmt;

/// The bits of one hex digit.
const DIGIT_BITS: u32 = 4;
/// The digits one byte takes.
const DIGITS_PER_BYTE: usize = 2;
/// The digits, as they are written.
const DIGITS: &[u8; 1 << DIGIT_BITS] = b"0123456789abcdef";
/// What [`VALUES`] has for a byte that is no hex digit. It is no value of
/// one.
const NO_DIGIT: u8 = u8::MAX;
/// The value of every byte as a hex digit of either case.
const VALUES: [u8; 1 << u8::BITS] = {
    let mut values = [NO_DIGIT; 1 << u8::BITS];
    let mut value = 0;
    while value < DIGITS.len() {
        let digit = DIGITS[value];
        values[digit as usize] = value as u8;
        values[digit.to_ascii_uppercase() as usize] = value as u8;
        value += 1;
    }
    values
};
/// How many bytes are formatted at a time.
const CHUNK: usize = 32;

/// Bytes that print as lower case hex.
pub(crate) struct Hex<'a>(pub(crate) &'a [u8]);

impl Hex<'_> {
    /// The value of a hex digit of either case.
    fn value(digit: u8) -> Option<u8> {
        let value = VALUES[usize::from(digit)];
        (value != NO_DIGIT).then_some(value)
    }

    /// The values of the hex digits of `text`. ASCII whitespace between
    /// them is passed over, as systemd passes over it. Anything else is
    /// None.
    fn values(text: &str) -> impl Iterator<Item = Option<u8>> + '_ {
        text.bytes().filter(|b| !b.is_ascii_whitespace()).map(Hex::value)
    }

    /// Decodes the bytes `text` spells, however many there are.
    // The reader of signature objects is what calls this.
    #[allow(dead_code)]
    pub(crate) fn decode(text: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(text.len() / DIGITS_PER_BYTE);
        let mut values = Hex::values(text);
        while let Some(high) = values.next() {
            out.push((high? << DIGIT_BITS) | values.next()??);
        }
        Some(out)
    }

    /// Decodes the `N` bytes `text` spells. More or fewer are None.
    pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        // A hash is written as its digits and nothing else, so that is
        // what is tried first.
        if text.len() == N * DIGITS_PER_BYTE {
            let mut all = 0;
            for (byte, digits) in out.iter_mut().zip(text.as_bytes().chunks_exact(DIGITS_PER_BYTE)) {
                let (high, low) = (VALUES[usize::from(digits[0])], VALUES[usize::from(digits[1])]);
                *byte = (high << DIGIT_BITS) | low;
                all |= high | low;
            }
            // Something that is no digit has bits no value of a digit has.
            if usize::from(all) < DIGITS.len() {
                return Some(out);
            }
        }
        let mut values = Hex::values(text);
        for byte in &mut out {
            *byte = (values.next()?? << DIGIT_BITS) | values.next()??;
        }
        values.next().is_none().then_some(out)
    }
}

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = [0u8; CHUNK * DIGITS_PER_BYTE];
        for chunk in self.0.chunks(CHUNK) {
            for (digits, byte) in text.chunks_exact_mut(DIGITS_PER_BYTE).zip(chunk) {
                digits[0] = DIGITS[usize::from(byte >> DIGIT_BITS)];
                digits[1] = DIGITS[usize::from(*byte) % DIGITS.len()];
            }
            let text = &text[..chunk.len() * DIGITS_PER_BYTE];
            f.write_str(std::str::from_utf8(text).expect("ASCII"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        assert_eq!(Hex::decode(""), Some(vec![]));
        assert_eq!(Hex::decode("00ff"), Some(vec![0, 0xff]));
        assert_eq!(Hex::decode("0aF0 1b\n2C\t\r\x0c"), Some(vec![0x0a, 0xf0, 0x1b, 0x2c]));
        assert_eq!(Hex::decode(" 0 1 2 3 "), Some(vec![0x01, 0x23]));
        for text in ["0", "012", "0g", "xyz", "0x10", "1\u{b}0", "\u{e9}\u{e9}", "+1", "-1"] {
            assert_eq!(Hex::decode(text), None, "{:?}", text);
        }
        assert_eq!(Hex::decode_array::<2>("00ff"), Some([0, 0xff]));
        assert_eq!(Hex::decode_array::<2>("00 FF"), Some([0, 0xff]));
        assert_eq!(Hex::decode_array::<2>("00f"), None);
        assert_eq!(Hex::decode_array::<2>("00"), None);
        assert_eq!(Hex::decode_array::<2>("00ff00"), None);
        assert_eq!(Hex::decode_array::<2>("00fg"), None);
        assert_eq!(Hex::decode_array::<0>(""), Some([]));
        assert_eq!(Hex::decode_array::<0>(" "), Some([]));
        assert_eq!(Hex::decode_array::<0>("00"), None);
        // As many characters as digits are expected, and not all of them
        // digits.
        assert_eq!(Hex::decode_array::<2>("0 ff"), None);
        assert_eq!(Hex::decode_array::<2>(" 0ff"), None);
        assert_eq!(Hex::decode_array::<2>("00f "), None);
        assert_eq!(Hex::decode_array::<2>("00\u{e9}"), None);
        assert_eq!(Hex::decode_array::<3>("0 1 23"), None);
        assert_eq!(Hex::decode_array::<3>("0 1 2 3 4 5"), Some([0x01, 0x23, 0x45]));
    }

    #[test]
    fn digits() {
        // Every byte is a digit or it is not, and the two ways to decode
        // agree on it.
        for byte in 0..=u8::MAX {
            let value = char::from(byte).to_digit(1 << DIGIT_BITS).map(|value| value as u8);
            assert_eq!(Hex::value(byte), value, "{:#x}", byte);
            let Ok(text) = String::from_utf8(vec![b'5', byte]) else {
                continue;
            };
            let expected = value.map(|value| [0x50 | value]);
            assert_eq!(Hex::decode_array::<1>(&text), expected, "{:?}", text);
            assert_eq!(Hex::decode(&text), expected.map(Vec::from), "{:?}", text);
            let text: String = text.chars().rev().collect();
            let expected = value.map(|value| [(value << DIGIT_BITS) | 0x5]);
            assert_eq!(Hex::decode_array::<1>(&text), expected, "{:?}", text);
        }
    }

    #[test]
    fn prints() {
        assert_eq!(Hex(&[]).to_string(), "");
        assert_eq!(Hex(&[0, 0x0f, 0xf0, 0xff]).to_string(), "000ff0ff");
        // More than is formatted at a time.
        let bytes: Vec<u8> = (0..=255).collect();
        let text = Hex(&bytes).to_string();
        assert_eq!(text.len(), 512);
        assert!(text.starts_with("000102") && text.ends_with("fdfeff"));
        assert_eq!(Hex::decode(&text), Some(bytes.clone()));
        assert_eq!(Hex::decode(&text.to_uppercase()), Some(bytes));
    }
}
