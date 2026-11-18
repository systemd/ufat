// SPDX-License-Identifier: LGPL-2.1-or-later
//! Hex, the way a manifest spells hashes and the key of a signature.

use std::fmt;

/// The bits of one hex digit.
const DIGIT_BITS: u32 = 4;
/// The digits one byte takes.
const DIGITS_PER_BYTE: usize = 2;
/// The digits, as they are written.
const DIGITS: &[u8; 1 << DIGIT_BITS] = b"0123456789abcdef";
/// How many bytes are formatted at a time.
const CHUNK: usize = 32;

/// Bytes that print as lower case hex.
pub(crate) struct Hex<'a>(pub(crate) &'a [u8]);

impl Hex<'_> {
    /// The value of a hex digit of either case.
    fn value(digit: u8) -> Option<u8> {
        // The value of a digit is less than 16, so it fits.
        char::from(digit).to_digit(1 << DIGIT_BITS).map(|value| value as u8)
    }

    /// The values of the bytes of `text` as hex digits, one for each byte.
    /// A byte that is not a hex digit, whitespace too, is None.
    fn values(text: &str) -> impl Iterator<Item = Option<u8>> + '_ {
        text.bytes().map(Hex::value)
    }

    /// Decodes the `N` bytes `text` spells, two hex digits for each. Fewer
    /// or more digits, or anything that is not a digit, are None.
    pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        let mut values = Hex::values(text);
        for byte in &mut out {
            *byte = (values.next()?? << DIGIT_BITS) | values.next()??;
        }
        values.next().is_none().then_some(out)
    }
}

impl fmt::Display for Hex<'_> {
    /// The digits come from a table, a chunk of bytes at a time: writing
    /// each byte with `{:02x}` is twenty times slower.
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
