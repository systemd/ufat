// SPDX-License-Identifier: LGPL-2.1-or-later
//! File names: long names, 8.3 aliases, case folding and long name entries.
//!
//! The rules follow what mtools and Windows NT do, so directories populated
//! by this crate look like directories populated by mcopy:
//!
//! - A name that fits 8.3 without loss and whose base and extension are each
//!   entirely upper or entirely lower case is stored as a short entry only.
//!   The NT case flags record which parts are lower case.
//! - Any other name gets a set of long name entries. If the 8.3 alias is
//!   lossy (characters dropped, replaced or truncated) it also gets a numeric
//!   tail, "~1" upwards, chosen so that it is unique in the directory.
//!
//! Short names are plain ASCII. Characters outside ASCII are replaced by
//! '_' in the alias, which makes it lossy, so the real name always survives
//! in the long name entries.
//!
//! Names are compared without regard to case. A character folds to its
//! upper case form when that form is a single character and is left alone
//! otherwise: ß, whose upper case is SS, and the Greek letters with
//! ypogegrammeni, whose upper case adds a capital iota, stay themselves.
//! The table is name/fold_table.rs, generated from UnicodeData.txt and
//! SpecialCasing.txt of Unicode 16.0.0. It never changes. A newer Unicode
//! version would make some names that differ today one name, and the same
//! tree would give a different image. Case pairs that Unicode added later
//! are not folded. HACKING.md says how to check the table.

use crate::bytes::le16;
use crate::dirent::{
    self, RawDirEntry, ATTR_LONG_NAME, CASE_LOWER_BASE, CASE_LOWER_EXT, DIR_ENTRY_SIZE, ENTRY_DELETED, ENTRY_E5_ESCAPE,
    ENTRY_END, NAME_BASE, NAME_EXT, SHORT_NAME_SIZE,
};
use crate::errno::*;
use crate::Result;
use crate::{Detail, NameProblem};

#[path = "name/fold_table.rs"]
mod fold_table;

/// The Unicode version of the case folding table. It never changes, so that
/// every build and every version of ufat tells the same names apart.
pub const FOLD_UNICODE_VERSION: (u8, u8, u8) = fold_table::UNICODE_VERSION;
/// Longest long name, in UTF-16 units.
pub const MAX_LONG_NAME: usize = 255;
/// UTF-16 units stored per long name entry.
pub const LFN_UNITS_PER_ENTRY: usize = 13;
/// Flag in the sequence byte of the last (physically first) long name entry.
pub const LFN_LAST_ENTRY: u8 = 0x40;
/// Largest sequence number of a long name entry.
pub const LFN_MAX_ENTRIES: usize = 20;
/// The unit that ends a long name that does not fill its last entry.
pub const LFN_TERMINATOR: u16 = 0x0000;
/// The unit that fills the last entry of a long name after its terminator.
pub const LFN_PADDING: u16 = 0xFFFF;

/// Characters that may not appear in a long name, besides control characters.
pub(crate) const LONG_NAME_INVALID: &[char] = &['"', '*', '/', ':', '<', '>', '?', '\\', '|'];

/// Device names DOS and Windows reserve. An alias that spells one of them
/// gets a numeric tail.
const RESERVED_NAMES: &[&[u8]] = &[
    b"CON", b"PRN", b"AUX", b"NUL", b"COM1", b"COM2", b"COM3", b"COM4", b"COM5", b"COM6", b"COM7", b"COM8", b"COM9",
    b"LPT1", b"LPT2", b"LPT3", b"LPT4", b"LPT5", b"LPT6", b"LPT7", b"LPT8", b"LPT9",
];

/// Byte offsets of the 13 UTF-16 units inside a long name entry: the units
/// of its three name fields, in order.
const LFN_UNIT_OFFSETS: [usize; LFN_UNITS_PER_ENTRY] = {
    let fields = [
        dirent::lfn_field::NAME1,
        dirent::lfn_field::NAME2,
        dirent::lfn_field::NAME3,
    ];
    let mut offsets = [0; LFN_UNITS_PER_ENTRY];
    let mut n = 0;
    let mut f = 0;
    while f < fields.len() {
        let mut off = fields[f].start;
        while off < fields[f].end {
            offsets[n] = off;
            n += 1;
            off += size_of::<u16>();
        }
        f += 1;
    }
    assert!(n == LFN_UNITS_PER_ENTRY);
    offsets
};

/// A validated long file name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongName {
    text: String,
    units: Vec<u16>,
}

impl LongName {
    /// Validates `name` as a single path component. Names must be 1 to 255
    /// UTF-16 units long, must not contain control characters or any of
    /// `" * / : < > ? \ |`, must not start with a space and must not end
    /// with a space or a dot, and must not be "." or "..".
    pub fn new(name: &str) -> Result<LongName> {
        let bad = |problem: NameProblem| Detail::Name {
            name: name.to_string(),
            problem,
        };
        if name.is_empty() {
            bail!(EINVAL, bad(NameProblem::Empty), "empty file name");
        }
        if name == "." || name == ".." {
            bail!(
                EINVAL,
                bad(NameProblem::DotComponent),
                "'{}' is not a valid file name",
                name
            );
        }
        for c in name.chars() {
            if c.is_ascii_control() {
                bail!(
                    EINVAL,
                    bad(NameProblem::InvalidCharacter),
                    "file name '{}' contains a control character",
                    name.escape_debug()
                );
            }
            // U+FFFF is the padding unit of long name entries and would end
            // the name early when read back.
            if c == '\u{ffff}' {
                bail!(
                    EINVAL,
                    bad(NameProblem::InvalidCharacter),
                    "file name '{}' contains U+FFFF",
                    name.escape_debug()
                );
            }
            if LONG_NAME_INVALID.contains(&c) {
                bail!(
                    EINVAL,
                    bad(NameProblem::InvalidCharacter),
                    "file name '{}' contains the invalid character '{}'",
                    name,
                    c
                );
            }
        }
        if name.starts_with(' ') {
            bail!(
                EINVAL,
                bad(NameProblem::LeadingSpace),
                "file name '{}' starts with a space",
                name
            );
        }
        if name.ends_with(' ') || name.ends_with('.') {
            bail!(
                EINVAL,
                bad(NameProblem::TrailingSpaceOrDot),
                "file name '{}' ends with a space or a dot",
                name
            );
        }
        // A name has no more UTF-16 units than UTF-8 bytes, so this is the
        // only allocation. collect() would size the vector from the
        // iterator's lower bound, a third of that, and reallocate as it
        // grows.
        let mut units = Vec::with_capacity(name.len());
        units.extend(name.encode_utf16());
        if units.len() > MAX_LONG_NAME {
            bail!(
                ENAMETOOLONG,
                bad(NameProblem::TooLong),
                "file name '{}' is longer than {} UTF-16 units",
                name,
                MAX_LONG_NAME
            );
        }
        Ok(LongName {
            text: name.to_string(),
            units,
        })
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The name in UTF-16.
    pub fn units(&self) -> &[u16] {
        &self.units
    }

    /// Number of long name entries needed to store the name.
    pub fn entry_count(&self) -> usize {
        self.units.len().div_ceil(LFN_UNITS_PER_ENTRY)
    }

    /// The name folded for case-insensitive comparison.
    pub fn folded(&self) -> Vec<u16> {
        fold_utf16(&self.units)
    }
}

/// Upper-cases a character if the pinned table has a single character upper
/// case form for it, otherwise leaves it alone. For ASCII that is
/// `to_ascii_uppercase`, which needs no table.
fn fold_char(c: char) -> char {
    if c.is_ascii() {
        return c.to_ascii_uppercase();
    }
    match fold_table::PAIRS.binary_search_by_key(&c, |&(lower, _)| lower) {
        Ok(i) => fold_table::PAIRS[i].1,
        Err(_) => c,
    }
}

/// Case folds UTF-16 text for comparison. Unpaired surrogates fold to
/// themselves.
pub fn fold_utf16(units: &[u16]) -> Vec<u16> {
    // Names on an ESP are almost all ASCII: no decoding and no table then.
    if units.iter().all(|&u| u < 0x80) {
        return units
            .iter()
            .map(|&u| u16::from((u as u8).to_ascii_uppercase()))
            .collect();
    }
    let mut out = Vec::with_capacity(units.len());
    for r in char::decode_utf16(units.iter().copied()) {
        match r {
            Ok(c) => {
                let mut buf = [0u16; 2];
                out.extend_from_slice(fold_char(c).encode_utf16(&mut buf));
            }
            Err(e) => out.push(e.unpaired_surrogate()),
        }
    }
    out
}

/// Case folds a string for comparison with folded UTF-16 text.
pub fn fold_str(s: &str) -> Vec<u16> {
    if s.is_ascii() {
        return s.bytes().map(|b| u16::from(b.to_ascii_uppercase())).collect();
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        let mut buf = [0u16; 2];
        out.extend_from_slice(fold_char(c).encode_utf16(&mut buf));
    }
    out
}

/// Whether `b` may appear in a short name.
pub(crate) fn valid_short_char(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'()-@^_`{}~".contains(&b)
}

/// The case of the letters in one part of an alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
    NoLetters,
    Lower,
    Upper,
    Mixed,
}

impl Case {
    fn add(self, lower: bool) -> Case {
        match (self, lower) {
            (Case::NoLetters | Case::Lower, true) => Case::Lower,
            (Case::NoLetters | Case::Upper, false) => Case::Upper,
            _ => Case::Mixed,
        }
    }
}

/// Converts one part (base or extension) of a name into at most `max`
/// alias bytes. Returns the bytes, whether information was lost and the
/// case of the letters seen.
fn convert_part(part: &str, max: usize) -> (Vec<u8>, bool, Case) {
    let mut out = Vec::with_capacity(max);
    let mut lossy = false;
    let mut case = Case::NoLetters;
    for c in part.chars() {
        if c == ' ' || c == '.' {
            lossy = true;
            continue;
        }
        if out.len() == max {
            lossy = true;
            break;
        }
        if c.is_ascii_alphabetic() {
            case = case.add(c.is_ascii_lowercase());
            out.push(c.to_ascii_uppercase() as u8);
        } else if c.is_ascii() && valid_short_char(c as u8) {
            out.push(c as u8);
        } else {
            lossy = true;
            out.push(b'_');
        }
    }
    (out, lossy, case)
}

/// The 8.3 alias derived from a long name, before any numeric tail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Alias {
    /// The alias, 8 base bytes and 3 extension bytes, space padded.
    pub name: [u8; SHORT_NAME_SIZE],
    /// Bytes used by the base part.
    pub base_len: usize,
    /// The alias lost information; it needs a numeric tail.
    pub lossy: bool,
    /// The name needs long name entries: it is lossy or has mixed case.
    pub needs_long_name: bool,
    /// NT case flags to store when no long name entries are written.
    pub case_flags: u8,
}

impl Alias {
    /// Derives the alias of a long name.
    pub fn of(name: &LongName) -> Alias {
        let text = name.as_str();
        let trimmed = text.trim_start_matches(['.', ' ']);
        let mut lossy = trimmed.len() != text.len();
        let (base, ext) = match trimmed.rfind('.') {
            Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
            None => (trimmed, ""),
        };
        let (base_bytes, base_lossy, base_case) = convert_part(base, NAME_BASE.len());
        let (ext_bytes, ext_lossy, ext_case) = convert_part(ext, NAME_EXT.len());
        lossy |= base_lossy || ext_lossy;
        if base_bytes.is_empty() || RESERVED_NAMES.contains(&base_bytes.as_slice()) {
            lossy = true;
        }
        let mixed = base_case == Case::Mixed || ext_case == Case::Mixed;
        let needs_long_name = lossy || mixed;
        let mut case_flags = 0;
        if !needs_long_name {
            if base_case == Case::Lower {
                case_flags |= CASE_LOWER_BASE;
            }
            if ext_case == Case::Lower {
                case_flags |= CASE_LOWER_EXT;
            }
        }
        let mut alias = [b' '; SHORT_NAME_SIZE];
        alias[..base_bytes.len()].copy_from_slice(&base_bytes);
        alias[NAME_EXT.start..NAME_EXT.start + ext_bytes.len()].copy_from_slice(&ext_bytes);
        Alias {
            name: alias,
            base_len: base_bytes.len(),
            lossy,
            needs_long_name,
            case_flags,
        }
    }

    /// Largest numeric tail: six digits fit after a one character base.
    pub const MAX_TAIL: u32 = 999_999;

    /// The alias with the numeric tail `~n` appended, keeping as much of the
    /// base as fits, the way mtools and Windows do it. `n` is clamped to
    /// [`Alias::MAX_TAIL`].
    pub fn with_tail(&self, n: u32) -> [u8; SHORT_NAME_SIZE] {
        // "~" and up to six decimal digits.
        let mut n = n.clamp(1, Alias::MAX_TAIL);
        let mut digits = [0u8; 6];
        let mut count = 0;
        while n > 0 {
            digits[count] = b'0' + (n % 10) as u8;
            n /= 10;
            count += 1;
        }
        let mut tail = [b'~'; 7];
        for i in 0..count {
            tail[1 + i] = digits[count - 1 - i];
        }
        let tail = &tail[..1 + count];
        let keep = self.base_len.min(NAME_BASE.len() - tail.len());
        let mut out = [b' '; SHORT_NAME_SIZE];
        out[..keep].copy_from_slice(&self.name[..keep]);
        out[keep..keep + tail.len()].copy_from_slice(tail);
        out[NAME_EXT].copy_from_slice(&self.name[NAME_EXT]);
        out
    }
}

/// Builds the long name entries for `name`, in the order they are stored:
/// the entry with the highest sequence number first, the one holding the
/// first 13 characters last, immediately before the short entry.
pub fn long_name_entries(name: &LongName, checksum: u8) -> Vec<[u8; DIR_ENTRY_SIZE]> {
    let units = name.units();
    let count = name.entry_count();
    let mut out = Vec::with_capacity(count);
    for seq in (1..=count).rev() {
        let mut e = [0u8; DIR_ENTRY_SIZE];
        e[dirent::lfn_field::ORDER] = seq as u8 | if seq == count { LFN_LAST_ENTRY } else { 0 };
        e[dirent::lfn_field::ATTR] = ATTR_LONG_NAME;
        e[dirent::lfn_field::CHECKSUM] = checksum;
        let start = (seq - 1) * LFN_UNITS_PER_ENTRY;
        for (i, &off) in LFN_UNIT_OFFSETS.iter().enumerate() {
            let pos = start + i;
            // The name ends with a terminator and is padded after it. A
            // name that fills its entries has neither.
            let unit = match units.get(pos) {
                Some(&u) => u,
                None if pos == units.len() => LFN_TERMINATOR,
                None => LFN_PADDING,
            };
            e[off..off + size_of::<u16>()].copy_from_slice(&unit.to_le_bytes());
        }
        out.push(e);
    }
    out
}

/// A decoded long name entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LongNameEntry {
    /// Sequence number, 1 to 20.
    pub sequence: u8,
    /// Whether this is the last entry of the set (first on disk).
    pub last: bool,
    /// Checksum of the short name the set belongs to.
    pub checksum: u8,
    /// The 13 UTF-16 units stored in this entry, padding included.
    pub units: [u16; LFN_UNITS_PER_ENTRY],
}

/// Decodes a long name entry. Returns None if the slot is not a well formed
/// long name entry.
pub fn parse_long_name_entry(raw: &[u8; DIR_ENTRY_SIZE]) -> Option<LongNameEntry> {
    let order = raw[dirent::lfn_field::ORDER];
    if raw[dirent::lfn_field::ATTR] != ATTR_LONG_NAME || order == ENTRY_DELETED || order == ENTRY_END {
        return None;
    }
    let sequence = order & !LFN_LAST_ENTRY;
    if sequence == 0 || sequence as usize > LFN_MAX_ENTRIES {
        return None;
    }
    let units = LFN_UNIT_OFFSETS.map(|off| le16(raw, off));
    Some(LongNameEntry {
        sequence,
        last: order & LFN_LAST_ENTRY != 0,
        checksum: raw[dirent::lfn_field::CHECKSUM],
        units,
    })
}

/// Joins the units of a complete set of long name entries, given in
/// sequence order (1 first), into the stored name. Reading stops at the
/// first [`LFN_TERMINATOR`]. [`LFN_PADDING`] without a terminator ends the
/// name as well, where Linux would decode it as U+FFFF. Nothing this crate
/// writes has such a name, see [`LongName::new`].
pub fn join_long_name(entries: &[LongNameEntry]) -> Vec<u16> {
    entries
        .iter()
        .flat_map(|e| e.units)
        .take_while(|&u| u != LFN_TERMINATOR && u != LFN_PADDING)
        .collect()
}

/// The name of a short entry as text, honouring the NT case flags and the
/// 0x05 escape. Bytes outside ASCII are mapped as Latin-1; their code page
/// is unknown.
pub fn short_name_to_string(entry: &RawDirEntry) -> String {
    let mut name = entry.name;
    if name[0] == ENTRY_E5_ESCAPE {
        name[0] = ENTRY_DELETED;
    }
    let part = |bytes: &[u8], lower: bool| -> String {
        let end = bytes.iter().rposition(|&b| b != b' ').map_or(0, |p| p + 1);
        bytes[..end]
            .iter()
            .map(|&b| {
                let c = b as char;
                if lower {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .collect()
    };
    let base = part(&name[NAME_BASE], entry.nt_flags & CASE_LOWER_BASE != 0);
    let ext = part(&name[NAME_EXT], entry.nt_flags & CASE_LOWER_EXT != 0);
    if ext.is_empty() {
        base
    } else {
        format!("{}.{}", base, ext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias(name: &str) -> Alias {
        Alias::of(&LongName::new(name).unwrap())
    }

    #[test]
    fn validation() {
        for bad in [
            "", ".", "..", "a/b", "a\\b", "a:b", "a*b", "a?b", "a\"b", "a<b", "a>b", "a|b", "a\tb", "a\x7fb", "a.",
            "a ", " a",
        ] {
            assert!(LongName::new(bad).is_err(), "{:?} accepted", bad);
        }
        assert!(LongName::new("a\u{ffff}b").is_err());
        for good in [
            "a",
            "a.b",
            "a..b",
            "..a",
            "hello world.txt",
            "ünïcödé",
            "a+b;c=d[e]",
            "日本語",
            "\u{fffe}",
        ] {
            assert!(LongName::new(good).is_ok(), "{:?} rejected", good);
        }
        let long: String = std::iter::repeat_n('x', 255).collect();
        assert_eq!(LongName::new(&long).unwrap().entry_count(), 20);
        let too_long: String = std::iter::repeat_n('x', 256).collect();
        assert_eq!(LongName::new(&too_long).unwrap_err().errno(), ENAMETOOLONG);
        // Surrogate pairs count as two units.
        let astral: String = std::iter::repeat_n('\u{1F600}', 128).collect();
        assert_eq!(LongName::new(&astral).unwrap_err().errno(), ENAMETOOLONG);
    }

    #[test]
    fn plain_short_names() {
        let a = alias("README.TXT");
        assert_eq!(&a.name, b"README  TXT");
        assert!(!a.needs_long_name && !a.lossy);
        assert_eq!(a.case_flags, 0);

        let a = alias("readme.txt");
        assert_eq!(&a.name, b"README  TXT");
        assert!(!a.needs_long_name);
        assert_eq!(a.case_flags, CASE_LOWER_BASE | CASE_LOWER_EXT);

        let a = alias("foo.TXT");
        assert_eq!(a.case_flags, CASE_LOWER_BASE);
        let a = alias("FOO.txt");
        assert_eq!(a.case_flags, CASE_LOWER_EXT);

        let a = alias("Readme.txt");
        assert_eq!(&a.name, b"README  TXT");
        assert!(a.needs_long_name && !a.lossy);
        assert_eq!(a.case_flags, 0);

        let a = alias("BOOTX64.EFI");
        assert_eq!(&a.name, b"BOOTX64 EFI");
        assert!(!a.needs_long_name);
        let a = alias("loader");
        assert_eq!(&a.name, b"LOADER     ");
        assert_eq!(a.case_flags, CASE_LOWER_BASE);
    }

    #[test]
    fn lossy_aliases() {
        let cases: &[(&str, &[u8; SHORT_NAME_SIZE])] = &[
            ("foo.html", b"FOO~1   HTM"),
            (".bashrc", b"BASHRC~1   "),
            ("a b.txt", b"AB~1    TXT"),
            ("a.b.c", b"AB~1    C  "),
            ("a+b.txt", b"A_B~1   TXT"),
            ("prn.txt", b"PRN~1   TXT"),
            ("longfilename.txt", b"LONGFI~1TXT"),
            ("ÄÖÜ.txt", b"___~1   TXT"),
            ("linux-6.12.efi", b"LINUX-~1EFI"),
            ("random-seed", b"RANDOM~1   "),
            ("a..b", b"A~1     B  "),
        ];
        for (name, expected) in cases {
            let a = alias(name);
            assert!(a.lossy && a.needs_long_name, "{}", name);
            assert_eq!(&a.with_tail(1), *expected, "{}", name);
        }
    }

    #[test]
    fn numeric_tails() {
        let a = alias("thisisalongname");
        assert_eq!(&a.name, b"THISISAL   ");
        assert_eq!(&a.with_tail(1), b"THISIS~1   ");
        assert_eq!(&a.with_tail(9), b"THISIS~9   ");
        assert_eq!(&a.with_tail(10), b"THISI~10   ");
        assert_eq!(&a.with_tail(999_999), b"T~999999   ");
        assert_eq!(&a.with_tail(u32::MAX), b"T~999999   ");
        assert_eq!(&a.with_tail(0), b"THISIS~1   ");
        let a = alias("ab cd");
        assert_eq!(&a.with_tail(9), b"ABCD~9     ");
        assert_eq!(&a.with_tail(10), b"ABCD~10    ");
    }

    #[test]
    fn long_name_entry_layout() {
        let n = LongName::new("Readme.txt").unwrap();
        let checksum = 0x42;
        let e = long_name_entries(&n, checksum);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0][dirent::lfn_field::ORDER], LFN_LAST_ENTRY | 1);
        assert_eq!(e[0][dirent::lfn_field::ATTR], ATTR_LONG_NAME);
        assert_eq!(e[0][dirent::lfn_field::TYPE], 0);
        assert_eq!(e[0][dirent::lfn_field::CHECKSUM], checksum);
        assert_eq!(&e[0][dirent::lfn_field::FIRST_CLUSTER], &[0, 0]);
        let p = parse_long_name_entry(&e[0]).unwrap();
        assert_eq!(p.sequence, 1);
        assert!(p.last);
        let mut expected: Vec<u16> = "Readme.txt".encode_utf16().collect();
        expected.push(LFN_TERMINATOR);
        expected.extend([LFN_PADDING, LFN_PADDING]);
        assert_eq!(p.units.to_vec(), expected);
        assert_eq!(join_long_name(&[p]), n.units());

        // Exactly 13 units: no terminator, no padding.
        let n = LongName::new("thirteen_char").unwrap();
        let e = long_name_entries(&n, 0);
        assert_eq!(e.len(), 1);
        assert_eq!(parse_long_name_entry(&e[0]).unwrap().units.to_vec(), n.units());

        // 14 units: two entries, the second one holds one character, the
        // terminator and padding.
        let n = LongName::new("fourteen_chars").unwrap();
        let e = long_name_entries(&n, 0);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0][dirent::lfn_field::ORDER], LFN_LAST_ENTRY | 2);
        assert_eq!(e[1][dirent::lfn_field::ORDER], 1);
        let first = parse_long_name_entry(&e[0]).unwrap();
        assert_eq!(first.units[0], 's' as u16);
        assert_eq!(first.units[1], LFN_TERMINATOR);
        assert_eq!(first.units[2], LFN_PADDING);
        let second = parse_long_name_entry(&e[1]).unwrap();
        assert_eq!(join_long_name(&[second, first]), n.units());
    }

    #[test]
    fn folding() {
        assert_eq!(fold_str("Hello"), fold_str("hELLO"));
        assert_eq!(fold_str("ünïcödé"), fold_str("ÜNÏCÖDÉ"));
        assert_ne!(fold_str("a"), fold_str("b"));
        // ß has no single character upper case form and stays itself.
        assert_eq!(fold_str("ß"), "ß".encode_utf16().collect::<Vec<_>>());
        // So does a Greek letter with ypogegrammeni, whose upper case form
        // adds a capital iota. Its simple upper case mapping would be U+1F88;
        // the rule here is the full mapping restricted to one character.
        assert_eq!(fold_char('\u{1f80}'), '\u{1f80}');
        // Characters outside the Basic Multilingual Plane fold as well.
        assert_eq!(fold_char('\u{10428}'), '\u{10400}');
        assert_eq!(fold_str("\u{10428}"), fold_str("\u{10400}"));
        let n = LongName::new("MiXeD.TxT").unwrap();
        assert_eq!(n.folded(), fold_str("mixed.txt"));
    }

    #[test]
    fn ascii_folds_like_to_ascii_uppercase() {
        for b in 0u8..=0x7f {
            let c = b as char;
            assert_eq!(fold_char(c), c.to_ascii_uppercase(), "{:?}", c);
        }
        let all: String = (0u8..=0x7f).map(|b| b as char).collect();
        let expected: Vec<u16> = all.bytes().map(|b| u16::from(b.to_ascii_uppercase())).collect();
        assert_eq!(fold_str(&all), expected);
        let units: Vec<u16> = all.encode_utf16().collect();
        assert_eq!(fold_utf16(&units), expected);
    }

    #[test]
    fn fold_table_is_well_formed() {
        let pairs = fold_table::PAIRS;
        assert_eq!(pairs.len(), 1450);
        assert!(pairs.windows(2).all(|w| w[0].0 < w[1].0), "not strictly sorted");
        for &(lower, upper) in pairs {
            assert_ne!(lower, upper, "{:?} folds to itself", lower);
            assert_eq!(fold_char(lower), upper);
            // Folding is idempotent: no upper case form folds any further.
            assert_eq!(fold_char(upper), upper, "{:?} -> {:?} folds on", lower, upper);
        }
    }

    /// The compiler's `to_uppercase()` gives the same single character for
    /// every character the table folds. Unicode never changes or removes a
    /// case pair, so this holds whatever Unicode version the compiler
    /// ships.
    #[test]
    fn fold_table_agrees_with_the_compiler() {
        for &(lower, upper) in fold_table::PAIRS {
            let mut u = lower.to_uppercase();
            assert_eq!((u.next(), u.next()), (Some(upper), None), "{:?}", lower);
        }
    }

    /// The case pairs Unicode added after 16.0.0 are not folded: the 28 of
    /// 17.0.0 (three Latin letters and the Beria Erfe alphabet) and the 20
    /// of 18.0.0. Two names that differ in the case of one of them stay two
    /// names.
    #[test]
    fn later_case_pairs_stay_unfolded() {
        let unicode_17 = ['\u{a7cf}', '\u{a7d3}', '\u{a7d5}']
            .into_iter()
            .chain('\u{16ebb}'..='\u{16ed3}');
        let unicode_18 = [
            '\u{0277}',
            '\u{027c}',
            '\u{ab4b}',
            '\u{ab4c}',
            '\u{1df41}',
            '\u{1df49}',
            '\u{1df4b}',
            '\u{1df4e}',
            '\u{1df52}',
            '\u{1df69}',
            '\u{1df6b}',
            '\u{1df6d}',
            '\u{1df6f}',
            '\u{1df73}',
            '\u{1df75}',
            '\u{1df77}',
            '\u{1df79}',
            '\u{1df7b}',
            '\u{1df7d}',
            '\u{1df7f}',
        ];
        let added: Vec<char> = unicode_17.chain(unicode_18).collect();
        assert_eq!(added.len(), 28 + 20);
        for c in added {
            assert_eq!(fold_char(c), c, "{:?}", c);
            assert!(fold_table::PAIRS.binary_search_by_key(&c, |&(lower, _)| lower).is_err());
        }
    }

    #[test]
    fn fold_str_and_fold_utf16_agree_with_fold_char() {
        for c in char::MIN..=char::MAX {
            let mut buf = [0u16; 2];
            let expected = fold_char(c).encode_utf16(&mut buf).to_vec();
            let s = c.to_string();
            assert_eq!(fold_str(&s), expected, "{:?}", c);
            let units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(fold_utf16(&units), expected, "{:?}", c);
        }
        // Unpaired surrogates fold to themselves.
        assert_eq!(fold_utf16(&[0xD800, 'a' as u16]), vec![0xD800, 'A' as u16]);
        assert_eq!(fold_utf16(&[0xDC00]), vec![0xDC00]);
    }

    /// Whole names, ASCII or not, fold like their characters do one by one.
    #[test]
    fn fold_str_and_fold_utf16_agree_on_names() {
        for s in [
            "",
            "README.TXT",
            "a b.txt",
            "Grüße.TXT",
            "ÄÖÜ",
            "straße",
            "x\u{10428}y",
            "\u{1f80}\u{3b1}",
            "\u{a7cf}A",
        ] {
            let expected: Vec<u16> = s.chars().map(fold_char).collect::<String>().encode_utf16().collect();
            assert_eq!(fold_str(s), expected, "{:?}", s);
            let units: Vec<u16> = s.encode_utf16().collect();
            assert_eq!(fold_utf16(&units), expected, "{:?}", s);
        }
    }

    #[test]
    fn short_name_display() {
        let mut e = RawDirEntry {
            name: *b"README  TXT",
            ..RawDirEntry::default()
        };
        assert_eq!(short_name_to_string(&e), "README.TXT");
        e.nt_flags = CASE_LOWER_BASE;
        assert_eq!(short_name_to_string(&e), "readme.TXT");
        e.nt_flags = CASE_LOWER_BASE | CASE_LOWER_EXT;
        assert_eq!(short_name_to_string(&e), "readme.txt");
        e.name = *b"LOADER     ";
        e.nt_flags = 0;
        assert_eq!(short_name_to_string(&e), "LOADER");
        e.name[0] = ENTRY_E5_ESCAPE;
        assert_eq!(short_name_to_string(&e).as_bytes()[0..2], [0xC3, 0xA5]);
    }
}

/// Bounded model checking harnesses for Kani.
#[cfg(kani)]
mod proofs {
    use super::*;

    fn legal_short_byte(b: u8) -> bool {
        b == b' ' || valid_short_char(b)
    }

    /// with_tail() never panics, keeps the extension, keeps the tail inside
    /// the base part and spells the counter in decimal, for every counter
    /// value and base length.
    #[kani::proof]
    #[kani::unwind(16)]
    fn with_tail_is_total() {
        let base_len: usize = kani::any_where(|l: &usize| *l <= NAME_BASE.len());
        let alias = Alias {
            name: *b"ABCDEFGHEXT",
            base_len,
            lossy: true,
            needs_long_name: true,
            case_flags: 0,
        };
        let n: u32 = kani::any();
        let tailed = alias.with_tail(n);
        assert!(&tailed[NAME_EXT] == &alias.name[NAME_EXT]);
        assert!(tailed.iter().all(|&b| legal_short_byte(b)));
        let tilde = tailed[NAME_BASE].iter().position(|&b| b == b'~').unwrap();
        assert!(tilde <= base_len);
        let mut value: u32 = 0;
        let mut digits = 0;
        for &b in &tailed[tilde + 1..NAME_BASE.end] {
            if b == b' ' {
                break;
            }
            assert!(b.is_ascii_digit());
            value = value * 10 + (b - b'0') as u32;
            digits += 1;
        }
        assert!(digits >= 1);
        assert!(value == n.clamp(1, Alias::MAX_TAIL));
    }
}
