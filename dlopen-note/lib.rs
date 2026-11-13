// SPDX-License-Identifier: LGPL-2.1-or-later
//! The `.note.dlopen` ELF note, which names the libraries a program loads
//! with dlopen().
//!
//! A program has no DT_NEEDED entry for a library it loads with dlopen(),
//! so packaging tools do not see that it needs the library. The ELF
//! dlopen metadata specification, UAPI.12
//! (<https://uapi-group.org/specifications/specs/elf_dlopen_metadata/>),
//! names such libraries in notes in the `.note.dlopen` section. A note has
//! the owner "FDO", the type 0x407c0c0a, and as its description a NUL
//! terminated JSON array of objects. Each object names a feature, says
//! what it does and how much the program needs it, and lists the sonames
//! of the libraries it loads. readelf and `systemd-analyze dlopen-metadata`
//! show the notes. systemd declares them with SD_ELF_NOTE_DLOPEN() of
//! src/systemd/sd-dlopen.h, and [`note!`] lays them out the same way.
//!
//! The JSON is laid out at compile time. A string that JSON would have to
//! escape fails the build.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::ffi::CStr;

/// The owner of the note: FDO, for freedesktop.org.
pub const OWNER: &str = "FDO";
/// The type of the note, which readelf calls FDO_DLOPEN_METADATA.
pub const TYPE: u32 = 0x407c_0c0a;

/// The fields of a note start at multiples of 4 bytes, and the name and
/// the description are padded with zeros to that.
const ALIGN: usize = 4;
/// The size of the owner's name in the note, with its NUL.
const NAME_SIZE: usize = OWNER.len() + 1;
/// The owner's name, padded.
const NAME_PADDED: usize = NAME_SIZE.next_multiple_of(ALIGN);

// What a JSON string cannot hold as it is: the quotation mark, the
// reverse solidus and the control characters U+0000 to U+001F (RFC 8259,
// section 7). The specification of the note allows no control character
// at all, so DEL and the C1 control characters U+0080 to U+009F are left
// out as well. These are what char::is_control() calls control
// characters.
/// The quotation mark, which ends a JSON string.
const QUOTATION_MARK: u8 = b'"';
/// The reverse solidus, which starts an escape in a JSON string.
const REVERSE_SOLIDUS: u8 = b'\\';
/// The space, the first character after the C0 control characters.
const SPACE: u8 = b' ';
/// DEL, U+007F.
const DELETE: u8 = 0x7f;
/// The first byte of U+0080 to U+00BF in UTF-8.
const C1_LEAD: u8 = 0xc2;
/// The second bytes of U+0080 and U+009F, the first and the last C1
/// control character.
const C1_FIRST: u8 = 0x80;
const C1_LAST: u8 = 0x9f;

/// How much a program needs a feature, and with it the libraries the
/// feature loads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Priority {
    /// The program does not work without the libraries.
    Required,
    /// The program works without the libraries, but most installations
    /// should have them.
    Recommended,
    /// Only installations that want every feature need the libraries.
    Suggested,
}

impl Priority {
    /// The name the note gives the priority.
    pub const fn as_str(self) -> &'static str {
        match self {
            Priority::Required => "required",
            Priority::Recommended => "recommended",
            Priority::Suggested => "suggested",
        }
    }
}

/// A feature of a program and the libraries it loads with dlopen(): one
/// object of the JSON array of a note.
#[derive(Clone, Copy, Debug)]
pub struct Dependency<'a> {
    /// A keyword that names the feature.
    pub feature: &'a str,
    /// What the feature does, for people to read.
    pub description: &'a str,
    /// How much the program needs the feature.
    pub priority: Priority,
    /// The libraries the feature loads, by the names dlopen() takes. There
    /// is at least one.
    pub sonames: &'a [&'a CStr],
}

impl Dependency<'_> {
    /// The length of the JSON, without its NUL.
    pub const fn json_len(&self) -> usize {
        self.write(&mut [])
    }

    /// The size of the description of the note: the JSON and its NUL,
    /// padded to 4 bytes.
    pub const fn desc_size(&self) -> usize {
        (self.json_len() + 1).next_multiple_of(ALIGN)
    }

    /// Writes the JSON to `out`, as much of it as fits, and returns its
    /// length. The keys come in the order SD_ELF_NOTE_DLOPEN() writes
    /// them.
    const fn write(&self, out: &mut [u8]) -> usize {
        assert!(!self.sonames.is_empty(), "a dlopen note names at least one library");
        let mut json = Writer { out, len: 0 };
        json.raw(b"[{\"feature\":");
        json.string(self.feature.as_bytes());
        json.raw(b",\"description\":");
        json.string(self.description.as_bytes());
        json.raw(b",\"priority\":");
        json.string(self.priority.as_str().as_bytes());
        json.raw(b",\"soname\":[");
        let mut i = 0;
        while i < self.sonames.len() {
            if i > 0 {
                json.raw(b",");
            }
            json.string(self.sonames[i].to_bytes());
            i += 1;
        }
        json.raw(b"]}]");
        json.len
    }
}

/// Writes bytes at compile time: as many as fit into `out`, and counts
/// all of them.
struct Writer<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Writer<'_> {
    /// Appends `bytes` as they are.
    const fn raw(&mut self, bytes: &[u8]) {
        let mut i = 0;
        while i < bytes.len() {
            if self.len < self.out.len() {
                self.out[self.len] = bytes[i];
            }
            self.len += 1;
            i += 1;
        }
    }

    /// Appends `s` as a JSON string. Fails for one that is not UTF-8 or
    /// that holds a character JSON would have to escape or a control
    /// character.
    const fn string(&mut self, s: &[u8]) {
        assert!(std::str::from_utf8(s).is_ok(), "a string of a dlopen note is UTF-8");
        let mut i = 0;
        while i < s.len() {
            assert!(
                !Writer::needs_escape(s, i),
                "a string of a dlopen note holds no quotation mark, backslash or control character"
            );
            i += 1;
        }
        self.raw(&[QUOTATION_MARK]);
        self.raw(s);
        self.raw(&[QUOTATION_MARK]);
    }

    /// Whether the character that starts at `s[i]`, or the byte there
    /// that continues one, has to be escaped in JSON or is a control
    /// character.
    const fn needs_escape(s: &[u8], i: usize) -> bool {
        match s[i] {
            QUOTATION_MARK | REVERSE_SOLIDUS | DELETE => true,
            b if b < SPACE => true,
            C1_LEAD => i + 1 < s.len() && s[i + 1] >= C1_FIRST && s[i + 1] <= C1_LAST,
            _ => false,
        }
    }
}

/// A note as it sits in a note section, in the byte order of the target:
/// the three 32-bit words of the header, which ELF32 and ELF64 share, the
/// owner's name with its NUL, and the description. The name and the
/// description are padded with zeros to 4 bytes. `N` is the padded size of
/// the description, [`Dependency::desc_size`].
#[repr(C, align(4))]
pub struct Note<const N: usize> {
    namesz: u32,
    descsz: u32,
    kind: u32,
    name: [u8; NAME_PADDED],
    desc: [u8; N],
}

// repr(align) takes no constant, so this ties it to ALIGN.
const _: () = assert!(align_of::<Note<0>>() == ALIGN);

impl<const N: usize> Note<N> {
    /// The note of `dependency`. Fails when `N` is not its
    /// [`Dependency::desc_size`].
    pub const fn new(dependency: &Dependency<'_>) -> Note<N> {
        let mut desc = [0; N];
        let len = dependency.write(&mut desc);
        assert!(
            len < u32::MAX as usize,
            "the JSON of a dlopen note is shorter than 4 GiB"
        );
        assert!(
            (len + 1).next_multiple_of(ALIGN) == N,
            "N is the padded size of the description of the note"
        );
        let mut name = [0; NAME_PADDED];
        Writer { out: &mut name, len: 0 }.raw(OWNER.as_bytes());
        Note {
            namesz: NAME_SIZE as u32,
            descsz: (len + 1) as u32,
            kind: TYPE,
            name,
            desc,
        }
    }

    /// The JSON of the note.
    pub fn json(&self) -> &str {
        let len = self.descsz as usize - 1;
        std::str::from_utf8(&self.desc[..len]).expect("the JSON of a dlopen note is UTF-8")
    }

    /// Refers to the note from the code that calls this. The linker keeps
    /// what kept code refers to, so the note stays in the program as long
    /// as that code does, whatever the linker does with sections nothing
    /// refers to.
    #[inline]
    pub fn keep(&'static self) {
        std::hint::black_box(self);
    }
}

/// Declares a static that holds the note for a [`Dependency`], in the
/// `.note.dlopen` section.
///
/// ```
/// use dlopen_note::{Dependency, Priority};
///
/// dlopen_note::note! {
///     /// The note for libfoo.
///     static NOTE = Dependency {
///         feature: "foo",
///         description: "Enables the foo feature",
///         priority: Priority::Recommended,
///         sonames: &[c"libfoo.so.1"],
///     };
/// }
///
/// assert_eq!(
///     NOTE.json(),
///     r#"[{"feature":"foo","description":"Enables the foo feature","priority":"recommended","soname":["libfoo.so.1"]}]"#
/// );
/// ```
///
/// A string that JSON would have to escape fails the build:
///
/// ```compile_fail,E0080
/// use dlopen_note::{Dependency, Priority};
///
/// dlopen_note::note! {
///     static NOTE = Dependency {
///         feature: "foo",
///         description: "Enables the \"foo\" feature",
///         priority: Priority::Recommended,
///         sonames: &[c"libfoo.so.1"],
///     };
/// }
/// ```
#[macro_export]
macro_rules! note {
    ($(#[$attr:meta])* $vis:vis static $name:ident = $dependency:expr;) => {
        $(#[$attr])*
        // A section whose name starts with .note is a note section
        // (SHT_NOTE). Its content is only read, by whoever reads the
        // notes. #[used] keeps the compiler from dropping the static,
        // which nothing has to refer to.
        #[used]
        #[link_section = ".note.dlopen"]
        #[allow(unsafe_code)]
        $vis static $name: $crate::Note<{ $crate::Dependency::desc_size(&$dependency) }> =
            $crate::Note::new(&$dependency);
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;

    /// The JSON of [`NOTE`].
    const JSON: &str = concat!(
        r#"[{"feature":"blkid","#,
        r#""description":"Identification of file systems and partition tables in images","#,
        r#""priority":"recommended","#,
        r#""soname":["libblkid.so.1"]}]"#,
    );

    note! {
        /// The note ufat had before this crate.
        static NOTE = Dependency {
            feature: "blkid",
            description: "Identification of file systems and partition tables in images",
            priority: Priority::Recommended,
            sonames: &[c"libblkid.so.1"],
        };
    }

    /// The bytes of `note` as it sits in memory.
    #[allow(unsafe_code)]
    fn bytes<const N: usize>(note: &Note<N>) -> &[u8] {
        // SAFETY: Note is repr(C), and its fields of u32 and of arrays of
        // u8 follow each other without padding. So all of its bytes are
        // initialized.
        unsafe { std::slice::from_raw_parts((note as *const Note<N>).cast::<u8>(), size_of::<Note<N>>()) }
    }

    /// A note in the layout ELF gives it: the sizes of the name and of the
    /// description and the type, then the name and the description, each
    /// padded to 4 bytes.
    fn elf_note(owner: &str, kind: u32, desc: &[u8]) -> Vec<u8> {
        let name = [owner.as_bytes(), b"\0"].concat();
        let mut note = Vec::new();
        for size in [name.len(), desc.len()] {
            note.extend_from_slice(&u32::try_from(size).unwrap().to_ne_bytes());
        }
        note.extend_from_slice(&kind.to_ne_bytes());
        for part in [&name[..], desc] {
            note.extend_from_slice(part);
            note.resize(note.len().next_multiple_of(ALIGN), 0);
        }
        note
    }

    #[test]
    fn the_note_is_laid_out_as_elf_has_it() {
        assert_eq!(NOTE.json(), JSON);
        let desc = [JSON.as_bytes(), b"\0"].concat();
        assert_eq!(bytes(&NOTE), elf_note(OWNER, TYPE, &desc));
    }

    /// A dependency on libfoo with `feature`.
    fn foo(feature: &str) -> Dependency<'_> {
        Dependency {
            feature,
            description: "Enables the foo feature",
            priority: Priority::Suggested,
            sonames: &[c"libfoo.so.1"],
        }
    }

    /// The JSON of `dependency`, as the note holds it.
    fn json(dependency: &Dependency<'_>) -> String {
        let mut out = vec![0; dependency.json_len()];
        assert_eq!(dependency.write(&mut out), out.len());
        String::from_utf8(out).unwrap()
    }

    /// Four JSON texts whose lengths follow each other take each of the
    /// four sizes of padding once.
    #[test]
    fn the_description_is_padded() {
        let mut padding = Vec::new();
        for feature in ["f", "fo", "foo", "food"] {
            let dependency = foo(feature);
            let len = json(&dependency).len();
            assert_eq!(dependency.json_len(), len);
            let size = dependency.desc_size();
            assert_eq!(size % ALIGN, 0, "{}", feature);
            assert!(size > len, "{}: no room for the NUL", feature);
            padding.push(size - len - 1);
        }
        padding.sort_unstable();
        assert_eq!(padding, (0..ALIGN).collect::<Vec<_>>());
    }

    #[test]
    fn every_field_is_in_the_json() {
        let dependency = Dependency {
            feature: "foo",
            description: "Enables the foo feature, ä€",
            priority: Priority::Required,
            sonames: &[c"libfoo.so.1", c"libfoo.so.0"],
        };
        assert_eq!(
            json(&dependency),
            concat!(
                r#"[{"feature":"foo","description":"Enables the foo feature, ä€","#,
                r#""priority":"required","soname":["libfoo.so.1","libfoo.so.0"]}]"#
            )
        );
        assert_eq!(Priority::Required.as_str(), "required");
        assert_eq!(Priority::Recommended.as_str(), "recommended");
        assert_eq!(Priority::Suggested.as_str(), "suggested");
    }

    /// Characters JSON escapes and control characters are refused, every
    /// other character is taken. All characters of one and two bytes in
    /// UTF-8 are tried, which holds all of the refused ones, and some of
    /// three and four bytes.
    #[test]
    fn strings_that_need_escaping_are_refused() {
        /// The last character UTF-8 encodes in two bytes.
        const LAST_OF_TWO_BYTES: char = '\u{7ff}';
        let longer = ['€', char::REPLACEMENT_CHARACTER, '😀', char::MAX];
        for c in ('\0'..=LAST_OF_TWO_BYTES).chain(longer) {
            let feature = c.to_string();
            let refused = catch_unwind(|| foo(&feature).json_len()).is_err();
            assert_eq!(refused, c.is_control() || c == '"' || c == '\\', "{:?}", c);
        }
        let soname = c"libfoo\xff.so.1";
        let dependency = Dependency {
            sonames: &[soname],
            ..foo("foo")
        };
        assert!(catch_unwind(|| dependency.json_len()).is_err());
        let dependency = Dependency {
            sonames: &[],
            ..foo("foo")
        };
        assert!(catch_unwind(|| dependency.json_len()).is_err());
    }
}
