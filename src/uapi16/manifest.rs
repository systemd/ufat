// SPDX-License-Identifier: LGPL-2.1-or-later
//! A whole manifest in memory.

use std::collections::HashSet;
use std::io::Read;

use crate::error::{Error, Problem};
use crate::object::{FileObject, Signature};
use crate::reader::{Reader, Record};
use crate::Name;

/// A manifest: its root file object, its file objects and its signature
/// objects.
///
/// ```
/// use uapi16::Manifest;
///
/// let manifest = Manifest::parse(concat!(
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"mTimeNSec\":5}\n",
///     "\x1e{\"name\":\"a\",\"size\":3}\n",
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
/// ).as_bytes())?;
/// assert_eq!(manifest.root.mtime_nsec, Some(5));
/// assert_eq!(manifest.objects[0].name, "a");
/// assert_eq!(manifest.objects[0].size, Some(3));
/// # Ok::<(), uapi16::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Manifest {
    /// The root file object.
    pub root: FileObject,
    /// The file objects, in the order of the manifest.
    pub objects: Vec<FileObject>,
    /// The signature objects, in the order of the manifest. None of them
    /// was verified.
    pub signatures: Vec<Signature>,
}

impl Manifest {
    /// A manifest with the root file object `root` and nothing else.
    pub fn new(root: FileObject) -> Manifest {
        Manifest {
            root,
            objects: Vec::new(),
            signatures: Vec::new(),
        }
    }

    /// Reads a manifest to its end. Every object is checked as a
    /// [`Reader`] checks it, and no two file objects may have the same
    /// name.
    pub fn read(input: impl Read) -> Result<Manifest, Error> {
        let mut reader = Reader::open(input)?;
        let mut manifest = Manifest::new(reader.root().clone());
        for record in &mut reader {
            match record? {
                Record::File(object) => manifest.objects.push(*object),
                Record::Signature(signature) => manifest.signatures.push(signature),
            }
        }
        if let Some(name) = manifest.duplicate_name() {
            return Err(
                Error::manifest(Problem::DuplicateName, format!("manifest lists '{}' twice", name))
                    .named(name.as_str()),
            );
        }
        Ok(manifest)
    }

    /// Reads a manifest that is held in memory, see [`Manifest::read`].
    pub fn parse(bytes: &[u8]) -> Result<Manifest, Error> {
        Manifest::read(bytes)
    }

    /// The name of the first file object that has the name of one before
    /// it, if there is one.
    pub fn duplicate_name(&self) -> Option<&Name> {
        let mut names = self.objects.iter().map(|object| &object.name);
        // A manifest mostly lists its names in order, and names that only
        // go up do not repeat.
        if names.clone().is_sorted_by(|a, b| a < b) {
            return None;
        }
        let mut seen = HashSet::with_capacity(self.objects.len());
        names.find(|name| !seen.insert(name.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::testing::{manifest, sequence, HELLO, ROOT, SIGNATURE, TRAILER};
    use crate::{Digest, InodeType, Sha256};

    #[test]
    fn reads_a_manifest() {
        let file = format!(
            r#"{{"mTimeNSec":1700000000000000000,"mode":420,"name":"EFI/BOOT/BOOTX64.EFI","sha256":"{}","size":5}}"#,
            HELLO
        );
        let m = Manifest::parse(&sequence(&[
            r#"{"mTimeNSec":7,"mediaType":"application/vnd.uapi.16.manifest","mode":509}"#,
            r#"{"mode":493,"name":"EFI","type":"dir","uid":0,"gid":0}"#,
            r#"{"name":"EFI/BOOT","type":"dir"}"#,
            &file,
            r#"{"name":"empty","size":"0"}"#,
            r#"{"contents":[{"literal":"aGVs bG8="}],"name":"literal.txt","mode":"644"}"#,
            r#"{"contents":[{"literal":"aGVsbG8="}],"name":"link","type":"lnk"}"#,
            SIGNATURE,
            r#"{"mediaType":"application/x-unknown","whatever":1}"#,
            TRAILER,
        ]))
        .unwrap();
        assert_eq!(m.root.inode_type, InodeType::Directory);
        assert_eq!(
            (m.root.mtime_nsec, m.root.mode.map(crate::Mode::bits)),
            (Some(7), Some(0o775))
        );
        let names: Vec<&str> = m.objects.iter().map(|object| object.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "EFI",
                "EFI/BOOT",
                "EFI/BOOT/BOOTX64.EFI",
                "empty",
                "literal.txt",
                "link"
            ]
        );
        assert_eq!(m.objects[2].sha256, Some(Sha256::of(b"hello")));
        assert_eq!(m.objects[3].sha256, Some(Sha256::EMPTY));
        assert_eq!(m.objects[4].size, Some(5));
        assert_eq!(m.objects[5].inode_type, InodeType::Symlink);
        assert_eq!(m.signatures.len(), 1);
        assert_eq!(m.signatures[0].mechanism, "pkcs7");
        assert_eq!(m.signatures[0].data.as_deref(), Some(&[0u8, 0, 0][..]));
        // The least a manifest is.
        let least = Manifest::read(&sequence(&[ROOT, TRAILER])[..]).unwrap();
        assert_eq!(least, Manifest::new(FileObject::root()));
    }

    #[test]
    fn names_are_unique() {
        let m = Manifest::parse(&manifest(&[r#"{"name":"a"}"#, r#"{"name":"b"}"#, r#"{"name":"a/b"}"#])).unwrap();
        assert_eq!(m.duplicate_name(), None);
        // In order, and in order but for the one that repeats.
        let m = Manifest::parse(&manifest(&[r#"{"name":"a"}"#, r#"{"name":"a/b"}"#, r#"{"name":"b"}"#])).unwrap();
        assert_eq!(m.duplicate_name(), None);
        let mut m = m;
        m.objects.push(m.objects[2].clone());
        m.objects.push(FileObject::new(Name::new("c").unwrap()));
        assert_eq!(m.duplicate_name().map(Name::as_str), Some("b"));
        assert_eq!(Manifest::new(FileObject::root()).duplicate_name(), None);
        // The names differ by a byte, by case or by a prefix.
        let m = Manifest::parse(&manifest(&[r#"{"name":"a"}"#, r#"{"name":"A"}"#, r#"{"name":"a."}"#])).unwrap();
        assert_eq!(m.duplicate_name(), None);
        let bytes = manifest(&[
            r#"{"name":"c"}"#,
            r#"{"name":"a"}"#,
            r#"{"name":"b"}"#,
            r#"{"name":"b","type":"dir"}"#,
            r#"{"name":"a"}"#,
            r#"{"name":"a"}"#,
        ]);
        let e = Manifest::parse(&bytes).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::DuplicateName));
        assert_eq!(e.name(), Some("b"));
        assert_eq!(e.to_string(), "manifest lists 'b' twice");
        // A reader does not look for this.
        assert_eq!(Reader::open(&bytes[..]).unwrap().filter(Result::is_ok).count(), 6);
    }

    /// The manifests `systemd-manifest` wrote, see tests/fixtures.
    #[test]
    fn manifests_of_systemd() {
        let fixtures: [(&str, &[u8], usize, usize); 6] = [
            ("esp", include_bytes!("../../tests/fixtures/esp/Uapi16Manifest"), 13, 0),
            (
                "signed",
                include_bytes!("../../tests/fixtures/esp/signed.Uapi16Manifest"),
                13,
                1,
            ),
            (
                "lean",
                include_bytes!("../../tests/fixtures/esp/size-hash-mtime.Uapi16Manifest"),
                13,
                0,
            ),
            (
                "none",
                include_bytes!("../../tests/fixtures/esp/none.Uapi16Manifest"),
                13,
                0,
            ),
            (
                "special",
                include_bytes!("../../tests/fixtures/special/Uapi16Manifest"),
                13,
                0,
            ),
            (
                "empty",
                include_bytes!("../../tests/fixtures/empty/Uapi16Manifest"),
                0,
                0,
            ),
        ];
        for (name, bytes, objects, signatures) in fixtures {
            let m = Manifest::parse(bytes).unwrap_or_else(|e| panic!("{}: {}", name, e));
            assert_eq!((m.objects.len(), m.signatures.len()), (objects, signatures), "{}", name);
        }
    }
}
