// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the root file object of a manifest says about the volume its file
//! objects go into: the volume serial number and the label. A volume made
//! from the manifest takes them, and a volume the manifest's content is put
//! into has to have them.

use uapi16::{FatSerial, Features, RootObject, Sha256};

use crate::boot::{LABEL_SIZE, NO_NAME};
use crate::errno::*;
use crate::format::{encode_exact_label, encode_label, FormatOptions, VolumeId};
use crate::volume::Volume;
use crate::{Detail, FileSystemField, Result};

/// Where the serial number of a volume made from a manifest comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SerialSource {
    /// The manifest names it, or the caller gave it. It is in the format
    /// options.
    Given,
    /// Neither: it is derived from the bytes of the manifest once they are
    /// read, see [`VolumeId::from_manifest_digest`].
    Derived,
}

impl SerialSource {
    /// The serial number a volume made from the manifest takes from
    /// `digest`, the SHA-256 hash of the manifest's bytes: the one derived
    /// from it for [`SerialSource::Derived`], and None where the serial
    /// number is given. A derived one needs the hash of the whole manifest,
    /// and without it fails with EIO.
    pub fn derived_serial(self, digest: Option<Sha256>) -> Result<Option<VolumeId>> {
        match (self, digest) {
            (SerialSource::Given, _) => Ok(None),
            (SerialSource::Derived, Some(digest)) => Ok(Some(VolumeId::from_manifest_digest(&digest))),
            (SerialSource::Derived, None) => bail!(
                EIO,
                "the manifest was not read to its end, so no serial number is derived from it"
            ),
        }
    }
}

/// What the root file object of a manifest says about the label of the
/// volume it is for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum ManifestLabel {
    /// Nothing: the manifest has no `fsLabel` and does not list the
    /// feature `fs-label`.
    #[default]
    Unrecorded,
    /// The volume has no label: the manifest has an empty `fsLabel`, or
    /// none and lists `fs-label`.
    Unlabeled,
    /// The volume has the label `fsLabel` names.
    Labeled(String),
}

impl ManifestLabel {
    /// The label the manifest names, None for no label and where it says
    /// nothing.
    pub fn text(&self) -> Option<&str> {
        match self {
            ManifestLabel::Labeled(label) => Some(label),
            ManifestLabel::Unrecorded | ManifestLabel::Unlabeled => None,
        }
    }

    /// The label field of a volume that has the label the manifest names:
    /// [`NO_NAME`] for no label, and None where the manifest says nothing.
    /// The label is what the volume reports, so one that FAT cannot store
    /// or would report another way fails, see [`encode_exact_label`].
    fn stored(&self) -> Result<Option<[u8; LABEL_SIZE]>> {
        match self {
            ManifestLabel::Unrecorded => Ok(None),
            ManifestLabel::Unlabeled => Ok(Some(NO_NAME)),
            ManifestLabel::Labeled(label) => encode_exact_label(label).map(Some),
        }
    }
}

/// The FAT volume a manifest is for, as its root file object says: the
/// serial number from `fatSerial`, or else the one derived from `fsUUID`,
/// and the label from `fsLabel` and the feature `fs-label`. A manifest
/// without them is for any volume.
///
/// The specification has a file system made from a manifest take them, and
/// a file system the file objects are placed in have them. The label is
/// what the file system reports, as blkid shows it. A manifest that is
/// placed below the root of a file system is a sub-manifest, which says
/// nothing about it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeIdentity {
    /// The serial number and the field it comes from.
    serial: Option<(VolumeId, FileSystemField)>,
    /// The label.
    label: ManifestLabel,
}

impl VolumeIdentity {
    /// What the root file object `root` says.
    pub fn from_root(root: &RootObject) -> VolumeIdentity {
        let identity = &root.file_system;
        // fatSerial before fsUUID, as the specification has it.
        let serial = match (identity.fat_serial, &identity.uuid) {
            (Some(serial), _) => Some((VolumeId::from(serial), FileSystemField::FatSerial)),
            (None, Some(uuid)) => Some((VolumeId::from(FatSerial::from_uuid(uuid)), FileSystemField::FsUuid)),
            (None, None) => None,
        };
        let label = match identity.label.as_deref() {
            Some("") => ManifestLabel::Unlabeled,
            Some(label) => ManifestLabel::Labeled(label.to_string()),
            None if root.recorded_features().contains(Features::FS_LABEL) => ManifestLabel::Unlabeled,
            None => ManifestLabel::Unrecorded,
        };
        VolumeIdentity { serial, label }
    }

    /// The serial number the manifest names, with the field it comes
    /// from.
    pub fn serial(&self) -> Option<(VolumeId, FileSystemField)> {
        self.serial
    }

    /// The label the manifest names.
    pub fn label(&self) -> &ManifestLabel {
        &self.label
    }

    /// Reconciles the serial number and the label of a volume made from the
    /// manifest with `options`: the manifest's go into them. A label in
    /// `options` that FAT stores another way than the manifest's, also one
    /// where the manifest names no label, and a serial number `identifier`
    /// the caller gave that is not the manifest's, fail with EINVAL and
    /// [`Detail::FileSystemMismatch`]. A label that FAT cannot store, or
    /// would report another way, fails with EINVAL and [`Detail::Label`],
    /// see [`encode_exact_label`]. Without a serial number from the
    /// manifest the volume takes `identifier`, and without that the one
    /// derived from the manifest: the returned [`SerialSource`] says which.
    pub fn reconcile(&self, options: &mut FormatOptions, identifier: Option<VolumeId>) -> Result<SerialSource> {
        if let Some(stored) = self.label.stored()? {
            if let Some(given) = options.label.as_deref() {
                if encode_label(given)? != stored {
                    let detail = Detail::file_system_mismatch(FileSystemField::FsLabel, self.label.text(), Some(given));
                    match self.label.text() {
                        Some(label) => bail!(
                            EINVAL,
                            detail,
                            "the label '{}' differs from the label '{}' the manifest gives in {}",
                            given,
                            label,
                            FileSystemField::FsLabel.as_str()
                        ),
                        None => bail!(
                            EINVAL,
                            detail,
                            "the label '{}' differs from the manifest, which gives the file system no label ({})",
                            given,
                            FileSystemField::FsLabel.as_str()
                        ),
                    }
                }
            }
            options.label = self.label.text().map(str::to_string);
        }
        match (self.serial, identifier) {
            (Some((serial, field)), Some(given)) if given != serial => bail!(
                EINVAL,
                Detail::file_system_mismatch(field, Some(serial), Some(given)),
                "the identifier {} differs from the serial number {} the manifest gives in {}",
                given,
                serial,
                field.as_str()
            ),
            (Some((serial, _)), _) | (None, Some(serial)) => {
                options.volume_id = serial.0;
                Ok(SerialSource::Given)
            }
            (None, None) => Ok(SerialSource::Derived),
        }
    }

    /// Checks that `volume` is the one the manifest is for: that it has the
    /// serial number and the label the manifest names, or no label where
    /// the manifest names none. What the manifest does not name is not
    /// checked. A label that FAT cannot store, or would report another way,
    /// fails with EINVAL and [`Detail::Label`], see [`encode_exact_label`].
    /// A volume that is not the manifest's fails with EINVAL and
    /// [`Detail::FileSystemMismatch`].
    pub fn check(&self, volume: &Volume) -> Result<()> {
        if let Some((serial, field)) = self.serial {
            let held = VolumeId(volume.boot_sector().volume_id);
            if held != serial {
                bail!(
                    EINVAL,
                    Detail::file_system_mismatch(field, Some(serial), Some(held)),
                    "the file system has the serial number {}, the manifest is for {} ({})",
                    held,
                    serial,
                    field.as_str()
                );
            }
        }
        let Some(stored) = self.label.stored()? else {
            return Ok(());
        };
        if volume.label_bytes()?.unwrap_or(NO_NAME) == stored {
            return Ok(());
        }
        let held = volume.label()?;
        let detail = Detail::file_system_mismatch(FileSystemField::FsLabel, self.label.text(), held.as_deref());
        let field = FileSystemField::FsLabel.as_str();
        match (held.as_deref(), self.label.text()) {
            (Some(held), Some(label)) => bail!(
                EINVAL,
                detail,
                "the file system has the label '{}', the manifest is for '{}' ({})",
                held,
                label,
                field
            ),
            (None, Some(label)) => bail!(
                EINVAL,
                detail,
                "the file system has no label, the manifest is for '{}' ({})",
                label,
                field
            ),
            (Some(held), None) => bail!(
                EINVAL,
                detail,
                "the file system has the label '{}', the manifest is for one without a label ({})",
                held,
                field
            ),
            // Neither has a label, which the comparison above took.
            (None, None) => Ok(()),
        }
    }
}

impl VolumeId {
    /// The serial number of a volume made from a manifest that names none,
    /// derived from the SHA-256 hash `digest` of the manifest's bytes: its
    /// first four bytes, read big-endian. So its eight hex digits are the
    /// first ones of the hash as `sha256sum` prints it, the way the first
    /// eight hex digits of `fsUUID` give a serial number.
    pub fn from_manifest_digest(digest: &Sha256) -> VolumeId {
        let [a, b, c, d, ..] = *digest.as_bytes();
        VolumeId(u32::from_be_bytes([a, b, c, d]))
    }
}

impl From<FatSerial> for VolumeId {
    fn from(serial: FatSerial) -> VolumeId {
        VolumeId(serial.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::format;
    use crate::test_util::{format_options, volume, TempImage};
    use crate::{Error, LabelProblem};
    use uapi16::{Field, Reader};

    /// The identity the root file object `root`, a JSON object, gives.
    fn identity_from_root(root: &str) -> VolumeIdentity {
        let manifest = format!(
            "\x1e{}\n\x1e{{\"mediaType\":\"application/vnd.uapi.16.trailer\"}}\n",
            root
        );
        VolumeIdentity::from_root(Reader::open(manifest.as_bytes()).unwrap().root())
    }

    /// A root file object with the fields `fields`, of a manifest that
    /// lists the features `features`.
    fn root(features: &str, fields: &str) -> String {
        let fields = if fields.is_empty() {
            String::new()
        } else {
            format!(",{}", fields)
        };
        format!(
            r#"{{"features":[{}],"mediaType":"application/vnd.uapi.16.manifest"{}}}"#,
            features, fields
        )
    }

    /// The fields of a mismatch.
    fn mismatch_fields(e: &Error) -> (FileSystemField, Option<&str>, Option<&str>) {
        match e.detail() {
            Some(Detail::FileSystemMismatch { field, expected, found }) => {
                (*field, expected.as_deref(), found.as_deref())
            }
            other => panic!("{:?}", other),
        }
    }

    /// What is wrong with a label refused.
    fn label_problem(e: &Error) -> LabelProblem {
        assert_eq!(e.errno(), EINVAL);
        match e.detail() {
            Some(Detail::Label { problem, .. }) => *problem,
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn what_the_root_says() {
        assert_eq!(identity_from_root(&root("", "")), VolumeIdentity::default());
        let named = identity_from_root(&root(
            r#""fat-serial","fs-label","fs-uuid""#,
            r#""fatSerial":"1234-abcd","fsLabel":"ESP","fsUUID":"5678abcd-0000-4000-8000-000000000000""#,
        ));
        assert_eq!(
            named.serial(),
            Some((VolumeId(0x1234_abcd), FileSystemField::FatSerial))
        );
        assert_eq!(named.label(), &ManifestLabel::Labeled("ESP".into()));
        // Without fatSerial, the first four bytes of fsUUID.
        let uuid = identity_from_root(&root(
            r#""fs-uuid""#,
            r#""fsUUID":"5678ABCD-0000-4000-8000-000000000000""#,
        ));
        assert_eq!(uuid.serial(), Some((VolumeId(0x5678_abcd), FileSystemField::FsUuid)));
        assert_eq!(uuid.label(), &ManifestLabel::Unrecorded);
        // With fs-label listed, a manifest without fsLabel names no label,
        // and so does an empty fsLabel.
        for root in [root(r#""fs-label""#, ""), root(r#""fs-label""#, r#""fsLabel":"""#)] {
            assert_eq!(identity_from_root(&root).label(), &ManifestLabel::Unlabeled, "{}", root);
        }
    }

    #[test]
    fn reconciles_a_new_volume() {
        let named = identity_from_root(&root(
            r#""fat-serial","fs-label""#,
            r#""fatSerial":"1234-ABCD","fsLabel":"esp""#,
        ));
        // What the manifest names goes into the options.
        let mut options = FormatOptions::default();
        assert_eq!(named.reconcile(&mut options, None).unwrap(), SerialSource::Given);
        assert_eq!(
            (options.volume_id, options.label.as_deref()),
            (0x1234_abcd, Some("esp"))
        );
        // The same values given are fine, the label as FAT stores it.
        let mut options = FormatOptions {
            label: Some("esp   ".into()),
            ..FormatOptions::default()
        };
        assert_eq!(
            named.reconcile(&mut options, Some(VolumeId(0x1234_abcd))).unwrap(),
            SerialSource::Given
        );
        // Other ones are not.
        let e = named
            .reconcile(&mut FormatOptions::default(), Some(VolumeId(0x1111_2222)))
            .unwrap_err();
        assert_eq!(e.errno(), EINVAL);
        assert_eq!(
            mismatch_fields(&e),
            (FileSystemField::FatSerial, Some("1234-ABCD"), Some("1111-2222"))
        );
        assert_eq!(
            e.message(),
            "the identifier 1111-2222 differs from the serial number 1234-ABCD the manifest gives in fatSerial"
        );
        let mut options = FormatOptions {
            label: Some("ESP".into()),
            ..FormatOptions::default()
        };
        let e = named.reconcile(&mut options, None).unwrap_err();
        assert_eq!(
            mismatch_fields(&e),
            (FileSystemField::FsLabel, Some("esp"), Some("ESP"))
        );
        assert_eq!(
            e.message(),
            "the label 'ESP' differs from the label 'esp' the manifest gives in fsLabel"
        );
        // The serial number derived from fsUUID is named by its field, and
        // written as serial numbers are.
        let uuid = identity_from_root(&root(
            r#""fs-uuid""#,
            r#""fsUUID":"5678abcd-0000-4000-8000-000000000000""#,
        ));
        let e = uuid
            .reconcile(&mut FormatOptions::default(), Some(VolumeId(1)))
            .unwrap_err();
        assert_eq!(
            mismatch_fields(&e),
            (FileSystemField::FsUuid, Some("5678-ABCD"), Some("0000-0001"))
        );
        // Without a serial number from the manifest, the one given, and
        // without that the one derived from the manifest. A label the
        // manifest does not record is the one given.
        let nothing = VolumeIdentity::default();
        let mut options = FormatOptions {
            label: Some("MINE".into()),
            ..FormatOptions::default()
        };
        assert_eq!(
            nothing.reconcile(&mut options, Some(VolumeId(7))).unwrap(),
            SerialSource::Given
        );
        assert_eq!((options.volume_id, options.label.as_deref()), (7, Some("MINE")));
        assert_eq!(nothing.reconcile(&mut options, None).unwrap(), SerialSource::Derived);
        // A manifest that names no label makes a volume without one, and a
        // label given is one too many.
        for unlabeled in [root(r#""fs-label""#, ""), root(r#""fs-label""#, r#""fsLabel":"""#)] {
            let unlabeled = identity_from_root(&unlabeled);
            let mut options = FormatOptions {
                label: Some("ESP".into()),
                ..FormatOptions::default()
            };
            let e = unlabeled.reconcile(&mut options, None).unwrap_err();
            assert_eq!(mismatch_fields(&e), (FileSystemField::FsLabel, None, Some("ESP")));
            assert_eq!(
                e.message(),
                "the label 'ESP' differs from the manifest, which gives the file system no label (fsLabel)"
            );
            for given in [None, Some(""), Some("NO NAME")] {
                let mut options = FormatOptions {
                    label: given.map(str::to_string),
                    ..FormatOptions::default()
                };
                unlabeled.reconcile(&mut options, None).unwrap();
                assert_eq!(options.label, None, "{:?}", given);
            }
        }
        // A label FAT cannot store, or would report as another label or as
        // none, is refused: blkid shows a FAT label without the spaces at
        // its end, and nothing for the blank label and NO NAME.
        for (label, problem) in [
            ("much too long", LabelProblem::TooLong),
            ("TEST ", LabelProblem::InvalidCharacter),
            ("   ", LabelProblem::Reserved),
            ("NO NAME", LabelProblem::Reserved),
        ] {
            let identity = identity_from_root(&root(r#""fs-label""#, &format!(r#""fsLabel":"{}""#, label)));
            let e = identity.reconcile(&mut FormatOptions::default(), None).unwrap_err();
            assert_eq!(label_problem(&e), problem, "{:?}", label);
        }
    }

    #[test]
    fn checks_a_volume() {
        // The test volume has the serial number 1234-ABCD and the label
        // TEST.
        let (_img, v) = volume(8 << 20, 512, 512);
        assert_eq!(format_options(512, 512).volume_id, 0x1234_abcd);
        for fits in [
            root("", ""),
            root(
                r#""fat-serial","fs-label""#,
                r#""fatSerial":"1234-abcd","fsLabel":"TEST""#,
            ),
            root(r#""fs-uuid""#, r#""fsUUID":"1234abcd-0000-4000-8000-000000000000""#),
        ] {
            identity_from_root(&fits).check(&v).unwrap();
        }
        let e = identity_from_root(&root(r#""fat-serial""#, r#""fatSerial":"1234-ABCE""#))
            .check(&v)
            .unwrap_err();
        assert_eq!(
            mismatch_fields(&e),
            (FileSystemField::FatSerial, Some("1234-ABCE"), Some("1234-ABCD"))
        );
        assert_eq!(
            e.message(),
            "the file system has the serial number 1234-ABCD, the manifest is for 1234-ABCE (fatSerial)"
        );
        let e = identity_from_root(&root(r#""fs-label""#, r#""fsLabel":"test""#))
            .check(&v)
            .unwrap_err();
        assert_eq!(
            mismatch_fields(&e),
            (FileSystemField::FsLabel, Some("test"), Some("TEST"))
        );
        // A manifest that names no label is not for a volume with one.
        let e = identity_from_root(&root(r#""fs-label""#, "")).check(&v).unwrap_err();
        assert_eq!(mismatch_fields(&e), (FileSystemField::FsLabel, None, Some("TEST")));
        assert_eq!(
            e.message(),
            "the file system has the label 'TEST', the manifest is for one without a label (fsLabel)"
        );
        // A label no FAT volume reports is refused as such, whatever the
        // volume has: one FAT cannot store, one with a space at its end,
        // which blkid shows without it, and the blank label and NO NAME,
        // which it shows as no label.
        for (label, problem) in [
            ("much too long", LabelProblem::TooLong),
            ("TEST ", LabelProblem::InvalidCharacter),
            ("   ", LabelProblem::Reserved),
            ("NO NAME", LabelProblem::Reserved),
        ] {
            let identity = identity_from_root(&root(r#""fs-label""#, &format!(r#""fsLabel":"{}""#, label)));
            assert_eq!(label_problem(&identity.check(&v).unwrap_err()), problem, "{:?}", label);
        }
        // A label the manifest names on a volume without one.
        let img = TempImage::new(8 << 20);
        let options = FormatOptions {
            label: None,
            ..format_options(512, 512)
        };
        format(&img.device(), &options).unwrap();
        let unlabeled = Volume::open(img.device()).unwrap();
        let e = identity_from_root(&root(r#""fs-label""#, r#""fsLabel":"TEST""#))
            .check(&unlabeled)
            .unwrap_err();
        assert_eq!(mismatch_fields(&e), (FileSystemField::FsLabel, Some("TEST"), None));
        assert_eq!(
            e.message(),
            "the file system has no label, the manifest is for 'TEST' (fsLabel)"
        );
        for fits in [root(r#""fs-label""#, ""), root(r#""fs-label""#, r#""fsLabel":"""#)] {
            identity_from_root(&fits).check(&unlabeled).unwrap();
        }
        // A label in the boot sector only is no label: the volume's label is
        // the one of its root directory, where blkid reads it.
        drop(unlabeled);
        img.device()
            .write_at(crate::boot::field::VOLUME_LABEL.start as u64, b"TEST       ")
            .unwrap();
        let boot_only = Volume::open(img.device()).unwrap();
        identity_from_root(&root(r#""fs-label""#, ""))
            .check(&boot_only)
            .unwrap();
        let e = identity_from_root(&root(r#""fs-label""#, r#""fsLabel":"TEST""#))
            .check(&boot_only)
            .unwrap_err();
        assert_eq!(mismatch_fields(&e), (FileSystemField::FsLabel, Some("TEST"), None));
    }

    #[test]
    fn the_serial_number_of_a_manifest() {
        // The first eight hex digits of the hash are those of the serial
        // number.
        let digest = Sha256::digest(b"a manifest");
        let serial = VolumeId::from_manifest_digest(&digest);
        let hex = digest.to_string();
        assert_eq!(
            serial.to_string(),
            format!("{}-{}", &hex[..4], &hex[4..8]).to_uppercase()
        );
        assert_eq!(VolumeId::from(FatSerial(0x1234_abcd)), VolumeId(0x1234_abcd));
        assert_eq!(SerialSource::Given.derived_serial(Some(digest)).unwrap(), None);
        assert_eq!(
            SerialSource::Derived.derived_serial(Some(digest)).unwrap(),
            Some(serial)
        );
        assert_eq!(SerialSource::Derived.derived_serial(None).unwrap_err().errno(), EIO);
    }

    /// The fields that name the volume are spelt as the manifest spells
    /// them.
    #[test]
    fn file_system_fields() {
        for (field, named) in [
            (FileSystemField::FatSerial, Field::FatSerial),
            (FileSystemField::FsUuid, Field::FsUuid),
            (FileSystemField::FsLabel, Field::FsLabel),
        ] {
            assert_eq!(field.as_str(), named.as_str());
        }
    }
}
