// SPDX-License-Identifier: LGPL-2.1-or-later
//! What a manifest says about itself in its root file object: the features
//! it records and the order it lists its file objects in.

use std::fmt;
use std::ops::{BitAnd, BitOr, BitOrAssign};
use std::str::FromStr;

/// The file system and partition table features a manifest records, which
/// its root file object lists in the field `features`.
///
/// A feature stands for fields of the file objects and of the root file
/// object: `mtime` for `mTimeNSec`, `device` for `major` and `minor`,
/// `fs-uuid` for `fsUUID`. An object carries the fields of the features its
/// manifest lists and no others. For some features the list also says what
/// a missing field means: with [`Features::HARDLINK`] a file object without
/// an `inodeToken` is not a hard link of another one, with
/// [`Features::USER_XATTR`] one without extended attributes has none, and
/// with [`Features::FS_LABEL`] a root file object without `fsLabel` is for
/// a file system without a label. With [`Features::GPT_FLAGS`] a partition
/// without `gptFlags` has all its attribute flags cleared, and with
/// [`Features::READ_ONLY`] or the feature of a single flag, such as
/// [`Features::FLAG_HIDDEN`] or [`Features::GPT_FLAG_NO_AUTO`], an object
/// without the field has that flag cleared. Where the list doesn't name the
/// feature, nothing is known about these properties.
///
/// A manifest that does not list its features records
/// [`Features::DEFAULT`], what `systemd-manifest make` records unless it
/// is told otherwise.
///
/// ```
/// use uapi16::Features;
///
/// let features = Features::SIZE | Features::SHA256;
/// assert!(features.contains(Features::SIZE) && !features.contains(Features::MTIME));
/// assert_eq!(Features::from_names(["size", "sha256"]), Ok(features));
/// assert_eq!(features.names().collect::<Vec<_>>(), ["sha256", "size"]);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Features(u32);

/// A name that is not the name of a feature, see [`Features`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownFeature(());

impl fmt::Display for UnknownFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a feature of a manifest")
    }
}

impl std::error::Error for UnknownFeature {}

impl Features {
    /// `mode`: the access mode, the field `mode`.
    pub const MODE: Features = Features(1 << 0);
    /// `uid`: the owning user, the field `uid`.
    pub const UID: Features = Features(1 << 1);
    /// `gid`: the owning group, the field `gid`.
    pub const GID: Features = Features(1 << 2);
    /// `user-name`: the name of the owning user, the field `userName`.
    pub const USER_NAME: Features = Features(1 << 3);
    /// `group-name`: the name of the owning group, the field `groupName`.
    pub const GROUP_NAME: Features = Features(1 << 4);
    /// `size`: the size of the contents, the field `size`.
    pub const SIZE: Features = Features(1 << 5);
    /// `sha256`: the hash of the contents, the field `sha256`.
    pub const SHA256: Features = Features(1 << 6);
    /// `symlink`: the targets of symbolic links, the field `contents` of
    /// file objects of the type `lnk`. Every one of them has its target in
    /// `contents` then, as a literal.
    pub const SYMLINK: Features = Features(1 << 7);
    /// `device`: the numbers of device nodes, the fields `major` and
    /// `minor`.
    pub const DEVICE: Features = Features(1 << 8);
    /// `hardlink`: which file objects are names of one file, the field
    /// `inodeToken`.
    pub const HARDLINK: Features = Features(1 << 9);
    /// `mtime`: the modification time, the field `mTimeNSec`.
    pub const MTIME: Features = Features(1 << 10);
    /// `user-xattr`: the extended attributes of the `user` namespace, the
    /// key `user` of the field `extendedAttributes`.
    pub const USER_XATTR: Features = Features(1 << 11);
    /// `flag-hidden`: the DOS attribute hidden, the field `flagHidden`.
    pub const FLAG_HIDDEN: Features = Features(1 << 12);
    /// `flag-system`: the DOS attribute system, the field `flagSystem`.
    pub const FLAG_SYSTEM: Features = Features(1 << 13);
    /// `flag-archive`: the DOS attribute archive, the field `flagArchive`.
    pub const FLAG_ARCHIVE: Features = Features(1 << 14);
    /// `flag-append-only`: the inode flag append only, the field
    /// `flagAppendOnly`.
    pub const FLAG_APPEND_ONLY: Features = Features(1 << 15);
    /// `flag-immutable`: the inode flag immutable, the field
    /// `flagImmutable`.
    pub const FLAG_IMMUTABLE: Features = Features(1 << 16);
    /// `flag-no-atime`: the inode flag no atime updates, the field
    /// `flagNoAtime`.
    pub const FLAG_NO_ATIME: Features = Features(1 << 17);
    /// `flag-no-cow`: the inode flag no copy on write, the field
    /// `flagNoCow`.
    pub const FLAG_NO_COW: Features = Features(1 << 18);
    /// `flag-no-dump`: the inode flag no dump, the field `flagNoDump`.
    pub const FLAG_NO_DUMP: Features = Features(1 << 19);
    /// `read-only`: whether a file is read-only, the field `readOnly`.
    pub const READ_ONLY: Features = Features(1 << 20);
    /// `fs-uuid`: the UUID of the file system, the field `fsUUID`.
    pub const FS_UUID: Features = Features(1 << 21);
    /// `fs-label`: the label of the file system, the field `fsLabel`.
    pub const FS_LABEL: Features = Features(1 << 22);
    /// `fat-serial`: the volume serial number of a FAT or exFAT file
    /// system, the field `fatSerial`.
    pub const FAT_SERIAL: Features = Features(1 << 23);
    /// `gpt-label`: the label of a partition, the field `gptLabel`.
    pub const GPT_LABEL: Features = Features(1 << 24);
    /// `gpt-uuid`: the UUID of a partition, the field `gptUuid`.
    pub const GPT_UUID: Features = Features(1 << 25);
    /// `gpt-type-uuid`: the type UUID of a partition, the field
    /// `gptTypeUuid`.
    pub const GPT_TYPE_UUID: Features = Features(1 << 26);
    /// `gpt-disk-uuid`: the disk UUID of the partition table, the field
    /// `gptDiskUuid`.
    pub const GPT_DISK_UUID: Features = Features(1 << 27);
    /// `gpt-flags`: the attribute flags of a partition, the field
    /// `gptFlags`.
    pub const GPT_FLAGS: Features = Features(1 << 28);
    /// `gpt-flag-no-auto`: the partition attribute flag no auto, the field
    /// `gptFlagNoAuto`.
    pub const GPT_FLAG_NO_AUTO: Features = Features(1 << 29);
    /// `gpt-flag-grow-file-system`: the partition attribute flag grow file
    /// system, the field `gptFlagGrowFileSystem`.
    pub const GPT_FLAG_GROW_FILE_SYSTEM: Features = Features(1 << 30);

    /// No feature: the file objects carry names, inode types and the
    /// fields that belong to no feature.
    pub const NONE: Features = Features(0);
    /// What a manifest records that does not list its features, as the
    /// specification says: the access mode, the owner, size and hash, the
    /// targets of symbolic links, device numbers and hard links.
    pub const DEFAULT: Features = Features(
        Features::DEVICE.0
            | Features::GID.0
            | Features::HARDLINK.0
            | Features::MODE.0
            | Features::SHA256.0
            | Features::SIZE.0
            | Features::SYMLINK.0
            | Features::UID.0,
    );
    /// Every feature.
    pub const ALL: Features = Features((1 << Features::NAMES.len()) - 1);

    /// Every single feature with its name, in the order of the names.
    const NAMES: [(Features, &'static str); 31] = [
        (Features::DEVICE, "device"),
        (Features::FAT_SERIAL, "fat-serial"),
        (Features::FLAG_APPEND_ONLY, "flag-append-only"),
        (Features::FLAG_ARCHIVE, "flag-archive"),
        (Features::FLAG_HIDDEN, "flag-hidden"),
        (Features::FLAG_IMMUTABLE, "flag-immutable"),
        (Features::FLAG_NO_ATIME, "flag-no-atime"),
        (Features::FLAG_NO_COW, "flag-no-cow"),
        (Features::FLAG_NO_DUMP, "flag-no-dump"),
        (Features::FLAG_SYSTEM, "flag-system"),
        (Features::FS_LABEL, "fs-label"),
        (Features::FS_UUID, "fs-uuid"),
        (Features::GID, "gid"),
        (Features::GPT_DISK_UUID, "gpt-disk-uuid"),
        (Features::GPT_FLAG_GROW_FILE_SYSTEM, "gpt-flag-grow-file-system"),
        (Features::GPT_FLAG_NO_AUTO, "gpt-flag-no-auto"),
        (Features::GPT_FLAGS, "gpt-flags"),
        (Features::GPT_LABEL, "gpt-label"),
        (Features::GPT_TYPE_UUID, "gpt-type-uuid"),
        (Features::GPT_UUID, "gpt-uuid"),
        (Features::GROUP_NAME, "group-name"),
        (Features::HARDLINK, "hardlink"),
        (Features::MODE, "mode"),
        (Features::MTIME, "mtime"),
        (Features::READ_ONLY, "read-only"),
        (Features::SHA256, "sha256"),
        (Features::SIZE, "size"),
        (Features::SYMLINK, "symlink"),
        (Features::UID, "uid"),
        (Features::USER_NAME, "user-name"),
        (Features::USER_XATTR, "user-xattr"),
    ];

    /// Whether every feature of `features` is among these.
    pub const fn contains(self, features: Features) -> bool {
        self.0 & features.0 == features.0
    }

    /// These features without those of `features`.
    #[must_use]
    pub const fn without(self, features: Features) -> Features {
        Features(self.0 & !features.0)
    }

    /// These features and those of `features`.
    #[must_use]
    pub const fn union(self, features: Features) -> Features {
        Features(self.0 | features.0)
    }

    /// The features with the names `names`, the names the specification
    /// has for them.
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Result<Features, UnknownFeature> {
        names
            .into_iter()
            .try_fold(Features::NONE, |features, name| Ok(features | name.parse()?))
    }

    /// The names of the features as the specification has them, in the
    /// order of the strings, as `features` lists them.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Features::NAMES
            .iter()
            .filter(move |(feature, _)| self.contains(*feature))
            .map(|&(_, name)| name)
    }

    /// Takes the name of a feature from the list of a manifest: one of the
    /// names of the specification. A name the specification does not have
    /// is None, which a reader passes over.
    pub(crate) fn listed(name: &str) -> Option<Features> {
        Features::NAMES
            .into_iter()
            .find(|(_, known)| *known == name)
            .map(|(feature, _)| feature)
    }
}

impl Default for Features {
    /// [`Features::DEFAULT`].
    fn default() -> Features {
        Features::DEFAULT
    }
}

impl BitOr for Features {
    type Output = Features;

    fn bitor(self, other: Features) -> Features {
        Features(self.0 | other.0)
    }
}

impl BitOrAssign for Features {
    fn bitor_assign(&mut self, other: Features) {
        self.0 |= other.0;
    }
}

impl BitAnd for Features {
    type Output = Features;

    /// The features both have, those a tool that combines two manifests
    /// can keep.
    fn bitand(self, other: Features) -> Features {
        Features(self.0 & other.0)
    }
}

impl FromStr for Features {
    type Err = UnknownFeature;

    /// The one feature with the name `name`, as the specification names
    /// it.
    fn from_str(name: &str) -> Result<Features, UnknownFeature> {
        Features::listed(name).ok_or(UnknownFeature(()))
    }
}

impl fmt::Debug for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Features(")?;
        for (i, name) in self.names().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(name)?;
        }
        f.write_str(")")
    }
}

/// The order a manifest lists its file objects in, which its root file
/// object declares in the field `order`.
///
/// A manifest that declares an order keeps to it, and a reader that relies
/// on it checks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Order {
    /// `codepoint`: the names of the file objects strictly increase in the
    /// order of [`Name`](crate::Name).
    CodePoint,
}

impl Order {
    /// The value of `order` that declares this order.
    pub const fn as_str(self) -> &'static str {
        match self {
            Order::CodePoint => "codepoint",
        }
    }

    /// The order a value of `order` declares. A value the specification
    /// does not have declares none, as it asks.
    pub(crate) fn declared(value: &str) -> Option<Order> {
        (value == Order::CodePoint.as_str()).then_some(Order::CodePoint)
    }
}

impl fmt::Display for Order {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        // The names are in the order of the strings, as `features` lists
        // them, and every feature has one.
        let names: Vec<&str> = Features::ALL.names().collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert_eq!(names.len(), Features::NAMES.len());
        assert_eq!(Features::from_names(names.iter().copied()), Ok(Features::ALL));
        for (feature, name) in Features::NAMES {
            assert_eq!(name.parse(), Ok(feature));
            assert_eq!(Features::listed(name), Some(feature));
            assert_eq!(feature.names().collect::<Vec<_>>(), [name]);
        }
        assert_eq!(Features::from_names([]), Ok(Features::NONE));
        assert_eq!(Features::NONE.names().count(), 0);
        // Only the names of the specification, not the word systemd-manifest
        // has for sha256 on its command line.
        for unknown in [
            "",
            "Mode",
            "userXattr",
            "user_xattr",
            "flag-hidden ",
            "x",
            "hash",
            "readOnly",
            "gpt-flag",
        ] {
            assert_eq!(unknown.parse::<Features>(), Err(UnknownFeature(())), "{:?}", unknown);
            assert_eq!(Features::listed(unknown), None, "{:?}", unknown);
        }
        assert_eq!(Features::from_names(["size", "hash"]), Err(UnknownFeature(())));
    }

    #[test]
    fn the_default() {
        assert_eq!(
            Features::DEFAULT.names().collect::<Vec<_>>(),
            ["device", "gid", "hardlink", "mode", "sha256", "size", "symlink", "uid"]
        );
        assert_eq!(Features::default(), Features::DEFAULT);
    }

    #[test]
    fn sets() {
        let some = Features::from_names(["size", "sha256", "mtime", "size"]).unwrap();
        assert_eq!(some, Features::SIZE | Features::SHA256 | Features::MTIME);
        assert!(some.contains(Features::SIZE) && some.contains(Features::SIZE | Features::MTIME));
        assert!(!some.contains(Features::MODE) && !some.contains(Features::SIZE | Features::MODE));
        assert!(some.contains(Features::NONE) && Features::NONE.contains(Features::NONE));
        assert_eq!(some & Features::DEFAULT, Features::SIZE | Features::SHA256);
        let mut more = some;
        more |= Features::MODE;
        assert_eq!(more, some | Features::MODE);
        assert_eq!(format!("{:?}", some), "Features(mtime | sha256 | size)");
    }

    #[test]
    fn orders() {
        assert_eq!(Order::declared("codepoint"), Some(Order::CodePoint));
        for value in ["", "CodePoint", "alphabetical", "bytes", "codepoint "] {
            assert_eq!(Order::declared(value), None, "{:?}", value);
        }
        assert_eq!(Order::CodePoint.to_string(), "codepoint");
    }
}
