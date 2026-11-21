// SPDX-License-Identifier: LGPL-2.1-or-later
//! The rules for the file objects of a manifest one after the other: which
//! fields each of them may have, and where it may come.

use crate::decode::Subject;
use crate::error::{Error, Field, Problem};
use crate::name::NamePair;
use crate::{Features, FileObject, InodeType, Order, RootObject};

/// The check of the file objects of a manifest one after the other: what
/// it keeps of the objects up to the last one to check the next one
/// against.
///
/// The file objects of a manifest are in tree order: a directory comes
/// before the objects below it, and these come right after it. So the
/// directories more objects may still be in are the root, the directories
/// the last object is in, and the last object if it is a directory. The
/// name of the last object is all that has to be kept, at most
/// [`Name::MAX_LEN`](crate::Name::MAX_LEN) bytes. That also finds a name
/// that comes again right after the entries of the directory it names,
/// and with the code point ordering every name that comes twice.
#[derive(Debug)]
pub(crate) struct SequenceCheck {
    /// What the manifest records.
    features: Features,
    /// The order the manifest declares, which the objects have to be in.
    order: Option<Order>,
    /// The name of the last file object. The root file object's is empty.
    last: String,
    /// The inode type of the last file object. The root file object is a
    /// directory.
    last_type: InodeType,
}

impl SequenceCheck {
    /// The check of the file objects of a manifest that records `features`
    /// and lists its file objects in `order`, after its root file object.
    pub(crate) fn new(features: Features, order: Option<Order>) -> SequenceCheck {
        SequenceCheck {
            features,
            order,
            last: String::new(),
            last_type: InodeType::Directory,
        }
    }

    /// What the manifest records.
    pub(crate) fn features(&self) -> Features {
        self.features
    }

    /// Checks the fields of the root file object `root`: they have to be of
    /// features the manifest records. The error names the first field of a
    /// feature the manifest does not record.
    pub(crate) fn check_root_fields(&self, root: &RootObject) -> Result<(), Error> {
        self.check_features_listed(root.feature_fields(), Subject::root())
    }

    /// Checks the fields of `object`, the one of the record with the number
    /// `record_number`, against what the manifest records: they have to be
    /// of features the manifest records, the fields a reader filled in
    /// aside, a symbolic link has its target in a manifest that records
    /// them, and the flags of a partition agree, see
    /// [`FileObject::check_partition_flags`]. The error names the first
    /// field of a feature the manifest does not record.
    pub(crate) fn check_fields(&self, object: &FileObject, record_number: u64) -> Result<(), Error> {
        let subject = Subject::new(object, record_number);
        self.check_features_listed(object.feature_fields(), subject)?;
        let target = object.contents.iter().any(|contents| contents.literal().is_some());
        if self.features.contains(Features::SYMLINK) && object.inode_type == InodeType::Symlink && !target {
            return Err(Error::manifest(
                Problem::NoTarget,
                format!(
                    "{}: the manifest records the targets of symbolic links, but this one has none",
                    subject
                ),
            ));
        }
        object.check_partition_flags(self.features, subject)
    }

    /// Checks that the manifest records the feature of every one of
    /// `fields`, the fields of the object `subject` names that belong to a
    /// feature, each with its feature. The error names the first one it
    /// does not record.
    fn check_features_listed(
        &self,
        mut fields: impl Iterator<Item = (Field, Features)>,
        subject: Subject<'_>,
    ) -> Result<(), Error> {
        let Some((field, feature)) = fields.find(|(_, feature)| !self.features.contains(*feature)) else {
            return Ok(());
        };
        Err(Error::manifest(
            Problem::UnlistedFeature,
            format!(
                "{}: '{}' is a field of the feature '{}', which the manifest does not record",
                subject,
                field,
                feature.names().next().unwrap_or_default()
            ),
        )
        .at(field))
    }

    /// Checks that `object`, the file object of the record with the number
    /// `record_number`, which comes after the root file object, may come
    /// next, and makes it the last one.
    pub(crate) fn admit(&mut self, object: &FileObject, record_number: u64) -> Result<(), Error> {
        let name = object.name.as_str();
        if object.name.is_root() {
            return Ok(());
        }
        let subject = Subject::new(object, record_number);
        // The first byte in which the name differs from that of the last
        // object settles each of the checks, so the two names are looked
        // at once.
        let pair = NamePair::new(&self.last, name);
        if !pair.second_is_in_open_directory(self.last_type) {
            let directory = object.name.parent().unwrap_or_default();
            return Err(Error::manifest(
                Problem::Misplaced,
                format!(
                    "{}: does not come right after the object of its directory '{}'",
                    subject,
                    directory.escape_debug()
                ),
            ));
        }
        // The entry of the directory of this object that came last is the
        // last object or a directory it is in. If that is this object, its
        // name comes twice.
        if pair.second_is_first_or_above() {
            return Err(Error::manifest(
                Problem::DuplicateName,
                format!("{}: the name is listed twice", subject),
            ));
        }
        if self.order == Some(Order::CodePoint) && pair.ordering().is_ge() {
            return Err(Error::manifest(
                Problem::OutOfOrder,
                format!(
                    "{}: comes after '{}', which it sorts before in the code point ordering",
                    subject,
                    self.last.escape_debug()
                ),
            ));
        }
        self.last.clear();
        self.last.push_str(name);
        self.last_type = object.inode_type;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::testing::full_tree_names;
    use crate::{Contents, DosFlags, FatSerial, InodeFlags, Location, Mode, Name, Uuid};
    use std::num::NonZeroU64;

    /// Gives an object a field.
    type Give<T> = fn(&mut T);

    fn object(name: &str, inode_type: InodeType) -> FileObject {
        let mut object = FileObject::new(Name::new(name).unwrap());
        object.inode_type = inode_type;
        object
    }

    /// Admits the objects `names`, directories where they end in a slash,
    /// and returns the problem of the first one that is not admitted.
    fn first_problem(order: Option<Order>, names: &[&str]) -> Option<(usize, Problem)> {
        let mut check = SequenceCheck::new(Features::DEFAULT, order);
        for (i, name) in names.iter().enumerate() {
            let object = match name.strip_suffix('/') {
                Some(dir) => object(dir, InodeType::Directory),
                None => object(name, InodeType::Regular),
            };
            if let Err(e) = check.admit(&object, i as u64 + 1) {
                let ErrorKind::Manifest(problem) = e.kind() else {
                    panic!("{}", e);
                };
                return Some((i, problem));
            }
        }
        None
    }

    #[test]
    fn tree_order() {
        for names in [
            &["a/", "a/b/", "a/b/c", "a/d", "e"][..],
            &["a", "b", "c"],
            &["z/", "z/y/", "z/y/x/", "z/y/x/w", "a"],
            &["a-b", "a/", "a/x"],
        ] {
            assert_eq!(first_problem(None, names), None, "{:?}", names);
        }
        for (names, at) in [
            // A directory that is not listed, or whose entries ended.
            (&["a/x"][..], 0),
            (&["a/", "b", "a/x"], 2),
            (&["a/", "a/b/", "a/b/c", "a/d", "a/b/e"], 4),
            // A file is no directory.
            (&["a", "a/x"], 1),
        ] {
            assert_eq!(
                first_problem(None, names),
                Some((at, Problem::Misplaced)),
                "{:?}",
                names
            );
        }
    }

    #[test]
    fn repeated_names() {
        // The previous entry of the directory is found also after the
        // entries of a directory.
        for (names, at) in [
            (&["a", "a"][..], 1),
            (&["a/", "a/b/", "a/b/c", "a/b/"], 3),
            (&["d/", "d/x", "d/"], 2),
        ] {
            assert_eq!(
                first_problem(None, names),
                Some((at, Problem::DuplicateName)),
                "{:?}",
                names
            );
        }
        // Without an order a name that comes again later is not found.
        assert_eq!(first_problem(None, &["a", "b", "a"]), None);
        assert_eq!(
            first_problem(Some(Order::CodePoint), &["a", "b", "a"]),
            Some((2, Problem::OutOfOrder))
        );
    }

    #[test]
    fn code_point_order() {
        let order = Some(Order::CodePoint);
        assert_eq!(first_problem(order, &["a/", "a/x", "a-b", "a0", "b/", "b/c"]), None);
        assert_eq!(
            first_problem(order, &["a-b", "a/", "a/x"]),
            Some((1, Problem::OutOfOrder))
        );
        assert_eq!(first_problem(order, &["b", "a"]), Some((1, Problem::OutOfOrder)));
        assert_eq!(first_problem(order, &["\u{ff61}", "\u{1f600}"]), None);
        assert_eq!(
            first_problem(order, &["\u{1f600}", "\u{ff61}"]),
            Some((1, Problem::OutOfOrder))
        );
    }

    /// What the specification says of an object of the name `name` right
    /// after one of the name `last` and the type `last_type`, with the
    /// components of the names compared one by one.
    fn by_the_definition(last: &Name, last_type: InodeType, name: &Name, order: Option<Order>) -> Option<Problem> {
        let last: Vec<&str> = last.components().collect();
        let name: Vec<&str> = name.components().collect();
        let directory = &name[..name.len() - 1];
        // The directories that are open: the root, those the last object
        // is in, and the last object itself if it is a directory.
        if !(last.starts_with(directory) && (last_type == InodeType::Directory || directory.len() < last.len())) {
            return Some(Problem::Misplaced);
        }
        // The name of the last object, or of a directory it is in.
        if last.starts_with(&name) {
            return Some(Problem::DuplicateName);
        }
        (order == Some(Order::CodePoint) && last >= name).then_some(Problem::OutOfOrder)
    }

    /// Every object of a name of a few components may come after every
    /// other one where the specification says so, and only there.
    #[test]
    fn checks_by_the_definition() {
        let names = full_tree_names(&["a", "ab", "a b", "a-b", "a.b", "\u{e9}"], 3);
        for order in [None, Some(Order::CodePoint)] {
            for last in &names {
                for last_type in [InodeType::Regular, InodeType::Directory] {
                    // The root is a directory.
                    if last.is_root() && last_type != InodeType::Directory {
                        continue;
                    }
                    for name in names.iter().filter(|name| !name.is_root()) {
                        let mut check = SequenceCheck::new(Features::DEFAULT, order);
                        check.last = last.to_string();
                        check.last_type = last_type;
                        let object = FileObject::new(name.clone());
                        let problem = check.admit(&object, 1).err().map(|e| e.kind());
                        let expected = by_the_definition(last, last_type, name, order).map(ErrorKind::Manifest);
                        assert_eq!(problem, expected, "{:?} {:?} {:?} {:?}", last, last_type, name, order);
                    }
                }
            }
        }
    }

    #[test]
    fn fields() {
        let check = SequenceCheck::new(Features::SIZE | Features::SYMLINK, None);
        let mut file = object("f", InodeType::Regular);
        file.size = Some(1);
        assert!(check.check_fields(&file, 1).is_ok());
        // A field of a feature the manifest does not record is named.
        file.inode.mtime_nsec = Some(1);
        let e = check.check_fields(&file, 1).unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::UnlistedFeature), Some(Field::MTimeNSec))
        );
        assert_eq!(
            e.to_string(),
            "manifest object 1 (f): 'mTimeNSec' is a field of the feature 'mtime', which the manifest does not record"
        );
        // The field the feature has: for the device numbers the one of the
        // two the object has, for symbolic links the target in `contents`.
        let none = SequenceCheck::new(Features::NONE, None);
        let cases: [(InodeType, Give<FileObject>, Field); 8] = [
            (InodeType::Regular, |o| o.inode.mode = Mode::new(0o644), Field::Mode),
            (InodeType::CharDevice, |o| o.major = Some(1), Field::Major),
            (InodeType::BlockDevice, |o| o.minor = Some(1), Field::Minor),
            (
                InodeType::Regular,
                |o| o.inode.user_xattrs = Some(Box::default()),
                Field::ExtendedAttributes,
            ),
            (
                InodeType::Regular,
                |o| o.dos_flags.put(DosFlags::HIDDEN, Some(false)),
                Field::FlagHidden,
            ),
            (
                InodeType::Regular,
                |o| o.inode_token = NonZeroU64::new(1),
                Field::InodeToken,
            ),
            (
                InodeType::Directory,
                |o| o.inode.group_name = Some("g".into()),
                Field::GroupName,
            ),
            (
                InodeType::Symlink,
                |o| o.contents = vec![Contents::new(Location::Literal(b"t".to_vec()))],
                Field::Contents,
            ),
        ];
        for (inode_type, set, field) in cases {
            let mut o = object("o", inode_type);
            set(&mut o);
            let e = none.check_fields(&o, 1).unwrap_err();
            assert_eq!(e.field(), Some(field), "{:?}", o);
        }
        let link = object("l", InodeType::Symlink);
        let e = check.check_fields(&link, 2).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoTarget));
        assert!(e.to_string().starts_with("manifest object 2 (l): "), "{}", e);
        let quiet = SequenceCheck::new(Features::SIZE, None);
        assert!(quiet.check_fields(&link, 2).is_ok());
        // The root file object has the fields of features too.
        let mut root = RootObject::default();
        assert!(none.check_root_fields(&root).is_ok());
        root.inode.uid = Some(0);
        let e = none.check_root_fields(&root).unwrap_err();
        assert_eq!(
            (e.kind(), e.field()),
            (ErrorKind::Manifest(Problem::UnlistedFeature), Some(Field::Uid))
        );
        assert_eq!(
            e.to_string(),
            "manifest object 0 (root): 'uid' is a field of the feature 'uid', which the manifest does not record"
        );
    }

    /// Of several fields of features the manifest does not record, the
    /// error names the first: those of the object itself in the order of
    /// their names, then the DOS attributes, then the inode attributes and
    /// last the inode flags. Each field given here comes before those given
    /// before it.
    #[test]
    fn the_first_unlisted_field() {
        let none = SequenceCheck::new(Features::NONE, None);
        let mut object = object("o", InodeType::Regular);
        let fields: [(Give<FileObject>, Field); 14] = [
            (
                |o| o.inode.flags.put(InodeFlags::NO_DUMP, Some(true)),
                Field::FlagNoDump,
            ),
            (
                |o| o.inode.flags.put(InodeFlags::APPEND_ONLY, Some(false)),
                Field::FlagAppendOnly,
            ),
            (|o| o.inode.user_name = Some("u".into()), Field::UserName),
            (|o| o.inode.read_only = Some(true), Field::ReadOnly),
            (|o| o.inode.mode = Mode::new(0o444), Field::Mode),
            (
                |o| o.inode.user_xattrs = Some(Box::default()),
                Field::ExtendedAttributes,
            ),
            (|o| o.dos_flags.put(DosFlags::SYSTEM, Some(true)), Field::FlagSystem),
            (|o| o.dos_flags.put(DosFlags::ARCHIVE, Some(false)), Field::FlagArchive),
            (|o| o.size = Some(1), Field::Size),
            (|o| o.major = Some(1), Field::Major),
            (|o| o.inode_token = NonZeroU64::new(1), Field::InodeToken),
            (
                |o| o.gpt.get_or_insert_with(Box::default).label = Some("l".into()),
                Field::GptLabel,
            ),
            (
                |o| o.gpt.get_or_insert_with(Box::default).flags = Some(0),
                Field::GptFlags,
            ),
            (
                |o| o.gpt.get_or_insert_with(Box::default).grow_file_system = Some(false),
                Field::GptFlagGrowFileSystem,
            ),
        ];
        for (give, field) in fields {
            give(&mut object);
            assert_eq!(none.check_fields(&object, 1).unwrap_err().field(), Some(field));
        }
        let mut root = RootObject::default();
        let fields: [(Give<RootObject>, Field); 6] = [
            (|r| r.inode.flags.put(InodeFlags::NO_COW, Some(true)), Field::FlagNoCow),
            (|r| r.inode.uid = Some(0), Field::Uid),
            (|r| r.inode.read_only = Some(false), Field::ReadOnly),
            (
                |r| r.gpt_disk_uuid = Some(Uuid::new([1; Uuid::SIZE])),
                Field::GptDiskUuid,
            ),
            (|r| r.file_system.label = Some("ESP".into()), Field::FsLabel),
            (|r| r.file_system.fat_serial = Some(FatSerial(1)), Field::FatSerial),
        ];
        for (give, field) in fields {
            give(&mut root);
            assert_eq!(none.check_root_fields(&root).unwrap_err().field(), Some(field));
        }
    }
}
