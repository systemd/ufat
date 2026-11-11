// SPDX-License-Identifier: LGPL-2.1-or-later
//! Adding to an archive that exists.
//!
//! An archive has no place to change in but its end. So what is added is
//! written where the trailer was, with a new trailer behind it, and the
//! result is one archive again that every reader takes.
//!
//! What an added entry does to an entry that is there is decided when the
//! archive is unpacked, by the rules of [`crate::tree`]: a file takes the
//! place of a file of its name. The earlier entry stays in the archive,
//! and its bytes with it, without ever being seen again. That is how the
//! kernel unpacks. GNU cpio and busybox keep the earlier of two entries
//! of the same age unless they are told to replace what is there (`-u`).
//!
//! Some things the kernel would do with an added entry are not what one
//! who adds it means, and those are refused here instead of being written:
//!
//! - a new file under one name of a hard-linked file. The kernel writes
//!   through to the file, which changes it under its other names too;
//! - a device node with another device number than the one that is there.
//!   The kernel keeps the old node and gives it the new owner and mode;
//! - a file where a directory is. The kernel loses the file when the
//!   directory has entries, and removes the directory when it has none;
//! - a directory where a file is. The kernel removes the file.
//!
//! A directory that is there is left as it is, as a copy into a file
//! system leaves it.
//!
//! Adding is not done in one step, and an archive has no state between
//! the old one and the new one. While entries are added the archive is
//! stopped, see [`SpliceSink`]: if adding is cut off, by a crash or by a
//! loss of power, the kernel unpacks what the archive held before or all
//! of what was added, never a part of it, and it says that unpacking
//! failed. cpio, bsdcpio and busybox fail on such an archive too. When
//! adding fails for a reason this crate gets to see, the archive is put
//! back as it was.
//!
//! All of this is held against kernels: tests/cpio_kernel.rs has the
//! rules, tests/cpio_made.rs has what this module writes, and
//! tests/crash/cpio/crash.rs has every state a crash can leave behind.

use crate::assemble::Report;
use crate::device::Device;
use crate::errno::*;
use crate::header::{Format, Kind, ALIGNMENT, TRAILER_LEN};
use crate::image::{Region, SpliceSink};
use crate::name::{Name, NameBuf};
use crate::plan::{Plan, Planned};
use crate::progress::Progress;
use crate::read::Source;
use crate::tree::{Inode, Tree};
use crate::write::{self, Cursor, Writer};
use crate::{Detail, Result};

/// How entries are added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    /// The archive ends at a multiple of this many bytes, as
    /// [`write::Options::end_alignment`].
    pub end_alignment: u32,
    /// The alignment of the contents of large files, as
    /// [`write::Options::data_alignment`].
    pub data_alignment: u32,
    /// Let a file take the place of one that is in the archive instead of
    /// failing with EEXIST.
    pub replace: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            end_alignment: write::DEFAULT_END_ALIGNMENT,
            data_alignment: 0,
            replace: true,
        }
    }
}

impl Tree {
    /// Whether the entry `planned` for `name` is written, given what the
    /// archive unpacks to: not when it is a directory that is there. An
    /// entry that cannot take the place of what is there is an error.
    fn admits(&self, name: Name<'_>, planned: &Planned, replace: bool) -> Result<bool> {
        let Some(existing) = self.get(name.as_bytes()) else {
            return Ok(true);
        };
        let at = Detail::from(name);
        match (existing.kind, planned.kind) {
            (Kind::Directory, Kind::Directory) => return Ok(false),
            (Kind::Directory, _) => bail!(EISDIR, at, "'{}' is a directory in the archive", name),
            (_, Kind::Directory) => bail!(ENOTDIR, at, "'{}' is not a directory in the archive", name),
            _ => {}
        }
        if !replace {
            bail!(EEXIST, at, "'{}' is in the archive", name);
        }
        if existing.nlink > 1 {
            bail!(
                EEXIST,
                at,
                "'{}' is one name of a hard-linked file in the archive, which cannot be replaced under one of its names",
                name
            );
        }
        if existing.kind == planned.kind && planned.kind.is_device() && existing.rdev != planned.rdev {
            bail!(
                EEXIST,
                at,
                "'{}' is a device node in the archive, and the kernel would keep its device number {}",
                name,
                existing.rdev
            );
        }
        Ok(true)
    }
}

/// What an archive is put back from when adding to it fails.
struct Before {
    /// Where the trailer is in the image.
    at: u64,
    /// The bytes that are there.
    trailer: Vec<u8>,
    /// The length of the image.
    len: u64,
}

impl Before {
    /// Puts the archive back as it was: the bytes where its trailer is,
    /// then NUL bytes over what was written behind them up to `end`, and
    /// the length the image had.
    fn restore(&self, device: &mut Device, end: u64) -> Result<()> {
        device.write_at(self.at, &self.trailer)?;
        device.sync_data()?;
        let from = self.at + self.trailer.len() as u64;
        let to = end.min(self.len);
        if to > from {
            device.zero(from, to - from)?;
        }
        device.shrink(self.len)?;
        device.sync_data()
    }
}

impl Plan {
    /// Adds what is planned to the archive at `offset` of the image
    /// `device`, in `size` bytes when a size is given and in what the
    /// image has or can be grown to otherwise. The archive stays in the
    /// header form it is in.
    ///
    /// Everything is checked before the archive is touched: that it is
    /// sound and one archive, that the plan fits what it unpacks to, and
    /// that there is room. A plan that adds nothing leaves the archive as
    /// it is. When writing fails, because a source changed or the image
    /// cannot take what is written, the archive is put back as it was.
    ///
    /// The contents of the files that are in the archive are not read. In
    /// the form with checksums one that does not hold makes the kernel
    /// stop before it gets to what was added. [`crate::check`] finds
    /// that.
    ///
    /// What the archive has already is taken out of the plan: a directory
    /// that is there is not written again.
    pub fn populate(
        &mut self,
        device: &mut Device,
        offset: u64,
        size: Option<u64>,
        options: &Options,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<Report> {
        let region = Region::new(device, offset, size)?;
        let room = region.len();
        let tree = Tree::open(&region)?;
        if tree.approximate() {
            bail!(
                EOPNOTSUPP,
                "the archive has entries with '..' in their names or below symbolic links: where they are unpacked is not known, so nothing can be added"
            );
        }
        let start = match tree.trailer_offset() {
            Some(start) if start % ALIGNMENT == 0 => start,
            _ => bail!(EUCLEAN, "the entries of the archive do not end at a multiple of four"),
        };
        // Behind the trailer there may be nothing but the NUL bytes that
        // pad the archive: what is added is written over them.
        if let Some(found) = region.first_nonzero(start.saturating_add(TRAILER_LEN).min(room))? {
            bail!(
                EOPNOTSUPP,
                "something follows the trailer of the archive at offset {}: adding to the archive would overwrite it",
                found
            );
        }
        let mut refused = None;
        self.retain(&mut |name, planned| match tree.admits(name, planned, options.replace) {
            Ok(keep) => keep,
            Err(e) => {
                refused.get_or_insert(e);
                true
            }
        });
        if let Some(e) = refused {
            return Err(e);
        }
        let layout = write::Options {
            format: tree.format().unwrap_or(Format::Newc),
            end_alignment: options.end_alignment,
            data_alignment: options.data_alignment,
        };
        // Below a file of the archive nothing can go, whatever the plan
        // says.
        let file = |inode: &Inode| inode.kind != Kind::Directory;
        let blocked = self.steps().find_map(|step| {
            let parent = step.name.as_name().parent()?;
            tree.get(parent.as_bytes())
                .is_some_and(file)
                .then(|| NameBuf::from(parent))
        });
        if let Some(parent) = blocked {
            bail!(
                ENOTDIR,
                Detail::from(parent.as_name()),
                "'{}' is not a directory in the archive",
                parent
            );
        }
        let measure = self.measure(&layout, start, &|name| {
            tree.get(name.as_bytes())
                .is_some_and(|inode| inode.kind == Kind::Directory)
        })?;
        if self.is_empty() {
            // The archive as it is, with the padding it has up to the
            // alignment asked for.
            return Ok(Report {
                len: Cursor::new(layout, start).finish().min(room),
                ..Report::default()
            });
        }
        // Every entry gets a number above the ones the archive uses.
        let next_ino = match tree.max_ino().checked_add(1) {
            Some(next) if u64::from(next) + self.len() as u64 <= u64::from(u32::MAX) => next,
            _ => bail!(
                EOVERFLOW,
                "the archive uses inode numbers up to {}, which leaves none for what is added",
                tree.max_ino()
            ),
        };
        // What is where the trailer is, to put it back should writing fail.
        let mut before = Before {
            at: offset + start,
            trailer: vec![0u8; (room - start).min(TRAILER_LEN) as usize],
            len: 0,
        };
        region.read_at(start, &mut before.trailer)?;
        drop(tree);
        before.len = device.len();
        if measure.len > room {
            if size.is_some() || device.is_block_device() {
                bail!(
                    ENOSPC,
                    Detail::TooSmall {
                        minimal: measure.len,
                        actual: room,
                    },
                    "the archive needs {} bytes and the image has room for {}",
                    measure.len,
                    room
                );
            }
            let end = offset
                .checked_add(measure.len)
                .ok_or_else(|| err!(ERANGE, "the size of the image overflows"))?;
            device.grow(end)?;
        }
        let written = (|| -> Result<Report> {
            let sink = SpliceSink::new(device, before.at, measure.trailer - start)?;
            let mut writer = Writer::resume(sink, layout, start, next_ino)?;
            let written = self.write(&mut writer, progress)?;
            let trailer = writer.offset();
            let (sink, len) = writer.finish()?;
            if (trailer, len) != (measure.trailer, measure.len) {
                bail!(
                    EIO,
                    "the archive came out at {} bytes with its trailer at {} where {} and {} were planned",
                    len,
                    trailer,
                    measure.len,
                    measure.trailer
                );
            }
            sink.commit()?;
            Ok(Report { len, ..written })
        })();
        let failure = match written {
            Ok(report) => return Ok(report),
            Err(failure) => failure,
        };
        match before.restore(device, offset + measure.len) {
            Ok(()) => Err(failure),
            Err(e) => Err(failure.context(format!(
                "the archive could not be put back as it was ({}) after",
                e.message()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{self, ProblemKind};
    use crate::header::DeviceNumber;
    use crate::host::open_dir;
    use crate::plan::TreeOptions;
    use crate::test_util::{archive, named, Raw, TempDir, TempImage};
    use crate::times::TimePolicy;
    use crate::write::Attributes;
    use std::fs::{self, File};
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};

    const T: u64 = 1_577_934_245;

    fn fixed() -> TreeOptions {
        TreeOptions {
            times: TimePolicy::Fixed(UNIX_EPOCH + Duration::from_secs(T)),
            uid: Some(0),
            gid: Some(0),
            replace: true,
        }
    }

    const DIRECTORY: Attributes = Attributes {
        mode: 0o755,
        uid: 0,
        gid: 0,
        mtime: T as u32,
    };

    /// An image with an archive of a small tree.
    fn base(options: &write::Options) -> (TempDir, TempImage) {
        let tmp = TempDir::new("populate-base");
        let root = tmp.path();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/conf"), b"old").unwrap();
        fs::write(root.join("init"), b"#!/bin/sh\n").unwrap();
        fs::write(root.join("a"), b"x").unwrap();
        fs::hard_link(root.join("a"), root.join("b")).unwrap();
        symlink("init", root.join("link")).unwrap();
        let mut plan = Plan::new();
        plan.add_directory(named(b"."), DIRECTORY).unwrap();
        plan.add_tree(open_dir(root).unwrap().as_fd(), named(b"."), &fixed())
            .unwrap();
        let measure = plan.measure(options, 0, &|_| false).unwrap();
        let img = TempImage::new(0);
        let window = measure.make_room(img.device(), 0, None).unwrap();
        plan.assemble(&window, options, &measure, &mut |_| {}).unwrap();
        (tmp, img)
    }

    fn names(bytes: &[u8]) -> Vec<String> {
        Tree::open(bytes)
            .unwrap()
            .entries()
            .map(|(name, _)| String::from_utf8(name).unwrap())
            .collect()
    }

    fn data(bytes: &[u8], name: &[u8]) -> Vec<u8> {
        let tree = Tree::open(bytes).unwrap();
        let inode = tree.get(name).unwrap();
        bytes[inode.data_offset as usize..][..inode.size as usize].to_vec()
    }

    fn add(img: &TempImage, plan: &mut Plan, options: &Options) -> Result<Report> {
        plan.populate(&mut img.device(), 0, None, options, &mut |_| {})
    }

    #[test]
    fn a_tree_is_added_behind_what_is_there() {
        for layout in [
            write::Options::default(),
            write::Options {
                format: Format::Crc,
                end_alignment: 4,
                data_alignment: 0,
            },
        ] {
            let (_tmp, img) = base(&layout);
            let before = fs::read(img.path()).unwrap();
            let more = TempDir::new("populate-more");
            fs::create_dir_all(more.path().join("modules/fs")).unwrap();
            fs::write(more.path().join("modules/fs/ext4.ko"), vec![b'k'; 5000]).unwrap();
            fs::write(more.path().join("one"), b"1").unwrap();
            fs::hard_link(more.path().join("one"), more.path().join("two")).unwrap();
            let mut plan = Plan::new();
            plan.add_directory(named(b"usr"), DIRECTORY).unwrap();
            plan.add_directory(named(b"usr/lib"), DIRECTORY).unwrap();
            plan.add_tree(open_dir(more.path()).unwrap().as_fd(), named(b"usr/lib"), &fixed())
                .unwrap();
            let options = Options {
                end_alignment: layout.end_alignment,
                ..Options::default()
            };
            let report = add(&img, &mut plan, &options).unwrap();
            assert_eq!((report.files, report.directories, report.bytes), (2, 4, 5001));
            let after = fs::read(img.path()).unwrap();
            assert_eq!(after.len() as u64, report.len);
            assert_eq!(report.len % u64::from(layout.end_alignment), 0);
            // What was there is there, byte for byte, up to the old trailer.
            let old_trailer = Tree::open(&before).unwrap().trailer_offset().unwrap() as usize;
            assert!(after[..old_trailer] == before[..old_trailer]);
            assert_eq!(
                names(&after),
                [
                    ".",
                    "a",
                    "b",
                    "etc",
                    "etc/conf",
                    "init",
                    "link",
                    "usr",
                    "usr/lib",
                    "usr/lib/modules",
                    "usr/lib/modules/fs",
                    "usr/lib/modules/fs/ext4.ko",
                    "usr/lib/one",
                    "usr/lib/two",
                ]
            );
            assert!(data(&after, b"usr/lib/modules/fs/ext4.ko") == vec![b'k'; 5000]);
            // One archive, in one form, with nothing to complain about.
            let checked = check::check(&after).unwrap();
            assert_eq!(checked.problems, [], "{:?}", layout.format);
            let tree = Tree::open(&after).unwrap();
            assert_eq!(tree.format(), Some(layout.format));
            // The new links are a file of their own, numbered behind the old.
            assert_eq!(tree.inode_id(b"usr/lib/one"), tree.inode_id(b"usr/lib/two"));
            assert_ne!(tree.inode_id(b"usr/lib/one"), tree.inode_id(b"a"));
            assert_eq!(tree.get(b"a").unwrap().nlink, 2);
        }
    }

    #[test]
    fn a_file_takes_the_place_of_a_file() {
        let (_tmp, img) = base(&write::Options::default());
        let dir = TempDir::new("populate-file");
        fs::write(dir.path().join("conf"), b"new and longer").unwrap();
        let mut plan = Plan::new();
        plan.add_file(
            named(b"etc/conf"),
            File::open(dir.path().join("conf")).unwrap(),
            &fixed(),
        )
        .unwrap();
        let report = add(&img, &mut plan, &Options::default()).unwrap();
        assert_eq!((report.files, report.directories, report.bytes), (1, 0, 14));
        let after = fs::read(img.path()).unwrap();
        assert_eq!(data(&after, b"etc/conf"), b"new and longer");
        // The old entry is still in the archive, and a check says so.
        let checked = check::check(&after).unwrap();
        assert_eq!(
            checked.problems.iter().map(|p| p.kind).collect::<Vec<_>>(),
            [ProblemKind::Replaced]
        );
        assert_eq!(checked.errors(), 0);
        // Without leave to replace it is refused, and nothing is written.
        let before = after;
        let mut plan = Plan::new();
        plan.add_file(
            named(b"etc/conf"),
            File::open(dir.path().join("conf")).unwrap(),
            &fixed(),
        )
        .unwrap();
        let keep = Options {
            replace: false,
            ..Options::default()
        };
        let error = add(&img, &mut plan, &keep).unwrap_err();
        assert_eq!(error.errno(), EEXIST);
        assert_eq!(error.detail(), Some(&Detail::Path("etc/conf".into())));
        assert!(fs::read(img.path()).unwrap() == before);
    }

    #[test]
    fn what_the_unpacker_cannot_do_is_refused() {
        let (_tmp, img) = base(&write::Options::default());
        let before = fs::read(img.path()).unwrap();
        let dir = TempDir::new("populate-refused");
        fs::write(dir.path().join("f"), b"f").unwrap();
        fs::create_dir(dir.path().join("d")).unwrap();
        let file = || File::open(dir.path().join("f")).unwrap();
        let refused = |plan: &mut Plan| add(&img, plan, &Options::default()).unwrap_err();
        // A file where a directory is.
        let mut plan = Plan::new();
        plan.add_file(named(b"etc"), file(), &fixed()).unwrap();
        let error = refused(&mut plan);
        assert_eq!(
            (error.errno(), error.detail()),
            (EISDIR, Some(&Detail::Path("etc".into())))
        );
        // A directory where a file is.
        let mut plan = Plan::new();
        plan.add_directory(named(b"init"), DIRECTORY).unwrap();
        assert_eq!(refused(&mut plan).errno(), ENOTDIR);
        // Something below a file, and below a symbolic link.
        let mut plan = Plan::new();
        plan.add_file(named(b"init/x"), file(), &fixed()).unwrap();
        let error = refused(&mut plan);
        assert_eq!(
            (error.errno(), error.detail()),
            (ENOTDIR, Some(&Detail::Path("init".into())))
        );
        let mut plan = Plan::new();
        plan.add_file(named(b"link/x"), file(), &fixed()).unwrap();
        assert_eq!(refused(&mut plan).errno(), ENOTDIR);
        // Something below a directory that is neither there nor planned.
        let mut plan = Plan::new();
        plan.add_file(named(b"nowhere/x"), file(), &fixed()).unwrap();
        let error = refused(&mut plan);
        assert_eq!(
            (error.errno(), error.detail()),
            (ENOENT, Some(&Detail::Path("nowhere".into())))
        );
        // A name of a hard-linked file.
        let mut plan = Plan::new();
        plan.add_file(named(b"a"), file(), &fixed()).unwrap();
        let error = refused(&mut plan);
        assert_eq!(
            (error.errno(), error.detail()),
            (EEXIST, Some(&Detail::Path("a".into())))
        );
        assert!(
            fs::read(img.path()).unwrap() == before,
            "a refused call wrote something"
        );
        // A directory that is there is left alone: nothing is added.
        let mut plan = Plan::new();
        plan.add_directory(
            named(b"etc"),
            Attributes {
                mode: 0o700,
                ..DIRECTORY
            },
        )
        .unwrap();
        let report = add(&img, &mut plan, &Options::default()).unwrap();
        assert_eq!(
            report,
            Report {
                len: before.len() as u64,
                ..Report::default()
            }
        );
        assert!(fs::read(img.path()).unwrap() == before);
    }

    #[test]
    fn a_device_node_keeps_its_number() {
        let img = TempImage::new(0);
        fs::write(
            img.path(),
            archive(&[Raw::new(0o020600, b"null").rdev(1, 3).inode(1, 1)]),
        )
        .unwrap();
        // The planner has no way to make a device node without one on the
        // host, so the rule is checked on its own.
        let bytes = fs::read(img.path()).unwrap();
        let tree = Tree::open(&bytes).unwrap();
        let node = |rdev| Planned::for_test(Kind::CharDevice, rdev);
        assert!(tree
            .admits(named(b"null"), &node(DeviceNumber::new(1, 3)), true)
            .unwrap());
        assert_eq!(
            tree.admits(named(b"null"), &node(DeviceNumber::new(1, 5)), true)
                .unwrap_err()
                .errno(),
            EEXIST
        );
        assert!(tree
            .admits(named(b"zero"), &node(DeviceNumber::new(1, 5)), true)
            .unwrap());
    }

    #[test]
    fn archives_that_cannot_be_added_to() {
        let dir = TempDir::new("populate-odd");
        fs::write(dir.path().join("f"), b"f").unwrap();
        let try_add = |bytes: &[u8]| {
            let img = TempImage::new(0);
            fs::write(img.path(), bytes).unwrap();
            let mut plan = Plan::new();
            plan.add_file(named(b"new"), File::open(dir.path().join("f")).unwrap(), &fixed())
                .unwrap();
            let result = add(&img, &mut plan, &Options::default());
            (result, fs::read(img.path()).unwrap())
        };
        let good = archive(&[Raw::new(0o100644, b"f").data(b"x").inode(1, 1)]);
        // Something behind the trailer.
        let mut followed = good.clone();
        followed.extend(&good);
        let (result, after) = try_add(&followed);
        assert_eq!(result.unwrap_err().errno(), EOPNOTSUPP);
        assert!(after == followed);
        // A trailer with contents of its own, which the kernel passes over.
        let mut odd = Raw::new(0o100644, b"f").data(b"x").inode(1, 1).bytes();
        odd.extend(Raw::new(0o100644, b"TRAILER!!!").data(b"contents").bytes());
        let (result, after) = try_add(&odd);
        assert_eq!(result.unwrap_err().errno(), EOPNOTSUPP);
        assert!(after == odd);
        // Entries that are not followed.
        let (result, _) = try_add(&archive(&[Raw::new(0o100644, b"a/../b").data(b"x")]));
        assert_eq!(result.unwrap_err().errno(), EOPNOTSUPP);
        // No archive, and a damaged one.
        assert_eq!(try_add(&[]).0.unwrap_err().errno(), ENODATA);
        assert_eq!(try_add(&[0u8; 512]).0.unwrap_err().errno(), ENODATA);
        assert_eq!(try_add(b"\x1f\x8b\x08\x00 gzip").0.unwrap_err().errno(), EMEDIUMTYPE);
        assert_eq!(try_add(&good[..100]).0.unwrap_err().errno(), EUCLEAN);
        // The largest inode number there is leaves none.
        let (result, _) = try_add(&archive(&[Raw::new(0o100644, b"f").inode(u32::MAX, 1)]));
        assert_eq!(result.unwrap_err().errno(), EOVERFLOW);
        // Padding behind the trailer is fine, and so is no trailer.
        let mut padded = good.clone();
        padded.extend([0u8; 4096]);
        let (result, after) = try_add(&padded);
        result.unwrap();
        assert_eq!(names(&after), [".", "f", "new"]);
        assert_eq!(check::check(&after).unwrap().problems, []);
        let (result, after) = try_add(&Raw::new(0o100644, b"f").data(b"x").inode(1, 1).bytes());
        result.unwrap();
        assert_eq!(names(&after), [".", "f", "new"]);
        assert_eq!(check::check(&after).unwrap().problems, []);
    }

    #[test]
    fn room_is_found_or_made_before_anything_is_written() {
        let layout = write::Options {
            end_alignment: 4,
            ..write::Options::default()
        };
        let (_tmp, img) = base(&layout);
        let before = fs::read(img.path()).unwrap();
        let dir = TempDir::new("populate-room");
        fs::write(dir.path().join("f"), vec![b'f'; 10_000]).unwrap();
        let plan = || {
            let mut plan = Plan::new();
            plan.add_file(named(b"big"), File::open(dir.path().join("f")).unwrap(), &fixed())
                .unwrap();
            plan
        };
        // In a size that is given the archive has to fit.
        let error = plan()
            .populate(
                &mut img.device(),
                0,
                Some(before.len() as u64),
                &Options::default(),
                &mut |_| {},
            )
            .unwrap_err();
        assert_eq!(error.errno(), ENOSPC);
        assert!(matches!(error.detail(), Some(Detail::TooSmall { actual, .. }) if *actual == before.len() as u64));
        assert!(fs::read(img.path()).unwrap() == before);
        // Without one the file grows.
        let report = add(&img, &mut plan(), &Options::default()).unwrap();
        let after = fs::read(img.path()).unwrap();
        assert_eq!(after.len() as u64, report.len);
        assert!(report.len > before.len() as u64 + 10_000);
        assert_eq!(report.len % 512, 0);
        // At an offset, with what is before left alone.
        let img = TempImage::new(0);
        let mut bytes = vec![0x55u8; 4096];
        bytes.extend(&before);
        fs::write(img.path(), &bytes).unwrap();
        plan()
            .populate(&mut img.device(), 4096, None, &Options::default(), &mut |_| {})
            .unwrap();
        let whole = fs::read(img.path()).unwrap();
        assert!(whole[..4096].iter().all(|&b| b == 0x55));
        assert!(whole[4096..] == after[..]);
    }

    #[test]
    fn a_failure_while_writing_leaves_the_archive_as_it_was() {
        let (_tmp, img) = base(&write::Options::default());
        let packed = fs::read(img.path()).unwrap();
        let dir = TempDir::new("populate-undo");
        // Enough before the file that fails for bytes to reach the image.
        fs::write(dir.path().join("big"), vec![b'b'; 3 << 20]).unwrap();
        let fail = |before: &[u8], size: Option<u64>| {
            fs::write(img.path(), before).unwrap();
            fs::write(dir.path().join("changing"), b"as it was planned").unwrap();
            let mut plan = Plan::new();
            for name in ["big", "changing"] {
                plan.add_file(
                    named(name.as_bytes()),
                    File::open(dir.path().join(name)).unwrap(),
                    &fixed(),
                )
                .unwrap();
            }
            fs::write(dir.path().join("changing"), b"shorter").unwrap();
            let error = plan
                .populate(&mut img.device(), 0, size, &Options::default(), &mut |_| {})
                .unwrap_err();
            assert_eq!(error.errno(), ESTALE);
            assert!(fs::read(img.path()).unwrap() == before);
        };
        // An image that was grown is cut back.
        fail(&packed, None);
        // In an image with room, what was written is NUL bytes again.
        let mut roomy = packed.clone();
        roomy.resize(8 << 20, 0);
        fail(&roomy, None);
        fail(&roomy, Some(6 << 20));
        // Without a trailer, and with what is before the archive.
        let trailer = Tree::open(&packed).unwrap().trailer_offset().unwrap() as usize;
        fail(&packed[..trailer], None);
        // The image takes what is added once the source holds still.
        let mut plan = Plan::new();
        plan.add_file(named(b"big"), File::open(dir.path().join("big")).unwrap(), &fixed())
            .unwrap();
        add(&img, &mut plan, &Options::default()).unwrap();
        let after = fs::read(img.path()).unwrap();
        assert_eq!(check::check(&after).unwrap().problems, []);
        assert_eq!(names(&after).last().unwrap(), "link");
        assert!(names(&after).contains(&"big".to_string()));
    }

    /// The same calls give the same bytes.
    #[test]
    fn adding_is_deterministic() {
        let build = || {
            let (_tmp, img) = base(&write::Options::default());
            let dir = TempDir::new("populate-twice");
            fs::write(dir.path().join("f"), b"contents").unwrap();
            let mut plan = Plan::new();
            plan.add_directory(named(b"opt"), DIRECTORY).unwrap();
            plan.add_file(named(b"opt/f"), File::open(dir.path().join("f")).unwrap(), &fixed())
                .unwrap();
            add(&img, &mut plan, &Options::default()).unwrap();
            fs::read(img.path()).unwrap()
        };
        assert!(build() == build());
    }
}
