// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writing what is planned: into a sink, or into an image as a new
//! archive.
//!
//! By the time anything is written everything that can be known up front
//! is known: the plan was measured, so the archive fits where it goes, and
//! nothing in it is something an archive cannot hold. What is left to go
//! wrong is the reading of the files. A file that is not the one that was
//! planned anymore, replaced or of another size, fails the writing: its
//! header would say something else than what follows it.
//!
//! An archive in an image is stopped while it is written, see
//! [`StoppedSink`]: its first byte goes in last. So if writing fails or is
//! cut off, by a crash or by a loss of power, the kernel unpacks nothing
//! of what is in the image and says that unpacking failed, and
//! [`crate::check`] and [`crate::tree`] call the archive unfinished.
//! tests/crash/cpio/crash.rs has every state a crash can leave behind.

use std::collections::hash_map::{Entry, HashMap};
use std::fs::File;
use std::os::fd::AsFd;

use crate::device::Device;
use crate::errno::*;
use crate::header::Kind;
use crate::host::{read_some, FromStart};
use crate::image::{Stopped, StoppedSink};
use crate::manifest::Feed;
use crate::name::Name;
use crate::plan::{Contents, Measure, Plan, Role, Step};
use crate::progress::Progress;
use crate::write::{self, Links, Sink, Writer};
use crate::{Context, Detail, Error, Result};

/// Size of the buffer file contents are copied through.
const COPY_BUFFER: usize = 1024 * 1024;

/// What was written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Regular files, each counted once whatever the number of its names.
    pub files: u64,
    /// Directories, the root not among them.
    pub directories: u64,
    /// The bytes of the regular files.
    pub bytes: u64,
    /// The length of the archive, its trailer and the padding of its end
    /// included.
    pub len: u64,
}

impl Report {
    fn progress(&self) -> Progress {
        Progress {
            files: self.files,
            directories: self.directories,
            bytes: self.bytes,
        }
    }
}

/// A plan while it is written.
struct Writing<'a, S: Sink> {
    plan: &'a Plan,
    writer: &'a mut Writer<S>,
    progress: &'a mut dyn FnMut(&Progress),
    /// What is written so far.
    report: Report,
    /// What the names of every hard-linked file share, by the number of
    /// the file in the plan.
    groups: HashMap<u32, Links>,
    /// What the contents of a file are copied through.
    buffer: Vec<u8>,
    /// Where the contents of what a manifest describes come from.
    feed: Option<Feed<'a>>,
}

impl<S: Sink> Writing<'_, S> {
    /// What a name with the role `role` shares with the other names of its
    /// file. None for the only name of a file.
    fn links(&mut self, role: Role) -> Result<Option<Links>> {
        let Role::Link { group, names, .. } = role else {
            return Ok(None);
        };
        Ok(Some(match self.groups.entry(group) {
            Entry::Occupied(known) => *known.get(),
            Entry::Vacant(new) => *new.insert(self.writer.links(names)?),
        }))
    }

    /// Writes the entry `step`.
    fn entry(&mut self, step: &Step<'_>) -> Result<()> {
        let (name, planned) = (step.name.as_name(), step.planned);
        let links = self.links(step.role)?;
        match planned.kind {
            Kind::Directory => {
                self.writer.directory(name, &planned.attributes)?;
                if !name.is_root() {
                    self.report.directories += 1;
                }
            }
            Kind::Symlink => self.writer.symlink(name, &planned.attributes, &planned.target)?,
            Kind::CharDevice | Kind::BlockDevice | Kind::Fifo | Kind::Socket => {
                self.writer
                    .node(name, planned.kind, &planned.attributes, planned.rdev, links.as_ref())?
            }
            Kind::Regular => {
                // What a manifest describes has its contents where the
                // manifest says.
                let object = match planned.contents {
                    Contents::Manifest { object } => Some(object as usize),
                    _ => None,
                };
                match (links, object.zip(self.feed.as_mut())) {
                    (Some(links), described) if !step.role.carries_contents() => {
                        self.writer.file_link(name, &planned.attributes, &links)?;
                        // A manifest has the contents with every name of a
                        // file. They are held against it for each of them.
                        if let Some((object, feed)) = described {
                            feed.check(object)?;
                        }
                    }
                    (links, Some((object, feed))) => {
                        self.writer
                            .file_begin(name, &planned.attributes, links.as_ref(), planned.size)?;
                        self.report.bytes += feed.write(object, self.writer, self.report.progress(), self.progress)?;
                        self.writer.file_end()?;
                        self.report.files += 1;
                    }
                    (links, None) => {
                        let file = self.plan.open(name, planned)?;
                        self.writer
                            .file_begin(name, &planned.attributes, links.as_ref(), planned.size)?;
                        self.copy(name, &file, planned.size)?;
                        self.writer.file_end()?;
                        self.report.files += 1;
                    }
                }
            }
        }
        (self.progress)(&self.report.progress());
        Ok(())
    }

    /// Writes every entry of the plan.
    fn entries(&mut self) -> Result<()> {
        for step in self.plan.steps() {
            self.entry(&step)?;
        }
        match &self.feed {
            Some(feed) => feed.finish(),
            None => Ok(()),
        }
    }

    /// Copies the `size` bytes of `file`, the contents of the entry
    /// `name`, into the file the writer has begun.
    fn copy(&mut self, name: Name<'_>, file: &File, size: u64) -> Result<()> {
        let mut data = FromStart::new(file.as_fd());
        let mut left = size;
        while left > 0 {
            let want = left.min(COPY_BUFFER as u64) as usize;
            let n = read_some(&mut data, &mut self.buffer[..want])
                .with_context(|| format!("reading the contents of '{}'", name))?;
            if n == 0 {
                bail!(
                    ESTALE,
                    "the contents of '{}' ended after {} of {} bytes: the file changed while the archive was written",
                    name,
                    size - left,
                    size
                );
            }
            self.writer.file_data(&self.buffer[..n])?;
            left -= n as u64;
            self.report.bytes += n as u64;
            (self.progress)(&self.report.progress());
        }
        Ok(())
    }
}

impl Plan {
    /// Writes the entries through `writer`, in the order of the archive,
    /// and tells `progress` what is written so far after every entry and
    /// every piece of a file's contents. The trailer is the caller's to
    /// write, with [`Writer::finish`].
    ///
    /// The contents of what a manifest describes are read from where
    /// [`Plan::add_manifest`] was told they are, and held against the
    /// sizes and hashes of the manifest while they are written. A stream
    /// of them is used up by that.
    pub fn write<S: Sink>(&mut self, writer: &mut Writer<S>, progress: &mut dyn FnMut(&Progress)) -> Result<Report> {
        // Reading from where the contents are changes it, the plan stays
        // as it is.
        let mut described = self.described.take();
        let mut writing = Writing {
            plan: self,
            writer,
            progress,
            report: Report::default(),
            groups: HashMap::new(),
            buffer: vec![0u8; COPY_BUFFER],
            feed: described.as_mut().map(Feed::new),
        };
        let written = writing.entries();
        let report = writing.report;
        self.described = described;
        written.map(|()| report)
    }

    /// Writes the plan as a new archive into `window`, the part of an
    /// image that [`Measure::make_room`] returned, laid out with `options`.
    /// What the window has beyond the archive is made to read as zeros:
    /// the kernel reads on behind a trailer, and whatever was there before
    /// is none of the archive's business. The archive is on the device for
    /// good when this returns, and it is stopped until then: a call that
    /// fails after it began to write leaves it stopped.
    pub fn assemble(
        &mut self,
        window: &Device,
        options: &write::Options,
        measure: &Measure,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<Report> {
        let (report, stopped) = self.assemble_stopped(window, options, measure, progress)?;
        stopped.finish()?;
        Ok(report)
    }

    /// [`Plan::assemble`] without its last step: all of the archive is on
    /// the device for good but for its first byte, and it stays stopped
    /// until [`Stopped::finish`]. For a caller that has more to do before
    /// the archive may be taken for a whole one: [`Stopped::archive`] is
    /// the archive to read until then.
    pub fn assemble_stopped<'a>(
        &mut self,
        window: &'a Device,
        options: &write::Options,
        measure: &Measure,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<(Report, Stopped<'a>)> {
        // Nothing is written for what fails here.
        options.check()?;
        if window.len() < measure.len {
            return Err(measure.too_small(window.len()));
        }
        let mut writer = Writer::new(StoppedSink::new(window, 0, options.format)?, *options)?;
        let mut report = self.write(&mut writer, progress)?;
        let (sink, len) = writer.finish()?;
        if len != measure.len {
            bail!(
                EIO,
                "the archive came out at {} bytes where {} were planned",
                len,
                measure.len
            );
        }
        window.zero(len, window.len() - len)?;
        let stopped = sink.settle()?;
        report.len = len;
        Ok((report, stopped))
    }
}

impl Measure {
    /// The error of an image that has room for `actual` bytes, which is
    /// less than the archive needs.
    fn too_small(&self, actual: u64) -> Error {
        err!(
            ENOSPC,
            Detail::TooSmall {
                minimal: self.len,
                actual,
            },
            "the archive needs {} bytes and the image has room for {}",
            self.len,
            actual
        )
    }

    /// Makes room for the archive that was measured at `offset` of the
    /// image `device`, in `size` bytes when a size is given and in what is
    /// there or can be grown otherwise, and returns the part of the image
    /// the archive goes to. A regular file is grown, never shrunk. A block
    /// device has the size it has. Too little room is `TooSmall`, found
    /// before anything is written.
    pub fn make_room(&self, mut device: Device, offset: u64, size: Option<u64>) -> Result<Device> {
        if let Some(size) = size.filter(|&size| size < self.len) {
            return Err(self.too_small(size));
        }
        let end = offset
            .checked_add(size.unwrap_or(self.len))
            .ok_or_else(|| err!(ERANGE, "the size of the image overflows"))?;
        device.grow(end)?;
        if device.len() < offset || device.len() - offset < self.len {
            return Err(self.too_small(device.len().saturating_sub(offset)));
        }
        device.window(offset, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check;
    use crate::device::Access;
    use crate::host::open_dir;
    use crate::plan::TreeOptions;
    use crate::test_util::{named, TempDir, TempImage};
    use crate::tree::Tree;
    use crate::write::Attributes;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::time::{Duration, UNIX_EPOCH};

    fn tree(name: &str) -> TempDir {
        let tmp = TempDir::new(name);
        let root = tmp.path();
        fs::create_dir_all(root.join("d/sub")).unwrap();
        fs::write(root.join("d/file"), b"hello\n").unwrap();
        fs::write(root.join("a"), b"x").unwrap();
        fs::hard_link(root.join("a"), root.join("d/hl1")).unwrap();
        fs::hard_link(root.join("a"), root.join("hl2")).unwrap();
        symlink("d/file", root.join("sym")).unwrap();
        fs::write(root.join("big"), vec![b'B'; 3 * COPY_BUFFER + 7]).unwrap();
        tmp
    }

    fn fixed() -> TreeOptions {
        TreeOptions {
            times: crate::times::TimePolicy::Fixed(UNIX_EPOCH + Duration::from_secs(1_577_934_245)),
            uid: Some(0),
            gid: Some(0),
            replace: true,
        }
    }

    fn plan_of(tmp: &TempDir) -> Plan {
        let mut plan = Plan::new();
        plan.add_directory(
            named(b"."),
            Attributes {
                mode: 0o755,
                uid: 0,
                gid: 0,
                mtime: 1_577_934_245,
            },
        )
        .unwrap();
        plan.add_tree(open_dir(tmp.path()).unwrap().as_fd(), named(b"."), &fixed())
            .unwrap();
        plan
    }

    fn archive_of(plan: &mut Plan, options: &write::Options) -> (Vec<u8>, Report) {
        let mut writer = Writer::new(Vec::new(), *options).unwrap();
        let mut report = plan.write(&mut writer, &mut |_| {}).unwrap();
        let (bytes, len) = writer.finish().unwrap();
        report.len = len;
        (bytes, report)
    }

    #[test]
    fn a_tree_becomes_an_archive_that_unpacks_to_it() {
        let tmp = tree("assemble");
        let mut plan = plan_of(&tmp);
        let options = write::Options::default();
        let measure = plan.measure(&options, 0, &|_| false).unwrap();
        let (bytes, report) = archive_of(&mut plan, &options);
        assert_eq!(report.len, measure.len);
        assert_eq!(bytes.len() as u64, measure.len);
        assert_eq!(
            (report.files, report.directories, report.bytes),
            (measure.files, measure.directories, measure.bytes)
        );
        assert_eq!((report.files, report.directories), (3, 2));
        // The archive is clean and unpacks to the tree.
        let checked = check::check(&bytes).unwrap();
        assert_eq!(checked.problems, []);
        let unpacked = Tree::open(&bytes).unwrap();
        let names: Vec<String> = unpacked
            .entries()
            .map(|(name, _)| String::from_utf8(name).unwrap())
            .collect();
        assert_eq!(names, [".", "a", "big", "d", "d/file", "d/hl1", "d/sub", "hl2", "sym"]);
        let data = |name: &[u8]| {
            let inode = unpacked.get(name).unwrap();
            bytes[inode.data_offset as usize..][..inode.size as usize].to_vec()
        };
        assert_eq!(data(b"d/file"), b"hello\n");
        assert_eq!(data(b"sym"), b"d/file");
        assert!(data(b"big") == vec![b'B'; 3 * COPY_BUFFER + 7]);
        // The three names are one file, with the contents.
        assert_eq!(unpacked.inode_id(b"a"), unpacked.inode_id(b"hl2"));
        assert_eq!(unpacked.inode_id(b"a"), unpacked.inode_id(b"d/hl1"));
        assert_eq!(data(b"d/hl1"), b"x");
        assert_eq!(unpacked.get(b"a").unwrap().nlink, 3);
        assert_eq!(unpacked.root_stated(), crate::tree::RootStated::all());
    }

    /// Two trees with the same contents give the same bytes, whatever
    /// their inode numbers, the order they were made in and the times of
    /// their files.
    #[test]
    fn the_archive_depends_on_the_contents_only() {
        let one = tree("assemble-one");
        let other = TempDir::new("assemble-other");
        let root = other.path();
        // The same tree, made in another order.
        fs::write(root.join("big"), vec![b'B'; 3 * COPY_BUFFER + 7]).unwrap();
        fs::create_dir(root.join("d")).unwrap();
        fs::write(root.join("hl2"), b"x").unwrap();
        symlink("d/file", root.join("sym")).unwrap();
        fs::hard_link(root.join("hl2"), root.join("d/hl1")).unwrap();
        fs::create_dir(root.join("d/sub")).unwrap();
        fs::write(root.join("d/file"), b"hello\n").unwrap();
        fs::hard_link(root.join("hl2"), root.join("a")).unwrap();
        for options in [
            write::Options::default(),
            write::Options {
                format: crate::header::Format::Crc,
                data_alignment: 4096,
                end_alignment: 4,
            },
        ] {
            let (first, _) = archive_of(&mut plan_of(&one), &options);
            let (second, _) = archive_of(&mut plan_of(&other), &options);
            assert!(first == second);
            assert_eq!(check::check(&first).unwrap().problems, []);
        }
    }

    #[test]
    fn progress_is_told_as_the_archive_grows() {
        let tmp = tree("assemble-progress");
        let mut plan = plan_of(&tmp);
        let mut writer = Writer::new(Vec::new(), write::Options::default()).unwrap();
        let mut seen = Vec::new();
        let report = plan.write(&mut writer, &mut |p| seen.push(*p)).unwrap();
        assert!(seen
            .windows(2)
            .all(|w| w[0].bytes <= w[1].bytes && w[0].files <= w[1].files));
        assert_eq!(seen.last().unwrap().bytes, report.bytes);
        // The large file is told piece by piece.
        assert!(seen.iter().filter(|p| p.files == 1 && p.bytes > 1).count() >= 3);
    }

    #[test]
    fn a_file_that_changed_fails_the_writing() {
        // Another file under the planned name. It is there before the
        // planned one goes, so it cannot get the same inode number.
        let tmp = tree("assemble-replaced");
        let mut plan = plan_of(&tmp);
        fs::write(tmp.path().join("d/other"), b"hello\n").unwrap();
        fs::rename(tmp.path().join("d/other"), tmp.path().join("d/file")).unwrap();
        let mut writer = Writer::new(Vec::new(), write::Options::default()).unwrap();
        assert_eq!(plan.write(&mut writer, &mut |_| {}).unwrap_err().errno(), ESTALE);
        // The same file with another size.
        let tmp = tree("assemble-grown");
        let mut plan = plan_of(&tmp);
        fs::OpenOptions::new()
            .append(true)
            .open(tmp.path().join("d/file"))
            .and_then(|mut f| std::io::Write::write_all(&mut f, b"more"))
            .unwrap();
        let mut writer = Writer::new(Vec::new(), write::Options::default()).unwrap();
        assert_eq!(plan.write(&mut writer, &mut |_| {}).unwrap_err().errno(), ESTALE);
        // A file that is gone, and one turned into a symbolic link.
        let tmp = tree("assemble-gone");
        let mut plan = plan_of(&tmp);
        fs::remove_file(tmp.path().join("big")).unwrap();
        let mut writer = Writer::new(Vec::new(), write::Options::default()).unwrap();
        assert_eq!(plan.write(&mut writer, &mut |_| {}).unwrap_err().errno(), ENOENT);
        let tmp = tree("assemble-linked");
        let mut plan = plan_of(&tmp);
        fs::remove_file(tmp.path().join("big")).unwrap();
        symlink("/etc/passwd", tmp.path().join("big")).unwrap();
        let mut writer = Writer::new(Vec::new(), write::Options::default()).unwrap();
        assert_eq!(plan.write(&mut writer, &mut |_| {}).unwrap_err().errno(), ELOOP);
    }

    #[test]
    fn an_image_is_grown_to_the_archive_and_never_shrunk() {
        let tmp = tree("assemble-image");
        let mut plan = plan_of(&tmp);
        let options = write::Options::default();
        let measure = plan.measure(&options, 0, &|_| false).unwrap();
        // An empty file is grown to the archive.
        let img = TempImage::new(0);
        let window = measure.make_room(img.device(), 0, None).unwrap();
        assert_eq!(window.len(), measure.len);
        let report = plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap();
        assert_eq!(report.len, measure.len);
        drop(window);
        let bytes = fs::read(img.path()).unwrap();
        assert_eq!(bytes.len() as u64, measure.len);
        assert_eq!(check::check(&bytes).unwrap().problems, []);
        // A larger file keeps its size, and what was in it is gone.
        let img = TempImage::new(0);
        fs::write(img.path(), vec![0xaau8; (measure.len + 8192) as usize]).unwrap();
        let window = measure.make_room(img.device(), 0, None).unwrap();
        plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap();
        drop(window);
        let larger = fs::read(img.path()).unwrap();
        assert_eq!(larger.len() as u64, measure.len + 8192);
        assert!(larger[..measure.len as usize] == bytes[..]);
        assert!(larger[measure.len as usize..].iter().all(|&b| b == 0));
        assert_eq!(check::check(&larger).unwrap().problems, []);
        // At an offset, in a size given: what is before stays.
        let img = TempImage::new(0);
        fs::write(img.path(), vec![0x55u8; 4096]).unwrap();
        let window = measure.make_room(img.device(), 4096, Some(measure.len + 512)).unwrap();
        assert_eq!(window.len(), measure.len + 512);
        plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap();
        drop(window);
        let whole = fs::read(img.path()).unwrap();
        assert_eq!(whole.len() as u64, 4096 + measure.len + 512);
        assert!(whole[..4096].iter().all(|&b| b == 0x55));
        assert!(whole[4096..][..measure.len as usize] == bytes[..]);
    }

    /// An archive is stopped while it is written. A call that fails leaves
    /// it stopped, and nothing takes it for an archive then.
    #[test]
    fn an_archive_is_stopped_until_all_of_it_is_written() {
        use crate::header::STOPPER;
        use crate::read::Foreign;
        let tmp = tree("assemble-stopped");
        let mut plan = plan_of(&tmp);
        let options = write::Options::default();
        let measure = plan.measure(&options, 0, &|_| false).unwrap();
        let (bytes, _) = archive_of(&mut plan, &options);
        // Over an archive that is there, in an image with room behind it.
        let img = TempImage::new(0);
        let mut old = bytes.clone();
        old.resize(bytes.len() + 4096, 0x30);
        fs::write(img.path(), &old).unwrap();
        let window = measure.make_room(img.device(), 0, None).unwrap();
        let (report, stopped) = plan.assemble_stopped(&window, &options, &measure, &mut |_| {}).unwrap();
        assert_eq!(report.len, measure.len);
        // All of it is in the image but for the first byte, and what was
        // behind it is gone.
        let image = fs::read(img.path()).unwrap();
        assert_eq!(image[0], STOPPER);
        assert!(image[1..bytes.len()] == bytes[1..]);
        assert!(image[bytes.len()..].iter().all(|&b| b == 0));
        // Nothing takes that for an archive.
        let unfinished = Tree::open(&image).unwrap_err();
        assert_eq!(unfinished.errno(), EUCLEAN);
        let checked = check::check(&image).unwrap();
        assert_eq!(checked.errors(), 1);
        assert_eq!(checked.problems[0].found, Some(Foreign::Unfinished));
        // It reads as the archive it is going to be, and then it is.
        let finished = stopped.archive();
        let unpacked = Tree::open(&finished).unwrap();
        assert_eq!(unpacked.records(), Tree::open(&bytes).unwrap().records());
        assert_eq!(check::check(&finished).unwrap().problems, []);
        stopped.finish().unwrap();
        drop(window);
        let image = fs::read(img.path()).unwrap();
        assert!(image[..bytes.len()] == bytes[..]);
        assert_eq!(check::check(&image).unwrap().problems, []);

        // A file that changed fails the writing behind the first megabyte
        // and behind a few bytes. Either way the image is left stopped.
        for (spoiled, name) in [("d/file", "assemble-spoiled-late"), ("a", "assemble-spoiled-early")] {
            let tmp = tree(name);
            let mut plan = plan_of(&tmp);
            let measure = plan.measure(&options, 0, &|_| false).unwrap();
            fs::OpenOptions::new()
                .append(true)
                .open(tmp.path().join(spoiled))
                .and_then(|mut f| std::io::Write::write_all(&mut f, b"more"))
                .unwrap();
            let img = TempImage::new(0);
            fs::write(img.path(), &bytes).unwrap();
            let window = measure.make_room(img.device(), 0, None).unwrap();
            let error = plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap_err();
            assert_eq!(error.errno(), ESTALE, "{}", spoiled);
            drop(window);
            let image = fs::read(img.path()).unwrap();
            assert_eq!(image.len() as u64, measure.len);
            assert_eq!(image[..6], crate::header::Format::Newc.stopped_magic());
            assert_eq!(Tree::open(&image).unwrap_err().errno(), EUCLEAN, "{}", spoiled);
            let checked = check::check(&image).unwrap();
            assert_eq!((checked.records, checked.errors()), (0, 1), "{}", spoiled);
            // Writing it again makes it whole.
            fs::write(
                tmp.path().join(spoiled),
                if spoiled == "a" { &b"x"[..] } else { b"hello\n" },
            )
            .unwrap();
            let mut plan = plan_of(&tmp);
            let measure = plan.measure(&options, 0, &|_| false).unwrap();
            let window = measure.make_room(img.device(), 0, None).unwrap();
            plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap();
            drop(window);
            assert!(fs::read(img.path()).unwrap() == bytes, "{}", spoiled);
        }
    }

    #[test]
    fn too_little_room_is_found_before_anything_is_written() {
        let img = TempImage::new(100);
        let needed = Measure {
            len: 2048,
            ..Measure::default()
        };
        let error = needed.make_room(img.device(), 0, Some(1000)).unwrap_err();
        assert_eq!(error.errno(), ENOSPC);
        assert_eq!(
            error.detail(),
            Some(&Detail::TooSmall {
                minimal: 2048,
                actual: 1000
            })
        );
        assert_eq!(fs::metadata(img.path()).unwrap().len(), 100);
        assert_eq!(
            needed.make_room(img.device(), u64::MAX - 10, None).unwrap_err().errno(),
            ERANGE
        );
        // A window that is too small for what was measured.
        let tmp = tree("assemble-small");
        let mut plan = plan_of(&tmp);
        let options = write::Options::default();
        let measure = plan.measure(&options, 0, &|_| false).unwrap();
        let img = TempImage::new(4096);
        let window = Device::open(img.path(), Access::ReadWrite).unwrap();
        let error = plan.assemble(&window, &options, &measure, &mut |_| {}).unwrap_err();
        assert!(matches!(error.detail(), Some(Detail::TooSmall { .. })));
        // And so is a layout an archive cannot have.
        let odd = write::Options {
            end_alignment: 6,
            ..options
        };
        let img_odd = TempImage::new(measure.len);
        let window_odd = Device::open(img_odd.path(), Access::ReadWrite).unwrap();
        let error = plan.assemble(&window_odd, &odd, &measure, &mut |_| {}).unwrap_err();
        assert_eq!(error.errno(), EINVAL);
        drop((window, window_odd));
        assert!(fs::read(img.path()).unwrap().iter().all(|&b| b == 0));
        assert!(fs::read(img_odd.path()).unwrap().iter().all(|&b| b == 0));
    }
}
