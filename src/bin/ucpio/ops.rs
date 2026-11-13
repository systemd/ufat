// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the command line and the service both do with what they are
//! given: turn sources into a plan, and add to an archive.

use std::fs::File;
use std::os::fd::{AsFd, OwnedFd};
use std::time::SystemTime;

use cpio::assemble::Report;
use cpio::device::Device;
use cpio::errno;
use cpio::header::Kind;
use cpio::image::Region;
use cpio::manifest::{Described, ManifestOptions};
use cpio::name::Name;
use cpio::plan::{Plan, TreeOptions};
use cpio::populate;
use cpio::progress::Progress;
use cpio::times::TimePolicy;
use cpio::tree::Tree;
use cpio::write::Attributes;
use cpio::{bail, Detail, Result};

/// What goes into an archive.
pub(crate) enum Source {
    /// A directory tree.
    Tree(OwnedFd),
    /// One file.
    File(File),
    /// What a manifest describes, with where the contents of its files
    /// are.
    Manifest(Box<Described>),
}

/// How sources become entries.
#[derive(Clone, Copy)]
pub(crate) struct How {
    pub times: TimePolicy,
    /// The time of what has none: an entry of a manifest without one, a
    /// directory that is made.
    pub time: SystemTime,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub replace: bool,
    /// The time to hold the validity of manifest entries against, in
    /// microseconds since the epoch. None skips that.
    pub now_usec: Option<u64>,
}

impl How {
    pub(crate) fn tree(&self) -> TreeOptions {
        TreeOptions {
            times: self.times,
            uid: self.uid,
            gid: self.gid,
            replace: self.replace,
        }
    }

    pub(crate) fn manifest(&self) -> ManifestOptions {
        ManifestOptions {
            times: self.times,
            default_time: self.time,
            uid: self.uid,
            gid: self.gid,
            replace: self.replace,
            now_usec: self.now_usec,
        }
    }

    /// What a directory is that is made without a source saying what it
    /// is.
    pub(crate) fn made(&self) -> Attributes {
        Attributes {
            mode: Attributes::DIRECTORY_MODE,
            uid: self.uid.unwrap_or(0),
            gid: self.gid.unwrap_or(0),
            mtime: Attributes::seconds(self.times.resolve(self.time)),
        }
    }

    /// What the root directory is, by the first of `sources`: a tree's
    /// own directory, the leading object of a manifest. Without a source
    /// it is a directory as [`How::made`] makes one.
    pub(crate) fn root_attributes(&self, sources: &[Source]) -> Result<Attributes> {
        Ok(match sources.first() {
            Some(Source::Tree(fd)) => {
                let md = File::from(fd.try_clone()?).metadata()?;
                self.tree().attributes(&md)
            }
            Some(Source::Manifest(described)) => self.manifest().attributes(&described.manifest().root),
            Some(Source::File(_)) | None => self.made(),
        })
    }

    /// Plans `sources` below the directory `dest` of the archive, a file
    /// as `dest` itself.
    pub(crate) fn plan(&self, plan: &mut Plan, sources: Vec<Source>, dest: Name<'_>) -> Result<()> {
        for source in sources {
            match source {
                Source::Tree(fd) => plan.add_tree(fd.as_fd(), dest, &self.tree())?,
                Source::File(file) => plan.add_file(dest, file, &self.tree())?,
                Source::Manifest(described) => plan.add_manifest(*described, dest, &self.manifest())?,
            }
        }
        Ok(())
    }
}

/// What is added to an archive, and how.
pub(crate) struct Addition<'a> {
    /// The directory a tree or what a manifest describes goes below, the
    /// name of a file, or the directory to make when there is no source.
    pub dest: Name<'a>,
    pub source: Option<Source>,
    /// Make the directories that lead to `dest`, and take a directory that
    /// is there for the one to make.
    pub parents: bool,
    pub how: How,
    pub options: populate::Options,
}

impl Addition<'_> {
    /// Adds to the archive at `offset` of `device`, in `size` bytes when a
    /// size is given.
    pub(crate) fn apply(
        self,
        device: &mut Device,
        offset: u64,
        size: Option<u64>,
        progress: &mut dyn FnMut(&Progress),
    ) -> Result<Report> {
        let Addition {
            dest,
            source,
            parents,
            how,
            options,
        } = self;
        let mut plan = Plan::new();
        let is_file = matches!(source, Some(Source::File(_)));
        if is_file && dest.is_root() {
            bail!(
                errno::EISDIR,
                Detail::Path(dest.to_string()),
                "a file cannot take the place of the root directory"
            );
        }
        // The directories that lead to where the content goes: the ones
        // above it, and itself unless it is a file.
        if parents {
            let itself = Some(dest).filter(|dest| !is_file && !dest.is_root());
            let missing: Vec<Name<'_>> = itself.into_iter().chain(dest.ancestors()).collect();
            for directory in missing.into_iter().rev() {
                plan.add_directory(directory, how.made())?;
            }
        }
        match source {
            None => {
                // Only the directory itself. One that is there is in the
                // way unless the caller said that it may be.
                if !parents {
                    let region = Region::new(device, offset, size)?;
                    if Tree::open(&region)?
                        .get(dest.as_bytes())
                        .is_some_and(|inode| inode.kind == Kind::Directory)
                    {
                        bail!(
                            errno::EEXIST,
                            Detail::Path(dest.to_string()),
                            "'{}' is in the archive",
                            dest
                        );
                    }
                }
                if !dest.is_root() {
                    plan.add_directory(dest, how.made())?;
                }
            }
            Some(source) => {
                // A tree goes below a directory, which is made when it is
                // not there.
                if matches!(source, Source::Tree(_)) && !dest.is_root() {
                    plan.add_directory(dest, how.made())?;
                }
                how.plan(&mut plan, vec![source], dest)?;
            }
        }
        plan.populate(device, offset, size, &options, progress)
    }
}
