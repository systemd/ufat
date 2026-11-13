// SPDX-License-Identifier: LGPL-2.1-or-later
//! The contents of the files a manifest describes: where they are, and
//! copying them from there with the sizes and hashes of the manifest
//! checked.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

use crate::digest::{Digest, Sha256Hasher};
use crate::error::{ContentProblem, Error, ErrorKind, Field, Problem, SourceProblem, Unsupported};
use crate::object::{Contents, FileObject, InodeType, Location};
use crate::reader::ReadSome;
use crate::{Name, Sha256};

/// How much a source copies at a time. A file that file objects are parts
/// of is checked in pieces of this size.
const COPY_SIZE: usize = 1024 * 1024;

/// Where the data of a file object is, as [`FileObject::data`] finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data<'a> {
    /// In the manifest itself. This is the data.
    Literal(&'a [u8]),
    /// Outside of the manifest. A [`ContentSource`] has it.
    External(Reference<'a>),
}

/// The file a file object has its data in, next to the manifest.
///
/// The file can hold more than the data of the one file object: several
/// file objects can each be a part of the same file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reference<'a> {
    /// The file: the one a contents object names, or else the one of the
    /// object's own name.
    pub file: &'a Name,
    /// Where the data starts in the file.
    pub offset: u64,
    /// The size of the whole file, if the manifest gives it.
    pub original_size: Option<u64>,
    /// The hash of the whole file, if the manifest gives it.
    pub original_sha256: Option<Sha256>,
}

impl<'a> Reference<'a> {
    /// The reference of an object to the file `file`, by way of the
    /// contents object `contents` if one names it.
    fn new(file: &'a Name, contents: Option<&'a Contents>) -> Reference<'a> {
        Reference {
            file,
            offset: contents.map_or(0, |contents| contents.offset),
            original_size: contents.and_then(|contents| contents.original_size),
            original_sha256: contents.and_then(|contents| contents.original_sha256),
        }
    }

    /// Checks the length `len` of the file against what the manifest says
    /// of it and of the data of `object` in it. Returns the size of that
    /// data: the rest of the file from the offset on when the manifest
    /// gives none. A length that does not fit is an error of the kind
    /// `kind`.
    ///
    /// A reference without an offset and without `originalSize` is the
    /// whole file, which has to be exactly as long as the data. A part of
    /// a file, at an offset or out of a larger `originalSize`, has to fit
    /// into it.
    fn check_len(&self, object: &FileObject, len: u64, kind: ErrorKind) -> Result<u64, Error> {
        let name = &object.name;
        if let Some(total) = self.original_size.filter(|&total| total != len) {
            let message = format!("{}: {} is {} bytes, the manifest says {}", name, self.file, len, total);
            return Err(Error::new(kind, message)
                .named(name.as_str())
                .sizes(Some(len), Some(total)));
        }
        let size = object.size.unwrap_or(len.saturating_sub(self.offset));
        // Without an offset and without originalSize the file holds the
        // data and nothing else, as systemd-sysupdate takes it. A file that
        // grew since the manifest was written would otherwise be cut short.
        if self.offset == 0 && self.original_size.is_none() && len != size {
            let message = format!("{}: {} is {} bytes, the manifest says {}", name, self.file, len, size);
            return Err(Error::new(kind, message)
                .named(name.as_str())
                .sizes(Some(len), Some(size)));
        }
        let end = self.offset.checked_add(size);
        if end.is_none_or(|end| end > len) {
            let message = format!(
                "{}: {} is too short for offset {} and size {}",
                name, self.file, self.offset, size
            );
            return Err(Error::new(kind, message).named(name.as_str()).sizes(Some(len), end));
        }
        Ok(size)
    }
}

impl FileObject {
    /// Where the data of the file is: the contents of a regular file, or
    /// the target of a symbolic link.
    ///
    /// The data is taken from the first contents object that has it as it
    /// is, in the manifest or in a file next to it. An object without
    /// contents objects has it in the file of its own name. Data that has
    /// to be decoded or fetched from a URL is not taken. An object whose
    /// every contents object gives it that way fails with
    /// [`Unsupported::Transport`].
    pub fn data(&self) -> Result<Data<'_>, Error> {
        if let Some(data) = self.plain_data() {
            return Ok(data);
        }
        let mut ways: Vec<String> = self
            .contents
            .iter()
            .map(|contents| match &contents.encoding {
                Some(encoding) => format!("'{}' encoding", encoding),
                None => "a URL".to_string(),
            })
            .collect();
        ways.sort();
        ways.dedup();
        let ways = ways.join(" or ");
        let message = format!(
            "'{}' is only available through {}, which is not supported",
            self.name, ways
        );
        Err(Error::new(ErrorKind::Unsupported(Unsupported::Transport), message)
            .named(self.name.as_str())
            .valued(ways))
    }

    /// Where the data of the file is, if it is somewhere as it is.
    fn plain_data(&self) -> Option<Data<'_>> {
        if self.contents.is_empty() {
            return Some(Data::External(Reference::new(&self.name, None)));
        }
        self.contents
            .iter()
            .filter(|contents| contents.encoding.is_none())
            .find_map(|contents| {
                let file = match &contents.location {
                    Location::Url(_) => return None,
                    Location::Literal(literal) => return Some(Data::Literal(self.part_of(literal, contents.offset))),
                    Location::File(file) => file,
                    Location::Implied => &self.name,
                };
                Some(Data::External(Reference::new(file, Some(contents))))
            })
    }

    /// The part of the literal `literal` that is the data of the file:
    /// from `offset` on, as many bytes as the object says it has. An
    /// offset or a size beyond the literal takes all there is.
    fn part_of<'a>(&self, literal: &'a [u8], offset: u64) -> &'a [u8] {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let data = literal.get(offset..).unwrap_or(&[]);
        match self.size.map(usize::try_from) {
            Some(Ok(size)) => data.get(..size).unwrap_or(data),
            _ => data,
        }
    }

    /// Whether this is a regular file whose data is outside of the
    /// manifest, where a [`ContentSource`] has it.
    pub fn is_streamed(&self) -> bool {
        self.inode_type == InodeType::Regular && matches!(self.plain_data(), Some(Data::External(_)))
    }

    /// Writes the data of the file to `sink`: the literal of the
    /// manifest, or what `source` has. Checks the data against the size
    /// and the hash the object gives, and returns how many bytes it is.
    ///
    /// What was written to the sink when this fails is not the data of
    /// the file.
    pub fn copy_contents(&self, source: &mut dyn ContentSource, sink: &mut dyn Write) -> Result<u64, Error> {
        let mut checked = Checked::<Sha256> {
            sink,
            hasher: self.sha256.map(|_| Sha256Hasher::default()),
            written: 0,
        };
        match self.data()? {
            Data::Literal(data) => checked.write_all(data)?,
            Data::External(reference) => source.copy(self, &reference, &mut checked)?,
        }
        let Checked { hasher, written, .. } = checked;
        if let Some(size) = self.size.filter(|&size| size != written) {
            let message = format!("'{}' is {} bytes, the manifest says {}", self.name, written, size);
            return Err(Error::new(ErrorKind::Content(ContentProblem::Size), message)
                .named(self.name.as_str())
                .sizes(Some(written), Some(size)));
        }
        if hasher.map(Sha256::from) != self.sha256 {
            let message = format!("'{}' does not match the hash in the manifest", self.name);
            return Err(Error::new(ErrorKind::Content(ContentProblem::Hash), message).named(self.name.as_str()));
        }
        Ok(written)
    }
}

/// Counts and hashes what passes through to a sink.
struct Checked<'a, D: Digest> {
    sink: &'a mut dyn Write,
    /// The hash so far, if the data has one to be held against.
    hasher: Option<D::Hasher>,
    written: u64,
}

impl<D: Digest> Write for Checked<'_, D> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.sink.write_all(data)?;
        if let Some(hasher) = &mut self.hasher {
            hasher.write_all(data)?;
        }
        self.written += data.len() as u64;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// Has the data of the file objects whose data is outside of the
/// manifest.
///
/// [`DirectorySource`] takes it from the files next to the manifest and
/// [`StreamSource`] from one stream that carries it all.
/// [`FileObject::copy_contents`] is what calls a source.
pub trait ContentSource {
    /// Writes the data of `object` to `sink`, which `reference` says
    /// where to find: exactly `object.size` bytes when the object has a
    /// size.
    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error>;

    /// Called after the data of `last` was copied and checked, the last
    /// file object whose data the source has. A source that has more data
    /// than the file objects account for fails here.
    fn end(&mut self, _last: &FileObject) -> Result<(), Error> {
        Ok(())
    }

    /// Whether the source hands the data out in one order only, the order
    /// of the manifest, and each file's data once.
    fn sequential(&self) -> bool {
        false
    }
}

/// Why a [`Directory`] does not hand out a file.
#[derive(Debug)]
pub enum OpenError {
    /// What the name names is not a regular file.
    NotRegular,
    /// The file could not be reached. An error of the kind `NotFound` or
    /// `NotADirectory` says the file is not there.
    Io(io::Error),
}

impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> OpenError {
        OpenError::Io(e)
    }
}

/// A place that holds the files a manifest refers to: the directory the
/// manifest is in.
///
/// A manifest is not to be trusted to stay inside that directory. The
/// names it gives are normalized relative paths, see [`Name`], but a
/// symbolic link in the directory can still lead out of it. It is on the
/// implementation to resolve a name below the directory and nowhere else.
pub trait Directory {
    /// A file of the directory, open for reading.
    type File: Read + Seek;

    /// Opens the regular file `file` names, and returns it with its
    /// size.
    fn open(&self, file: &Name) -> Result<(Self::File, u64), OpenError>;

    /// The size of the regular file `file` names, without opening it.
    fn size(&self, file: &Name) -> Result<u64, OpenError>;
}

/// Takes the data of file objects from the files next to the manifest,
/// in a [`Directory`].
///
/// A file can hold the data of many file objects, each a part of it, and
/// the manifest can give the hash of the whole file with every one of
/// them. Such a file is read whole for the first of them. The source keeps
/// the hash of every piece of it, and the others are checked against
/// those. So the time a manifest takes does not grow with the number of
/// file objects times the size of the file.
#[derive(Debug)]
pub struct DirectorySource<D> {
    directory: D,
    /// What a copy goes through, made when the first file is copied.
    buffer: Vec<u8>,
    /// The files that were read whole and have the hash the manifest
    /// gives for them, by their names.
    whole: HashMap<Name, Whole>,
}

/// A file that was read whole and has the hash the manifest gives for it.
#[derive(Debug)]
struct Whole {
    sha256: Sha256,
    len: u64,
    /// The hash of every [`COPY_SIZE`] bytes of the file, and of what is
    /// left at its end.
    pieces: Vec<Sha256>,
}

impl<D: Directory> DirectorySource<D> {
    /// A source that takes the files from `directory`.
    pub fn new(directory: D) -> DirectorySource<D> {
        DirectorySource {
            directory,
            buffer: Vec::new(),
            whole: HashMap::new(),
        }
    }

    /// The directory the files are taken from.
    pub fn directory(&self) -> &D {
        &self.directory
    }

    /// Checks, without reading any data, that every file the regular
    /// files among `objects` have their data in is in the directory, is a
    /// regular file and is as long as the manifest says. A caller runs
    /// this before it makes anything out of the manifest, so that a wrong
    /// directory is found with nothing half-made left behind. The sizes
    /// and hashes of the data itself are checked while it is copied.
    ///
    /// Objects that have their data in the manifest, or in a way that is
    /// not supported, are passed over.
    pub fn verify<'a>(&self, objects: impl IntoIterator<Item = &'a FileObject>) -> Result<(), Error> {
        for object in objects {
            if object.inode_type != InodeType::Regular {
                continue;
            }
            let Some(Data::External(reference)) = object.plain_data() else {
                continue;
            };
            let len = self
                .directory
                .size(reference.file)
                .map_err(|e| reference.unavailable(object, e))?;
            reference.check_len(object, len, ErrorKind::Source(SourceProblem::Size))?;
        }
        Ok(())
    }
}

impl Reference<'_> {
    /// The error for the file of the reference that `object` cannot be
    /// taken from.
    fn unavailable(&self, object: &FileObject, error: OpenError) -> Error {
        let name = &object.name;
        let error = match error {
            OpenError::NotRegular => {
                let message = format!("{}: {} is not a regular file", name, self.file);
                return Error::new(ErrorKind::Source(SourceProblem::NotRegular), message).named(name.as_str());
            }
            OpenError::Io(error) => error,
        };
        let problem = match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => SourceProblem::Missing,
            io::ErrorKind::InvalidInput => SourceProblem::NotRegular,
            _ => SourceProblem::Unreadable,
        };
        let message = format!("{}: failed to open {}: {}", name, self.file, error);
        Error::new(ErrorKind::Source(problem), message)
            .named(name.as_str())
            .caused_by(error)
    }
}

/// A file a [`DirectorySource`] copies a part of.
struct Pieces<'a, F> {
    file: F,
    /// What a piece is read into: [`COPY_SIZE`] bytes.
    buffer: &'a mut [u8],
    /// Where in the file the next piece starts.
    pos: u64,
    /// Whether the file was read to its end.
    ended: bool,
    /// The part of the file that is copied.
    data: Range<u64>,
}

impl<F: Read + Seek> Pieces<'_, F> {
    /// Copies the part without a look at the rest of the file.
    fn copy_part(&mut self, sink: &mut dyn Write) -> io::Result<()> {
        // Most files are copied whole and need no seek.
        if self.data.start > 0 {
            self.file.seek(SeekFrom::Start(self.data.start))?;
        }
        let mut remaining = self.data.end - self.data.start;
        while remaining > 0 {
            let want = (self.buffer.len() as u64).min(remaining) as usize;
            let read = self.file.read_some(&mut self.buffer[..want])?;
            if read == 0 {
                break;
            }
            sink.write_all(&self.buffer[..read])?;
            remaining -= read as u64;
        }
        Ok(())
    }

    /// Reads the next piece and writes what of it is to be copied to
    /// `sink`. Returns the piece, which is empty at the end of the file.
    fn copy_piece(&mut self, sink: &mut dyn Write) -> io::Result<&[u8]> {
        let mut len = 0;
        while len < self.buffer.len() && !self.ended {
            let read = self.file.read_some(&mut self.buffer[len..])?;
            self.ended = read == 0;
            len += read;
        }
        let piece = &self.buffer[..len];
        let within = |at: u64| at.saturating_sub(self.pos).min(len as u64) as usize;
        let (start, end) = (within(self.data.start), within(self.data.end));
        if start < end {
            sink.write_all(&piece[start..end])?;
        }
        self.pos += len as u64;
        Ok(piece)
    }

    /// Reads all of the file, copies the part and returns the hash of the
    /// file. The hash of every piece goes to `pieces`, if there is one.
    fn copy_hashed(&mut self, sink: &mut dyn Write, mut pieces: Option<&mut Vec<Sha256>>) -> io::Result<Sha256> {
        let mut hasher = Sha256Hasher::default();
        loop {
            let piece = self.copy_piece(sink)?;
            if piece.is_empty() {
                return Ok(hasher.finish());
            }
            hasher.update(piece);
            if let Some(pieces) = &mut pieces {
                pieces.push(Sha256::of(piece));
            }
        }
    }

    /// Copies the part and checks every piece it is in against the hash
    /// in `pieces`. Returns whether they are the pieces of that file.
    fn copy_checked(&mut self, sink: &mut dyn Write, pieces: &[Sha256]) -> io::Result<bool> {
        let first = self.data.start / self.buffer.len() as u64;
        if first > 0 {
            self.pos = first * self.buffer.len() as u64;
            self.file.seek(SeekFrom::Start(self.pos))?;
        }
        let mut expected = pieces.iter().skip(usize::try_from(first).unwrap_or(usize::MAX));
        while self.pos < self.data.end {
            let piece = Sha256::of(self.copy_piece(sink)?);
            if expected.next() != Some(&piece) {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

impl<D: Directory> ContentSource for DirectorySource<D> {
    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error> {
        let (file, len) = self
            .directory
            .open(reference.file)
            .map_err(|e| reference.unavailable(object, e))?;
        let size = reference.check_len(object, len, ErrorKind::Content(ContentProblem::Size))?;
        self.buffer.resize(COPY_SIZE, 0);
        let mut pieces = Pieces {
            file,
            buffer: &mut self.buffer,
            pos: 0,
            ended: false,
            // check_len made sure that this is inside the file.
            data: reference.offset..reference.offset + size,
        };
        let Some(sha256) = reference.original_sha256 else {
            return Ok(pieces.copy_part(sink)?);
        };
        // The hash of the whole file is checked by reading all of it. What
        // is not the data of the object is hashed and not copied.
        let matches = if pieces.data == (0..len) {
            pieces.copy_hashed(sink, None)? == sha256
        } else if let Some(whole) = self
            .whole
            .get(reference.file)
            .filter(|whole| whole.sha256 == sha256 && whole.len == len)
        {
            // The file was read whole for another part of it.
            pieces.copy_checked(sink, &whole.pieces)?
        } else {
            let mut hashes = Vec::new();
            let matches = pieces.copy_hashed(sink, Some(&mut hashes))? == sha256;
            if matches {
                let whole = Whole {
                    sha256,
                    len,
                    pieces: hashes,
                };
                self.whole.insert(reference.file.clone(), whole);
            }
            matches
        };
        if !matches {
            let message = format!(
                "{}: {} does not match the hash in the manifest",
                object.name, reference.file
            );
            return Err(Error::new(ErrorKind::Content(ContentProblem::Hash), message).named(object.name.as_str()));
        }
        Ok(())
    }
}

/// Takes the data of file objects from one stream that carries the data
/// of every one of them back to back, in the order of the manifest.
#[derive(Debug)]
pub struct StreamSource<R> {
    reader: R,
    /// What a copy goes through, made when the first file is copied.
    buffer: Vec<u8>,
}

impl<R: Read> StreamSource<R> {
    /// A source that takes the data from `reader`.
    pub fn new(reader: R) -> StreamSource<R> {
        StreamSource {
            reader,
            buffer: Vec::new(),
        }
    }
}

impl<R: Read> ContentSource for StreamSource<R> {
    fn sequential(&self) -> bool {
        true
    }

    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error> {
        let name = &object.name;
        if reference.offset != 0 {
            let message = format!("{}: an offset cannot be used with streamed contents", name);
            return Err(Error::new(ErrorKind::Unsupported(Unsupported::Offset), message).named(name.as_str()));
        }
        let Some(total) = object.size else {
            let message = format!("{}: streamed contents need a known size", name);
            return Err(Error::manifest(Problem::NoSize, message)
                .at(Field::Size)
                .named(name.as_str()));
        };
        self.buffer.resize(COPY_SIZE, 0);
        let mut remaining = total;
        while remaining > 0 {
            let want = (self.buffer.len() as u64).min(remaining) as usize;
            let read = self.reader.read_some(&mut self.buffer[..want])?;
            if read == 0 {
                let message = format!("{}: the stream ended {} bytes early", name, remaining);
                return Err(Error::new(ErrorKind::Content(ContentProblem::StreamEnded), message)
                    .named(name.as_str())
                    .sizes(Some(total - remaining), Some(total)));
            }
            sink.write_all(&self.buffer[..read])?;
            remaining -= read as u64;
        }
        Ok(())
    }

    /// The stream ends with the last file. Anything behind it is data the
    /// manifest does not describe, so the last file got more than the
    /// manifest says.
    fn end(&mut self, last: &FileObject) -> Result<(), Error> {
        let mut byte = [0u8; 1];
        if self.reader.read_some(&mut byte)? > 0 {
            let message = format!("{}: the stream goes on after the last file", last.name);
            return Err(Error::new(ErrorKind::Content(ContentProblem::Size), message)
                .named(last.name.as_str())
                .sizes(None, last.size));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{manifest, HELLO, WORLD};
    use crate::Manifest;
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    /// What is in a directory under a name.
    #[derive(Debug)]
    enum Entry {
        File(Rc<[u8]>),
        /// Something that is no regular file.
        Other,
        /// Something that cannot be reached, for this reason.
        Fails(i32),
    }

    /// A directory in memory. It counts the bytes that are read from its
    /// files.
    #[derive(Debug, Default)]
    struct Files {
        entries: RefCell<HashMap<&'static str, Entry>>,
        read: Rc<Cell<u64>>,
    }

    /// A file of [`Files`].
    #[derive(Debug)]
    struct Counted {
        data: io::Cursor<Rc<[u8]>>,
        read: Rc<Cell<u64>>,
    }

    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let read = self.data.read(buf)?;
            self.read.set(self.read.get() + read as u64);
            Ok(read)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            self.data.seek(to)
        }
    }

    impl Files {
        fn of(list: &[(&'static str, &'static [u8])]) -> Files {
            let files = Files::default();
            for &(name, data) in list {
                files.put(name, Entry::File(data.into()));
            }
            files
        }

        fn put(&self, name: &'static str, entry: Entry) {
            self.entries.borrow_mut().insert(name, entry);
        }

        /// How many bytes were read since this was asked last.
        fn read(&self) -> u64 {
            self.read.replace(0)
        }

        fn find(&self, file: &Name) -> Result<Rc<[u8]>, OpenError> {
            match self.entries.borrow().get(file.as_str()) {
                Some(Entry::File(data)) => Ok(Rc::clone(data)),
                Some(Entry::Other) => Err(OpenError::NotRegular),
                Some(Entry::Fails(errno)) => Err(io::Error::from_raw_os_error(*errno).into()),
                None => Err(io::Error::from_raw_os_error(libc::ENOENT).into()),
            }
        }
    }

    impl Directory for Files {
        type File = Counted;

        fn open(&self, file: &Name) -> Result<(Counted, u64), OpenError> {
            let data = self.find(file)?;
            let len = data.len() as u64;
            let file = Counted {
                data: io::Cursor::new(data),
                read: Rc::clone(&self.read),
            };
            Ok((file, len))
        }

        fn size(&self, file: &Name) -> Result<u64, OpenError> {
            self.find(file).map(|data| data.len() as u64)
        }
    }

    /// The file objects of the manifest with the records `records`.
    fn objects(records: &[&str]) -> Vec<FileObject> {
        Manifest::parse(&manifest(records))
            .unwrap_or_else(|e| panic!("{:?}: {}", records, e))
            .objects
    }

    fn object(record: &str) -> FileObject {
        objects(&[record]).remove(0)
    }

    /// Copies the contents of `object` from `source`.
    fn copy(object: &FileObject, source: &mut dyn ContentSource) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        let written = object.copy_contents(source, &mut out)?;
        assert_eq!(written, out.len() as u64);
        Ok(out)
    }

    /// The kind, the name, the sizes and the text of an error.
    fn facts(e: &Error) -> (ErrorKind, Option<&str>, Option<u64>, Option<u64>, String) {
        (e.kind(), e.name(), e.size(), e.expected_size(), e.to_string())
    }

    #[test]
    fn where_the_data_is() {
        // Without contents objects it is in the file of the object's name.
        let o = object(r#"{"name":"dir/x","size":5}"#);
        let Data::External(reference) = o.data().unwrap() else {
            panic!()
        };
        assert_eq!(reference.file.as_str(), "dir/x");
        assert_eq!(
            (reference.offset, reference.original_size, reference.original_sha256),
            (0, None, None)
        );
        assert!(o.is_streamed());
        // The first contents object that has the data as it is gives it: a
        // URL and an encoding are passed over.
        let o = object(&format!(
            concat!(
                r#"{{"name":"x","size":3,"contents":[{{"url":"https://example.com/x"}},"#,
                r#"{{"file":"x.gz","encoding":"gzip"}},"#,
                r#"{{"file":"data/y.bin","offset":2,"originalSize":9,"originalSha256":"{}"}},"#,
                r#"{{"literal":"aGVsbG8="}}]}}"#
            ),
            WORLD
        ));
        let Data::External(reference) = o.data().unwrap() else {
            panic!()
        };
        assert_eq!(reference.file.as_str(), "data/y.bin");
        assert_eq!((reference.offset, reference.original_size), (2, Some(9)));
        assert_eq!(reference.original_sha256, WORLD.parse().ok());
        assert!(o.is_streamed());
        let o = object(concat!(
            r#"{"name":"x","contents":[{"url":"https://example.com/x"},{"literal":"AAAA","encoding":"gzip"},"#,
            r#"{"literal":"aGVsbG8="},{"file":"y"}]}"#
        ));
        assert_eq!(o.data().unwrap(), Data::Literal(b"hello"));
        assert!(!o.is_streamed());
        // A contents object that names no place is the file of the
        // object's name.
        let o = object(r#"{"name":"x","contents":[{"offset":1,"originalSize":4}]}"#);
        let Data::External(reference) = o.data().unwrap() else {
            panic!()
        };
        assert_eq!((reference.file.as_str(), reference.offset), ("x", 1));
        // The part of a literal that the object is.
        for (record, data) in [
            (
                r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":1}],"size":3}"#,
                "ell",
            ),
            (r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":3}]}"#, "lo"),
            (r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":5}]}"#, ""),
            (r#"{"name":"x","contents":[{"literal":"aGVsbG8="}],"size":2}"#, "he"),
        ] {
            assert_eq!(
                object(record).data().unwrap(),
                Data::Literal(data.as_bytes()),
                "{}",
                record
            );
        }
        // Data that only comes in ways this crate does not go.
        let o = object(concat!(
            r#"{"name":"dir/x","contents":[{"url":"https://example.com/x"},{"file":"x.zst","encoding":"zstd"},"#,
            r#"{"url":"http://example.com/x"},{"literal":"AAAA","encoding":"gzip"},{"encoding":"zstd"}]}"#
        ));
        let e = o.data().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported(Unsupported::Transport));
        assert_eq!(e.name(), Some("dir/x"));
        assert_eq!(e.value(), Some("'gzip' encoding or 'zstd' encoding or a URL"));
        assert_eq!(
            e.to_string(),
            "'dir/x' is only available through 'gzip' encoding or 'zstd' encoding or a URL, which is not supported"
        );
        assert!(!o.is_streamed());
        // Only a regular file has data a source hands out.
        assert!(!object(r#"{"name":"x","type":"dir"}"#).is_streamed());
        assert!(!object(r#"{"name":"x","type":"lnk"}"#).is_streamed());
        assert!(!object(r#"{"name":"x","type":"lnk","contents":[{"literal":"YQ=="}]}"#).is_streamed());
    }

    #[test]
    fn copies_from_a_directory() {
        let files = Files::of(&[("a", b"hello world"), ("empty", b""), ("dir/b", b"hello")]);
        let mut source = DirectorySource::new(files);
        assert!(!source.sequential());
        assert!(source.directory().size(&Name::new("a").unwrap()).is_ok());
        for (record, data) in [
            // A whole file, by the name of the object and by a file reference.
            (format!(r#"{{"name":"dir/b","size":5,"sha256":"{}"}}"#, HELLO), "hello"),
            (
                format!(
                    r#"{{"name":"x","size":5,"sha256":"{}","contents":[{{"file":"dir/b"}}]}}"#,
                    HELLO
                ),
                "hello",
            ),
            (r#"{"name":"dir/b"}"#.to_string(), "hello"),
            (r#"{"name":"empty","size":0}"#.to_string(), ""),
            (r#"{"name":"empty"}"#.to_string(), ""),
            // Parts of a file: at an offset, and out of a larger file.
            (
                format!(
                    r#"{{"name":"c","size":5,"sha256":"{}","contents":[{{"file":"a","offset":6}}]}}"#,
                    WORLD
                ),
                "world",
            ),
            (
                r#"{"name":"d","size":3,"contents":[{"file":"a","offset":2}]}"#.to_string(),
                "llo",
            ),
            (
                r#"{"name":"d","contents":[{"file":"a","offset":6}]}"#.to_string(),
                "world",
            ),
            (r#"{"name":"d","contents":[{"file":"a","offset":11}]}"#.to_string(), ""),
            (
                format!(
                    r#"{{"name":"e","size":5,"sha256":"{}","contents":[{{"file":"a","originalSize":11}}]}}"#,
                    HELLO
                ),
                "hello",
            ),
            (
                r#"{"name":"f","size":11,"contents":[{"file":"a","originalSize":11}]}"#.to_string(),
                "hello world",
            ),
            // The hash of the whole file is checked too.
            (
                format!(
                    r#"{{"name":"g","size":5,"contents":[{{"file":"a","offset":6,"originalSize":11,"originalSha256":"{}"}}]}}"#,
                    Sha256::of(b"hello world")
                ),
                "world",
            ),
            // A literal needs no source.
            (
                r#"{"name":"missing","contents":[{"literal":"aGVsbG8="}]}"#.to_string(),
                "hello",
            ),
        ] {
            let o = object(&record);
            assert_eq!(copy(&o, &mut source).unwrap(), data.as_bytes(), "{}", record);
            source.verify([&o]).unwrap_or_else(|e| panic!("{}: {}", record, e));
        }
    }

    #[test]
    fn files_that_are_not_what_the_manifest_says() {
        let files = Files::of(&[("a", b"hello world"), ("dir/b", b"hello")]);
        let mut source = DirectorySource::new(files);
        let size = ErrorKind::Content(ContentProblem::Size);
        let hash = ErrorKind::Content(ContentProblem::Hash);
        for (record, expected) in [
            // A file the manifest takes whole has the size of the manifest:
            // one that grew fails like one that shrank.
            (
                format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
                (
                    size,
                    Some("a"),
                    Some(11),
                    Some(5),
                    "a: a is 11 bytes, the manifest says 5",
                ),
            ),
            (
                r#"{"name":"x/y","size":12,"contents":[{"file":"a"}]}"#.to_string(),
                (
                    size,
                    Some("x/y"),
                    Some(11),
                    Some(12),
                    "x/y: a is 11 bytes, the manifest says 12",
                ),
            ),
            // An originalSize that is not the file's.
            (
                r#"{"name":"h","size":5,"contents":[{"file":"a","originalSize":12}]}"#.to_string(),
                (
                    size,
                    Some("h"),
                    Some(11),
                    Some(12),
                    "h: a is 11 bytes, the manifest says 12",
                ),
            ),
            // A part that runs past the end.
            (
                r#"{"name":"g","size":6,"contents":[{"file":"a","offset":6}]}"#.to_string(),
                (
                    size,
                    Some("g"),
                    Some(11),
                    Some(12),
                    "g: a is too short for offset 6 and size 6",
                ),
            ),
            (
                r#"{"name":"g","contents":[{"file":"a","offset":12}]}"#.to_string(),
                (
                    size,
                    Some("g"),
                    Some(11),
                    Some(12),
                    "g: a is too short for offset 12 and size 0",
                ),
            ),
            // Contents that are not the ones the manifest describes.
            (
                format!(r#"{{"name":"dir/b","size":5,"sha256":"{}"}}"#, WORLD),
                (
                    hash,
                    Some("dir/b"),
                    None,
                    None,
                    "'dir/b' does not match the hash in the manifest",
                ),
            ),
            (
                format!(
                    r#"{{"name":"dir/b","size":2,"contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
                    WORLD
                ),
                (
                    hash,
                    Some("dir/b"),
                    None,
                    None,
                    "dir/b: dir/b does not match the hash in the manifest",
                ),
            ),
        ] {
            let o = object(&record);
            let e = copy(&o, &mut source).unwrap_err();
            let (kind, name, found, expected_size, text) = expected;
            assert_eq!(
                facts(&e),
                (kind, name, found, expected_size, text.to_string()),
                "{}",
                record
            );
            // Up front the sizes are found, as a problem of the source. The
            // contents are not looked at.
            let up_front = source.verify([&o]);
            if kind == size {
                let e = up_front.unwrap_err();
                let source_size = ErrorKind::Source(SourceProblem::Size);
                assert_eq!(
                    facts(&e),
                    (source_size, name, found, expected_size, text.to_string()),
                    "{}",
                    record
                );
            } else {
                up_front.unwrap();
            }
        }
        // A literal that is not what the object says.
        let o = object(
            r#"{"name":"x","size":5,"contents":[{"literal":"aGVsbG8="}],"sha256":"486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"}"#,
        );
        assert_eq!(copy(&o, &mut source).unwrap_err().kind(), hash);
        let mut o = object(r#"{"name":"x","contents":[{"literal":"aGVsbG8="}]}"#);
        o.size = Some(6);
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(
            facts(&e),
            (
                size,
                Some("x"),
                Some(5),
                Some(6),
                "'x' is 5 bytes, the manifest says 6".to_string()
            )
        );
    }

    #[test]
    fn parts_of_one_file() {
        // A file of three pieces and a half, no two of them the same.
        let len = 3 * COPY_SIZE + COPY_SIZE / 2;
        let blob: Vec<u8> = (0..len).map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8).collect();
        let whole = Sha256::of(&blob);
        let files = Files::default();
        files.put("blob", Entry::File(blob[..].into()));
        let mut source = DirectorySource::new(files);
        let part = |offset: usize, size: usize, total: usize, sha256: Option<Sha256>| {
            let sha256 = sha256.map(|sha256| format!(r#","originalSha256":"{}""#, sha256));
            object(&format!(
                r#"{{"name":"p","size":{},"contents":[{{"file":"blob","offset":{},"originalSize":{}{}}}]}}"#,
                size,
                offset,
                total,
                sha256.unwrap_or_default()
            ))
        };
        let hash = ErrorKind::Content(ContentProblem::Hash);
        let parts = [
            (5, 10),
            (0, 1),
            (COPY_SIZE - 1, 2),
            (COPY_SIZE, COPY_SIZE),
            (2 * COPY_SIZE + 7, COPY_SIZE + 9),
            (len - 3, 3),
            (len, 0),
            (17, 0),
            (1, len - 1),
            (0, len),
        ];
        // Without the hash of the file a part is all that is read.
        for (offset, size) in parts {
            let o = part(offset, size, len, None);
            assert_eq!(copy(&o, &mut source).unwrap(), &blob[offset..offset + size]);
            assert_eq!(source.directory().read(), size as u64);
        }
        // With it the file is read whole for the first part. For the
        // others the pieces they are in are read.
        let mut first = true;
        for (offset, size) in parts {
            let o = part(offset, size, len, Some(whole));
            assert_eq!(copy(&o, &mut source).unwrap(), &blob[offset..offset + size]);
            let from = offset / COPY_SIZE * COPY_SIZE;
            let to = (offset + size).next_multiple_of(COPY_SIZE).min(len);
            let pieces = if first { len } else { to.saturating_sub(from) };
            assert_eq!(source.directory().read(), pieces as u64, "{} at {}", size, offset);
            first = false;
        }
        // Another hash for the same file is not taken on trust.
        let o = part(5, 10, len, Some(Sha256::of(b"another file")));
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(
            facts(&e),
            (
                hash,
                Some("p"),
                None,
                None,
                "p: blob does not match the hash in the manifest".to_string()
            )
        );
        assert_eq!(source.directory().read(), len as u64);
        // A file that changed is found out where it changed, and a file
        // of another length is read whole again.
        let mut changed = blob.clone();
        changed[2 * COPY_SIZE + 100] ^= 1;
        source.directory().put("blob", Entry::File(changed[..].into()));
        for (offset, size, good) in [
            (5, 10, true),
            (COPY_SIZE, COPY_SIZE, true),
            (2 * COPY_SIZE, 5, false),
            (2 * COPY_SIZE + 100, 1, false),
            (COPY_SIZE + 5, COPY_SIZE, false),
            (3 * COPY_SIZE - 1, 2, false),
            (3 * COPY_SIZE, 1, true),
            (1, len - 1, false),
            (0, len, false),
        ] {
            let copied = copy(&part(offset, size, len, Some(whole)), &mut source);
            match copied {
                Ok(data) => assert!(good && data == changed[offset..offset + size], "{} at {}", size, offset),
                Err(e) => assert!(!good && e.kind() == hash, "{} at {}: {}", size, offset, e),
            }
        }
        source.directory().read();
        source.directory().put("blob", Entry::File(blob[..len - 1].into()));
        let e = copy(&part(5, 10, len - 1, Some(whole)), &mut source).unwrap_err();
        assert_eq!(e.kind(), hash);
        assert_eq!(source.directory().read(), len as u64 - 1);
        let shorter = Sha256::of(&blob[..len - 1]);
        for _ in 0..2 {
            let o = part(len - 11, 10, len - 1, Some(shorter));
            assert_eq!(copy(&o, &mut source).unwrap(), &blob[len - 11..len - 1]);
        }
        assert_eq!(source.directory().read(), (len - 1 + COPY_SIZE / 2 - 1) as u64);
        // A file that is one object is read once, hash or no hash.
        let source_of_small = || DirectorySource::new(Files::of(&[("a", b"hello")]));
        for record in [
            r#"{"name":"a","size":5}"#.to_string(),
            format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
            format!(
                r#"{{"name":"a","contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
                HELLO
            ),
        ] {
            let mut source = source_of_small();
            for _ in 0..2 {
                assert_eq!(copy(&object(&record), &mut source).unwrap(), b"hello", "{}", record);
                assert_eq!(source.directory().read(), 5);
            }
        }
    }

    #[test]
    fn files_that_are_not_there() {
        let files = Files::of(&[("a", b"hello")]);
        files.put("fifo", Entry::Other);
        files.put("below-a-file/x", Entry::Fails(libc::ENOTDIR));
        files.put("odd", Entry::Fails(libc::EINVAL));
        files.put("link", Entry::Fails(libc::ELOOP));
        files.put("secret", Entry::Fails(libc::EACCES));
        let mut source = DirectorySource::new(files);
        for (file, problem, errno, text) in [
            (
                "missing",
                SourceProblem::Missing,
                Some(libc::ENOENT),
                "x: failed to open missing: ",
            ),
            (
                "below-a-file/x",
                SourceProblem::Missing,
                Some(libc::ENOTDIR),
                "x: failed to open below-a-file/x: ",
            ),
            ("fifo", SourceProblem::NotRegular, None, "x: fifo is not a regular file"),
            (
                "odd",
                SourceProblem::NotRegular,
                Some(libc::EINVAL),
                "x: failed to open odd: ",
            ),
            (
                "link",
                SourceProblem::Unreadable,
                Some(libc::ELOOP),
                "x: failed to open link: ",
            ),
            (
                "secret",
                SourceProblem::Unreadable,
                Some(libc::EACCES),
                "x: failed to open secret: ",
            ),
        ] {
            let o = object(&format!(
                r#"{{"name":"x","size":5,"contents":[{{"file":"{}"}}]}}"#,
                file
            ));
            for e in [copy(&o, &mut source).unwrap_err(), source.verify([&o]).unwrap_err()] {
                assert_eq!(e.kind(), ErrorKind::Source(problem), "{}", file);
                assert_eq!(e.name(), Some("x"));
                assert_eq!(e.io_error().and_then(io::Error::raw_os_error), errno, "{}", file);
                let cause = errno.map(|errno| io::Error::from_raw_os_error(errno).to_string());
                assert_eq!(e.to_string(), format!("{}{}", text, cause.unwrap_or_default()));
            }
        }
        // The check up front is of the regular files that have their data
        // in a file. It stops at the first one that is not right.
        let all = objects(&[
            r#"{"name":"d","type":"dir"}"#,
            r#"{"name":"l","type":"lnk"}"#,
            r#"{"name":"literal","contents":[{"literal":"aGVsbG8="}]}"#,
            r#"{"name":"remote","contents":[{"url":"https://example.com/x"}]}"#,
            r#"{"name":"a","size":5}"#,
            r#"{"name":"missing","size":5}"#,
            r#"{"name":"fifo","size":5}"#,
        ]);
        assert_eq!(source.verify(&all).unwrap_err().name(), Some("missing"));
        source.verify(&all[..5]).unwrap();
        source
            .verify(all.iter().filter(|o| o.name != "missing" && o.name != "fifo"))
            .unwrap();
    }

    #[test]
    fn copies_from_a_stream() {
        let all = objects(&[
            &format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
            r#"{"name":"d","type":"dir"}"#,
            r#"{"name":"literal","contents":[{"literal":"aGVsbG8="}]}"#,
            r#"{"name":"empty","size":0}"#,
            &format!(
                r#"{{"name":"d/b","size":5,"sha256":"{}","contents":[{{"file":"other"}}]}}"#,
                WORLD
            ),
        ]);
        let streamed: Vec<&FileObject> = all.iter().filter(|o| o.is_streamed()).collect();
        assert_eq!(streamed.len(), 3);
        let mut stream = &b"helloworld"[..];
        let mut source = StreamSource::new(&mut stream);
        assert!(source.sequential());
        assert_eq!(copy(streamed[0], &mut source).unwrap(), b"hello");
        assert_eq!(copy(&all[2], &mut source).unwrap(), b"hello");
        assert_eq!(copy(streamed[1], &mut source).unwrap(), b"");
        assert_eq!(copy(streamed[2], &mut source).unwrap(), b"world");
        source.end(streamed[2]).unwrap();
        assert!(stream.is_empty());

        // A stream that ends early, and one that goes on after the last file.
        let mut stream = &b"hellowo"[..];
        let mut source = StreamSource::new(&mut stream);
        copy(streamed[0], &mut source).unwrap();
        let e = copy(streamed[2], &mut source).unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::StreamEnded),
                Some("d/b"),
                Some(2),
                Some(5),
                "d/b: the stream ended 3 bytes early".to_string()
            )
        );
        let mut stream = &b"helloworldmore"[..];
        let mut source = StreamSource::new(&mut stream);
        copy(streamed[0], &mut source).unwrap();
        copy(streamed[2], &mut source).unwrap();
        let e = source.end(streamed[2]).unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::Size),
                Some("d/b"),
                None,
                Some(5),
                "d/b: the stream goes on after the last file".to_string()
            )
        );
        // Contents that are not the ones the manifest describes.
        let mut stream = &b"hellp"[..];
        let e = copy(streamed[0], &mut StreamSource::new(&mut stream)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Content(ContentProblem::Hash));
        // A stream has no place for a file without a size or at an offset.
        let mut stream = &b"hello"[..];
        let mut source = StreamSource::new(&mut stream);
        let e = copy(&object(r#"{"name":"x"}"#), &mut source).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoSize));
        assert_eq!((e.name(), e.field()), (Some("x"), Some(Field::Size)));
        let e = copy(
            &object(r#"{"name":"x","size":2,"contents":[{"offset":1}]}"#),
            &mut source,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported(Unsupported::Offset));
        assert_eq!(e.name(), Some("x"));
        assert_eq!(stream, b"hello");
    }

    /// Takes a few bytes and then fails.
    #[derive(Debug)]
    struct Full(usize);

    impl Write for Full {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if data.len() > self.0 {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.0 -= data.len();
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_sink_that_fails() {
        let o = object(r#"{"name":"a","size":5}"#);
        let literal = object(r#"{"name":"l","contents":[{"literal":"aGVsbG8="}]}"#);
        let mut directory = DirectorySource::new(Files::of(&[("a", b"hello")]));
        let mut stream = &b"hello"[..];
        let mut stream = StreamSource::new(&mut stream);
        let sources: [(&FileObject, &mut dyn ContentSource); 3] = [
            (&o, &mut directory),
            (&o, &mut stream),
            (&literal, &mut directory_of_nothing()),
        ];
        for (object, source) in sources {
            let e = object.copy_contents(source, &mut Full(4)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Io);
            assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::ENOSPC));
        }
    }

    fn directory_of_nothing() -> DirectorySource<Files> {
        DirectorySource::new(Files::default())
    }
}
