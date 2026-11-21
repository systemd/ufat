// SPDX-License-Identifier: LGPL-2.1-or-later
//! The contents of the files a manifest describes: where they are, and
//! copying them from there with the sizes and hashes of the manifest
//! checked.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;

use crate::digest::{Finalize, Sha256Context};
use crate::error::{ContentProblem, Error, ErrorKind, Field, SourceProblem, UnsupportedContent};
use crate::object::{Contents, FileObject, InodeType, Location};
use crate::{Name, Sha256};

/// How much a source copies at a time. It is also the smallest piece a
/// file is hashed in.
const COPY_SIZE: usize = 1024 * 1024;
/// How many bytes the hashes a [`DirectorySource`] keeps of the pieces of
/// files take at most: 32 bytes for every piece of a file, and what the
/// file takes besides, see [`PieceHashes::stored_bytes`]. The map that
/// holds them adds up to about half a MiB, with many small files, which
/// does not grow with the manifest either.
const PIECE_HASH_BYTES: usize = 1024 * 1024;
/// What a file takes in [`PieceHashes`] besides the hashes of its pieces:
/// its hash and its length, which it is known by, and the pointer to the
/// hashes of its pieces.
const FILE_ENTRY_BYTES: usize = size_of::<(Sha256, u64)>() + size_of::<Box<[Sha256]>>();
/// The most pieces a file is hashed in, so that the hashes of a file of
/// any length fit into [`PIECE_HASH_BYTES`].
const MAX_PIECES: u64 = ((PIECE_HASH_BYTES - FILE_ENTRY_BYTES) / size_of::<Sha256>()) as u64;

/// Where the data of a file object is, as [`FileObject::data`] finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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

/// How much of its file the data of a file object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataExtent {
    /// All of the file.
    WholeFile,
    /// A part of it.
    PartOfFile,
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
    /// data: the rest of the file from the offset on when the object gives
    /// none. A length that does not fit is a
    /// [`ContentProblem::SizeMismatch`].
    ///
    /// The data is the part of the file that starts at the offset and is
    /// as long as the object says, whatever else the file holds. So the
    /// file has to be long enough for it, and as long as `originalSize`
    /// where the manifest gives that.
    fn check_len(&self, object: &FileObject, len: u64) -> Result<u64, Error> {
        let name = &object.name;
        let mismatch = |message: String| {
            Error::new(ErrorKind::Content(ContentProblem::SizeMismatch), message).named(name.as_str())
        };
        if let Some(total) = self.original_size.filter(|&total| total != len) {
            let message = format!(
                "{}: {} is {} bytes, the manifest says {}",
                name.escape_debug(),
                self.file.escape_debug(),
                len,
                total
            );
            return Err(mismatch(message).sizes(Some(len), Some(total)));
        }
        let size = object.size.unwrap_or(len.saturating_sub(self.offset));
        let end = self.offset.checked_add(size);
        if end.is_none_or(|end| end > len) {
            let message = format!(
                "{}: {} is too short for offset {} and size {}",
                name.escape_debug(),
                self.file.escape_debug(),
                self.offset,
                size
            );
            return Err(mismatch(message).sizes(Some(len), end));
        }
        Ok(size)
    }

    /// The error for the file of the reference that `object` cannot be
    /// taken from.
    fn unavailable(&self, object: &FileObject, error: OpenError) -> Error {
        let name = &object.name;
        let error = match error {
            OpenError::NotRegular => {
                let message = format!(
                    "{}: {} is not a regular file",
                    name.escape_debug(),
                    self.file.escape_debug()
                );
                return Error::new(ErrorKind::Source(SourceProblem::NotRegular), message).named(name.as_str());
            }
            OpenError::Io(error) => error,
        };
        let problem = match error.kind() {
            io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => SourceProblem::Missing,
            io::ErrorKind::InvalidInput => SourceProblem::NotRegular,
            _ => SourceProblem::Unreadable,
        };
        let message = format!(
            "{}: failed to open {}: {}",
            name.escape_debug(),
            self.file.escape_debug(),
            error
        );
        Error::new(ErrorKind::Source(problem), message)
            .named(name.as_str())
            .caused_by(error)
    }
}

impl FileObject {
    /// Where the data of the file is: the contents of a regular file, the
    /// target of a symbolic link, or the manifest of its own that a
    /// directory refers to.
    ///
    /// A literal is taken first, as the specification suggests: the
    /// manifest carries the data itself. Otherwise the data is in the file
    /// next to the manifest that the first contents object without an
    /// encoding names, or in the file of the object's own name where that
    /// contents object names no place. A regular file without contents
    /// objects has it in the file of its own name too. Data that has to be
    /// decoded or fetched from a URL is not taken: an object whose every
    /// contents object gives it that way fails with
    /// [`UnsupportedContent::UrlOrEncoding`]. Any other object without
    /// contents objects has no data and fails with
    /// [`UnsupportedContent::Absent`].
    pub fn data(&self) -> Result<Data<'_>, Error> {
        self.unencoded_data()
            .map(|(data, _)| data)
            .ok_or_else(|| self.unsupported())
    }

    /// The error of an object whose data this crate cannot take.
    fn unsupported(&self) -> Error {
        if self.contents.is_empty() {
            let message = format!(
                "'{}' is a {} without contents objects, which has no data",
                self.name.escape_debug(),
                self.inode_type
            );
            return Error::new(ErrorKind::Unsupported(UnsupportedContent::Absent), message).named(self.name.as_str());
        }
        let mut ways: Vec<String> = self
            .contents
            .iter()
            .map(|contents| match &contents.encoding {
                Some(encoding) => format!("'{}' encoding", encoding.escape_debug()),
                None => "a URL".to_string(),
            })
            .collect();
        ways.sort();
        ways.dedup();
        let ways = ways.join(" or ");
        let message = format!(
            "'{}' is only available through {}, which is not supported",
            self.name.escape_debug(),
            ways
        );
        Error::new(ErrorKind::Unsupported(UnsupportedContent::UrlOrEncoding), message)
            .named(self.name.as_str())
            .valued(ways)
    }

    /// Where the data of the file is if it is somewhere without an
    /// encoding, with the contents object that says so: in the first
    /// literal, else in the file of the first contents object that names
    /// one. The specification implies a contents object for a regular file
    /// that has none, with the file of its own name.
    fn unencoded_data(&self) -> Option<(Data<'_>, Option<&Contents>)> {
        if self.contents.is_empty() {
            let implied = Data::External(Reference::new(&self.name, None));
            return (self.inode_type == InodeType::Regular).then_some((implied, None));
        }
        let mut file = None;
        for contents in self.contents.iter().filter(|contents| contents.encoding.is_none()) {
            match &contents.location {
                Location::Literal(literal) => {
                    let data = self.data_in_literal(literal, contents.offset);
                    return Some((Data::Literal(data), Some(contents)));
                }
                Location::File(name) => {
                    file.get_or_insert((name, contents));
                }
                Location::Implied => {
                    file.get_or_insert((&self.name, contents));
                }
                Location::Url(_) => {}
            }
        }
        file.map(|(name, contents)| (Data::External(Reference::new(name, Some(contents))), Some(contents)))
    }

    /// The data of the file in the literal `literal`: from `offset` on, as
    /// many bytes as the object says it has. An offset or a size beyond the
    /// literal takes all there is, which the size of the object then finds.
    fn data_in_literal<'a>(&self, literal: &'a [u8], offset: u64) -> &'a [u8] {
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let data = literal.get(offset..).unwrap_or(&[]);
        match self.size.map(usize::try_from) {
            Some(Ok(size)) => data.get(..size).unwrap_or(data),
            _ => data,
        }
    }

    /// Whether the data of the file is outside of the manifest, where a
    /// [`ContentSource`] has it.
    pub fn has_external_data(&self) -> bool {
        matches!(self.unencoded_data(), Some((Data::External(_), _)))
    }

    /// The hash the manifest gives for all of the file the data is in,
    /// `original_sha256`, if the data is to be checked against it. Where
    /// the data is all of the file, that is unless it is the hash the
    /// object gives. Where it is a part, that is unless the object gives a
    /// hash: what is copied is checked against that, and the specification
    /// lets a consumer that takes a part of a file skip the checks of all
    /// of it.
    fn original_sha256_to_check(&self, original_sha256: Option<Sha256>, extent: DataExtent) -> Option<Sha256> {
        original_sha256.filter(|&sha256| match (self.sha256, extent) {
            (None, _) => true,
            (Some(own), DataExtent::WholeFile) => own != sha256,
            (Some(_), DataExtent::PartOfFile) => false,
        })
    }

    /// Writes the data of the file to `sink`: the literal of the manifest,
    /// or what `source` has. Checks the data against the size and the hash
    /// the object gives with a [`ContentCheck`], and returns how many bytes
    /// it is. An object whose data this crate cannot take fails as
    /// [`FileObject::data`] does, and the source is not asked for it. An
    /// error of the sink comes back as it was.
    ///
    /// What was written to the sink when this fails is not the data of
    /// the file.
    pub fn copy_contents(&self, source: &mut dyn ContentSource, sink: &mut dyn Write) -> Result<u64, Error> {
        let (data, contents) = self.unencoded_data().ok_or_else(|| self.unsupported())?;
        let mut checked = CheckedSink {
            sink,
            check: ContentCheck::new(self),
            failure: None,
        };
        let copied = match data {
            Data::Literal(data) => contents
                .map_or(Ok(()), |contents| contents.check_literal(self, data))
                .and_then(|()| checked.write_all(data).map_err(Error::from)),
            Data::External(reference) => source.copy(self, &reference, &mut checked),
        };
        let CheckedSink { check, failure, .. } = checked;
        // What the check refused and what the sink failed to take reached
        // the source as I/O errors. These are the errors to report.
        if let Some(failure) = failure {
            return Err(failure);
        }
        copied?;
        check.finish()
    }
}

impl Contents {
    /// Checks the literal of the contents object, which `data`, the data
    /// of `object`, is all of or a part of, against the hash the manifest
    /// gives for all of it, where the data is to be checked against that.
    /// A literal is no larger than a record and is hashed whole.
    fn check_literal(&self, object: &FileObject, data: &[u8]) -> Result<(), Error> {
        let Some(literal) = self.literal() else {
            return Ok(());
        };
        let extent = if data.len() == literal.len() {
            DataExtent::WholeFile
        } else {
            DataExtent::PartOfFile
        };
        let Some(sha256) = object.original_sha256_to_check(self.original_sha256, extent) else {
            return Ok(());
        };
        if Sha256::digest(literal) == sha256 {
            return Ok(());
        }
        let message = format!(
            "'{}' is a part of literal contents that do not match the hash in the manifest",
            object.name.escape_debug()
        );
        Err(Error::new(ErrorKind::Content(ContentProblem::HashMismatch), message).named(object.name.as_str()))
    }
}

/// Holds the data of a file object against the size and the hash the
/// object gives, as the data passes: it counts the bytes and hashes them.
///
/// It checks what the object says of its data, the check the
/// specification has for the data of every file. What its contents
/// objects say of the files the data is in, their sizes and hashes, is
/// for whoever reads those files to check, such as a [`DirectorySource`].
///
/// [`FileObject::copy_contents`] checks what it copies with one. A caller
/// that moves the data itself, such as a copy in an async runtime, hands
/// every piece of it to [`ContentCheck::update`] before it writes it on,
/// and calls [`ContentCheck::finish`] after the last one.
///
/// ```
/// use uapi16::{ContentCheck, FileObject, Name, Sha256};
///
/// let mut object = FileObject::new(Name::new("hello.txt")?);
/// object.size = Some(5);
/// object.sha256 = Some(Sha256::digest(b"hello"));
/// let mut check = ContentCheck::new(&object);
/// check.update(b"hel")?;
/// check.update(b"lo")?;
/// assert_eq!(check.finish()?, 5);
///
/// let mut check = ContentCheck::new(&object);
/// check.update(b"hello")?;
/// assert!(check.update(b"!").is_err());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct ContentCheck<'a> {
    /// The name of the object, which an error carries.
    name: &'a Name,
    /// The size the object gives.
    size: Option<u64>,
    /// The hash the object gives.
    sha256: Option<Sha256>,
    /// The hash of the data so far, if the object gives one.
    context: Option<Sha256Context>,
    /// How many bytes the data has so far.
    len: u64,
}

impl<'a> ContentCheck<'a> {
    /// A check of the data of `object`, of which nothing has passed yet.
    pub fn new(object: &'a FileObject) -> ContentCheck<'a> {
        ContentCheck {
            name: &object.name,
            size: object.size,
            sha256: object.sha256,
            context: object.sha256.map(|_| Sha256Context::default()),
            len: 0,
        }
    }

    /// Takes `data`, the next bytes of the data. Fails, and takes none of
    /// them, when they would make the data larger than the size the object
    /// gives.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        let added = data.len() as u64;
        if let Some(size) = self.size.filter(|&size| added > size.saturating_sub(self.len)) {
            let message = format!(
                "'{}' has more than the {} bytes the manifest says",
                self.name.escape_debug(),
                size
            );
            return Err(Error::new(ErrorKind::Content(ContentProblem::SizeMismatch), message)
                .named(self.name.as_str())
                .sizes(None, Some(size)));
        }
        if let Some(context) = &mut self.context {
            context.update(data);
        }
        self.len = self.len.saturating_add(added);
        Ok(())
    }

    /// Checks the data that passed against the size and the hash the
    /// object gives, and returns how many bytes it is.
    pub fn finish(self) -> Result<u64, Error> {
        if let Some(size) = self.size.filter(|&size| size != self.len) {
            let message = format!(
                "'{}' is {} bytes, the manifest says {}",
                self.name.escape_debug(),
                self.len,
                size
            );
            return Err(Error::new(ErrorKind::Content(ContentProblem::SizeMismatch), message)
                .named(self.name.as_str())
                .sizes(Some(self.len), Some(size)));
        }
        if self.context.map(Finalize::finalize) != self.sha256 {
            let message = format!("'{}' does not match the hash in the manifest", self.name.escape_debug());
            return Err(Error::new(ErrorKind::Content(ContentProblem::HashMismatch), message).named(self.name.as_str()));
        }
        Ok(self.len)
    }
}

/// A sink that hands what is written to it to a [`ContentCheck`] before it
/// passes it on.
struct CheckedSink<'a, 'b> {
    sink: &'a mut dyn Write,
    check: ContentCheck<'b>,
    /// Why what was written did not go through, if it did not: the check
    /// refused it, or the sink failed to take it. The writer is told with
    /// an I/O error of that kind, and this is the error to report. Nothing
    /// written after it goes through.
    failure: Option<Error>,
}

impl Write for CheckedSink<'_, '_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.failure.is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Err(e) = self.check.update(data) {
            self.failure = Some(e);
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Err(e) = self.sink.write_all(data) {
            let kind = e.kind();
            self.failure = Some(Error::from(e));
            return Err(kind.into());
        }
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
/// [`StreamSource`] from one stream that carries it all, in the order of
/// the manifest. A consumer hands a source every file object, in the
/// order of the manifest: those whose data it takes to
/// [`FileObject::copy_contents`], which calls [`ContentSource::copy`], and
/// the others to [`ContentSource::skip`]. After the last one it calls
/// [`ContentSource::end`].
pub trait ContentSource {
    /// Writes the data of `object` to `sink`, which `reference` says
    /// where to find: exactly `object.size` bytes when the object has a
    /// size. An error of the sink comes back as it was, and one of the
    /// source names the object.
    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error>;

    /// Passes over the data of `object`, which the consumer does not take.
    /// A source that hands out the data in the order of the manifest reads
    /// past it, and fails where a copy of it would.
    fn skip(&mut self, _object: &FileObject) -> Result<(), Error> {
        Ok(())
    }

    /// Called after the last file object of the manifest, whether the
    /// source had the data of any or not. A source that has data the file
    /// objects do not account for fails here.
    fn end(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

/// Why a [`Directory`] does not hand out a file.
#[derive(Debug)]
#[non_exhaustive]
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
}

/// Takes the data of file objects from the files next to the manifest,
/// in a [`Directory`].
///
/// The data of an object is the part of its file that starts at the
/// offset its contents object gives and is as long as the object says,
/// whatever else the file holds, as the specification has it. A file is
/// read as long as it was when it was opened. One that ends before the
/// data does, or that goes on where it is read whole for its hash, changed
/// in the meantime and fails.
///
/// A file can hold the data of many file objects, each a part of it, and
/// the manifest can give the hash of the whole file with every one of
/// them. A part whose object gives a hash of its own is checked against
/// that one, as every object is, and the specification lets a consumer
/// that takes a part of a file skip the checks of all of it. So only a
/// part without a hash of its own is checked against the hash of the whole
/// file. The source reads the file whole for the first of these parts and
/// keeps the hash of every piece of it, if they fit into what is left of
/// the 1 MiB the hashes it keeps take at most. The parts after that are
/// checked against those, and only the pieces they are in are read. A
/// piece is 1 MiB, or larger in a file of more than about 32 GiB, so that
/// the hashes of a file of any size fit into 1 MiB, and those of a file of
/// about 32 GiB or more take all of it. A part of a file whose hashes do
/// not fit is not checked against the hash of the whole file, as the
/// specification allows. So the memory the source takes does not grow
/// with the manifest, and while copies succeed, a file of more than one
/// piece is read whole once at most for its parts.
pub struct DirectorySource<D> {
    directory: D,
    /// What a copy goes through, made when the first file is copied.
    buffer: Vec<u8>,
    /// The hashes of the pieces of the files read whole for a part.
    hashes: PieceHashes,
}

impl<D: Directory> DirectorySource<D> {
    /// A source that takes the files from `directory`.
    pub fn new(directory: D) -> DirectorySource<D> {
        DirectorySource {
            directory,
            buffer: Vec::new(),
            hashes: PieceHashes::default(),
        }
    }
}

impl<D: fmt::Debug> fmt::Debug for DirectorySource<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectorySource")
            .field("directory", &self.directory)
            .field(
                "buffer",
                &format_args!("{}/{}", self.buffer.len(), self.buffer.capacity()),
            )
            .field("hashes", &self.hashes)
            .finish()
    }
}

/// The files a [`DirectorySource`] read whole for a part of them, which
/// have the hash the manifest gives for them, with the hash of every piece
/// of each. A file is known by its hash and its length: a part of it is
/// checked against the hashes of the pieces of the file of that hash,
/// whatever its name is.
///
/// Nothing is dropped. The hashes of a file are kept while they fit into
/// what is left of [`PIECE_HASH_BYTES`], and those of a file of about
/// 32 GiB or more take all of it. The parts of a file whose hashes do not
/// fit are not checked against the hash of the whole file, which the
/// specification allows for a file that is taken only in part. A part that
/// gives a hash of its own is checked against that one in any case.
#[derive(Default)]
struct PieceHashes {
    /// The hashes of the pieces of each file, by its hash and its length.
    files: HashMap<(Sha256, u64), Box<[Sha256]>>,
    /// How many bytes they take, at most [`PIECE_HASH_BYTES`].
    bytes: usize,
}

impl PieceHashes {
    /// The size of the pieces a file of the length `len` is hashed in:
    /// [`COPY_SIZE`], or more for a file that would have more than
    /// [`MAX_PIECES`] pieces of that size. The last piece is what is left.
    fn piece_size(len: u64) -> u64 {
        len.div_ceil(MAX_PIECES).max(COPY_SIZE as u64)
    }

    /// How many pieces a file of the length `len` has, [`MAX_PIECES`] at
    /// most.
    fn piece_count(len: u64) -> u64 {
        len.div_ceil(PieceHashes::piece_size(len))
    }

    /// How many bytes a file of `pieces` pieces takes when it is kept: the
    /// hashes of its pieces and [`FILE_ENTRY_BYTES`].
    fn stored_bytes(pieces: u64) -> usize {
        usize::try_from(pieces)
            .unwrap_or(usize::MAX)
            .saturating_mul(size_of::<Sha256>())
            .saturating_add(FILE_ENTRY_BYTES)
    }

    /// Whether the hashes of the pieces of a file of the length `len` are
    /// kept when it is read whole for a part of it: those of a file of more
    /// than one piece, while they fit into what is left of
    /// [`PIECE_HASH_BYTES`]. A part of a file of one piece is checked by
    /// reading that piece, all of the file.
    fn is_keepable(&self, len: u64) -> bool {
        let pieces = PieceHashes::piece_count(len);
        pieces > 1 && PieceHashes::stored_bytes(pieces) <= PIECE_HASH_BYTES.saturating_sub(self.bytes)
    }

    /// The hashes of the pieces of the file of the length `len` with the
    /// hash `sha256`, if it was read whole.
    fn get(&self, sha256: Sha256, len: u64) -> Option<&[Sha256]> {
        self.files.get(&(sha256, len)).map(|pieces| &**pieces)
    }

    /// Keeps `pieces`, the hashes of the pieces of the file of the length
    /// `len` with the hash `sha256`, as [`PieceHashes::is_keepable`] allows.
    fn keep(&mut self, sha256: Sha256, len: u64, pieces: Box<[Sha256]>) {
        self.bytes = self
            .bytes
            .saturating_add(PieceHashes::stored_bytes(pieces.len() as u64));
        self.files.insert((sha256, len), pieces);
    }
}

impl fmt::Debug for PieceHashes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PieceHashes")
            .field("files", &self.files.len())
            .field("bytes", &format_args!("{}/{}", self.bytes, PIECE_HASH_BYTES))
            .finish()
    }
}

/// Why a copy from a file or a stream did not go through.
#[derive(Debug)]
enum CopyFailure {
    /// Reading the file or the stream failed.
    ReadFailed(io::Error),
    /// The sink did not take what was read.
    WriteFailed(io::Error),
    /// The file does not have the hash it is checked against.
    HashMismatch,
    /// The file is not as long as it was when it was opened, or longer:
    /// it changed while it was read.
    SourceChanged,
}

impl CopyFailure {
    /// The error of a copy of the data of `object` from `place`, its file
    /// or the stream, that failed so.
    fn into_error(self, object: &FileObject, place: &str) -> Error {
        let name = &object.name;
        let (problem, what) = match self {
            CopyFailure::ReadFailed(error) => {
                let message = format!("{}: failed to read {}: {}", name.escape_debug(), place, error);
                return Error::new(ErrorKind::Source(SourceProblem::Unreadable), message)
                    .named(name.as_str())
                    .caused_by(error);
            }
            // The error of the sink comes back as it was.
            CopyFailure::WriteFailed(error) => return Error::from(error),
            CopyFailure::HashMismatch => (ContentProblem::HashMismatch, "does not match the hash in the manifest"),
            CopyFailure::SourceChanged => (ContentProblem::SourceChanged, "changed while it was read"),
        };
        let message = format!("{}: {} {}", name.escape_debug(), place, what);
        Error::new(ErrorKind::Content(problem), message).named(name.as_str())
    }
}

/// Reads that go on when a signal interrupts them. A bare read() fails
/// with EINTR when a handler that returns is installed, and std retries
/// only in read_exact() and friends. The copies read into a buffer of
/// their own: read_to_end() would start every piece with a small read, and
/// io::copy() reads into a small buffer of its own.
trait ReadSome: Read {
    /// Reads into `buf` once.
    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }

    /// Copies `len` bytes to `sink` through `buffer`, or as many as there
    /// are up to the end, and returns how many it copied. No read goes past
    /// them. What it copies goes to `context` too, if there is one.
    fn copy_up_to(
        &mut self,
        len: u64,
        buffer: &mut [u8],
        sink: &mut dyn Write,
        mut context: Option<&mut Sha256Context>,
    ) -> Result<u64, CopyFailure> {
        let mut copied = 0;
        while copied < len {
            let want = usize::try_from(len - copied).map_or(buffer.len(), |left| left.min(buffer.len()));
            let read = self.read_some(&mut buffer[..want]).map_err(CopyFailure::ReadFailed)?;
            if read == 0 {
                break;
            }
            let chunk = &buffer[..read];
            sink.write_all(chunk).map_err(CopyFailure::WriteFailed)?;
            if let Some(context) = &mut context {
                context.update(chunk);
            }
            copied += read as u64;
        }
        Ok(copied)
    }
}

impl<R: Read + ?Sized> ReadSome for R {}

/// A file a [`DirectorySource`] copies the data of an object from, in
/// pieces where it checks them.
struct Pieces<'a, F> {
    file: F,
    /// What the file is read into: [`COPY_SIZE`] bytes.
    buffer: &'a mut [u8],
    /// The length the file had when it was opened.
    len: u64,
    /// The size of its pieces, see [`PieceHashes::piece_size`].
    piece_size: u64,
    /// Where in the file the next read starts.
    pos: u64,
    /// The data of the object in the file.
    data: Range<u64>,
}

impl<F: Read + Seek> Pieces<'_, F> {
    /// Copies the data without a look at the rest of the file. A file that
    /// ends before the data does changed since it was opened.
    fn copy_data(&mut self, sink: &mut dyn Write) -> Result<(), CopyFailure> {
        // Most files are copied whole and need no seek.
        if self.data.start > 0 {
            self.file
                .seek(SeekFrom::Start(self.data.start))
                .map_err(CopyFailure::ReadFailed)?;
        }
        let size = self.data.end - self.data.start;
        if self.file.copy_up_to(size, self.buffer, sink, None)? < size {
            return Err(CopyFailure::SourceChanged);
        }
        Ok(())
    }

    /// Reads the next chunk of the file, at most up to `end`, and writes
    /// what of it is data to `sink`. Returns the chunk, which is empty at
    /// the end of the file.
    fn copy_chunk(&mut self, end: u64, sink: &mut dyn Write) -> Result<&[u8], CopyFailure> {
        let want = usize::try_from(end - self.pos).map_or(self.buffer.len(), |left| left.min(self.buffer.len()));
        let read = self
            .file
            .read_some(&mut self.buffer[..want])
            .map_err(CopyFailure::ReadFailed)?;
        let chunk = &self.buffer[..read];
        let within = |at: u64| at.saturating_sub(self.pos).min(read as u64) as usize;
        let (start, stop) = (within(self.data.start), within(self.data.end));
        if start < stop {
            sink.write_all(&chunk[start..stop]).map_err(CopyFailure::WriteFailed)?;
        }
        self.pos += read as u64;
        Ok(chunk)
    }

    /// Reads the piece that starts where the file is, writes what of it is
    /// data to `sink`, and returns its hash. What it reads goes to `whole`
    /// too, if there is one. A piece that ends before the file did when it
    /// was opened is one of a file that changed while it was read.
    fn copy_piece(
        &mut self,
        sink: &mut dyn Write,
        mut whole: Option<&mut Sha256Context>,
    ) -> Result<Sha256, CopyFailure> {
        let end = self.pos.saturating_add(self.piece_size).min(self.len);
        let mut context = Sha256Context::default();
        while self.pos < end {
            let chunk = self.copy_chunk(end, sink)?;
            if chunk.is_empty() {
                return Err(CopyFailure::SourceChanged);
            }
            context.update(chunk);
            if let Some(whole) = &mut whole {
                whole.update(chunk);
            }
        }
        Ok(context.finalize())
    }

    /// Reads all of the file, as long as it was when it was opened, copies
    /// the data, and checks the file against `sha256`. The hash of every
    /// piece goes to `pieces`, if there is one. A file that ends early, or
    /// goes on after that, changed while it was read.
    fn copy_hashed(
        &mut self,
        sink: &mut dyn Write,
        mut pieces: Option<&mut Vec<Sha256>>,
        sha256: Sha256,
    ) -> Result<(), CopyFailure> {
        let mut context = Sha256Context::default();
        while self.pos < self.len {
            match &mut pieces {
                Some(pieces) => {
                    let piece = self.copy_piece(sink, Some(&mut context))?;
                    pieces.push(piece);
                }
                None => {
                    let chunk = self.copy_chunk(self.len, sink)?;
                    if chunk.is_empty() {
                        return Err(CopyFailure::SourceChanged);
                    }
                    context.update(chunk);
                }
            }
        }
        // One byte more says whether the file ends where it did.
        if self.file.read_some(&mut [0u8; 1]).map_err(CopyFailure::ReadFailed)? != 0 {
            return Err(CopyFailure::SourceChanged);
        }
        if context.finalize() != sha256 {
            return Err(CopyFailure::HashMismatch);
        }
        Ok(())
    }

    /// Copies the data and checks every piece it is in against its hash
    /// in `pieces`, those of the file that was read whole.
    fn copy_checked(&mut self, sink: &mut dyn Write, pieces: &[Sha256]) -> Result<(), CopyFailure> {
        if self.data.is_empty() {
            return Ok(());
        }
        let first = self.data.start / self.piece_size;
        self.pos = first * self.piece_size;
        if self.pos > 0 {
            self.file
                .seek(SeekFrom::Start(self.pos))
                .map_err(CopyFailure::ReadFailed)?;
        }
        let mut expected = pieces.iter().skip(usize::try_from(first).unwrap_or(usize::MAX));
        while self.pos < self.data.end {
            let piece = self.copy_piece(sink, None)?;
            if expected.next() != Some(&piece) {
                return Err(CopyFailure::HashMismatch);
            }
        }
        Ok(())
    }
}

impl<D: Directory> ContentSource for DirectorySource<D> {
    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error> {
        let (file, len) = self
            .directory
            .open(reference.file)
            .map_err(|e| reference.unavailable(object, e))?;
        let size = reference.check_len(object, len)?;
        self.buffer.resize(COPY_SIZE, 0);
        let mut pieces = Pieces {
            file,
            buffer: &mut self.buffer,
            len,
            piece_size: PieceHashes::piece_size(len),
            pos: 0,
            // check_len made sure that this is inside the file.
            data: reference.offset..reference.offset + size,
        };
        let extent = if pieces.data == (0..len) {
            DataExtent::WholeFile
        } else {
            DataExtent::PartOfFile
        };
        let failed = |failure: CopyFailure| failure.into_error(object, &reference.file.escape_debug().to_string());
        let Some(sha256) = object.original_sha256_to_check(reference.original_sha256, extent) else {
            return pieces.copy_data(sink).map_err(failed);
        };
        let piece_count = PieceHashes::piece_count(len);
        // All of the file is read where it is the data or a single piece.
        // What is not the data of the object is hashed and not copied.
        let copied = if extent == DataExtent::WholeFile || piece_count < 2 {
            pieces.copy_hashed(sink, None, sha256)
        } else if let Some(known) = self.hashes.get(sha256, len) {
            // The file was read whole for another part of it.
            pieces.copy_checked(sink, known)
        } else if self.hashes.is_keepable(len) {
            let mut hashes = Vec::with_capacity(usize::try_from(piece_count).unwrap_or_default());
            let copied = pieces.copy_hashed(sink, Some(&mut hashes), sha256);
            if copied.is_ok() {
                self.hashes.keep(sha256, len, hashes.into_boxed_slice());
            }
            copied
        } else {
            // The hashes of the file do not fit into what is left of the
            // room for them. The specification lets a consumer that takes a
            // part of a file skip the checks of all of it.
            pieces.copy_data(sink)
        };
        copied.map_err(failed)
    }
}

/// Takes the data of file objects from one stream: the data of every
/// object that has it outside of the manifest, back to back, in the order
/// of the manifest.
///
/// The stream has the data of an object and nothing else of its file. So
/// an object needs a size, which says where its data ends, and one whose
/// data starts at an offset in its file is refused. The data is checked
/// against the hash the manifest gives for the whole file where it is all
/// of the file: where its contents object gives the size of the file, and
/// that is the size of the object. A part of a file is checked against the
/// hash of its object, and is taken unchecked where the object gives none,
/// as the specification permits a consumer that takes a part of a file.
pub struct StreamSource<R> {
    reader: R,
    /// What a copy goes through, made when the first file is copied.
    buffer: Vec<u8>,
    /// The name and the size of the last file object the stream had the
    /// data of, if it had the data of one, which data left at its end is
    /// about.
    last: Option<(String, u64)>,
}

impl<R: Read> StreamSource<R> {
    /// A source that takes the data from `reader`.
    pub fn new(reader: R) -> StreamSource<R> {
        StreamSource {
            reader,
            buffer: Vec::new(),
            last: None,
        }
    }

    /// Notes the file object of the name `name` and the size `size` as the
    /// last one the stream had the data of.
    fn note_served(&mut self, name: &Name, size: u64) {
        let (last, last_size) = self.last.get_or_insert_with(Default::default);
        last.clear();
        last.push_str(name);
        *last_size = size;
    }
}

impl<R: fmt::Debug> fmt::Debug for StreamSource<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamSource")
            .field("reader", &self.reader)
            .field(
                "buffer",
                &format_args!("{}/{}", self.buffer.len(), self.buffer.capacity()),
            )
            .field("last", &self.last)
            .finish()
    }
}

impl<R: Read> ContentSource for StreamSource<R> {
    fn copy(&mut self, object: &FileObject, reference: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error> {
        let name = &object.name;
        if reference.offset != 0 {
            let message = format!(
                "{}: an offset cannot be used with streamed contents",
                name.escape_debug()
            );
            return Err(
                Error::new(ErrorKind::Unsupported(UnsupportedContent::OffsetInStream), message).named(name.as_str()),
            );
        }
        let Some(size) = object.size else {
            let message = format!("{}: streamed contents need a known size", name.escape_debug());
            return Err(Error::new(ErrorKind::Unsupported(UnsupportedContent::NoSize), message)
                .at(Field::Size)
                .named(name.as_str()));
        };
        // The stream has all of the file where the contents object gives
        // its size, and that is the size of the object. A part cannot be
        // checked against the hash of the whole file.
        let sha256 = if reference.original_size == Some(size) {
            object.original_sha256_to_check(reference.original_sha256, DataExtent::WholeFile)
        } else {
            None
        };
        let mut context = sha256.map(|_| Sha256Context::default());
        // No read goes past the file, into the data of the next one.
        self.buffer.resize(COPY_SIZE, 0);
        let copied = self
            .reader
            .copy_up_to(size, &mut self.buffer, sink, context.as_mut())
            .map_err(|failure| failure.into_error(object, "the stream"))?;
        self.note_served(name, size);
        if copied < size {
            let message = format!(
                "{}: the stream ended {} bytes early",
                name.escape_debug(),
                size - copied
            );
            return Err(Error::new(ErrorKind::Content(ContentProblem::StreamEnded), message)
                .named(name.as_str())
                .sizes(Some(copied), Some(size)));
        }
        if context.map(Finalize::finalize) != sha256 {
            let message = format!(
                "{}: {} does not match the hash in the manifest",
                name.escape_debug(),
                reference.file.escape_debug()
            );
            return Err(Error::new(ErrorKind::Content(ContentProblem::HashMismatch), message).named(name.as_str()));
        }
        Ok(())
    }

    /// Reads past the data of `object` where the stream has it, and checks
    /// it as a copy does. Data that does not match the object's size and
    /// hash means that the stream is out of step with the manifest, and
    /// every object after it would get the wrong bytes.
    fn skip(&mut self, object: &FileObject) -> Result<(), Error> {
        if object.has_external_data() {
            object.copy_contents(self, &mut io::sink())?;
        }
        Ok(())
    }

    /// The stream ends with the last file it had the data of. Anything
    /// behind it is data the manifest does not describe: the last file got
    /// more than the manifest says, or no file takes data from the stream.
    fn end(&mut self) -> Result<(), Error> {
        let mut byte = [0u8; 1];
        let read = self.reader.read_some(&mut byte).map_err(|error| {
            let message = format!("failed to read the stream after the last file: {}", error);
            Error::new(ErrorKind::Source(SourceProblem::Unreadable), message).caused_by(error)
        })?;
        if read == 0 {
            return Ok(());
        }
        let kind = ErrorKind::Content(ContentProblem::SizeMismatch);
        Err(match &self.last {
            Some((name, size)) => {
                let message = format!("{}: the stream goes on after the last file", name.escape_debug());
                Error::new(kind, message).named(name.as_str()).sizes(None, Some(*size))
            }
            None => Error::new(
                kind,
                "the stream has data that no file of the manifest describes".into(),
            )
            .sizes(None, Some(0)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{json, manifest, read_whole, sequence, HELLO, TRAILER, WORLD};
    use crate::Digest;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// What is in a directory under a name.
    #[derive(Debug)]
    enum Entry {
        File(Rc<[u8]>),
        /// A file that was `len` bytes long when it was opened and holds
        /// these bytes when it is read: it changed in between.
        Changed {
            data: Rc<[u8]>,
            len: u64,
        },
        /// A file that runs into `trouble` where `at` is reached.
        Troubled {
            data: Rc<[u8]>,
            at: u64,
            trouble: Trouble,
        },
        /// Something that is no regular file.
        Other,
        /// Something that cannot be reached, for this reason.
        Fails(i32),
    }

    /// What a read runs into in a file of [`Files`].
    #[derive(Clone, Copy, Debug)]
    enum Trouble {
        /// The read gives nothing, once, and the file goes on after that:
        /// what a file that is cut short and written to again gives, or
        /// one of a network file system.
        Stall,
        /// The read fails with this error, every time.
        FailRead(i32),
        /// Every seek fails with this error.
        FailSeek(i32),
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
        /// What the read that starts at an offset runs into.
        trouble: Option<(u64, Trouble)>,
    }

    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let pos = self.data.position();
            let trouble = self.trouble;
            let buf = match trouble {
                Some((at, Trouble::Stall)) if pos == at => {
                    self.trouble = None;
                    return Ok(0);
                }
                Some((at, Trouble::FailRead(errno))) if pos == at => return Err(io::Error::from_raw_os_error(errno)),
                // A read stops where the trouble is, so that a read starts
                // there.
                Some((at, _)) if pos < at => {
                    let before = usize::try_from(at - pos).unwrap_or(usize::MAX);
                    let len = buf.len().min(before);
                    &mut buf[..len]
                }
                _ => buf,
            };
            let read = self.data.read(buf)?;
            self.read.set(self.read.get() + read as u64);
            Ok(read)
        }
    }

    impl Seek for Counted {
        fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
            if let Some((_, Trouble::FailSeek(errno))) = self.trouble {
                return Err(io::Error::from_raw_os_error(errno));
            }
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
    }

    /// A source over a reference to the files, so that a test can look
    /// at them and change them while the source has them.
    impl Directory for &Files {
        type File = Counted;

        fn open(&self, file: &Name) -> Result<(Counted, u64), OpenError> {
            let (data, len, trouble) = match self.entries.borrow().get(file.as_str()) {
                Some(Entry::File(data)) => (Rc::clone(data), data.len() as u64, None),
                Some(Entry::Changed { data, len }) => (Rc::clone(data), *len, None),
                Some(&Entry::Troubled { ref data, at, trouble }) => {
                    (Rc::clone(data), data.len() as u64, Some((at, trouble)))
                }
                Some(Entry::Other) => return Err(OpenError::NotRegular),
                Some(Entry::Fails(errno)) => return Err(io::Error::from_raw_os_error(*errno).into()),
                None => return Err(io::Error::from_raw_os_error(libc::ENOENT).into()),
            };
            let file = Counted {
                data: io::Cursor::new(data),
                read: Rc::clone(&self.read),
                trouble,
            };
            Ok((file, len))
        }
    }

    /// The file objects of the manifest with the records `records`.
    fn objects(records: &[&str]) -> Vec<FileObject> {
        read_whole(&manifest(records))
            .unwrap_or_else(|e| panic!("{:?}: {}", records, e))
            .objects
    }

    /// The file object of `record`, which comes after the objects of the
    /// directories it is in.
    fn object(record: &str) -> FileObject {
        let name = json(record)
            .and_then(|value| {
                value
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_default();
        let mut records: Vec<String> = name
            .match_indices('/')
            .map(|(end, _)| format!(r#"{{"name":"{}","type":"dir"}}"#, &name[..end]))
            .collect();
        records.push(record.to_string());
        let records: Vec<&str> = records.iter().map(String::as_str).collect();
        objects(&records).pop().unwrap()
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
        (e.kind(), e.name(), e.found_size(), e.expected_size(), e.to_string())
    }

    /// A hash that no data in these tests has.
    fn hash_of(n: u8) -> Sha256 {
        Sha256::digest(&[n])
    }

    #[test]
    fn where_the_data_is() {
        // Without contents objects a regular file has it in the file of its
        // name.
        let o = object(r#"{"name":"dir/x","size":5}"#);
        let Data::External(reference) = o.data().unwrap() else {
            panic!()
        };
        assert_eq!(reference.file.as_str(), "dir/x");
        assert_eq!(
            (reference.offset, reference.original_size, reference.original_sha256),
            (0, None, None)
        );
        assert!(o.has_external_data());
        // The first contents object that has the data as it is in a file
        // gives it: a URL and an encoding are passed over.
        let file = format!(
            r#"{{"file":"data/y.bin","offset":2,"originalSize":9,"originalSha256":"{}"}}"#,
            WORLD
        );
        let others = r#"{"url":"https://example.com/x"},{"file":"x.gz","encoding":"gzip"}"#;
        let o = object(&format!(
            r#"{{"name":"x","size":3,"contents":[{},{},{{"file":"z"}}]}}"#,
            others, file
        ));
        let Data::External(reference) = o.data().unwrap() else {
            panic!()
        };
        assert_eq!(reference.file.as_str(), "data/y.bin");
        assert_eq!((reference.offset, reference.original_size), (2, Some(9)));
        assert_eq!(reference.original_sha256, WORLD.parse().ok());
        assert!(o.has_external_data());
        // A literal is taken before any file, wherever it is among the
        // contents objects. One in an encoding is not.
        let literal = r#"{"literal":"aGVsbG8="}"#;
        for contents in [
            format!(r#"{},{},{}"#, others, file, literal),
            format!(r#"{},{}"#, file, literal),
            format!(r#"{},{}"#, literal, file),
            format!(r#"{{"literal":"AAAA","encoding":"gzip"}},{},{}"#, file, literal),
        ] {
            let o = object(&format!(r#"{{"name":"x","size":3,"contents":[{}]}}"#, contents));
            assert_eq!(o.data().unwrap(), Data::Literal(b"hel"), "{}", contents);
            assert!(!o.has_external_data());
        }
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
        assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::UrlOrEncoding));
        assert_eq!(e.name(), Some("dir/x"));
        assert_eq!(e.value(), Some("'gzip' encoding or 'zstd' encoding or a URL"));
        assert_eq!(
            e.to_string(),
            "'dir/x' is only available through 'gzip' encoding or 'zstd' encoding or a URL, which is not supported"
        );
        assert!(!o.has_external_data());
    }

    /// Only a regular file has a contents object implied. Any other object
    /// without one has no data, and a copy of it fails without a look at
    /// the source.
    #[test]
    fn objects_without_data() {
        // A manifest that does not record the targets of symbolic links.
        let root = r#"{"features":["size"],"mediaType":"application/vnd.uapi.16.manifest"}"#;
        let none = read_whole(&sequence(&[
            root,
            r#"{"name":"d","type":"dir"}"#,
            r#"{"name":"f","type":"fifo"}"#,
            r#"{"name":"l","type":"lnk"}"#,
            r#"{"name":"r","size":5}"#,
            TRAILER,
        ]))
        .unwrap()
        .objects;
        let mut stream = &b"hello"[..];
        let mut source = StreamSource::new(&mut stream);
        for (o, kind) in none.iter().zip(["dir", "fifo", "lnk"]) {
            let e = o.data().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::Absent));
            assert_eq!(e.name(), Some(o.name.as_str()));
            assert_eq!(
                e.to_string(),
                format!("'{}' is a {} without contents objects, which has no data", o.name, kind)
            );
            assert!(!o.has_external_data());
            let e = copy(o, &mut source).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::Absent));
            source.skip(o).unwrap();
        }
        assert_eq!(copy(&none[3], &mut source).unwrap(), b"hello");
        source.end().unwrap();
        // A symbolic link with its target in the manifest, and a directory
        // that refers to a manifest of its own in a file.
        let some = objects(&[
            r#"{"name":"d","type":"dir","size":3,"contents":[{"file":"d.Uapi16Manifest"}]}"#,
            r#"{"name":"l","type":"lnk","contents":[{"literal":"eA=="}]}"#,
        ]);
        assert!(some[0].has_external_data());
        assert_eq!(some[1].data().unwrap(), Data::Literal(b"x"));
        let files = Files::of(&[("d.Uapi16Manifest", b"abc")]);
        let mut source = DirectorySource::new(&files);
        assert_eq!(copy(&some[0], &mut source).unwrap(), b"abc");
        assert_eq!(copy(&some[1], &mut source).unwrap(), b"x");
    }

    #[test]
    fn copies_from_a_directory() {
        let files = Files::of(&[("a", b"hello world"), ("empty", b""), ("dir/b", b"hello")]);
        let mut source = DirectorySource::new(&files);
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
            // The start of a file that holds more, which is all the
            // specification takes of it.
            (format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO), "hello"),
            (r#"{"name":"x","size":2,"contents":[{"file":"a"}]}"#.to_string(), "he"),
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
                    Sha256::digest(b"hello world")
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
        }
    }

    #[test]
    fn files_that_are_not_what_the_manifest_says() {
        let files = Files::of(&[("a", b"hello world"), ("dir/b", b"hello")]);
        let mut source = DirectorySource::new(&files);
        let size = ErrorKind::Content(ContentProblem::SizeMismatch);
        let hash = ErrorKind::Content(ContentProblem::HashMismatch);
        for (record, expected) in [
            // A file too short for the data.
            (
                r#"{"name":"x/y","size":12,"contents":[{"file":"a"}]}"#.to_string(),
                (
                    size,
                    Some("x/y"),
                    Some(11),
                    Some(12),
                    "x/y: a is too short for offset 0 and size 12",
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
            // All of a file that is not what the manifest says of it, as a
            // hash of the object and as one of the file.
            (
                format!(
                    r#"{{"name":"w","size":11,"sha256":"{}","contents":[{{"file":"a","originalSha256":"{}"}}]}}"#,
                    Sha256::digest(b"hello world"),
                    WORLD
                ),
                (
                    hash,
                    Some("w"),
                    None,
                    None,
                    "w: a does not match the hash in the manifest",
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
        }
        // A part of an object with a hash of its own is held against that
        // one, and the file is not read beyond the part.
        files.read();
        let o = object(&format!(
            r#"{{"name":"x","size":5,"sha256":"{}","contents":[{{"file":"a","originalSize":11,"originalSha256":"{}"}}]}}"#,
            HELLO, WORLD
        ));
        assert_eq!(copy(&o, &mut source).unwrap(), b"hello");
        assert_eq!(files.read(), 5);
        // A part of a literal is held against the hash of all of the
        // literal the manifest gives, as a part of a file is, unless the
        // object has a hash of its own.
        for (record, data) in [
            (
                r#"{"name":"x","contents":[{"literal":"aGVsbG8=","offset":1,"originalSha256":"#,
                "ello",
            ),
            (
                r#"{"name":"x","size":2,"contents":[{"literal":"aGVsbG8=","originalSha256":"#,
                "he",
            ),
        ] {
            let o = object(&format!(r#"{}"{}"}}]}}"#, record, HELLO));
            assert_eq!(copy(&o, &mut source).unwrap(), data.as_bytes());
            let o = object(&format!(r#"{}"{}"}}]}}"#, record, WORLD));
            let e = copy(&o, &mut source).unwrap_err();
            assert_eq!(
                facts(&e),
                (
                    hash,
                    Some("x"),
                    None,
                    None,
                    "'x' is a part of literal contents that do not match the hash in the manifest".to_string()
                )
            );
        }
        let o = object(&format!(
            r#"{{"name":"x","size":2,"sha256":"{}","contents":[{{"literal":"aGVsbG8=","originalSha256":"{}"}}]}}"#,
            Sha256::digest(b"he"),
            WORLD
        ));
        assert_eq!(copy(&o, &mut source).unwrap(), b"he");
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

    /// A file that is read whole is read as long as it was when it was
    /// opened, and one byte more to see that it ends there.
    #[test]
    fn files_that_change_while_they_are_read() {
        let files = Files::default();
        let mut source = DirectorySource::new(&files);
        let changed = |file: &str| {
            (
                ErrorKind::Content(ContentProblem::SourceChanged),
                Some("x"),
                None,
                None,
                format!("x: {} changed while it was read", file),
            )
        };
        // A file of one piece, which grew and which shrank.
        let part = format!(
            r#"{{"name":"x","size":2,"contents":[{{"file":"g","originalSize":5,"originalSha256":"{}"}}]}}"#,
            HELLO
        );
        for (data, read) in [(&b"hello world"[..], 6), (b"hel", 3)] {
            files.put(
                "g",
                Entry::Changed {
                    data: data.into(),
                    len: 5,
                },
            );
            let e = copy(&object(&part), &mut source).unwrap_err();
            assert_eq!(facts(&e), changed("g"));
            assert_eq!(files.read(), read);
        }
        // A file of pieces that grew, read for its first part: it is not
        // read on to its end, and the hashes of its pieces are not kept.
        let len = 2 * COPY_SIZE + 3;
        let blob: Vec<u8> = (0..len + 100).map(|i| (i ^ (i >> 8)) as u8).collect();
        files.put(
            "p",
            Entry::Changed {
                data: blob[..].into(),
                len: len as u64,
            },
        );
        let o = object(&format!(
            r#"{{"name":"x","size":3,"contents":[{{"file":"p","offset":1,"originalSize":{},"originalSha256":"{}"}}]}}"#,
            len,
            Sha256::digest(&blob[..len])
        ));
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(facts(&e), changed("p"));
        assert_eq!(files.read(), len as u64 + 1);
        assert!(source.hashes.files.is_empty());
        // Once it is as long as it was, it is taken.
        files.put("p", Entry::File(blob[..len].into()));
        assert_eq!(copy(&o, &mut source).unwrap(), &blob[1..4]);
        assert_eq!(files.read(), len as u64);
        assert_eq!(source.hashes.files.len(), 1);
        // The data of an object that is checked against its own hash only
        // is taken from a file that grew.
        files.put(
            "g",
            Entry::Changed {
                data: (&b"hello world"[..]).into(),
                len: 5,
            },
        );
        let o = object(&format!(
            r#"{{"name":"x","size":5,"sha256":"{}","contents":[{{"file":"g"}}]}}"#,
            HELLO
        ));
        assert_eq!(copy(&o, &mut source).unwrap(), b"hello");
        assert_eq!(files.read(), 5);
        // A file that is shorter than when it was opened, for an object
        // that says nothing about its size or its hash and for one that
        // gives its size.
        files.put(
            "g",
            Entry::Changed {
                data: (&b"hel"[..]).into(),
                len: 5,
            },
        );
        for record in [
            r#"{"name":"x","contents":[{"file":"g"}]}"#,
            r#"{"name":"x","size":5,"contents":[{"file":"g"}]}"#,
        ] {
            let e = copy(&object(record), &mut source).unwrap_err();
            assert_eq!(facts(&e), changed("g"), "{}", record);
            assert_eq!(files.read(), 3);
        }
    }

    /// A file whose read gives nothing in the middle of it and more after
    /// that changed while it was read, wherever it is read, and nothing is
    /// kept of it.
    #[test]
    fn a_read_that_stalls() {
        let len = 3 * COPY_SIZE + COPY_SIZE / 2;
        let blob: Rc<[u8]> = (0..len).map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8).collect();
        let whole = Sha256::digest(&blob);
        // In the middle of the second piece.
        let at = COPY_SIZE + COPY_SIZE / 2;
        let stalling = || Entry::Troubled {
            data: Rc::clone(&blob),
            at: at as u64,
            trouble: Trouble::Stall,
        };
        let files = Files::default();
        let mut source = DirectorySource::new(&files);
        let changed = (
            ErrorKind::Content(ContentProblem::SourceChanged),
            Some("x"),
            None,
            None,
            "x: blob changed while it was read".to_string(),
        );
        let part = |offset: usize, size: usize| {
            object(&format!(
                r#"{{"name":"x","size":{},"contents":[{{"file":"blob","offset":{},"originalSize":{},"originalSha256":"{}"}}]}}"#,
                size, offset, len, whole
            ))
        };
        // Read whole for the hash of the file, as all of the file and for a
        // part, which would keep the hashes of its pieces. Read for the
        // data alone.
        for (o, from) in [
            (
                object(&format!(
                    r#"{{"name":"x","contents":[{{"file":"blob","originalSha256":"{}"}}]}}"#,
                    whole
                )),
                0,
            ),
            (part(5, 10), 0),
            (object(r#"{"name":"x","contents":[{"file":"blob","offset":1}]}"#), 1),
        ] {
            files.put("blob", stalling());
            let e = copy(&o, &mut source).unwrap_err();
            assert_eq!(facts(&e), changed, "{:?}", o);
            assert_eq!(files.read(), (at - from) as u64, "{:?}", o);
            assert!(source.hashes.files.is_empty());
        }
        // A part checked against the hashes of the pieces of the file.
        files.put("blob", Entry::File(Rc::clone(&blob)));
        assert_eq!(copy(&part(5, 10), &mut source).unwrap(), &blob[5..15]);
        assert_eq!(files.read(), len as u64);
        files.put("blob", stalling());
        let e = copy(&part(COPY_SIZE + 7, 10), &mut source).unwrap_err();
        assert_eq!(facts(&e), changed);
        assert_eq!(files.read(), (at - COPY_SIZE) as u64);
    }

    /// An error of a read names the object and the file or the stream it
    /// was read from. One of the sink comes back as it was, see
    /// a_sink_that_fails().
    #[test]
    fn reads_that_fail() {
        let eio = io::Error::from_raw_os_error(libc::EIO);
        let files = Files::default();
        files.put(
            "bad",
            Entry::Troubled {
                data: (&b"hello world"[..]).into(),
                at: 6,
                trouble: Trouble::FailRead(libc::EIO),
            },
        );
        let mut source = DirectorySource::new(&files);
        let o = object(r#"{"name":"x","size":11,"contents":[{"file":"bad"}]}"#);
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.to_string()),
            (
                ErrorKind::Source(SourceProblem::Unreadable),
                Some("x"),
                format!("x: failed to read bad: {}", eio)
            )
        );
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EIO));
        /// A stream whose every read fails.
        struct Failing;
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        }
        let o = object(r#"{"name":"x","size":5}"#);
        let e = copy(&o, &mut StreamSource::new(Failing)).unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.to_string()),
            (
                ErrorKind::Source(SourceProblem::Unreadable),
                Some("x"),
                format!("x: failed to read the stream: {}", eio)
            )
        );
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EIO));
        let e = StreamSource::new(Failing).end().unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.to_string()),
            (
                ErrorKind::Source(SourceProblem::Unreadable),
                None,
                format!("failed to read the stream after the last file: {}", eio)
            )
        );
        // A seek to the data, and one to the piece a part is in after its
        // file was read whole.
        let blob: Rc<[u8]> = (0..2 * COPY_SIZE + 3).map(|i| (i >> 4) as u8).collect();
        let unseekable = || Entry::Troubled {
            data: Rc::clone(&blob),
            at: u64::MAX,
            trouble: Trouble::FailSeek(libc::EIO),
        };
        files.put("blob", unseekable());
        let o = object(r#"{"name":"x","size":3,"contents":[{"file":"blob","offset":2}]}"#);
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.to_string()),
            (
                ErrorKind::Source(SourceProblem::Unreadable),
                Some("x"),
                format!("x: failed to read blob: {}", eio)
            )
        );
        let part = |offset: usize| {
            object(&format!(
                r#"{{"name":"x","size":3,"contents":[{{"file":"blob","offset":{},"originalSize":{},"originalSha256":"{}"}}]}}"#,
                offset,
                blob.len(),
                Sha256::digest(&blob)
            ))
        };
        files.put("blob", Entry::File(Rc::clone(&blob)));
        assert_eq!(copy(&part(0), &mut source).unwrap(), &blob[..3]);
        files.put("blob", unseekable());
        let e = copy(&part(COPY_SIZE + 1), &mut source).unwrap_err();
        assert_eq!(
            (e.kind(), e.to_string()),
            (
                ErrorKind::Source(SourceProblem::Unreadable),
                format!("x: failed to read blob: {}", eio)
            )
        );
    }

    #[test]
    fn parts_of_one_file() {
        // A file of three pieces and a half, no two of them the same.
        let len = 3 * COPY_SIZE + COPY_SIZE / 2;
        let blob: Vec<u8> = (0..len).map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8).collect();
        let whole = Sha256::digest(&blob);
        let files = Files::default();
        files.put("blob", Entry::File(blob[..].into()));
        let mut source = DirectorySource::new(&files);
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
        let hash = ErrorKind::Content(ContentProblem::HashMismatch);
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
            assert_eq!(files.read(), size as u64);
        }
        // With it the file is read whole for the first part. For the
        // others the pieces they are in are read. A part of no bytes has
        // the hash of no data, and all of the file the hash of the file,
        // which the manifest gives for the object then: those are checked
        // against that alone.
        let mut first = true;
        for (offset, size) in parts {
            let o = part(offset, size, len, Some(whole));
            assert_eq!(copy(&o, &mut source).unwrap(), &blob[offset..offset + size]);
            let from = offset / COPY_SIZE * COPY_SIZE;
            let to = (offset + size).next_multiple_of(COPY_SIZE).min(len);
            let read = match (size, first) {
                (0, _) => 0,
                (_, true) => len,
                _ => to - from,
            };
            assert_eq!(files.read(), read as u64, "{} at {}", size, offset);
            first &= size == 0;
        }
        // Another hash for the same file is not taken on trust.
        let o = part(5, 10, len, Some(Sha256::digest(b"another file")));
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
        assert_eq!(files.read(), len as u64);
        // A file that changed is found out where it changed, and a file
        // of another length is read whole again.
        let mut changed = blob.clone();
        changed[2 * COPY_SIZE + 100] ^= 1;
        files.put("blob", Entry::File(changed[..].into()));
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
        files.read();
        files.put("blob", Entry::File(blob[..len - 1].into()));
        let e = copy(&part(5, 10, len - 1, Some(whole)), &mut source).unwrap_err();
        assert_eq!(e.kind(), hash);
        assert_eq!(files.read(), len as u64 - 1);
        let shorter = Sha256::digest(&blob[..len - 1]);
        for _ in 0..2 {
            let o = part(len - 11, 10, len - 1, Some(shorter));
            assert_eq!(copy(&o, &mut source).unwrap(), &blob[len - 11..len - 1]);
        }
        assert_eq!(files.read(), (len - 1 + COPY_SIZE / 2 - 1) as u64);
        // A file that is one object is read once, hash or no hash.
        let small = Files::of(&[("a", b"hello")]);
        for record in [
            r#"{"name":"a","size":5}"#.to_string(),
            format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
            format!(
                r#"{{"name":"a","contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
                HELLO
            ),
        ] {
            let mut source = DirectorySource::new(&small);
            for _ in 0..2 {
                assert_eq!(copy(&object(&record), &mut source).unwrap(), b"hello", "{}", record);
                assert_eq!(small.read(), 5);
            }
        }
    }

    /// The file `data` to copy `part` of, hashed in pieces of `piece_size`
    /// bytes. What is read of it is counted in `read`.
    fn pieces_over<'a>(
        data: &[u8],
        piece_size: usize,
        part: Range<usize>,
        buffer: &'a mut [u8],
        read: &Rc<Cell<u64>>,
    ) -> Pieces<'a, Counted> {
        Pieces {
            file: Counted {
                data: io::Cursor::new(data.into()),
                read: Rc::clone(read),
                trouble: None,
            },
            buffer,
            len: data.len() as u64,
            piece_size: piece_size as u64,
            pos: 0,
            data: part.start as u64..part.end as u64,
        }
    }

    /// Pieces larger than what is read at a time, as those of a file of
    /// more than [`MAX_PIECES`] MiB are.
    #[test]
    fn pieces_larger_than_a_read() {
        let piece_size = 2 * COPY_SIZE + COPY_SIZE / 2;
        let len = 2 * piece_size + 3;
        let blob: Vec<u8> = (0..len).map(|i| (i ^ (i >> 9) ^ (i >> 17)) as u8).collect();
        let mut buffer = vec![0; COPY_SIZE];
        let read = Rc::new(Cell::new(0));
        // Read whole, a part of the file is copied and every piece hashed.
        let mut hashes = Vec::new();
        let mut out = Vec::new();
        let mut pieces = pieces_over(&blob, piece_size, 7..piece_size + 9, &mut buffer, &read);
        pieces
            .copy_hashed(&mut out, Some(&mut hashes), Sha256::digest(&blob))
            .unwrap();
        assert_eq!(out, &blob[7..piece_size + 9]);
        let expected: Vec<Sha256> = blob.chunks(piece_size).map(Sha256::digest).collect();
        assert_eq!(hashes, expected);
        assert_eq!(read.replace(0), len as u64);
        // A part is checked against the pieces it is in, and only those are
        // read.
        for part in [0..1, piece_size - 1..piece_size + 1, 2 * piece_size..len, 1..len - 1] {
            let mut out = Vec::new();
            let mut pieces = pieces_over(&blob, piece_size, part.clone(), &mut buffer, &read);
            pieces.copy_checked(&mut out, &hashes).unwrap();
            assert_eq!(out, &blob[part.clone()]);
            let from = part.start / piece_size * piece_size;
            let to = part.end.next_multiple_of(piece_size).min(len);
            assert_eq!(read.replace(0), (to - from) as u64, "{:?}", part);
        }
        // A change in a piece is found where the piece is read.
        let mut changed = blob.clone();
        changed[piece_size + 5] ^= 1;
        for (part, matches) in [
            (0..piece_size, true),
            (2..piece_size + 1, false),
            (2 * piece_size - 1..2 * piece_size, false),
            (2 * piece_size..len, true),
        ] {
            let mut pieces = pieces_over(&changed, piece_size, part.clone(), &mut buffer, &read);
            match pieces.copy_checked(&mut io::sink(), &hashes) {
                Ok(()) => assert!(matches, "{:?}", part),
                Err(CopyFailure::HashMismatch) => assert!(!matches, "{:?}", part),
                Err(e) => panic!("{:?}: {:?}", part, e),
            }
        }
    }

    /// What a source keeps of the files it read whole does not grow with
    /// the manifest, and what it decides to keep it keeps.
    #[test]
    fn keeps_hashes_up_to_the_bound() {
        let mib = COPY_SIZE as u64;
        // A file is cut into pieces of 1 MiB, and of more where it would
        // have more than MAX_PIECES of them. The hashes of the pieces of a
        // file of any length fit into what a source keeps.
        assert_eq!(PieceHashes::piece_size(MAX_PIECES * mib), mib);
        assert_eq!(PieceHashes::piece_size(MAX_PIECES * mib + 1), mib + 1);
        assert_eq!(PieceHashes::piece_count(MAX_PIECES * mib + 1), MAX_PIECES);
        for len in [
            0,
            1,
            mib,
            mib + 1,
            MAX_PIECES * mib,
            33 << 30,
            1 << 50,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let (size, count) = (PieceHashes::piece_size(len), PieceHashes::piece_count(len));
            assert!(count <= MAX_PIECES, "{}", len);
            assert!(
                count == 0 || (count - 1) * size < len && len <= count.saturating_mul(size),
                "{}",
                len
            );
            assert!(PieceHashes::stored_bytes(count) <= PIECE_HASH_BYTES, "{}", len);
        }
        // So a source that holds no hashes keeps those of any file of more
        // than one piece.
        let empty = PieceHashes::default();
        assert!(empty.is_keepable(u64::MAX) && empty.is_keepable(mib + 1));
        assert!(!empty.is_keepable(mib) && !empty.is_keepable(0));
        let mut kept = PieceHashes::default();
        kept.keep(hash_of(0), u64::MAX, vec![Sha256::EMPTY; MAX_PIECES as usize].into());
        assert!(kept.bytes <= PIECE_HASH_BYTES && kept.get(hash_of(0), u64::MAX).is_some());
        // At the bound: what keep() takes is what is_keepable() counts. A
        // file whose hashes fill what is left is kept, one of a piece more
        // is not, and nothing that was kept is dropped.
        let mut kept = PieceHashes::default();
        kept.keep(hash_of(1), 1000 * mib, vec![Sha256::EMPTY; 1000].into());
        let left = PIECE_HASH_BYTES - kept.bytes;
        let fitting = ((left - FILE_ENTRY_BYTES) / size_of::<Sha256>()) as u64;
        assert!(kept.is_keepable(fitting * mib) && !kept.is_keepable(fitting * mib + 1));
        kept.keep(hash_of(2), fitting * mib, vec![Sha256::EMPTY; fitting as usize].into());
        assert!(kept.bytes <= PIECE_HASH_BYTES && PIECE_HASH_BYTES - kept.bytes < size_of::<Sha256>());
        assert!(!kept.is_keepable(2 * mib));
        assert!(kept.get(hash_of(1), 1000 * mib).is_some() && kept.get(hash_of(2), fitting * mib).is_some());
        // A file is known by its hash and its length.
        assert!(kept.get(hash_of(1), 1000 * mib - 1).is_none() && kept.get(hash_of(2), 1000 * mib).is_none());
        // A part of a file of one piece is checked by reading all of the
        // file, and nothing is kept of it.
        let names = ["a", "b", "c", "d"];
        let files = Files::of(&names.map(|name| (name, &b"ab"[..])));
        let mut source = DirectorySource::new(&files);
        for name in names {
            let o = object(&format!(
                r#"{{"name":"x","size":1,"contents":[{{"file":"{}","offset":1,"originalSize":2,"originalSha256":"{}"}}]}}"#,
                name,
                Sha256::digest(b"ab")
            ));
            assert_eq!(copy(&o, &mut source).unwrap(), b"b");
            assert_eq!(files.read(), 2);
        }
        assert_eq!((source.hashes.files.len(), source.hashes.bytes), (0, 0));
        // A part of a file whose hashes the source cannot keep any more is
        // copied without the check of the whole file: the hash the
        // manifest gives for that is not looked at.
        let blob: Vec<u8> = (0..2 * COPY_SIZE).map(|i| (i >> 3) as u8).collect();
        files.put("blob", Entry::File(blob[..].into()));
        source.hashes = kept;
        let o = object(&format!(
            r#"{{"name":"x","size":3,"contents":[{{"file":"blob","offset":5,"originalSize":{},"originalSha256":"{}"}}]}}"#,
            blob.len(),
            hash_of(3)
        ));
        assert_eq!(copy(&o, &mut source).unwrap(), &blob[5..8]);
        assert_eq!(files.read(), 3);
        assert_eq!(source.hashes.files.len(), 2);
    }

    #[test]
    fn files_that_are_not_there() {
        let files = Files::of(&[("a", b"hello")]);
        files.put("fifo", Entry::Other);
        files.put("below-a-file/x", Entry::Fails(libc::ENOTDIR));
        files.put("odd", Entry::Fails(libc::EINVAL));
        files.put("link", Entry::Fails(libc::ELOOP));
        files.put("secret", Entry::Fails(libc::EACCES));
        let mut source = DirectorySource::new(&files);
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
            let e = copy(&o, &mut source).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Source(problem), "{}", file);
            assert_eq!(e.name(), Some("x"));
            assert_eq!(e.io_error().and_then(io::Error::raw_os_error), errno, "{}", file);
            let cause = errno.map(|errno| io::Error::from_raw_os_error(errno).to_string());
            assert_eq!(e.to_string(), format!("{}{}", text, cause.unwrap_or_default()));
        }
        // A name is quoted with its control characters escaped: one of C1
        // is a control sequence on a terminal.
        let o = object(r#"{"name":"x\u009b2J","size":5}"#);
        let e = copy(&o, &mut source).unwrap_err();
        assert_eq!(e.name(), Some("x\u{9b}2J"));
        assert!(
            e.to_string().starts_with(r"x\u{9b}2J: failed to open x\u{9b}2J: "),
            "{}",
            e
        );
    }

    #[test]
    fn copies_from_a_stream() {
        let all = objects(&[
            &format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
            r#"{"name":"empty","size":0}"#,
            r#"{"name":"literal","contents":[{"literal":"aGVsbG8="}]}"#,
            r#"{"name":"d","type":"dir"}"#,
            &format!(
                r#"{{"name":"d/b","size":5,"sha256":"{}","contents":[{{"file":"other"}}]}}"#,
                WORLD
            ),
        ]);
        let streamed: Vec<&FileObject> = all.iter().filter(|o| o.has_external_data()).collect();
        assert_eq!(streamed.len(), 3);
        let mut stream = &b"helloworld"[..];
        let mut source = StreamSource::new(&mut stream);
        assert_eq!(copy(streamed[0], &mut source).unwrap(), b"hello");
        assert_eq!(copy(&all[2], &mut source).unwrap(), b"hello");
        assert_eq!(copy(streamed[1], &mut source).unwrap(), b"");
        assert_eq!(copy(streamed[2], &mut source).unwrap(), b"world");
        source.end().unwrap();
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
        let e = source.end().unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::SizeMismatch),
                Some("d/b"),
                None,
                Some(5),
                "d/b: the stream goes on after the last file".to_string()
            )
        );
        // A stream that has data when it had none of a file, and one that
        // has none.
        let mut stream = &b"junk"[..];
        let e = StreamSource::new(&mut stream).end().unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::SizeMismatch),
                None,
                None,
                Some(0),
                "the stream has data that no file of the manifest describes".to_string()
            )
        );
        let mut stream = &b""[..];
        StreamSource::new(&mut stream).end().unwrap();
        // Contents that are not the ones the manifest describes.
        let mut stream = &b"hellp"[..];
        let e = copy(streamed[0], &mut StreamSource::new(&mut stream)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Content(ContentProblem::HashMismatch));
    }

    /// The hash the manifest gives for all of a file is checked where a
    /// stream has all of the file, and a part of a file is checked against
    /// the hash of the object alone.
    #[test]
    fn whole_files_and_parts_in_a_stream() {
        let hash = ErrorKind::Content(ContentProblem::HashMismatch);
        let check = |o: &FileObject, data: &'static [u8]| {
            let mut stream = data;
            let copied = copy(o, &mut StreamSource::new(&mut stream));
            assert!(stream.is_empty());
            copied
        };
        // A reader gives an object that is all of its file the hash of the
        // file as its own.
        let sized = object(&format!(
            r#"{{"name":"x","size":5,"contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
            HELLO
        ));
        assert_eq!(sized.sha256, HELLO.parse().ok());
        assert_eq!(check(&sized, b"hello").unwrap(), b"hello");
        assert_eq!(check(&sized, b"world").unwrap_err().kind(), hash);
        // An object that is all of its file without a hash of its own.
        let mut whole = FileObject::new(Name::new("x").unwrap());
        whole.size = Some(5);
        let mut contents = Contents::new(Location::Implied);
        contents.original_size = Some(5);
        contents.original_sha256 = HELLO.parse().ok();
        whole.contents.push(contents);
        assert_eq!(check(&whole, b"hello").unwrap(), b"hello");
        let e = check(&whole, b"world").unwrap_err();
        assert_eq!(
            facts(&e),
            (
                hash,
                Some("x"),
                None,
                None,
                "x: x does not match the hash in the manifest".to_string()
            )
        );
        // A part with a hash of its own is held against that, and one
        // without, or one the stream cannot tell from all of the file, is
        // taken as it is.
        let part = object(&format!(
            r#"{{"name":"x","size":2,"sha256":"{}","contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
            Sha256::digest(b"he"),
            HELLO
        ));
        assert_eq!(check(&part, b"he").unwrap(), b"he");
        assert_eq!(check(&part, b"hx").unwrap_err().kind(), hash);
        for record in [
            format!(
                r#"{{"name":"x","size":2,"contents":[{{"originalSize":5,"originalSha256":"{}"}}]}}"#,
                HELLO
            ),
            format!(
                r#"{{"name":"x","size":5,"contents":[{{"originalSha256":"{}"}}]}}"#,
                HELLO
            ),
        ] {
            let o = object(&record);
            assert_eq!(o.sha256, None);
            let data: &'static [u8] = if o.size == Some(2) { b"xx" } else { b"world" };
            assert_eq!(check(&o, data).unwrap(), data, "{}", record);
        }
        // A stream has no place for a file without a size or at an offset.
        let mut stream = &b"hello"[..];
        let mut source = StreamSource::new(&mut stream);
        let e = copy(&object(r#"{"name":"x"}"#), &mut source).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::NoSize));
        assert_eq!((e.name(), e.field()), (Some("x"), Some(Field::Size)));
        assert_eq!(e.to_string(), "x: streamed contents need a known size");
        let e = copy(
            &object(r#"{"name":"x","size":2,"contents":[{"offset":1}]}"#),
            &mut source,
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::OffsetInStream));
        assert_eq!(e.name(), Some("x"));
        assert_eq!(stream, b"hello");
    }

    /// The data of an object that a consumer does not take is read past
    /// on a stream, and checked as it would be in a copy.
    #[test]
    fn skips_what_is_not_taken() {
        let all = objects(&[
            &format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO),
            r#"{"name":"d","type":"dir"}"#,
            &format!(r#"{{"name":"d/b","size":5,"sha256":"{}"}}"#, WORLD),
            r#"{"name":"literal","contents":[{"literal":"aGVsbG8="}]}"#,
            r#"{"name":"remote","contents":[{"url":"https://example.com/x"}]}"#,
        ]);
        let mut stream = &b"helloworld"[..];
        let mut source = StreamSource::new(&mut stream);
        for o in [&all[0], &all[1]] {
            source.skip(o).unwrap();
        }
        assert_eq!(copy(&all[2], &mut source).unwrap(), b"world");
        for o in &all[3..] {
            source.skip(o).unwrap();
        }
        source.end().unwrap();
        // A skip fails where a copy would.
        let mut stream = &b"hellp"[..];
        let e = StreamSource::new(&mut stream).skip(&all[0]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Content(ContentProblem::HashMismatch));
        let mut stream = &b"hel"[..];
        let e = StreamSource::new(&mut stream).skip(&all[0]).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Content(ContentProblem::StreamEnded));
        let mut stream = &b"hello"[..];
        let e = StreamSource::new(&mut stream)
            .skip(&object(r#"{"name":"x"}"#))
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Unsupported(UnsupportedContent::NoSize));
        // A directory has nothing to read past.
        let files = Files::of(&[("a", b"hello")]);
        DirectorySource::new(&files).skip(&all[0]).unwrap();
        assert_eq!(files.read(), 0);
    }

    /// Writes "hello world" for every object, whatever it says.
    struct Babbler {
        /// Whether a write that fails fails the copy.
        careful: bool,
    }

    impl ContentSource for Babbler {
        fn copy(&mut self, _: &FileObject, _: &Reference<'_>, sink: &mut dyn Write) -> Result<(), Error> {
            let written = sink.write_all(b"hello world");
            if self.careful {
                written?;
            }
            Ok(())
        }
    }

    #[test]
    fn checks_what_passes() {
        let o = object(&format!(r#"{{"name":"x","size":5,"sha256":"{}"}}"#, HELLO));
        let mut check = ContentCheck::new(&o);
        for piece in [&b"he"[..], b"", b"llo"] {
            check.update(piece).unwrap();
        }
        assert_eq!(check.finish().unwrap(), 5);
        // Too few bytes, the wrong ones, and too many.
        let mut check = ContentCheck::new(&o);
        check.update(b"hell").unwrap();
        let e = check.finish().unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::SizeMismatch),
                Some("x"),
                Some(4),
                Some(5),
                "'x' is 4 bytes, the manifest says 5".to_string()
            )
        );
        let mut check = ContentCheck::new(&o);
        check.update(b"world").unwrap();
        assert_eq!(
            check.finish().unwrap_err().kind(),
            ErrorKind::Content(ContentProblem::HashMismatch)
        );
        let mut check = ContentCheck::new(&o);
        check.update(b"hell").unwrap();
        let e = check.update(b"o!").unwrap_err();
        assert_eq!(
            facts(&e),
            (
                ErrorKind::Content(ContentProblem::SizeMismatch),
                Some("x"),
                None,
                Some(5),
                "'x' has more than the 5 bytes the manifest says".to_string()
            )
        );
        // What it refused it did not take.
        check.update(b"o").unwrap();
        assert_eq!(check.finish().unwrap(), 5);
        // Without a size and a hash it counts.
        let o = object(r#"{"name":"x","contents":[{"url":"https://example.com/x"}]}"#);
        let mut check = ContentCheck::new(&o);
        check.update(b"any").unwrap();
        check.update(b"thing").unwrap();
        assert_eq!(check.finish().unwrap(), 8);
        // A source that writes more than the size of the object is stopped
        // before the sink gets any of it, and fails the copy with what the
        // check says, also when it passes over the error of the write.
        let o = object(r#"{"name":"x","size":5}"#);
        for careful in [true, false] {
            let mut out = Vec::new();
            let e = o.copy_contents(&mut Babbler { careful }, &mut out).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Content(ContentProblem::SizeMismatch));
            assert_eq!((e.found_size(), e.expected_size()), (None, Some(5)));
            assert!(out.is_empty());
        }
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
        let files = Files::of(&[("a", b"hello")]);
        let nothing = Files::default();
        let mut directory = DirectorySource::new(&files);
        let mut stream = &b"hello"[..];
        let mut stream = StreamSource::new(&mut stream);
        let mut empty = DirectorySource::new(&nothing);
        let sources: [(&FileObject, &mut dyn ContentSource); 3] =
            [(&o, &mut directory), (&o, &mut stream), (&literal, &mut empty)];
        for (object, source) in sources {
            let e = object.copy_contents(source, &mut Full(4)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Io);
            assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::ENOSPC));
        }
    }

    /// What a source prints for debugging says how large its buffer is,
    /// and does not hold it.
    #[test]
    fn debug_shows_no_buffers() {
        let files = Files::of(&[("a", b"hello")]);
        let mut source = DirectorySource::new(&files);
        copy(&object(r#"{"name":"a","size":5}"#), &mut source).unwrap();
        let text = format!("{:?}", source);
        assert!(text.len() < 500, "{}", text);
        assert!(
            text.contains("buffer: 1048576/1048576, hashes: PieceHashes { files: 0, bytes: 0/1048576 }"),
            "{}",
            text
        );
        let mut source = StreamSource::new(io::repeat(7).take(2 * COPY_SIZE as u64));
        copy(&object(r#"{"name":"a","size":5}"#), &mut source).unwrap();
        let text = format!("{:?}", source);
        assert!(text.len() < 200, "{}", text);
        assert!(
            text.ends_with(r#"buffer: 1048576/1048576, last: Some(("a", 5)) }"#),
            "{}",
            text
        );
    }
}
