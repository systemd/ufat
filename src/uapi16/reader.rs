// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading a manifest record by record.

use std::fmt;
use std::io::{self, BufRead};

use json::is_whitespace;

use crate::decode::{DecodedObject, RecordDecoder, ROOT_RECORD};
use crate::error::{Error, Problem};
use crate::object::{FileObject, RootObject, Signature};
use crate::sequence::SequenceCheck;
use crate::{MAX_RECORD_SIZE, RECORD_END, RECORD_SEPARATOR};

/// The most bytes a record has behind its record separator, which counts
/// as a part of the record.
const MAX_RECORD_TEXT: usize = MAX_RECORD_SIZE - size_of_val(&RECORD_SEPARATOR);
/// The most the read of one record takes from the input: the bytes of a
/// record as large as a record can be behind its separator, and the
/// separator behind them.
const READ_LIMIT: usize = MAX_RECORD_TEXT + size_of_val(&RECORD_SEPARATOR);
/// The byte no record may have.
const NUL: u8 = 0;

/// Where the read of a record ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecordEnd {
    /// At a record separator, where the next record starts.
    Separator,
    /// At the end of the input.
    Input,
    /// At [`READ_LIMIT`], without a separator: the record is too large.
    Limit,
}

/// What [`RecordSplitter::next_record`] has.
enum NextRecord<'a> {
    /// The text of the next record that is more than whitespace.
    Text(&'a str),
    /// Nothing yet: the next record goes on in input that was not fed.
    Input,
    /// Nothing: the input ended.
    End,
}

/// Splits the input into the records of a JSON text sequence as it is
/// fed: each one starts with a record separator and goes up to the next
/// one. It holds one record without its separator, at most
/// [`MAX_RECORD_TEXT`] bytes, and takes no more of the input for it than
/// [`READ_LIMIT`].
#[derive(Default)]
struct RecordSplitter {
    /// The record being read, or the one handed out last, without its
    /// separators. A record too large is kept up to the limit.
    record: Vec<u8>,
    /// How many bytes of the input the read of the record took, its
    /// separator included.
    taken: usize,
    /// Where the read of the record ended, once it did.
    end: Option<RecordEnd>,
    /// Whether the record was handed out, so that the next one is read.
    handed_out: bool,
    /// Whether the input ended.
    input_ended: bool,
    /// How many bytes of the input went into the records read so far.
    pos: u64,
    /// Where in the input the record that was handed out last starts.
    offset: u64,
}

impl RecordSplitter {
    /// Takes bytes from the start of `input` into the record being read,
    /// up to the separator behind it, and no more than [`READ_LIMIT`] for
    /// the record. Returns how many it took. Once the read ended it takes
    /// none, until the record was handed out and the next read started.
    #[inline]
    fn feed(&mut self, input: &[u8]) -> usize {
        if self.end.is_some() {
            return 0;
        }
        let window = &input[..input.len().min(READ_LIMIT - self.taken)];
        // Reading a slice does no I/O and cannot fail. The search is the
        // one BufRead::skip_until() does in a BufReader.
        let mut rest = window;
        let took = rest.skip_until(RECORD_SEPARATOR).unwrap_or_default();
        let separated = window[..took].last() == Some(&RECORD_SEPARATOR);
        // The separator is not kept, and neither is the byte of a record
        // too large that reaches the limit.
        let kept = took - usize::from(separated);
        let kept = &window[..kept.min(MAX_RECORD_TEXT - self.record.len())];
        // The buffer grows the way a Vec grows, but not beyond the largest
        // record.
        let len = self.record.len() + kept.len();
        if len > self.record.capacity() {
            let capacity = (2 * self.record.capacity()).max(len).min(MAX_RECORD_TEXT);
            self.record.reserve_exact(capacity - self.record.len());
        }
        self.record.extend_from_slice(kept);
        self.taken += took;
        if separated {
            self.end = Some(RecordEnd::Separator);
        } else if self.taken == READ_LIMIT {
            self.end = Some(RecordEnd::Limit);
        }
        took
    }

    /// Notes that the input ended: the read of the record ends there, and
    /// so does every read after it.
    #[inline]
    fn end_input(&mut self) {
        self.input_ended = true;
        self.end.get_or_insert(RecordEnd::Input);
    }

    /// Starts the read of the next record.
    #[inline]
    fn restart(&mut self) {
        self.record.clear();
        self.taken = 0;
        self.end = self.input_ended.then_some(RecordEnd::Input);
    }

    /// Moves on to the read of the next record once the record read last
    /// was handed out.
    #[inline]
    fn advance(&mut self) {
        if std::mem::take(&mut self.handed_out) {
            self.restart();
        }
    }

    /// Whether the record being read goes on in input that was not fed
    /// yet.
    #[inline]
    fn wants_input(&self) -> bool {
        self.end.is_none()
    }

    /// Whether the record that was handed out last, which holds the
    /// trailer object, is the end of the input: nothing comes behind the
    /// object but whitespace up to the newline that ends the record.
    fn ends_with_trailer(&self) -> bool {
        // The record was read as JSON, so behind the object there is only
        // JSON's whitespace, which is ASCII whitespace.
        let behind = &self.record[self.record.trim_ascii_end().len()..];
        let newline = behind.iter().position(|&b| b == RECORD_END);
        self.end == Some(RecordEnd::Input) && newline.is_none_or(|at| at + 1 == behind.len())
    }

    /// The next record that is more than whitespace, once it was read up to
    /// its end. Its text stays as it is until the next call.
    #[inline]
    fn next_record(&mut self) -> Result<NextRecord<'_>, Error> {
        self.advance();
        if self.wants_input() {
            return Ok(NextRecord::Input);
        }
        loop {
            let Some(end) = self.end else {
                return Ok(NextRecord::Input);
            };
            let start = self.pos;
            self.pos += self.taken as u64;
            // Nothing may come before the first separator.
            if start == 0 {
                if self.taken == 0 {
                    return Ok(NextRecord::End);
                }
                if let Some(&first) = self.record.first() {
                    return Err(Error::manifest(
                        Problem::NoRecordSeparator,
                        format!(
                            "manifest record does not start with a record separator but with byte 0x{:02x}",
                            first
                        ),
                    ));
                }
                self.restart();
                continue;
            }
            if self.taken == 0 {
                return Ok(NextRecord::End);
            }
            if end == RecordEnd::Limit {
                return Err(Error::record_too_large());
            }
            if self.record.contains(&NUL) {
                return Err(Error::manifest(
                    Problem::ContainsNulByte,
                    "manifest record contains a NUL byte".into(),
                ));
            }
            self.offset = start - size_of_val(&RECORD_SEPARATOR) as u64;
            // Empty records are skipped, as RFC 7464 suggests. Only JSON's
            // whitespace counts as empty.
            if !self.record.iter().all(|&b| is_whitespace(b)) {
                self.handed_out = true;
                return match std::str::from_utf8(&self.record) {
                    Ok(text) => Ok(NextRecord::Text(text)),
                    Err(_) => Err(Error::manifest(Problem::NotUtf8, "manifest record is not UTF-8".into())),
                };
            }
            self.restart();
        }
    }
}

impl fmt::Debug for RecordSplitter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSplitter")
            .field(
                "record",
                &format_args!("{}/{}", self.record.len(), self.record.capacity()),
            )
            .field("taken", &self.taken)
            .field("end", &self.end)
            .field("handed_out", &self.handed_out)
            .field("input_ended", &self.input_ended)
            .field("pos", &self.pos)
            .field("offset", &self.offset)
            .finish()
    }
}

/// An object of a manifest after its root file object, as a [`Reader`]
/// and a [`Decoder`] hand it out.
///
/// [`Reader`]: crate::Reader
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Object {
    /// A file object.
    File(Box<FileObject>),
    /// A signature object. It comes after the last file object.
    Signature(Signature),
}

/// How far a decoder has got in the manifest.
#[derive(Debug)]
enum Stage {
    /// The root file object comes.
    Root,
    /// File objects come, each checked against the ones before it.
    Files(SequenceCheck),
    /// A signature object was read. File objects cannot follow.
    Signatures,
    /// The manifest is decoded to its end, or decoding it failed.
    Done,
}

/// What a [`Decoder`] has for its caller next.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// More of the manifest: [`Decoder::feed`] takes it, and
    /// [`Decoder::end`] says that the input ended.
    Input,
    /// The root file object. It comes first, once.
    Root(Box<RootObject>),
    /// A file object or a signature object.
    Object(Object),
    /// The end of the manifest, after its trailer object. Once
    /// [`Decoder::step`] returned an error, it returns this as well.
    End,
}

/// Reads a manifest from the bytes it is fed, and does no I/O itself.
///
/// [`Decoder::step`] says what comes next. [`Step::Input`] asks for more
/// of the manifest: [`Decoder::feed`] takes the bytes that come next, and
/// [`Decoder::end`] says that there are no more. [`Step::Root`] is the root
/// file object, [`Step::Object`] each object after it, and [`Step::End`]
/// the end of the manifest.
///
/// A record ends where the next one starts, so an object comes once the
/// separator of the record after it was fed, or [`Decoder::end`] was
/// called. Nothing may follow the trailer object, so [`Step::End`] comes
/// only after [`Decoder::end`]. [`Decoder::step`] reads a whole record, of
/// up to [`MAX_RECORD_SIZE`] bytes with its record separator, in one call.
///
/// A decoder checks and fills in what a [`Reader`] does, which is a
/// decoder fed from a [`Read`]. It takes the bytes of one record at a time,
/// up to the record separator behind it, and keeps one record without its
/// separator and the name of the last file object in memory: less than
/// [`MAX_RECORD_SIZE`] and at most [`Name::MAX_LEN`](crate::Name::MAX_LEN)
/// bytes, in whatever pieces the manifest comes.
///
/// ```
/// use uapi16::{Decoder, Object, Step};
///
/// let manifest = concat!(
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
///     "\x1e{\"name\":\"a\",\"size\":3}\n",
///     "\x1e{\"name\":\"b\",\"type\":\"dir\"}\n",
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
/// );
/// let mut input = manifest.as_bytes();
/// let mut decoder = Decoder::new();
/// let mut names = Vec::new();
/// loop {
///     match decoder.step()? {
///         Step::Input if input.is_empty() => decoder.end(),
///         // The manifest comes in pieces of at most five bytes.
///         Step::Input => {
///             let taken = decoder.feed(&input[..input.len().min(5)]);
///             input = &input[taken..];
///         }
///         Step::Object(Object::File(object)) => names.push(object.name),
///         Step::End => break,
///         _ => {}
///     }
/// }
/// assert_eq!(names, ["a", "b"]);
/// # Ok::<(), uapi16::Error>(())
/// ```
///
/// [`Read`]: std::io::Read
/// [`Reader`]: crate::Reader
#[derive(Debug)]
pub struct Decoder {
    splitter: RecordSplitter,
    /// The number of the record that is read next.
    next_record: u64,
    /// The number of the record the object handed out last came from.
    last_record: u64,
    stage: Stage,
    /// Where in the input the first signature object starts.
    signed: Option<u64>,
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// A decoder at the start of a manifest.
    pub fn new() -> Decoder {
        Decoder {
            splitter: RecordSplitter::default(),
            next_record: ROOT_RECORD,
            last_record: ROOT_RECORD,
            stage: Stage::Root,
            signed: None,
        }
    }

    /// Takes bytes from the start of `input`, after [`Step::Input`], up to
    /// the end of the record it reads. It takes one at least where `input`
    /// has any, and returns how many it took. The others are for a later
    /// call, after the next step.
    #[inline]
    #[must_use]
    pub fn feed(&mut self, input: &[u8]) -> usize {
        self.splitter.feed(input)
    }

    /// Says that the input ended, after [`Step::Input`].
    #[inline]
    pub fn end(&mut self) {
        self.splitter.end_input();
    }

    /// What comes next. Once it returned an error, it returns
    /// [`Step::End`].
    #[inline]
    pub fn step(&mut self) -> Result<Step, Error> {
        if !matches!(self.stage, Stage::Done) {
            // The next record goes on in input that was not fed yet, as it
            // does right after every object that was handed out.
            self.splitter.advance();
            if self.splitter.wants_input() {
                return Ok(Step::Input);
            }
        }
        let step = match self.stage {
            Stage::Root => self.root(),
            Stage::Files(_) | Stage::Signatures => self.object(),
            Stage::Done => return Ok(Step::End),
        };
        if matches!(step, Ok(Step::End) | Err(_)) {
            self.stage = Stage::Done;
        }
        step
    }

    /// The number of the record the object handed out last came from. The
    /// record of the root file object is number 0. Records that are empty
    /// do not count.
    pub fn record_number(&self) -> u64 {
        self.last_record
    }

    /// How many bytes at the start of the manifest its signature objects
    /// sign, see [`Reader::signed_len`].
    ///
    /// [`Reader::signed_len`]: crate::Reader::signed_len
    pub fn signed_len(&self) -> Option<u64> {
        self.signed
    }

    /// An error `e` of the input the manifest is read from, as an error
    /// about the record the decoder reads.
    pub fn input_error(&self, e: io::Error) -> Error {
        Error::from(e).in_record(self.next_record)
    }

    /// Reads the root file object.
    fn root(&mut self) -> Result<Step, Error> {
        let text = match self.splitter.next_record().map_err(|e| e.in_record(ROOT_RECORD))? {
            NextRecord::Input => return Ok(Step::Input),
            NextRecord::End => {
                return Err(Error::manifest(
                    Problem::NoObjects,
                    "manifest contains no objects".into(),
                ))
            }
            NextRecord::Text(text) => text,
        };
        let mut root = RecordDecoder::root(text)?;
        let features = root.recorded_features();
        let sequence_check = SequenceCheck::new(features, root.order);
        sequence_check
            .check_root_fields(&root)
            .map_err(|e| e.in_record(ROOT_RECORD))?;
        root.fill_in(features);
        self.stage = Stage::Files(sequence_check);
        self.next_record = ROOT_RECORD + 1;
        Ok(Step::Root(Box::new(root)))
    }

    /// Reads on to the next file or signature object.
    fn object(&mut self) -> Result<Step, Error> {
        loop {
            let number = self.next_record;
            let text = match self.splitter.next_record().map_err(|e| e.in_record(number))? {
                NextRecord::Input => return Ok(Step::Input),
                NextRecord::End => {
                    return Err(Error::manifest(
                        Problem::NoTrailer,
                        "manifest lacks the trailer object, it is incomplete".into(),
                    ))
                }
                NextRecord::Text(text) => text,
            };
            let decoded = RecordDecoder::record(text, number)?;
            self.next_record += 1;
            match decoded {
                // Nothing may come behind the trailer, not even an empty
                // record or whitespace.
                DecodedObject::Trailer if self.splitter.ends_with_trailer() => return Ok(Step::End),
                DecodedObject::Trailer => return Err(Error::data_after_trailer(self.next_record)),
                DecodedObject::Other => {}
                DecodedObject::Signature(signature) => {
                    self.stage = Stage::Signatures;
                    self.signed.get_or_insert(self.splitter.offset);
                    self.last_record = number;
                    return Ok(Step::Object(Object::Signature(signature)));
                }
                DecodedObject::File(object) => {
                    // A file object behind a signature is one the signature
                    // does not cover.
                    let Stage::Files(sequence_check) = &mut self.stage else {
                        return Err(Error::file_after_signature(number));
                    };
                    let mut object = object?;
                    let checked = sequence_check
                        .check_fields(&object, number)
                        .and_then(|()| sequence_check.admit(&object, number));
                    checked.map_err(|e| e.in_record(number).named(object.name.as_str()))?;
                    object.fill_in(sequence_check.features());
                    self.last_record = number;
                    return Ok(Step::Object(Object::File(object)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocking::READ_SIZE;
    use crate::error::{ErrorKind, Field};
    use crate::testing::{manifest, sequence, ROOT, SIGNATURE, TRAILER};
    use crate::testing::{read_whole, Whole, HELLO, PIECES};
    use crate::{Digest, DosFlags, Features, FlagStates, InodeFlags, InodeType, Order, Reader, RootObject, Sha256};
    use std::collections::BTreeMap;

    /// Reads `bytes` to the end and returns the names of the file objects
    /// and the number of signature objects.
    fn read(bytes: &[u8]) -> Result<(Vec<String>, usize), Error> {
        let mut names = Vec::new();
        let mut signatures = 0;
        for object in Reader::open(bytes)? {
            match object? {
                Object::File(object) => names.push(object.name.to_string()),
                Object::Signature(_) => signatures += 1,
            }
        }
        Ok((names, signatures))
    }

    /// The problem with `bytes` and the record it is in.
    fn problem(bytes: &[u8]) -> (Problem, Option<u64>) {
        let e = read(bytes).expect_err("the manifest was taken");
        match e.kind() {
            ErrorKind::Manifest(problem) => (problem, e.record_number()),
            other => panic!("{:?}: {}", other, e),
        }
    }

    #[test]
    fn reads_a_manifest() {
        let file = format!(
            r#"{{"mTimeNSec":1700000000000000000,"mode":420,"name":"EFI/BOOT/BOOTX64.EFI","sha256":"{}","size":5}}"#,
            HELLO
        );
        let m = read_whole(&sequence(&[
            concat!(
                r#"{"features":["device","gid","hardlink","mode","mtime","sha256","size","symlink","uid"],"#,
                r#""mTimeNSec":7,"mediaType":"application/vnd.uapi.16.manifest","mode":509}"#
            ),
            r#"{"mode":493,"name":"EFI","type":"dir","uid":0,"gid":0}"#,
            r#"{"name":"EFI/BOOT","type":"dir"}"#,
            &file,
            r#"{"name":"empty","size":0}"#,
            r#"{"contents":[{"literal":"aGVsbG8="}],"name":"literal.txt","mode":420}"#,
            r#"{"contents":[{"literal":"aGVsbG8="}],"name":"link","type":"lnk"}"#,
            SIGNATURE,
            r#"{"mediaType":"application/x-unknown","whatever":1}"#,
            TRAILER,
        ]))
        .unwrap();
        assert_eq!(
            (m.root.inode.mtime_nsec, m.root.inode.mode.map(crate::Mode::bits)),
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
        assert_eq!(m.objects[2].sha256, Some(Sha256::digest(b"hello")));
        assert_eq!(m.objects[3].sha256, Some(Sha256::EMPTY));
        assert_eq!(m.objects[4].size, Some(5));
        assert_eq!(m.objects[5].inode_type, InodeType::Symlink);
        assert_eq!(m.signatures.len(), 1);
        assert_eq!(m.signatures[0].mechanism, "pkcs7");
        assert_eq!(m.signatures[0].data.as_deref(), Some(&[0u8, 0, 0][..]));
        // The least a manifest is.
        let least = read_whole(&sequence(&[ROOT, TRAILER])).unwrap();
        assert_eq!((least.root, least.objects.len()), (RootObject::default(), 0));
    }

    #[test]
    fn tree_order() {
        let dir = |name: &str| format!(r#"{{"name":"{}","type":"dir"}}"#, name);
        let file = |name: &str| format!(r#"{{"name":"{}","size":0}}"#, name);
        let read_names = |records: &[String]| {
            let records: Vec<&str> = records.iter().map(String::as_str).collect();
            read(&manifest(&records))
        };
        let good = [dir("a"), dir("a/b"), file("a/b/c"), file("a/d"), file("e")];
        assert_eq!(read_names(&good).unwrap().0.len(), 5);
        for (records, record) in [
            (vec![file("a/x")], 1),
            (vec![dir("a"), file("b"), file("a/x")], 3),
            (vec![file("a"), file("a/x")], 2),
        ] {
            let records: Vec<&str> = records.iter().map(String::as_str).collect();
            assert_eq!(
                problem(&manifest(&records)),
                (Problem::Misplaced, Some(record)),
                "{:?}",
                records
            );
        }
    }

    #[test]
    fn repeated_names() {
        // A name right after itself, or right after the entries of the
        // directory it names, is found in any order.
        for records in [
            &[r#"{"name":"a"}"#, r#"{"name":"a"}"#][..],
            &[
                r#"{"name":"d","type":"dir"}"#,
                r#"{"name":"d/x"}"#,
                r#"{"name":"d","type":"dir"}"#,
            ],
        ] {
            assert_eq!(problem(&manifest(records)).0, Problem::DuplicateName, "{:?}", records);
        }
        // A name that comes again later is only found if the manifest
        // declares an order.
        let later = manifest(&[r#"{"name":"a"}"#, r#"{"name":"b"}"#, r#"{"name":"a"}"#]);
        assert_eq!(read(&later).unwrap().0, ["a", "b", "a"]);
        let declared = sequence(&[
            r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#,
            r#"{"name":"a"}"#,
            r#"{"name":"b"}"#,
            r#"{"name":"a"}"#,
            TRAILER,
        ]);
        assert_eq!(problem(&declared), (Problem::OutOfOrder, Some(3)));
        // Names that differ by case, by a byte or by a prefix are not the
        // same.
        let m = read_whole(&manifest(&[r#"{"name":"A"}"#, r#"{"name":"a"}"#, r#"{"name":"a."}"#])).unwrap();
        assert_eq!(m.objects.len(), 3);
    }

    #[test]
    fn requires_the_declared_order() {
        // A consumer that relies on the order requires the manifest to
        // declare it. File objects that are in it are not enough.
        let sorted = manifest(&[r#"{"name":"a"}"#, r#"{"name":"b"}"#]);
        let reader = Reader::open(&sorted[..]).unwrap();
        assert_eq!(reader.root().order, None);
        let e = reader.root().require_order(Order::CodePoint).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number(), e.field()),
            (ErrorKind::Manifest(Problem::NoOrder), Some(0), Some(Field::Order))
        );
        assert_eq!(
            e.to_string(),
            r#"the manifest does not declare "order": "codepoint" in its root file object"#
        );
        // An order the specification does not have, or null, declares none.
        for order in [r#""later""#, r#""CodePoint""#, "null"] {
            let root = format!(
                r#"{{"mediaType":"application/vnd.uapi.16.manifest","order":{}}}"#,
                order
            );
            let bytes = sequence(&[&root, TRAILER]);
            let reader = Reader::open(&bytes[..]).unwrap();
            let e = reader.root().require_order(Order::CodePoint).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoOrder), "{}", order);
        }
        let declared = sequence(&[
            r#"{"mediaType":"application/vnd.uapi.16.manifest","order":"codepoint"}"#,
            r#"{"name":"a"}"#,
            TRAILER,
        ]);
        let reader = Reader::open(&declared[..]).unwrap();
        assert_eq!(reader.root().order, Some(Order::CodePoint));
        assert!(reader.root().require_order(Order::CodePoint).is_ok());
    }

    #[test]
    fn features() {
        let with = |root: &str, records: &[&str]| sequence(&[&[root][..], records, &[TRAILER]].concat());
        // A field of a feature the manifest does not record, on any file
        // object, the root's too.
        assert_eq!(
            problem(&manifest(&[r#"{"name":"a","mTimeNSec":5}"#])),
            (Problem::UnlistedFeature, Some(1))
        );
        let root = r#"{"mediaType":"application/vnd.uapi.16.manifest","features":["size"]}"#;
        assert_eq!(
            problem(&with(root, &[r#"{"name":"a","mode":420}"#])),
            (Problem::UnlistedFeature, Some(1))
        );
        let e = Reader::open(
            &with(
                r#"{"mediaType":"application/vnd.uapi.16.manifest","uid":0,"features":[]}"#,
                &[],
            )[..],
        )
        .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::UnlistedFeature));
        // The error names the field and the record.
        assert_eq!((e.record_number(), e.field()), (Some(0), Some(Field::Uid)));
        let e = read(&manifest(&[r#"{"name":"a","mTimeNSec":5}"#])).unwrap_err();
        assert_eq!(
            (e.record_number(), e.name(), e.field()),
            (Some(1), Some("a"), Some(Field::MTimeNSec))
        );
        // The fields of the file system and of partitions belong to
        // features too.
        for (root, records, field) in [
            (
                r#"{"mediaType":"application/vnd.uapi.16.manifest","readOnly":true}"#,
                &[][..],
                Field::ReadOnly,
            ),
            (
                r#"{"mediaType":"application/vnd.uapi.16.manifest","fsLabel":"ESP"}"#,
                &[],
                Field::FsLabel,
            ),
            (
                r#"{"mediaType":"application/vnd.uapi.16.manifest","fsUUID":"11111111-2222-3333-4444-555555555555"}"#,
                &[],
                Field::FsUuid,
            ),
            (
                r#"{"mediaType":"application/vnd.uapi.16.manifest","fatSerial":"1234-ABCD"}"#,
                &[],
                Field::FatSerial,
            ),
            (
                r#"{"mediaType":"application/vnd.uapi.16.manifest","gptDiskUuid":"11111111-2222-3333-4444-555555555555"}"#,
                &[],
                Field::GptDiskUuid,
            ),
            (ROOT, &[r#"{"name":"a","readOnly":false}"#], Field::ReadOnly),
            (ROOT, &[r#"{"name":"a","gptLabel":"l"}"#], Field::GptLabel),
            (ROOT, &[r#"{"name":"a","gptFlags":0}"#], Field::GptFlags),
            (ROOT, &[r#"{"name":"a","gptFlagNoAuto":false}"#], Field::GptFlagNoAuto),
        ] {
            let e = read(&with(root, records)).unwrap_err();
            assert_eq!(
                (e.kind(), e.field()),
                (ErrorKind::Manifest(Problem::UnlistedFeature), Some(field)),
                "{} {:?}",
                root,
                records
            );
        }
        // A size of 0 that the hash of no data follows from names the size,
        // not the hash it gives.
        let sized = with(
            r#"{"mediaType":"application/vnd.uapi.16.manifest","features":["sha256"]}"#,
            &[r#"{"name":"a","size":0}"#],
        );
        assert_eq!(read(&sized).unwrap_err().field(), Some(Field::Size));
        // A symbolic link without its target in a manifest that records
        // them.
        assert_eq!(
            problem(&manifest(&[r#"{"name":"l","type":"lnk"}"#])),
            (Problem::NoTarget, Some(1))
        );
        let quiet = r#"{"mediaType":"application/vnd.uapi.16.manifest","features":["size"]}"#;
        assert!(read(&with(quiet, &[r#"{"name":"l","type":"lnk"}"#])).is_ok());
        // What the features say about the fields an object does not have.
        let root = concat!(
            r#"{"mediaType":"application/vnd.uapi.16.manifest","#,
            r#""features":["flag-hidden","flag-no-cow","gpt-flags","gpt-label","read-only","user-xattr"]}"#
        );
        let read_only = format!(
            r#"{{"name":"b","readOnly":true,"gptFlags":{}}}"#,
            crate::GptPartition::FLAG_READ_ONLY
        );
        let bytes = with(
            root,
            &[
                r#"{"name":"a","flagHidden":true,"gptLabel":"l"}"#,
                &read_only,
                r#"{"name":"c"}"#,
                r#"{"name":"l","type":"lnk"}"#,
            ],
        );
        let reader = Reader::open(&bytes[..]).unwrap();
        assert_eq!(
            reader.root().recorded_features(),
            Features::FLAG_HIDDEN
                | Features::FLAG_NO_COW
                | Features::GPT_FLAGS
                | Features::GPT_LABEL
                | Features::READ_ONLY
                | Features::USER_XATTR
        );
        // The root has the inode flags. It has no DOS attributes at all.
        let root = reader.root();
        assert_eq!(root.inode.flags.get(InodeFlags::NO_COW), Some(false));
        assert_eq!(root.inode.read_only, Some(false));
        assert_eq!(root.inode.user_xattrs.as_deref().map(BTreeMap::len), Some(0));
        let m = read_whole(&bytes).unwrap();
        let a = &m.objects[0];
        assert_eq!(a.dos_flags.get(DosFlags::HIDDEN), Some(true));
        assert_eq!(a.dos_flags.get(DosFlags::SYSTEM), None);
        assert_eq!(a.inode.flags.get(InodeFlags::NO_COW), Some(false));
        assert_eq!(a.inode.read_only, Some(false));
        assert_eq!(a.inode.user_xattrs.as_deref().map(BTreeMap::len), Some(0));
        assert_eq!(m.objects[1].inode.read_only, Some(true));
        // The gpt fields are as the records have them: a missing gptFlags
        // is 0, but nothing fills it in, and a regular file without any
        // gpt field has no GptPartition.
        assert_eq!(a.gpt.as_deref().map(|gpt| gpt.flags), Some(None));
        assert_eq!(m.objects[2].gpt, None);
        // A symbolic link has no flags.
        let link = &m.objects[3];
        assert_eq!(
            (link.dos_flags, link.inode.flags),
            (FlagStates::default(), FlagStates::default())
        );
        // Without the features nothing is known about them.
        let m = read_whole(&manifest(&[r#"{"name":"a"}"#])).unwrap();
        let a = &m.objects[0];
        assert_eq!(
            (a.dos_flags, a.inode.flags),
            (FlagStates::default(), FlagStates::default())
        );
        assert_eq!((a.inode.user_xattrs.as_deref(), a.inode.read_only), (None, None));
        assert_eq!(m.root, RootObject::default());
    }

    #[test]
    fn records() {
        let files = [r#"{"name":"a","size":0}"#, r#"{"name":"b","type":"dir"}"#];
        let plain = manifest(&files);
        assert_eq!(read(&plain).unwrap(), (vec!["a".to_string(), "b".to_string()], 0));
        // Records of nothing but whitespace are passed over, up to the
        // trailer. A newline at the end of a record is not needed.
        let mut spaced = vec![RECORD_SEPARATOR, RECORD_SEPARATOR, b' ', RECORD_SEPARATOR, b'\n', b'\t'];
        spaced.extend(sequence(&[ROOT]));
        spaced.extend([RECORD_SEPARATOR, b'\r', b'\n', RECORD_SEPARATOR, b'\t']);
        spaced.extend(sequence(&files));
        spaced.extend([RECORD_SEPARATOR, b' ', RECORD_SEPARATOR]);
        spaced.push(RECORD_SEPARATOR);
        spaced.extend(TRAILER.as_bytes());
        assert_eq!(read(&spaced).unwrap(), read(&plain).unwrap());
        // Behind the trailer object there is the newline that ends its
        // record, and nothing else: no empty record and no whitespace.
        for behind in [&b" "[..], b"\r", b" \r\n", b"\t\n"] {
            let mut bytes = sequence(&[ROOT, TRAILER]);
            bytes.pop();
            bytes.extend(behind);
            assert!(read(&bytes).is_ok(), "{:?}", behind);
        }
        for behind in [
            &[RECORD_SEPARATOR][..],
            &[RECORD_SEPARATOR, b'\n'],
            &[RECORD_SEPARATOR, RECORD_SEPARATOR],
            b"\n",
            b" ",
            b"\r\n",
            b"\t",
        ] {
            let mut bytes = sequence(&[ROOT, TRAILER]);
            bytes.extend(behind);
            assert_eq!(problem(&bytes), (Problem::DataAfterTrailer, Some(2)), "{:?}", behind);
        }
        let crlf: Vec<u8> = String::from_utf8(plain.clone())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes();
        assert_eq!(read(&crlf).unwrap(), read(&plain).unwrap());
        // Whitespace is JSON's, as systemd has it: whitespace beyond ASCII
        // is not nothing, and neither is a form feed or a vertical tab, on
        // its own or next to whitespace.
        for odd in ["\u{2028}", "\u{a0}", "\u{b}", "\u{c}", " \u{c}\n"] {
            let mut bytes = sequence(&[ROOT]);
            bytes.push(RECORD_SEPARATOR);
            bytes.extend(odd.as_bytes());
            bytes.extend(sequence(&[TRAILER]));
            assert_eq!(problem(&bytes), (Problem::NotJson, Some(1)), "{:?}", odd);
        }
    }

    #[test]
    fn what_is_no_sequence_of_records() {
        assert_eq!(problem(b""), (Problem::NoObjects, None));
        assert_eq!(
            problem(&[RECORD_SEPARATOR, b'\n', RECORD_SEPARATOR]),
            (Problem::NoObjects, None)
        );
        // Every record starts with a record separator.
        assert_eq!(problem(ROOT.as_bytes()), (Problem::NoRecordSeparator, Some(0)));
        assert_eq!(problem(b"garbage"), (Problem::NoRecordSeparator, Some(0)));
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend(manifest(&[]));
        let e = read(&bom).unwrap_err();
        assert_eq!(
            e.to_string(),
            "manifest record does not start with a record separator but with byte 0xef"
        );
        // What comes after a record belongs to it up to the next separator.
        let mut junk = sequence(&[ROOT]);
        junk.extend(b"junk");
        junk.extend(sequence(&[TRAILER]));
        assert_eq!(problem(&junk), (Problem::NotJson, Some(0)));
        let mut junk = manifest(&[]);
        junk.extend(b"junk");
        assert_eq!(problem(&junk), (Problem::NotJson, Some(1)));
        // A NUL byte and bytes that are not UTF-8. Behind the trailer they
        // are data behind the trailer like any other.
        for (bad, expected) in [(&b"\0"[..], Problem::ContainsNulByte), (&b"\xff"[..], Problem::NotUtf8)] {
            let mut bytes = sequence(&[ROOT]);
            bytes.push(RECORD_SEPARATOR);
            bytes.extend(br#"{"name":"a"#);
            bytes.extend(bad);
            bytes.extend(br#""}"#);
            bytes.extend(sequence(&[TRAILER]));
            assert_eq!(problem(&bytes), (expected, Some(1)));
            let mut bytes = manifest(&[]);
            bytes.push(RECORD_SEPARATOR);
            bytes.extend(bad);
            assert_eq!(problem(&bytes), (Problem::DataAfterTrailer, Some(2)));
        }
        let mut bytes = sequence(&[ROOT]);
        bytes.extend([RECORD_SEPARATOR, b' ', 0, b' ']);
        bytes.extend(sequence(&[TRAILER]));
        assert_eq!(problem(&bytes), (Problem::ContainsNulByte, Some(1)));
    }

    #[test]
    fn the_largest_record() {
        // A record is its bytes from its separator up to the next one, the
        // newline at its end included.
        let record = |len: usize| {
            let frame = "\x1e{\"name\":\"x\",\"size\":0,\"pad\":\"\"}\n";
            let pad = "p".repeat(len - frame.len());
            format!(r#"{{"name":"x","size":0,"pad":"{}"}}"#, pad)
        };
        let fits = record(MAX_RECORD_SIZE);
        assert_eq!(sequence(&[&fits]).len(), MAX_RECORD_SIZE);
        assert_eq!(read(&manifest(&[&fits])).unwrap().0, ["x"]);
        let too_large = record(MAX_RECORD_SIZE + 1);
        let bytes = manifest(&[&too_large]);
        assert_eq!(problem(&bytes), (Problem::RecordTooLarge, Some(1)));
        assert_eq!(
            read(&bytes).unwrap_err().to_string(),
            format!("manifest record exceeds {} bytes", MAX_RECORD_SIZE)
        );
        // A record that is too large is that before it is anything else,
        // and before its end was seen.
        let mut bytes = sequence(&[ROOT]);
        bytes.push(RECORD_SEPARATOR);
        bytes.resize(bytes.len() + MAX_RECORD_SIZE, 0);
        bytes.extend(sequence(&[TRAILER]));
        assert_eq!(problem(&bytes), (Problem::RecordTooLarge, Some(1)));
        let mut bytes = sequence(&[ROOT]);
        bytes.push(RECORD_SEPARATOR);
        bytes.resize(bytes.len() + MAX_RECORD_SIZE + 2 * READ_SIZE, b'x');
        assert_eq!(problem(&bytes), (Problem::RecordTooLarge, Some(1)));
    }

    #[test]
    fn the_order_of_the_objects() {
        let file = r#"{"name":"x"}"#;
        let other = r#"{"mediaType":"application/x-other","name":5,"contents":7}"#;
        assert_eq!(problem(&sequence(&[ROOT])), (Problem::NoTrailer, None));
        assert_eq!(problem(&sequence(&[ROOT, file])), (Problem::NoTrailer, None));
        for behind in [file, "{", TRAILER, other, "5"] {
            assert_eq!(
                problem(&sequence(&[ROOT, TRAILER, behind])),
                (Problem::DataAfterTrailer, Some(2)),
                "{}",
                behind
            );
        }
        // Signature objects come after the file objects. An object of an
        // unknown media type can be anywhere and is passed over.
        let read_all = |records: &[&str]| read(&sequence(records));
        assert_eq!(read_all(&[ROOT, SIGNATURE, TRAILER]).unwrap(), (vec![], 1));
        assert_eq!(
            read_all(&[ROOT, other, file, other, SIGNATURE, other, SIGNATURE, other, TRAILER]).unwrap(),
            (vec!["x".to_string()], 2)
        );
        assert_eq!(
            problem(&sequence(&[ROOT, SIGNATURE, file, TRAILER])),
            (Problem::FileAfterSignature, Some(2))
        );
        // That it is a file object after a signature comes before what is
        // wrong with it. That it is no object comes before both.
        assert_eq!(
            problem(&sequence(&[ROOT, SIGNATURE, r#"{"name":"/x","size":"y"}"#, TRAILER])),
            (Problem::FileAfterSignature, Some(2))
        );
        assert_eq!(
            problem(&sequence(&[ROOT, SIGNATURE, r#"{"name":"x","mediaType":5}"#, TRAILER])),
            (Problem::InvalidMediaType, Some(2))
        );
        // The first object is the root file object, and says so with its
        // media type.
        for first in [file, TRAILER, SIGNATURE, other, r#"{"type":"dir"}"#] {
            let e = read(&sequence(&[first, TRAILER])).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::InvalidMediaType), "{}", first);
            assert_eq!(e.record_number(), Some(0));
            assert_eq!(
                e.to_string(),
                "the first object of the manifest is not of the manifest media type"
            );
        }
    }

    /// Reads the manifest `bytes` to its end with a decoder that is fed
    /// `size` bytes at a time. Returns the manifest, the number of the
    /// record of every object after the root file object, and how much the
    /// signature objects sign.
    fn decode(bytes: &[u8], size: usize) -> Result<(Whole, Vec<u64>, Option<u64>), Error> {
        let mut pieces = bytes.chunks(size);
        let mut piece: &[u8] = &[];
        let mut decoder = Decoder::new();
        let mut whole = None;
        let mut numbers = Vec::new();
        loop {
            match decoder.step()? {
                Step::Input => {
                    if piece.is_empty() {
                        let Some(next) = pieces.next() else {
                            decoder.end();
                            continue;
                        };
                        piece = next;
                    }
                    // A decoder that asks for input takes some of it.
                    let taken = decoder.feed(piece);
                    assert_ne!(taken, 0, "{} at a time", size);
                    piece = &piece[taken..];
                }
                Step::Root(root) => {
                    assert!(whole.is_none(), "a second root file object");
                    whole = Some(Whole {
                        root: *root,
                        objects: Vec::new(),
                        signatures: Vec::new(),
                    });
                }
                Step::Object(object) => {
                    let whole = whole.as_mut().expect("an object before the root file object");
                    match object {
                        Object::File(object) => whole.objects.push(*object),
                        Object::Signature(signature) => whole.signatures.push(signature),
                    }
                    numbers.push(decoder.record_number());
                }
                Step::End => {
                    let whole = whole.expect("the end before the root file object");
                    return Ok((whole, numbers, decoder.signed_len()));
                }
            }
        }
    }

    /// What the tests compare of an error.
    fn described(e: &Error) -> (ErrorKind, Option<u64>, Option<&str>, Option<Field>, String) {
        (e.kind(), e.record_number(), e.name(), e.field(), e.to_string())
    }

    #[test]
    fn decoding_in_pieces() {
        let long = format!(r#"{{"name":"long","size":0,"pad":"{}"}}"#, "p".repeat(3 * READ_SIZE));
        let signed = sequence(&[
            ROOT,
            " ",
            r#"{"name":"a","size":0}"#,
            &long,
            "\n\n",
            r#"{"mediaType":"application/x-other"}"#,
            r#"{"name":"é","type":"dir"}"#,
        ]);
        let mut bytes = signed.clone();
        bytes.extend(sequence(&[SIGNATURE, SIGNATURE, TRAILER]));
        let (whole, numbers, signed_len) = decode(&bytes, bytes.len()).unwrap();
        assert_eq!(whole, read_whole(&bytes).unwrap());
        assert_eq!((whole.objects.len(), whole.signatures.len()), (3, 2));
        // Records of whitespace do not count, objects that are passed over
        // do.
        assert_eq!(numbers, [1, 2, 4, 5, 6]);
        assert_eq!(signed_len, Some(signed.len() as u64));
        let decoded = (whole, numbers, signed_len);
        for size in PIECES {
            assert_eq!(decode(&bytes, size).unwrap(), decoded, "{} at a time", size);
        }
        // Behind the trailer object there may be whitespace up to the
        // newline that ends its record.
        for behind in [&b" "[..], b"\r", b" \r\n", b"\t\n"] {
            let mut bytes = sequence(&[ROOT, r#"{"name":"a"}"#, TRAILER]);
            bytes.pop();
            bytes.extend(behind);
            let whole = read_whole(&bytes).unwrap();
            for size in PIECES {
                assert_eq!(
                    decode(&bytes, size).unwrap().0,
                    whole,
                    "{:?} {} at a time",
                    behind,
                    size
                );
            }
        }
    }

    /// A record as large as a record can be, with the separator of the
    /// next one right behind it, is taken in any pieces, and the decoder
    /// holds no more than the record.
    #[test]
    fn the_largest_record_in_pieces() {
        // The separator in front of the record and the newline at its end
        // count.
        let frame = "\x1e{\"name\":\"x\",\"size\":0,\"pad\":\"\"}\n";
        let pad = "p".repeat(MAX_RECORD_SIZE - frame.len());
        let largest = format!(r#"{{"name":"x","size":0,"pad":"{}"}}"#, pad);
        assert_eq!(sequence(&[&largest]).len(), MAX_RECORD_SIZE);
        let bytes = manifest(&[&largest]);
        let whole = read_whole(&bytes).unwrap();
        for size in PIECES.into_iter().chain([bytes.len()]) {
            assert_eq!(decode(&bytes, size).unwrap().0, whole, "{} at a time", size);
            let mut decoder = Decoder::new();
            let mut taken = 0;
            loop {
                match decoder.step().unwrap() {
                    Step::Input if taken == bytes.len() => decoder.end(),
                    Step::Input => taken += decoder.feed(&bytes[taken..][..size.min(bytes.len() - taken)]),
                    Step::Object(_) => assert_eq!(decoder.splitter.record.len(), MAX_RECORD_TEXT),
                    Step::Root(_) => {}
                    Step::End => break,
                }
                assert!(
                    decoder.splitter.record.capacity() <= MAX_RECORD_TEXT,
                    "{} at a time",
                    size
                );
            }
        }
    }

    #[test]
    fn failing_in_pieces() {
        let too_large = format!(r#"{{"name":"x","pad":"{}"}}"#, "p".repeat(MAX_RECORD_SIZE));
        let root_too_large = format!(
            r#"{{"mediaType":"application/vnd.uapi.16.manifest","pad":"{}"}}"#,
            "p".repeat(MAX_RECORD_SIZE)
        );
        // More than the read of a record takes before the first separator.
        let mut unseparated = vec![b'x'; READ_LIMIT + READ_SIZE];
        unseparated.extend(manifest(&[]));
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend(manifest(&[]));
        let mut behind = manifest(&[]);
        behind.push(RECORD_SEPARATOR);
        let mut nul = sequence(&[ROOT]);
        nul.extend([RECORD_SEPARATOR, b' ', NUL, b' ']);
        nul.extend(sequence(&[TRAILER]));
        let mut not_utf8 = sequence(&[ROOT]);
        not_utf8.extend([RECORD_SEPARATOR, b'"', 0xff, b'"']);
        not_utf8.extend(sequence(&[TRAILER]));
        let mut junk = sequence(&[ROOT]);
        junk.extend(b"junk");
        junk.extend(sequence(&[TRAILER]));
        let cases = [
            Vec::new(),
            vec![RECORD_SEPARATOR, b'\n', RECORD_SEPARATOR],
            ROOT.as_bytes().to_vec(),
            unseparated,
            bom,
            sequence(&[ROOT]),
            sequence(&[ROOT, r#"{"name":"x"}"#]),
            manifest(&[&too_large]),
            sequence(&[&root_too_large, TRAILER]),
            behind,
            nul,
            not_utf8,
            junk,
            manifest(&[r#"{"name":"b"}"#, r#"{"name":"a"}"#, r#"{"name":"a/x"}"#]),
            manifest(&[r#"{"name":"a"}"#, r#"{"name":"b","size":"x"}"#]),
            manifest(&[r#"{"name":"a","mTimeNSec":5}"#]),
            sequence(&[ROOT, SIGNATURE, r#"{"name":"x"}"#, TRAILER]),
        ];
        for bytes in &cases {
            let expected = read_whole(bytes).unwrap_err();
            let e = decode(bytes, bytes.len().max(1)).unwrap_err();
            assert_eq!(described(&e), described(&expected));
            for size in PIECES {
                let e = decode(bytes, size).unwrap_err();
                assert_eq!(described(&e), described(&expected), "{} at a time", size);
            }
        }
    }

    #[test]
    fn a_record_over_the_limit() {
        // The record after the root file object has more bytes than a
        // record can have: behind them come more bytes, a separator, or
        // the end of the input.
        let mut start = sequence(&[ROOT]);
        start.push(RECORD_SEPARATOR);
        let mut endless = start.clone();
        endless.resize(start.len() + MAX_RECORD_SIZE + 2 * READ_SIZE, b'x');
        let mut separated = start.clone();
        separated.resize(start.len() + READ_LIMIT, b'x');
        separated.extend(sequence(&[TRAILER]));
        let mut ended = start.clone();
        ended.resize(start.len() + READ_LIMIT, b'x');
        for bytes in [&endless, &separated, &ended] {
            for size in PIECES.into_iter().chain([bytes.len()]) {
                let mut decoder = Decoder::new();
                let mut taken = 0;
                let e = loop {
                    match decoder.step() {
                        Ok(Step::Input) if taken == bytes.len() => decoder.end(),
                        Ok(Step::Input) => taken += decoder.feed(&bytes[taken..][..size.min(bytes.len() - taken)]),
                        Ok(Step::Root(_)) => {}
                        Ok(step) => panic!("{} at a time: {:?}", size, step),
                        Err(e) => break e,
                    }
                };
                assert_eq!(
                    (e.kind(), e.record_number()),
                    (ErrorKind::Manifest(Problem::RecordTooLarge), Some(1)),
                    "{} at a time",
                    size
                );
                // The decoder took the record up to the limit and nothing
                // behind it, and takes nothing once it refused it. It holds
                // no more than the largest record, and does not print it.
                assert_eq!(taken, start.len() + READ_LIMIT, "{} at a time", size);
                assert_eq!(decoder.feed(&bytes[taken..]), 0);
                assert_eq!(decoder.step().unwrap(), Step::End);
                assert!(
                    decoder.splitter.record.capacity() <= MAX_RECORD_TEXT,
                    "{} at a time",
                    size
                );
                let debug = format!("{:?}", decoder);
                assert!(debug.len() < READ_SIZE, "{} at a time: {}", size, debug.len());
            }
        }
    }
}
