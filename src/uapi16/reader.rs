// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading a manifest record by record.

use std::io::{self, BufRead, Read};
use std::iter::FusedIterator;
use std::ops::Range;

use crate::decode::{Decoded, Decoder, ROOT_RECORD};
use crate::error::{Error, Problem};
use crate::object::{FileObject, Signature};
use crate::{MAX_RECORD_SIZE, RECORD_SEPARATOR};

/// How much is read from the input at a time.
const READ_SIZE: usize = 64 * 1024;
/// The byte no record may have.
const NUL: u8 = 0;

/// Reads that go on when a signal interrupts them. A bare read() fails
/// with EINTR when a handler that returns is installed, and std retries
/// only in read_exact() and friends.
pub(crate) trait ReadSome: Read {
    /// Reads into `buf` once.
    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                result => return result,
            }
        }
    }
}

impl<R: Read + ?Sized> ReadSome for R {}

/// Splits the input into the records of a JSON text sequence: each one
/// starts with a record separator and goes up to the next one.
#[derive(Debug)]
struct Records<R> {
    input: R,
    /// What was read from the input. The part that is not handed out yet
    /// is `buffer[start..end]`.
    buffer: Vec<u8>,
    start: usize,
    end: usize,
    /// How many bytes of the input came before the ones in the buffer.
    before: u64,
    /// Where in the input the record that was handed out last starts.
    offset: u64,
    /// Up to here the record at `start` was searched for its end.
    searched: usize,
    /// Whether the input is read to its end.
    ended: bool,
    /// Whether a NUL byte was read. No record may have one, and a record
    /// is only searched for one once the input had one.
    nul: bool,
}

impl<R: Read> Records<R> {
    fn new(input: R) -> Records<R> {
        Records {
            input,
            buffer: Vec::new(),
            start: 0,
            end: 0,
            before: 0,
            offset: 0,
            searched: 0,
            ended: false,
            nul: false,
        }
    }

    /// Reads more of the input behind what is not handed out yet.
    fn fill(&mut self) -> io::Result<()> {
        // What was handed out makes room first, once per read and not once
        // per record.
        if self.start > 0 {
            self.buffer.copy_within(self.start..self.end, 0);
            self.before += self.start as u64;
            self.end -= self.start;
            self.searched = self.searched.saturating_sub(self.start);
            self.start = 0;
        }
        if self.buffer.len() - self.end < READ_SIZE {
            self.buffer.resize(self.end + READ_SIZE, 0);
        }
        let read = self.input.read_some(&mut self.buffer[self.end..])?;
        self.nul = self.nul || self.buffer[self.end..self.end + read].contains(&NUL);
        self.end += read;
        self.ended = read == 0;
        Ok(())
    }

    /// Where the first record separator in `bytes` is.
    fn separator(mut bytes: &[u8]) -> Option<usize> {
        let all = bytes;
        // Skipping up to a byte looks at a word at a time, which looking
        // for its position does not. Reading from memory does not fail.
        let skipped = bytes.skip_until(RECORD_SEPARATOR).ok()?;
        let last = skipped.checked_sub(1)?;
        (all[last] == RECORD_SEPARATOR).then_some(last)
    }

    /// Finds the next record that is more than whitespace, and returns
    /// where it is in the buffer, without its separator. None is the end
    /// of the input.
    fn find(&mut self) -> Result<Option<Range<usize>>, Error> {
        loop {
            if self.start == self.end {
                if self.ended {
                    return Ok(None);
                }
                self.fill()?;
                continue;
            }
            let first = self.buffer[self.start];
            if first != RECORD_SEPARATOR {
                return Err(Error::manifest(
                    Problem::RecordSeparator,
                    format!(
                        "manifest record does not start with a record separator but with byte 0x{:02x}",
                        first
                    ),
                ));
            }
            let body = self.start + size_of_val(&RECORD_SEPARATOR);
            let from = body.max(self.searched);
            let end = match Records::<R>::separator(&self.buffer[from..self.end]) {
                Some(at) => from + at,
                None if self.ended => self.end,
                None => {
                    if self.end - body > MAX_RECORD_SIZE {
                        return Err(Records::<R>::too_large());
                    }
                    self.searched = self.end;
                    self.fill()?;
                    continue;
                }
            };
            let record = &self.buffer[body..end];
            if record.len() > MAX_RECORD_SIZE {
                return Err(Records::<R>::too_large());
            }
            if self.nul && record.contains(&NUL) {
                return Err(Error::manifest(
                    Problem::NulByte,
                    "manifest record contains a NUL byte".into(),
                ));
            }
            let empty = record.iter().all(u8::is_ascii_whitespace);
            self.offset = self.before + self.start as u64;
            self.start = end;
            self.searched = end;
            // Empty records are skipped, as RFC 7464 suggests. Only ASCII
            // whitespace counts as empty.
            if empty {
                continue;
            }
            return Ok(Some(body..end));
        }
    }

    fn too_large() -> Error {
        Error::manifest(
            Problem::RecordTooLarge,
            format!("manifest record exceeds {} bytes", MAX_RECORD_SIZE),
        )
    }

    /// The text of the next record that is more than whitespace. None is
    /// the end of the input.
    fn next(&mut self) -> Result<Option<&str>, Error> {
        let Some(record) = self.find()? else {
            return Ok(None);
        };
        match std::str::from_utf8(&self.buffer[record]) {
            Ok(text) => Ok(Some(text)),
            Err(_) => Err(Error::manifest(Problem::NotUtf8, "manifest record is not UTF-8".into())),
        }
    }
}

/// An object of a manifest after its root file object, as a [`Reader`]
/// returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Record {
    /// A file object.
    File(Box<FileObject>),
    /// A signature object. It comes after the last file object.
    Signature(Signature),
}

/// How far a reader has got in the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// File objects come.
    Files,
    /// A signature object was read. File objects cannot follow.
    Signatures,
    /// The trailer object was read. Nothing can follow.
    Trailer,
    /// The manifest is read to its end, or reading it failed.
    Done,
}

/// Reads a manifest record by record.
///
/// [`Reader::open`] reads the root file object, the first object of
/// every manifest. The reader is then an iterator over the file objects
/// and the signature objects that follow. It ends after the trailer
/// object. Objects of a media type the specification does not have are
/// passed over, as it asks.
///
/// The reader keeps one record in memory. It checks every object against
/// the rules of the specification, and the order of the objects: file
/// objects, then signature objects, then the trailer, and nothing behind
/// it. It does not check that no two file objects have the same name,
/// which takes all the names. [`Manifest::read`](crate::Manifest::read)
/// does. Once it returned an error it returns nothing more.
///
/// A manifest comes from outside and may be anything. No record is larger
/// than [`MAX_RECORD_SIZE`], and reading takes time in proportion to the
/// size of the input.
///
/// ```
/// use uapi16::{Reader, Record};
///
/// let manifest = concat!(
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
///     "\x1e{\"name\":\"a\",\"size\":3}\n",
///     "\x1e{\"name\":\"b\",\"type\":\"dir\"}\n",
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
/// );
/// let mut names = Vec::new();
/// for record in Reader::open(manifest.as_bytes())? {
///     if let Record::File(object) = record? {
///         names.push(object.name);
///     }
/// }
/// assert_eq!(names, ["a", "b"]);
/// # Ok::<(), uapi16::Error>(())
/// ```
#[derive(Debug)]
pub struct Reader<R> {
    records: Records<R>,
    root: FileObject,
    /// The number of the next record.
    next: u64,
    /// The number of the record the last object came from.
    last: u64,
    stage: Stage,
    /// Where in the input the first signature object starts.
    signed: Option<u64>,
}

impl<R: Read> Reader<R> {
    /// Starts to read a manifest from `input`, with its root file object.
    pub fn open(input: R) -> Result<Reader<R>, Error> {
        let mut records = Records::new(input);
        let Some(text) = records.next().map_err(|e| e.in_record(ROOT_RECORD))? else {
            return Err(Error::manifest(Problem::Empty, "manifest contains no objects".into()));
        };
        let root = Decoder::root(text)?;
        Ok(Reader {
            records,
            root,
            next: ROOT_RECORD + 1,
            last: ROOT_RECORD,
            stage: Stage::Files,
            signed: None,
        })
    }

    /// The root file object of the manifest.
    pub fn root(&self) -> &FileObject {
        &self.root
    }

    /// The number of the record the object returned last came from. The
    /// record of the root file object is number 0. Records that are empty
    /// do not count.
    pub fn record(&self) -> u64 {
        self.last
    }

    /// How many bytes at the start of the manifest its signature objects
    /// sign: all that comes before the record of the first of them, up to
    /// its record separator. None as long as no signature object was read.
    ///
    /// This crate does not verify signatures. With this number and the
    /// [`Signature`] objects a caller can.
    pub fn signed_len(&self) -> Option<u64> {
        self.signed
    }

    /// Reads on to the next file or signature object. None is the end of
    /// a complete manifest.
    fn advance(&mut self) -> Result<Option<Record>, Error> {
        loop {
            let number = self.next;
            let Some(text) = self.records.next().map_err(|e| e.in_record(number))? else {
                if self.stage != Stage::Trailer {
                    return Err(Error::manifest(
                        Problem::NoTrailer,
                        "manifest lacks the trailer object, it is incomplete".into(),
                    ));
                }
                return Ok(None);
            };
            if self.stage == Stage::Trailer {
                return Err(Error::manifest(
                    Problem::DataAfterTrailer,
                    "manifest contains data after the trailer object".into(),
                )
                .in_record(number));
            }
            let decoded = Decoder::record(text, number)?;
            self.next += 1;
            match decoded {
                Decoded::Trailer => self.stage = Stage::Trailer,
                Decoded::Other => {}
                Decoded::Signature(signature) => {
                    self.stage = Stage::Signatures;
                    self.signed.get_or_insert(self.records.offset);
                    self.last = number;
                    return Ok(Some(Record::Signature(signature)));
                }
                Decoded::File(object) => {
                    // A file object behind a signature is one the signature
                    // does not cover.
                    if self.stage == Stage::Signatures {
                        return Err(Error::manifest(
                            Problem::FileAfterSignature,
                            "manifest contains a file object after a signature object".into(),
                        )
                        .in_record(number));
                    }
                    self.last = number;
                    return Ok(Some(Record::File(object?)));
                }
            }
        }
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Result<Record, Error>> {
        if self.stage == Stage::Done {
            return None;
        }
        let record = self.advance().transpose();
        if !matches!(record, Some(Ok(_))) {
            self.stage = Stage::Done;
        }
        record
    }
}

impl<R: Read> FusedIterator for Reader<R> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;
    use crate::testing::{manifest, sequence, ROOT, SIGNATURE, TRAILER};
    use crate::{Manifest, Name};

    /// Reads `bytes` to the end and returns the names of the file objects
    /// and the number of signature objects.
    fn read(bytes: &[u8]) -> Result<(Vec<String>, usize), Error> {
        let mut names = Vec::new();
        let mut signatures = 0;
        for record in Reader::open(bytes)? {
            match record? {
                Record::File(object) => names.push(object.name.to_string()),
                Record::Signature(_) => signatures += 1,
            }
        }
        Ok((names, signatures))
    }

    /// The problem with `bytes` and the record it is in.
    fn problem(bytes: &[u8]) -> (Problem, Option<u64>) {
        let e = read(bytes).expect_err("the manifest was taken");
        match e.kind() {
            ErrorKind::Manifest(problem) => (problem, e.record()),
            other => panic!("{:?}: {}", other, e),
        }
    }

    #[test]
    fn records() {
        let files = [r#"{"name":"a","size":0}"#, r#"{"name":"b","type":"dir"}"#];
        let plain = manifest(&files);
        assert_eq!(read(&plain).unwrap(), (vec!["a".to_string(), "b".to_string()], 0));
        // Records of nothing but ASCII whitespace are passed over, wherever
        // they are. A newline at the end of a record is not needed.
        let mut spaced = vec![RECORD_SEPARATOR, RECORD_SEPARATOR, b' ', RECORD_SEPARATOR, b'\n', b'\t'];
        spaced.extend(sequence(&[ROOT]));
        spaced.extend([RECORD_SEPARATOR, b'\r', b'\n', RECORD_SEPARATOR, 0x0c]);
        spaced.extend(sequence(&files));
        spaced.push(RECORD_SEPARATOR);
        spaced.extend(TRAILER.as_bytes());
        spaced.extend([RECORD_SEPARATOR, b' ', RECORD_SEPARATOR]);
        assert_eq!(read(&spaced).unwrap(), read(&plain).unwrap());
        let crlf: Vec<u8> = String::from_utf8(plain.clone())
            .unwrap()
            .replace('\n', "\r\n")
            .into_bytes();
        assert_eq!(read(&crlf).unwrap(), read(&plain).unwrap());
        // Whitespace that is not ASCII is not nothing, and neither is a
        // vertical tab.
        for odd in ["\u{2028}", "\u{a0}", "\u{b}"] {
            let mut bytes = sequence(&[ROOT]);
            bytes.push(RECORD_SEPARATOR);
            bytes.extend(odd.as_bytes());
            bytes.extend(sequence(&[TRAILER]));
            assert_eq!(problem(&bytes), (Problem::NotJson, Some(1)), "{:?}", odd);
        }
    }

    #[test]
    fn what_is_no_sequence_of_records() {
        assert_eq!(problem(b""), (Problem::Empty, None));
        assert_eq!(
            problem(&[RECORD_SEPARATOR, b'\n', RECORD_SEPARATOR]),
            (Problem::Empty, None)
        );
        // Every record starts with a record separator.
        assert_eq!(problem(ROOT.as_bytes()), (Problem::RecordSeparator, Some(0)));
        assert_eq!(problem(b"garbage"), (Problem::RecordSeparator, Some(0)));
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
        // A NUL byte and bytes that are not UTF-8, behind the trailer too.
        for (bad, expected) in [(&b"\0"[..], Problem::NulByte), (&b"\xff"[..], Problem::NotUtf8)] {
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
            assert_eq!(problem(&bytes), (expected, Some(2)));
        }
        let mut bytes = sequence(&[ROOT]);
        bytes.extend([RECORD_SEPARATOR, b' ', 0, b' ']);
        bytes.extend(sequence(&[TRAILER]));
        assert_eq!(problem(&bytes), (Problem::NulByte, Some(1)));
    }

    #[test]
    fn the_largest_record() {
        // A record is its bytes between two separators, the newline at its
        // end included.
        let record = |len: usize| {
            let frame = r#"{"name":"x","size":0,"pad":""}"#;
            let pad = "p".repeat(len - frame.len());
            format!(r#"{{"name":"x","size":0,"pad":"{}"}}"#, pad)
        };
        let fits = record(MAX_RECORD_SIZE - 1);
        assert_eq!(read(&manifest(&[&fits])).unwrap().0, ["x"]);
        let too_large = record(MAX_RECORD_SIZE);
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
        bytes.resize(bytes.len() + MAX_RECORD_SIZE + 1, 0);
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
            (Problem::MediaType, Some(2))
        );
        // The first object is the root file object, and says so with its
        // media type.
        for first in [file, TRAILER, SIGNATURE, other, r#"{"type":"dir"}"#] {
            let e = read(&sequence(&[first, TRAILER])).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::MediaType), "{}", first);
            assert_eq!(e.record(), Some(0));
            assert_eq!(
                e.to_string(),
                "the first object of the manifest is not of the manifest media type"
            );
        }
    }

    #[test]
    fn the_reader_as_an_iterator() {
        let bytes = sequence(&[
            ROOT,
            " ",
            r#"{"name":"a","size":0}"#,
            "\n\n",
            r#"{"mediaType":"application/x-other"}"#,
            r#"{"name":"b","type":"dir"}"#,
            SIGNATURE,
            TRAILER,
        ]);
        let mut reader = Reader::open(&bytes[..]).unwrap();
        assert!(reader.root().name.is_root());
        assert_eq!(reader.record(), 0);
        // Records of whitespace do not count, objects that are passed over
        // do.
        assert!(matches!(reader.next(), Some(Ok(Record::File(object))) if object.name == "a"));
        assert_eq!(reader.record(), 1);
        assert!(matches!(reader.next(), Some(Ok(Record::File(object))) if object.name == "b"));
        assert_eq!(reader.record(), 3);
        assert_eq!(reader.signed_len(), None);
        assert!(matches!(reader.next(), Some(Ok(Record::Signature(signature))) if signature.mechanism == "pkcs7"));
        assert_eq!(reader.record(), 4);
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
        assert_eq!(reader.record(), 4);
        // What is signed ends in front of the first signature object.
        let signed = sequence(&[
            ROOT,
            " ",
            r#"{"name":"a","size":0}"#,
            "\n\n",
            r#"{"mediaType":"application/x-other"}"#,
            r#"{"name":"b","type":"dir"}"#,
        ]);
        assert_eq!(reader.signed_len(), Some(signed.len() as u64));
        assert_eq!(
            &bytes[signed.len()..][..1 + SIGNATURE.len()],
            [&[RECORD_SEPARATOR][..], SIGNATURE.as_bytes()].concat()
        );
        // After an error there is nothing more.
        let bytes = manifest(&[r#"{"name":"a"}"#, r#"{"name":"b","size":"x"}"#, r#"{"name":"c"}"#]);
        let mut reader = Reader::open(&bytes[..]).unwrap();
        assert!(matches!(reader.next(), Some(Ok(_))));
        let e = reader.next().unwrap().unwrap_err();
        assert_eq!((e.record(), e.name()), (Some(2), Some("b")));
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    /// Hands out the bytes of a manifest a few at a time, and says now
    /// and then that a signal interrupted the read.
    #[derive(Debug)]
    struct Trickle<'a> {
        bytes: &'a [u8],
        step: usize,
        calls: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls % 3 == 0 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let n = self.step.min(buf.len()).min(self.bytes.len());
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    #[test]
    fn input_in_pieces() {
        let long = format!(r#"{{"name":"long","size":0,"pad":"{}"}}"#, "p".repeat(3 * READ_SIZE));
        let bytes = manifest(&[r#"{"name":"a","size":0}"#, &long, r#"{"name":"é","type":"dir"}"#]);
        let whole = Manifest::parse(&bytes).unwrap();
        assert_eq!(whole.objects.len(), 3);
        assert_eq!(whole.objects[2].name, Name::new("\u{e9}").unwrap());
        // The pieces end anywhere: inside a record, inside a character,
        // right in front of a separator.
        for step in [1, 2, 3, 7, 4096, READ_SIZE - 1, READ_SIZE, READ_SIZE + 1] {
            let trickle = Trickle {
                bytes: &bytes,
                step,
                calls: 0,
            };
            assert_eq!(Manifest::read(trickle).unwrap(), whole, "{} at a time", step);
        }
        // A NUL byte spoils the record it is in and none before it, and
        // where the signed part ends does not depend on the pieces.
        let mut bytes = sequence(&[ROOT, r#"{"name":"a"}"#, &long, r#"{"name":"b"}"#, SIGNATURE, SIGNATURE]);
        let signed = bytes.len() - 2 * (SIGNATURE.len() + 2);
        bytes.push(RECORD_SEPARATOR);
        bytes.extend(b"{\"mediaType\":\"application/x-other\0\"}\n");
        bytes.extend(sequence(&[TRAILER]));
        for step in [1, 7, READ_SIZE, 5 * READ_SIZE] {
            let mut reader = Reader::open(Trickle {
                bytes: &bytes,
                step,
                calls: 0,
            })
            .unwrap();
            for name in ["a", "long", "b"] {
                assert!(matches!(reader.next(), Some(Ok(Record::File(object))) if object.name == name));
            }
            assert_eq!(reader.signed_len(), None);
            for _ in 0..2 {
                assert!(matches!(reader.next(), Some(Ok(Record::Signature(_)))));
                assert_eq!(reader.signed_len(), Some(signed as u64), "{} at a time", step);
            }
            let e = reader.next().unwrap().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NulByte));
            assert_eq!(e.record(), Some(6));
            assert!(reader.next().is_none());
        }
    }

    #[test]
    fn finds_the_separator() {
        // Wherever it is, and the first one of several.
        for len in 0..5 * size_of::<usize>() {
            let mut bytes = vec![b'x'; len];
            assert_eq!(Records::<&[u8]>::separator(&bytes), None);
            for first in (0..len).rev() {
                bytes[first] = RECORD_SEPARATOR;
                assert_eq!(Records::<&[u8]>::separator(&bytes), Some(first), "{} of {}", first, len);
            }
        }
    }

    /// Fails every read.
    #[derive(Debug)]
    struct Broken;

    impl Read for Broken {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    #[test]
    fn a_read_that_fails() {
        let e = Reader::open(Broken).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EIO));
        // Later on too. A record ends where the next one starts, so the
        // first one is read whole when the second one begins.
        let bytes = sequence(&[ROOT, r#"{"name":"a"}"#]);
        let mut reader = Reader::open(bytes.chain(Broken)).unwrap();
        let e = reader.next().unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert!(reader.next().is_none());
    }
}
