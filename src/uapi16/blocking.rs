// SPDX-License-Identifier: LGPL-2.1-or-later
//! Reading a manifest from a [`Read`] and writing one to a [`Write`]: a
//! [`Reader`] feeds a [`Decoder`], and a [`Writer`] writes out what an
//! [`Encoder`] puts together.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::iter::FusedIterator;

use crate::decode::ROOT_RECORD;
use crate::error::Error;
use crate::object::{FileObject, RootObject, Signature};
use crate::reader::{Decoder, Object, Step};
use crate::writer::Encoder;

/// How much is read from the input at a time.
pub(crate) const READ_SIZE: usize = 64 * 1024;
/// The most room for the text of a record that a [`Writer`] keeps from one
/// record to the next. A larger record takes more, and gives it back once
/// it went out.
const TEXT_CAPACITY: usize = 64 * 1024;

/// Reads a manifest record by record.
///
/// [`Reader::open`] reads the root file object, the first object of
/// every manifest. The reader is then an iterator over the file objects
/// and the signature objects that follow. It ends after the trailer
/// object. Objects of a media type the specification does not have are
/// passed over, as it asks.
///
/// The reader keeps one record and the name of the last file object in
/// memory. It checks every object against the rules of the specification,
/// and the order of the objects: the file objects in tree order, each
/// right after the object of its directory, then signature objects, then
/// the trailer, and nothing behind it. A file object has no field of a
/// feature the manifest does not record, and the reader fills in what the
/// features say about the fields it does not have, see
/// [`Features`](crate::Features): a
/// flag the manifest records is cleared, a file is not read-only and has
/// no extended attributes. It leaves the `gpt` fields as they are, see
/// [`GptPartition`](crate::GptPartition).
///
/// A name that comes again right after the entries of the directory it
/// names is an error, a name that comes again later only if the manifest
/// declares an order in `order`. Then every name has to come after the one
/// before it, and none can come twice. A consumer that relies on the order
/// requires the manifest to declare it with
/// [`RootObject::require_order`].
///
/// Once the reader returned an error it returns nothing more. An error of
/// the kind [`WouldBlock`](io::ErrorKind::WouldBlock) from the input is
/// the exception: the reader lost nothing, and reads on when it is asked
/// again.
///
/// A manifest comes from outside and may be anything. No record is larger
/// than [`MAX_RECORD_SIZE`] with its record separator, and reading takes
/// time in proportion to the size of the input.
///
/// ```
/// use uapi16::{Object, Reader};
///
/// let manifest = concat!(
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
///     "\x1e{\"name\":\"a\",\"size\":3}\n",
///     "\x1e{\"name\":\"b\",\"type\":\"dir\"}\n",
///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
/// );
/// let mut names = Vec::new();
/// for object in Reader::open(manifest.as_bytes())? {
///     if let Object::File(object) = object? {
///         names.push(object.name);
///     }
/// }
/// assert_eq!(names, ["a", "b"]);
/// # Ok::<(), uapi16::Error>(())
/// ```
///
/// [`MAX_RECORD_SIZE`]: crate::MAX_RECORD_SIZE
#[derive(Debug)]
pub struct Reader<R> {
    input: BufReader<R>,
    decoder: Decoder,
    root: RootObject,
    /// Whether an error ended the reading.
    failed: bool,
}

impl<R: Read> Reader<R> {
    /// Starts to read a manifest from `input`, with its root file object.
    /// An error of the input fails it, one of the kind
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) as well. The input is
    /// dropped then, with what was read of it.
    pub fn open(input: R) -> Result<Reader<R>, Error> {
        let mut reader = Reader {
            input: BufReader::with_capacity(READ_SIZE, input),
            decoder: Decoder::new(),
            root: RootObject::default(),
            failed: false,
        };
        let Step::Root(root) = reader.pull()? else {
            unreachable!("a decoder hands out the root file object first");
        };
        reader.root = *root;
        Ok(reader)
    }

    /// The root file object of the manifest.
    pub fn root(&self) -> &RootObject {
        &self.root
    }

    /// What the manifest is read from. The reader reads ahead of the
    /// objects it returned. It has read the input to its end once it
    /// returned None after the last of them, which it does when it read
    /// the trailer object.
    pub fn get_ref(&self) -> &R {
        self.input.get_ref()
    }

    /// What the manifest is read from, to change it. Reading from it
    /// directly takes bytes away from the reader, which reads ahead of the
    /// objects it returned.
    pub fn get_mut(&mut self) -> &mut R {
        self.input.get_mut()
    }

    /// The number of the record the object returned last came from. The
    /// record of the root file object is number 0. Records that are empty
    /// do not count.
    pub fn record_number(&self) -> u64 {
        self.decoder.record_number()
    }

    /// How many bytes at the start of the manifest its signature objects
    /// sign: all that comes before the record of the first of them, up to
    /// its record separator. None as long as no signature object was read.
    ///
    /// This crate does not verify signatures. With this number and the
    /// [`Signature`] objects a caller can.
    pub fn signed_len(&self) -> Option<u64> {
        self.decoder.signed_len()
    }

    /// Feeds the decoder until it takes a step other than [`Step::Input`].
    fn pull(&mut self) -> Result<Step, Error> {
        loop {
            match self.decoder.step()? {
                Step::Input => self.fill()?,
                step => return Ok(step),
            }
        }
    }

    /// Feeds the decoder what the input has next, or tells it that the
    /// input ended. An error of the input is one about the record being
    /// read.
    fn fill(&mut self) -> Result<(), Error> {
        let input = loop {
            match self.input.fill_buf() {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                result => break result,
            }
        };
        let input = input.map_err(|e| self.decoder.input_error(e))?;
        if input.is_empty() {
            self.decoder.end();
        } else {
            let taken = self.decoder.feed(input);
            self.input.consume(taken);
        }
        Ok(())
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Object, Error>;

    fn next(&mut self) -> Option<Result<Object, Error>> {
        if self.failed {
            return None;
        }
        match self.pull() {
            Ok(Step::Object(object)) => Some(Ok(object)),
            Ok(Step::End) => None,
            // pull() feeds the decoder what it asks for, and the root file
            // object came when the reader was opened.
            Ok(Step::Input | Step::Root(_)) => unreachable!("a decoder hands out the root file object once"),
            Err(e) => {
                // An input that has nothing right now gave the decoder
                // nothing, and it reads on from where it was.
                self.failed = e.io_error().map(io::Error::kind) != Some(io::ErrorKind::WouldBlock);
                Some(Err(e))
            }
        }
    }
}

impl<R: Read> FusedIterator for Reader<R> {}

/// Writes a manifest record by record.
///
/// [`Writer::begin`] writes the root file object, [`Writer::file`] the
/// file objects, [`Writer::signature`] the signature objects after them
/// and [`Writer::finish`] the trailer object. A manifest without its
/// trailer is one a reader takes as incomplete, so a writer that is
/// dropped before it finished leaves nothing that passes for a manifest.
///
/// Every object is one record of the JSON text sequence: a record
/// separator, the object with its keys sorted and without whitespace, and
/// a newline, the way `systemd-manifest` writes it. A field that says
/// nothing is left out. So is the inode type where the specification
/// implies it, on the root file object and on regular files. An
/// [`Encoder`] puts each record together, and it goes out in one write, so
/// a file wants a `BufWriter` around it.
///
/// The root file object says what the manifest records in `features` and
/// which order it lists its file objects in in `order`. The writer checks
/// every object against them as a [`Reader`] does: an object
/// has no fields of features the manifest does not record, it comes right
/// after the object of its directory, and it keeps to the order. It checks
/// what an object is itself as a reader does too: the fields its inode
/// type permits, the value of every field and every string it writes, and
/// the fields against each other. An object with more than one fault is
/// refused for the one a reader finds first. The one fault a reader does
/// not find is an encoding that is not in lower case: a reader lowers its
/// case, and the writer refuses it. No record is larger than
/// [`MAX_RECORD_SIZE`], its record separator included, and no file object
/// has more than [`MAX_CONTENTS`] contents objects. An object the writer
/// refuses is not written, and the writer goes on as if it had not been
/// given it.
///
/// The writer leaves out what the manifest says without it: where the
/// manifest records them, a flag that is cleared, `readOnly` of false,
/// `gptFlags` of 0 and extended attributes there are none of, and
/// `features` if they are the default ones. It leaves out the hash of no
/// data next to the size 0, as the specification recommends. Without an
/// encoding the specification says that the encoded size and hash should
/// not be there. The writer leaves them out next to the original ones, and
/// writes one that is the only statement of the size or the hash: written
/// as the original size or hash it would come back as another field, and
/// left out it would be lost. The writer also leaves out every field a
/// [`Reader`] filled in, see [`FilledIn`]. So what a reader
/// returns can be written back with the root file object it read. A record
/// close to [`MAX_RECORD_SIZE`] can grow past it on the way back, as the
/// writer writes some values in another form than a manifest may have them
/// in: a UUID with its hyphens, and the value of an extended attribute as
/// text where it can. The writer refuses such a record.
///
/// ```
/// use uapi16::{FileObject, Name, Object, Order, Reader, RootObject, Writer};
///
/// let mut root = RootObject::default();
/// root.order = Some(Order::CodePoint);
/// let mut file = FileObject::new(Name::new("a")?);
/// file.size = Some(3);
/// let mut writer = Writer::begin(Vec::new(), &root)?;
/// writer.file(&file)?;
/// let bytes = writer.finish()?;
/// assert_eq!(
///     String::from_utf8_lossy(&bytes),
///     concat!(
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
///         "\x1e{\"name\":\"a\",\"size\":3}\n",
///         "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
///     )
/// );
/// let mut reader = Reader::open(&bytes[..])?;
/// assert!(matches!(reader.next(), Some(Ok(Object::File(object))) if *object == file));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// [`FilledIn`]: crate::FilledIn
/// [`MAX_CONTENTS`]: crate::MAX_CONTENTS
/// [`MAX_RECORD_SIZE`]: crate::MAX_RECORD_SIZE
#[derive(Debug)]
pub struct Writer<W> {
    out: W,
    /// The text of the record that goes out next. The room for it is kept
    /// from one record to the next.
    text: String,
    encoder: Encoder,
}

impl<W: Write> Writer<W> {
    /// Starts a manifest in `out` with the root file object `root`.
    pub fn begin(out: W, root: &RootObject) -> Result<Writer<W>, Error> {
        let mut text = String::new();
        let encoder = Encoder::begin(root, &mut text)?;
        let mut writer = Writer { out, text, encoder };
        writer.write_out(ROOT_RECORD)?;
        Ok(writer)
    }

    /// Writes the file object `file`.
    pub fn file(&mut self, file: &FileObject) -> Result<(), Error> {
        self.send_record(|encoder, text| encoder.file(file, text))
    }

    /// Writes a signature object. No file object can follow it: it would
    /// be one the signature does not cover.
    pub fn signature(&mut self, signature: &Signature) -> Result<(), Error> {
        self.send_record(|encoder, text| encoder.signature(signature, text))
    }

    /// Ends the manifest with the trailer object, flushes what it was
    /// written to and returns it.
    pub fn finish(mut self) -> Result<W, Error> {
        let record_number = self.encoder.next_record;
        self.send_record(|encoder, text| encoder.finish(text))?;
        self.out.flush().map_err(|e| Error::from(e).in_record(record_number))?;
        Ok(self.out)
    }

    /// What the manifest is written to. Every method writes its record to
    /// it before it returns, so it has the manifest up to the last record.
    /// Before the first signature object, that is what the signature
    /// objects sign.
    pub fn get_ref(&self) -> &W {
        &self.out
    }

    /// Writes out the record that `encode` has the encoder append to the
    /// text. When the encoder took it back as too large, the text gives
    /// back the room it took.
    fn send_record(
        &mut self,
        encode: impl FnOnce(&mut Encoder, &mut String) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let record_number = self.encoder.next_record;
        match encode(&mut self.encoder, &mut self.text) {
            Ok(()) => self.write_out(record_number),
            Err(e) => {
                self.text.shrink_to(TEXT_CAPACITY);
                Err(e)
            }
        }
    }

    /// Writes out the text, the record with the number `record_number`, in
    /// one write, and empties it for the next record. A record larger than
    /// [`TEXT_CAPACITY`] gives back the room it took beyond that.
    fn write_out(&mut self, record_number: u64) -> Result<(), Error> {
        let written = self.out.write_all(self.text.as_bytes());
        self.text.clear();
        self.text.shrink_to(TEXT_CAPACITY);
        written.map_err(|e| Error::from(e).in_record(record_number))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorKind, Problem};
    use crate::testing::{
        directory, everything, manifest, name, read_whole, read_whole_from, record, recording_all, sequence,
        write_whole, Whole, EMPTY, PIECES, ROOT, SIGNATURE, TRAILER,
    };
    use crate::{InodeType, Name, Sha256, MAX_RECORD_SIZE, RECORD_SEPARATOR};
    use std::collections::BTreeMap;

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
        assert_eq!(reader.root(), &RootObject::default());
        assert_eq!(reader.record_number(), 0);
        // Records of whitespace do not count, objects that are passed over
        // do.
        assert!(matches!(reader.next(), Some(Ok(Object::File(object))) if object.name == "a"));
        assert_eq!(reader.record_number(), 1);
        assert!(matches!(reader.next(), Some(Ok(Object::File(object))) if object.name == "b"));
        assert_eq!(reader.record_number(), 3);
        assert_eq!(reader.signed_len(), None);
        assert!(matches!(reader.next(), Some(Ok(Object::Signature(signature))) if signature.mechanism == "pkcs7"));
        assert_eq!(reader.record_number(), 4);
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
        assert_eq!(reader.record_number(), 4);
        // The input is read to its end once None was returned.
        assert!(reader.get_ref().is_empty());
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
        assert_eq!((e.record_number(), e.name()), (Some(2), Some("b")));
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
        let whole = read_whole(&bytes).unwrap();
        assert_eq!(whole.objects.len(), 3);
        assert_eq!(whole.objects[2].name, Name::new("\u{e9}").unwrap());
        // The pieces end anywhere: inside a record, inside a character,
        // right in front of a separator.
        for step in PIECES {
            let trickle = Trickle {
                bytes: &bytes,
                step,
                calls: 0,
            };
            assert_eq!(read_whole_from(trickle).unwrap(), whole, "{} at a time", step);
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
                assert!(matches!(reader.next(), Some(Ok(Object::File(object))) if object.name == name));
            }
            assert_eq!(reader.signed_len(), None);
            for _ in 0..2 {
                assert!(matches!(reader.next(), Some(Ok(Object::Signature(_)))));
                assert_eq!(reader.signed_len(), Some(signed as u64), "{} at a time", step);
            }
            let e = reader.next().unwrap().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::ContainsNulByte));
            assert_eq!(e.record_number(), Some(6));
            assert!(reader.next().is_none());
        }
    }

    /// Fails every read.
    #[derive(Debug)]
    struct FaultyInput;

    impl Read for FaultyInput {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from_raw_os_error(libc::EIO))
        }
    }

    #[test]
    fn a_read_that_fails() {
        let e = Reader::open(FaultyInput).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EIO));
        // Later on too. A record ends where the next one starts, so the
        // first one is read whole when the second one begins.
        let bytes = sequence(&[ROOT, r#"{"name":"a"}"#]);
        let mut reader = Reader::open(bytes.chain(FaultyInput)).unwrap();
        let e = reader.next().unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Io);
        assert!(reader.next().is_none());
    }

    /// Hands out the bytes of a manifest `step` at a time. With `blocking`
    /// it says before every piece that it has nothing yet, as a pipe that
    /// does not block does while its writer is slow.
    #[derive(Debug)]
    struct Hiccups<'a> {
        bytes: &'a [u8],
        step: usize,
        blocking: bool,
        /// Whether it said so before the next piece.
        said: bool,
    }

    impl Read for Hiccups<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.blocking && !self.said {
                self.said = true;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.said = false;
            let n = self.step.min(buf.len()).min(self.bytes.len());
            buf[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }

    #[test]
    fn reading_on_after_would_block() {
        let long = format!(r#"{{"name":"long","size":0,"pad":"{}"}}"#, "p".repeat(3 * READ_SIZE));
        let bytes = sequence(&[
            ROOT,
            r#"{"name":"a","size":0}"#,
            &long,
            r#"{"name":"é","type":"dir"}"#,
            SIGNATURE,
            TRAILER,
        ]);
        let whole = read_whole(&bytes).unwrap();
        // The number of the record of every object, and how much is signed
        // after it, as a reader says that never sees a WouldBlock.
        let mut unblocked = Vec::new();
        let mut reader = Reader::open(&bytes[..]).unwrap();
        while let Some(object) = reader.next() {
            object.unwrap();
            unblocked.push((reader.record_number(), reader.signed_len()));
        }
        let would_block = |e: &Error| e.io_error().map(io::Error::kind) == Some(io::ErrorKind::WouldBlock);
        for step in [1, 7, 4096, READ_SIZE + 1] {
            let hiccups = Hiccups {
                bytes: &bytes,
                step,
                blocking: false,
                said: false,
            };
            let mut reader = Reader::open(hiccups).unwrap();
            // From here on the input has nothing every other time it is
            // read, in the middle of records as well.
            reader.get_mut().blocking = true;
            let mut read = Whole {
                root: reader.root().clone(),
                objects: Vec::new(),
                signatures: Vec::new(),
            };
            let mut blocked = 0;
            let mut numbers = Vec::new();
            let mut last = (reader.record_number(), reader.signed_len());
            while let Some(object) = reader.next() {
                let now = (reader.record_number(), reader.signed_len());
                match object {
                    Ok(Object::File(object)) => read.objects.push(*object),
                    Ok(Object::Signature(signature)) => read.signatures.push(signature),
                    // The error is about the record being read, and the
                    // reader says what it said before it.
                    Err(e) if would_block(&e) => {
                        assert_eq!(e.record_number(), Some(last.0 + 1), "{} at a time", step);
                        assert_eq!(now, last, "{} at a time", step);
                        blocked += 1;
                        continue;
                    }
                    Err(e) => panic!("{} at a time: {}", step, e),
                }
                numbers.push(now);
                last = now;
            }
            assert_eq!(read, whole, "{} at a time", step);
            assert_eq!(numbers, unblocked, "{} at a time", step);
            assert!(blocked > 0, "{} at a time", step);
            assert!(reader.next().is_none());
        }
        // Reader::open() has no reader to go on with.
        let hiccups = Hiccups {
            bytes: &bytes,
            step: 7,
            blocking: true,
            said: false,
        };
        assert!(would_block(&Reader::open(hiccups).unwrap_err()));
    }

    /// No record is larger than MAX_RECORD_SIZE, its record separator
    /// included, which is how a reader counts it too. A larger one is not
    /// written, and the writer goes on.
    #[test]
    fn the_largest_record() {
        // An object whose record is as large as one with the name `name_of`
        // and an extended attribute, plus `pad` bytes.
        let padded = |name_of: &str, pad: usize| {
            let mut object = FileObject::new(name(name_of));
            object.inode.user_xattrs = Some(Box::new(BTreeMap::from([("p".to_string(), vec![b'x'; pad])])));
            object
        };
        // The separator and the newline are not in what record() returns.
        let frame = record(&padded("a", 0)).len() + 2;
        let (root, _) = recording_all();
        let mut writer = Writer::begin(Vec::new(), &root).unwrap();
        let before = writer.get_ref().len();
        let e = writer.file(&padded("a", MAX_RECORD_SIZE - frame + 1)).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number(), e.name()),
            (ErrorKind::Manifest(Problem::RecordTooLarge), Some(1), Some("a"))
        );
        assert_eq!(
            e.to_string(),
            format!("manifest record exceeds {} bytes", MAX_RECORD_SIZE)
        );
        assert_eq!(writer.get_ref().len(), before);
        assert!(writer.text.capacity() <= TEXT_CAPACITY);
        // A directory that is not written is not the directory of what
        // comes next.
        let mut large = padded("d", MAX_RECORD_SIZE);
        large.inode_type = InodeType::Directory;
        let e = writer.file(&large).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::RecordTooLarge));
        let e = writer.file(&FileObject::new(name("d/x"))).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::Misplaced));
        // The largest one, which a reader takes.
        let largest = padded("a", MAX_RECORD_SIZE - frame);
        writer.file(&largest).unwrap();
        assert_eq!(writer.get_ref().len() - before, MAX_RECORD_SIZE);
        assert!(writer.text.capacity() <= TEXT_CAPACITY);
        let mut signature = Signature::new("pkcs7");
        signature.data = Some(vec![0; MAX_RECORD_SIZE]);
        let e = writer.signature(&signature).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number()),
            (ErrorKind::Manifest(Problem::RecordTooLarge), Some(2))
        );
        let bytes = writer.finish().unwrap();
        let m = read_whole(&bytes).unwrap();
        assert_eq!(m.objects.len(), 1);
        assert_eq!(m.objects[0].inode.user_xattrs, largest.inode.user_xattrs);
        // What a reader read, the writer writes back.
        assert_eq!(write_whole(&m).unwrap(), bytes);
        // The root file object's record is record 0.
        let mut root = recording_all().0;
        root.inode.user_xattrs = padded("a", MAX_RECORD_SIZE).inode.user_xattrs;
        let e = Writer::begin(Vec::new(), &root).unwrap_err();
        assert_eq!(
            (e.kind(), e.record_number()),
            (ErrorKind::Manifest(Problem::RecordTooLarge), Some(0))
        );
    }

    /// What was written so far is there to be signed: the signature
    /// objects sign what comes before the first of them.
    #[test]
    fn what_was_written_can_be_signed() {
        let mut writer = Writer::begin(Vec::new(), &RootObject::default()).unwrap();
        writer.file(&FileObject::new(name("a"))).unwrap();
        let signed = writer.get_ref().len();
        let hash = Sha256::digest(writer.get_ref());
        let mut signature = Signature::new("pkcs7");
        signature.data = Some(hash.as_bytes().to_vec());
        writer.signature(&signature).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::open(&bytes[..]).unwrap();
        let objects: Vec<_> = reader.by_ref().collect::<Result<_, _>>().unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(reader.signed_len(), u64::try_from(signed).ok());
        assert_eq!(Sha256::digest(&bytes[..signed]), hash);
    }

    /// Notes every write and every flush, and fails the write `fail_at`.
    #[derive(Debug, Default)]
    struct Calls {
        writes: Vec<usize>,
        flushes: usize,
        fail_at: Option<usize>,
    }

    impl Write for Calls {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if self.fail_at == Some(self.writes.len()) {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.writes.push(data.len());
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[test]
    fn a_record_is_one_write() {
        let mut calls = Calls::default();
        let (root, root_text) = recording_all();
        let mut writer = Writer::begin(&mut calls, &root).unwrap();
        writer.file(&directory("a")).unwrap();
        writer.file(&everything()).unwrap();
        let mut empty = FileObject::new(name("empty"));
        empty.sha256 = EMPTY.parse().ok();
        writer.file(&empty).unwrap();
        writer.finish().unwrap();
        assert_eq!(calls.writes.len(), 5);
        assert_eq!(calls.writes[0], sequence(&[root_text.as_str()]).len());
        assert_eq!(calls.writes[4], sequence(&[TRAILER]).len());
        assert_eq!(calls.flushes, 1);
        // An error of what is written to is the writer's, about the record
        // it wrote.
        for (fail_at, record_number) in [(0, 0), (1, 1)] {
            let mut calls = Calls {
                fail_at: Some(fail_at),
                ..Calls::default()
            };
            let e = Writer::begin(&mut calls, &RootObject::default())
                .and_then(|mut writer| writer.file(&FileObject::new(name("a"))))
                .unwrap_err();
            assert_eq!((e.kind(), e.record_number()), (ErrorKind::Io, Some(record_number)));
            assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::ENOSPC));
        }
    }
}
