// SPDX-License-Identifier: LGPL-2.1-or-later
//! An archive in an image: a file or a block device, or a part of one.

use crate::device::Device;
use crate::errno::*;
use crate::header::Format;
use crate::read::Source;
use crate::write::Sink;
use crate::Result;

/// How many bytes a sink collects before it writes them.
const BUFFER: usize = 1024 * 1024;

/// Writes an archive to a device from an offset on. The bytes are
/// collected and written in large pieces.
#[derive(Debug)]
pub struct DeviceSink<'a> {
    device: &'a Device,
    /// Where on the device the first byte of this sink went.
    start: u64,
    /// Where on the device the buffer goes.
    at: u64,
    buffer: Vec<u8>,
}

impl<'a> DeviceSink<'a> {
    /// A sink whose first byte goes to `offset` of `device`.
    pub fn new(device: &'a Device, offset: u64) -> DeviceSink<'a> {
        DeviceSink {
            device,
            start: offset,
            at: offset,
            buffer: Vec::with_capacity(BUFFER),
        }
    }

    /// Writes what is collected. Without this the last bytes stay behind.
    pub fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            self.device.write_at(self.at, &self.buffer)?;
            self.at += self.buffer.len() as u64;
            self.buffer.clear();
        }
        Ok(())
    }
}

impl Sink for DeviceSink<'_> {
    fn write_all(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            let room = BUFFER - self.buffer.len();
            let n = room.min(buf.len());
            self.buffer.extend_from_slice(&buf[..n]);
            buf = &buf[n..];
            if self.buffer.len() == BUFFER {
                self.flush()?;
            }
        }
        Ok(())
    }

    fn patch(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        let end = self.at - self.start + self.buffer.len() as u64;
        let Some(patch_end) = offset.checked_add(buf.len() as u64).filter(|&e| e <= end) else {
            bail!(EINVAL, "a patch at offset {} is outside of what was written", offset);
        };
        let written = self.at - self.start;
        // The part that is on the device already, and the part that is
        // still here.
        if offset < written {
            let n = (written.min(patch_end) - offset) as usize;
            self.device.write_at(self.start + offset, &buf[..n])?;
        }
        if patch_end > written {
            let skip = written.saturating_sub(offset) as usize;
            let from = (offset.max(written) - written) as usize;
            self.buffer[from..from + buf.len() - skip].copy_from_slice(&buf[skip..]);
        }
        Ok(())
    }
}

/// What [`StoppedSink`] does with a piece of what it is given: the sink
/// behind it, the offset of the piece there and the piece.
type Put<'a, 'p> = dyn FnMut(&mut DeviceSink<'a>, u64, &[u8]) -> Result<()> + 'p;

/// Writes a new archive to a device in three steps that leave no state
/// the kernel takes for an archive when it is none:
///
/// - where the archive goes, a magic with [`STOPPER`] for its first byte
///   is written over what is there. From here on the kernel unpacks
///   nothing of it and says that unpacking failed;
/// - the archive goes to the device but for its first byte;
/// - the first byte goes where the stopper is, and the archive is whole.
///
/// Each step is on the device for good before the next one begins, and
/// the last one writes a single byte, which no device tears. So whatever
/// a crash leaves behind, and whatever a call leaves behind that fails
/// after the first step, the kernel unpacks all of the archive or nothing
/// of it, and it says that unpacking failed unless all three steps are
/// done. bsdcpio and busybox fail on a stopped archive too. GNU cpio
/// complains about its start and unpacks the entries it finds behind it.
///
/// [`StoppedSink::settle`] ends the second step and hands out the third
/// as a [`Stopped`], so that what depends on the archive can be done
/// before it is whole.
#[derive(Debug)]
pub struct StoppedSink<'a> {
    device: &'a Device,
    /// Where the archive starts on the device.
    start: u64,
    /// How many bytes were written.
    written: u64,
    /// The first byte of what was written.
    first: Option<u8>,
    rest: DeviceSink<'a>,
}

impl<'a> StoppedSink<'a> {
    /// A sink for an archive of the form `format` that goes to `offset` of
    /// `device`. This stops what is there.
    pub fn new(device: &'a Device, offset: u64, format: Format) -> Result<StoppedSink<'a>> {
        device.write_at(offset, &format.stopped_magic())?;
        device.sync_data()?;
        Ok(StoppedSink {
            device,
            start: offset,
            written: 0,
            first: None,
            rest: DeviceSink::new(device, offset + 1),
        })
    }

    /// Puts what was written on the device for good, but for its first
    /// byte. The archive stays stopped until [`Stopped::finish`].
    pub fn settle(mut self) -> Result<Stopped<'a>> {
        let Some(first) = self.first else {
            bail!(EINVAL, "nothing was written where the archive goes");
        };
        self.rest.flush()?;
        self.device.sync_data()?;
        Ok(Stopped {
            device: self.device,
            start: self.start,
            first,
        })
    }

    /// Takes the first byte out of `buf`, which goes to `offset` of what
    /// is written, and hands what is left to `put` with its offset in the
    /// rest.
    fn hold(&mut self, offset: u64, buf: &[u8], put: &mut Put<'a, '_>) -> Result<()> {
        if offset != 0 {
            return put(&mut self.rest, offset - 1, buf);
        }
        let Some((&first, rest)) = buf.split_first() else {
            return Ok(());
        };
        self.first = Some(first);
        put(&mut self.rest, 0, rest)
    }
}

impl Sink for StoppedSink<'_> {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        let offset = self.written;
        self.written += buf.len() as u64;
        self.hold(offset, buf, &mut |rest, _, piece| rest.write_all(piece))
    }

    fn patch(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        match offset.checked_add(buf.len() as u64) {
            Some(end) if end <= self.written => {}
            _ => bail!(EINVAL, "a patch at offset {} is outside of what was written", offset),
        }
        self.hold(offset, buf, &mut |rest, at, piece| rest.patch(at, piece))
    }
}

/// An archive that is on a device for good but for its first byte, where
/// [`STOPPER`] is. It stays stopped when this is dropped: that is what a
/// call leaves behind that fails after the archive was written.
#[derive(Debug)]
#[must_use = "the archive stays stopped until this is finished"]
pub struct Stopped<'a> {
    device: &'a Device,
    start: u64,
    first: u8,
}

impl Stopped<'_> {
    /// The archive as it reads once it is finished, for what has to be
    /// done with it before it is.
    pub fn archive(&self) -> Finished<'_> {
        Finished {
            device: self.device,
            start: self.start,
            first: self.first,
        }
    }

    /// Writes the first byte. The archive is whole, and on the device for
    /// good.
    pub fn finish(self) -> Result<()> {
        self.device.write_at(self.start, &[self.first])?;
        self.device.sync_data()
    }
}

/// What a [`Stopped`] archive reads as once it is finished: the device
/// from where the archive starts, with the first byte that is held back
/// in its place.
#[derive(Debug)]
pub struct Finished<'a> {
    device: &'a Device,
    start: u64,
    first: u8,
}

impl Source for Finished<'_> {
    fn len(&self) -> u64 {
        self.device.len() - self.start
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        match offset.checked_add(buf.len() as u64) {
            Some(end) if end <= Source::len(self) => {}
            _ => bail!(EINVAL, "a read at offset {} is outside of the archive", offset),
        }
        self.device.read_at(self.start + offset, buf)?;
        if offset == 0 {
            if let Some(first) = buf.first_mut() {
                *first = self.first;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::STOPPER;
    use crate::test_util::TempImage;

    #[test]
    fn a_new_archive_is_stopped_until_it_is_finished() {
        let img = TempImage::new(1 << 20);
        let device = img.device();
        let at = |offset: u64, len: usize| {
            let mut bytes = vec![0u8; len];
            device.read_at(offset, &mut bytes).unwrap();
            bytes
        };
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 250) as u8 + 1).collect();
        for (offset, format) in [(0u64, Format::Newc), (4096, Format::Crc), (510, Format::Newc)] {
            // Something that is taken for an archive is where this one
            // goes.
            device.write_at(offset, &[b'0'; 600]).unwrap();
            let mut sink = StoppedSink::new(&device, offset, format).unwrap();
            // It is stopped before anything of the new one is written.
            assert_eq!(at(offset, 7), [&format.stopped_magic()[..], b"0"].concat());
            sink.write_all(b"").unwrap();
            for piece in data.chunks(77) {
                sink.write_all(piece).unwrap();
            }
            let mut expected = data.clone();
            // Patches of the first byte, across it and behind it.
            for (patched, patch) in [(0u64, &b"0"[..]), (0, b"01234567"), (1, b"abc"), (300, b"ABCDEFGH")] {
                sink.patch(patched, patch).unwrap();
                expected[patched as usize..patched as usize + patch.len()].copy_from_slice(patch);
            }
            assert_eq!(sink.patch(4999, b"ab").unwrap_err().errno(), EINVAL);
            let stopped = sink.settle().unwrap();
            // All of it is there but for the first byte.
            let mut held = expected.clone();
            held[0] = STOPPER;
            assert!(at(offset, 5000) == held, "at offset {}", offset);
            // And it reads as it is going to be.
            let finished = stopped.archive();
            assert_eq!(Source::len(&finished), (1 << 20) - offset);
            let mut back = vec![0u8; 5000];
            finished.read_at(0, &mut back).unwrap();
            assert!(back == expected);
            finished.read_at(1, &mut back[..10]).unwrap();
            assert!(back[..10] == expected[1..11]);
            finished.read_at(0, &mut []).unwrap();
            let beyond = (1 << 20) - offset - 1;
            assert_eq!(finished.read_at(beyond, &mut back[..2]).unwrap_err().errno(), EINVAL);
            assert_eq!(finished.read_at(u64::MAX, &mut back[..2]).unwrap_err().errno(), EINVAL);
            stopped.finish().unwrap();
            assert!(at(offset, 5000) == expected, "at offset {}", offset);
        }
        // What is dropped before it is finished stays stopped, and without
        // a first byte there is nothing to finish.
        let sink = StoppedSink::new(&device, 8192, Format::Newc).unwrap();
        assert_eq!(sink.settle().unwrap_err().errno(), EINVAL);
        assert_eq!(at(8192, 6), Format::Newc.stopped_magic());
        let mut sink = StoppedSink::new(&device, 8192, Format::Newc).unwrap();
        sink.write_all(b"070701 and so on").unwrap();
        let _ = sink.settle().unwrap();
        assert_eq!(at(8192, 16), b"X70701 and so on");
    }

    #[test]
    fn bytes_reach_the_device_and_patches_land() {
        let img = TempImage::new(4 << 20);
        let device = img.device();
        let mut sink = DeviceSink::new(&device, 4096);
        let data: Vec<u8> = (0..(3 * BUFFER + 12345) as u32).map(|i| (i % 251) as u8).collect();
        // In pieces that do not line up with the buffer.
        for piece in data.chunks(100_003) {
            sink.write_all(piece).unwrap();
        }
        let mut expected = data.clone();
        // On the device, across the edge of what is written, in the buffer.
        for (offset, patch) in [
            (10u64, &b"on the device"[..]),
            (3 * BUFFER as u64 - 4, b"across the edge"),
            (3 * BUFFER as u64 + 100, b"in the buffer"),
            (data.len() as u64 - 3, b"end"),
        ] {
            sink.patch(offset, patch).unwrap();
            expected[offset as usize..offset as usize + patch.len()].copy_from_slice(patch);
        }
        assert_eq!(sink.patch(data.len() as u64 - 2, b"end").unwrap_err().errno(), EINVAL);
        assert_eq!(sink.patch(u64::MAX, b"x").unwrap_err().errno(), EINVAL);
        sink.flush().unwrap();
        let mut back = vec![0u8; data.len()];
        device.read_at(4096, &mut back).unwrap();
        assert!(back == expected);
        // Nothing before the offset was touched.
        let mut head = vec![1u8; 4096];
        device.read_at(0, &mut head).unwrap();
        assert!(head.iter().all(|&b| b == 0));
    }
}
