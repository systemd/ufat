# ucpio

ucpio creates, fills and checks cpio archives without unpacking them. It
is made for the initramfs, the archive the Linux kernel unpacks into its
root file system at boot. It can:

- make an archive from a directory tree,
- add files and directory trees to an archive,
- build an archive from a [UAPI.16][uapi16] file manifest,
- list an archive, print a file in it and write its manifest,
- check an archive for entries the kernel does not unpack as they were
  meant,
- compute how large an archive will be.

[uapi16]: https://uapi-group.org/specifications/specs/file_manifest/

ucpio is a Rust library, a command line tool and a Varlink service. The
tool and the service are the same binary. It is built and installed
together with ufat, see the README.

## Properties

- The new ASCII format only, with or without checksums. This is the
  format the kernel takes. ucpio reads and writes one archive and does
  not compress it.
- Linux only.
- The output is reproducible. The same files, options and time stamps
  give the same archive, byte for byte.
- The entries are written in one order: a directory before what is in
  it, and the entries of a directory sorted by name.
- Hard links are kept. A file with several names is stored once.
- Owners, modes, symbolic links, device nodes, FIFOs and sockets are
  kept. Extended attributes are not: the format has no place for them.
- ucpio refuses what the format cannot hold: a file of more than
  4294967295 bytes, a path of more than 4095 bytes, and a device number
  with a major above 4095 or a minor above 1048575. A time is stored in
  whole seconds, from 1970 to 2106.
- What ucpio assumes about the kernel is tested against a kernel.
  tests/fixtures/cpio holds archives and what a kernel unpacked them
  to.
- The code uses the Rust standard library and the crates libc, sha2 and
  lexopt.

## Using the command line tool

Make an archive of a directory tree:

    ucpio assemble initrd.cpio tree/

Add to an existing archive, a directory tree or one file:

    ucpio populate initrd.cpio more/
    ucpio populate --parents --path /usr/lib/firmware/blob.bin initrd.cpio blob.bin

Create an empty directory:

    ucpio populate --parents --path /var/empty initrd.cpio

Look at an archive:

    ucpio list -l initrd.cpio /etc
    ucpio cat initrd.cpio /etc/os-release
    ucpio describe initrd.cpio
    ucpio check initrd.cpio

Print how large the archive of a tree will be, without writing it:

    ucpio assemble --plan tree/

`--offset` and `--size` say where the archive is inside the image, for an
archive that is part of a larger file or on a block device. `ucpio --help`
lists all commands and options.

### Reproducible archives

The archive depends on the files, the options and the time stamps only.
For the same archive on every run, set the time and the owner:

    SOURCE_DATE_EPOCH=1700000000 ucpio assemble --uid 0 --gid 0 initrd.cpio tree/

With `SOURCE_DATE_EPOCH` or `--timestamp`, a time later than the given
one is replaced by the given one. `--times fixed` gives every entry the
given time. `--times preserve` keeps the times of the files.

Without `--uid` and `--gid` the entries have the owners of the files.

### Manifests

`--manifest` builds what a UAPI.16 manifest describes. The one SOURCE is
the directory with the files, or `-` for the contents of the files on
standard input, back to back in the order of the manifest:

    ucpio assemble --manifest tree.Uapi16Manifest initrd.cpio tree/
    cat blob | ucpio assemble --manifest tree.Uapi16Manifest initrd.cpio -

The sizes and hashes in the manifest are checked while the files are
copied. With `-`, the manifest has to list the entries in the order of
the archive, which is the order `systemd-manifest` writes, and standard
input has to end after the last file.

`--write-manifest` writes the manifest of the archive, after `assemble`
and `populate` or with `describe`:

    ucpio describe --write-manifest initrd.Uapi16Manifest initrd.cpio

### Options of the format

- `--checksums` writes the form with checksums. The kernel verifies them
  and stops unpacking at the first that is wrong.
- `--end-alignment BYTES` pads the end of the archive to a multiple of
  BYTES. The default is 512.
- `--data-alignment BYTES` starts the contents of every file of at least
  BYTES bytes at a multiple of BYTES.
- `--no-root-entry` writes no entry for the root directory. With the
  entry, the root directory the kernel unpacks into gets the mode, the
  owner and the time of the source directory.

## Adding to an archive

`populate` writes the new entries where the end of the archive was. The
result is one archive.

When the kernel unpacks an archive, an entry that has the name of an
earlier one takes its place. This is how `populate` replaces a file. The
earlier entry stays in the archive and takes up room. `ucpio check`
reports it as a warning.

GNU cpio and busybox keep the earlier of two entries of the same age
when they unpack an archive. `-u` makes them take the later one.

`populate` refuses what the kernel would not do as it was meant:

- a file where a directory is, and a directory where a file is,
- a new file under one name of a hard-linked file,
- a device node with another device number than the one that is there.

A directory that is in the archive is left as it is. Nothing can be
removed from an archive.

`populate` needs one archive with nothing but padding behind it. It
refuses an archive with entries that have `..` in their names or that
are below a symbolic link.

## Checking an archive

`ucpio check` goes through the archive the way the kernel unpacks it. An
error is an entry the kernel loses or removes, or a place where the
kernel stops unpacking. A warning is something the kernel unpacks and
another reader may not, or an entry that only takes up room.

The exit status follows fsck(8): 0 for an archive without errors, 4 when
errors were found, 8 when the image could not be checked.

## Crash safety

An archive cannot be written or changed in one step. So `assemble` and
`populate` mark the archive while they write.

`assemble` replaces the first byte of the archive until everything else
is written, the manifest of `--write-manifest` included. If `assemble`
fails, or is interrupted by a crash or a power loss:

- The kernel unpacks nothing of the archive. It reports that unpacking
  failed.
- bsdcpio and busybox fail on the archive.
- GNU cpio complains about the start of the archive and unpacks the
  entries it finds behind it.
- `ucpio check` reports that the archive was not finished. The other
  commands refuse it.

Running `assemble` again writes the archive anew.

While `populate` adds entries, the first byte of the old end of the
archive is replaced, and the new end is marked the same way until
everything is written. If `populate` is interrupted by a crash or a power
loss:

- The kernel unpacks either what the archive held before or everything
  that was added, never a part of it. It reports that unpacking failed.
- cpio, bsdcpio and busybox fail on the archive.

When `populate` fails for another reason, for example because a source
file changed or the disk is full, it puts the archive back as it was.

## The Varlink service

When the binary is started with a socket passed in `LISTEN_FDS`, it
serves the `org.uapi-group.FileSystem` Varlink interface for the type
`cpio`:

    varlinkctl call ./target/release/ucpio org.uapi-group.FileSystem.GetCapabilities '{}'
    varlinkctl call --push-fd=./initrd.cpio ./target/release/ucpio \
        org.uapi-group.FileSystem.Describe '{"image":{"fileDescriptor":0}}'

docs/varlink.md describes the interface as ufat serves it. The ucpio
service differs in these points:

- `Remove` and a `Check` with a repair mode fail with
  `OperationNotSupported`. So do the options `label`, `identifier`,
  `discard` and features.
- `FormatOptions` takes `cpio`, with `endAlignment`, `dataAlignment`,
  `checksums` and `rootEntry`. They do what the options of the command
  line do.
- An archive has no sectors and no blocks. `sectorSize` is 1 and
  `blockSize` is 4, the multiple every entry starts at.
- `Description.sizeBytes` is the length of the archive with its padding.
- A finding of `Check` has the position of its entry among the entries in
  `slot` and the offset of the entry, divided by 4, in `block`.
- `Content.uid` and `Content.gid` set the owner of every entry.
  `Content.unsupported` and `Content.extendedAttributes` change nothing.
- An `Assemble` that fails after it began to write leaves the archive
  marked as not finished, see "Crash safety". `Check` reports the mark
  with the error `noMagic`. `Describe`, `List` and `Populate` fail with
  `Corrupt` until `Assemble` writes the archive again.

`ucpio capabilities` prints what `GetCapabilities` returns.

## The library

The library is the crate `cpio` in src/cpio/. The modules are:

- `plan`, `assemble` and `populate` make an archive and add to one,
- `manifest` plans what a UAPI.16 manifest describes and writes the
  manifest of an archive. The manifests themselves are read and written
  by the crate `uapi16` in the same tree, which knows nothing of cpio,
- `tree` says what an archive unpacks to,
- `check` checks an archive,
- `read` and `write` read and write entries.
