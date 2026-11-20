# ufat

ufat creates, fills and checks FAT32 file systems without mounting them.
It is made for the EFI System Partition (ESP). It can:

- format an image file or a partition,
- copy files and directory trees into it,
- build it from a [UAPI.16][uapi16] file manifest,
- check it for errors,
- compute how large it has to be for a given set of files.

[uapi16]: https://uapi-group.org/specifications/specs/file_manifest/

ufat is a Rust library, a command line tool and a Varlink service. The
tool and the service are the same binary.

## Properties

- FAT32 only, with long file names. FAT12, FAT16 and exFAT are not
  supported.
- Linux only.
- The output is reproducible. The same files, options and time stamps
  give the same image, byte for byte.
- One writer at a time. An image file is locked while it is open. A
  block device is opened exclusively, so a mounted file system is
  refused.
- Writes are ordered so that a crash or a power loss leaves every file
  in its old state, its new state, or absent. A file is never left
  damaged.
- The code uses the Rust standard library and the crates libc, sha2,
  lexopt and serde_json.
- libblkid names what an image holds when it holds no FAT32 file
  system, and keeps `assemble` from formatting over a file system or a
  partition table. ufat loads it at run time when it is installed, and
  works without it.

## Building and installing

You need rustc and cargo 1.85 or newer, on Linux with glibc or musl.
libblkid from util-linux is not needed to build ufat. A statically
linked ufat, which a musl build is by default, cannot load it.

    cargo build --release --locked
    cargo install --locked --path . --root /usr/local

This builds the tool `target/release/ufat` and installs it into
/usr/local/bin. Without `--root` it goes into ~/.cargo/bin.

HACKING.md describes the tests and the other tools, and how to submit
changes.

## Using the command line tool

This recording uses the tool to make, change and check an ESP image:

[![ufat command line tool](https://asciinema.org/a/1272219.svg)](https://asciinema.org/a/1272219)

Make an image that fits a directory tree and copy the tree into it:

    ufat assemble --create --minimize --label ESP esp.img tree/

Without `--minimize` the file system takes the size given with `--size`,
or the whole image, as mkfs.fat does:

    ufat assemble --create --size 1G --label ESP esp.img tree/

Copy more files into an existing file system, a directory tree or one
file:

    ufat populate esp.img more/
    ufat populate --parents --path /EFI/BOOT/BOOTX64.EFI esp.img bootx64.efi

Look at the result and check it:

    ufat list -l esp.img /EFI/Linux
    ufat check esp.img

Compute the size a tree needs without writing anything:

    ufat assemble --plan tree/

Make an empty file system of a given size:

    ufat assemble --create --size 1G --label ESP empty.img

`assemble` does not format over a file system, a partition table or
other data that libblkid recognizes. `--force` or `-f` formats the image
anyway. So running `ufat assemble` again on an image that holds a file
system already needs `--force`, as mkfs.xfs needs `-f`:

    ufat assemble --force --label ESP esp.img tree/

A new image file, an empty one and one whose first 256 KiB are zeros
are formatted without `--force`, and so is data that libblkid does not
recognize. Without libblkid, ufat formats only an image whose first
256 KiB are zeros, unless `--force` is given. `--offset` and `--size`
select the part of the image that is looked at.

The commands are:

| Command | What it does |
|---|---|
| `assemble IMAGE [SOURCE]` | Create a file system and fill it with SOURCE or what `--manifest` describes. Without a SOURCE, create an empty file system. |
| `assemble --plan [SOURCE]` | Print the smallest file system size that holds SOURCE or what `--manifest` describes. |
| `populate IMAGE [SOURCE]` | Copy a directory tree, one file, or what `--manifest` describes into an existing file system. Without a SOURCE, create a directory. |
| `remove IMAGE PATH...` | Remove files and empty directories. `-r` removes directories with everything in them. |
| `list IMAGE [PATH]` | List a directory. `-l` shows sizes and times. |
| `describe IMAGE` | Show the geometry of a file system. |
| `check IMAGE` | Check a file system. |
| `capabilities` | Print what ufat supports, as JSON. |
| `cat IMAGE PATH` | Print a file. |
| `manifest DIR` | Write a UAPI.16 manifest of a directory tree. |

The commands are named after the methods of the Varlink service, see
below. `cat` and `manifest` have no method.

`ufat --version` prints the version. `ufat --help` lists all options.
The most common ones:

- `--offset BYTES` and `--size BYTES` select a file system inside a larger
  image, for example one partition of a disk image.
- `--label LABEL` sets the volume label. `--identifier ID` sets the volume
  serial number, as XXXX-XXXX or 8 hex digits.
- `--sector-size BYTES` sets the logical sector size. See "Sector size"
  below.
- `--path PATH` copies the directory tree below PATH instead of the root.
  For `populate` it is also the path of a single file, or the directory
  to create.
- `--minimize` makes the file system of `assemble` as small as its
  content allows. A `--size` is then the most it may take.
- `--replace` lets `populate` replace a file that is there already, and
  lets `assemble` and `populate` take names that FAT does not tell apart,
  such as `A.TXT` and `a.txt`, as one name. Without it they fail on
  them.
- `--unsupported fail` fails on files FAT cannot store, such as FIFOs
  and device nodes. By default they are left out with a message.
- `--write-manifest PATH` writes a UAPI.16 manifest of what the file
  system holds after `assemble` or `populate`, or of what `describe`
  finds. It has the size and the SHA-256 hash of every file, says which
  files and directories are read-only, and has no times. It records no
  hidden, system or archive attributes either. Its root object names the
  serial number of the file system and its label, or says that it has no
  label. A label that a file system made from the manifest would not get,
  which only other tools write, is left out, and ufat says so. With `-`
  as PATH the manifest goes to standard output, and what the command
  prints there otherwise goes to standard error.
- `--hash sha256` or `--hash sha512` prints the hash of the file system
  `assemble` wrote.
- `--write-hash PATH` writes that hash to PATH instead, or with `-` to
  standard output.
- `--force` or `-f` lets `assemble` format an image that holds a file
  system, a partition table or other data.

Sizes take the suffixes K, M, G and T.

### Reproducible images

Set `--timestamp SECONDS` or the `SOURCE_DATE_EPOCH` environment variable
to make the output depend on the inputs only. That time is used for the
volume and for entries that carry no time of their own.

`--times` decides what happens to the modification times of copied
files:

- `preserve` keeps them. This is the default.
- `fixed` sets every file to the time stamp.
- `clamp` keeps times up to the time stamp and sets later ones to it.
  This is the default when `SOURCE_DATE_EPOCH` is set.

With `--timestamp` or `SOURCE_DATE_EPOCH`, the volume serial number is
derived from the time stamp and the label instead of drawn at random. A
file system made from a manifest gets its serial number from the
manifest, see "Manifests".

### Manifests

`assemble`, `populate` and `assemble --plan` can work from a UAPI.16
manifest instead of a tree:

    ufat assemble --create --minimize --manifest m.json esp.img tree/
    ufat assemble --create --minimize --manifest m.json esp.img - < contents
    ufat assemble --plan --manifest m.json

With `--manifest`, the one SOURCE is the directory that the manifest's
file references point into. `-` reads the file contents from standard
input instead, back to back in manifest order. Standard input has to end
after the last file. It has the contents of each file and nothing else
of it, so an entry whose contents start at an offset in their file fails
the command with `-`, whatever `--unsupported` says. A manifest names its
paths from the root of the file system, so `--path` does not apply.

`--manifest -` reads the manifest from standard input. The file
contents then have to come from a directory.

ufat reads a manifest one record at a time, and writes each file and
directory when its record comes. So a manifest of any size can come
through a pipe on standard input, with `--manifest -`. A `--manifest`
PATH names a regular file. To size the file system to fit, ufat reads
the manifest once before it writes anything. So `--minimize` with a
SOURCE needs the manifest in a regular file, also on standard input.
`assemble --plan` and `assemble` without a SOURCE read the manifest only
once, so they take one through a pipe as well. While it sizes, ufat
keeps the path of the deepest open directory, and a count for each
directory on that path. Memory use does not grow with the manifest.

The objects of a manifest have to be in code point order: every
directory before what is in it, and the names of a directory sorted by
their bytes. The root object of the manifest has to declare that order
with `"order": "codepoint"`. `ufat manifest` writes manifests that way.
`systemd-manifest make` sorts its output that way, and declares the order
since systemd commit 330fab5e90, which is not in a release yet. ufat
refuses a manifest that does not declare the order, that is out of that
order, or that names a file twice. Two names that FAT does not tell
apart, such as `A.TXT` and `a.txt`, make `assemble` and `populate` fail
unless `--replace` is given.

While copying, ufat verifies the size and the SHA-256 hash of every file.
The data of a file is the part of its file below the SOURCE that starts
at the offset the manifest gives and is as long as the manifest says,
whatever else that file holds. A file that is missing below the SOURCE,
too short for the data, or does not match fails the command. If
`--create` made the image, nothing is left of it. Otherwise the file
system is left marked as not cleanly unmounted, with the files that were
complete.

FAT has no hard links. Files that a manifest lists as hard links of one
file become copies. `readOnly`, `flagHidden`, `flagSystem` and
`flagArchive` set or clear the read-only, hidden, system and archive
attributes of files and directories, also of directories that are there
already. A flag that the manifest lists in `features` and an object
leaves out clears its attribute. An object without `readOnly` is not
read-only, unless the manifest does not list `read-only` and the object
has a `mode` that gives nobody write permission. The inode flags such as
`flagImmutable` are ignored, since FAT has none.

The root object of a manifest can name the file system it is for, with
`fatSerial`, or `fsUUID` whose first eight hex digits give a serial
number, and `fsLabel`. A manifest that lists `fs-label` in `features`
and has no `fsLabel` names a file system without a label, and so does
an empty `fsLabel`. `assemble` gives the file system that serial number
and label. `--identifier` and `--label` have to agree with them. Without
a serial number from the manifest or from `--identifier`, the serial
number is the first eight hex digits that `sha256sum` prints for the
manifest. So a manifest gives the file system the same serial number
whether it comes from a file or from standard input, with or without
`--minimize`.
`populate` checks that the file system has the serial number and the
label the manifest names, and fails if it has not.

The label is the one the file system reports, as `blkid` shows it. FAT
pads a label with spaces, and stores the blank label and `NO NAME` for
no label. So `assemble` and `populate` refuse a manifest whose label
ends with a space, is blank or is `NO NAME`, as they refuse one whose
label FAT cannot store. `--label` takes such a label as `mkfs.fat -n`
does: it pads it with spaces, and a blank one or `NO NAME` is no label.

Signatures in a manifest are recognized but not verified. Verify a
signed manifest before you hand it to ufat.

`ufat manifest DIR` writes a manifest of a directory tree to standard
output. It has the size and the SHA-256 hash of every regular file, and
the modification time of every file and directory. Its root object lists
these features and declares the code point order. Other kinds of files,
such as symbolic links, are left out. So are entries whose names a
manifest cannot carry, such as names that are not UTF-8, with everything
below them, and ufat says how many it left out. A file that changes
while ufat reads it gets the size and the hash of what ufat read, and
ufat says how many files changed. When the command fails, the manifest
it wrote so far has no trailer, and readers refuse it. For a tree of
regular files and directories, `systemd-manifest make
--field=size,hash,mtime` writes the same file objects. A
systemd-manifest from before systemd commits 118717cfe2, 330fab5e90 and
e83f7bce0c, which are not in a release yet, writes neither `features`
nor `order` in the root file object. It also writes the hash of an empty
file.

### Time stamps

FAT stores times without a time zone. ufat writes and reads them as UTC.
systemd does the same when it fills an ESP, and so does the kernel with
the `tz=UTC` mount option. Tools that read FAT times as local time, such
as mtools, show them shifted unless they run with `TZ=UTC`.

Modification times have a resolution of two seconds and are rounded
down. Creation times have a resolution of ten milliseconds.

### Names

A name that fits the 8.3 format is stored as a short name only, if its
base and its extension are each entirely upper case or entirely lower
case. Every other
name is stored as a long name with a generated 8.3 alias. This is what
mtools and Windows do.

Names are compared without regard to case. ufat folds a character to its
upper case form when that form is a single character. The table comes
from Unicode 16.0.0 and is the same in every build and every version of
ufat. Case pairs that Unicode added later are not folded. How Linux
folds depends on the iocharset mount option. The default, iso8859-1,
folds ASCII and Latin-1 letters.

## Sizing

A FAT32 file system needs at least 65525 clusters. EDK2 firmware refuses
smaller volumes. ufat never creates a volume below that limit:

| Sector size | Smallest volume |
|---|---|
| 512 bytes | 34089472 bytes, about 33 MiB |
| 4096 bytes | 269045760 bytes, about 257 MiB |

`ufat assemble --plan` prints the smallest size for a tree or a manifest.
`assemble --minimize` creates a file system of exactly that size, and
fails when it is more than `--size`. Without `--minimize` the file system
takes `--size`, or the whole image, and an empty image without `--size`
is refused. An empty file system made with `--fit DIR`, or with
`--manifest` and no SOURCE, takes `--size` too, which DIR or what the
manifest describes has to fit. Without `--size` it gets the smallest size
that holds them. `--plan` with `--size` answers for `assemble` with the
same options: without `--minimize` the content has to fit a file system
of that size, in the clusters that size gets, and with `--minimize` the
smallest file system has to fit in `--size`. An existing image file is
grown when needed and never shrunk. A smaller volume made by another
tool can still be read, filled and checked. `ufat check` reports that it
is below the minimum.

A plan does not compare names. Two names that FAT does not tell apart
are two names to the plan: names that differ in case only, such as
`A.TXT` and `a.txt`, and a name and the short name FAT gives another
one, such as `FOOBAR~1` for `FOO BAR`. So they pass the plan also where
`assemble` refuses them without `--replace`.

With `--replace` a file under such a name replaces the other one, and
the plan counts both. The file system keeps the clusters of every
replaced file free then. Both also count against the 65536 directory
entries a FAT directory holds, so the plan of a directory close to that
limit can fail although the write would fit. A long name takes up to 21
of these entries.

With `--replace` the entries of a directory under two such names, such
as `FOO BAR/a` and `FOOBAR~1/b`, go into one directory. The plan holds
the entries under each name to the limit on their own, and only the
write sees them all in one directory. When they do not fit, `assemble`
fails with "directory is full", and nothing is left of an image that
`--create` made.

A file and a directory under two such names pass the plan, and
`assemble` fails on the second one, with or without `--replace`.

## Sector size

The sector size of the file system has to be at least the logical block
size of the device it ends up on. Linux refuses to mount it otherwise.
An image made with the default of 512 bytes does not mount on a disk
with 4096 byte sectors. Use `--sector-size 4096` for such a disk.

A file system with 4096 byte sectors also mounts on devices with 512
byte sectors on Linux and in EDK2. U-Boot requires the sector size to
match the device.

## Checking a file system

`ufat check` reads the whole file system and reports what is wrong. It
never changes the image. It reports problems that make Linux, EDK2, GRUB,
U-Boot or Windows fail or misread the volume, and names the reader in
the message.

The exit status follows fsck(8):

| Status | Meaning |
|---|---|
| 0 | No errors were found. Warnings do not count. |
| 4 | Errors were found and left uncorrected. |
| 8 | The image could not be checked. |

An image that holds no FAT32 file system cannot be checked. The message
says what the image holds instead: another file system or a partition
table by the name libblkid gives it, such as ext4 or gpt, or that the
image is blank. Blank means that its first 256 KiB are zeros. Without
libblkid, the message can only say whether the image is blank.

## Crash safety

ufat writes data and the allocation table before the directory entry
that points at them. A new file's entry is written only when the file is
complete. A removed entry is gone before its clusters are freed. A new
directory cluster is zeroed and allocated on disk before anything points
at it.

A device with a write cache can reorder writes. So on block devices,
ufat waits for the data to reach the device (fdatasync) before it writes
the entry that points at it. This is on by default for block devices
and off for image files. Image files are synced once, when ufat closes
them.

While ufat writes to a volume, it marks the volume as not cleanly
unmounted, the way Linux, Windows and EDK2 expect. ufat removes the mark
when it closes the volume. After a crash, the mark tells readers and
`ufat check` to look at the volume.

An image that `assemble --create` makes gets its name only when
everything else succeeded, its hash included. Until then it has no name,
so a failed `assemble` leaves nothing of it. If a file takes the name
meanwhile, `assemble` fails and leaves that file as it is. On a file
system that cannot make a file without a name, such as NFS or FAT, the
image has a temporary name in the same directory until then: `.#`
followed by its name and 16 hex digits. A kill or a crash leaves that
file behind. Once the image and the files written next to it have their
names, ufat syncs their directories, so that a power cut does not lose
the names. It does that also when `assemble` fails after the image got
its name. It does not sync a directory on a file system that cannot sync
directories, such as vboxsf, or a directory it may not read.

There are exceptions. A file system that can neither rename a file
without replacing another one nor make hard links, such as vboxsf, does
not let the image wait for its name. There the image gets its name right
away, and a failed `assemble` removes it again, but a kill or a crash
leaves it. ufat removes such a name only while it still refers to the
image, but another file can take the name between that check and the
removal, and is removed then. Another file that takes the temporary name
of the image just before ufat renames the image gets the name of the
image, and `assemble` fails and leaves it there. When another process
locks the new image first, `assemble` fails and leaves the image to that
process: under its temporary name where it has one, or under its name on
a file system such as vboxsf. A file system that makes files without a
name but cannot give them one, such as a FUSE file system without hard
links, fails `assemble` at its very end. An image that has its name
keeps it when a file written next to it cannot get its own, and when
syncing its directory or checking its name fails, which ufat says. A
name that cannot be removed stays, and ufat says so after the error.

The files that `--write-manifest` and `--write-hash` write get their
names after the image, and a failed `assemble` leaves what is at their
paths as it was. A regular file there is replaced, not written over, so
other hard links to it keep what it held. A pipe, a device or a symbolic
link at such a path is written to as `assemble` goes, like standard
output. A hash that `--hash` prints is printed once the image has its
name.

When `assemble` fails after it has formatted the file system in an image
that was there before, ufat leaves the file system marked as not cleanly
unmounted, as after a crash. It holds the files that were complete when
the command failed. `ufat check` and fsck.fat report the mark, and Linux
warns about it when it mounts the file system read-write. Running
`assemble --force` again formats the file system anew.

When `populate` fails while it writes a tree or a manifest, ufat leaves
the file system marked the same way, unless nothing was written yet. A
manifest that is refused at its first object leaves the file system as
it was.

A crash can leave a state that readers resolve in different ways. A
replaced file can briefly exist twice, and a long name can lose its long
form. `ufat check` reports both. Every reader still finds a complete file.

## The Varlink service

When the binary is started with a socket passed in `LISTEN_FDS`, it
serves the `org.uapi-group.FileSystem` Varlink interface for vfat.
`varlinkctl` and systemd socket units start it this way:

    varlinkctl call ./target/release/ufat org.uapi-group.FileSystem.GetCapabilities '{}'
    varlinkctl call --push-fd=./esp.img ./target/release/ufat \
        org.uapi-group.FileSystem.Describe '{"image":{"fileDescriptor":0}}'

The service takes every file and directory as a file descriptor passed
with the call, never as a path. docs/varlink.md describes the methods,
the parameters and the errors. The commands of the command line tool do
what the methods of the same name do, and `ufat capabilities` prints
what `GetCapabilities` returns.

This recording uses varlinkctl to make an ESP image from a manifest:

[![ufat Varlink service](https://asciinema.org/a/1272221.svg)](https://asciinema.org/a/1272221)

## The library

The crate `fat` provides the same operations as the tool:

- `format` creates a file system on a `device::Device`.
- `volume::Volume` opens one and reads, writes, creates and removes
  files and directories.
- `populate` copies directory trees from the host into a volume.
- `plan` computes the size a set of files needs.
- `manifest` builds volumes from UAPI.16 manifests while they are read,
  and writes manifests. The manifests themselves are read and written by
  the crate `uapi16` in the same tree, which knows nothing of FAT.
- `fsck` checks a volume.

A path on the host is resolved once. Everything below it is reached
through file descriptors, so the library copies exactly what it looked
at, even if the tree changes meanwhile.

## Differences from other tools

- mkfs.fat 4.2 refuses volumes with fewer than 65529 clusters. The FAT
  specification and EDK2 require 65525. ufat uses 65525.
- On devices with 4096 byte sectors, mkfs.fat 4.2 writes the hidden
  sectors field in 512 byte units (dosfstools issue 221). ufat uses the
  file system's sector size.
- fsck.fat 4.2 miscomputes the length of a file within one cluster of 4
  GiB. With `-a` it truncates such a file (dosfstools issue 208). Do not
  run `fsck.fat -a` on an ESP that holds one. `ufat check` checks such
  files correctly.
- ufat checks the boot sector more strictly than Linux. It refuses fewer
  than two reserved sectors, an FSInfo sector number of 0, a backup boot
  sector outside the reserved area, and FAT mirroring turned off. Linux
  mounts such volumes. ufat refuses to open them, and `ufat check`
  reports them as errors.

## Status

Manifest signatures are not verified, and `ufat check` does not repair
anything.

## License

LGPL-2.1-or-later, see LICENSE.
