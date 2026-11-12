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
- The code uses the Rust standard library and the crates libc, sha2 and
  lexopt.

## Building and installing

You need rustc and cargo 1.85 or newer, on Linux with glibc.

    cargo build --release --locked
    cargo install --locked --path . --root /usr/local

This builds the tool `target/release/ufat` and installs it into
/usr/local/bin. Without `--root` it goes into ~/.cargo/bin.

HACKING.md describes the tests and the other tools.

## Using the command line tool

Make an image that fits a directory tree and copy the tree into it:

    ufat assemble --create --label ESP esp.img tree/

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

The commands are:

| Command | What it does |
|---|---|
| `assemble IMAGE [SOURCE...]` | Create a file system sized to fit the sources and copy them into it. Without a SOURCE, create an empty file system. |
| `assemble --plan [SOURCE...]` | Print the smallest file system size that holds the sources. |
| `populate IMAGE [SOURCE...]` | Copy directory trees or one file into an existing file system. Without a SOURCE, create a directory. |
| `remove IMAGE PATH...` | Remove files and empty directories. `-r` removes directories with everything in them. |
| `list IMAGE [PATH]` | List a directory. `-l` shows sizes and times. |
| `describe IMAGE` | Show the geometry of a file system. |
| `check IMAGE` | Check a file system. |
| `capabilities` | Print what ufat supports, as JSON. |
| `cat IMAGE PATH` | Print a file. |
| `manifest DIR` | Write a UAPI.16 manifest of a directory tree. |

The commands are named after the methods of the Varlink service, see
below. `cat` and `manifest` have no method.

`ufat --help` lists all options. The most common ones:

- `--offset BYTES` and `--size BYTES` select a file system inside a larger
  image, for example one partition of a disk image.
- `--label LABEL` sets the volume label. `--identifier ID` sets the volume
  serial number, as XXXX-XXXX or 8 hex digits.
- `--sector-size BYTES` sets the logical sector size. See "Sector size"
  below.
- `--path PATH` copies directory trees below PATH instead of the root.
  For `populate` it is also the path of a single file, or the directory
  to create.
- `--no-replace` fails instead of replacing files that exist.
- `--unsupported fail` fails on files FAT cannot store, such as FIFOs
  and device nodes. By default they are left out with a message.
- `--write-manifest PATH` writes a UAPI.16 manifest of what the file
  system holds after `assemble` or `populate`, or of what `describe`
  finds.
- `--hash sha256` or `--hash sha512` prints the hash of the file system
  `assemble` wrote.

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
derived from the time stamp and the label instead of drawn at random.

### Manifests

`assemble`, `populate` and `assemble --plan` can work from a UAPI.16
manifest instead of a tree:

    ufat assemble --create --manifest m.json esp.img tree/
    ufat assemble --create --manifest m.json esp.img - < contents
    ufat assemble --plan --manifest m.json

With `--manifest`, the one SOURCE is the directory that the manifest's
file references point into. `-` reads the file contents from standard
input instead, back to back in manifest order. A manifest names its
paths from the root of the file system, so `--path` does not apply.

When the contents come from a directory, ufat first checks that every
file the manifest names is there with the size the manifest gives. This
happens before the image is changed. While copying, ufat verifies the
size and the SHA-256 hash of every file. A mismatch fails the command.

Signatures in a manifest are recognized but not verified. Verify a
signed manifest before you hand it to ufat.

`ufat manifest DIR` writes a manifest of a directory tree. For a tree of
regular files and directories, the output is the same as that of
`systemd-manifest make --field=size,hash,mtime`.

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

Two entries in one directory of a tree whose names differ only in case,
such as `A.txt` and `a.txt`, would be one file on FAT. `assemble` and
`populate` refuse such a tree before they change the image. This includes
a pair where one entry is a FIFO, socket or device node that would
otherwise be skipped. A manifest that lists two such names is refused as
well. A file in the file system whose name differs only in case from one
in the tree is replaced like any other file, unless `--no-replace` is
given.

## Sizing

A FAT32 file system needs at least 65525 clusters. EDK2 firmware refuses
smaller volumes. ufat never creates a volume below that limit:

| Sector size | Smallest volume |
|---|---|
| 512 bytes | 34089472 bytes, about 33 MiB |
| 4096 bytes | 269045760 bytes, about 257 MiB |

`ufat assemble --plan` prints the smallest size for a tree or a manifest.
`assemble` creates an image of exactly that size unless `--size` is given.
An existing image file is grown when needed and never shrunk. A smaller
volume made by another tool can still be read, filled and checked.
`ufat check` reports that it is below the minimum.

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

## Crash safety

ufat writes data and the allocation table before the directory entry
that points at them. A new file's entry is written only when the file is
complete. A removed entry is gone before its clusters are freed. A new
directory cluster is zeroed on disk before anything points at it.

A device with a write cache can reorder writes. So on block devices,
ufat waits for the data to reach the device (fdatasync) before it writes
the entry that points at it. This is on by default for block devices
and off for image files. Image files are synced once, when ufat closes
them.

While ufat writes to a volume, it marks the volume as not cleanly
unmounted, the way Linux, Windows and EDK2 expect. ufat removes the mark
when it closes the volume. After a crash, the mark tells readers and
`ufat check` to look at the volume.

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

## The library

The crate `ufat` provides the same operations as the tool:

- `format` creates a file system on a `device::Device`.
- `volume::Volume` opens one and reads, writes, creates and removes
  files and directories.
- `populate` copies directory trees from the host into a volume.
- `plan` computes the size a set of files needs.
- `manifest` reads UAPI.16 manifests, builds volumes from them and writes
  manifests.
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
