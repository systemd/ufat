# The Varlink service

The `ufat` binary serves the `org.uapi-group.FileSystem` Varlink interface
for FAT32, which the interface calls `vfat`. The interface description is
docs/org.uapi-group.FileSystem.varlink. The service and the command line
tool are the same binary.

## Starting the service

ufat runs as a service when it finds a Varlink socket in its
environment. There is no command line flag for it.

- A socket passed as file descriptor 3, with `LISTEN_FDS=1`,
  `LISTEN_PID` set to the process ID and `LISTEN_FDNAMES=varlink`. This
  is what `varlinkctl call /path/to/ufat ...`, `varlinkctl call
  exec:/path/to/ufat ...`, `sd_varlink_connect_exec()` and a systemd
  socket unit with `Accept=yes` and `FileDescriptorName=varlink` do.
- `SYSTEMD_VARLINK_LISTEN=-` serves standard input and standard output.
- `SYSTEMD_VARLINK_LISTEN=/some/path` listens on a socket at that path,
  created with mode 0644. `SYSTEMD_VARLINK_LISTEN=@name` listens on an
  abstract socket.

A connected socket is served until the client hangs up. A listening
socket serves connections in parallel. The service exits with status 0
when the first connection has ended and no other one is left.
Diagnostics go to standard error.

Only root and the user the service runs as may connect. Connections from
other users are dropped.

## Calling the service

`varlinkctl` from systemd is the simplest client:

    varlinkctl introspect ./ufat org.uapi-group.FileSystem
    varlinkctl call ./ufat org.uapi-group.FileSystem.GetCapabilities '{}'
    varlinkctl call --push-fd=./esp.img ./ufat \
        org.uapi-group.FileSystem.Describe '{"image":{"fileDescriptor":0}}'

The service never opens a path. Every image, directory and file reaches
it as a file descriptor passed with the call. A parameter of type `int`
whose name ends in `FileDescriptor` is the index of a passed descriptor.
Indexes count from 0 in the order the descriptors were sent.

`varlinkctl call --push-fd=` passes descriptors. With a number it passes
a descriptor the shell has open. With a path it opens the file read-only.
A path has to be absolute or start with `./`. To pass an image for
writing, let the shell open it:

    varlinkctl call --push-fd=3 --push-fd=./tree ./ufat \
        org.uapi-group.FileSystem.Populate \
        '{"image":{"fileDescriptor":0},"path":"/","content":{"sourceFileDescriptor":1}}' \
        3<>esp.img

## Common parameters

Every method takes an optional `fileSystemType`. ufat serves `vfat` only.
Any other value fails with `FileSystemTypeNotSupported`.

Every method except `GetCapabilities` works on an `Image`:

| Field | Meaning |
|---|---|
| `fileDescriptor` | Index of the passed image file or block device. |
| `offset` | Byte offset of the file system in the image. 0 by default. |
| `size` | Size of the file system in bytes. The rest of the image by default. |

Paths inside the file system are absolute. `/` is the root. Times are
microseconds since the UNIX epoch, in UTC.

## Methods

| Method | What it does |
|---|---|
| `GetCapabilities` | Describes what the vfat implementation supports. |
| `Assemble` | Creates a file system and fills it, or computes the size it needs. |
| `Describe` | Reports the label, the serial number, the geometry and the free space. Can write a manifest of the contents. |
| `Populate` | Copies a tree, a file or the contents of a manifest into an existing file system. |
| `Remove` | Removes a file, an empty directory or a whole tree. |
| `List` | Lists a directory, one entry per reply. |
| `Check` | Checks the file system and reports every problem found. |

### GetCapabilities

The reply does not depend on the call. It is:

    {
      "capabilities" : {
        "fileSystemType" : "vfat",
        "implementation" : "ufat",
        "version" : "0.1",
        "readOnly" : false,
        "operations" : [ "plan", "assembleWithContent", "populate", "remove",
                         "list", "check", "label", "identifier", "reproducible",
                         "manifest", "writeManifest" ],
        "sizeToFit" : "exact",
        "minimalSizeBytes" : 34089472,
        "maximalSizeBytes" : 2199023255040,
        "sizeGranularityBytes" : 512,
        "sectorSizes" : [ 512, 1024, 2048, 4096 ],
        "blockSizes" : [ 512, 1024, 2048, 4096, 8192, 16384, 32768 ],
        "label" : { "lengthMax" : 11, "unit" : "bytes", "charset" : "fat" },
        "identifier" : "serial",
        "preserves" : [ "dosAttributes" ],
        "times" : {
          "resolutionNSec" : 2000000000,
          "minUSec" : 315532800000000,
          "maxUSec" : 4354819199000000,
          "created" : true,
          "accessed" : true,
          "changed" : false,
          "utc" : true
        },
        "caseSensitive" : false,
        "nameLengthMax" : 255,
        "nameUnit" : "utf16Units",
        "fileSizeMaxBytes" : 4294967295
      }
    }

What the fields mean for vfat:

- `operations` lists what the implementation can do. `repair`,
  `features` and `discard` are missing. Asking for them fails with
  `OperationNotSupported`.
- `sizeToFit` is `exact`. A plan gives the size the content needs, to the
  sector.
- `minimalSizeBytes` is the smallest volume: 65525 clusters of 512 bytes
  plus the reserved sectors and two FATs. With 4096 byte sectors the
  minimum is 269045760 bytes. `maximalSizeBytes` is 2^32 - 1 sectors of
  512 bytes. Sizes are multiples of 512 bytes.
- `sectorSizes` and `blockSizes` are the supported sector sizes and
  cluster sizes.
- A label has at most 11 bytes of printable ASCII. It must not contain
  any of `*?.,;:/\|+=<>[]"` and must not start with a space.
- The identifier is the 32-bit volume serial number, written `XXXX-XXXX`.
- `preserves` lists what is kept from a source tree: the read-only,
  hidden, system and archive attributes. Ownership, modes, extended
  attributes and inode flags are not kept. A hard link becomes a copy. A
  symbolic link is followed. A hole in a file is filled with zeros.
  Sockets, FIFOs and device nodes are skipped.
- Modification times have a resolution of two seconds and range from
  1980-01-01 to 2107-12-31. Creation and access times exist. A change
  time does not. Times are stored as UTC.
- Names are compared without regard to case and hold up to 255 UTF-16
  units. A file holds at most 4294967295 bytes.

### Assemble

| Parameter | Meaning |
|---|---|
| `image` | The image to format. Not needed for mode `plan`. |
| `mode` | `assemble`, the default, or `plan`. |
| `options` | `FormatOptions`, see below. |
| `content` | What to copy into the new file system, see "Content". |
| `imageHash` | `sha256` or `sha512`. Hashes the image after formatting. |

Mode `format` creates the file system and copies the content into it, in
one call. Mode `plan` computes the geometry and the size the content
needs. It writes nothing.

How the image is sized:

- With content and without `size`, a regular image file is grown to the
  exact size the content needs. It is never shrunk.
- With a `size`, the file system gets that size. Content that does not
  fit fails with `TooSmall` before anything is written.
- Without content, a regular image file is grown to `size`. An empty
  image file without a `size` fails with `SizeRequired`.
- A block device is never resized.

The reply carries a `description` with the label and the serial number
as stored, the sector size, the cluster size (`blockSize`), the size and
the free space. With content, the counts `files`, `directories`, `bytes`,
`skipped` and `omitted` follow. `exact` is true when the size was
computed to fit the content.

Mode `plan` answers with `minimalSizeBytes` in place of `freeBytes`:

    $ varlinkctl call --json=pretty --push-fd=./tree ./ufat \
          org.uapi-group.FileSystem.Assemble \
          '{"mode":"plan","options":{"label":"ESP"},"content":{"sourceFileDescriptor":0}}'
    {
      "description" : {
        "fileSystemType" : "vfat",
        "identifier" : "E48E-77A0",
        "sectorSize" : 512,
        "blockSize" : 512,
        "sizeBytes" : 34089472,
        "minimalSizeBytes" : 34089472,
        "label" : "ESP"
      },
      "exact" : true,
      "files" : 2,
      "directories" : 3,
      "bytes" : 5010
    }

With `imageHash`, the service reads the whole file system back after
writing it and returns the digest in lower case hex. For an image file
sized to fit, this is the hash of the file.

#### FormatOptions

| Option | Meaning |
|---|---|
| `label` | The volume label. Fails with `InvalidLabel` when it breaks the label rules. |
| `identifier` | The volume serial number, as `XXXX-XXXX` or eight hex digits. Fails with `InvalidIdentifier` otherwise. Random by default. With `timestampUSec` it is derived from the time stamp and the label. |
| `timestampUSec` | The time stamp. It is the time of the root directory, the time `fixed` and `clamp` use, and the time of manifest entries without one. The current time by default. |
| `sectorSize` | 512, 1024, 2048 or 4096. The logical block size of a block device by default, 512 for an image file. It must not be smaller than the device's logical block size. |
| `blockSize` | The cluster size: a power of two from the sector size up to 32768, at most 128 sectors. Chosen from the volume size by default, like mkfs.fat does. |
| `zero` | Overwrites the whole data area with zeros. Off by default. |
| `reproducible` | Makes the image depend on the inputs only. Requires `identifier` and `timestampUSec`, and fails with `NotReproducible` without them. Set `times` to `fixed` or `clamp` to make the file times reproducible too. |
| `discard` | `false` is accepted. `true` fails with `OperationNotSupported`. |
| `enableFeatures`, `disableFeatures` | FAT has none. Setting them fails with `OperationNotSupported`. |
| `vfat` | FAT32 options, see below. |

Options that apply to one filesystem only are kept in a struct named
after that filesystem. For vfat this is `vfat`, of type `VfatOptions`.
An implementation for another filesystem adds its own struct the same
way.

`VfatOptions`:

| Option | Meaning |
|---|---|
| `reservedSectors` | Number of reserved sectors. 32 by default. |
| `fats` | Number of FAT copies. 2 by default. |
| `oemName` | The OEM name in the boot sector, up to eight printable ASCII characters. |
| `hiddenSectors` | The hidden sectors field. The start of the partition by default. |
| `mkfsFatCompatible` | Reproduces the layout of `mkfs.fat -F 32` exactly. |

The root directory has no entry of its own in FAT. Its time is stored on
the volume label entry. It comes from `timestampUSec`, else from the
manifest's root object, else from the source directory.

### Describe

| Parameter | Meaning |
|---|---|
| `image` | The image to read. |
| `manifestSink` | Optional. Writes a UAPI.16 manifest of everything the volume holds. See "Content". |

The reply carries a `description` as `Assemble` returns it. With a
`manifestSink`, it also carries the counts `files`, `directories`,
`bytes` and `omitted`. Writing the manifest reads every file.

### Populate

| Parameter | Meaning |
|---|---|
| `image` | The image to write to. |
| `path` | Where the content goes. |
| `content` | What to copy, see "Content". |
| `parents` | Creates missing parent directories. Off by default. |
| `timestampUSec` | The time for `fixed` and `clamp`, and for a new directory. The current time by default. |

A tree is copied below `path`. A single file is stored at `path`. A
manifest names its paths from the root, so with a manifest `path` has to
be `/`. Without content, `Populate` creates an empty directory at `path`.
With `parents`, an existing directory at `path` is accepted.

The reply carries the counts `files`, `directories`, `bytes`, `skipped`
and `omitted`.

### Remove

| Parameter | Meaning |
|---|---|
| `image` | The image to write to. |
| `path` | The file or directory to remove. |
| `recursive` | Removes a directory with everything below it. Off by default. |

Without `recursive`, a directory must be empty. The root cannot be
removed. The reply carries the counts `files` and `directories`.

### List

| Parameter | Meaning |
|---|---|
| `image` | The image to read. |
| `path` | A directory or a file. The root by default. |

Listing a directory needs the `more` flag. Without it the call fails
with `org.varlink.service.ExpectedMore`. Each reply carries one `entry`.
An empty directory gets one final reply without an entry. A file gets
one reply with its own entry, with or without the flag.

An entry carries `name`, `type` (`reg` or `dir`), `sizeBytes`,
`modifiedUSec`, `createdUSec` and `alternateName`, the 8.3 name.
`dosAttributes` lists `readOnly`, `hidden`, `system` and `archive` when
any of them is set.

    $ varlinkctl call --json=pretty --more --push-fd=./esp.img ./ufat \
          org.uapi-group.FileSystem.List '{"image":{"fileDescriptor":0},"path":"/EFI/BOOT"}'
    {
      "entry" : {
        "name" : "BOOTX64.EFI",
        "type" : "reg",
        "sizeBytes" : 5000,
        "modifiedUSec" : 1794316672000000,
        "createdUSec" : 1794316672480000,
        "alternateName" : "BOOTX64.EFI",
        "dosAttributes" : [ "archive" ]
      }
    }

### Check

| Parameter | Meaning |
|---|---|
| `image` | The image to check. |
| `repair` | Only `none` is supported. Anything else fails with `OperationNotSupported`. |

`Check` never changes the image. The reply carries:

| Field | Meaning |
|---|---|
| `errors`, `warnings` | The number of problems of each severity. |
| `clean` | True when no error was found. Warnings do not count. |
| `repaired` | Always 0. |
| `dropped` | Problems found beyond the first 10000, which are not reported. |
| `problems` | The problems. |

A problem carries:

- `severity`: `error` or `warning`.
- `class`: what part of the file system is affected, such as
  `superblock`, `allocation`, `directory`, `name` or `chain`.
- `kind`: what is wrong, such as `chainLoop`, `orphanedLongName` or
  `lostClusters`. There are 64 kinds.
- The facts that belong to the kind: `path`, `otherPath`, `slot`,
  `slots`, `block` and `blocks` (clusters), `sizeBytes`, `value`,
  `expected`, `name`, `otherName`, `field`, `copy` and `count`.

The service returns no text. A client turns the kind and its facts into
a message.

With the `more` flag, the problems come in batches of up to 100 and the
final reply carries the counts only. Without it, the final reply carries
everything. A clean volume answers:

    {"errors":0,"warnings":0,"repaired":0,"dropped":0,"clean":true,"problems":[]}

## Content

`Assemble` and `Populate` take what goes into the file system as a
`Content`. The type of the descriptor in `sourceFileDescriptor` decides
what the content is:

| Source | Manifest | Content |
|---|---|---|
| Directory | none | The tree below the directory. |
| Regular file | none | One file. `Populate` only. |
| Regular file or pipe | given | The contents of all files the manifest lists, back to back in manifest order. |
| Directory | given | The tree the manifest describes. File references are resolved below the directory. |
| none | given | Only for `Assemble` in mode `plan`, which needs no data. |

Other combinations fail with `InvalidParameter`. When a manifest's
contents come from a directory, every file the manifest names is checked
first. A file that is missing, not a regular file or of the wrong size
fails the call with `SourceMismatch` before the image is changed.

Symbolic links below a source directory are followed. They are resolved
below that directory and never lead out of it.

The other fields of `Content`:

| Field | Meaning |
|---|---|
| `manifest` | A UAPI.16 manifest: `fileDescriptor` names it. `checkValidity`, true by default, rejects revoked entries and entries outside their validity window with `EntryNotValid`. |
| `times` | `preserve` keeps modification times. This is the default. `fixed` sets every entry to the time stamp. `clamp` keeps times up to the time stamp and sets later ones to it. |
| `unsupported` | `skip`, the default, leaves out what FAT cannot store and counts it in `skipped`. `fail` fails with `ContentNotSupported` before anything is written. |
| `replace` | Replaces existing files. True by default. With `false`, an existing file fails with `FileExists`. |
| `extendedAttributes`, `uid`, `gid` | Accepted and ignored. FAT stores none of them. |
| `manifestSink` | Writes a UAPI.16 manifest of the whole volume after the content is in. |

What FAT cannot store: sockets, FIFOs and device nodes in a tree, and
manifest entries that need a `url`, an `encoding` or an `offset`, that
refer to a sub-manifest, or that have an inode type FAT does not have.

The sizes and SHA-256 hashes in a manifest are verified while the
contents are copied. A mismatch fails with `ContentMismatch`.

A `ManifestSink` has a `fileDescriptor` open for writing and optional
`fields`, the per-file fields in the vocabulary of systemd-manifest:
`mode`, `uid`, `gid`, `size`, `hash`, `symlink`, `device`, `hardlink`,
`mtime`, `userXattr`, `userName`, `groupName`. Without `fields`, the
default set of systemd-manifest is used. Fields FAT has no notion of are
left out. The manifest describes the whole volume, including files that
were there before the call. Entries whose names a manifest cannot carry
are left out and counted in `omitted`.

## The more flag

Every method except `GetCapabilities` accepts the `more` flag. With it,
the service sends intermediate replies with a `phase` before the final
reply. Without it, only the final reply is sent.

| Method | Phases |
|---|---|
| `Assemble` | `planning` (with content), `formatting`, `populating` (with content), `reading` (with a `manifestSink`, and again with `imageHash`). Mode `plan` sends `planning` only. |
| `Describe` | `reading`, with a `manifestSink` only. |
| `Populate` | `populating`, then `reading` with a `manifestSink`. |
| `Remove` | `removing`, for a recursive removal only. |
| `Check` | `checking`, then the problems in batches. |
| `List` | No phases. One entry per reply. |

While a phase lasts, the service repeats it about once a second. The
repeated reply carries the counts so far: `files`, `directories` and
`bytes` while `Assemble` and `Populate` are `populating` and while
`Describe` is `reading`, and `files` and `directories` while `Remove` is
`removing`. The other phases repeat without counts. So a caller can show
progress, and the connection is not quiet long enough for the caller's
idle timeout to fire. `planning` and `formatting` are not repeated.

## Passing file descriptors

Each parameter needs a descriptor of a certain kind:

| Parameter | Requirements |
|---|---|
| `image.fileDescriptor` | A regular file or a block device. Open read-write for `Assemble` in mode `assemble`, `Populate` and `Remove`. Read-only or read-write for `Describe`, `List` and `Check`. |
| `content.sourceFileDescriptor` | A directory, a regular file or a pipe, open read-only. |
| `content.manifest.fileDescriptor` | A regular file or a pipe, open read-only. A manifest of any size can be passed this way. |
| `manifestSink.fileDescriptor` | A regular file or a pipe, open for writing. `O_APPEND` is allowed. |

The service checks every descriptor before it uses it. The call fails
with `BadFileDescriptor`, naming the parameter and a `reason`, when the
descriptor:

- was opened with `O_PATH` (`oPath`),
- carries other status flags than the ones allowed, such as `O_APPEND`
  on an image, `O_DIRECT`, or `O_NONBLOCK` on a pipe (`flags`, with the
  offending bits in `flags`),
- is opened for writing only (`writeOnly`),
- is not open read-write for a method that writes (`notReadWrite`),
- is not open read-only for a source or a manifest (`notReadOnly`),
- is not open for writing for a manifest sink (`notWritable`),
- is not of the type the parameter needs (`wrongType`).

All descriptors are checked, and the manifest is read and verified,
before the image is opened. A call that fails this way leaves the image
unchanged.

A block device is claimed exclusively while a writing call runs. A
mounted device, or one that another process has claimed, fails with
`ImageBusy`. The service takes no lock on a passed image file. The
caller is responsible for locking it.

A call can carry at most 253 descriptors. Descriptors cannot be passed
over standard input and output. In that mode, every method that takes an
image fails with `InvalidParameter`.

## Errors

The service returns no text. Every error is a name with typed fields.

| Error | When | Fields |
|---|---|---|
| `org.varlink.service.InvalidParameter` | A parameter is missing, unknown, of the wrong type or out of range. An index names no descriptor. The content does not fit the method. `Populate` of a manifest at a `path` other than `/`. `Remove` of the root. | `parameter` |
| `org.varlink.service.ExpectedMore` | `List` of a directory without the `more` flag. | none |
| `org.varlink.service.MethodNotFound` | An unknown method. | `method` |
| `BadFileDescriptor` | A passed descriptor does not meet the requirements. | `parameter`, `reason`, `flags` |
| `FileSystemTypeNotSupported` | A `fileSystemType` other than `vfat`. | `fileSystemType` |
| `OperationNotSupported` | `discard`, features or `repair` were requested. | `operation` |
| `SizeRequired` | `Assemble` without content into an empty file without a `size`. | none |
| `NotFileSystem` | The image holds no FAT32 file system. | `reason` (`blank`, `otherFileSystem`, `sectorSize`, `tooSmall`), `sectorSize` |
| `Corrupt` | The file system is damaged where the operation needs it. | `where` (`superblock`, `allocation`, `chain`, `directory`), `field`, `path`, `block` |
| `NoSpaceLeft` | The file system is full, or the cluster size leaves fewer than 65525 clusters. | `reason` (`blocks`, `directoryEntries`, `names`, `volume`), `path` |
| `TooSmall` | The content does not fit the `size` given to `Assemble`. | `minimalSizeBytes`, `sizeBytes` |
| `TooLarge` | A file is larger than FAT allows, or a volume has more clusters than FAT32 can address. | `path`, `sizeBytes`, `sizeMaxBytes` |
| `NoSuchFile` | A path does not exist. | `path` |
| `FileExists` | A file exists and `replace` is false, or a directory exists and `parents` is false. | `path` |
| `NotADirectory` | A path component is a file. | `path` |
| `IsADirectory` | `Populate` of a single file at a path that is a directory. | `path` |
| `DirectoryNotEmpty` | `Remove` of a directory with entries, without `recursive`. | `path` |
| `InvalidName` | A name FAT cannot store. | `name`, `reason` (`empty`, `dotComponent`, `invalidCharacter`, `leadingSpace`, `trailingSpaceOrDot`, `tooLong`) |
| `InvalidLabel` | A label that breaks the label rules. | `label`, `reason` (`tooLong`, `invalidCharacter`) |
| `InvalidIdentifier` | A serial number that is not `XXXX-XXXX` or eight hex digits. | `identifier`, `reason` (`malformed`) |
| `InvalidManifest` | The manifest cannot be parsed or is inconsistent. | `reason`, `record`, `name`, `field` |
| `SourceMismatch` | A file the manifest names is missing from the source directory, not a regular file, or of the wrong size. | `name`, `reason` (`missing`, `notRegular`, `size`), `sizeBytes`, `expectedSizeBytes` |
| `ContentMismatch` | Copied contents do not match the manifest. | `name`, `reason` (`size`, `hash`, `streamEnded`), `sizeBytes`, `expectedSizeBytes` |
| `ContentNotSupported` | Content FAT cannot store, with `unsupported` set to `fail`. | `what` (`url`, `encoding`, `offset`, `transport`, `subManifest`, `inodeType`), `name`, `value` |
| `EntryNotValid` | A manifest entry is revoked or outside its validity window. | `name`, `reason` (`revoked`, `notYetValid`, `expired`) |
| `NotReproducible` | `reproducible` without `identifier` or `timestampUSec`. | `reason` (`identifierRequired`, `timestampRequired`) |
| `ImageBusy` | The block device is mounted or claimed by another process. | none |
| `io.systemd.System` | Any other failure, such as an I/O error. | `errno`, `errnoName` |

The interface also declares `ContentRequired` and `ToolFailed`. The vfat
implementation never returns them.

## Running as a systemd service

The service opens no paths, so its unit can be locked down tightly:

    [Service]
    ExecStart=/usr/bin/ufat
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateDevices=yes
    PrivateTmp=yes
    PrivateNetwork=yes
    RestrictAddressFamilies=AF_UNIX
    RestrictNamespaces=yes
    RestrictRealtime=yes
    RestrictSUIDSGID=yes
    LockPersonality=yes
    MemoryDenyWriteExecute=yes
    ProtectKernelTunables=yes
    ProtectKernelModules=yes
    ProtectKernelLogs=yes
    ProtectControlGroups=yes
    ProtectClock=yes
    ProtectHostname=yes
    CapabilityBoundingSet=
    SystemCallArchitectures=native
    SystemCallFilter=@system-service
    SystemCallFilter=~@privileged @resources @mount @swap @reboot @clock @module @debug @cpu-emulation @obsolete
    UMask=0077
    MemoryMax=512M
    TasksMax=512

Notes:

- The caller opens images and devices and passes them in. The service
  needs no access to `/dev` and no writable path.
- A mounted block device is refused with `ImageBusy`. No exception for
  `/efi` or `/boot` is needed.
- Files below a passed directory are opened with the service's
  credentials. This is why only root and the service's own user may
  connect.
- Memory use does not grow with the volume. 512M leaves room for several
  connections.
- `DynamicUser=yes` works. Only root can then connect.
- Do not set `LimitFSIZE=`. A write past the limit kills the process with
  SIGXFSZ.

## Limits

- At most 256 connections are served at once. Further clients wait.
- A message can be at most 16 MiB. Pass large manifests as descriptors.
- A client that stops in the middle of a message for 30 seconds, or does
  not read a reply for 30 seconds, is disconnected. Idle connections are
  kept.
- `varlinkctl` gives up after 45 seconds by default. Use `--timeout=` for
  long writes. When the client gives up, the service still completes the
  operation in progress before it exits, so the image is not left half
  written.
- The service returns no file descriptors.
