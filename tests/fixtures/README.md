# Manifest fixtures

Manifests written by systemd's own `systemd-manifest make`, so that the
reader, the planner, the assembler, the generator and the volume's
manifest writer are tested against what the reference implementation
actually emits rather than against records written by hand.
`tests/fixtures.rs` runs them.

`make-fixtures.sh` builds the trees and writes everything here; `VERSION`
records the systemd that did it. The fixtures were made with systemd
commit 4343b7c7d5 ("nsresourced: add an inode-based BPF policy") built
from a git checkout, with `--field` as listed below.

| case | manifests | tree | fields |
| --- | --- | --- | --- |
| `esp` | `Uapi16Manifest` | an ESP: boot loader, UKI, loader.conf, entries, random seed | default plus mtime |
| | `size-hash-mtime.Uapi16Manifest` | | size, hash, mtime: what ufat's own generator writes |
| | `none.Uapi16Manifest` | | names and types only |
| | `signed.Uapi16Manifest` | | default plus mtime, signed with a throwaway key |
| `special` | `Uapi16Manifest` | symlink, FIFO, hardlink pair, extended attribute, empty file and directory, read-only file, mixed case and non-ASCII names | default plus mtime, user and group names |
| `empty` | `Uapi16Manifest` | an empty directory | default plus mtime |

The `tree` directories are copies of what the manifests describe, as far
as git can hold it: the FIFO is missing, the hardlinks are two files, the
extended attribute is gone and the modification times are whatever the
checkout set. The tests take times from the manifests and skip the FIFO
and the symlink the way an assembly skips them.

The `cpio` directory holds the fixtures of ucpio: archives and what a
kernel unpacked them to. It has a README of its own.
