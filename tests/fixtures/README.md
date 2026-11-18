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

The fixtures were made with a systemd-manifest from before systemd
commits 118717cfe2, 330fab5e90 and e83f7bce0c, which are not in a
release yet.

That systemd-manifest does not write the `features` and `order` fields
of the root file object. UAPI.16 has them since uapi-group/specifications
pull request 253, and a manifest that records other than the default
fields has to list its features. systemd-manifest writes the features
since 118717cfe2 and the order since 330fab5e90. `make-fixtures.sh`
adds both to every manifest after systemd-manifest wrote it: the
features its `--field` records and the code point ordering it is sorted
in. This changes the bytes the signature of `signed.Uapi16Manifest`
covers, so the signature no longer matches them.

That systemd-manifest also writes the hash of no data for a file of size
0. UAPI.16 recommends to leave it out, ufat leaves it out, and
systemd-manifest does since e83f7bce0c. `make-fixtures.sh` takes it out
of the file objects of size 0, which is the file `empty` of the
`special` case. The other file objects stay as systemd-manifest wrote
them.

The `tree` directories are copies of what the manifests describe, as far
as git can hold it: the FIFO is missing, the hardlinks are two files, the
extended attribute is gone and the modification times are whatever the
checkout set. The tests take times from the manifests and skip the FIFO
and the symlink the way an assembly skips them.
