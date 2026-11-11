# cpio fixtures

Archives, and what a kernel unpacked each of them to. The kernel's
unpacker is the reference for ucpio, the way `systemd-manifest` is the
reference for the manifest fixtures next to this directory. Nothing here
is written by hand: `make-fixtures.py` boots every archive and records
what the kernel made of it.

Every case is two files:

- `<case>.cpio`, the archive.
- `<case>.unpacked`, the root file system after a kernel unpacked the
  archive, and what the kernel logged about it.

`VERSION` has the banner of the kernel that was booted. The fixtures
were made with Debian's kernel 7.2.12-1 for amd64. It is built with
`CONFIG_INITRAMFS_PRESERVE_MTIME`, it has a tmpfs as its root file system
and the default archive built in.

## The tests that use them

- tests/cpio_kernel.rs holds what ucpio says an archive unpacks to
  against the listing, for every case.

## The cases

The cases are written by `make-fixtures.py` itself, byte by byte and
without ucpio. Many of them are archives that no tool writes.

| cases | what is in them |
| --- | --- |
| `types` | one of everything, with the root stated |
| `device-numbers` | device numbers beyond the bits the kernel keeps |
| `links`, `links-lost-first` | hard links |
| `replace` | later entries where earlier ones are |
| `removal` | entries without a file type |
| `names`, `names-dotdot`, `names-symlink`, `names-directory`, `long-names` | names in other forms than cpio writes |
| `skipped`, `symlink-targets` | entries the kernel passes over, targets at the limit |
| `directory-times` | the times of directories |
| `root-*` | entries for the root directory |
| `trailer-*` | trailers with a mode, data or another name, in the middle of an archive |
| `end-*` | archives that are cut short, damaged, or followed by something |
| `crc`, `crc-wrong`, `crc-wrong-link` | the form with checksums |
| `builtin` | entries below the directories the kernel has before it unpacks anything |

## Making them again

    tests/fixtures/cpio/make-fixtures.py --kernel /boot/vmlinuz-...

This needs qemu-system-x86_64, a C compiler that links statically and a
kernel image with `CONFIG_BLK_DEV_INITRD`,
`CONFIG_INITRAMFS_PRESERVE_MTIME` and a serial console built in. It takes
the names of cases to make only those. `--keep DIR` keeps the boot images
and the console logs.

## How a case is booted

The archive is appended to a first archive that holds nothing but
`/.harness/init`, built from `init.c`. The kernel unpacks the two, one
after the other, and runs that init. It lists the root file system to
the second serial port and powers the machine off.

## The listings

A listing has one line for every name, a directory right before what is
in it, the entries of a directory sorted by the bytes of their names:

    name type key=value ...

- `name` is the path below the root, `.` for the root. Bytes outside of
  `!` to `~` and the backslash are written as `\xNN`.
- `type` is `d` for a directory, `f` for a regular file, `l` for a
  symbolic link, `c` and `b` for device nodes, `p` for a FIFO and `s` for
  a socket.
- `mode=` has the permission bits in octal. A symbolic link has none.
- `uid=`, `gid=` and `mtime=` are the owner and the modification time in
  seconds. `mtime=boot` stands for a time the kernel did not take from
  the archive: the time of the boot.
- `nlink=` is the number of names of what is no directory. `link=` names
  the first name in the listing of a file that has several.
- `size=`, `sum=` and `head=` are the length of a regular file, the sum
  of its bytes modulo 2^32 and its first 16 bytes, both in hexadecimal.
- `target=` is the target of a symbolic link.
- `rdev=` is the device number of a device node, major and minor.

Lines that start with `! ` come first. They are what the kernel logged
about the archive.

Left out of a listing are `/.harness` and the lines of `/dev`,
`/dev/console` and `/root` as long as they are what a boot without a case
shows. The kernel has these three before it unpacks anything: they come
from the archive that is built into it.
