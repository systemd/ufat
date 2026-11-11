#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Regenerates the cpio fixtures by booting them:

    tests/fixtures/cpio/make-fixtures.py --kernel /boot/vmlinuz-...

Every case is an archive and what a kernel unpacked it to. The archives
are written here byte by byte, without ucpio, but for the ones named
made-*: those are ucpio's own, tests/cpio_made.rs writes them, and they
are booted as they are. An archive is appended to a small one that holds
nothing but an init (init.c), the kernel is booted on the two in qemu,
and the init lists the root file system. README.md describes the files
this leaves behind.

Needs qemu-system-x86_64, a C compiler that links statically and a kernel
image with CONFIG_BLK_DEV_INITRD, CONFIG_INITRAMFS_PRESERVE_MTIME and a
serial console built in.
"""

import argparse
import concurrent.futures
import gzip
import os
import stat
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# 2020-01-02T03:04:05Z, the time of everything that does not say otherwise.
T = 1577934245

REG = stat.S_IFREG
DIR = stat.S_IFDIR
LNK = stat.S_IFLNK
CHR = stat.S_IFCHR
BLK = stat.S_IFBLK
FIFO = stat.S_IFIFO
SOCK = stat.S_IFSOCK


class Archive:
    """Writes entries in the new ASCII format, right or wrong."""

    def __init__(self, magic=b"070701"):
        self.out = bytearray()
        self.magic = magic
        self.next_ino = 1

    def align(self, to=4):
        while len(self.out) % to:
            self.out.append(0)

    def entry(self, name, mode, data=b"", *, ino=None, nlink=None, uid=0, gid=0, mtime=T,
              dev=(0, 0), rdev=(0, 0), magic=None, check=None, size=None, namesize=None,
              name_pad=0, terminate=True, upper=False):
        if isinstance(name, str):
            name = name.encode()
        if ino is None:
            ino = self.next_ino
            self.next_ino += 1
        if nlink is None:
            nlink = 2 if stat.S_ISDIR(mode) else 1
        magic = magic or self.magic
        stored = name + (b"\0" if terminate else b"") + b"\0" * name_pad
        if check is None:
            check = sum(data) & 0xFFFFFFFF if magic == b"070702" and stat.S_ISREG(mode) else 0
        fields = (ino, mode, uid, gid, nlink, mtime, len(data) if size is None else size,
                  dev[0], dev[1], rdev[0], rdev[1], len(stored) if namesize is None else namesize, check)
        digits = "%08X" if upper else "%08x"
        self.out += magic + b"".join((digits % field).encode() for field in fields)
        self.out += stored
        self.align()
        self.out += data
        self.align()
        return ino

    def dir(self, name, mode=0o755, **kw):
        return self.entry(name, DIR | mode, **kw)

    def file(self, name, data=b"", mode=0o644, **kw):
        return self.entry(name, REG | mode, data, **kw)

    def symlink(self, name, target, **kw):
        return self.entry(name, LNK | 0o777, target, **kw)

    def char(self, name, rdev, mode=0o600, **kw):
        return self.entry(name, CHR | mode, rdev=rdev, **kw)

    def block(self, name, rdev, mode=0o660, **kw):
        return self.entry(name, BLK | mode, rdev=rdev, **kw)

    def fifo(self, name, mode=0o644, **kw):
        return self.entry(name, FIFO | mode, **kw)

    def socket(self, name, mode=0o755, **kw):
        return self.entry(name, SOCK | mode, **kw)

    def typeless(self, name, data=b"", **kw):
        return self.entry(name, 0, data, ino=0, mtime=0, **kw)

    def trailer(self, mode=0, data=b"", **kw):
        """The trailer as cpio(1) writes it."""
        return self.entry("TRAILER!!!", mode, data, ino=0, nlink=1, mtime=0, **kw)

    def raw(self, data):
        self.out += data

    def bytes(self):
        return bytes(self.out)


CASES = {}


def case(function):
    CASES[function.__name__.replace("_", "-")] = function
    return function


@case
def types():
    """One of everything, with the root stated."""
    a = Archive()
    a.dir(".", 0o751, uid=1, gid=2, mtime=T + 1)
    a.dir("d")
    a.file("d/file", b"contents\n")
    a.file("d/empty", b"", 0o600)
    a.file("d/suid", b"s", 0o4755)
    a.dir("d/sgid-dir", 0o2775)
    a.dir("d/sticky", 0o1777)
    a.file("d/owned", b"o", 0o640, uid=1234, gid=5678)
    a.file("d/max-owner", b"m", uid=0xFFFFFFFE, gid=0xFFFFFFFE)
    a.char("d/chr", (1, 3))
    a.block("d/blk", (8, 1))
    a.char("d/bigdev", (4095, 1048575))
    a.fifo("d/fifo")
    a.socket("d/sock")
    a.symlink("d/sym", b"file", uid=42, gid=43)
    a.symlink("d/dangling", b"nowhere/at/all")
    a.entry("d/sym-mode", LNK | 0o600, b"file")
    a.file("d/mtime-0", b"0", mtime=0)
    a.file("d/mtime-max", b"m", mtime=0xFFFFFFFF)
    a.dir("d/dir-mtime-max", mtime=0xFFFFFFFF)
    a.file("d/mode-0000", b"n", 0)
    a.file("d/mode-7777", b"a", 0o7777)
    a.dir("d/mode-dir-0000", 0)
    a.trailer()
    return a.bytes()


@case
def device_numbers():
    """Device numbers beyond the 12 and 20 bits the kernel keeps."""
    a = Archive()
    a.dir("d")
    a.char("d/major-4096", (4096, 0))
    a.char("d/major-4097", (4097, 5))
    a.char("d/minor-2-20", (0, 1 << 20))
    a.char("d/minor-2-20-plus", (7, (1 << 20) + 9))
    a.block("d/both-max", (0xFFFFFFFF, 0xFFFFFFFF))
    # The device number fields of a file that is no device.
    a.file("d/file-rdev", b"f", rdev=(1, 3))
    a.dir("d/dir-rdev", rdev=(1, 3))
    a.trailer()
    return a.bytes()


@case
def links():
    """Hard links."""
    a = Archive()
    a.dir("l")
    # The contents with the last name, the first, the one in the middle.
    for group, (ino, holder) in {"last": (100, 2), "first": (101, 0), "mid": (102, 1)}.items():
        for index, letter in enumerate("abc"):
            a.file("l/%s-%s" % (group, letter), group.encode() if index == holder else b"", ino=ino, nlink=3)
    # Contents with two names of one file.
    a.file("l/both-a", b"the first and longer", ino=103, nlink=2)
    a.file("l/both-b", b"second", ino=103, nlink=2)
    # Two names counted, one there.
    a.file("l/single", b"solo", ino=104, nlink=2)
    # One name counted, two entries with one inode number.
    a.file("l/one-a", b"1a", ino=105, nlink=1)
    a.file("l/one-b", b"1b", ino=105, nlink=1)
    # The inode number zero.
    a.file("l/zero-a", b"", ino=0, nlink=2)
    a.file("l/zero-b", b"zero", ino=0, nlink=2)
    # Nodes.
    a.char("l/chr-a", (1, 5), ino=106, nlink=2)
    a.char("l/chr-b", (1, 5), ino=106, nlink=2)
    a.char("l/chr-other-a", (1, 5), ino=107, nlink=2)
    a.char("l/chr-other-b", (1, 7), 0o666, ino=107, nlink=2, uid=9)
    a.fifo("l/fifo-a", ino=108, nlink=2)
    a.fifo("l/fifo-b", ino=108, nlink=2)
    a.socket("l/sock-a", ino=109, nlink=2)
    a.socket("l/sock-b", ino=109, nlink=2)
    # Symbolic links and directories are never linked.
    a.symlink("l/sym-a", b"single", ino=110, nlink=2)
    a.symlink("l/sym-b", b"single", ino=110, nlink=2)
    a.dir("l/dir-a", ino=111, nlink=2)
    a.dir("l/dir-b", ino=111, nlink=2)
    # One inode number, two types.
    a.file("l/mix-file", b"mix", ino=112, nlink=2)
    a.char("l/mix-chr", (1, 3), ino=112, nlink=2)
    a.file("l/mix-file-2", b"", ino=112, nlink=2)
    # One inode number on two devices.
    a.file("l/dev-a", b"dev a", ino=113, nlink=2, dev=(8, 1))
    a.file("l/dev-b", b"dev b", ino=113, nlink=2, dev=(8, 2))
    a.file("l/dev-a-2", b"", ino=113, nlink=2, dev=(8, 1))
    # More names counted than there are.
    a.file("l/count-a", b"", ino=114, nlink=5)
    a.file("l/count-b", b"count", ino=114, nlink=5)
    # Names in other directories, the owner and mode of every name.
    a.dir("l/x")
    a.dir("l/y")
    a.file("l/x/a", b"", 0o600, ino=115, nlink=2, uid=1, gid=1, mtime=1000)
    a.file("l/y/b", b"across", 0o644, ino=115, nlink=2, uid=2, gid=2, mtime=2000)
    # The attributes of a later name that brings no contents.
    a.file("l/attr-a", b"attr", 0o600, ino=116, nlink=2, uid=1, gid=1, mtime=1000)
    a.file("l/attr-b", b"", 0o644, ino=116, nlink=2, uid=2, gid=2, mtime=2000)
    # The same name twice in one group.
    a.file("l/twice", b"twice", ino=117, nlink=2)
    a.file("l/twice", b"", ino=117, nlink=2)
    # The first name gone, or a directory, by the time the second comes.
    a.file("l/gone-1", b"gone", ino=118, nlink=2)
    a.typeless("l/gone-1")
    a.file("l/gone-2", b"", ino=118, nlink=2)
    a.file("l/turned-1", b"turned", ino=119, nlink=2)
    a.dir("l/turned-1")
    a.file("l/turned-2", b"", ino=119, nlink=2)
    # A name whose directory is not there, then one that works.
    a.file("l/nowhere/lost", b"lost", ino=120, nlink=2)
    a.file("l/found", b"", ino=120, nlink=2)
    a.trailer()
    return a.bytes()


@case
def replace():
    """Later entries where earlier ones are."""
    a = Archive()
    a.dir("r")
    a.file("r/file-file", b"one", 0o600, uid=1, gid=1, mtime=1000)
    a.file("r/file-file", b"two!", 0o644, uid=2, gid=2, mtime=2000)
    a.file("r/file-shorter", b"longer contents")
    a.file("r/file-shorter", b"x")
    a.file("r/file-empty", b"data")
    a.file("r/file-empty", b"")
    # A new file under one name of a hard-linked file.
    a.file("r/link-1", b"", ino=100, nlink=2)
    a.file("r/link-2", b"old contents", ino=100, nlink=2)
    a.file("r/link-1", b"new!", 0o600, uid=3, mtime=3000)
    # A file where a symbolic link is, and what the link points to.
    a.file("r/victim", b"victim")
    a.symlink("r/sym-file", b"victim")
    a.file("r/sym-file", b"direct")
    a.file("r/file-sym", b"file")
    a.symlink("r/file-sym", b"victim")
    a.symlink("r/sym-sym", b"one")
    a.symlink("r/sym-sym", b"two", uid=4, mtime=4000)
    # Files and directories.
    a.file("r/file-dir", b"file")
    a.dir("r/file-dir", 0o700, mtime=5000)
    a.dir("r/dir-file", mtime=1000)
    a.file("r/dir-file", b"f", mtime=7000)
    a.dir("r/full-file", mtime=1000)
    a.file("r/full-file/child", b"c")
    a.file("r/full-file", b"lost", 0o600, uid=5, mtime=5000)
    a.dir("r/full-sym", mtime=1000)
    a.file("r/full-sym/child", b"c")
    a.symlink("r/full-sym", b"victim", uid=9, gid=9, mtime=6000)
    a.dir("r/full-node", mtime=1000)
    a.file("r/full-node/child", b"c")
    a.char("r/full-node", (1, 3), 0o600, uid=7, gid=8, mtime=5000)
    a.dir("r/dir-sym")
    a.symlink("r/dir-sym", b"victim")
    a.dir("r/dir-fifo")
    a.fifo("r/dir-fifo")
    a.symlink("r/sym-dir", b"victim")
    a.dir("r/sym-dir")
    # A directory stated twice.
    a.dir("r/dir-dir", 0o700, uid=1, gid=1, mtime=1000)
    a.dir("r/dir-dir", 0o755, uid=2, gid=2, mtime=2000)
    # Nodes.
    a.char("r/node-node", (1, 3), 0o600)
    a.char("r/node-node", (1, 5), 0o666, uid=3, mtime=T + 9)
    a.char("r/node-other", (1, 3))
    a.block("r/node-other", (8, 1))
    a.fifo("r/fifo-fifo", 0o600)
    a.fifo("r/fifo-fifo", 0o644, uid=5, mtime=5000)
    a.char("r/node-file", (1, 3))
    a.file("r/node-file", b"file")
    a.file("r/file-node", b"file")
    a.char("r/file-node", (1, 3))
    a.trailer()
    return a.bytes()


@case
def removal():
    """Entries without a file type."""
    a = Archive()
    a.dir("x")
    a.file("x/file", b"file")
    a.typeless("x/file")
    a.dir("x/empty-dir")
    a.typeless("x/empty-dir")
    a.dir("x/full-dir")
    a.file("x/full-dir/child", b"c")
    a.typeless("x/full-dir")
    a.symlink("x/sym", b"kept")
    a.typeless("x/sym")
    a.char("x/chr", (1, 3))
    a.typeless("x/chr")
    a.typeless("x/never-there")
    # With contents the entry is passed over.
    a.file("x/kept", b"kept")
    a.typeless("x/kept", b"data")
    # Permission bits and no type, and types that are none.
    a.file("x/perm-only", b"p")
    a.entry("x/perm-only", 0o644)
    for bits in (0o030000, 0o050000, 0o070000, 0o110000, 0o130000, 0o150000, 0o160000, 0o170000):
        name = "x/type-%06o" % bits
        a.file(name, b"t")
        a.entry(name, bits | 0o644)
    # A link count on such an entry, with the inode number of a file.
    a.file("x/linked-1", b"linked", ino=100, nlink=2)
    a.entry("x/linked-2", 0, ino=100, nlink=2)
    a.file("x/linked-3", b"", ino=100, nlink=2)
    a.trailer()
    return a.bytes()


@case
def names():
    """Names the kernel takes that are not in the form cpio(1) writes."""
    a = Archive()
    a.dir("n")
    a.file("./n/dot-slash", b"1")
    a.file("/n/absolute", b"2")
    a.file("n//double", b"3")
    a.file("n/./dot", b"4")
    a.file("././/n///./many", b"5")
    a.dir("n/sub/")
    a.file("n/sub/in-slashed-dir", b"6")
    a.dir("n/subdot/.")
    a.file("n/file-slash/", b"lost")
    a.symlink("n/sym-slash/", b"lost")
    a.fifo("n/fifo-slash/")
    a.file("n/missing/child", b"lost")
    a.file("n/notdir", b"7")
    a.file("n/notdir/child", b"lost")
    a.file("n/" + "a" * 255, b"8")
    a.file("n/" + "b" * 256, b"lost")
    a.dir("n/" + "c" * 256)
    a.file("", b"lost")
    a.file("n/TRAILER!!!", b"9")
    a.file("./TRAILER!!!", b"10")
    a.file("n/upper", b"11", upper=True)
    a.file("n/padded", b"12", name_pad=5)
    a.file("n/padded-more", b"13", name_pad=600)
    a.file("n/space name", b"14")
    a.file(b"n/latin-\xe9", b"15")
    a.file(b"n/utf8-\xc3\xa9", b"16")
    a.file(b"n/bytes-\xff\xfe", b"17")
    a.file("n/new\nline", b"18")
    a.file("n/back\\slash", b"19")
    a.file("n/...", b"20")
    a.file("n/.hidden", b"21")
    # What follows a NUL byte in a name is not part of it.
    a.file(b"n/cut\0tail", b"22")
    a.trailer()
    return a.bytes()


@case
def names_dotdot():
    """Names with '..' in them."""
    a = Archive()
    a.dir("n")
    a.dir("n/sub")
    a.file("n/sub/../up", b"1")
    a.file("n/sub/../../top", b"2")
    a.file("../outside", b"3")
    a.dir("n/sub/..", 0o700, mtime=1000)
    a.trailer()
    return a.bytes()


@case
def names_symlink():
    """Names that lead through a symbolic link."""
    a = Archive()
    a.dir("n")
    a.dir("n/real")
    a.symlink("n/link", b"real")
    a.file("n/link/through", b"1")
    a.symlink("n/abs", b"/n/real")
    a.file("n/abs/through-abs", b"2")
    a.symlink("n/dangling", b"nowhere")
    a.file("n/dangling/lost", b"lost")
    a.symlink("n/to-file", b"real/through")
    a.file("n/to-file/lost", b"lost")
    a.trailer()
    return a.bytes()


@case
def names_directory():
    """Names that end in a slash or in '.', where something is already."""
    a = Archive()
    a.dir("d")
    # A slash at the end.
    a.dir("d/slash-empty-file")
    a.file("d/slash-empty-file/", b"lost")
    a.dir("d/slash-empty-typeless")
    a.typeless("d/slash-empty-typeless/")
    a.dir("d/slash-empty-sym")
    a.symlink("d/slash-empty-sym/", b"lost")
    a.dir("d/slash-empty-fifo")
    a.fifo("d/slash-empty-fifo/")
    a.dir("d/slash-full-file")
    a.file("d/slash-full-file/child", b"c")
    a.file("d/slash-full-file/", b"lost", 0o600, uid=5)
    a.dir("d/slash-full-sym")
    a.file("d/slash-full-sym/child", b"c")
    a.symlink("d/slash-full-sym/", b"lost", uid=9, gid=9)
    a.dir("d/slash-full-chr")
    a.file("d/slash-full-chr/child", b"c")
    a.char("d/slash-full-chr/", (1, 3), 0o600, uid=7, gid=8)
    a.dir("d/slash-dir", 0o755)
    a.dir("d/slash-dir/", 0o700, uid=3, mtime=1000)
    a.file("d/slash-file-typeless", b"kept")
    a.typeless("d/slash-file-typeless/")
    a.file("d/slash-file-dir", b"kept")
    a.dir("d/slash-file-dir/")
    a.file("d/slash-file-file", b"kept")
    a.file("d/slash-file-file/", b"lost")
    a.symlink("d/slash-sym-typeless", b"slash-dir")
    a.typeless("d/slash-sym-typeless/")
    # A '.' at the end.
    a.dir("d/dot-empty-file")
    a.file("d/dot-empty-file/.", b"lost", 0o600, uid=5)
    a.dir("d/dot-empty-typeless")
    a.typeless("d/dot-empty-typeless/.")
    a.dir("d/dot-empty-sym")
    a.symlink("d/dot-empty-sym/.", b"lost", uid=9, gid=9, mtime=6000)
    a.dir("d/dot-empty-chr")
    a.char("d/dot-empty-chr/.", (1, 3), 0o600, uid=7, gid=8, mtime=5000)
    a.dir("d/dot-dir", 0o755)
    a.dir("d/dot-dir/.", 0o700, uid=3, mtime=1000)
    a.dir("d/dot-dir-slash", 0o755)
    a.dir("d/dot-dir-slash/./", 0o700, uid=3, mtime=1000)
    a.dir("d/dot-missing/.")
    a.file("d/dot-file-dir", b"kept")
    a.dir("d/dot-file-dir/.")
    a.file("d/dot-file-typeless", b"kept")
    a.typeless("d/dot-file-typeless/.")
    a.file("d/dot-file-file", b"kept")
    a.file("d/dot-file-file/.", b"lost")
    # A directory made under such a name is there for what comes behind.
    a.dir("d/made/")
    a.file("d/made/child", b"c")
    a.trailer()
    return a.bytes()


@case
def links_lost_first():
    """Hard-linked files whose first name the kernel could not make."""
    a = Archive()
    a.dir("l")
    # No directory for the first name.
    a.file("l/nowhere/first", b"lost", ino=100, nlink=3)
    a.file("l/second", b"", ino=100, nlink=3)
    a.file("l/third", b"contents", ino=100, nlink=3)
    # A first name no lookup takes.
    a.file("l/" + "x" * 256, b"lost", ino=101, nlink=2)
    a.file("l/after-long", b"", ino=101, nlink=2)
    a.file("l/slash/", b"lost", ino=102, nlink=2)
    a.file("l/after-slash", b"", ino=102, nlink=2)
    # A directory with something in it where the first name wants to be.
    a.dir("l/full")
    a.file("l/full/child", b"c")
    a.file("l/full", b"lost", ino=103, nlink=2)
    a.file("l/after-full", b"", ino=103, nlink=2)
    # Nodes.
    a.char("l/nowhere/chr", (1, 3), ino=104, nlink=2)
    a.char("l/after-chr", (1, 3), ino=104, nlink=2)
    # An entry the kernel passes over is not a first name.
    a.entry("l/passed", CHR | 0o600, b"data", rdev=(1, 3), ino=105, nlink=2)
    a.char("l/after-passed-a", (1, 3), ino=105, nlink=2)
    a.char("l/after-passed-b", (1, 3), ino=105, nlink=2)
    # Nor is a directory or a symbolic link.
    a.symlink("l/sym", b"second", ino=106, nlink=2)
    a.entry("l/after-sym", LNK | 0o777, b"second", ino=106, nlink=2)
    # The first name comes late: a link to it then works.
    a.file("l/late/first", b"lost", ino=107, nlink=3)
    a.dir("l/late")
    a.file("l/late/first", b"late", ino=107, nlink=3)
    a.file("l/late-other", b"", ino=107, nlink=3)
    a.trailer()
    return a.bytes()


@case
def symlink_targets():
    """Targets at the limit, where something is already."""
    a = Archive()
    a.dir("s")
    long = b"t" * 4096
    a.file("s/long-over-file", b"file")
    a.symlink("s/long-over-file", long)
    a.dir("s/long-over-empty")
    a.symlink("s/long-over-empty", long)
    a.dir("s/long-over-full")
    a.file("s/long-over-full/child", b"c")
    a.symlink("s/long-over-full", long, uid=9, gid=9, mtime=6000)
    a.symlink("s/long-over-sym", b"short")
    a.symlink("s/long-over-sym", long)
    # A NUL byte makes the target shorter than its field.
    a.symlink("s/nul-4096", b"short\0" + b"t" * 4090)
    a.symlink("s/nul-4097", b"short\0" + b"t" * 4091)
    a.symlink("s/nul-last", b"t" * 4095 + b"\0")
    # Beyond the limit the entry is passed over and nothing goes.
    a.file("s/longer-over-file", b"kept")
    a.symlink("s/longer-over-file", b"t" * 4097)
    a.trailer()
    return a.bytes()


@case
def long_names():
    """The longest name the kernel takes, and one byte more."""
    a = Archive()
    a.dir("long")
    path = "long"
    while len(path) + 256 <= 4095 - 2:
        path += "/" + "d" * 255
        a.dir(path)
    rest = 4095 - len(path) - 1
    a.file(path + "/" + "f" * rest, b"fits")
    a.file(path + "/" + "g" * (rest + 1), b"lost")
    a.file("after", b"after")
    a.trailer()
    return a.bytes()


@case
def skipped():
    """Entries the kernel passes over."""
    a = Archive()
    a.dir("s")
    a.entry("s/dir-data", DIR | 0o755, b"data")
    a.file("s/dir-data/child", b"lost")
    a.entry("s/chr-data", CHR | 0o600, b"data", rdev=(1, 3))
    a.entry("s/fifo-data", FIFO | 0o644, b"data")
    a.entry("s/sock-data", SOCK | 0o644, b"data")
    a.typeless("s/typeless-data", b"data")
    a.symlink("s/sym-4095", b"t" * 4095)
    a.symlink("s/sym-4096", b"t" * 4096)
    a.symlink("s/sym-4097", b"t" * 4097)
    a.symlink("s/sym-empty", b"")
    a.symlink("s/sym-nul", b"cut\0tail")
    a.symlink("s/sym-nul-first", b"\0tail")
    # A name size of zero, and one above the limit.
    a.entry(b"", REG | 0o644, b"data", terminate=False, namesize=0)
    a.entry("s/" + "n" * 4094, REG | 0o644, b"lost")
    a.entry("s/" + "n" * 4095, REG | 0o644, b"lost")
    # An existing file is left alone by an entry that is passed over.
    a.file("s/kept", b"kept")
    a.entry("s/kept", DIR | 0o755, b"data")
    a.file("s/after", b"after")
    a.trailer()
    return a.bytes()


def around_trailer(trailer):
    """A hard-linked file with a name before and a name behind a trailer."""
    a = Archive()
    a.dir("t")
    a.file("t/before", b"before", ino=100, nlink=2)
    trailer(a)
    a.file("t/behind", b"", ino=100, nlink=2)
    a.file("t/last", b"last")
    a.trailer()
    return a.bytes()


@case
def trailer_plain():
    return around_trailer(lambda a: a.trailer())


@case
def trailer_typeless_data():
    return around_trailer(lambda a: a.trailer(data=b"data"))


@case
def trailer_file():
    return around_trailer(lambda a: a.trailer(REG | 0o644))


@case
def trailer_file_data():
    return around_trailer(lambda a: a.trailer(REG | 0o644, b"data of the trailer"))


@case
def trailer_directory():
    return around_trailer(lambda a: a.trailer(DIR | 0o755))


@case
def trailer_directory_data():
    return around_trailer(lambda a: a.trailer(DIR | 0o755, b"data"))


@case
def trailer_symlink():
    return around_trailer(lambda a: a.trailer(LNK | 0o777, b"before"))


@case
def trailer_node():
    return around_trailer(lambda a: a.trailer(CHR | 0o600, rdev=(1, 3)))


@case
def trailer_padded_name():
    return around_trailer(lambda a: a.trailer(name_pad=9))


@case
def trailer_dot_slash():
    return around_trailer(lambda a: a.entry("./TRAILER!!!", 0, ino=0, mtime=0))


@case
def trailer_slash():
    return around_trailer(lambda a: a.entry("TRAILER!!!/", 0, ino=0, mtime=0))


@case
def end_no_trailer():
    a = Archive()
    a.dir("e")
    a.file("e/a", b"", ino=100, nlink=2)
    a.file("e/b", b"linked", ino=100, nlink=2)
    return a.bytes()


@case
def end_no_trailer_padded():
    return end_no_trailer() + bytes(512)


@case
def end_gap():
    """NUL bytes between entries, a multiple of four of them."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"", ino=100, nlink=2)
    a.raw(bytes(8))
    a.file("e/b", b"linked", ino=100, nlink=2)
    a.raw(bytes(4096))
    a.file("e/c", b"c")
    a.trailer()
    return a.bytes()


@case
def end_gap_misaligned():
    """NUL bytes between entries that leave the next one off a multiple of four."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.raw(bytes(6))
    a.file("e/lost", b"lost")
    a.trailer()
    return a.bytes()


def cut(length):
    """An archive cut short `length` bytes into its last entry."""
    a = Archive()
    a.dir("e")
    a.file("e/whole", b"whole")
    start = len(a.out)
    a.file("e/cut", b"0123456789abcdefghijklmnopqrstuvwxyz")
    return a.bytes()[:start + length]


@case
def end_cut_header():
    return cut(50)


@case
def end_cut_name():
    return cut(110 + 3)


@case
def end_cut_data():
    return cut(110 + 6 + 10)


@case
def end_cut_padding():
    """Everything of the last entry but the padding behind its contents."""
    a = Archive()
    a.dir("e")
    a.file("e/whole", b"whole")
    a.file("e/cut", b"12345")
    return a.bytes()[:-3]


@case
def end_junk():
    """Something that is no archive behind the trailer."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.trailer()
    a.raw(b"junk")
    return a.bytes()


@case
def end_junk_padded():
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.trailer()
    a.raw(bytes(512) + b"junk")
    return a.bytes()


@case
def end_second_archive():
    """An archive behind the trailer, which has names of the first one."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"first", ino=100, nlink=2)
    a.file("e/over", b"first")
    a.trailer()
    a.align(512)
    a.file("e/b", b"", ino=100, nlink=2)
    a.file("e/over", b"second")
    a.file("e/c", b"c")
    a.trailer()
    return a.bytes()


def followed(behind):
    """An archive with `behind` after its trailer."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.trailer()
    return a.bytes() + behind


def second():
    a = Archive()
    a.file("e/second", b"second")
    a.trailer()
    return a.bytes()


@case
def end_follower_old():
    """An archive in the old ASCII format behind the trailer."""
    a = Archive(b"070707")
    a.file("e/second", b"second")
    a.trailer()
    return followed(a.bytes())


@case
def end_follower_misaligned():
    """An archive behind the trailer, off a multiple of four."""
    return followed(bytes(2) + second())


@case
def end_follower_short():
    """The start of an entry behind the trailer, and nothing more."""
    return followed(b"0707")


@case
def end_follower_zero():
    """Something that starts like an entry and is none."""
    return followed(b"0" * 200)


@case
def end_follower_compressed():
    """A compressed archive behind the trailer and its padding."""
    return followed(bytes(388) + gzip.compress(second(), mtime=0))


@case
def end_follower_compressed_misaligned():
    return followed(bytes(2) + gzip.compress(second(), mtime=0))


@case
def end_stopper():
    """An entry whose first byte is no '0', with entries behind it."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    start = len(a.out)
    a.file("e/lost", b"lost")
    a.out[start] = ord("X")
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def end_magic_old():
    """An entry in the old ASCII format in the middle."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.file("e/lost", b"lost", magic=b"070707")
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def end_magic_none():
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.file("e/lost", b"lost", magic=b"070703")
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def end_field():
    """A header field that is not hexadecimal."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    start = len(a.out)
    a.file("e/lost", b"lost")
    a.out[start + 6 + 8 * 5 + 3] = ord("g")
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def end_unterminated():
    """A name without its NUL byte."""
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.file("e/lost", b"lost", terminate=False)
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def end_unterminated_symlink():
    a = Archive()
    a.dir("e")
    a.file("e/a", b"a")
    a.symlink("e/lost", b"a", terminate=False)
    a.file("e/after", b"after")
    a.trailer()
    return a.bytes()


@case
def crc():
    """The form with checksums."""
    a = Archive(b"070702")
    a.dir("c")
    a.file("c/file", b"checked contents")
    a.file("c/empty", b"")
    a.file("c/a", b"", ino=100, nlink=2)
    a.file("c/b", b"linked", ino=100, nlink=2)
    # A checksum where the kernel does not look at it.
    a.dir("c/dir", check=0x1234)
    a.symlink("c/sym", b"file", check=0x1234)
    a.char("c/chr", (1, 3), check=0x1234)
    # The two forms in one archive.
    a.file("c/newc", b"no checksum", magic=b"070701")
    a.file("c/newc-check", b"a checksum that is not looked at", magic=b"070701", check=0x1234)
    a.file("c/again", b"checked again")
    a.trailer()
    return a.bytes()


@case
def crc_wrong():
    """A checksum that is not the sum of the contents."""
    a = Archive(b"070702")
    a.dir("c")
    a.file("c/good", b"good")
    a.file("c/bad", b"bad contents", check=1)
    a.file("c/after", b"after")
    a.trailer()
    return a.bytes()


@case
def crc_wrong_link():
    """A wrong checksum with a name that brings no contents."""
    a = Archive(b"070702")
    a.dir("c")
    a.file("c/a", b"", ino=100, nlink=2, check=7)
    a.file("c/b", b"linked", ino=100, nlink=2)
    a.file("c/after", b"after")
    a.trailer()
    return a.bytes()


@case
def root_unstated():
    a = Archive()
    a.file("file", b"file")
    a.trailer()
    return a.bytes()


@case
def root_twice():
    a = Archive()
    a.dir(".", 0o700, uid=1, gid=1, mtime=1000)
    a.file("file", b"file")
    a.dir(".", 0o750, uid=2, gid=2, mtime=2000)
    a.trailer()
    return a.bytes()


@case
def root_slash():
    a = Archive()
    a.dir("/", 0o750, uid=2, gid=2, mtime=2000)
    a.file("file", b"file")
    a.trailer()
    return a.bytes()


@case
def root_dot_slash():
    a = Archive()
    a.dir("./", 0o750, uid=2, gid=2, mtime=2000)
    a.file("file", b"file")
    a.trailer()
    return a.bytes()


@case
def root_not_directory():
    """Entries for the root that are no directory."""
    a = Archive()
    a.file(".", b"lost", 0o600, uid=3, mtime=3000)
    a.symlink(".", b"lost", uid=4, mtime=4000)
    a.char(".", (1, 3), 0o640, uid=5, gid=5, mtime=5000)
    a.typeless(".")
    a.file("file", b"file")
    a.trailer()
    return a.bytes()


@case
def root_node_last():
    """A node entry for the root with nothing behind it."""
    a = Archive()
    a.file("file", b"file")
    a.char(".", (1, 3), 0o640, uid=5, gid=6, mtime=5000)
    a.trailer()
    return a.bytes()


@case
def root_symlink_last():
    a = Archive()
    a.file("file", b"file")
    a.symlink(".", b"lost", uid=4, gid=3, mtime=4000)
    a.trailer()
    return a.bytes()


@case
def root_node_then_directory():
    a = Archive()
    a.char(".", (1, 3), 0o640, uid=5, gid=6, mtime=5000)
    a.dir(".", 0o711, uid=1, gid=2, mtime=1000)
    a.symlink(".", b"lost", uid=4, gid=3, mtime=4000)
    a.trailer()
    return a.bytes()


@case
def directory_times():
    """The times of directories, which the kernel sets last."""
    a = Archive()
    a.dir("t")
    # An entry that made no directory, and the one that did.
    a.dir("t/late/sub", mtime=1000)
    a.dir("t/late", mtime=2000)
    a.dir("t/late/sub", mtime=3000)
    # A directory that went and came back.
    a.dir("t/again", mtime=1000)
    a.typeless("t/again")
    a.dir("t/again", mtime=2000)
    # What took the place of a directory.
    a.dir("t/file", mtime=1000)
    a.file("t/file", b"f", mtime=7000)
    a.file("t/target", b"target", mtime=3000)
    a.dir("t/sym", mtime=1000)
    a.symlink("t/sym", b"target", mtime=2000)
    a.dir("t/fifo", mtime=1000)
    a.fifo("t/fifo", mtime=2000)
    a.dir("t/gone", mtime=1000)
    a.typeless("t/gone")
    # A file first, then the directory.
    a.file("t/file-first", b"f", mtime=4000)
    a.dir("t/file-first", mtime=5000)
    # A directory that is written into after it was made.
    a.dir("t/busy", mtime=1000)
    a.file("t/busy/child", b"c", mtime=2000)
    # The same directory under other names.
    a.dir("t/forms", mtime=1000)
    a.dir("t/forms/", mtime=2000)
    a.dir("./t/forms", mtime=3000)
    a.dir("t/forms-late/", mtime=1000)
    a.dir("t/forms-late", mtime=2000)
    a.trailer()
    return a.bytes()


@case
def builtin():
    """What the kernel's own archive put there before: /dev and /root."""
    a = Archive()
    a.char("dev/null", (1, 3), 0o666)
    a.file("root/file", b"file")
    a.trailer()
    return a.bytes()


def run(command, **kw):
    return subprocess.run(command, check=True, stdin=subprocess.DEVNULL, **kw)


def harness(init):
    """The archive that brings the init. It ends at a multiple of four so
    that the case behind it starts where an archive of its own would."""
    a = Archive()
    a.dir(".harness", 0o700)
    with open(init, "rb") as f:
        a.file(".harness/init", f.read(), 0o700)
    a.trailer()
    a.align(4096)
    return a.bytes()


def boot(args, work, name, image):
    """Boots `image` and returns what the init listed, as lines."""
    path = os.path.join(work, name)
    with open(path + ".img", "wb") as f:
        f.write(image)
    open(path + ".out", "wb").close()
    kvm = os.access("/dev/kvm", os.R_OK | os.W_OK)
    command = [
        args.qemu, "-m", "512M", "-nographic", "-no-reboot", "-nodefaults", "-display", "none",
        "-serial", "file:" + path + ".log", "-serial", "file:" + path + ".out",
        "-kernel", args.kernel, "-initrd", path + ".img",
        "-append", "console=ttyS0 panic=-1 rdinit=/.harness/init",
    ]
    command += ["-enable-kvm", "-cpu", "host"] if kvm else ["-cpu", "max"]
    start = int(time.time())
    subprocess.run(command, check=True, stdin=subprocess.DEVNULL, timeout=120 if kvm else 900)
    end = int(time.time())
    with open(path + ".out", "rb") as f:
        lines = f.read().decode("ascii").splitlines()
    if not lines or lines[-1] != "# end" or not lines[0].startswith("# "):
        sys.exit("%s: the boot did not get to the end of its listing, see %s.log" % (name, path))
    version = lines[0][2:]
    listing = []
    for line in lines[1:-1]:
        # The kernel says this of every archive.
        if line == "! Trying to unpack rootfs image as initramfs...":
            continue
        fields = line.split(" ")
        for index, field in enumerate(fields):
            # A time the kernel did not take from the archive.
            if field.startswith("mtime=") and start - 5 <= int(field[6:]) <= end + 5:
                fields[index] = "mtime=boot"
        listing.append(" ".join(fields))
    return version, listing


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--kernel", required=True, help="the kernel image to boot")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--keep", help="a directory to keep the boot images and logs in")
    parser.add_argument("cases", nargs="*", help="the cases to make, all of them when none is named")
    args = parser.parse_args()
    # The archives ucpio wrote, see tests/cpio_made.rs. They are booted as
    # they are.
    made = {}
    for entry in sorted(os.listdir(HERE)):
        stem, extension = os.path.splitext(entry)
        if stem.startswith("made-") and extension == ".cpio":
            with open(os.path.join(HERE, entry), "rb") as f:
                made[stem] = f.read()
    unknown = [name for name in args.cases if name not in CASES and name not in made]
    if unknown:
        sys.exit("no such case: " + ", ".join(unknown))
    selected = args.cases or sorted(CASES) + sorted(made)

    with tempfile.TemporaryDirectory() as temporary:
        work = args.keep or temporary
        os.makedirs(work, exist_ok=True)
        init = os.path.join(work, "init")
        run([args.cc, "-static", "-O2", "-Wall", "-Wextra", "-o", init, os.path.join(HERE, "init.c")])
        first = harness(init)
        # What is there without a case: the kernel's own archive. Its
        # lines are left out of every listing they are in unchanged.
        version, baseline = boot(args, work, "baseline", first)
        baseline = set(line for line in baseline if not line.startswith(". "))

        def make(name):
            archive = made[name] if name in made else CASES[name]()
            booted, listing = boot(args, work, name, first + archive)
            if booted != version:
                sys.exit("%s: booted another kernel" % name)
            listing = [line for line in listing if line not in baseline]
            return name, archive, listing

        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            for name, archive, listing in pool.map(make, selected):
                if name not in made:
                    with open(os.path.join(HERE, name + ".cpio"), "wb") as f:
                        f.write(archive)
                with open(os.path.join(HERE, name + ".unpacked"), "w") as f:
                    f.write("".join(line + "\n" for line in listing))
                print("%-28s %6d bytes, %3d lines" % (name, len(archive), len(listing)))
        if not args.cases:
            # Cases that are gone leave no files behind.
            for entry in sorted(os.listdir(HERE)):
                stem, extension = os.path.splitext(entry)
                if extension in (".cpio", ".unpacked") and stem not in CASES and stem not in made:
                    os.remove(os.path.join(HERE, entry))
            with open(os.path.join(HERE, "VERSION"), "w") as f:
                f.write(version + "\n")


if __name__ == "__main__":
    main()
