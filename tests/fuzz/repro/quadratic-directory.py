#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Writes a well-formed UAPI.16 manifest with N entries in one directory, the
input that made `ufat assemble` take time quadratic in N while every create
rescanned the directory: 2000 entries 0.7 s, 4000 2.3 s, 8000 8.8 s, 16000
36 s, 50000 several minutes, with `ufat assemble --plan --manifest` on
the same manifest below 0.1 s. Fixed by the directory cache and index:
16000 entries now assemble in 0.15 s. Kept to check that it stays that
way.

    tests/fuzz/repro/quadratic-directory.py 16000 dir > many.Uapi16Manifest
    time ufat assemble --create --manifest many.Uapi16Manifest img - < /dev/null

With `dir` every entry is a directory (no contents needed); with `file`
every entry is an empty file whose contents come from the stream or from a
source directory; with `lossy` the files share one 8.3 alias prefix, which
adds the numeric-tail search on top (2000 files: 7.5 s before the index,
16000 files 0.17 s with it).
"""
import sys

n = int(sys.argv[1]) if len(sys.argv) > 1 else 16000
kind = sys.argv[2] if len(sys.argv) > 2 else "dir"
out = sys.stdout.buffer
RS = b"\x1e"
out.write(RS + b'{"mediaType":"application/vnd.uapi.16.manifest"}\n')
for i in range(n):
    if kind == "dir":
        out.write(RS + b'{"name":"d%d","type":"dir"}\n' % i)
    elif kind == "lossy":
        out.write(RS + b'{"name":"EFI/Linux/linux-6.12.%d-200.fc41.x86_64.efi","size":0}\n' % i)
    else:
        out.write(RS + b'{"name":"f%d","size":0}\n' % i)
out.write(RS + b'{"mediaType":"application/vnd.uapi.16.trailer"}\n')
