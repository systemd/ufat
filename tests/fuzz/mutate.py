#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Mutation-based robustness campaign for the ufat binary.

Variants of seed FAT32 images and UAPI.16 manifests are produced with
random and targeted mutations and run through the command line tool. Every
run records the exit status or signal, the peak RSS, the wall time, the
stderr tail and the image size before and after. A clean outcome is exit 0
or exit 1 with a message; for `fsck`, which uses the fsck(8) codes, exit 4
(problems found and left as they are) and exit 8 (the image could not be
checked) are clean as well. A panic (exit 101), a signal, a timeout, an
outsized RSS, any other exit status or an image that changed size is a
defect and is saved under OUT/findings/<signature>/ together with the
mutated bytes and the edit list that reproduces it from the seed.

    tests/fuzz/mutate.py images   --ufat build/ufat --seeds SEEDS --out OUT --count N
    tests/fuzz/mutate.py manifests --ufat build/ufat --seeds SEEDS --out OUT --count N

SEEDS is what tests/fuzz/seeds.sh writes. Python 3 standard library only.
"""

import argparse
import json
import os
import random
import re
import resource
import shutil
import signal
import struct
import sys
import time
import multiprocessing

# ----------------------------------------------------------------- helpers

RS = b"\x1e"


def le16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def le32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def p16(v):
    return struct.pack("<H", v & 0xFFFF)


def p32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def apply_edits(seed, edits):
    """Edits are ("w", offset, bytes) writes and ("len", n) truncations or
    extensions (zero filled). Applied in order."""
    data = bytearray(seed)
    for e in edits:
        if e[0] == "w":
            _, off, blob = e
            blob = bytes(blob)
            if off >= len(data):
                continue
            end = min(len(data), off + len(blob))
            data[off:end] = blob[: end - off]
        elif e[0] == "len":
            n = e[1]
            if n < len(data):
                del data[n:]
            else:
                data.extend(b"\0" * (n - len(data)))
    return bytes(data)


def edits_to_json(edits):
    out = []
    for e in edits:
        if e[0] == "w":
            out.append({"w": e[1], "hex": bytes(e[2]).hex()})
        else:
            out.append({"len": e[1]})
    return out


# ----------------------------------------------------------------- FAT32 parser

class Fat32:
    """A tolerant reader of the seed images, used to aim mutations."""

    def __init__(self, data):
        self.data = data
        b = data
        self.bps = le16(b, 11)
        self.spc = b[13]
        self.reserved = le16(b, 14)
        self.fats = b[16]
        self.total = le16(b, 19) or le32(b, 32)
        self.fat_sectors = le32(b, 36)
        self.root_cluster = le32(b, 44)
        self.fsinfo = le16(b, 48)
        self.backup = le16(b, 50)
        self.cluster_size = self.bps * self.spc
        self.fat_off = [(self.reserved + i * self.fat_sectors) * self.bps for i in range(self.fats)]
        self.data_off = (self.reserved + self.fats * self.fat_sectors) * self.bps
        self.clusters = max(1, (self.total * self.bps - self.data_off) // self.cluster_size)
        self.max_cluster = self.clusters + 1
        self.dirs = []    # (path, first_cluster, chain, [slot offsets])
        self.entries = [] # dicts: path, off (short entry), lfn (offsets), is_dir, first, size, name, dir_cluster
        self.files = []
        self.used = set()
        self.walk()

    def cluster_off(self, c):
        return self.data_off + (c - 2) * self.cluster_size

    def fat_entry_off(self, c, copy=0):
        return self.fat_off[copy] + 4 * c

    def fat_get(self, c):
        return le32(self.data, self.fat_entry_off(c)) & 0x0FFFFFFF

    def chain(self, first):
        out = []
        c = first
        seen = set()
        while 2 <= c <= self.max_cluster and c not in seen and len(out) <= self.clusters:
            out.append(c)
            seen.add(c)
            c = self.fat_get(c)
            if c >= 0x0FFFFFF8:
                break
        return out

    def walk(self):
        pending = [("", self.root_cluster)]
        seen = set()
        while pending:
            path, first = pending.pop()
            if first in seen:
                continue
            seen.add(first)
            chain = self.chain(first)
            self.used.update(chain)
            slots = []
            for c in chain:
                base = self.cluster_off(c)
                for i in range(self.cluster_size // 32):
                    slots.append(base + i * 32)
            self.dirs.append((path or "/", first, chain, slots))
            lfn = []
            name_units = []
            for off in slots:
                raw = self.data[off:off + 32]
                if raw[0] == 0:
                    break
                if raw[0] == 0xE5:
                    lfn = []
                    name_units = []
                    continue
                if raw[11] == 0x0F:
                    lfn.append(off)
                    units = b"".join(raw[o:o + 2] for o in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30))
                    name_units.insert(0, units)
                    continue
                short = raw[:11]
                attr = raw[11]
                first_c = (le16(raw, 20) << 16) | le16(raw, 26)
                size = le32(raw, 28)
                base = short[:8].rstrip(b" ").decode("latin-1")
                ext = short[8:].rstrip(b" ").decode("latin-1")
                shortname = base + ("." + ext if ext else "")
                long_name = None
                if lfn:
                    u = b"".join(name_units)
                    try:
                        text = u.decode("utf-16-le", errors="replace")
                        for term in ("\0", "\uffff"):
                            i = text.find(term)
                            if i >= 0:
                                text = text[:i]
                        long_name = text
                    except Exception:
                        long_name = None
                name = long_name or shortname
                is_dot = short in (b".          ", b"..         ")
                e = {
                    "path": (path + "/" + name) if not is_dot else None,
                    "short_path": (path + "/" + shortname) if not is_dot else None,
                    "off": off,
                    "lfn": list(lfn),
                    "is_dir": bool(attr & 0x10),
                    "is_label": bool(attr & 0x08) and not (attr & 0x10),
                    "is_dot": is_dot,
                    "first": first_c,
                    "size": size,
                    "name": name,
                    "dir_cluster": first,
                    "attr": attr,
                }
                self.entries.append(e)
                lfn = []
                name_units = []
                if is_dot or e["is_label"]:
                    continue
                if e["is_dir"]:
                    if first_c >= 2:
                        pending.append((path + "/" + name, first_c))
                else:
                    self.files.append(e)
                    if first_c >= 2:
                        self.used.update(self.chain(first_c))


# ----------------------------------------------------------------- image mutators

BOOT_FIELDS = [
    ("jump", 0, 3), ("oem", 3, 8), ("bps", 11, 2), ("spc", 13, 1), ("reserved", 14, 2),
    ("fats", 16, 1), ("root_entries", 17, 2), ("total16", 19, 2), ("media", 21, 1),
    ("fat16", 22, 2), ("spt", 24, 2), ("heads", 26, 2), ("hidden", 28, 4), ("total32", 32, 4),
    ("fat32", 36, 4), ("ext_flags", 40, 2), ("fs_version", 42, 2), ("root_cluster", 44, 4),
    ("fsinfo", 48, 2), ("backup", 50, 2), ("reserved12", 52, 12), ("drive", 64, 1),
    ("nt_flags", 65, 1), ("ext_sig", 66, 1), ("vol_id", 67, 4), ("label", 71, 11),
    ("fs_type", 82, 8), ("signature", 510, 2),
]

FSINFO_FIELDS = [("lead", 0, 4), ("struct", 484, 4), ("free", 488, 4), ("next", 492, 4), ("trail", 508, 4)]


def interesting_int(rng, size, orig, img):
    maxv = (1 << (8 * size)) - 1
    choices = [0, 1, 2, 3, maxv, maxv - 1, maxv >> 1, (maxv >> 1) + 1, orig ^ 1, orig + 1, orig - 1,
               orig * 2, orig // 2, 1 << rng.randrange(8 * size), rng.randrange(maxv + 1),
               0x80, 0xF0, 0xF8, 0xFF, img.max_cluster, img.max_cluster + 1, img.root_cluster,
               img.total, img.total - 1, img.total + 1, img.reserved, img.fat_sectors, img.clusters]
    v = rng.choice(choices)
    return max(0, min(maxv, v))


def pick_offset(rng, img):
    """Random offset, weighted towards metadata and directories."""
    r = rng.random()
    if r < 0.25:
        return rng.randrange(0, min(len(img.data), (img.reserved + 1) * img.bps))
    if r < 0.5 and img.fats:
        copy = rng.randrange(img.fats)
        return img.fat_off[copy] + rng.randrange(0, max(1, min(img.fat_sectors * img.bps, 4 * (img.max_cluster + 2))))
    if r < 0.85 and img.dirs:
        _, _, _, slots = rng.choice(img.dirs)
        return rng.choice(slots) + rng.randrange(32)
    return rng.randrange(len(img.data))


def mut_flip(rng, img):
    n = rng.choice([1, 1, 1, 2, 2, 4, 8, 16, 32, 64])
    edits = []
    for _ in range(n):
        off = pick_offset(rng, img)
        old = img.data[off]
        mode = rng.random()
        if mode < 0.5:
            new = old ^ (1 << rng.randrange(8))
        elif mode < 0.8:
            new = rng.randrange(256)
        else:
            new = rng.choice([0, 0xFF, 0xE5, 0x05, 0x20, 0x0F, 0x10, 0x2E])
        edits.append(("w", off, bytes([new])))
    return edits, "flip x%d" % n


def mut_write(rng, img):
    n = rng.choice([1, 1, 2, 3, 4])
    edits = []
    for _ in range(n):
        off = pick_offset(rng, img)
        length = rng.choice([1, 2, 4, 8, 11, 13, 16, 32, 64, 128, 512, img.cluster_size])
        fill = rng.random()
        if fill < 0.3:
            blob = bytes(rng.randrange(256) for _ in range(length))
        elif fill < 0.5:
            blob = b"\0" * length
        elif fill < 0.65:
            blob = b"\xff" * length
        elif fill < 0.8:
            blob = bytes([rng.choice([0xE5, 0x05, 0x20, 0x0F, 0x2E, 0x41])]) * length
        else:
            # Copy another region of the image over this one.
            src = pick_offset(rng, img)
            blob = img.data[src:src + length]
        edits.append(("w", off, blob))
    return edits, "write x%d" % n


def mut_boot(rng, img):
    n = rng.choice([1, 1, 1, 2, 3])
    edits = []
    names = []
    which = rng.random()
    bases = [0]
    if which < 0.15 and img.backup:
        bases = [img.backup * img.bps]
    elif which < 0.25 and img.backup:
        bases = [0, img.backup * img.bps]
    for _ in range(n):
        name, off, size = rng.choice(BOOT_FIELDS)
        if size in (1, 2, 4):
            orig = int.from_bytes(img.data[off:off + size], "little")
            v = interesting_int(rng, size, orig, img)
            blob = v.to_bytes(size, "little")
        else:
            blob = bytes(rng.randrange(256) for _ in range(size)) if rng.random() < 0.5 else bytes([rng.choice([0, 0xFF, 0x20])]) * size
        for base in bases:
            edits.append(("w", base + off, blob))
        names.append("%s=%s" % (name, blob.hex()))
    return edits, "boot " + " ".join(names)


def mut_fsinfo(rng, img):
    base = img.fsinfo * img.bps
    n = rng.choice([1, 1, 2])
    edits = []
    names = []
    for _ in range(n):
        name, off, size = rng.choice(FSINFO_FIELDS)
        orig = le32(img.data, base + off) if base + off + 4 <= len(img.data) else 0
        v = interesting_int(rng, 4, orig, img)
        edits.append(("w", base + off, p32(v)))
        names.append("%s=%x" % (name, v))
    return edits, "fsinfo " + " ".join(names)


def fat_value(rng, img, c):
    used = sorted(img.used) or [img.root_cluster]
    choices = [
        0, 1, 2, c, c - 1 if c > 2 else c, c + 1, img.root_cluster, rng.choice(used),
        rng.randrange(2, img.max_cluster + 1), img.max_cluster, img.max_cluster + 1,
        0x0FFFFFF0, 0x0FFFFFF6, 0x0FFFFFF7, 0x0FFFFFF8, 0x0FFFFFFF, 0xFFFFFFFF, 0xF0000000 | c,
        0x10000000 | (c + 1), 0x7FFFFFFF,
    ]
    return rng.choice(choices)


def mut_fat(rng, img):
    copies = rng.choice([[0], [0], [0, 1] if img.fats > 1 else [0], [1] if img.fats > 1 else [0], list(range(img.fats))])
    edits = []
    desc = []
    kind = rng.random()
    used = sorted(img.used) or [img.root_cluster]
    if kind < 0.6:
        n = rng.choice([1, 1, 2, 3, 4, 8])
        for _ in range(n):
            r = rng.random()
            if r < 0.6:
                c = rng.choice(used)
            elif r < 0.7:
                c = rng.choice([0, 1, img.root_cluster])
            else:
                c = rng.randrange(0, img.max_cluster + 2)
            v = fat_value(rng, img, c)
            for copy in copies:
                edits.append(("w", img.fat_entry_off(c, copy), p32(v)))
            desc.append("fat[%d]=%x" % (c, v))
    elif kind < 0.75:
        # A long chain: k consecutive clusters linked, ending in a loop, an end marker or free.
        start = rng.choice([rng.choice(used), rng.randrange(2, img.max_cluster + 1)])
        k = rng.choice([2, 5, 16, 100, 1000, img.clusters])
        end = rng.choice(["loop", "eoc", "free", "bad", "root", "self"])
        for i in range(k):
            c = start + i
            if c > img.max_cluster:
                break
            nxt = c + 1
            if c == min(start + k - 1, img.max_cluster):
                nxt = {"loop": start, "eoc": 0x0FFFFFFF, "free": 0, "bad": 0x0FFFFFF7, "root": img.root_cluster, "self": c}[end]
            for copy in copies:
                edits.append(("w", img.fat_entry_off(c, copy), p32(nxt)))
        desc.append("chain %d+%d->%s" % (start, k, end))
    elif kind < 0.85:
        # Merge: a used cluster's entry points into another chain.
        a = rng.choice(used)
        b = rng.choice(used)
        for copy in copies:
            edits.append(("w", img.fat_entry_off(a, copy), p32(b)))
        desc.append("merge %d->%d" % (a, b))
    elif kind < 0.93:
        # Every entry points at the next cluster: one chain through the volume.
        v = rng.choice(["next", "eoc", "zero", "self", "root", "random"])
        blob = bytearray()
        for c in range(0, img.max_cluster + 1):
            if v == "next":
                val = c + 1 if c < img.max_cluster else 0x0FFFFFFF
            elif v == "eoc":
                val = 0x0FFFFFFF
            elif v == "zero":
                val = 0
            elif v == "self":
                val = c
            elif v == "root":
                val = img.root_cluster
            else:
                val = rng.randrange(0, 1 << 32)
            blob += p32(val)
        if rng.random() < 0.7:
            blob[0:8] = img.data[img.fat_off[0]:img.fat_off[0] + 8]
        for copy in copies:
            edits.append(("w", img.fat_off[copy], bytes(blob)))
        desc.append("fill %s" % v)
    else:
        # Root directory chain extended through many clusters.
        chain = img.chain(img.root_cluster)
        last = chain[-1] if chain else img.root_cluster
        k = rng.choice([1, 2, 10, 100, img.clusters])
        c = last
        cnt = 0
        target = rng.randrange(2, img.max_cluster + 1)
        while cnt < k and target <= img.max_cluster:
            for copy in copies:
                edits.append(("w", img.fat_entry_off(c, copy), p32(target)))
            c = target
            target += 1
            cnt += 1
        for copy in copies:
            edits.append(("w", img.fat_entry_off(c, copy), p32(0x0FFFFFFF)))
        desc.append("rootchain +%d" % cnt)
    return edits, "fat " + " ".join(desc)


def mut_dirent(rng, img):
    if not img.entries:
        return mut_flip(rng, img)
    n = rng.choice([1, 1, 1, 2, 3, 4])
    edits = []
    desc = []
    for _ in range(n):
        e = rng.choice(img.entries)
        off = e["off"]
        raw = bytearray(img.data[off:off + 32])
        what = rng.choice(["size", "size", "first", "first", "attr", "name0", "name", "dates", "nt", "tenths",
                           "lfn", "lfn", "dup", "crosslink", "dot", "end", "garbage", "fill", "swap"])
        if what == "size":
            cs = img.cluster_size
            v = rng.choice([0, 1, cs - 1, cs, cs + 1, e["size"] * 2, e["size"] + 1, max(0, e["size"] - 1),
                            0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, rng.randrange(1 << 32), cs * img.clusters, cs * (img.clusters + 1)])
            raw[28:32] = p32(v)
            desc.append("size=%d" % v)
        elif what == "first":
            others = [x["first"] for x in img.entries if x["first"] >= 2]
            v = rng.choice([0, 1, img.root_cluster, e["first"] + 1, max(0, e["first"] - 1), img.max_cluster, img.max_cluster + 1,
                            0x0FFFFFFF, 0xFFFFFFFF, 0x0FFFFFF7, 0x0FFFFFF8, rng.randrange(1 << 32), rng.randrange(2, img.max_cluster + 1),
                            rng.choice(others) if others else 2, e["dir_cluster"]])
            raw[20:22] = p16(v >> 16)
            raw[26:28] = p16(v & 0xFFFF)
            desc.append("first=%d" % v)
        elif what == "attr":
            v = rng.choice([0x00, 0x01, 0x02, 0x04, 0x08, 0x0F, 0x10, 0x20, 0x30, 0x18, 0x28, 0x38, 0x3F, 0x40, 0x80, 0xFF,
                            e["attr"] ^ 0x10, e["attr"] ^ 0x08, e["attr"] | 0x0F])
            raw[11] = v
            desc.append("attr=%02x" % v)
        elif what == "name0":
            v = rng.choice([0x00, 0xE5, 0x05, 0x20, 0x2E, 0x22, 0x2A, 0x2F, 0x3A, 0x7C, 0xFF, 0x61, 0x80, 0xE5])
            raw[0] = v
            desc.append("name0=%02x" % v)
        elif what == "name":
            v = rng.choice([b".          ", b"..         ", b"           ", b"\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5",
                            b"lower   txt", b"A B C   D E", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                            bytes(rng.randrange(256) for _ in range(11)), b"\xff" * 11, b"CON        ", b"A/B:C*D    "])
            raw[0:11] = v
            desc.append("name=%s" % v.hex())
        elif what == "dates":
            for o in rng.sample([14, 16, 18, 22, 24], rng.randrange(1, 6)):
                raw[o:o + 2] = p16(rng.choice([0, 0xFFFF, 0x0021, 0x1E00, 0x001F, 0xBF7D, 0xFF9F, rng.randrange(1 << 16)]))
            desc.append("dates")
        elif what == "nt":
            raw[12] = rng.choice([0x08, 0x10, 0x18, 0xFF, rng.randrange(256)])
            desc.append("nt")
        elif what == "tenths":
            raw[13] = rng.choice([200, 201, 255, rng.randrange(256)])
            desc.append("tenths")
        elif what == "lfn" and e["lfn"]:
            loff = rng.choice(e["lfn"])
            lraw = bytearray(img.data[loff:loff + 32])
            how = rng.choice(["seq", "seq", "chk", "attr", "type", "cluster", "units", "units", "e5", "zero"])
            if how == "seq":
                lraw[0] = rng.choice([0, 0x40, 0x41, 0x5F, 0x54, 0x55, 0x80, 0xC1, 0x7F, lraw[0] ^ 0x40, (lraw[0] + 1) & 0xFF, (lraw[0] - 1) & 0xFF, 20, 21, 0xE5])
            elif how == "chk":
                lraw[13] = rng.choice([(lraw[13] + 1) & 0xFF, 0, 0xFF, rng.randrange(256)])
            elif how == "attr":
                lraw[11] = rng.choice([0x00, 0x0E, 0x1F, 0x2F, 0x3F, 0x20, 0x10])
            elif how == "type":
                lraw[12] = rng.choice([1, 0xFF])
            elif how == "cluster":
                lraw[26:28] = p16(rng.choice([1, 2, 0xFFFF]))
            elif how == "units":
                for o in rng.sample([1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30], rng.randrange(1, 5)):
                    lraw[o:o + 2] = p16(rng.choice([0x0000, 0xFFFF, 0xD800, 0xDC00, 0xDBFF, 0x002F, 0x005C, 0x003A, 0x0020, 0x002E, 0xFFFE, rng.randrange(1 << 16)]))
            elif how == "e5":
                lraw[0] = 0xE5
            else:
                lraw[:] = b"\0" * 32
            edits.append(("w", loff, bytes(lraw)))
            desc.append("lfn:%s" % how)
            continue
        elif what == "dup":
            # Copy another entry (with its long name slots) over this one.
            o = rng.choice(img.entries)
            raw = bytearray(img.data[o["off"]:o["off"] + 32])
            desc.append("dup")
        elif what == "crosslink":
            o = rng.choice(img.entries)
            raw[20:22] = img.data[o["off"] + 20:o["off"] + 22]
            raw[26:28] = img.data[o["off"] + 26:o["off"] + 28]
            if rng.random() < 0.5:
                raw[11] = img.data[o["off"] + 11]
            desc.append("crosslink")
        elif what == "dot":
            dots = [x for x in img.entries if x["is_dot"]]
            if dots:
                d = rng.choice(dots)
                draw = bytearray(img.data[d["off"]:d["off"] + 32])
                how = rng.choice(["first", "del", "attr", "name", "swap"])
                if how == "first":
                    v = rng.choice([0, 1, img.root_cluster, img.max_cluster + 1, rng.randrange(2, img.max_cluster + 1), 0xFFFFFFFF])
                    draw[20:22] = p16(v >> 16)
                    draw[26:28] = p16(v & 0xFFFF)
                elif how == "del":
                    draw[0] = 0xE5
                elif how == "attr":
                    draw[11] = rng.choice([0x20, 0x00, 0x08, 0x0F])
                elif how == "name":
                    draw[0:11] = b"..         " if draw[1] == 0x20 else b".          "
                else:
                    other = d["off"] + (32 if d["off"] % img.cluster_size == 0 else -32)
                    edits.append(("w", d["off"], img.data[other:other + 32]))
                    edits.append(("w", other, bytes(draw)))
                    desc.append("dot:swap")
                    continue
                edits.append(("w", d["off"], bytes(draw)))
                desc.append("dot:%s" % how)
            else:
                # Put a dot entry into the root directory.
                raw[0:11] = rng.choice([b".          ", b"..         "])
                raw[11] = 0x10
                desc.append("dot:root")
        elif what == "end":
            raw[0] = 0
            desc.append("end")
        elif what == "garbage":
            # Something after the end marker of this entry's directory.
            d = [x for x in img.dirs if x[1] == e["dir_cluster"]]
            if d:
                slots = d[0][3]
                tail = [s for s in slots if img.data[s] == 0]
                if tail:
                    s = rng.choice(tail)
                    edits.append(("w", s + rng.randrange(32), bytes([rng.choice([1, 0x20, 0x41, 0xFF, 0xE5])])))
                    desc.append("garbage")
                    continue
            raw[0] = 0x41
            desc.append("garbage0")
        elif what == "fill":
            # Fill the directory's free slots with copies of this entry or
            # with LFN-looking slots, removing the end marker.
            d = [x for x in img.dirs if x[1] == e["dir_cluster"]]
            if d:
                slots = d[0][3]
                filler = rng.choice(["entry", "lfn", "e5", "random"])
                blob = bytearray()
                for s in slots:
                    if img.data[s] != 0:
                        blob += img.data[s:s + 32]
                        continue
                    if filler == "entry":
                        x = bytearray(img.data[e["off"]:e["off"] + 32])
                        x[0] = 0x41 + (len(blob) // 32) % 26
                        x[1] = 0x41 + (len(blob) // 32 // 26) % 26
                        x[2:8] = b"%06d" % ((len(blob) // 32) % 1000000)
                        blob += x
                    elif filler == "lfn":
                        x = bytearray(32)
                        x[0] = 0x41 + rng.randrange(20)
                        x[11] = 0x0F
                        x[13] = rng.randrange(256)
                        blob += x
                    elif filler == "e5":
                        x = bytearray(img.data[e["off"]:e["off"] + 32])
                        x[0] = 0xE5
                        blob += x
                    else:
                        blob += bytes(rng.randrange(256) for _ in range(32))
                edits.append(("w", slots[0], bytes(blob)))
                desc.append("fill:%s" % filler)
                continue
            raw[0] = 0x41
            desc.append("fill0")
        elif what == "swap":
            o = rng.choice(img.entries)
            edits.append(("w", off, img.data[o["off"]:o["off"] + 32]))
            edits.append(("w", o["off"], bytes(raw)))
            desc.append("swap")
            continue
        else:
            raw[0] ^= 0x01
            desc.append("bit")
        edits.append(("w", off, bytes(raw)))
    return edits, "dirent " + " ".join(desc)


def mut_truncate(rng, img):
    n = len(img.data)
    cs = img.cluster_size
    choices = [0, 1, 511, 512, 513, img.bps, img.bps - 1, img.reserved * img.bps, img.data_off - 1, img.data_off,
               img.data_off + cs, img.data_off + cs - 1, n - 1, n // 2, n - cs, img.fat_off[0] + 4 * img.root_cluster,
               rng.randrange(n), n + 1, n + cs, n + 512, img.total * img.bps - 1]
    v = max(0, rng.choice(choices))
    return [("len", v)], "len=%d" % v


def mut_combo(rng, img):
    edits = []
    descs = []
    for f in rng.sample([mut_flip, mut_write, mut_boot, mut_fsinfo, mut_fat, mut_dirent], rng.choice([2, 2, 3])):
        e, d = f(rng, img)
        edits += e
        descs.append(d)
    if rng.random() < 0.1:
        e, d = mut_truncate(rng, img)
        edits += e
        descs.append(d)
    return edits, "combo[" + "; ".join(descs) + "]"


IMAGE_STRATEGIES = {
    "flip": mut_flip,
    "write": mut_write,
    "boot": mut_boot,
    "fsinfo": mut_fsinfo,
    "fat": mut_fat,
    "dirent": mut_dirent,
    "truncate": mut_truncate,
    "combo": mut_combo,
}
IMAGE_WEIGHTS = {"flip": 3, "write": 2, "boot": 3, "fsinfo": 1, "fat": 4, "dirent": 5, "truncate": 1, "combo": 3}


# ----------------------------------------------------------------- manifest mutators

def split_records(text):
    """Returns the list of records (bytes without the separator)."""
    parts = text.split(RS)
    return [p for p in parts[1:]] if text.startswith(RS) else parts


def join_records(records):
    return b"".join(RS + r for r in records)


def parse_record(r):
    try:
        return json.loads(r.decode("utf-8"))
    except Exception:
        return None


def dump_record(obj):
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


ROOT_REC = b'{"mediaType":"application/vnd.uapi.16.manifest"}\n'
TRAILER_REC = b'{"mediaType":"application/vnd.uapi.16.trailer"}\n'

BIG_INTS = [0, 1, -1, 2 ** 31, 2 ** 32 - 1, 2 ** 32, 2 ** 63 - 1, 2 ** 63, 2 ** 64 - 1, 2 ** 64, 2 ** 127 - 1,
            -(2 ** 127), 2 ** 128, 10 ** 40, 4294967295, 4294967296, 4 * 1024 * 1024, 65535, 65536]
FLOATS = ["1e400", "-1e400", "1.5", "0.0", "-0", "1e-400", "1E+2", "123456789012345678901234567890.5", "2.5e9"]
STRANGE_STRINGS = ["", " ", "a" * 255, "a" * 256, "a" * 4095, "a" * 4096, "x" * 100000, "\u0000", "a\u0000b", "\u007f",
                   "..", ".", "a/..", "../a", "a/../b", "./a", "a/./b", "//", "a//b", "/a", "a/", "a\\b", "a:b", "a*b",
                   "a?b", "a<b", "a\"b", "a|b", "con", "CON", "nul.txt", "a.", "a ", " a", "日本語", "ünïcödé",
                   "\ufeff", "\uffff", "\ufffe", "a\u2028b", "urn:uuid:" + "é" * 9, "urn:uuidé" + "0" * 27,
                   "é" * 5, "0123456789abcdef0123456789abcdef", "01234567-89ab-cdef-0123-456789abcdef",
                   "urn:uuid:01234567-89ab-cdef-0123-456789abcdef", "Uapi16Manifest", "Uapi16Manifest.x", "uapi16manifest",
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "AAAA", "A", "====", "0x10", "777",
                   "18446744073709551615", "18446744073709551616", "-1", "+1", "1e3", " 1", "1 ", "0" * 1000, "9" * 1000,
                   "http://x", "https://", "ftp://x", "identity", "gzip", "zstd", "revoked", "reg", "dir", "lnk",
                   "a/" * 2000 + "b", "/".join(["d"] * 100), "name with spaces", "a" * 300 + "/b", "\udcff" if False else "x"]
KEYS = ["name", "type", "size", "mode", "uid", "gid", "userName", "groupName", "gptLabel", "gptUuid", "gptTypeUuid",
        "gptDiskUuid", "major", "minor", "gptFlags", "gptFlagNoAuto", "gptFlagGrowFileSystem", "mTimeNSec", "inodeToken",
        "extendedAttributes", "readOnly", "contents", "sha256", "validSinceUSec", "validUntilUSec", "validity",
        "mediaType", "mechanism", "key", "data", "unknownField", "a.b", ""]
CONTENT_KEYS = ["file", "url", "literal", "encoding", "encodedSize", "encodedSha256", "originalSize", "originalSha256", "offset"]


def random_value(rng, depth=0):
    r = rng.random()
    if r < 0.25:
        return rng.choice(BIG_INTS)
    if r < 0.45:
        return rng.choice(STRANGE_STRINGS)
    if r < 0.55:
        return rng.choice([True, False, None])
    if r < 0.65 and depth < 3:
        return [random_value(rng, depth + 1) for _ in range(rng.choice([0, 1, 2, 5]))]
    if r < 0.75 and depth < 3:
        return {rng.choice(KEYS): random_value(rng, depth + 1) for _ in range(rng.choice([0, 1, 2, 3]))}
    if r < 0.8:
        return rng.choice(["", "a" * 40000])
    return rng.choice([0, "0", "1", "o644", "644", 420, 0o7777, 0o10000, -1, 2 ** 64])


def random_contents(rng):
    c = {}
    for k in rng.sample(CONTENT_KEYS, rng.randrange(0, 4)):
        c[k] = random_value(rng)
    if rng.random() < 0.3:
        c["literal"] = rng.choice(["aGVsbG8=", "aGVsbG8", "AA==", "!!", "", "A" * 100000, "YQ==" * 50000])
    if rng.random() < 0.3:
        c["offset"] = rng.choice(BIG_INTS)
    if rng.random() < 0.3:
        c["originalSize"] = rng.choice(BIG_INTS)
    return c


def mut_manifest_structural(rng, records):
    """JSON-aware edits of the records."""
    recs = list(records)
    objs = [parse_record(r) for r in recs]
    idx = [i for i, o in enumerate(objs) if isinstance(o, dict)]
    if not idx:
        return recs, "structural:noobj"
    desc = []
    for _ in range(rng.choice([1, 1, 2, 3])):
        i = rng.choice(idx)
        o = objs[i]
        if not isinstance(o, dict):
            continue
        how = rng.choice(["set", "set", "set", "del", "type", "contents", "contents", "name", "name", "size", "nest",
                          "dupkey", "manykeys", "huge", "bigint", "float", "null", "mediatype"])
        if how == "set":
            k = rng.choice(KEYS)
            o[k] = random_value(rng)
            desc.append("set %s" % k)
        elif how == "del":
            if o:
                k = rng.choice(list(o.keys()))
                del o[k]
                desc.append("del %s" % k)
        elif how == "type":
            o["type"] = rng.choice(["reg", "dir", "lnk", "fifo", "chr", "blk", "sock", "weird", "", 5, None, "DIR"])
            desc.append("type")
        elif how == "contents":
            n = rng.choice([0, 1, 2, 256, 257, 300, 1000])
            o["contents"] = [random_contents(rng) for _ in range(n)] if rng.random() < 0.8 else random_value(rng)
            desc.append("contents x%d" % n)
        elif how == "name":
            base = o.get("name") if isinstance(o.get("name"), str) else "x"
            o["name"] = rng.choice([base.upper(), base.lower(), base + "/", "/" + base, base + "/..", "../" + base, base + "//x",
                                    base.swapcase(), "a" * rng.choice([254, 255, 256, 1000]), "a/" * 1000, base + "\u0000",
                                    base + "." if base else ".", base + " ", rng.choice(STRANGE_STRINGS), "Uapi16Manifest",
                                    "é".join(base.split("e")) if "e" in base else base + "é", base.replace("/", "\\")])
            desc.append("name")
        elif how == "size":
            o["size"] = rng.choice(BIG_INTS + ["0", "1", "18446744073709551615", "-1", "abc", 1.5, None])
            desc.append("size")
        elif how == "nest":
            d = rng.choice([10, 100, 127, 128, 129, 200, 1000, 10000])
            v = 1
            for _ in range(d):
                v = [v] if rng.random() < 0.5 else {"a": v}
            o[rng.choice(KEYS)] = v
            desc.append("nest %d" % d)
        elif how == "dupkey":
            # Serialised by hand below: mark for duplicate key emission.
            o["__dupkey__"] = rng.choice(list(o.keys()) + ["name", "size"])
            desc.append("dupkey")
        elif how == "manykeys":
            n = rng.choice([100, 1000, 5000, 20000])
            for j in range(n):
                o["k%d" % j] = j
            desc.append("manykeys %d" % n)
        elif how == "huge":
            n = rng.choice([65536, 1 << 20, 4 * 1024 * 1024 - 200, 4 * 1024 * 1024 + 10, 5 * 1024 * 1024])
            o[rng.choice(["pad", "name", "sha256", "literalpad"])] = "p" * n
            desc.append("huge %d" % n)
        elif how == "bigint":
            o[rng.choice(KEYS)] = rng.choice(BIG_INTS)
            desc.append("bigint")
        elif how == "float":
            o["__rawfloat__"] = (rng.choice(KEYS), rng.choice(FLOATS))
            desc.append("float")
        elif how == "null":
            k = rng.choice(list(o.keys()) + KEYS) if o else rng.choice(KEYS)
            o[k] = None
            desc.append("null %s" % k)
        elif how == "mediatype":
            o["mediaType"] = rng.choice(["application/vnd.uapi.16.manifest", "application/vnd.uapi.16.trailer",
                                         "application/vnd.uapi.16.signature", "application/x-unknown", "", None, 5])
            desc.append("mediatype")
        objs[i] = o
    out = []
    for i, r in enumerate(recs):
        o = objs[i]
        if i in idx and isinstance(o, dict):
            dup = o.pop("__dupkey__", None)
            rawfloat = o.pop("__rawfloat__", None)
            text = json.dumps(o, ensure_ascii=False, separators=(",", ":"))
            if dup is not None:
                text = text[:-1] + ',"%s":1}' % dup if len(text) > 2 else '{"%s":1,"%s":2}' % (dup, dup)
            if rawfloat is not None:
                k, f = rawfloat
                text = text[:-1] + (',' if len(text) > 2 else '') + '"%s":%s}' % (k, f)
            out.append(text.encode("utf-8") + b"\n")
        else:
            out.append(r)
    return out, "structural " + " ".join(desc)


def mut_manifest_records(rng, records):
    recs = list(records)
    how = rng.choice(["drop", "dup", "shuffle", "notrailer", "noroot", "extra", "empty", "many", "sep", "nul", "utf8",
                      "surrogate", "garbage", "whitespace", "deeparray", "longnum", "label"])
    if how == "drop" and recs:
        del recs[rng.randrange(len(recs))]
    elif how == "dup" and recs:
        i = rng.randrange(len(recs))
        recs.insert(i, recs[i])
    elif how == "shuffle":
        rng.shuffle(recs)
    elif how == "notrailer":
        recs = [r for r in recs if b"trailer" not in r]
    elif how == "noroot" and recs:
        recs = recs[1:]
    elif how == "extra":
        recs.insert(rng.randrange(len(recs) + 1), rng.choice([
            b'{"name":"extra","size":0}\n', b'[1,2,3]\n', b'"string"\n', b'null\n', b'42\n', b'{}\n', b'\n', b' \n',
            b'{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AAAA"}\n',
            b'{"mediaType":"application/vnd.uapi.16.signature"}\n',
            b'{"mediaType":"application/vnd.uapi.16.manifest"}\n',
            b'{"name":"a.txt","size":0}\n', b'{"name":"A.TXT","size":0}\n',
            b'{"name":"zzz","type":"dir","contents":[]}\n',
            b'{"name":"zzz","type":"dir","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}\n',
            b'{"name":"\xff\xfe","size":0}\n', b'{"name":"a\x00b","size":0}\n',
            b'{"name":"lit","contents":[{"literal":"aGVsbG8=","offset":3}],"size":2}\n',
            b'{"name":"lit2","contents":[{"literal":"aGVsbG8=","offset":5}],"size":0}\n',
            b'{"name":"lit3","contents":[{"literal":"aGVsbG8=","offset":6}]}\n',
            b'{"name":"big","size":4294967295}\n', b'{"name":"big2","size":4294967296}\n',
            b'{"name":"off","contents":[{"file":"x","offset":18446744073709551615,"originalSize":18446744073709551615}],"size":0}\n',
            b'{"name":"off2","contents":[{"file":"x","offset":18446744073709551615}],"size":1}\n',
            b'{"name":"u","gptUuid":"urn:uuid:\xc3\xa9\xc3\xa9"}\n',
            b'{"name":"m","mode":"7777"}\n', b'{"name":"m2","mode":"77777777777777777777777"}\n',
            b'{"name":"v","validSinceUSec":18446744073709551615}\n',
            b'{"name":"t","mTimeNSec":18446744073709551615}\n',
            b'{"name":"t2","mTimeNSec":"18446744073709551615"}\n',
            b'{"name":"x","extendedAttributes":{"user":{"a":{"base64":"' + b"A" * 100000 + b'"}}}}\n',
        ]))
    elif how == "empty":
        recs = [rng.choice([b"", b"\n", b" ", b"\t\r\n"])] * rng.choice([1, 10, 1000])
    elif how == "many":
        n = rng.choice([200, 500, 1000, 2000, 10000])
        body = rng.choice([b'{"name":"f%d","size":0}\n', b'{"name":"d%d","type":"dir"}\n', b'{"name":"f%d","size":1,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}\n', b'{"mediaType":"application/x-unknown","n":%d}\n', b'{"name":"a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/%d","size":0}\n'])
        recs = [recs[0]] + [body % i for i in range(n)] + recs[1:]
    elif how == "sep":
        recs.insert(rng.randrange(len(recs) + 1), b'{"name":"s\x1ex","size":0}\n')
    elif how == "nul":
        recs.insert(rng.randrange(len(recs) + 1), b'{"name":"n\x00x","size":0}\n')
    elif how == "utf8":
        recs.insert(rng.randrange(len(recs) + 1), rng.choice([b'{"name":"\xff","size":0}\n', b'{"name":"\xc3","size":0}\n', b'{"name":"\xed\xa0\x80","size":0}\n', b'{"\xff":1,"name":"x"}\n', b'\xef\xbb\xbf{"name":"bom","size":0}\n']))
    elif how == "surrogate":
        recs.insert(rng.randrange(len(recs) + 1), rng.choice([b'{"name":"\\ud800","size":0}\n', b'{"name":"\\udc00","size":0}\n', b'{"name":"\\ud800\\u0041","size":0}\n', b'{"name":"\\ud83d\\ude00","size":0}\n', b'{"name":"\\u0000","size":0}\n', b'{"name":"\\u002f","size":0}\n', b'{"name":"\\uFFFF","size":0}\n', b'{"name":"\\u+041","size":0}\n', b'{"name":"\\u-041","size":0}\n']))
    elif how == "garbage":
        recs.insert(rng.randrange(len(recs) + 1), bytes(rng.randrange(256) for _ in range(rng.choice([1, 10, 100, 5000]))))
    elif how == "whitespace":
        recs = [b" " * rng.choice([1, 100, 100000]) + r for r in recs]
    elif how == "deeparray":
        d = rng.choice([100, 128, 129, 1000, 100000])
        recs.insert(rng.randrange(len(recs) + 1), b"[" * d + b"]" * d + b"\n")
    elif how == "longnum":
        n = rng.choice([100, 10000, 1000000])
        recs.insert(rng.randrange(len(recs) + 1), rng.choice([b'{"name":"n","size":' + b"9" * n + b'}\n', b'{"name":"n","size":1' + b"0" * n + b'.5}\n', b'{"name":"n","size":1e' + b"9" * n + b'}\n', b'{"name":"n","size":-' + b"1" * n + b'}\n']))
    elif how == "label":
        recs.insert(1, b'{"name":"g","gptLabel":"' + "\u65e5".encode("utf-8") * rng.choice([36, 37, 100]) + b'"}\n')
    return recs, "records:" + how


def mut_manifest_bytes(rng, text):
    data = bytearray(text)
    n = rng.choice([1, 1, 2, 4, 8, 32])
    how = rng.choice(["flip", "flip", "write", "truncate", "insert", "delete"])
    if how == "flip":
        for _ in range(n):
            if not data:
                break
            i = rng.randrange(len(data))
            data[i] ^= (1 << rng.randrange(8)) if rng.random() < 0.6 else data[i] ^ rng.randrange(1, 256)
    elif how == "write":
        for _ in range(n):
            if not data:
                break
            i = rng.randrange(len(data))
            blob = rng.choice([b"\x1e", b"\x00", b"\xff", b'"', b"{", b"}", b"[", b"]", b"\\", b"\\u", b",", b":", b"\xc3", b"\xed\xa0\x80", b" " * 10, b"9" * 30])
            data[i:i + len(blob)] = blob
    elif how == "truncate":
        data = data[: rng.randrange(len(data) + 1)]
    elif how == "insert":
        i = rng.randrange(len(data) + 1)
        blob = rng.choice([b"\x1e", b"\x1e\x1e", b"\x00", b"\xff" * 10, b'{"a":1}', b"\n" * 100, b"\\", b"\x1e{", bytes(rng.randrange(256) for _ in range(rng.choice([1, 16, 256])))])
        data[i:i] = blob
    else:
        i = rng.randrange(len(data) + 1)
        del data[i:i + rng.choice([1, 2, 8, 64])]
    return bytes(data), "bytes:%s" % how


def mutate_manifest(rng, seed_bytes):
    r = rng.random()
    if r < 0.3:
        return mut_manifest_bytes(rng, seed_bytes)
    records = split_records(seed_bytes)
    if r < 0.75:
        recs, d = mut_manifest_structural(rng, records)
    else:
        recs, d = mut_manifest_records(rng, records)
    out = join_records(recs)
    if rng.random() < 0.15:
        out, d2 = mut_manifest_bytes(rng, out)
        d += " + " + d2
    return out, d


# ----------------------------------------------------------------- running commands

MEM_LIMIT_BYTES = 4_000_000 * 1024   # ulimit -v 4000000
FSIZE_LIMIT = 1 << 30                # keep runaway images off the tmpfs


def run_local(argv, stdin_path=None, timeout=5.0, stderr_path=None, cwd=None, env=None):
    """Runs argv under the resource limits and returns a dict of outcome
    data: exit status or signal, wall time, peak RSS (ru_maxrss from
    wait4, the counter /usr/bin/time -v reports as the maximum resident set
    size) and the stderr tail."""
    err_fd = os.open(stderr_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644) if stderr_path else os.open(os.devnull, os.O_WRONLY)
    in_fd = os.open(stdin_path, os.O_RDONLY) if stdin_path else os.open(os.devnull, os.O_RDONLY)
    out_fd = os.open(os.devnull, os.O_WRONLY)
    start = time.monotonic()
    pid = os.fork()
    if pid == 0:
        try:
            os.setsid()
            os.dup2(in_fd, 0)
            os.dup2(out_fd, 1)
            os.dup2(err_fd, 2)
            resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
            resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            if cwd:
                os.chdir(cwd)
            e = dict(os.environ)
            for k in ("SOURCE_DATE_EPOCH", "LISTEN_FDS", "LISTEN_PID", "SYSTEMD_VARLINK_LISTEN"):
                e.pop(k, None)
            if env:
                e.update(env)
            os.execve(argv[0], argv, e)
        except BaseException:
            os._exit(127)
    os.close(in_fd)
    os.close(out_fd)
    os.close(err_fd)
    delay = 0.0005
    timed_out = False
    while True:
        wpid, status, ru = os.wait4(pid, os.WNOHANG)
        if wpid == pid:
            break
        if time.monotonic() - start > timeout:
            timed_out = True
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            wpid, status, ru = os.wait4(pid, 0)
            break
        time.sleep(delay)
        delay = min(delay * 1.5, 0.01)
    elapsed = time.monotonic() - start
    res = {"secs": round(elapsed, 4), "rss_kb": ru.ru_maxrss, "timeout": timed_out}
    if os.WIFEXITED(status):
        res["exit"] = os.WEXITSTATUS(status)
        res["signal"] = None
    else:
        res["exit"] = None
        res["signal"] = os.WTERMSIG(status)
    if stderr_path:
        try:
            with open(stderr_path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                f.seek(max(0, size - 4000))
                res["stderr"] = f.read().decode("utf-8", "replace")
                res["stderr_size"] = size
        except OSError:
            res["stderr"] = ""
    return res


# The process that forks the tool. ru_maxrss of a child includes the RSS it
# inherited from its parent before exec, so the forking is done by a small
# helper process started before the worker loads any data; its own RSS (a
# bare interpreter, about 15 MB) is the baseline of every measurement.
_SPAWNER = None


def spawner_loop(rfd, wfd):
    rf = os.fdopen(rfd, "rb")
    wf = os.fdopen(wfd, "wb")
    for line in rf:
        req = json.loads(line)
        res = run_local(req["argv"], req.get("stdin"), req.get("timeout", 5.0), req.get("stderr"), req.get("cwd"), req.get("env"))
        wf.write(json.dumps(res).encode("utf-8") + b"\n")
        wf.flush()
    os._exit(0)


def start_spawner():
    global _SPAWNER
    r1, w1 = os.pipe()
    r2, w2 = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(w1)
        os.close(r2)
        spawner_loop(r1, w2)
    os.close(r1)
    os.close(w2)
    _SPAWNER = (os.fdopen(w1, "wb"), os.fdopen(r2, "rb"), pid)


def run(argv, stdin_path=None, timeout=5.0, stderr_path=None, cwd=None, env=None):
    if _SPAWNER is None:
        return run_local(argv, stdin_path, timeout, stderr_path, cwd, env)
    w, r, _ = _SPAWNER
    w.write(json.dumps({"argv": argv, "stdin": stdin_path, "timeout": timeout, "stderr": stderr_path, "cwd": cwd, "env": env}).encode("utf-8") + b"\n")
    w.flush()
    line = r.readline()
    if not line:
        raise RuntimeError("spawner died")
    return json.loads(line)


# fsck follows fsck(8): 0 clean, 4 problems found (and left, the check never
# repairs), 8 the image could not be checked, e.g. it is not a FAT volume.
FSCK_EXITS = (0, 4, 8)


def clean_exits(cmd):
    """The exit statuses that are not a defect for the command `cmd`."""
    return FSCK_EXITS if cmd is not None and cmd.startswith("check") else (0, 1)


def classify(res, mem_mb, size_before=None, size_after=None, allow_grow=False):
    """Returns (kind, detail) with kind None for a clean outcome. res["cmd"]
    names the command when the caller knows it; fsck's exit codes differ."""
    cmd = res.get("cmd")
    if res["timeout"]:
        return "hang", "timeout after %.1fs" % res["secs"]
    if res["signal"] is not None:
        return "signal", "killed by signal %d" % res["signal"]
    stderr = res.get("stderr", "")
    if res["exit"] == 101 or "panicked at" in stderr:
        m = re.search(r"panicked at ([^:\n]+:\d+:\d+)", stderr)
        return "panic", m.group(1) if m else "exit 101"
    if res["rss_kb"] > mem_mb * 1024:
        return "memory", "RSS %d MB" % (res["rss_kb"] // 1024)
    if res["exit"] not in clean_exits(cmd):
        return "exit", "exit status %s" % res["exit"]
    if size_before is not None and size_after is not None and size_after != size_before and not allow_grow:
        return "resize", "image size %d -> %d" % (size_before, size_after)
    if res["exit"] == 1 and not stderr.strip() and cmd is not None and not cmd.startswith("check"):
        return "silent", "exit 1 without a message"
    return None, None


def signature(cmd_name, kind, detail, stderr):
    if kind == "panic":
        m = re.search(r"panicked at ([^:\n]+:\d+)", stderr)
        where = m.group(1) if m else detail
        return "panic@%s" % where.replace("/", "_")
    return "%s:%s" % (kind, cmd_name)


# ----------------------------------------------------------------- the image campaign

def image_commands(ufat, img_path, seed_info, small_tree, rng):
    """The commands to run against a variant image. Write commands get a
    fresh copy each (handled by the caller through the 'fresh' flag)."""
    files = [e for e in seed_info.files if e["path"] and e["first"] >= 2] or seed_info.files
    cat_target = rng.choice(files)["path"] if files else "/missing"
    rm_target = rng.choice(seed_info.files)["path"] if seed_info.files else "/missing"
    dirs = [d[0] for d in seed_info.dirs if d[0] != "/"]
    ls_dir = rng.choice(dirs) if dirs and rng.random() < 0.5 else "/"
    if rng.random() < 0.3 and files:
        cat_target = rng.choice(files)["short_path"]
    cmds = [
        ("list", [ufat, "list", "-l", img_path, ls_dir], False),
        ("cat", [ufat, "cat", img_path, cat_target], False),
        ("check", [ufat, "check", img_path], False),
        ("describe", [ufat, "describe", img_path], False),
        ("populate-dir", [ufat, "populate", "--path", rng.choice(["/new", "/EFI/new", "/new dir with long name", "/deep/er/new"]), img_path], True),
        ("remove", [ufat, "remove", img_path, rm_target], True),
        ("populate", [ufat, "populate", img_path, small_tree], True),
    ]
    if rng.random() < 0.2:
        cmds.append(("populate-parents", [ufat, "populate", "--parents", "--path", "/a/b/c/d/e/f", img_path], True))
    if rng.random() < 0.2:
        cmds.append(("remove-dir", [ufat, "remove", img_path, rng.choice(dirs) if dirs else "/x"], True))
    return cmds


def save_finding(out, sig, kind, detail, cmd_name, argv, res, variant_bytes, seed_name, edits, desc, ext, extra=None):
    d = os.path.join(out, "findings", sig)
    os.makedirs(d, exist_ok=True)
    existing = [x for x in os.listdir(d) if x.startswith("case-")]
    if len(existing) >= 3:
        # Keep a count only.
        with open(os.path.join(d, "count"), "a") as f:
            f.write("%s %s %s\n" % (seed_name, cmd_name, desc))
        return False
    case = os.path.join(d, "case-%d" % (len(existing) + 1))
    os.makedirs(case, exist_ok=True)
    with open(os.path.join(case, "variant" + ext), "wb") as f:
        f.write(variant_bytes)
    with open(os.path.join(case, "info.json"), "w") as f:
        json.dump({"kind": kind, "detail": detail, "command": cmd_name, "argv": argv, "result": res, "seed": seed_name,
                   "mutation": desc, "edits": edits_to_json(edits) if edits is not None else None, "extra": extra}, f, indent=1)
    with open(os.path.join(case, "stderr.txt"), "w") as f:
        f.write(res.get("stderr", ""))
    return True


_SEEDS = {}


def load_seed(path):
    """Seed bytes (and the parsed image for .img seeds), cached per worker."""
    if path not in _SEEDS:
        with open(path, "rb") as f:
            data = f.read()
        _SEEDS[path] = (data, Fat32(data) if path.endswith(".img") else None)
    return _SEEDS[path]


def worker_images(args):
    (indices, ufat, seed_paths, out, small_tree, timeout, mem_mb, strategies, base_seed) = args
    work = os.path.join(out, "images-work", str(os.getpid()))
    os.makedirs(work, exist_ok=True)
    img_path = os.path.join(work, "variant.img")
    err_path = os.path.join(work, "stderr.txt")
    stats = {}
    findings = []
    weights = [IMAGE_WEIGHTS[s] for s in strategies]
    for idx in indices:
        rng = random.Random(base_seed * 1_000_003 + idx)
        seed_path = seed_paths[idx % len(seed_paths)]
        seed_name = os.path.basename(seed_path)
        seed_bytes, info = load_seed(seed_path)
        strat = rng.choices(strategies, weights=weights)[0]
        edits, desc = IMAGE_STRATEGIES[strat](rng, info)
        variant = apply_edits(seed_bytes, edits)
        cmds = image_commands(ufat, img_path, info, small_tree, rng)
        with open(img_path, "wb") as f:
            f.write(variant)
        for cmd_name, argv, fresh in cmds:
            if fresh:
                with open(img_path, "wb") as f:
                    f.write(variant)
            before = os.stat(img_path).st_size
            res = run(argv, timeout=timeout, stderr_path=err_path)
            res["cmd"] = cmd_name
            after = os.stat(img_path).st_size
            kind, detail = classify(res, mem_mb, before, after)
            key = (strat, cmd_name, kind or ("ok%d" % res["exit"]))
            stats[key] = stats.get(key, 0) + 1
            if kind:
                sig = signature(cmd_name, kind, detail, res.get("stderr", ""))
                saved = save_finding(out, sig, kind, detail, cmd_name, argv, res, variant, seed_name, edits, desc, ".img")
                findings.append((sig, kind, detail, cmd_name, seed_name, desc, saved))
        # A truncated variant leaves a short file; the next variant rewrites it.
    return stats, findings


def campaign_images(a):
    seeds = sorted(os.path.join(a.seeds, "images", n) for n in os.listdir(os.path.join(a.seeds, "images")) if n.endswith(".img"))
    if a.only_seeds:
        seeds = [s for s in seeds if any(x in os.path.basename(s) for x in a.only_seeds.split(","))]
    if not seeds:
        sys.exit("no seed images")
    small_tree = os.path.join(a.seeds, "trees", "small")
    strategies = a.strategies.split(",") if a.strategies else list(IMAGE_STRATEGIES)
    os.makedirs(a.out, exist_ok=True)
    indices = list(range(a.start, a.start + a.count))
    chunks = [indices[i:i + a.chunk] for i in range(0, len(indices), a.chunk)]
    jobs = [(c, a.ufat, seeds, a.out, small_tree, a.timeout, a.mem_mb, strategies, a.seed) for c in chunks]
    return run_jobs(a, jobs, worker_images, "images")


# ----------------------------------------------------------------- the manifest campaign

def source_tree_for(seeds_dir, name):
    if name.startswith("special"):
        return os.path.join(seeds_dir, "trees", "special")
    if name.startswith("seed-tree"):
        return os.path.join(seeds_dir, "trees", "seed")
    return os.path.join(seeds_dir, "trees", "esp")


def worker_manifests(args):
    (indices, ufat, seed_paths, seeds_dir, out, timeout, mem_mb, base_seed, blob_path) = args
    work = os.path.join(out, "manifests-work", str(os.getpid()))
    os.makedirs(work, exist_ok=True)
    m_path = os.path.join(work, "variant.Uapi16Manifest")
    img_path = os.path.join(work, "assembled.img")
    err_path = os.path.join(work, "stderr.txt")
    stream_path = os.path.join(work, "stream.bin")
    stats = {}
    findings = []
    blob = open(blob_path, "rb").read()
    for idx in indices:
        rng = random.Random(base_seed * 1_000_003 + idx)
        seed_path = seed_paths[idx % len(seed_paths)]
        seed_name = os.path.basename(seed_path)
        seed_bytes, _ = load_seed(seed_path)
        variant, desc = mutate_manifest(rng, seed_bytes)
        strat = desc.split(" ")[0].split(":")[0]
        with open(m_path, "wb") as f:
            f.write(variant)
        source = source_tree_for(seeds_dir, seed_name)
        n = rng.choice([0, 1, 100, len(blob) // 2, len(blob), len(blob) - 1])
        with open(stream_path, "wb") as f:
            f.write(blob[:n])
        cmds = [
            ("plan", [ufat, "assemble", "--plan", "--manifest", m_path], None),
            ("assemble", [ufat, "assemble", "--create", "--unsupported", "fail", "--manifest", m_path, img_path, source], None),
            ("assemble-stream", [ufat, "assemble", "--create", "--manifest", m_path, img_path, "-"], stream_path),
        ]
        if rng.random() < 0.3:
            cmds.append(("assemble-skip", [ufat, "assemble", "--create", "--unsupported", "skip", "--no-check-validity", "--manifest", m_path, img_path, source], None))
        for cmd_name, argv, stdin in cmds:
            try:
                os.unlink(img_path)
            except FileNotFoundError:
                pass
            res = run(argv, stdin_path=stdin, timeout=timeout, stderr_path=err_path)
            res["cmd"] = cmd_name
            try:
                res["image_size"] = os.stat(img_path).st_size
            except FileNotFoundError:
                res["image_size"] = None
            kind, detail = classify(res, mem_mb)
            if kind is None and res["image_size"] is not None and res["image_size"] > 256 << 20:
                kind, detail = "bigimage", "image of %d bytes created" % res["image_size"]
            key = (strat, cmd_name, kind or ("ok%d" % res["exit"]))
            stats[key] = stats.get(key, 0) + 1
            if kind:
                sig = signature(cmd_name, kind, detail, res.get("stderr", ""))
                saved = save_finding(out, sig, kind, detail, cmd_name, argv, res, variant, seed_name, None, desc, ".Uapi16Manifest",
                                     extra={"stream_bytes": n if stdin else None})
                findings.append((sig, kind, detail, cmd_name, seed_name, desc, saved))
    try:
        os.unlink(img_path)
    except FileNotFoundError:
        pass
    return stats, findings


def campaign_manifests(a):
    seeds = sorted(os.path.join(a.seeds, "manifests", n) for n in os.listdir(os.path.join(a.seeds, "manifests")))
    if a.only_seeds:
        seeds = [s for s in seeds if any(x in os.path.basename(s) for x in a.only_seeds.split(","))]
    if not seeds:
        sys.exit("no seed manifests")
    os.makedirs(a.out, exist_ok=True)
    blob_path = os.path.join(a.out, "stream-blob.bin")
    if not os.path.exists(blob_path):
        with open(blob_path, "wb") as f:
            f.write(random.Random(7).randbytes(1 << 20))
    indices = list(range(a.start, a.start + a.count))
    chunks = [indices[i:i + a.chunk] for i in range(0, len(indices), a.chunk)]
    jobs = [(c, a.ufat, seeds, a.seeds, a.out, a.timeout, a.mem_mb, a.seed, blob_path) for c in chunks]
    return run_jobs(a, jobs, worker_manifests, "manifests")


# ----------------------------------------------------------------- driver

def run_jobs(a, jobs, fn, label):
    start = time.time()
    stats = {}
    findings = []
    done = 0
    with multiprocessing.Pool(a.workers, initializer=start_spawner) as pool:
        for st, fi in pool.imap_unordered(fn, jobs):
            done += 1
            for k, v in st.items():
                stats[k] = stats.get(k, 0) + v
            findings.extend(fi)
            if done % 10 == 0 or done == len(jobs):
                variants = sum(v for (s, c, k), v in stats.items() if c in ("list", "plan"))
                sys.stderr.write("[%s] %d/%d chunks, %d variants, %d findings, %.0fs\n" % (label, done, len(jobs), variants, len(findings), time.time() - start))
    elapsed = time.time() - start
    shutil.rmtree(os.path.join(a.out, label + "-work"), ignore_errors=True)
    report = {
        "campaign": label, "seconds": round(elapsed, 1), "count": a.count, "start": a.start, "seed": a.seed,
        "stats": sorted(["%s/%s/%s=%d" % (s, c, k, v) for (s, c, k), v in stats.items()]),
        "findings": [{"sig": s, "kind": k, "detail": d, "command": c, "seed": sd, "mutation": m, "saved": sv} for (s, k, d, c, sd, m, sv) in findings],
    }
    path = os.path.join(a.out, "report-%s-%d.json" % (label, a.start))
    with open(path, "w") as f:
        json.dump(report, f, indent=1)
    sys.stderr.write("wrote %s\n" % path)
    # Summary by signature.
    by_sig = {}
    for (s, k, d, c, sd, m, sv) in findings:
        by_sig[s] = by_sig.get(s, 0) + 1
    for s, n in sorted(by_sig.items(), key=lambda x: -x[1]):
        sys.stderr.write("  %6d  %s\n" % (n, s))
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("campaign", choices=["images", "manifests"])
    p.add_argument("--ufat", required=True)
    p.add_argument("--seeds", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--count", type=int, default=1000)
    p.add_argument("--start", type=int, default=0, help="first variant index (variants are a function of --seed and the index)")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--chunk", type=int, default=50)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--mem-mb", type=int, default=300)
    p.add_argument("--strategies", default="", help="comma separated subset of " + ",".join(IMAGE_STRATEGIES))
    p.add_argument("--only-seeds", default="", help="comma separated substrings selecting seeds")
    a = p.parse_args()
    a.ufat = os.path.abspath(a.ufat)
    a.seeds = os.path.abspath(a.seeds)
    a.out = os.path.abspath(a.out)
    report = campaign_images(a) if a.campaign == "images" else campaign_manifests(a)
    sys.exit(1 if report["findings"] else 0)


if __name__ == "__main__":
    main()
