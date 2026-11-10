#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Targeted robustness probes for ufat: inputs built from reading the code
rather than from random mutation. Each probe prints PASS or DEFECT with the
observed outcome; exit status 1 when a defect was seen.

    tests/fuzz/targeted.py --ufat target/debug/ufat --seeds SEEDS --work DIR
"""

import argparse
import json
import os
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mutate  # noqa: E402

RS = b"\x1e"
ROOT = b'{"mediaType":"application/vnd.uapi.16.manifest"}\n'
TRAILER = b'{"mediaType":"application/vnd.uapi.16.trailer"}\n'


def manifest(records):
    return b"".join(RS + r for r in [ROOT] + records + [TRAILER])


class Probes:
    def __init__(self, ufat, seeds, work, timeout=20.0, mem_mb=300):
        self.ufat = ufat
        self.seeds = seeds
        self.work = work
        self.timeout = timeout
        self.mem_mb = mem_mb
        self.defects = []
        self.seed_img = os.path.join(seeds, "images", "ufat-512s-512c-2M.img")
        self.small_tree = os.path.join(seeds, "trees", "small")

    def run(self, name, argv, stdin=None, env=None, expect_exit=None, timeout=None):
        """Runs argv and records a defect unless it exits with one of
        expect_exit: 0 or 1, for fsck the fsck(8) codes 0, 4 and 8."""
        err = os.path.join(self.work, "stderr.txt")
        res = mutate.run_local(argv, stdin_path=stdin, timeout=timeout or self.timeout, stderr_path=err, env=env)
        res["cmd"] = argv[1]
        if expect_exit is None:
            expect_exit = mutate.clean_exits(argv[1])
        kind, detail = mutate.classify(res, self.mem_mb)
        if kind is None and res["exit"] not in expect_exit:
            kind, detail = "exit", "exit %s" % res["exit"]
        tail = res.get("stderr", "").strip().splitlines()
        tail = tail[-1][:160] if tail else ""
        if kind:
            self.defects.append((name, kind, detail))
            print("DEFECT %-42s %-8s %s  [%.2fs, %d MB] %s" % (name, kind, detail, res["secs"], res["rss_kb"] // 1024, tail))
        else:
            print("pass   %-42s exit %s [%.2fs, %d MB] %s" % (name, res["exit"], res["secs"], res["rss_kb"] // 1024, tail))
        return res

    def fresh_image(self, name="probe.img", seed=None):
        p = os.path.join(self.work, name)
        shutil.copyfile(seed or self.seed_img, p)
        return p

    # ---------------------------------------------------------------- probes

    def timestamps(self):
        img = self.fresh_image()
        for t in ["18446744073709551615", "9223372036854775808", "9223372036854775807", "-1", "1e3", "4354819199", "99999999999999999"]:
            self.run("populate --timestamp %s" % t, [self.ufat, "populate", "--timestamp", t, "--path", "/t" + t[:3], img])
        for t in ["18446744073709551615", "9223372036854775808", "abc", "", " 1700000000", "1700000000.5"]:
            self.run("populate SOURCE_DATE_EPOCH=%r" % t, [self.ufat, "populate", img, self.small_tree], env={"SOURCE_DATE_EPOCH": t})
        for t in ["18446744073709551615", "9223372036854775808"]:
            self.run("assemble --timestamp %s" % t, [self.ufat, "assemble", "--create", "--size", "40M", "--timestamp", t, os.path.join(self.work, "ts.img")])
            self.run("assemble --plan SOURCE_DATE_EPOCH=%s" % t, [self.ufat, "assemble", "--plan", self.small_tree], env={"SOURCE_DATE_EPOCH": t})

    def cli_sizes(self):
        img = self.fresh_image()
        for s in ["18446744073709551615", "18446744073709551616", "-1", "1T", "16777216T", "17179869184G", "0", "1", "511", "k", "1k1", "", " ", "1 K", "9" * 100]:
            self.run("list --offset %r" % s, [self.ufat, "list", "--offset", s, img, "/"])
            self.run("list --size %r" % s, [self.ufat, "list", "--size", s, img, "/"])
        for s in ["4294967296", "4294967295", "0", "1", "3", "1024", "2048", "8192", "65536", "262144", "18446744073709551615"]:
            self.run("assemble --sector-size %s" % s, [self.ufat, "assemble", "--create", "--size", "300M", "--sector-size", s, os.path.join(self.work, "ss.img")])
            self.run("assemble --cluster-size %s" % s, [self.ufat, "assemble", "--create", "--size", "300M", "--cluster-size", s, os.path.join(self.work, "cs.img")])
            self.run("assemble --reserved-sectors %s" % s, [self.ufat, "assemble", "--create", "--size", "300M", "--reserved-sectors", s, os.path.join(self.work, "rs.img")])
            self.run("assemble --fats %s" % s, [self.ufat, "assemble", "--create", "--size", "300M", "--fats", s, os.path.join(self.work, "fats.img")])
        for s in ["0", "1", "511", "512", "1023", "1024", "32K", "1M", "32M", "40M"]:
            self.run("assemble --size %s" % s, [self.ufat, "assemble", "--create", "--size", s, os.path.join(self.work, "small.img")])
        self.run("assemble --label 12 chars", [self.ufat, "assemble", "--create", "--size", "40M", "--label", "123456789012", os.path.join(self.work, "l.img")])
        self.run("assemble --label unicode", [self.ufat, "assemble", "--create", "--size", "40M", "--label", "日本語", os.path.join(self.work, "l.img")])
        self.run("assemble --label 0xE5", [self.ufat, "assemble", "--create", "--size", "40M", "--label", "å", os.path.join(self.work, "l.img")])
        self.run("assemble --identifier long", [self.ufat, "assemble", "--create", "--size", "40M", "--identifier", "1-2-3-4-5-6-7-8-9", os.path.join(self.work, "l.img")])
        self.run("assemble --oem-name long", [self.ufat, "assemble", "--create", "--size", "40M", "--oem-name", "123456789", os.path.join(self.work, "l.img")])
        self.run("assemble on directory", [self.ufat, "assemble", self.work])
        self.run("assemble on /dev/null", [self.ufat, "assemble", "/dev/null"])
        self.run("list /dev/null", [self.ufat, "list", "/dev/null", "/"])
        self.run("check /dev/zero", [self.ufat, "check", "/dev/zero"])
        self.run("list dir", [self.ufat, "list", self.work, "/"])
        self.run("cat path with NUL", [self.ufat, "cat", img, "/a\0b".replace("\0", "")])
        self.run("list 5000-deep path", [self.ufat, "list", img, "/" + "a/" * 5000])
        self.run("list 300-char component", [self.ufat, "list", img, "/" + "a" * 300])
        self.run("populate --path 300-char component", [self.ufat, "populate", "--path", "/" + "a" * 300, img])
        self.run("populate --path 255 utf16 units", [self.ufat, "populate", "--path", "/" + "日" * 255, img])
        self.run("populate --path 128 astral chars", [self.ufat, "populate", "--path", "/" + "\U0001F600" * 128, img])
        self.run("populate --path 127 astral chars", [self.ufat, "populate", "--path", "/" + "\U0001F600" * 127, img])
        self.run("populate --parents 2000 levels", [self.ufat, "populate", "--parents", "--path", "/" + "d/" * 2000, img], timeout=60)
        self.run("populate --path weird chars", [self.ufat, "populate", "--path", "/\u0001", img])
        self.run("populate --path U+FFFF", [self.ufat, "populate", "--path", "/￿", img])
        self.run("populate --path U+FFFE", [self.ufat, "populate", "--path", "/￾", img])
        self.run("populate --path trailing dot", [self.ufat, "populate", "--path", "/a.", img])
        self.run("populate --path E5 start", [self.ufat, "populate", "--path", "/åx", img])
        aliases = os.path.join(self.work, "aliases")
        for i in range(300):
            os.makedirs(os.path.join(aliases, "long name %d.txt" % i), exist_ok=True)
        self.run("populate many ~ aliases", [self.ufat, "populate", img, aliases], timeout=60)

    def alias_exhaustion(self):
        """A directory full of LONGFI~N aliases makes the tail search for a
        new lossy name scan every candidate against every entry."""
        for n in (1000, 4000, 16000, 65000):
            img = self.fresh_image("alias-%d.img" % n, seed=os.path.join(self.seeds, "images", "ufat-512s-4096c-8M.img"))
            data = bytearray(open(img, "rb").read())
            info = mutate.Fat32(bytes(data))
            # Build a root directory of n short entries LONGFI~k.TXT (k = 1..n)
            # and chain enough clusters for them.
            slots_needed = n + 2
            clusters_needed = (slots_needed * 32 + info.cluster_size - 1) // info.cluster_size
            # Use clusters right after the existing ones; mark them in both FATs.
            free = [c for c in range(2, info.max_cluster + 1) if info.fat_get(c) == 0]
            if len(free) < clusters_needed:
                print("skip   alias exhaustion %d: not enough clusters" % n)
                continue
            chain = [info.root_cluster] + free[:clusters_needed]
            for i, c in enumerate(chain):
                nxt = chain[i + 1] if i + 1 < len(chain) else 0x0FFFFFFF
                for copy in range(info.fats):
                    struct.pack_into("<I", data, info.fat_entry_off(c, copy), nxt)
            entries = bytearray()
            for k in range(1, n + 1):
                tail = ("~%d" % k).encode()
                base = b"LONGFI"[: 8 - len(tail)] + tail
                e = bytearray(32)
                e[0:11] = base.ljust(8, b" ") + b"TXT"
                e[11] = 0x20
                e[24:26] = struct.pack("<H", 0x0021)
                entries += e
            for i, c in enumerate(chain):
                off = info.cluster_off(c)
                chunk = entries[i * info.cluster_size:(i + 1) * info.cluster_size]
                data[off:off + info.cluster_size] = chunk.ljust(info.cluster_size, b"\0")
            with open(img, "wb") as f:
                f.write(data)
            self.run("alias exhaustion %d entries: list" % n, [self.ufat, "list", img, "/"], timeout=60)
            self.run("alias exhaustion %d entries: populate --path lossy" % n, [self.ufat, "populate", "--path", "/longfilename.txt", img], timeout=120)
            self.run("alias exhaustion %d entries: check" % n, [self.ufat, "check", img], timeout=60)

    def big_directory(self):
        """populate and assemble with many entries in one directory."""
        for n in (2000, 8000):
            tree = os.path.join(self.work, "big-%d" % n)
            os.makedirs(tree, exist_ok=True)
            for i in range(n):
                open(os.path.join(tree, "f%d" % i), "wb").close()
            img = os.path.join(self.work, "big-%d.img" % n)
            self.run("populate %d files in one dir" % n, [self.ufat, "assemble", "--create", "--fit", tree, img], timeout=60)
            self.run("populate %d files in one dir (2)" % n, [self.ufat, "populate", img, tree], timeout=300)
            shutil.rmtree(tree)

    def manifests(self):
        cases = {
            "uuid non-char-boundary (known)": [b'{"name":"x","size":0,"gptUuid":"urn:uuid\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"}\n'],
            "uuid 8 bytes multibyte": [b'{"name":"x","size":0,"gptTypeUuid":"\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"}\n'],
            "deep nesting 128": [b'{"name":"x","size":0,"a":' + b"[" * 128 + b"]" * 128 + b"}\n"],
            "deep nesting 100000": [b'{"name":"x","size":0,"a":' + b"[" * 100000 + b"]" * 100000 + b"}\n"],
            "100000 keys (known quadratic)": [b'{"name":"x","size":0,' + b",".join(b'"k%d":1' % i for i in range(100000)) + b"}\n"],
            "4MiB digits": [b'{"name":"x","size":' + b"9" * (4 * 1024 * 1024 - 100) + b"}\n"],
            "4MiB float": [b'{"name":"x","size":1' + b"0" * (4 * 1024 * 1024 - 100) + b".5}\n"],
            "1e999999": [b'{"name":"x","size":1e999999}\n'],
            "i128 max": [b'{"name":"x","size":170141183460469231731687303715884105727}\n'],
            "i128 overflow": [b'{"name":"x","size":170141183460469231731687303715884105728}\n'],
            "size u64 max": [b'{"name":"x","size":18446744073709551615}\n'],
            "size 2^32": [b'{"name":"x","size":4294967296}\n'],
            "size 2^32-1 x 300": [b'{"name":"f%d","size":4294967295}\n' % i for i in range(300)],
            "mtime u64 max": [b'{"name":"x","size":0,"mTimeNSec":18446744073709551615}\n'],
            "validSince u64 max": [b'{"name":"x","size":0,"validSinceUSec":18446744073709551615}\n'],
            "offset u64 max": [b'{"name":"x","size":0,"contents":[{"file":"x","offset":18446744073709551615}]}\n'],
            "offset+size overflow": [b'{"name":"x","size":18446744073709551615,"contents":[{"file":"x","offset":1}]}\n'],
            "originalSize u64 max": [b'{"name":"x","contents":[{"file":"x","originalSize":18446744073709551615,"offset":18446744073709551614}]}\n'],
            "literal offset past end": [b'{"name":"x","contents":[{"literal":"aGVsbG8=","offset":100}],"size":0}\n'],
            "literal huge base64": [b'{"name":"x","contents":[{"literal":"' + b"QUFB" * (1024 * 1024) + b'"}]}\n'],
            "mode octal huge": [b'{"name":"x","size":0,"mode":"' + b"7" * 100000 + b'"}\n'],
            "mode negative": [b'{"name":"x","size":0,"mode":-1}\n'],
            "uid negative": [b'{"name":"x","size":0,"uid":-1}\n'],
            "uid huge": [b'{"name":"x","size":0,"uid":18446744073709551616}\n'],
            "name 4095": [b'{"name":"' + b"a/" * 2047 + b'b","size":0}\n'],
            "name 4096": [b'{"name":"' + b"a/" * 2047 + b'bb","size":0}\n'],
            "name 2000 components": [b'{"name":"' + b"d/" * 2000 + b'f","size":0}\n'],
            "name astral 200": [('{"name":"' + "\U0001F600" * 200 + '","size":0}\n').encode()],
            "name 255 x U+65E5": [('{"name":"' + "日" * 255 + '","size":0}\n').encode()],
            "name 128 astral": [('{"name":"' + "\U0001F600" * 128 + '","size":0}\n').encode()],
            "name U+FFFF": [('{"name":"￿","size":0}\n').encode()],
            "name trailing dot": [b'{"name":"a.","size":0}\n'],
            "name leading space": [b'{"name":" a","size":0}\n'],
            "name colon": [b'{"name":"a:b","size":0}\n'],
            "name backslash": [b'{"name":"a\\\\b","size":0}\n'],
            "name dot dir": [b'{"name":"a","type":"dir"}\n', b'{"name":"a/.","size":0}\n'],
            "dup case dirs": [b'{"name":"A","type":"dir"}\n', b'{"name":"a/x","size":0}\n'],
            "file then dir same name": [b'{"name":"a","size":0}\n', b'{"name":"a/x","size":0}\n'],
            "dir then file same name": [b'{"name":"a","type":"dir"}\n', b'{"name":"A","size":0}\n'],
            "gpt label 36 astral": [('{"name":"x","size":0,"gptLabel":"' + "\U0001F600" * 18 + '"}\n').encode()],
            "gpt label 37 astral": [('{"name":"x","size":0,"gptLabel":"' + "\U0001F600" * 19 + '"}\n').encode()],
            "xattr huge base64": [b'{"name":"x","size":0,"extendedAttributes":{"user":{"a":{"base64":"' + b"QUFB" * (1024 * 1024) + b'"}}}}\n'],
            "signature huge": [b'{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"' + b"QUFB" * (1024 * 1024) + b'"}\n'],
            "sha256 whitespace": [b'{"name":"x","size":0,"sha256":"' + b" ".join(bytes([c]) for c in b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") + b'"}\n'],
            "hash wrong length": [b'{"name":"x","size":0,"sha256":"e3b0"}\n'],
            "contents 256 literal": [b'{"name":"x","contents":[' + b",".join([b'{"literal":"AA=="}'] * 256) + b"]}\n"],
            "records 20000 dirs nested": [b'{"name":"%s","type":"dir"}\n' % b"/".join([b"d%d" % j for j in range(i % 16 + 1)]) for i in range(20000)],
            "1000 empty records": [b"\n"] * 1000,
            "ws only record non-ascii": [" \n".encode()],
            "record 4MiB+1": [b'{"name":"x","size":0,"p":"' + b"p" * (4 * 1024 * 1024) + b'"}\n'],
            "stream size 2^32-1": [b'{"name":"x","size":4294967295}\n'],
        }
        src = os.path.join(self.seeds, "trees", "esp")
        for name, recs in cases.items():
            m = os.path.join(self.work, "probe.Uapi16Manifest")
            with open(m, "wb") as f:
                f.write(manifest(recs))
            img = os.path.join(self.work, "probe-assemble.img")
            self.run("manifest %s: plan" % name, [self.ufat, "assemble", "--plan", "--manifest", m], timeout=60)
            if os.path.exists(img):
                os.unlink(img)
            self.run("manifest %s: assemble" % name, [self.ufat, "assemble", "--create", "--manifest", m, img, src], timeout=120)
            if os.path.exists(img):
                os.unlink(img)
            self.run("manifest %s: assemble from a stream" % name, [self.ufat, "assemble", "--create", "--manifest", m, img, "-"], stdin=os.devnull, timeout=120)
            if os.path.exists(img):
                os.unlink(img)
        # Not a manifest at all.
        for name, data in [("empty", b""), ("rs only", RS), ("rs x 1M", RS * (1 << 20)), ("root only", RS + ROOT), ("4 MiB garbage", bytes(range(256)) * (16 * 1024)),
                           ("binary zeros", b"\0" * 100000), ("utf8 bom", b"\xef\xbb\xbf" + manifest([])), ("CRLF", manifest([]).replace(b"\n", b"\r\n")),
                           ("nul in record", RS + b'{"name":"a\x00"}' + RS + TRAILER), ("huge valid", manifest([b'{"name":"f%d","size":0}\n' % i for i in range(60000)]))]:
            m = os.path.join(self.work, "probe.Uapi16Manifest")
            with open(m, "wb") as f:
                f.write(data)
            self.run("manifest %s: plan" % name, [self.ufat, "assemble", "--plan", "--manifest", m], timeout=60)
        self.run("manifest of /proc", [self.ufat, "manifest", "/proc/self"], timeout=60)
        self.run("manifest of nonexistent", [self.ufat, "manifest", "/nonexistent"])
        self.run("manifest of a file", [self.ufat, "manifest", self.seed_img])
        self.run("assemble --plan of /dev", [self.ufat, "assemble", "--plan", "/dev"], timeout=60)
        self.run("assemble --plan of /proc/self", [self.ufat, "assemble", "--plan", "/proc/self"], timeout=60)

    def images_hand_made(self):
        """Boot sectors that pass validation with extreme geometry."""
        base = open(self.seed_img, "rb").read()
        info = mutate.Fat32(base)

        def variant(name, edits, cmds=("list", "check", "populate-dir", "populate", "cat")):
            img = os.path.join(self.work, "hand.img")
            with open(img, "wb") as f:
                f.write(mutate.apply_edits(base, edits))
            for c in cmds:
                argv = {"list": [self.ufat, "list", "-l", img, "/"], "check": [self.ufat, "check", img], "populate-dir": [self.ufat, "populate", "--path", "/new", img],
                        "populate": [self.ufat, "populate", img, self.small_tree], "cat": [self.ufat, "cat", img, "/EFI/BOOT/BOOTX64.EFI"],
                        "remove": [self.ufat, "remove", img, "/EFI/BOOT/BOOTX64.EFI"], "describe": [self.ufat, "describe", img]}[c]
                before = os.path.getsize(img)
                res = self.run("%s: %s" % (name, c), argv, timeout=60)
                after = os.path.getsize(img)
                if after != before:
                    self.defects.append((name + ": " + c, "resize", "%d -> %d" % (before, after)))
                    print("DEFECT %s: image size changed %d -> %d" % (name, before, after))

        bps = info.bps
        variant("sector size 1024 (seed is 512)", [("w", 11, struct.pack("<H", 1024))])
        variant("sector size 2048", [("w", 11, struct.pack("<H", 2048))])
        variant("sector size 4096", [("w", 11, struct.pack("<H", 4096))])
        variant("spc 128", [("w", 13, b"\x80")])
        variant("spc 0", [("w", 13, b"\x00")])
        variant("fats 255", [("w", 16, b"\xff")])
        variant("fats 1", [("w", 16, b"\x01")])
        variant("reserved 2 fsinfo 1", [("w", 14, struct.pack("<H", 2))])
        variant("reserved 65535", [("w", 14, struct.pack("<H", 65535))])
        variant("fat sectors 1", [("w", 36, struct.pack("<I", 1))])
        variant("fat sectors huge", [("w", 36, struct.pack("<I", 0x7FFFFFFF))])
        variant("fat sectors u32 max", [("w", 36, struct.pack("<I", 0xFFFFFFFF))])
        variant("total 16 = 1", [("w", 19, struct.pack("<H", 1))])
        variant("total 16 = 65535", [("w", 19, struct.pack("<H", 65535))])
        variant("total32 = u32 max", [("w", 32, struct.pack("<I", 0xFFFFFFFF))])
        variant("total32 = data start + 1", [("w", 32, struct.pack("<I", info.reserved + info.fats * info.fat_sectors + 1))])
        variant("root cluster = max", [("w", 44, struct.pack("<I", info.max_cluster))])
        variant("root cluster = max+1", [("w", 44, struct.pack("<I", info.max_cluster + 1))])
        variant("root cluster = 0x0FFFFFF7", [("w", 44, struct.pack("<I", 0x0FFFFFF7))])
        variant("root cluster chain into itself", [("w", info.fat_entry_off(info.root_cluster), struct.pack("<I", info.root_cluster))])
        variant("root chain -> free", [("w", info.fat_entry_off(info.root_cluster), struct.pack("<I", 0))])
        variant("root chain -> bad", [("w", info.fat_entry_off(info.root_cluster), struct.pack("<I", 0x0FFFFFF7))])
        variant("root chain -> invalid 0x0FFFFFF0", [("w", info.fat_entry_off(info.root_cluster), struct.pack("<I", 0x0FFFFFF0))])
        variant("backup boot = fsinfo", [("w", 50, struct.pack("<H", 1))])
        variant("backup boot = 31", [("w", 50, struct.pack("<H", 31))])
        variant("fsinfo = 31", [("w", 48, struct.pack("<H", 31))])
        variant("ext flags 0x80", [("w", 40, struct.pack("<H", 0x80))])
        variant("ext flags 0x7F", [("w", 40, struct.pack("<H", 0x7F))])
        variant("media 0", [("w", 21, b"\x00")])
        variant("nt flags dirty", [("w", 65, b"\x01")])
        variant("fsinfo garbage", [("w", bps, b"\xff" * 512)])
        variant("fsinfo next free huge", [("w", bps + 492, struct.pack("<I", 0xFFFFFFF0))])
        variant("fsinfo free huge", [("w", bps + 488, struct.pack("<I", 0xFFFFFFFF))])
        # Every FAT entry chains to the next cluster: the root directory is the whole volume.
        fat = bytearray()
        for c in range(0, info.max_cluster + 1):
            fat += struct.pack("<I", c + 1 if c < info.max_cluster else 0x0FFFFFFF)
        fat[0:8] = base[info.fat_off[0]:info.fat_off[0] + 8]
        variant("all clusters one chain", [("w", info.fat_off[i], bytes(fat)) for i in range(info.fats)])
        # Every FAT entry is an end marker: all clusters allocated, none chained.
        variant("all clusters eoc", [("w", info.fat_off[i], base[info.fat_off[0]:info.fat_off[0] + 8] + b"\xff\xff\xff\x0f" * (info.max_cluster - 1)) for i in range(info.fats)])
        # Every FAT entry free, root included.
        variant("all clusters free", [("w", info.fat_off[i], b"\0" * 4 * (info.max_cluster + 1)) for i in range(info.fats)])
        # Directory entries: a file whose chain is the root directory, a file of size u32 max.
        files = [e for e in info.files if e["path"] and e["first"] >= 2]
        e = files[0]
        raw = bytearray(base[e["off"]:e["off"] + 32])
        raw[20:22] = struct.pack("<H", info.root_cluster >> 16)
        raw[26:28] = struct.pack("<H", info.root_cluster & 0xFFFF)
        variant("file chain = root dir (%s)" % e["path"], [("w", e["off"], bytes(raw))], cmds=("list", "check", "cat", "remove", "list", "populate-dir"))
        raw = bytearray(base[e["off"]:e["off"] + 32])
        raw[28:32] = struct.pack("<I", 0xFFFFFFFF)
        variant("file size u32 max", [("w", e["off"], bytes(raw))], cmds=("list", "check", "cat"))
        raw = bytearray(base[e["off"]:e["off"] + 32])
        raw[11] = 0x10
        variant("file marked directory", [("w", e["off"], bytes(raw))], cmds=("list", "check", "cat", "remove", "populate-dir"))
        d = [x for x in info.entries if x["is_dir"] and not x["is_dot"] and x["path"]][0]
        raw = bytearray(base[d["off"]:d["off"] + 32])
        raw[11] = 0x20
        variant("directory marked file (%s)" % d["path"], [("w", d["off"], bytes(raw))], cmds=("list", "check", "cat", "remove", "populate-dir"))
        raw = bytearray(base[d["off"]:d["off"] + 32])
        raw[20:22] = struct.pack("<H", info.root_cluster >> 16)
        raw[26:28] = struct.pack("<H", info.root_cluster & 0xFFFF)
        variant("subdir points at root", [("w", d["off"], bytes(raw))], cmds=("list", "check", "populate-dir", "populate"))
        # A directory cluster filled with 0xE5 entries and no end marker.
        chain = info.chain(d["first"])
        variant("subdir all deleted no end", [("w", info.cluster_off(chain[0]), (b"\xe5" + b"A" * 10 + b"\x20" + b"\0" * 20) * (info.cluster_size // 32))], cmds=("list", "check", "populate-dir", "populate"))
        # Root directory: no end marker, all slots valid entries.
        rchain = info.chain(info.root_cluster)
        filler = b""
        for i in range(info.cluster_size // 32):
            x = bytearray(32)
            x[0:11] = b"F%07d   " % i
            x[11] = 0x20
            filler += bytes(x)
        variant("root full no end marker", [("w", info.cluster_off(rchain[-1]), filler)], cmds=("list", "check", "populate-dir", "populate"))
        # LFN sequence of 20 entries with a matching checksum but no short entry.
        lfn = b""
        for seq in range(20, 0, -1):
            x = bytearray(32)
            x[0] = seq | (0x40 if seq == 20 else 0)
            x[11] = 0x0F
            x[13] = 0x12
            for o in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30):
                x[o:o + 2] = b"A\0"
            lfn += bytes(x)
        variant("20 lfn entries then end", [("w", info.cluster_off(rchain[-1]), lfn + b"\0" * (info.cluster_size - len(lfn)))], cmds=("list", "check", "populate-dir"))
        # LFN with all 0xFFFF units and a valid short entry.
        x = bytearray(32)
        x[0] = 0x41
        x[11] = 0x0F
        short = bytearray(32)
        short[0:11] = b"FFFF       "
        short[11] = 0x20
        chk = 0
        for b in short[0:11]:
            chk = ((chk >> 1) | ((chk & 1) << 7)) + b
            chk &= 0xFF
        x[13] = chk
        for o in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30):
            x[o:o + 2] = b"\xff\xff"
        variant("lfn all 0xffff", [("w", info.cluster_off(rchain[-1]), bytes(x) + bytes(short) + b"\0" * (info.cluster_size - 64))], cmds=("list", "check", "populate-dir"))
        for o in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30):
            x[o:o + 2] = b"\x00\xd8"
        variant("lfn all high surrogates", [("w", info.cluster_off(rchain[-1]), bytes(x) + bytes(short) + b"\0" * (info.cluster_size - 64))], cmds=("list", "check", "populate-dir"))
        for o in (1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30):
            x[o:o + 2] = b"/\x00"
        variant("lfn all slashes", [("w", info.cluster_off(rchain[-1]), bytes(x) + bytes(short) + b"\0" * (info.cluster_size - 64))], cmds=("list", "check", "populate-dir", "cat"))
        # Short name that is all 0xE5 bytes with the 0x05 escape.
        short[0:11] = b"\x05\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5\xe5"
        variant("short name 05 e5*10", [("w", info.cluster_off(rchain[-1]), bytes(short) + b"\0" * (info.cluster_size - 32))], cmds=("list", "check", "populate-dir"))
        # Volume label entry with a cluster and a size, plus 100 label entries.
        lab = bytearray(32)
        lab[0:11] = b"LABEL      "
        lab[11] = 0x08
        lab[26:28] = struct.pack("<H", 2)
        lab[28:32] = struct.pack("<I", 1 << 31)
        variant("100 label entries", [("w", info.cluster_off(rchain[-1]), bytes(lab) * (info.cluster_size // 32))], cmds=("list", "check", "populate-dir", "describe"))
        # Truncated images at every interesting boundary.
        for n in (0, 1, 511, 512, 513, bps, bps * 2, info.fat_off[0], info.fat_off[0] + 4, info.data_off - 1, info.data_off, info.data_off + 32,
                  info.data_off + info.cluster_size, len(base) - 1):
            variant("truncated to %d" % n, [("len", n)], cmds=("list", "check", "populate-dir", "describe"))
        variant("extended by 1", [("len", len(base) + 1)], cmds=("list", "check", "populate-dir"))
        variant("extended by 1 cluster", [("len", len(base) + info.cluster_size)], cmds=("list", "check", "populate-dir", "populate"))

    def offsets(self):
        img = self.fresh_image()
        n = os.path.getsize(img)
        for off, size in [(0, 0), (0, 1), (0, 511), (0, 512), (512, None), (n, None), (n - 1, None), (n + 1, None), (0, n + 1), (1, n), (0, n - 1),
                          (2 ** 63, None), (2 ** 64 - 1, None), (0, 2 ** 64 - 1), (2 ** 64 - 1, 2 ** 64 - 1), (n // 2, n // 2)]:
            argv = [self.ufat, "list", "--offset", str(off)]
            if size is not None:
                argv += ["--size", str(size)]
            self.run("list --offset %d --size %s" % (off, size), argv + [img, "/"])
            argv = [self.ufat, "check", "--offset", str(off)]
            if size is not None:
                argv += ["--size", str(size)]
            self.run("check --offset %d --size %s" % (off, size), argv + [img])
        # A file system inside a larger image.
        big = os.path.join(self.work, "offset.img")
        with open(big, "wb") as f:
            f.write(b"\xaa" * 4096)
            f.write(open(img, "rb").read())
            f.write(b"\x55" * 777)
        self.run("check at offset 4096", [self.ufat, "check", "--offset", "4096", "--size", str(n), big])
        self.run("list at offset 4096 no size", [self.ufat, "list", "--offset", "4096", big, "/"])
        self.run("populate --path at offset 4096", [self.ufat, "populate", "--offset", "4096", "--size", str(n), "--path", "/off", big])
        self.run("populate at offset 4096 (no size, slack)", [self.ufat, "populate", "--offset", "4096", big, self.small_tree])
        before = os.path.getsize(big)
        self.run("assemble at offset beyond end", [self.ufat, "assemble", "--offset", str(n * 2), big])
        if os.path.getsize(big) != before:
            print("DEFECT assemble at offset beyond end changed the image size")
            self.defects.append(("assemble offset beyond end", "resize", ""))
        self.run("assemble --create existing with --size", [self.ufat, "assemble", "--create", "--size", "40M", big])
        self.run("assemble --fit on nonexistent dir", [self.ufat, "assemble", "--fit", "/nonexistent", big])
        self.run("assemble --fit on /proc/self", [self.ufat, "assemble", "--fit", "/proc/self", os.path.join(self.work, "fit.img")], timeout=60)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ufat", required=True)
    p.add_argument("--seeds", required=True)
    p.add_argument("--work", required=True)
    p.add_argument("--only", default="", help="comma separated probe groups")
    a = p.parse_args()
    os.makedirs(a.work, exist_ok=True)
    pr = Probes(os.path.abspath(a.ufat), os.path.abspath(a.seeds), os.path.abspath(a.work))
    groups = ["timestamps", "cli_sizes", "offsets", "images_hand_made", "manifests", "alias_exhaustion", "big_directory"]
    if a.only:
        groups = a.only.split(",")
    for g in groups:
        print("== %s" % g)
        getattr(pr, g)()
    print()
    print("%d defects" % len(pr.defects))
    for d in pr.defects:
        print("  ", d)
    sys.exit(1 if pr.defects else 0)


if __name__ == "__main__":
    main()
