#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Robustness tests for the Varlink service in the ufat binary.

Every case starts a fresh server with a connected socket passed as fd 3
through the LISTEN_FDS protocol (or on stdin/stdout with
SYSTEMD_VARLINK_LISTEN=-), sends it malformed or hostile input, and checks
that the service answers with an error or drops the connection, and exits
cleanly (status 0) once the client is gone. A panic (exit 101), a signal, a
server that does not exit after the client hung up, or an outsized RSS is a
defect and is saved under OUT/varlink-findings/<signature>/.

    tests/fuzz/varlink_fuzz.py --ufat build/ufat --seeds SEEDS --out OUT [--count N]

Python 3 standard library only; reuses the mutators of mutate.py.
"""

import argparse
import array
import json
import os
import random
import re
import resource
import signal
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mutate  # noqa: E402

MEM_LIMIT_BYTES = 4_000_000 * 1024
FSIZE_LIMIT = 1 << 30


class Server:
    """A ufat process serving one connected socket (fd 3) or stdio."""

    def __init__(self, ufat, work, stdio=False, env=None):
        self.ufat = ufat
        self.stdio = stdio
        self.err_path = os.path.join(work, "server-stderr.txt")
        err_fd = os.open(self.err_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        if stdio:
            in_r, in_w = os.pipe()
            out_r, out_w = os.pipe()
        else:
            ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        self.start = time.monotonic()
        pid = os.fork()
        if pid == 0:
            try:
                os.setsid()
                resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
                resource.setrlimit(resource.RLIMIT_FSIZE, (FSIZE_LIMIT, FSIZE_LIMIT))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                os.dup2(err_fd, 2)
                e = dict(os.environ)
                for k in ("SOURCE_DATE_EPOCH", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES", "SYSTEMD_VARLINK_LISTEN"):
                    e.pop(k, None)
                if stdio:
                    os.dup2(in_r, 0)
                    os.dup2(out_w, 1)
                    e["SYSTEMD_VARLINK_LISTEN"] = "-"
                else:
                    os.dup2(theirs.fileno(), 3)
                    null = os.open(os.devnull, os.O_RDWR)
                    os.dup2(null, 0)
                    os.dup2(null, 1)
                    e["LISTEN_PID"] = str(os.getpid())
                    e["LISTEN_FDS"] = "1"
                    e["LISTEN_FDNAMES"] = "varlink"
                if env:
                    e.update(env)
                os.execve(ufat, [ufat], e)
            except BaseException:
                os._exit(127)
        os.close(err_fd)
        self.pid = pid
        if stdio:
            os.close(in_r)
            os.close(out_w)
            self.w = in_w
            self.r = out_r
        else:
            theirs.close()
            self.sock = ours
            self.sock.setblocking(False)
            self.w = self.sock.fileno()
            self.r = self.sock.fileno()
        self.result = None
        self.hwm_kb = None

    def send(self, data, timeout=5.0):
        """Writes a message, returns the number of bytes written before the
        timeout or a closed peer. A message built by fdcall() carries
        descriptors: they are opened from their specs, sent with the first
        bytes as SCM_RIGHTS, and closed again. Over stdio there is no way
        to pass them, so the bytes go alone."""
        fds = []
        if isinstance(data, tuple):
            _, data, specs = data
            if not self.stdio:
                for spec in specs:
                    try:
                        fds.append(open_spec(spec))
                    except OSError:
                        pass
        view = memoryview(bytes(data))
        done = 0
        deadline = time.monotonic() + timeout
        import select
        try:
            if fds and done < len(view):
                r, w, _ = select.select([], [self.w], [], max(0, deadline - time.monotonic()))
                if w:
                    try:
                        done = self.sock.sendmsg([view[:65536]], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
                    except (BrokenPipeError, ConnectionResetError, BlockingIOError, PermissionError):
                        pass
        finally:
            for fd in fds:
                os.close(fd)
        while done < len(view):
            r, w, _ = select.select([], [self.w], [], max(0, deadline - time.monotonic()))
            if not w:
                break
            try:
                n = os.write(self.w, view[done:done + 65536])
            except (BrokenPipeError, ConnectionResetError):
                break
            except BlockingIOError:
                continue
            done += n
        return done

    def recv(self, timeout=5.0, until_nul=True, maxbytes=1 << 24):
        """Reads until a NUL (one message), EOF or the timeout. Returns
        (bytes, eof)."""
        import select
        buf = bytearray()
        deadline = time.monotonic() + timeout
        eof = False
        while True:
            if until_nul and b"\0" in buf:
                break
            if len(buf) >= maxbytes:
                break
            r, _, _ = select.select([self.r], [], [], max(0, deadline - time.monotonic()))
            if not r:
                break
            try:
                chunk = os.read(self.r, 65536)
            except (ConnectionResetError, BlockingIOError):
                chunk = b""
                if isinstance(sys.exc_info()[1], BlockingIOError):
                    continue
            if not chunk:
                eof = True
                break
            buf += chunk
        self.peak_rss_kb()
        return bytes(buf), eof

    def peak_rss_kb(self):
        """VmHWM of the server, read while it is still alive. Unlike
        ru_maxrss it does not include the RSS inherited before exec. The
        largest value seen is kept in hwm_kb."""
        try:
            with open("/proc/%d/status" % self.pid) as f:
                for line in f:
                    if line.startswith("VmHWM:"):
                        v = int(line.split()[1])
                        if self.hwm_kb is None or v > self.hwm_kb:
                            self.hwm_kb = v
                        return v
        except OSError:
            pass
        return None

    def shutdown_write(self):
        if self.stdio:
            try:
                os.close(self.w)
            except OSError:
                pass
            self.w = -1
        else:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.peak_rss_kb()
        if self.stdio:
            for fd in (self.w, self.r):
                try:
                    if fd >= 0:
                        os.close(fd)
                except OSError:
                    pass
            self.w = self.r = -1
        else:
            try:
                self.sock.close()
            except OSError:
                pass

    def wait(self, timeout=5.0):
        """Waits for the server to exit, killing it after the timeout."""
        if self.result is not None:
            return self.result
        deadline = time.monotonic() + timeout
        delay = 0.0005
        timed_out = False
        while True:
            wpid, status, ru = os.wait4(self.pid, os.WNOHANG)
            if wpid == self.pid:
                break
            if time.monotonic() > deadline:
                timed_out = True
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                wpid, status, ru = os.wait4(self.pid, 0)
                break
            time.sleep(delay)
            delay = min(delay * 1.5, 0.01)
        self.peak_rss_kb()
        # ru_maxrss includes what the server inherited from this process
        # before exec, so it is recorded but not judged.
        res = {"secs": round(time.monotonic() - self.start, 4), "rss_kb": self.hwm_kb if self.hwm_kb is not None else 0,
               "maxrss_kb": ru.ru_maxrss, "timeout": timed_out}
        if os.WIFEXITED(status):
            res["exit"] = os.WEXITSTATUS(status)
            res["signal"] = None
        else:
            res["exit"] = None
            res["signal"] = os.WTERMSIG(status)
        try:
            with open(self.err_path, "rb") as f:
                res["stderr"] = f.read()[-4000:].decode("utf-8", "replace")
        except OSError:
            res["stderr"] = ""
        self.result = res
        return res


def msg(obj):
    return json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\0"


def call(method, params=None, **flags):
    m = {"method": method}
    if params is not None:
        m["parameters"] = params
    m.update(flags)
    return msg(m)


def fdcall(method, params, fds, **flags):
    """A call with descriptors passed along: fds is a list of specs, each a
    path opened read-only, or (path, mode) with mode "rw" (read-write),
    "dir" (a directory), "path" (O_PATH), "append" (read-write with
    O_APPEND), "wo" (write-only) or "nonblock" (read-only, O_NONBLOCK).
    Index i in the parameters names fds[i]."""
    return ("fds", call(method, params, **flags), list(fds))


def open_spec(spec):
    if isinstance(spec, tuple):
        path, mode = spec
    else:
        path, mode = spec, "r"
    flags = {"r": os.O_RDONLY, "rw": os.O_RDWR, "dir": os.O_RDONLY | os.O_DIRECTORY, "path": os.O_PATH,
             "append": os.O_RDWR | os.O_APPEND, "wo": os.O_WRONLY, "nonblock": os.O_RDONLY | os.O_NONBLOCK}[mode]
    if mode == "rw" and not os.path.exists(path):
        flags |= os.O_CREAT
    return os.open(path, flags | os.O_CLOEXEC, 0o644)


IMG = {"image": {"fileDescriptor": 0}}
IFACE = "org.uapi-group.FileSystem."


def message_bytes(m):
    """The bytes of a message built by call() or fdcall()."""
    return m[1] if isinstance(m, tuple) else bytes(m)


def decode_reply(data):
    try:
        return json.loads(data.rstrip(b"\0").decode("utf-8"))
    except Exception:
        return None


# ----------------------------------------------------------------- cases

def protocol_cases(rng, img):
    """Raw byte sequences to send, each followed by closing the connection.
    Expectation: the server drops the connection or answers an error, and
    exits 0."""
    cases = []
    deep = rng.choice([100, 128, 129, 1000, 100000])
    cases += [
        ("empty-close", b""),
        ("nul-only", b"\0"),
        ("many-nuls", b"\0" * 1000),
        ("not-json", b"not json at all\0"),
        ("array", b"[1,2,3]\0"),
        ("number", b"42\0"),
        ("string", b'"hello"\0'),
        ("empty-object", b"{}\0"),
        ("no-method", b'{"parameters":{}}\0'),
        ("method-int", b'{"method":5}\0'),
        ("method-null", b'{"method":null}\0'),
        ("method-empty", b'{"method":""}\0'),
        ("method-dots", b'{"method":"..."}\0'),
        ("method-long", b'{"method":"' + b"a" * 100000 + b'"}\0'),
        ("method-unicode", '{"method":"org.uapi-group.FileSystem.Describ\u00e9"}\0'.encode("utf-8")),
        ("params-array", b'{"method":"org.uapi-group.FileSystem.Describe","parameters":[]}\0'),
        ("params-string", b'{"method":"org.uapi-group.FileSystem.Describe","parameters":"x"}\0'),
        ("params-null", b'{"method":"org.varlink.service.GetInfo","parameters":null}\0'),
        ("unknown-key", b'{"method":"org.varlink.service.GetInfo","bogus":1}\0'),
        ("vendor-key", b'{"method":"org.varlink.service.GetInfo","org.example.x":{"a":[1,2]}}\0'),
        ("two-flags", b'{"method":"org.varlink.service.GetInfo","more":true,"oneway":true}\0'),
        ("three-flags", b'{"method":"org.varlink.service.GetInfo","more":true,"oneway":true,"upgrade":true}\0'),
        ("flag-int", b'{"method":"org.varlink.service.GetInfo","more":1}\0'),
        ("flag-string", b'{"method":"org.varlink.service.GetInfo","upgrade":"true"}\0'),
        ("flags-false", b'{"method":"org.varlink.service.GetInfo","more":false,"oneway":false,"upgrade":false}\0'),
        ("oneway-error", b'{"method":"org.uapi-group.FileSystem.Nope","oneway":true}\0{"method":"org.varlink.service.GetInfo"}\0'),
        ("more-on-plain", b'{"method":"org.varlink.service.GetInfo","more":true}\0'),
        ("upgrade-on-plain", b'{"method":"org.varlink.service.GetInfo","upgrade":true}\0'),
        ("upgrade-on-info", fdcall("org.uapi-group.FileSystem.Describe", IMG, [img], upgrade=True)),
        ("more-on-check", fdcall("org.uapi-group.FileSystem.Check", IMG, [img], more=True)),
        ("more-on-list", fdcall("org.uapi-group.FileSystem.List", IMG, [img], more=True)),
        ("more-on-describe", fdcall("org.uapi-group.FileSystem.Describe", IMG, [img], more=True)),
        ("more-on-capabilities", call("org.uapi-group.FileSystem.GetCapabilities", {}, more=True)),
        ("capabilities-other-type", call("org.uapi-group.FileSystem.GetCapabilities", {"fileSystemType": "ext4"})),
        ("capabilities-bogus-type", call("org.uapi-group.FileSystem.GetCapabilities", {"fileSystemType": 5})),
        ("dup-key", b'{"method":"org.varlink.service.GetInfo","method":"org.varlink.service.GetInfo"}\0'),
        ("unterminated-then-close", b'{"method":"org.varlink.service.GetInfo"}'),
        ("half-json-then-close", b'{"method":'),
        ("truncated-string", b'{"method":"org.varlink.serv'),
        ("invalid-utf8", b'{"method":"\xff\xfe"}\0'),
        ("overlong-utf8", b'{"method":"\xc0\xaf"}\0'),
        ("lone-surrogate", b'{"method":"\\ud800"}\0'),
        ("control-char", b'{"method":"a\x01b"}\0'),
        ("nul-in-string", b'{"method":"a\\u0000b"}\0'),
        ("deep-array", b'{"method":"x","parameters":{"a":' + b"[" * deep + b"]" * deep + b"}}\0"),
        ("deep-object", b'{"method":"x","parameters":' + b'{"a":' * deep + b"1" + b"}" * deep + b"}\0"),
        ("big-number", ("fds", b'{"method":"org.uapi-group.FileSystem.Describe","parameters":{"image":{"fileDescriptor":0,"offset":' + b"9" * 5000 + b"}}}\0", [img])),
        ("float-offset", ("fds", b'{"method":"org.uapi-group.FileSystem.Describe","parameters":{"image":{"fileDescriptor":0,"offset":1.5}}}\0', [img])),
        ("neg-offset", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "offset": -1}}, [img])),
        ("huge-offset", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "offset": 2 ** 63}}, [img])),
        ("huge-offset-str", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "offset": "18446744073709551615"}}, [img])),
        ("i128-offset-str", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "offset": "170141183460469231731687303715884105727"}}, [img])),
        ("size-zero", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "size": 0}}, [img])),
        ("size-one", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "size": 1}}, [img])),
        ("size-huge", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "size": 2 ** 64 - 1}}, [img])),
        ("offset-eq-size", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 0, "offset": os.path.getsize(img)}}, [img])),
        ("offset-512-size-rest", fdcall("org.uapi-group.FileSystem.Check", {"image": {"fileDescriptor": 0, "offset": 512}}, [img])),
        ("fd-index-neg", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": -1}}, [img])),
        ("fd-index-huge", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": 2 ** 64 - 1}}, [img])),
        ("fd-index-str", fdcall("org.uapi-group.FileSystem.Describe", {"image": {"fileDescriptor": "0"}}, [img])),
        ("fd-index-float", ("fds", b'{"method":"org.uapi-group.FileSystem.Describe","parameters":{"image":{"fileDescriptor":0.5}}}\0', [img])),
        ("fd-none-passed", call("org.uapi-group.FileSystem.Describe", IMG)),
        ("fd-two-passed-one-named", fdcall("org.uapi-group.FileSystem.Describe", IMG, [img, img])),
        ("fd-many-passed", fdcall("org.uapi-group.FileSystem.Describe", IMG, [img] * 200)),
        ("fd-unused-with-getinfo", fdcall("org.varlink.service.GetInfo", None, [img, img, img])),
        ("whitespace", b"   \n\t " + call("org.varlink.service.GetInfo") + b"  \0"),
        ("two-calls", call("org.varlink.service.GetInfo") + call("org.varlink.service.GetInfo")),
        ("pipelined-100", call("org.varlink.service.GetInfo") * 100),
        ("get-desc-missing", call("org.varlink.service.GetInterfaceDescription", {})),
        ("get-desc-bad", call("org.varlink.service.GetInterfaceDescription", {"interface": "io.nope"})),
        ("get-desc-int", call("org.varlink.service.GetInterfaceDescription", {"interface": 5})),
        ("get-desc-long", call("org.varlink.service.GetInterfaceDescription", {"interface": "a" * 1000000})),
        ("getinfo-params", call("org.varlink.service.GetInfo", {"x": 1})),
        ("unknown-iface", call("io.nope.X.Y")),
        ("unknown-method", call("org.uapi-group.FileSystem.Nope")),
        ("own-error-as-method", call("org.uapi-group.FileSystem.Corrupt")),
        ("type-as-method", call("org.uapi-group.FileSystem.Image")),
        ("systemd-iface", call("io.systemd.Anything")),
        ("binary-garbage", bytes(rng.randrange(256) for _ in range(rng.choice([1, 100, 5000]))) + b"\0"),
        ("garbage-no-nul", bytes(rng.randrange(1, 256) for _ in range(rng.choice([1, 100, 70000])))),
        ("msg-16MiB-minus", b'{"method":"org.varlink.service.GetInfo","org.x":"' + b" " * (16 * 1024 * 1024 - 60) + b'"}\0'),
        ("msg-16MiB-plus-nonul", b" " * (16 * 1024 * 1024 + 10)),
        ("msg-17MiB", b'{"method":"org.varlink.service.GetInfo","org.x":"' + b" " * (17 * 1024 * 1024) + b'"}\0'),
        ("string-16MiB-param", fdcall("org.uapi-group.FileSystem.List", {"image": {"fileDescriptor": 0}, "path": "x" * (15 * 1024 * 1024)}, [img])),
    ]
    return cases


def method_cases(rng, seeds, work, small_tree, img):
    """Well-formed calls with hostile parameters. Expectation: a reply, an
    error or a dropped connection; a second GetInfo afterwards shows the
    service survived."""
    cases = []
    # Descriptors of the wrong kind, opened the wrong way, or none at all.
    weird_fds = [["/dev/null"], ["/dev/zero"], [("/dev/null", "rw")], ["/proc/self/exe"], [(work, "dir")], [("/", "dir")],
                 [(img, "path")], [(img, "append")], [(img, "wo")], [(img, "nonblock")], ["/dev/full"], ["/proc/self/mounts"],
                 [(img, "rw")], [img], []]
    for fds in weird_fds:
        label = "%r" % (fds[:1],)
        for m in ("Describe", "List", "Check"):
            cases.append(("%s-fd-%s" % (m, label[:30]), [fdcall(IFACE + m, IMG, fds)]))
        cases.append(("Populate-fd-%s" % label[:30], [fdcall(IFACE + "Populate", {"image": {"fileDescriptor": 0}, "path": "/x"}, fds)]))
        cases.append(("Describe-sink-fd-%s" % label[:30], [fdcall(IFACE + "Describe", {"image": {"fileDescriptor": 0}, "manifestSink": {"fileDescriptor": 1}}, [img] + fds)]))
    inner = ["", "/", "//", "/../x", "/./x", "/a/../b", "/" + "a" * 255, "/" + "a" * 256, "/" + "a/" * 2000, "/con", "/a:b", "/a*b",
             "/\u0000", "/x\u0000y", "/\uffff", "/\ufffe", "/a ", "/ a", "/a.", "/日本語/ünïcödé", "/" + "\U0001F600" * 200,
             "/" + "é" * 200, "/EFI/BOOT/BOOTX64.EFI/x", "/EFI/BOOT/BOOTX64.EFI", "/EFI", "/empty dir", "/missing"]
    hello = os.path.join(small_tree, "hello.txt")
    rw = [(img, "rw")]
    for p in inner:
        cases.append(("List-%r" % p[:20], [fdcall(IFACE + "List", {"image": {"fileDescriptor": 0}, "path": p}, [img], more=True)]))
        cases.append(("Populate-mkdir-%r" % p[:20], [fdcall(IFACE + "Populate", {"image": {"fileDescriptor": 0}, "path": p, "parents": rng.random() < 0.5}, rw)]))
        cases.append(("Remove-%r" % p[:20], [fdcall(IFACE + "Remove", {"image": {"fileDescriptor": 0}, "path": p}, rw)]))
        cases.append(("Remove-recursive-%r" % p[:20], [fdcall(IFACE + "Remove", {"image": {"fileDescriptor": 0}, "path": p, "recursive": True}, rw)]))
        cases.append(("Populate-file-%r" % p[:20], [fdcall(IFACE + "Populate", {"image": {"fileDescriptor": 0}, "path": p, "content": {"sourceFileDescriptor": 1}}, rw + [hello])]))
    # Wrong types for every field of a few methods.
    for field, bad in [("image", 5), ("image", "x"), ("image", None), ("image", {}), ("image", {"fileDescriptor": "x"}), ("image", {"fileDescriptor": None}),
                       ("image", {"fileDescriptor": 0, "offset": "x"}), ("image", {"fileDescriptor": 0, "offset": None, "size": None}),
                       ("image", {"fileDescriptor": 0, "bogus": 1}), ("image", {"fileDescriptor": 1}), ("path", 5), ("path", None), ("path", []),
                       ("parents", "yes"), ("parents", 1), ("timestampUSec", -1), ("timestampUSec", 2 ** 64 - 1), ("timestampUSec", "18446744073709551615"),
                       ("timestampUSec", 1.5), ("timestampUSec", "abc"), ("timestampUSec", 2 ** 100)]:
        params = {"image": {"fileDescriptor": 0}, "path": "/t"}
        params[field] = bad
        cases.append(("Populate-%s=%r" % (field, str(bad)[:20]), [fdcall(IFACE + "Populate", params, rw)]))
    # Assemble with extreme options on a fresh image file.
    fimg = os.path.join(work, "format.img")
    with open(fimg, "wb") as f:
        f.truncate(40 << 20)
    for opts in [{"sectorSize": 0}, {"sectorSize": 1}, {"sectorSize": 256}, {"sectorSize": 1024}, {"sectorSize": 8192}, {"sectorSize": 2 ** 32},
                 {"sectorSize": 2 ** 64 - 1}, {"sectorSize": "4096"}, {"blockSize": 0}, {"blockSize": 3}, {"blockSize": 2 ** 20},
                 {"blockSize": 2 ** 32 - 1}, {"blockSize": 512, "sectorSize": 4096}, {"label": "x" * 12}, {"label": "日本語"}, {"label": ""},
                 {"label": "A.B"}, {"label": "\u0000"}, {"identifier": ""}, {"identifier": "xyz"}, {"identifier": "1234-ABCD-9999"}, {"identifier": "-"},
                 {"timestampUSec": 2 ** 64 - 1}, {"timestampUSec": 0}, {"timestampUSec": "0"}, {"zero": "yes"}, {"zero": True},
                 {"reproducible": True}, {"reproducible": True, "identifier": "1234-ABCD"}, {"discard": True},
                 {"enableFeatures": ["x"]}, {"ext4": {}}, {"squashfs": {"noPadding": True}}, {"vfat": {"fats": 0}}, {"vfat": {"reservedSectors": 1}},
                 {"vfat": {"oemName": "x" * 9}}, {"vfat": {"oemName": "\u00e9"}}, {"vfat": {"hiddenSectors": 2 ** 40}}, {"vfat": {"mkfsFatCompatible": True}},
                 {"bogus": 1}, None, 5, "x", []]:
        params = {"image": {"fileDescriptor": 0}}
        if opts is not None:
            params["options"] = opts
        cases.append(("Assemble-%s" % json.dumps(opts)[:30], [fdcall(IFACE + "Assemble", params, [(fimg, "rw")])]))
        cases.append(("Plan-%s" % json.dumps(opts)[:30], [fdcall(IFACE + "Assemble", dict(params, mode="plan"), [(fimg, "rw")])]))
    for extra in [{"imageHash": "sha256"}, {"imageHash": "sha512"}, {"imageHash": "md5"}, {"mode": "repair"}, {"fileSystemType": "ext4"}, {"fileSystemType": ""},
                  {"content": {}}, {"content": {"sourceFileDescriptor": 0}}, {"content": {"manifest": {"fileDescriptor": 0}}}, {"content": 5}]:
        cases.append(("Assemble-%s" % json.dumps(extra)[:30], [fdcall(IFACE + "Assemble", dict({"image": {"fileDescriptor": 0}}, **extra), [(fimg, "rw")])]))
    for sz in [0, 1, 511, 512, 4096, 65536, 1 << 20]:
        p = os.path.join(work, "tiny-%d.img" % sz)
        with open(p, "wb") as f:
            f.truncate(sz)
        cases.append(("Assemble-size-%d" % sz, [fdcall(IFACE + "Assemble", {"image": {"fileDescriptor": 0}, "options": {}}, [(p, "rw")])]))
        cases.append(("Info-size-%d" % sz, [fdcall("org.uapi-group.FileSystem.Describe", IMG, [p])]))
    # Assemble with mode plan, with odd sources and manifests, every one a
    # descriptor.
    for name, fds, index in [("none", [], None), ("tree", [(small_tree, "dir")], 0), ("devnull", ["/dev/null"], 0), ("file", [hello], 0),
                             ("out-of-range", [(small_tree, "dir")], 5), ("neg", [(small_tree, "dir")], -1), ("str-type", [(small_tree, "dir")], "x"),
                             ("list-type", [(small_tree, "dir")], [0]), ("null", [(small_tree, "dir")], None), ("opath", [(small_tree, "path")], 0),
                             ("rw-image", [(img, "rw")], 0)]:
        content = {} if index is None else {"sourceFileDescriptor": index}
        cases.append(("Plan-source-%s" % name, [fdcall(IFACE + "Assemble", {"mode": "plan", "content": content}, fds)]))
    for text in ["", "\x1e", "\x1e{}", "garbage", "\x1e" * 100000]:
        mpath = os.path.join(work, "odd-manifest-%d" % len(text))
        with open(mpath, "wb") as f:
            f.write(text.encode("utf-8"))
        cases.append(("Plan-manifest-%r" % text[:10], [fdcall(IFACE + "Assemble", {"mode": "plan", "content": {"manifest": {"fileDescriptor": 0}}}, [mpath])]))
    for extra, fds in [({"options": {"sectorSize": 0}}, [(small_tree, "dir")]), ({"options": {"sectorSize": 1024}}, [(small_tree, "dir")]),
                       ({"options": {"blockSize": 7}}, [(small_tree, "dir")]), ({"options": {"blockSize": 2 ** 40}}, [(small_tree, "dir")]),
                       ({"options": {"label": 1}}, [(small_tree, "dir")]),
                       ({"content": {"sourceFileDescriptor": 0, "manifest": {"fileDescriptor": 5}}}, [(small_tree, "dir")]),
                       ({"content": {"sourceFileDescriptor": 0, "manifest": {"fileDescriptor": 0}}}, [(small_tree, "dir")]),
                       ({"content": {"sourceFileDescriptor": 0, "manifest": {"fileDescriptor": 1}}}, [(small_tree, "dir"), (small_tree, "dir")]),
                       ({"content": {"sourceFileDescriptor": 0, "manifest": {"fileDescriptor": 1}}}, [(small_tree, "dir"), (img, "rw")]),
                       ({"content": {"sourceFileDescriptor": 0, "unsupported": "fail"}}, [(small_tree, "dir")]),
                       ({"content": {"sourceFileDescriptor": 0, "unsupported": "maybe"}}, [(small_tree, "dir")]),
                       ({"imageHash": "sha256"}, [(small_tree, "dir")])]:
        params = {"mode": "plan", "content": {"sourceFileDescriptor": 0}}
        params.update(extra)
        cases.append(("Plan-%s" % json.dumps(extra)[:30], [fdcall(IFACE + "Assemble", params, fds)]))
    # Populate with a tree, with odd sources and policies.
    tree = (small_tree, "dir")
    sink_path = os.path.join(work, "sink")
    open(sink_path, "wb").close()
    for content, fds in [({"sourceFileDescriptor": 1}, rw), ({"sourceFileDescriptor": 1}, rw + [hello]), ({"sourceFileDescriptor": 1}, rw + [(small_tree, "path")]),
                         ({"sourceFileDescriptor": 1, "destination": "/../x"}, rw + [tree]), ({"sourceFileDescriptor": 1, "destination": "/EFI/BOOT/BOOTX64.EFI"}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "times": "weird"}, rw + [tree]), ({"sourceFileDescriptor": 1, "times": "fixed"}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "times": "clamp", "timestampUSec": 2 ** 64 - 1}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "times": "fixed", "timestampUSec": 0}, rw + [tree]), ({"sourceFileDescriptor": 1, "followSymlinks": "x"}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "replace": None}, rw + [tree]), ({"sourceFileDescriptor": 1}, rw + [("/dev", "dir")]),
                         ({"sourceFileDescriptor": 0}, rw), ({"sourceFileDescriptor": 1}, [img, tree]),
                         ({"sourceFileDescriptor": 1, "unsupported": "fail"}, rw + [("/dev", "dir")]), ({"sourceFileDescriptor": 1, "uid": -1, "gid": 2 ** 40}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "manifestSink": {"fileDescriptor": 1}}, rw + [tree]),
                         ({"sourceFileDescriptor": 1, "manifestSink": {"fileDescriptor": 2, "fields": ["bogus"]}}, rw + [tree, (sink_path, "wo")]),
                         ({"sourceFileDescriptor": 1, "manifestSink": {"fileDescriptor": 2, "fields": ["size", "hash", "mtime"]}}, rw + [tree, (sink_path, "wo")]),
                         ({"sourceFileDescriptor": 1, "manifestSink": {"fileDescriptor": 2}}, rw + [tree, sink_path])]:
        content = dict(content)
        params = {"image": {"fileDescriptor": 0}, "path": content.pop("destination", "/"), "content": content}
        if "timestampUSec" in content:
            params["timestampUSec"] = content.pop("timestampUSec")
        cases.append(("Populate-%s" % json.dumps({k: v for k, v in params.items() if k != "image"})[:40], [fdcall(IFACE + "Populate", params, fds)]))
    return cases


def manifest_cases(rng, seeds, work, img, count):
    """Assemble, written and planned, with mutated manifests."""
    cases = []
    msets = [(n, mutate.load_seed(p)[0]) for n, p in seeds["manifests"]]
    for i in range(count):
        name, data = rng.choice(msets)
        variant, desc = mutate.mutate_manifest(rng, data)
        text = variant.decode("utf-8", "surrogateescape")
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            text = variant.decode("utf-8", "replace")
        source = mutate.source_tree_for(seeds["dir"], name)
        fimg = os.path.join(work, "assemble.img")
        mpath = os.path.join(work, "case.Uapi16Manifest")
        kind = rng.random()
        if kind < 0.45:
            content = {"manifest": {"fileDescriptor": 1}, "sourceFileDescriptor": 2, "unsupported": "fail"}
            if rng.random() < 0.3:
                content["unsupported"] = "skip"
                content["manifest"]["checkValidity"] = False
            params = {"image": {"fileDescriptor": 0}, "options": {}, "content": content}
            cases.append(("Assemble-manifest[%s]" % desc[:40], [fdcall(IFACE + "Assemble", params, [(fimg, "rw"), mpath, (source, "dir")])],
                          {"manifest": variant, "cleanup": fimg}))
        elif kind < 0.65:
            cases.append(("Plan-manifest[%s]" % desc[:40], [fdcall(IFACE + "Assemble", {"mode": "plan", "content": {"manifest": {"fileDescriptor": 0}}}, [mpath])],
                          {"manifest": variant}))
        else:
            # The contents from a stream of random length instead of the
            # directory: too short, too long, or just right by accident.
            blob = os.path.join(work, "case.blob")
            n = rng.choice([0, 1, 1000, 100000, 1 << 20])
            params = {"image": {"fileDescriptor": 0}, "options": {}, "content": {"manifest": {"fileDescriptor": 1}, "sourceFileDescriptor": 2}}
            cases.append(("Assemble-stream[%s]" % desc[:40], [fdcall(IFACE + "Assemble", params, [(fimg, "rw"), mpath, blob])],
                          {"manifest": variant, "cleanup": fimg, "blob": bytes([0x5A]) * n, "blob_path": blob}))
    return cases


def image_cases(rng, seeds, work, count):
    """Describe/List/Check/Populate/Remove on mutated images."""
    cases = []
    isets = [(n, p) for n, p in seeds["images"]]
    for i in range(count):
        name, path = rng.choice(isets)
        data, info = mutate.load_seed(path)
        strat = rng.choices(list(mutate.IMAGE_WEIGHTS), weights=list(mutate.IMAGE_WEIGHTS.values()))[0]
        edits, desc = mutate.IMAGE_STRATEGIES[strat](rng, info)
        variant = mutate.apply_edits(data, edits)
        vpath = os.path.join(work, "variant.img")
        files = [e["path"] for e in info.files if e["path"]]
        target = rng.choice(files) if files else "/x"
        calls = [
            fdcall(IFACE + "Describe", IMG, [vpath]),
            fdcall(IFACE + "List", {"image": {"fileDescriptor": 0}, "path": rng.choice(["/", "/EFI", "/EFI/Linux", "/deep/er"])}, [vpath], more=True),
            fdcall(IFACE + "Check", IMG, [vpath], more=rng.random() < 0.5),
            fdcall(IFACE + "Populate", {"image": {"fileDescriptor": 0}, "path": "/varlink new", "timestampUSec": 1700000000000000}, [(vpath, "rw")]),
            fdcall(IFACE + "Remove", {"image": {"fileDescriptor": 0}, "path": target, "recursive": rng.random() < 0.5}, [(vpath, "rw")]),
        ]
        cases.append(("Image[%s/%s]" % (name, desc[:40]), calls, {"image": variant, "image_path": vpath, "edits": edits, "seed": name}))
    return cases


# ----------------------------------------------------------------- running

def classify(res, mem_mb):
    if res["timeout"]:
        return "hang", "server did not exit %.1fs after the client hung up" % res["secs"]
    if res["signal"] is not None:
        return "signal", "killed by signal %d" % res["signal"]
    if res["exit"] == 101 or "panicked at" in res.get("stderr", ""):
        m = re.search(r"panicked at ([^:\n]+:\d+:\d+)", res.get("stderr", ""))
        return "panic", m.group(1) if m else "exit 101"
    if res["rss_kb"] > mem_mb * 1024:
        return "memory", "RSS %d MB" % (res["rss_kb"] // 1024)
    if res["exit"] != 0:
        return "exit", "exit status %s" % res["exit"]
    return None, None


def run_case(ufat, work, name, payload, extra, timeout, mem_mb, stdio=False, log=None):
    extra = extra or {}
    if "manifest" in extra:
        with open(os.path.join(work, "case.Uapi16Manifest"), "wb") as f:
            f.write(extra["manifest"])
    if "image" in extra:
        with open(extra["image_path"], "wb") as f:
            f.write(extra["image"])
    if extra.get("cleanup"):
        try:
            os.unlink(extra["cleanup"])
        except FileNotFoundError:
            pass
    if "blob" in extra:
        with open(extra["blob_path"], "wb") as f:
            f.write(extra["blob"])
    s = Server(ufat, work, stdio=stdio)
    replies = []
    try:
        if True:
            eof = False
            if isinstance(payload, (bytes, bytearray, tuple)):
                payload = [payload]
            for m in payload:
                s.send(m, timeout)
                # Without a terminating NUL no reply can come; look only
                # briefly for a dropped connection.
                data, eof = s.recv(timeout if message_bytes(m).endswith(b"\0") else 0.3)
                replies.append(data[:300])
                if eof:
                    break
            # The service must still answer after whatever happened.
            if not eof and not (replies and replies[-1] == b""):
                s.send(call("org.varlink.service.GetInfo"), timeout)
                data, eof = s.recv(timeout)
                replies.append(data[:120])
            s.close()
    finally:
        res = s.wait(timeout)
    res["replies"] = [r.decode("utf-8", "replace") for r in replies]
    kind, detail = classify(res, mem_mb)
    if log is not None:
        log.write(json.dumps({"case": name, "stdio": stdio, "kind": kind, "detail": detail, "exit": res["exit"], "signal": res["signal"],
                              "secs": res["secs"], "rss_kb": res["rss_kb"], "replies": res["replies"][:3]}) + "\n")
        log.flush()
    return kind, detail, res


def save_finding(out, name, kind, detail, res, extra, payload):
    sig = ("panic@" + re.sub(r"[/:]", "_", detail)) if kind == "panic" else "%s:%s" % (kind, name.split("[")[0].split("-")[0])
    d = os.path.join(out, "varlink-findings", sig)
    os.makedirs(d, exist_ok=True)
    existing = [x for x in os.listdir(d) if x.startswith("case-")]
    if len(existing) >= 3:
        with open(os.path.join(d, "count"), "a") as f:
            f.write(name + "\n")
        return sig
    case = os.path.join(d, "case-%d" % (len(existing) + 1))
    os.makedirs(case)
    with open(os.path.join(case, "info.json"), "w") as f:
        json.dump({"case": name, "kind": kind, "detail": detail, "result": {k: v for k, v in res.items() if k != "stderr"},
                   "stderr": res.get("stderr", ""), "edits": mutate.edits_to_json(extra["edits"]) if extra and "edits" in extra else None,
                   "seed": extra.get("seed") if extra else None}, f, indent=1, default=str)
    if extra and "manifest" in extra:
        with open(os.path.join(case, "manifest.Uapi16Manifest"), "wb") as f:
            f.write(extra["manifest"])
    if extra and "image" in extra:
        with open(os.path.join(case, "variant.img"), "wb") as f:
            f.write(extra["image"])
    with open(os.path.join(case, "payload.bin"), "wb") as f:
        if isinstance(payload, (bytes, bytearray, tuple)):
            payload = [payload]
        for m in payload:
            f.write(message_bytes(m))
            if isinstance(m, tuple):
                f.write(("\n# descriptors: %r\n" % (m[2],)).encode("utf-8"))
    return sig


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ufat", required=True)
    p.add_argument("--seeds", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--count", type=int, default=300, help="mutated manifests and images to push through the service, each")
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--mem-mb", type=int, default=300)
    a = p.parse_args()
    a.ufat = os.path.abspath(a.ufat)
    a.seeds = os.path.abspath(a.seeds)
    a.out = os.path.abspath(a.out)
    work = os.path.join(a.out, "vwork-%d" % os.getpid())
    os.makedirs(work, exist_ok=True)
    rng = random.Random(a.seed)
    seeds = {
        "dir": a.seeds,
        "images": sorted((n, os.path.join(a.seeds, "images", n)) for n in os.listdir(os.path.join(a.seeds, "images")) if n.endswith(".img")),
        "manifests": sorted((n, os.path.join(a.seeds, "manifests", n)) for n in os.listdir(os.path.join(a.seeds, "manifests"))),
    }
    small_tree = os.path.join(a.seeds, "trees", "small")
    img = os.path.join(work, "seed.img")
    with open(img, "wb") as f:
        f.write(mutate.load_seed(seeds["images"][-1][1])[0])
    start = time.time()
    stats = {}
    findings = []
    log = open(os.path.join(a.out, "varlink-log-%d.jsonl" % a.seed), "w")

    def go(label, cases, stdio=False):
        for name, payload, *rest in cases:
            extra = rest[0] if rest else None
            # Image mutations are relative to a pristine seed copy for the raw cases.
            kind, detail, res = run_case(a.ufat, work, name, payload, extra, a.timeout, a.mem_mb, stdio=stdio, log=log)
            stats[(label, kind or "ok")] = stats.get((label, kind or "ok"), 0) + 1
            if kind:
                sig = save_finding(a.out, name, kind, detail, res, extra, payload)
                findings.append((sig, name, kind, detail))
        sys.stderr.write("[varlink] %s: %d cases, %d findings so far, %.0fs\n" % (label, len(cases), len(findings), time.time() - start))

    with open(img, "wb") as f:
        f.write(mutate.load_seed(seeds["images"][-1][1])[0])
    go("protocol-fd3", protocol_cases(rng, img))
    with open(img, "wb") as f:
        f.write(mutate.load_seed(seeds["images"][-1][1])[0])
    go("protocol-stdio", [c for c in protocol_cases(rng, img) if "16MiB" not in c[0] and "17MiB" not in c[0]], stdio=True)
    with open(img, "wb") as f:
        f.write(mutate.load_seed(seeds["images"][-1][1])[0])
    go("methods", method_cases(rng, seeds, work, small_tree, img))
    go("manifests", manifest_cases(rng, seeds, work, img, a.count))
    go("images", image_cases(rng, seeds, work, a.count))
    log.close()
    import shutil
    shutil.rmtree(work, ignore_errors=True)
    report = {"seconds": round(time.time() - start, 1), "stats": {"%s/%s" % k: v for k, v in stats.items()},
              "findings": [{"sig": s, "case": n, "kind": k, "detail": d} for (s, n, k, d) in findings]}
    with open(os.path.join(a.out, "report-varlink-%d.json" % a.seed), "w") as f:
        json.dump(report, f, indent=1)
    by_sig = {}
    for s, n, k, d in findings:
        by_sig[s] = by_sig.get(s, 0) + 1
    for s, n in sorted(by_sig.items(), key=lambda x: -x[1]):
        sys.stderr.write("  %6d  %s\n" % (n, s))
    sys.stderr.write("stats: %s\n" % json.dumps(report["stats"]))
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
