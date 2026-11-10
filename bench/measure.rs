// SPDX-License-Identifier: LGPL-2.1-or-later
//! measure: runs one command, or one Varlink call against the ufat binary,
//! and prints what it cost: wall, user and system time, peak RSS, and the
//! bytes the child passed to read and write system calls.
//!
//! Standard library only, like the rest of ufat. bench/meson.build builds
//! it against the json and varlink crates.
//!
//! Usage:
//!   measure [OPTIONS] -- COMMAND [ARGS...]
//!   measure [OPTIONS] --ufat BIN --method METHOD [--params JSON] [--fd SPEC]...
//!
//! Options:
//!   -l LABEL        first column of the output line (default: the command)
//!   --stdin FILE    the child's standard input (default: /dev/null)
//!   --stdout FILE   the child's standard output (default: /dev/null)
//!   -v              let the child's standard error through (default: /dev/null)
//!   --fd SPEC       passes a file descriptor along with the Varlink call:
//!                   PATH opened read-only, or rw:PATH opened read-write;
//!                   the n-th --fd is index n in the call's parameters
//!
//! The Varlink form starts BIN the way sd_varlink_connect_exec() does, with
//! a connected socket as file descriptor 3 announced through LISTEN_FDS,
//! sends one call with the descriptors attached and reads the reply.
//!
//! The output is one tab separated line on standard output:
//!   label wall_s user_s sys_s maxrss_kib wchar rchar syscw syscr status
//! wchar, rchar, syscw and syscr come from /proc/PID/io, read after the
//! child exited and before it is reaped, so they cover the child alone.
//! The child's exit status becomes ours.

use std::ffi::{c_int, c_long};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::Instant;

#[repr(C)]
struct Timeval {
    tv_sec: c_long,
    tv_usec: c_long,
}

#[repr(C)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
    ru_maxrss: c_long,
    ru_ixrss: c_long,
    ru_idrss: c_long,
    ru_isrss: c_long,
    ru_minflt: c_long,
    ru_majflt: c_long,
    ru_nswap: c_long,
    ru_inblock: c_long,
    ru_oublock: c_long,
    ru_msgsnd: c_long,
    ru_msgrcv: c_long,
    ru_nsignals: c_long,
    ru_nvcsw: c_long,
    ru_nivcsw: c_long,
}

extern "C" {
    fn waitid(idtype: c_int, id: u32, infop: *mut [u64; 16], options: c_int) -> c_int;
    fn wait4(pid: c_int, status: *mut c_int, options: c_int, rusage: *mut Rusage) -> c_int;
    fn dup2(from: c_int, to: c_int) -> c_int;
    fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
}

const P_PID: c_int = 1;
const WEXITED: c_int = 4;
const WNOWAIT: c_int = 0x0100_0000;
const EINTR: i32 = 4;
const F_SETFD: c_int = 2;

#[derive(Default)]
struct ProcIo {
    rchar: u64,
    wchar: u64,
    syscr: u64,
    syscw: u64,
}

fn read_proc_io(pid: u32) -> ProcIo {
    let mut io = ProcIo::default();
    let text = std::fs::read_to_string(format!("/proc/{}/io", pid)).unwrap_or_default();
    for line in text.lines() {
        if let Some((k, v)) = line.split_once(": ") {
            let v: u64 = v.trim().parse().unwrap_or(0);
            match k {
                "rchar" => io.rchar = v,
                "wchar" => io.wchar = v,
                "syscr" => io.syscr = v,
                "syscw" => io.syscw = v,
                _ => {}
            }
        }
    }
    io
}

/// Waits for the child without reaping it, reads its I/O counters while it
/// is a zombie, then reaps it with its resource usage.
fn wait_measured(pid: u32) -> io::Result<(i32, Rusage, ProcIo)> {
    let raw_pid = c_int::try_from(pid).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut info = [0u64; 16];
    loop {
        // SAFETY: info is a 128 byte buffer, the size of siginfo_t.
        let r = unsafe { waitid(P_PID, pid, &mut info, WEXITED | WNOWAIT) };
        if r == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(EINTR) {
            return Err(e);
        }
    }
    let io = read_proc_io(pid);
    let mut status: c_int = 0;
    // SAFETY: Rusage is plain data; wait4 fills it.
    let mut ru: Rusage = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: both pointers are valid for the call.
        let r = unsafe { wait4(raw_pid, &mut status, 0, &mut ru) };
        if r == raw_pid {
            break;
        }
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(EINTR) {
            return Err(e);
        }
    }
    let code = if status & 0x7f == 0 {
        (status >> 8) & 0xff
    } else {
        128 + (status & 0x7f)
    };
    Ok((code, ru, io))
}

fn seconds(t: &Timeval) -> f64 {
    t.tv_sec as f64 + t.tv_usec as f64 / 1e6
}

struct Options {
    label: Option<String>,
    stdin: Option<String>,
    stdout: Option<String>,
    verbose: bool,
    command: Vec<String>,
    ufat: Option<String>,
    method: Option<String>,
    params: String,
    fds: Vec<String>,
}

fn usage() -> ! {
    eprintln!("usage: measure [-l LABEL] [--stdin FILE] [--stdout FILE] [-v] -- COMMAND [ARGS...]");
    eprintln!("       measure [-l LABEL] [-v] --ufat BIN --method METHOD [--params JSON] [--fd SPEC]...");
    std::process::exit(2);
}

fn parse_args() -> Options {
    let mut o = Options {
        label: None,
        stdin: None,
        stdout: None,
        verbose: false,
        command: Vec::new(),
        ufat: None,
        method: None,
        params: "{}".to_string(),
        fds: Vec::new(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    let value = |i: &mut usize| -> String {
        *i += 1;
        args.get(*i).cloned().unwrap_or_else(|| usage())
    };
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                o.command = args[i + 1..].to_vec();
                break;
            }
            "-l" => o.label = Some(value(&mut i)),
            "--stdin" => o.stdin = Some(value(&mut i)),
            "--stdout" => o.stdout = Some(value(&mut i)),
            "-v" => o.verbose = true,
            "--ufat" => o.ufat = Some(value(&mut i)),
            "--method" => o.method = Some(value(&mut i)),
            "--params" => o.params = value(&mut i),
            "--fd" => o.fds.push(value(&mut i)),
            _ => usage(),
        }
        i += 1;
    }
    if o.command.is_empty() && o.method.is_none() {
        usage();
    }
    o
}

fn stdio(path: &Option<String>, write: bool) -> io::Result<Stdio> {
    Ok(match path {
        None => Stdio::null(),
        Some(p) => Stdio::from(if write { File::create(p)? } else { File::open(p)? }),
    })
}

/// Starts the ufat binary serving a connected socket passed as fd 3,
/// announced through the LISTEN_FDS protocol. LISTEN_PID has to be the
/// service's own pid: a shell puts its pid into the environment and execs
/// ufat in place, which keeps the pid, so that the forked child neither
/// allocates nor takes locks.
fn spawn_ufat(o: &Options) -> io::Result<(Child, UnixStream)> {
    let (ours, theirs) = UnixStream::pair()?;
    let theirs_fd = theirs.into_raw_fd();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("LISTEN_PID=$$ exec \"$0\"")
        .arg(o.ufat.as_ref().unwrap())
        .env("LISTEN_FDS", "1")
        .env("LISTEN_FDNAMES", "varlink")
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    if !o.verbose {
        command.stderr(Stdio::null());
    }
    // SAFETY: the closure runs in the forked child and calls nothing but
    // dup2 and fcntl, which are async-signal-safe. The descriptor may be 3
    // already, then dup2 does nothing and fcntl clears its FD_CLOEXEC.
    unsafe {
        command.pre_exec(move || {
            if dup2(theirs_fd, 3) < 0 || fcntl(3, F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    // SAFETY: theirs_fd is ours to close; the child has its own copy.
    drop(unsafe { OwnedFd::from_raw_fd(theirs_fd) });
    Ok((child, ours))
}

fn varlink_call(o: &Options, socket: UnixStream) -> io::Result<()> {
    let Ok(json::Value::Object(params)) = json::parse(&o.params) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--params is not a JSON object",
        ));
    };
    // The descriptors, in the order given: index n of the call is fds[n].
    let mut files = Vec::new();
    for spec in &o.fds {
        files.push(match spec.strip_prefix("rw:") {
            Some(path) => std::fs::OpenOptions::new().read(true).write(true).open(path)?,
            None => File::open(spec)?,
        });
    }
    let fds: Vec<std::os::fd::BorrowedFd<'_>> = files.iter().map(|f| f.as_fd()).collect();
    let mut client = varlink::Client::new(Box::new(socket));
    let method = o.method.as_ref().unwrap();
    let reply = client.call_with_fds(method, params, &fds)?;
    if o.verbose {
        eprintln!("{:?}", reply);
    }
    match reply {
        varlink::Response::Reply { .. } => Ok(()),
        varlink::Response::Error(e) => Err(io::Error::other(format!(
            "{} failed: {} {}",
            method,
            e.name,
            json::Value::Object(e.parameters)
        ))),
    }
}

fn main() -> ExitCode {
    let o = parse_args();
    let start = Instant::now();
    let (pid, label, client_result) = if o.method.is_some() {
        let (child, socket) = match spawn_ufat(&o) {
            Ok(x) => x,
            Err(e) => {
                eprintln!(
                    "measure: failed to start {}: {}",
                    o.ufat.as_deref().unwrap_or("ufat"),
                    e
                );
                return ExitCode::from(125);
            }
        };
        let result = varlink_call(&o, socket);
        // Our end of the socket is closed now: the service exits.
        (
            child.id(),
            o.label.clone().unwrap_or_else(|| o.method.clone().unwrap()),
            result,
        )
    } else {
        let mut command = Command::new(&o.command[0]);
        command.args(&o.command[1..]);
        let (stdin, stdout) = match (stdio(&o.stdin, false), stdio(&o.stdout, true)) {
            (Ok(i), Ok(o)) => (i, o),
            (Err(e), _) | (_, Err(e)) => {
                eprintln!("measure: {}", e);
                return ExitCode::from(125);
            }
        };
        command.stdin(stdin).stdout(stdout);
        if !o.verbose {
            command.stderr(Stdio::null());
        }
        let child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("measure: failed to start {}: {}", o.command[0], e);
                return ExitCode::from(125);
            }
        };
        (
            child.id(),
            o.label.clone().unwrap_or_else(|| o.command.join(" ")),
            Ok(()),
        )
    };
    let (status, ru, io) = match wait_measured(pid) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("measure: wait failed: {}", e);
            return ExitCode::from(125);
        }
    };
    let wall = start.elapsed().as_secs_f64();
    let mut status = status;
    if let Err(e) = client_result {
        eprintln!("measure: {}", e);
        if status == 0 {
            status = 1;
        }
    }
    println!(
        "{}\t{:.4}\t{:.4}\t{:.4}\t{}\t{}\t{}\t{}\t{}\t{}",
        label,
        wall,
        seconds(&ru.ru_utime),
        seconds(&ru.ru_stime),
        ru.ru_maxrss,
        io.wchar,
        io.rchar,
        io.syscw,
        io.syscr,
        status
    );
    let _ = io::stdout().flush();
    ExitCode::from(status.clamp(0, 255) as u8)
}
