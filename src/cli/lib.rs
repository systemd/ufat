// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the command line tools of this repository have in common: the
//! parsing of a command line and of the sizes and the times given on it,
//! the wording of a count and the format of the times of a listing.
//!
//! This crate is not an interface of its own and changes with the tools.
//! It uses the standard library and the lexopt and shared crates.

#![deny(unsafe_code, unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shared::times::civil_from_days;
use shared::{bail, err, errno, Result};

/// Parsed command line: options with optional values plus positional
/// arguments. Paths on the host are taken as the bytes they are; the
/// values of all other options have to be UTF-8.
pub struct Args {
    options: Vec<(String, Option<OsString>)>,
    /// The positional arguments, in the order they were given.
    pub positional: Vec<OsString>,
}

impl Args {
    /// Splits `args` with lexopt: `--name=value` or `--name value` for the
    /// options in `with_value`, `--name` for those in `flags`, and -p, -l,
    /// -r and -f for `--parents`, `--long`, `--recursive` and `--force`
    /// where `flags` has them. Short options can be bundled, as in `-lh`.
    /// `--` ends the options, and `-` is a positional argument. `-h` or
    /// `--help` anywhere among the options prints `usage` and exits,
    /// whatever else is on the command line. After `--`, or as the value of
    /// an option, `-h` is an argument like any other.
    ///
    /// The values of the options in `path_options` are paths on the host,
    /// which can be any bytes. The values of all other options are UTF-8.
    pub fn parse(
        args: &[OsString],
        with_value: &[&str],
        flags: &[&str],
        path_options: &[&str],
        usage: &str,
    ) -> Result<Args> {
        use lexopt::Arg::{Long, Short, Value};

        let mut options = Vec::new();
        let mut positional = Vec::new();
        let mut help = false;
        let mut problem = None;
        let mut parser = lexopt::Parser::from_args(args.iter().cloned());
        loop {
            let error = match parser.next() {
                Ok(None) => break,
                Ok(Some(Short('h') | Long("help"))) => {
                    help = true;
                    continue;
                }
                Ok(Some(Short(c))) => match short_option(c).filter(|name| flags.contains(name)) {
                    Some(name) => {
                        options.push((name.to_string(), None));
                        continue;
                    }
                    None => err!(errno::EINVAL, "unknown option -{}", c),
                },
                Ok(Some(Long(name))) if with_value.contains(&name) => {
                    let name = name.to_string();
                    match parser.value() {
                        Err(_) => err!(errno::EINVAL, "option --{} needs a value", name),
                        Ok(value) if !path_options.contains(&name.as_str()) && value.to_str().is_none() => {
                            err!(errno::EINVAL, "the value of --{} is not valid UTF-8", name)
                        }
                        Ok(value) => {
                            options.push((name, Some(value)));
                            continue;
                        }
                    }
                }
                Ok(Some(Long(name))) if flags.contains(&name) => {
                    let name = name.to_string();
                    if parser.optional_value().is_some() {
                        err!(errno::EINVAL, "option --{} takes no value", name)
                    } else {
                        options.push((name, None));
                        continue;
                    }
                }
                Ok(Some(Long(name))) => err!(errno::EINVAL, "unknown option --{}", name),
                Ok(Some(Value(value))) => {
                    positional.push(value);
                    continue;
                }
                // A value attached to a short option, as in -r=x.
                Err(lexopt::Error::UnexpectedValue { option, .. }) => {
                    err!(errno::EINVAL, "option {} takes no value", option)
                }
                Err(e) => err!(errno::EINVAL, "{}", e),
            };
            problem.get_or_insert(error);
        }
        if help {
            print!("{}", usage);
            let _ = std::io::stdout().flush();
            std::process::exit(0);
        }
        match problem {
            Some(e) => Err(e),
            None => Ok(Args { options, positional }),
        }
    }

    /// The last value given to the option `name`.
    pub fn last(&self, name: &str) -> Option<&OsStr> {
        self.options
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    /// The value of a text option.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.last(name).and_then(OsStr::to_str)
    }

    /// The value of a path option.
    pub fn path(&self, name: &str) -> Option<&Path> {
        self.last(name).map(Path::new)
    }

    /// All values of a path option that can be given more than once.
    pub fn paths(&self, name: &str) -> Vec<&Path> {
        self.options
            .iter()
            .filter(|(n, _)| n == name)
            .filter_map(|(_, v)| v.as_deref().map(Path::new))
            .collect()
    }

    /// Whether the flag `name` was given.
    pub fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }

    /// The value of a size option that has to fit 32 bits.
    pub fn u32(&self, name: &str) -> Result<Option<u32>> {
        let Some(v) = self.value(name) else {
            return Ok(None);
        };
        let n = parse_size(v)?;
        u32::try_from(n)
            .map(Some)
            .map_err(|_| err!(errno::ERANGE, "--{} '{}' is too large", name, v))
    }

    /// The value of a size option, see [`parse_size`].
    pub fn size(&self, name: &str) -> Result<Option<u64>> {
        self.value(name).map(parse_size).transpose()
    }

    /// The positional arguments as paths on the host.
    pub fn positional_paths(&self) -> Vec<&Path> {
        self.positional.iter().map(Path::new).collect()
    }
}

/// The long option a short option stands for.
fn short_option(c: char) -> Option<&'static str> {
    match c {
        'p' => Some("parents"),
        'l' => Some("long"),
        'r' => Some("recursive"),
        'f' => Some("force"),
        _ => None,
    }
}

/// `n` followed by `one` or `many`, as the count asks for.
pub fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{} {}", n, if n == 1 { one } else { many })
}

/// Parses seconds since the epoch, as `--timestamp` and `SOURCE_DATE_EPOCH`
/// give them. Adding to a SystemTime panics on overflow, so check.
pub fn time_from_secs(text: &str, what: &str) -> Result<SystemTime> {
    let secs: u64 = text
        .parse()
        .map_err(|_| err!(errno::EINVAL, "invalid {} '{}'", what, text))?;
    UNIX_EPOCH
        .checked_add(Duration::from_secs(secs))
        .ok_or_else(|| err!(errno::ERANGE, "{} '{}' is out of range", what, text))
}

/// `SOURCE_DATE_EPOCH`, if set and valid.
pub fn source_date_epoch() -> Result<Option<SystemTime>> {
    match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(t) => time_from_secs(&t, "$SOURCE_DATE_EPOCH").map(Some),
        Err(_) => Ok(None),
    }
}

/// Parses a size with an optional binary suffix.
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let (digits, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m: u64 = match c.to_ascii_uppercase() {
                'K' => 1 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => bail!(errno::EINVAL, "unknown size suffix in '{}'", s),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| err!(errno::EINVAL, "invalid size '{}'", s))?;
    n.checked_mul(mult)
        .ok_or_else(|| err!(errno::ERANGE, "size '{}' is too large", s))
}

/// A time as a listing shows it: `YYYY-MM-DD HH:MM:SS`, in UTC.
pub fn format_time(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}
