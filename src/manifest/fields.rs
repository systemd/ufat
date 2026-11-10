// SPDX-License-Identifier: LGPL-2.1-or-later
//! The field level rules of a manifest: how a value is read and what is a
//! valid name, hash, UUID, label, user name or extended attribute. They
//! follow systemd's reader (src/shared/uapi16-manifest.c) rule for rule.

use json::{Object, Value};

use super::{malformed_field, FILENAME, GPT_LABEL_MAX, NAME_MAX, PATH_MAX};
use crate::errno::*;
use crate::sha256::DIGEST_SIZE;
use crate::{ManifestProblem, Result};

/// An unsigned integer. 64 bit values are a problem for many JSON
/// implementations, so like systemd we also take them as decimal strings.
pub(super) fn uint(v: &Value, what: &str) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = s.parse() {
                return Ok(n);
            }
        }
    }
    bail!(
        EBADMSG,
        malformed_field(ManifestProblem::FieldType, what),
        "manifest field '{}' is not an unsigned integer",
        what
    )
}

/// An access mode: a number, or a string in octal as everywhere else.
pub(super) fn access_mode(v: &Value, what: &str) -> Result<u32> {
    let m = match v.as_str() {
        Some(s) if !s.is_empty() && s.bytes().all(|b| (b'0'..=b'7').contains(&b)) => {
            u64::from_str_radix(s, 8).unwrap_or(u64::MAX)
        }
        Some(_) => {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::FieldType, what),
                "manifest field '{}' is not an octal access mode",
                what
            )
        }
        None => uint(v, what)?,
    };
    if m > 0o7777 {
        bail!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldRange, what),
            "manifest field '{}' is out of range: {}",
            what,
            m
        );
    }
    Ok(m as u32)
}

pub(super) fn string<'a>(v: &'a Value, what: &str) -> Result<&'a str> {
    v.as_str().ok_or_else(|| {
        err!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldType, what),
            "manifest field '{}' is not a string",
            what
        )
    })
}

pub(super) fn boolean(v: &Value, what: &str) -> Result<bool> {
    v.as_bool().ok_or_else(|| {
        err!(
            EBADMSG,
            malformed_field(ManifestProblem::FieldType, what),
            "manifest field '{}' is not a boolean",
            what
        )
    })
}

/// Hex digits with whitespace allowed in between, as systemd decodes them.
pub(super) fn hex_bytes(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut high = None;
    for c in text.chars().filter(|c| !c.is_ascii_whitespace()) {
        let d = c.to_digit(16)? as u8;
        match high.take() {
            None => high = Some(d),
            Some(h) => out.push(h << 4 | d),
        }
    }
    if high.is_some() {
        return None;
    }
    Some(out)
}

pub(super) fn hash(v: &Value, what: &str) -> Result<[u8; DIGEST_SIZE]> {
    hex_bytes(string(v, what)?)
        .and_then(|b| <[u8; DIGEST_SIZE]>::try_from(b).ok())
        .ok_or_else(|| {
            err!(
                EBADMSG,
                malformed_field(ManifestProblem::FieldType, what),
                "manifest field '{}' is not a SHA-256 hash",
                what
            )
        })
}

/// A 128 bit ID as systemd spells them: 32 hex digits, or a GUID with the
/// usual dashes, optionally behind "urn:uuid:".
pub(super) fn valid_id128(s: &str) -> bool {
    // Compare bytes: slicing the string at a byte offset would panic inside a
    // multi-byte character, and the string comes from the manifest.
    let s = match s.as_bytes().get(..9) {
        Some(prefix) if prefix.eq_ignore_ascii_case(b"urn:uuid:") => &s[9..],
        _ => s,
    };
    let bytes = s.as_bytes();
    match bytes.len() {
        32 => bytes.iter().all(u8::is_ascii_hexdigit),
        36 => bytes.iter().enumerate().all(|(i, &b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        }),
        _ => false,
    }
}

/// A GPT partition label: no control characters and at most 36 UTF-16
/// units, which is what the partition table has room for.
pub(super) fn valid_gpt_label(s: &str) -> bool {
    let mut units = 0;
    for c in s.chars() {
        if c < ' ' || ('\x7f'..='\u{9f}').contains(&c) {
            return false;
        }
        units += c.len_utf16();
        if units > GPT_LABEL_MAX {
            return false;
        }
    }
    true
}

/// User and group names, as liberally as systemd's relaxed rules allow:
/// anything that is not obviously broken or a number in disguise.
pub(super) fn valid_user_group_name(s: &str) -> bool {
    if s.is_empty() || s.starts_with(' ') || s.ends_with(' ') || s == "." || s == ".." {
        return false;
    }
    if s.chars().any(|c| c.is_ascii_control() || c == ':' || c == '/') {
        return false;
    }
    let digits = s.strip_prefix('-').unwrap_or(s);
    !digits.bytes().all(|b| b.is_ascii_digit())
}

/// The `extendedAttributes` object: namespaces mapping names to values, a
/// value being an object with exactly one of `text` and `base64`. Only the
/// `user` namespace is defined; others are ignored, as systemd does.
pub(super) fn check_extended_attributes(v: &Value, what: &str) -> Result<()> {
    let namespaces = v.as_object().ok_or_else(|| {
        err!(
            EBADMSG,
            malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
            "{}: 'extendedAttributes' is not an object",
            what
        )
    })?;
    for (ns, attrs) in namespaces.iter() {
        if ns != "user" || attrs.is_null() {
            continue;
        }
        let attrs = attrs.as_object().ok_or_else(|| {
            err!(
                EBADMSG,
                malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
                "{}: extended attribute namespace '{}' is not an object",
                what,
                ns
            )
        })?;
        for (name, value) in attrs.iter() {
            if name.is_empty() || name.chars().any(|c| c.is_ascii_control()) {
                bail!(
                    EBADMSG,
                    malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
                    "{}: invalid extended attribute name '{}'",
                    what,
                    name
                );
            }
            let value = value.as_object().ok_or_else(|| {
                err!(
                    EBADMSG,
                    malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
                    "{}: value of extended attribute '{}' is not an object",
                    what,
                    name
                )
            })?;
            let text = value.get("text").filter(|v| !v.is_null());
            let base64 = value.get("base64").filter(|v| !v.is_null());
            match (text, base64) {
                (Some(t), None) => {
                    string(t, "text")?;
                }
                (None, Some(b)) => {
                    if base64_decode(string(b, "base64")?).is_none() {
                        bail!(
                            EBADMSG,
                            malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
                            "{}: extended attribute '{}' is not valid Base64",
                            what,
                            name
                        );
                    }
                }
                _ => bail!(
                    EBADMSG,
                    malformed_field(ManifestProblem::ExtendedAttributes, "extendedAttributes"),
                    "{}: extended attribute '{}' needs exactly one of 'text' and 'base64'",
                    what,
                    name
                ),
            }
        }
    }
    Ok(())
}

/// Checks a signature object's shape. The signature is not verified, but a
/// manifest whose signature objects are malformed is refused like systemd
/// refuses it.
pub(super) fn check_signature(object: &Object, index: usize) -> Result<()> {
    let what = format!("manifest signature object {}", index);
    match object.get("mechanism") {
        Some(Value::String(_)) => {}
        _ => {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Signature, "mechanism"),
                "{} has no 'mechanism' string",
                what
            )
        }
    }
    if let Some(key) = object.get("key").filter(|v| !v.is_null()) {
        if hex_bytes(string(key, "key")?).is_none() {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Signature, "key"),
                "{}: 'key' is not hex",
                what
            );
        }
    }
    if let Some(data) = object.get("data").filter(|v| !v.is_null()) {
        if base64_decode(string(data, "data")?).is_none() {
            bail!(
                EBADMSG,
                malformed_field(ManifestProblem::Signature, "data"),
                "{}: 'data' is not Base64",
                what
            );
        }
    }
    Ok(())
}

/// Whether `name` is a normalized relative path without control characters
/// that does not clash with the manifest's own name. Components are limited
/// to NAME_MAX bytes and the whole name to PATH_MAX, as on Linux.
pub fn valid_name(name: &str) -> bool {
    if name.is_empty() || name.len() >= PATH_MAX || name.starts_with('/') || name.ends_with('/') {
        return false;
    }
    if name.chars().any(|c| c.is_ascii_control()) {
        return false;
    }
    if name
        .split('/')
        .any(|c| c.is_empty() || c == "." || c == ".." || c.len() > NAME_MAX)
    {
        return false;
    }
    !(name == FILENAME || name.starts_with(&format!("{}.", FILENAME)))
}

/// The key under which FAT, which folds case, files `name`.
pub(super) fn fat_key(name: &str) -> Vec<u16> {
    let mut key = Vec::new();
    for (i, component) in name.split('/').enumerate() {
        if i > 0 {
            key.push(u16::from(b'/'));
        }
        key.extend(crate::name::fold_str(component));
    }
    key
}

/// Decodes Base64 in either the standard or the URL-safe alphabet, with or
/// without padding. Whitespace between the digits is skipped, as systemd
/// skips it.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut padding = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                padding += 1;
                continue;
            }
            c if c.is_ascii_whitespace() => continue,
            _ => return None,
        };
        if padding > 0 {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero padding of less than one byte.
    if bits >= 6 || acc != 0 || padding > 2 {
        return None;
    }
    Some(out)
}
